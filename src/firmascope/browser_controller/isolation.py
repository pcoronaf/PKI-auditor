"""Aislamiento de red y prueba de firma local por etapas (Nivel 3).

Dos piezas:

* :class:`NetworkIsolation` corta la red **interceptando peticiones nuevas**,
  no apagando la pila de red del navegador. La pagina ya cargada sigue viva, y
  cada intento de salida bloqueado queda registrado como evidencia en lugar de
  desaparecer: un intento de exfiltracion con la red cortada es una de las
  pruebas mas fuertes que puede producir una auditoria.

* :class:`StagedOfflineTest` ejecuta el flujo por etapas de la especificacion
  (LOAD, GET DOCUMENT/NONCE, NETWORK OFF, firma, NETWORK ON, SUBMIT) con
  control interactivo: continuar, repetir, **retroceder** o **cancelar**.

El estado de red se *reconcilia* a partir de la etapa destino, nunca se aplica
como un delta. Por eso retroceder de una etapa aislada a una etapa en linea
restablece la red automaticamente, y cancelar siempre deja el navegador
utilizable: es imposible quedarse con la pagina muerta por un corte que nadie
deshizo.
"""

from __future__ import annotations

import enum
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence

from ..audit_core.config import AuditConfig, IsolationMode, IsolationPolicy
from ..audit_core.events import Event, EventType, Tag
from ..audit_core.secrets import SecretVault
from ..network_analyzer import domains

#: Patron de ruta que intercepta todo el trafico del contexto.
ROUTE_PATTERN = "**/*"

#: Esquemas que nunca se bloquean: no son trafico de red.
LOCAL_SCHEMES = ("data:", "blob:", "about:", "chrome-extension:", "filesystem:")


# ----------------------------------------------------------------------
# Aislamiento
# ----------------------------------------------------------------------

@dataclass
class BlockedAttempt:
    """Intento de salida bloqueado durante el aislamiento."""

    timestamp: float
    method: str
    url: str
    host: str
    third_party: bool
    body_size: int
    body_digest: str
    tags: list[str] = field(default_factory=list)
    canary_matches: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": round(self.timestamp, 3),
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "third_party": self.third_party,
            "body_size": self.body_size,
            "body_digest": self.body_digest,
            "tags": list(self.tags),
            "canary_matches": list(self.canary_matches),
            "blocked": True,
        }


class NetworkIsolation:
    """Controla el aislamiento de red de un contexto de navegador."""

    def __init__(self, context, config: AuditConfig,
                 emit: Callable[[Event], None], session_id: str,
                 vault: SecretVault | None = None,
                 store: Any | None = None):
        self.context = context
        self.config = config
        self.emit = emit
        self.session_id = session_id
        self.vault = vault
        self.store = store

        self.policy: IsolationPolicy = config.isolation
        self._engaged = False
        self._route_installed = False
        self._reason = ""
        self._engaged_at: float | None = None
        self.blocked: list[BlockedAttempt] = []
        #: True en cuanto una navegacion termina con exito. Aislar antes de eso
        #: es la causa habitual de la pagina en blanco.
        self.navigation_succeeded = False

    # ------------------------------------------------------------------
    @property
    def engaged(self) -> bool:
        return self._engaged

    @property
    def network_state(self) -> str:
        return "OFFLINE" if self._engaged else "ONLINE"

    # ------------------------------------------------------------------
    def preload(self, page, timeout: float | None = None) -> bool:
        """Espera a que la red se calme antes de aislar.

        Es el paso que evita el sintoma mas comun: cortar la red cuando el sitio
        aun no ha terminado de descargar sus scripts, y encontrarse una pagina
        que no carga.
        """
        if page is None or page.is_closed():
            return False
        limit = timeout if timeout is not None else self.policy.preload_timeout
        try:
            page.wait_for_load_state("networkidle", timeout=limit * 1000)
            return True
        except Exception:
            # No alcanzar networkidle no es fatal: hay sitios con conexiones
            # permanentes (WebSocket, long polling) que nunca estan inactivos.
            self.emit(Event(
                EventType.CHECKPOINT, self.session_id, sensor="isolation",
                data={"name": "preload-timeout",
                      "detail": f"la red no quedo inactiva en {limit:g}s; "
                                "se aisla igualmente, pero algun recurso puede faltar"}))
            return False

    # ------------------------------------------------------------------
    def engage(self, reason: str = "", policy: IsolationPolicy | None = None) -> bool:
        """Activa el aislamiento. Devuelve True si quedo activo."""
        if policy is not None:
            self.policy = policy
        if self.policy.mode is IsolationMode.NONE:
            return False
        if self._engaged:
            return True

        if not self.navigation_succeeded:
            # Aislar antes de la primera navegacion deja el navegador sin poder
            # cargar nada. Se avisa y no se aisla: es un error de secuencia.
            self.emit(Event(
                EventType.AGENT_ERROR, self.session_id, sensor="isolation",
                data={"kind": "isolation-sequence",
                      "error": "se intento aislar la red antes de cargar el sitio; "
                               "cargue primero el objetivo y despues aisle"}))
            return False

        self._install_route()
        self._engaged = True
        self._engaged_at = time.time()
        self._reason = reason
        self._set_online_flag(False)

        self.emit(Event(
            EventType.NETWORK_OFF, self.session_id, sensor="isolation",
            data={
                "reason": reason,
                "mode": self.policy.mode.value,
                "allow_hosts": list(self.policy.allow_hosts),
                "mechanism": "interceptacion y aborto de peticiones (Playwright route)",
                "offline_flag_emulated": self.policy.emulate_offline_flag,
            }))
        if self.store is not None:
            self.store.add_checkpoint(name="network-off", network="OFFLINE", detail=reason)
        return True

    def release(self, reason: str = "") -> bool:
        """Desactiva el aislamiento y restablece la red."""
        if not self._engaged:
            return False
        self._remove_route()
        self._engaged = False
        self._set_online_flag(True)
        duration = time.time() - (self._engaged_at or time.time())

        self.emit(Event(
            EventType.NETWORK_ON, self.session_id, sensor="isolation",
            data={
                "reason": reason,
                "duration_s": round(duration, 3),
                "blocked_attempts": len(self.blocked),
            }))
        if self.store is not None:
            self.store.add_checkpoint(name="network-on", network="ONLINE", detail=reason)
        return True

    def reconcile(self, desired: str, reason: str = "") -> None:
        """Lleva el estado de red al deseado (``ONLINE`` / ``OFFLINE``).

        Idempotente y sin memoria de como se llego al estado actual: es lo que
        hace que retroceder de etapa y cancelar sean correctos sin bookkeeping.
        """
        target = str(desired).upper()
        if target == "OFFLINE" and not self._engaged:
            self.engage(reason)
        elif target == "ONLINE" and self._engaged:
            self.release(reason)

    # ------------------------------------------------------------------
    def _install_route(self) -> None:
        if self._route_installed:
            return
        try:
            self.context.route(ROUTE_PATTERN, self._handle_route)
            self._route_installed = True
        except Exception as exc:  # pragma: no cover
            self.emit(Event(EventType.AGENT_ERROR, self.session_id, sensor="isolation",
                            data={"error": f"no se pudo instalar la interceptacion: {exc}"[:300]}))

    def _remove_route(self) -> None:
        if not self._route_installed:
            return
        try:
            self.context.unroute(ROUTE_PATTERN, self._handle_route)
        except Exception:  # pragma: no cover
            pass
        self._route_installed = False

    def _should_block(self, url: str) -> bool:
        if not self._engaged:
            return False
        if url.startswith(LOCAL_SCHEMES):
            return False
        host = domains.host_of(url)
        if not host:
            return False
        mode = self.policy.mode
        if mode is IsolationMode.NONE:
            return False
        if mode is IsolationMode.THIRD_PARTY:
            return domains.is_third_party(url, self.config.target,
                                          self.config.first_party_domains)
        if mode is IsolationMode.ALLOWLIST:
            for allowed in self.policy.allow_hosts:
                allowed = allowed.strip().lower()
                if not allowed:
                    continue
                if host == allowed or host.endswith("." + allowed):
                    return False
            return True
        return True  # FULL

    def _handle_route(self, route) -> None:
        """Deja pasar o aborta, registrando el intento como evidencia."""
        try:
            request = route.request
            url = request.url
        except Exception:  # pragma: no cover
            try:
                route.fallback()
            except Exception:
                pass
            return

        if not self._should_block(url):
            # fallback y no continue_: cede al siguiente manejador. Con
            # continue_ la peticion salia directa y se saltaba la ruta que
            # instrumenta los workers, que se registro antes que esta.
            try:
                route.fallback()
            except Exception:  # pragma: no cover - la peticion pudo cancelarse
                pass
            return

        self._record_blocked(request, url)
        try:
            route.abort("internetdisconnected")
        except Exception:  # pragma: no cover
            pass

    def _record_blocked(self, request, url: str) -> None:
        body = b""
        if self.policy.inspect_blocked_bodies:
            try:
                raw = request.post_data_buffer
                if callable(raw):  # compatibilidad entre versiones de Playwright
                    raw = raw()
                body = raw or b""
            except Exception:
                body = b""

        matches = self.vault.scan(body) if (self.vault and body) else []
        tags = sorted({m.label for m in matches})
        if body and not tags:
            tags = [Tag.UNCLASSIFIED.value]

        attempt = BlockedAttempt(
            timestamp=time.time(),
            method=getattr(request, "method", "GET") or "GET",
            url=url,
            host=domains.host_of(url),
            third_party=domains.is_third_party(url, self.config.target,
                                               self.config.first_party_domains),
            body_size=len(body),
            body_digest=hashlib.sha256(body).hexdigest() if body else "",
            tags=tags,
            canary_matches=[m.to_dict() for m in matches],
        )
        self.blocked.append(attempt)

        data = attempt.to_dict()
        data["blocked_by"] = "firmascope-isolation"
        data["isolation_mode"] = self.policy.mode.value
        # Se emite como NETWORK_REQUEST para que aparezca en la linea temporal y
        # las reglas de egress lo vean: el sitio INTENTO sacar estos datos.
        self.emit(Event(EventType.NETWORK_REQUEST, self.session_id,
                        timestamp=attempt.timestamp, sensor="isolation",
                        origin=attempt.host, tags=tags, data=data))

    def _set_online_flag(self, online: bool) -> None:
        """Emula ``navigator.onLine`` en todos los contextos accesibles."""
        if not self.policy.emulate_offline_flag:
            return
        script = (
            "(v) => { try { return globalThis.__FIRMASCOPE__ "
            "? globalThis.__FIRMASCOPE__.setOnline(v) : null; } catch (e) { return null; } }"
        )
        for page in list(getattr(self.context, "pages", []) or []):
            try:
                if page.is_closed():
                    continue
                for frame in page.frames:
                    try:
                        frame.evaluate(script, online)
                    except Exception:
                        continue
            except Exception:  # pragma: no cover
                continue

    # ------------------------------------------------------------------
    def summary(self) -> dict[str, Any]:
        return {
            "policy": self.policy.to_dict(),
            "state": self.network_state,
            "blocked_attempts": [a.to_dict() for a in self.blocked],
            "blocked_count": len(self.blocked),
            "blocked_with_private_data": sum(
                1 for a in self.blocked
                if set(a.tags) & {Tag.KEY_FILE.value, Tag.KEY_PASSWORD.value, Tag.PRIVATE_KEY.value}
            ),
        }


# ----------------------------------------------------------------------
# Prueba por etapas
# ----------------------------------------------------------------------

class StageAction(str, enum.Enum):
    """Lo que el operador decide al terminar de atender una etapa."""

    CONTINUE = "continue"   # avanzar a la siguiente
    RETRY = "retry"         # repetir esta etapa
    BACK = "back"           # retroceder a la etapa anterior
    ABORT = "abort"         # cancelar el proceso

    @classmethod
    def parse(cls, value: str) -> "StageAction":
        text = str(value).strip().lower()
        aliases = {
            "": cls.CONTINUE, "c": cls.CONTINUE, "continue": cls.CONTINUE,
            "continuar": cls.CONTINUE, "siguiente": cls.CONTINUE, "next": cls.CONTINUE,
            "n": cls.CONTINUE,
            "r": cls.RETRY, "retry": cls.RETRY, "repetir": cls.RETRY,
            "b": cls.BACK, "back": cls.BACK, "atras": cls.BACK,
            "regresar": cls.BACK, "anterior": cls.BACK,
            "a": cls.ABORT, "abort": cls.ABORT, "cancelar": cls.ABORT,
            "cancel": cls.ABORT, "q": cls.ABORT, "salir": cls.ABORT,
        }
        if text not in aliases:
            raise ValueError(f"accion desconocida: {value!r}")
        return aliases[text]


@dataclass(frozen=True)
class Stage:
    """Una etapa del flujo de firma, con el estado de red que exige."""

    name: str
    network: str          # ONLINE | OFFLINE
    title: str
    instruction: str
    #: Si el operador puede retroceder desde aqui.
    allow_back: bool = True
    #: Nota que se muestra cuando retroceder no deshace efectos en el servidor.
    irreversible_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "network": self.network, "title": self.title,
                "instruction": self.instruction}


#: Flujo por etapas de la especificacion.
DEFAULT_STAGES: tuple[Stage, ...] = (
    Stage("load", "ONLINE", "Cargar el sitio",
          "Se abre el objetivo y se esperan sus recursos. No introduzca nada todavia.",
          allow_back=False),
    Stage("prepare", "ONLINE", "Preparar la operacion",
          "Inicie sesion si hace falta y llegue hasta la pantalla de firma, incluyendo "
          "la descarga del documento y del nonce. Aun NO cargue la clave."),
    Stage("isolate", "OFFLINE", "Aislar la red",
          "FirmaScope corta la salida de red. La pagina sigue cargada y operativa."),
    Stage("sign", "OFFLINE", "Firmar con la red aislada",
          "Cargue el .cer, el .key y la contrasena, y pulse firmar. Si el sitio "
          "completa la firma aqui, la operacion es local."),
    Stage("restore", "ONLINE", "Restablecer la red",
          "Se devuelve la conectividad para poder enviar la firma."),
    Stage("submit", "ONLINE", "Enviar la firma",
          "Complete el envio de la firma al servidor.",
          irreversible_note="El envio de la firma no se puede deshacer retrocediendo: "
                            "el servidor ya la recibio."),
)


@dataclass
class StageRecord:
    """Lo ocurrido en una visita a una etapa."""

    stage: str
    index: int
    action: str
    entered_at: float
    left_at: float
    network: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage, "index": self.index, "action": self.action,
            "entered_at": round(self.entered_at, 3), "left_at": round(self.left_at, 3),
            "duration_s": round(self.left_at - self.entered_at, 3),
            "network": self.network,
        }


@dataclass
class StagedResult:
    """Resultado de la prueba por etapas."""

    completed: bool
    aborted: bool
    history: list[StageRecord] = field(default_factory=list)
    reached: list[str] = field(default_factory=list)
    abort_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "completed": self.completed,
            "aborted": self.aborted,
            "abort_reason": self.abort_reason,
            "stages_reached": list(self.reached),
            "history": [r.to_dict() for r in self.history],
            "back_count": sum(1 for r in self.history if r.action == StageAction.BACK.value),
            "retry_count": sum(1 for r in self.history if r.action == StageAction.RETRY.value),
        }


#: Firma del controlador interactivo. Recibe la etapa y su indice, y devuelve la
#: accion elegida. Una interfaz grafica mapea los botones a estas acciones.
StageController = Callable[[Stage, int, "StagedOfflineTest"], StageAction]


class StagedOfflineTest:
    """Ejecuta el flujo de firma por etapas con control interactivo.

    El estado de red se reconcilia contra ``Stage.network`` al entrar en cada
    etapa, de modo que:

    * avanzar de ``prepare`` a ``isolate`` corta la red;
    * **retroceder** de ``sign`` a ``prepare`` la restablece sola;
    * **cancelar** en cualquier punto restablece la red antes de salir.

    Ninguna de esas tres cosas requiere que quien llama recuerde el estado.
    """

    def __init__(self, controller, isolation: NetworkIsolation,
                 emit: Callable[[Event], None], session_id: str,
                 stages: Sequence[Stage] = DEFAULT_STAGES):
        self.controller = controller
        self.isolation = isolation
        self.emit = emit
        self.session_id = session_id
        self.stages = list(stages)
        self.history: list[StageRecord] = []
        self.current_index = 0

    # ------------------------------------------------------------------
    # Avance paso a paso
    # ------------------------------------------------------------------
    #
    # Hay dos formas de recorrer las etapas y las dos usan la misma maquina:
    #
    # * :meth:`run` empuja -- llama a quien decide y espera la respuesta. Es lo
    #   que necesita una CLI, que bloquea en ``input()``.
    # * :meth:`begin` y :meth:`apply` tiran -- quien decide pregunta en que
    #   etapa esta y luego envia la accion. Es lo que necesita una interfaz
    #   grafica, que no puede bloquear su bucle de eventos esperando un clic.
    #
    # Lo importante es que el orden de las etapas, la reconciliacion de la red y
    # la salida segura viven en un solo sitio. Si la interfaz grafica tuviera su
    # propio bucle, "cancelar" podria dejar el navegador aislado en un camino y
    # no en el otro.

    def begin(self) -> Stage:
        """Entra en la primera etapa y la devuelve. Para el modo paso a paso."""
        self._reached: list[str] = []
        self._aborted = False
        self._abort_reason = ""
        self._index = 0
        self._entered_at = 0.0
        self._finished = False
        return self._enter_step(0)

    @property
    def finished(self) -> bool:
        return bool(getattr(self, "_finished", False))

    def current(self) -> Stage | None:
        """Etapa actual, o ``None`` si el recorrido ya termino."""
        if self.finished or not 0 <= self.current_index < len(self.stages):
            return None
        return self.stages[self.current_index]

    def apply(self, action: StageAction | str,
              reason: str = "") -> Stage | None:
        """Aplica una accion y devuelve la etapa siguiente, o ``None`` al terminar.

        Es el mismo cuerpo que ejecuta :meth:`run` en cada vuelta: registra la
        transicion, decide el indice siguiente y, si el recorrido acaba,
        restablece la red.
        """
        if self.finished:
            return None
        if not isinstance(action, StageAction):
            action = StageAction.parse(str(action))

        index = self._index
        stage = self.stages[index]
        self.history.append(StageRecord(
            stage=stage.name, index=index, action=action.value,
            entered_at=self._entered_at, left_at=time.time(),
            network=self.isolation.network_state,
        ))
        self._emit_transition(stage, index, action)

        if action is StageAction.ABORT:
            self._aborted = True
            self._abort_reason = reason or "cancelado por el operador"
            return self._close_steps()
        if action is StageAction.RETRY:
            return self._enter_step(index)
        if action is StageAction.BACK:
            return self._enter_step(self._previous_index(index))

        following = index + 1
        if following >= len(self.stages):
            return self._close_steps()
        return self._enter_step(following)

    def result(self) -> StagedResult:
        """Resultado del recorrido, valido una vez terminado."""
        completed = (not getattr(self, "_aborted", False)
                     and getattr(self, "_index", 0) >= len(self.stages) - 1
                     and self.finished)
        return StagedResult(
            completed=completed,
            aborted=bool(getattr(self, "_aborted", False)),
            history=list(self.history),
            reached=list(getattr(self, "_reached", [])),
            abort_reason=str(getattr(self, "_abort_reason", "")),
        )

    def _enter_step(self, index: int) -> Stage:
        stage = self.stages[index]
        self._index = index
        self.current_index = index
        self._enter(stage, index)
        if stage.name not in self._reached:
            self._reached.append(stage.name)
        self._entered_at = time.time()
        return stage

    def _close_steps(self) -> None:
        """Cierre comun: red restablecida y evento de fin."""
        self._finished = True
        self._index = len(self.stages)
        # Salida segura: suceda lo que suceda, la red queda restablecida.
        self.isolation.reconcile(
            "ONLINE",
            "proceso cancelado" if self._aborted else "fin de la prueba por etapas")
        self.emit(Event(EventType.CHECKPOINT, self.session_id, sensor="isolation",
                        data={"name": "staged-test-end", **self.result().to_dict()}))
        return None

    # ------------------------------------------------------------------
    def run(self, on_stage: StageController) -> StagedResult:
        """Recorre las etapas delegando la decision en ``on_stage``.

        Es el modo de empuje, sobre la misma maquina paso a paso: lo unico que
        anade es el bucle que pregunta y la traduccion de las excepciones del
        controlador en una cancelacion.
        """
        stage = self.begin()
        while stage is not None:
            reason = ""
            try:
                action = on_stage(stage, self.current_index, self)
            except KeyboardInterrupt:
                action = StageAction.ABORT
                reason = "interrumpido por el operador"
            except Exception as exc:
                action = StageAction.ABORT
                reason = f"error en el controlador de etapa: {exc}"
            stage = self.apply(action, reason)
        return self.result()

    # ------------------------------------------------------------------
    def _previous_index(self, index: int) -> int:
        """Indice de la etapa anterior que admita retroceso."""
        candidate = index - 1
        while candidate >= 0 and not self.stages[candidate].allow_back:
            candidate -= 1
        if candidate < 0:
            # Ya se esta en la primera etapa util: se repite en lugar de salir.
            self.emit(Event(EventType.CHECKPOINT, self.session_id, sensor="isolation",
                            data={"name": "back-at-first-stage",
                                  "detail": "no hay etapa anterior; se repite la actual"}))
            return index
        return candidate

    def _enter(self, stage: Stage, index: int) -> None:
        """Reconcilia la red y anuncia la etapa."""
        if stage.network == "OFFLINE":
            if self.isolation.policy.preload_before_isolating:
                self.isolation.preload(getattr(self.controller, "page", None))
            self.isolation.reconcile("OFFLINE", f"etapa {stage.name}")
        else:
            self.isolation.reconcile("ONLINE", f"etapa {stage.name}")

        actual = self.isolation.network_state
        self.emit(Event(EventType.CHECKPOINT, self.session_id, sensor="isolation",
                        data={
                            "name": f"stage:{stage.name}",
                            "index": index,
                            "title": stage.title,
                            "requested_network": stage.network,
                            "actual_network": actual,
                            "instruction": stage.instruction,
                        }))
        if actual != stage.network:
            # Entrar en la etapa de firma sin haber logrado el aislamiento
            # invalidaria la conclusion: se avisa en lugar de callar.
            self.emit(Event(
                EventType.AGENT_ERROR, self.session_id, sensor="isolation",
                data={"kind": "stage-network-mismatch", "stage": stage.name,
                      "requested": stage.network, "actual": actual,
                      "error": "la etapa no logro el estado de red que exige; "
                               "la conclusion sobre localidad de la firma no es valida "
                               "para esta etapa"}))

    def _emit_transition(self, stage: Stage, index: int, action: StageAction) -> None:
        self.emit(Event(EventType.CHECKPOINT, self.session_id, sensor="isolation",
                        data={"name": f"stage-action:{stage.name}", "index": index,
                              "action": action.value,
                              "network": self.isolation.network_state}))

    # ------------------------------------------------------------------
    def describe(self) -> list[dict[str, Any]]:
        """Etapas con su estado de red, para pintar la interfaz."""
        return [
            {**stage.to_dict(), "index": i,
             "can_go_back": stage.allow_back and i > 0,
             "irreversible_note": stage.irreversible_note}
            for i, stage in enumerate(self.stages)
        ]


# ----------------------------------------------------------------------
# Localidad del procesamiento
# ----------------------------------------------------------------------

#: Hitos del flujo de firma y el evento que los delata.
LOCALITY_MILESTONES: tuple[tuple[str, tuple[EventType, ...]], ...] = (
    ("Document retrieval", (EventType.NETWORK_RESPONSE,)),
    ("Private key access", (EventType.FILE_READ,)),
    ("Password access", (EventType.PASSWORD_READ,)),
    ("Private key decryption", (EventType.CRYPTO_DECRYPT, EventType.CRYPTO_UNWRAP,
                                EventType.CRYPTO_IMPORT)),
    ("Signature generation", (EventType.CRYPTO_SIGN,)),
    ("Signature submission", (EventType.NETWORK_REQUEST,)),
)


def processing_locality(events: Iterable[Event],
                        offline_windows: Sequence[tuple[float, float | None]]) -> dict[str, str]:
    """Tabla ``hito -> ONLINE | OFFLINE | NOT OBSERVED`` de la especificacion.

    Para cada hito se toma el **primer** evento que lo representa y se mira si
    cayo dentro de una ventana de aislamiento.
    """

    def offline_at(ts: float) -> bool:
        for start, end in offline_windows:
            if ts >= start and (end is None or ts <= end):
                return True
        return False

    by_type: dict[EventType, list[Event]] = {}
    for event in events:
        by_type.setdefault(event.type, []).append(event)

    report: dict[str, str] = {}
    for label, types in LOCALITY_MILESTONES:
        candidates: list[Event] = []
        for event_type in types:
            candidates.extend(by_type.get(event_type, []))
        if not candidates:
            report[label] = "NOT OBSERVED"
            continue
        first = min(candidates, key=lambda e: e.timestamp)
        report[label] = "OFFLINE" if offline_at(first.timestamp) else "ONLINE"
    return report
