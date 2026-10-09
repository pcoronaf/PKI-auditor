"""Contexto de evaluacion del motor de reglas.

Agrupa todo lo que una regla puede necesitar (eventos, peticiones, scripts,
analisis estatico, checkpoints) y ofrece consultas temporales elementales:
cuando se accedio por primera vez a la clave, que salio despues, si el
navegador estaba aislado en un instante dado.

Las preguntas de *causalidad* (reconstruir la cadena completa de procedencia)
son competencia del motor de correlacion, que se inyecta en ``correlation``
cuando esta disponible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from ..audit_core.config import AuditConfig
from ..audit_core.events import (
    EGRESS_EVENTS,
    KEY_ACCESS_EVENTS,
    foreign_key_digest,
    is_key_access,
    Event,
    EventType,
    Tag,
)
from ..network_analyzer import domains
from ..static_analyzer.analyzer import StaticReport

#: Marca temporal minima considerada "epoch plausible" (2001-09-09).
#: Algunos eventos de CDP traen tiempos monotonos desde el arranque del
#: navegador; compararlos con tiempos de pared producuria ordenes falsos.
MIN_EPOCH = 1_000_000_000.0

#: Codificaciones de canario que demuestran transmision *directa* del material.
DIRECT_ENCODINGS = frozenset(
    {"raw", "raw-marker", "base64", "base64url", "base64-marker", "hex", "utf8", "url", "utf16le"}
)

#: Tipos de cuerpo que se consideran binarios opacos.
BINARY_BODY_TYPES = frozenset({"ArrayBuffer", "Blob", "Uint8Array", "Int8Array", "DataView", "TypedArray"})


@dataclass
class AuditContext:
    """Entrada unica de todas las reglas."""

    config: AuditConfig
    events: list[Event] = field(default_factory=list)
    requests: list[dict[str, Any]] = field(default_factory=list)
    scripts: list[dict[str, Any]] = field(default_factory=list)
    checkpoints: list[dict[str, Any]] = field(default_factory=list)
    static: StaticReport | None = None
    correlation: Any | None = None
    #: Etiquetas de canario registradas en el vault de la sesion.
    canary_labels: set[str] = field(default_factory=set)
    #: Longitud de la contrasena de la credencial registrada, si la hay. Solo
    #: sirve para descartar: un campo de contrasena cuyo valor nunca llega a esa
    #: longitud no es el de la e.firma. Nunca sale de memoria.
    key_password_length: int | None = None
    #: SHA-256 del ``.key`` registrado, para reconocer en la pagina otro
    #: distinto (``foreign_key_selections``). Es un digest, no el secreto.
    key_sha256: str | None = None

    # -- consultas basicas ----------------------------------------------
    def events_of(self, *types: EventType) -> list[Event]:
        wanted = set(types)
        return [e for e in self.events if e.type in wanted]

    def events_with_tag(self, *tags: Tag | str) -> list[Event]:
        wanted = {t.value if isinstance(t, Tag) else t for t in tags}
        return [e for e in self.events if wanted & set(e.tags)]

    @classmethod
    def from_store(cls, store: Any, config: AuditConfig, *, static: Any = None,
                   credential: Any = None) -> "AuditContext":
        """El contexto de una sesion, igual para las reglas y para el reporte.

        Antes cada uno construia el suyo, y el del reporte no conocia la
        credencial: en el piloto del panel, FS-NET-001 decia que ningun tercero
        habia recibido trafico tras el acceso a la clave y la tabla del mismo
        reporte listaba dos, porque contaba la contrasena de la cuenta del
        portal como acceso a la clave. Una pieza, una implementacion.
        """
        import hashlib

        vault = getattr(store, "vault", None)
        password = getattr(credential, "password", None)
        key_der = getattr(credential, "key_der", None)
        return cls(
            config=config,
            events=store.events(),
            requests=store.requests(),
            scripts=store.scripts(),
            checkpoints=store.checkpoints(),
            static=static,
            canary_labels=vault.labels if vault is not None and vault.alive else set(),
            key_password_length=len(password) if password else None,
            key_sha256=hashlib.sha256(key_der).hexdigest() if key_der else None,
        )

    def __post_init__(self) -> None:
        if self.correlation is None:
            from ..correlation_engine import correlate
            self.correlation = correlate(self.events)

    def egress_events(self) -> list[Event]:
        """Salidas observadas, una por peticion real.

        La correlacion une las observaciones de los distintos sensores sobre una
        misma peticion. Sin ella, una exfiltracion vista por el agente, por CDP
        y por el aislamiento se contaria tres veces, y el intento que el
        aislamiento abortó aparecería tambien como salida consumada.
        """
        events = [e for e in self.events if e.type in EGRESS_EVENTS]
        if self.correlation is None:
            return events
        return [e for e in events if self.correlation.is_primary(e)]

    def was_blocked(self, event: Event) -> bool:
        """``True`` si la peticion que este evento observa no llego a salir."""
        if self.correlation is not None:
            return self.correlation.is_blocked(event)
        return bool(event.data.get("blocked"))

    def egress_host(self, event: Event) -> str:
        """Destino de una salida, con puerto, tomado de la URL y no del sensor."""
        group = self.correlation.group_of(event) if self.correlation else None
        if group is not None and group.netloc:
            return group.netloc
        return str(event.data.get("host") or "")

    def key_access_events(self) -> list[Event]:
        """Accesos a material *privado*: leer el documento o el .cer no cuenta.

        Tampoco la contrasena de *otra cosa*: en el primer piloto del panel,
        la lectura de la contrasena de la cuenta del portal, al iniciar sesion,
        se tomo como acceso a la clave y adelanto el instante de referencia de
        FS-NET-001 a antes de la firma.
        """
        return [e for e in self.events
                if is_key_access(e) and not self.is_other_password_read(e)]

    # -- contrasenas que no son la de la e.firma ------------------------
    def _password_field(self, event: Event) -> str:
        return str(event.data.get("input_id") or "")

    # -- credencial en uso ------------------------------------------------
    def foreign_key_selections(self) -> list[Event]:
        """Elecciones de un ``.key`` que no es el de la credencial registrada.

        Si las hay, lo que la sesion sabe de la credencial (canarios, longitud
        de la contrasena) no describe el material que de verdad se uso.
        """
        cached = getattr(self, "_foreign_cache", None)
        if cached is None:
            cached = [e for e in self.events_of(EventType.FILE_SELECTED)
                      if foreign_key_digest(e, self.key_sha256)]
            self._foreign_cache = cached
        return cached

    def foreign_key_used(self) -> bool:
        return bool(self.foreign_key_selections())

    def other_password_fields(self) -> set[str]:
        """Campos de contrasena cuyo valor nunca tuvo la longitud de la e.firma.

        El agente etiqueta como KEY_PASSWORD todo ``input[type=password]``,
        porque desde la pagina no puede saber de que es la contrasena. Con la
        credencial registrada si se puede descartar: un campo que nunca llega a
        la longitud de su contrasena guarda otra (la de la cuenta del portal).
        Se mira la lectura mas larga de cada campo, porque los frameworks leen
        el valor mientras se escribe.

        Si en la pagina se cargo otro ``.key``, la longitud registrada no es la
        de la contrasena en uso: en el piloto, la e.firma real (8 caracteres) se
        descarto por no medir 21 como la sintetica, y el reporte dijo que nadie
        habia leido la contrasena. Entonces solo se descartan los campos leidos
        exclusivamente antes de elegir cualquier ``.key`` (el inicio de sesion).
        """
        if self.foreign_key_used():
            return self._fields_read_before_key_selection()
        if not self.key_password_length:
            return set()
        longest: dict[str, int] = {}
        unknown: set[str] = set()
        for event in self.events_of(EventType.PASSWORD_READ):
            name = self._password_field(event)
            size = int(event.data.get("length") or 0)
            if size <= 0:
                # Sin longitud no hay con que descartar: el campo cuenta.
                unknown.add(name)
                continue
            longest[name] = max(longest.get(name, 0), size)
        return {name for name, size in longest.items()
                if size != self.key_password_length and name not in unknown}

    def _fields_read_before_key_selection(self) -> set[str]:
        key_choices = [e.timestamp for e in self.events_of(EventType.FILE_SELECTED)
                       if Tag.KEY_FILE.value in e.tags]
        if not key_choices:
            return set()
        first_choice = min(key_choices)
        before: set[str] = set()
        after: set[str] = set()
        for event in self.events_of(EventType.PASSWORD_READ):
            name = self._password_field(event)
            (before if event.timestamp < first_choice else after).add(name)
        return {name for name in before - after if name}

    def is_other_password_read(self, event: Event) -> bool:
        return (event.type is EventType.PASSWORD_READ
                and self._password_field(event) in self.other_password_fields())

    def contradicted(self, event: Event, label: Tag | str) -> bool:
        """La etiqueta del agente la desmiente un sensor que vio los bytes.

        Requiere el canario registrado (si no, no hay nada que buscar), un
        cuerpo visto por CDP o el proxy, y que el dato no sea derivado: una
        transformacion puede ocultar el canario, y entonces la ausencia no
        prueba nada.
        """
        value = label.value if isinstance(label, Tag) else str(label)
        if value not in self.canary_labels or self.correlation is None:
            return False
        if self.foreign_key_used():
            # Los canarios son de la credencial registrada, no de la que se uso:
            # que falten no desmiente nada.
            return False
        if Tag.DERIVED.value in self.event_tags(event):
            return False
        group = self.correlation.group_of(event)
        return group is not None and group.content_lacks(value)

    # -- tiempo ----------------------------------------------------------
    @staticmethod
    def usable_time(event_or_ts: Event | float | None) -> float | None:
        """Devuelve la marca temporal si es comparable, o ``None``."""
        if event_or_ts is None:
            return None
        ts = event_or_ts.timestamp if isinstance(event_or_ts, Event) else float(event_or_ts)
        return ts if ts >= MIN_EPOCH else None

    def first_key_access(self) -> Event | None:
        """Primer evento que implica acceso a material privado."""
        candidates = [e for e in self.key_access_events() if self.usable_time(e) is not None]
        return min(candidates, key=lambda e: e.timestamp) if candidates else None

    def observed_key_material(self) -> bool:
        """True si la sesion llego a manejar material privado.

        Si nunca ocurrio, las reglas sobre egress de la clave no pueden
        concluir nada: el estado correcto es ``INCONCLUSIVE``, no
        ``NOT_OBSERVED``.
        """
        if self.key_access_events():
            return True
        return bool(self.events_with_tag(Tag.KEY_FILE, Tag.PRIVATE_KEY))

    def password_tag_from_other_field(self, event: Event) -> bool:
        """La etiqueta KEY_PASSWORD de esta salida solo puede venir de otro campo.

        La etiqueta nace al leer un campo de contrasena; si todas las lecturas
        anteriores a la salida son de campos que no son el de la e.firma (el
        inicio de sesion), la contrasena que viaja es esa otra.

        Solo se aplica con una llave ajena: sin canarios de la credencial en
        uso, el contenido no puede desmentir la etiqueta, y el inicio de sesion
        volveria a reportarse como "la contrasena de la e.firma salio". Con la
        credencial registrada decide el contenido, y un dato transformado sigue
        contando aunque el campo no mida lo esperado.
        """
        if not self.foreign_key_used():
            return False
        if Tag.KEY_PASSWORD.value not in self.event_tags(event):
            return False
        earlier = [e for e in self.events_of(EventType.PASSWORD_READ)
                   if e.timestamp <= event.timestamp]
        return bool(earlier) and all(self.is_other_password_read(e) for e in earlier)

    def not_key_password_egress(self, event: Event) -> bool:
        """Salida etiquetada KEY_PASSWORD que no lleva la contrasena de la e.firma."""
        return (self.contradicted(event, Tag.KEY_PASSWORD)
                or self.password_tag_from_other_field(event))

    def observed_password(self) -> bool:
        """True si la sesion llego a usar la contrasena de la e.firma."""
        if any(not self.is_other_password_read(e)
               for e in self.events_of(EventType.PASSWORD_READ)):
            return True
        return any(e.type is not EventType.PASSWORD_READ
                   and not (e.type in EGRESS_EVENTS and self.not_key_password_egress(e))
                   for e in self.events_with_tag(Tag.KEY_PASSWORD))

    def after_key_access(self, events: Iterable[Event]) -> list[Event]:
        """Filtra los eventos posteriores al primer acceso a la clave."""
        anchor = self.first_key_access()
        if anchor is None:
            return []
        start = anchor.timestamp
        out = []
        for event in events:
            ts = self.usable_time(event)
            if ts is not None and ts >= start:
                out.append(event)
        return out

    def within_window(self, events: Iterable[Event], window_ms: int | None = None) -> list[Event]:
        """Eventos dentro de la ventana de correlacion tras el acceso a la clave."""
        anchor = self.first_key_access()
        if anchor is None:
            return []
        window = (window_ms if window_ms is not None else self.config.correlation_window_ms) / 1000.0
        return [e for e in self.after_key_access(events)
                if e.timestamp - anchor.timestamp <= window]

    # -- estado de red ---------------------------------------------------
    def offline_windows(self) -> list[tuple[float, float | None]]:
        """Intervalos ``(inicio, fin)`` en los que la red estuvo aislada."""
        windows: list[tuple[float, float | None]] = []
        start: float | None = None
        for event in sorted(self.events, key=lambda e: e.timestamp):
            if event.type is EventType.NETWORK_OFF and start is None:
                start = event.timestamp
            elif event.type is EventType.NETWORK_ON and start is not None:
                windows.append((start, event.timestamp))
                start = None
        if start is not None:
            windows.append((start, None))
        return windows

    def offline_at(self, timestamp: float) -> bool:
        for start, end in self.offline_windows():
            if timestamp >= start and (end is None or timestamp <= end):
                return True
        return False

    def offline_test_ran(self) -> bool:
        return bool(self.offline_windows())

    def events_while_offline(self, events: Iterable[Event]) -> list[Event]:
        return [e for e in events if self.offline_at(e.timestamp)]

    # -- egress etiquetado -----------------------------------------------
    def canary_matches(self, event: Event) -> list[dict[str, Any]]:
        """Coincidencias de canario de la peticion, no solo de una observacion.

        El canario lo encuentra quien ve el cuerpo (CDP o proxy); la procedencia
        la conoce el agente. Unir ambas es lo que permite afirmar a la vez *que*
        salio y *de donde* venia.
        """
        if self.correlation is not None:
            return self.correlation.enriched_matches(event)
        matches = event.data.get("canary_matches")
        return list(matches) if isinstance(matches, list) else []

    def event_tags(self, event: Event) -> set[str]:
        """Etiquetas de la peticion, uniendo lo que vio cada sensor."""
        if self.correlation is not None:
            return self.correlation.enriched_tags(event)
        return set(event.tags)

    def direct_egress(self, *labels: Tag | str) -> list[Event]:
        """Egress que transporta el material *tal cual* (sin transformar).

        Dos fuentes de evidencia independientes:

        * el proxy o CDP encontraron una representacion del canario en el
          cuerpo (prueba directa: los bytes estaban ahi);
        * la instrumentacion etiqueto el dato y no lo marco como derivado.
        """
        wanted = {t.value if isinstance(t, Tag) else t for t in labels}
        out: list[Event] = []
        for event in self.egress_events():
            tags = self.event_tags(event)
            matches = self.canary_matches(event)
            if any(m.get("label") in wanted and m.get("encoding") in DIRECT_ENCODINGS for m in matches):
                out.append(event)
                continue
            if wanted & tags and Tag.DERIVED.value not in tags:
                out.append(event)
        return out

    def derived_egress(self, *labels: Tag | str) -> list[Event]:
        """Egress que transporta datos *derivados* del material indicado."""
        wanted = {t.value if isinstance(t, Tag) else t for t in labels}
        out: list[Event] = []
        for event in self.egress_events():
            tags = self.event_tags(event)
            if wanted & tags and Tag.DERIVED.value in tags:
                out.append(event)
        return out

    def any_egress(self, *labels: Tag | str) -> list[Event]:
        wanted = {t.value if isinstance(t, Tag) else t for t in labels}
        out: list[Event] = []
        for event in self.egress_events():
            if wanted & self.event_tags(event):
                out.append(event)
                continue
            if any(m.get("label") in wanted for m in self.canary_matches(event)):
                out.append(event)
        return out

    def unclassified_binary_egress(self) -> list[Event]:
        """Salidas binarias sin clasificar: candidatas a exfiltracion opaca."""
        out: list[Event] = []
        for event in self.egress_events():
            tags = self.event_tags(event)
            if tags - {Tag.UNCLASSIFIED.value}:
                continue  # ya esta clasificado por otra via
            size = int(event.data.get("body_size") or event.data.get("size") or 0)
            if size < 64:
                continue
            body_type = str(event.data.get("body_type") or "")
            content_type = str(event.data.get("content_type") or "")
            if body_type in BINARY_BODY_TYPES or "octet-stream" in content_type:
                out.append(event)
        return out

    # -- almacenamiento ---------------------------------------------------
    def storage_writes(self, store: str | None = None, labels: Sequence[Tag | str] = ()) -> list[Event]:
        wanted = {t.value if isinstance(t, Tag) else t for t in labels}
        out: list[Event] = []
        for event in self.events_of(EventType.STORAGE_WRITE):
            if store and str(event.data.get("store", "")).lower() != store.lower():
                continue
            if wanted and not (wanted & set(event.tags)):
                continue
            out.append(event)
        return out

    # -- terceros ----------------------------------------------------------
    def third_party_requests(self) -> list[dict[str, Any]]:
        return [r for r in self.requests if r.get("third_party")]

    def third_parties_after_key_access(self) -> dict[str, list[dict[str, Any]]]:
        """Dominios de tercero que recibieron trafico tras el acceso a la clave."""
        anchor = self.first_key_access()
        if anchor is None:
            return {}
        grouped: dict[str, list[dict[str, Any]]] = {}
        for request in self.third_party_requests():
            ts = self.usable_time(request.get("timestamp"))
            if ts is None or ts < anchor.timestamp:
                continue
            if self.request_blocked(request):
                # El aislamiento la aborto: el tercero no recibio nada.
                continue
            domain = request.get("registrable_domain") or domains.host_of(request.get("url", ""))
            grouped.setdefault(domain, []).append(request)
        return grouped

    def request_blocked(self, request: dict[str, Any]) -> bool:
        """True si la peticion no llego a su destino.

        Se pregunta primero a la correlacion, que sabe que abortó el
        aislamiento. Si no tiene esa peticion, decide el modo de aislamiento:
        en modo total o de terceros, un tercero emitido con la red cortada no
        pudo salir; en modo lista de permitidos solo si no estaba en la lista.
        Contar sin mas toda peticion emitida sin red, como hacia el PR #2,
        acusaria de nada a un tercero permitido y absolveria a uno que si salio.
        """
        from ..audit_core.config import IsolationMode

        if request.get("blocked"):
            return True
        if request.get("id") and request["id"] in self._blocked_request_ids():
            return True
        ts = self.usable_time(request.get("timestamp"))
        if ts is None or not self.offline_at(ts):
            return False
        policy = self.config.isolation
        if policy.mode in (IsolationMode.FULL, IsolationMode.THIRD_PARTY):
            return True
        if policy.mode is IsolationMode.ALLOWLIST:
            host = str(request.get("host") or "").split(":", 1)[0]
            return host not in {h.split(":", 1)[0] for h in policy.allow_hosts}
        return False

    def _blocked_request_ids(self) -> set[str]:
        cached = getattr(self, "_blocked_ids_cache", None)
        if cached is not None:
            return cached
        ids: set[str] = set()
        for event in self.events:
            request_id = event.data.get("request_id")
            if request_id and event.type in EGRESS_EVENTS and self.was_blocked(event):
                ids.add(str(request_id))
        self._blocked_ids_cache = ids
        return ids

    def third_party_names(self) -> dict[str, str]:
        names: dict[str, str] = {}
        for request in self.third_party_requests():
            domain = request.get("registrable_domain") or ""
            if domain and domain not in names:
                names[domain] = domains.third_party_name(request.get("url", "")) or domain
        return names

    # -- utilidades para construir evidencia ------------------------------
    @staticmethod
    def event_evidence(event: Event, note: str = "") -> dict[str, Any]:
        return {
            "type": "event",
            "event_id": event.id,
            "seq": event.seq,
            "event_type": event.type.value,
            "timestamp": round(event.timestamp, 3),
            "context": event.context,
            "source": event.source,
            "sensor": event.sensor,
            "tags": list(event.tags),
            "url": event.data.get("url", ""),
            "note": note,
        }

    @staticmethod
    def request_evidence(request: dict[str, Any], note: str = "") -> dict[str, Any]:
        return {
            "type": "request",
            "request_id": request.get("id", ""),
            "method": request.get("method", ""),
            "url": request.get("url", ""),
            "timestamp": request.get("timestamp"),
            "body_size": request.get("body_size", 0),
            "third_party": bool(request.get("third_party")),
            "note": note,
        }

    @staticmethod
    def code_evidence(path: Any, note: str = "") -> dict[str, Any]:
        return {
            "type": "code",
            "file": path.file_label,
            "url": path.url,
            "line": path.sink_line,
            "source": path.source.name,
            "sink": path.sink_name,
            "snippet": path.sink_snippet,
            "transforms": list(path.transforms),
            "call_chain": list(path.call_chain),
            "confidence": path.confidence.value,
            "note": note,
        }
