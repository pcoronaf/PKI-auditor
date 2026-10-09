"""Control de un Chromium limpio por sesion.

Responsabilidades (FR-001, FR-007, FR-011):

* perfil efimero, sin estado heredado entre sesiones;
* inyeccion temprana del agente de instrumentacion, antes del JS del sitio;
* auto-adjuncion a nuevos contextos (iframes, workers, service workers);
* control del estado de red sin cerrar el navegador;
* inventario de scripts tal y como los parsea el motor (incluye inline y eval).
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections import deque
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from playwright.sync_api import Browser, BrowserContext, Page, Playwright, sync_playwright

from ..audit_core.config import AuditConfig
from ..audit_core.events import Event, EventType
from ..audit_core.secrets import SecretVault
from ..evidence_store.store import EvidenceStore, ScriptRecord
from ..instrumentation_agent.loader import (
    DEFAULT_CHANNEL,
    WORKER_MARK,
    build_init_script,
    record_to_event,
)
from ..network_analyzer import domains
from ..network_analyzer.cdp_observer import NetworkObserver
from .isolation import NetworkIsolation, Stage, StagedOfflineTest, stages_for


class BrowserController:
    """Envoltura de Playwright orientada a auditoria."""

    def __init__(self, config: AuditConfig, session_id: str, store: EvidenceStore,
                 emit: Callable[[Event], None], vault: SecretVault | None = None,
                 session_state: dict[str, Any] | None = None):
        self.config = config
        #: Estado autenticado, ya leido y protegido en el vault por la sesion.
        self.session_state = session_state
        self.session_id = session_id
        self.store = store
        self.emit = emit
        self.vault = vault

        self._playwright: Playwright | None = None
        self.browser: Browser | None = None
        self.context: BrowserContext | None = None
        self.page: Page | None = None
        self.observer: NetworkObserver | None = None
        self.isolation: NetworkIsolation | None = None
        self.proxy: Any | None = None

        self.browser_version = ""
        self._frame_names: dict[Any, str] = {}
        self._frame_counter = 0
        self._worker_counter = 0
        self._script_ids: deque[tuple[Any, str, str]] = deque()
        self._seen_scripts: set[str] = set()
        self._cdp_sessions: list[Any] = []
        self._pages: list[Page] = []

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------
    def start(self) -> "BrowserController":
        self._playwright = sync_playwright().start()
        from .launch import launch_chromium

        launch_kwargs: dict[str, Any] = {
            "headless": self.config.headless,
            "args": list(self.config.browser_args),
            "executable_path": self.config.browser_path,
            "sandbox": self.config.sandbox,
        }

        # El proxy arranca antes del navegador: su puerto se elige en tiempo de
        # ejecucion y el navegador lo necesita en la linea de comandos.
        self._start_proxy()
        if self.proxy is not None and self.proxy.running:
            launch_kwargs["proxy"] = {"server": self.proxy.server}
            # Chromium no envia el trafico de loopback al proxy salvo que se le
            # diga: sin esto, un portal servido en 127.0.0.1 -- el laboratorio,
            # o un entorno de preproduccion local -- quedaria sin observar y el
            # silencio se leeria como ausencia de trafico.
            launch_kwargs["args"] = list(launch_kwargs["args"]) + [
                "--proxy-bypass-list=<-loopback>"]
        self.browser = launch_chromium(self._playwright, **launch_kwargs)
        self.browser_version = self.browser.version

        context_kwargs: dict[str, Any] = {
            "viewport": {"width": self.config.viewport[0], "height": self.config.viewport[1]},
            # El perfil es efimero: Playwright crea un directorio temporal por
            # contexto y lo destruye al cerrarlo.
        }
        if self.proxy is not None and self.proxy.running:
            # La CA de auditoria solo se acepta durante la sesion; no se instala
            # en el almacen de certificados del sistema. El contexto muere con
            # la sesion, y con el la excepcion.
            context_kwargs["ignore_https_errors"] = True
        if self.session_state is not None:
            # Se pasa el estado ya leido, no la ruta: asi el fichero se abre
            # una sola vez, y lo que entra al navegador es exactamente lo que
            # se protegio en el vault.
            context_kwargs["storage_state"] = self.session_state
        self.context = self.browser.new_context(**context_kwargs)
        self.context.set_default_timeout(30_000)

        if self.config.instrumentation:
            self.context.expose_binding(DEFAULT_CHANNEL, self._on_agent_record)
            self.context.add_init_script(self._init_script())
            # Los workers se instrumentan interceptando la descarga de su script
            # (ver `workerTarget` en agent.js): asi conservan su URL real.
            # Cargarlos desde un blob: rompia toda ruta relativa dentro del
            # worker, y la auditoria observaba un sitio roto en lugar del real.
            # Portado del PR #2.
            self.context.route(re.compile(rf"[?&]{WORKER_MARK}=1"), self._on_worker_script)
        # En nivel 1 la pagina corre sin el agente: es la prueba de control de
        # "la instrumentacion no altera el sitio". En el segundo piloto, "Solo
        # red" seguia inyectandolo, y no habia forma de descartar que el agente
        # fuera la causa de que el portal se colgara.

        self.observer = NetworkObserver(self.session_id, self.store, self.config, self.emit, self.vault)
        self.isolation = NetworkIsolation(
            self.context, self.config, self.emit, self.session_id,
            vault=self.vault, store=self.store)

        self.context.on("page", self._on_page)
        self.context.on("serviceworker", self._on_service_worker)

        self.page = self.context.new_page()
        self._register_page(self.page)
        return self

    def _init_script(self) -> str:
        return build_init_script(
            self.session_id, DEFAULT_CHANNEL,
            redact_names=bool(getattr(self.config.privacy, "redact_filenames", False)),
            worker_routing=True)

    def _on_worker_script(self, route) -> None:
        """Antepone el agente al script de un worker marcado por el agente.

        El script se pide al servidor sin la marca, de modo que el sitio ve
        exactamente la peticion que habria hecho. Si algo falla, la peticion
        sigue su curso sin instrumentar: un worker sin observar es preferible a
        un worker roto, y el evento de error lo deja dicho en el expediente.
        """
        original = strip_worker_mark(route.request.url)
        try:
            response = route.fetch(url=original)
            if not response.ok:
                route.fulfill(response=response)
                return
            headers = {k: v for k, v in response.headers.items()
                       if k.lower() not in ("content-length", "content-encoding")}
            route.fulfill(status=response.status, headers=headers,
                          body=self._init_script().encode("utf-8") + b"\n;\n" + response.body())
        except Exception as exc:
            self.emit(Event(EventType.AGENT_ERROR, self.session_id, sensor="browser",
                            data={"kind": "worker-route", "url": original,
                                  "error": str(exc)[:200]}))
            try:
                route.continue_(url=original)
            except Exception:  # pragma: no cover - la ruta ya se resolvio
                pass

    def stop(self) -> None:
        self.drain_agent()
        self.pump()
        if self.proxy is not None:
            # Antes de cerrar el navegador: para y destruye la CA efimera.
            try:
                self.proxy.stop()
            except Exception:  # pragma: no cover - cierre best-effort
                pass
        for closer in (self.context, self.browser):
            try:
                if closer is not None:
                    closer.close()
            except Exception:  # pragma: no cover - cierre best-effort
                pass
        if self._playwright is not None:
            try:
                self._playwright.stop()
            except Exception:  # pragma: no cover
                pass

    def __enter__(self) -> "BrowserController":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    # ------------------------------------------------------------------
    # Registro de contextos
    # ------------------------------------------------------------------
    def _register_page(self, page: Page) -> None:
        if page in self._pages:
            return
        self._pages.append(page)
        name = "main" if len(self._pages) == 1 else f"page-{len(self._pages)}"
        self._frame_names[page.main_frame] = name
        page.on("worker", self._on_worker)
        page.on("frameattached", self._on_frame_attached)
        page.on("console", self._on_console)
        # Tambien cuenta como navegacion exitosa la que hace el operador a mano
        # en modo headful: sin esto, aislar se negaria por falta de carga previa.
        page.on("load", self._on_page_load)
        page.on("pageerror", lambda err: self.emit(Event(
            EventType.AGENT_ERROR, self.session_id, sensor="browser",
            data={"kind": "pageerror", "message": str(err)[:300]})))
        if self.observer is not None:
            try:
                self.observer.attach(page, name)
            except Exception as exc:  # pragma: no cover - degradacion elegante
                self.emit(Event(EventType.AGENT_ERROR, self.session_id, sensor="cdp",
                                data={"error": f"no se pudo adjuntar CDP: {exc}"[:300]}))
        self._attach_debugger(page, name)

    def _on_page(self, page: Page) -> None:
        self._register_page(page)
        self.emit(Event(EventType.CONTEXT_CREATED, self.session_id, sensor="browser",
                        data={"kind": "page", "url": page.url}))

    def _on_frame_attached(self, frame) -> None:
        self._frame_counter += 1
        name = f"iframe-{self._frame_counter}"
        self._frame_names[frame] = name
        self.emit(Event(EventType.CONTEXT_CREATED, self.session_id, context=name, sensor="browser",
                        data={"kind": "iframe", "url": frame.url}))

    def _on_worker(self, worker) -> None:
        self._worker_counter += 1
        name = f"worker-{self._worker_counter}"
        self.emit(Event(EventType.CONTEXT_CREATED, self.session_id, context=name, sensor="browser",
                        data={"kind": "worker", "url": worker.url}))

    def _on_service_worker(self, worker) -> None:
        self.emit(Event(EventType.CONTEXT_CREATED, self.session_id, context="service-worker",
                        sensor="browser", data={"kind": "service-worker", "url": worker.url}))

    def _on_page_load(self, page) -> None:
        if self.isolation is not None:
            self.isolation.navigation_succeeded = True

    def _on_console(self, message) -> None:
        if message.type in ("error", "warning"):
            self.emit(Event(EventType.AGENT_ERROR, self.session_id, sensor="browser",
                            data={"kind": f"console.{message.type}", "message": message.text[:300]}))

    # ------------------------------------------------------------------
    # Canal del agente
    # ------------------------------------------------------------------
    def _on_agent_record(self, source: dict[str, Any], payload: str) -> None:
        try:
            record = json.loads(payload)
        except Exception:
            return
        frame = source.get("frame") if isinstance(source, dict) else None
        hint = ""
        if frame is not None:
            hint = self._frame_names.get(frame, "")
            if not hint:
                self._frame_counter += 1
                hint = f"iframe-{self._frame_counter}"
                self._frame_names[frame] = hint
        context = record.get("ctx") or "main"
        if hint and context in ("main", "iframe"):
            context = hint
        self.emit(record_to_event(record, self.session_id, context))

    def drain_agent(self) -> int:
        """Vacia la cola interna del agente en todos los contextos accesibles."""
        drained = 0
        for page in list(self._pages):
            try:
                if page.is_closed():
                    continue
                for frame in page.frames:
                    try:
                        records = frame.evaluate(
                            "() => (globalThis.__FIRMASCOPE__ ? globalThis.__FIRMASCOPE__.drain() : [])"
                        )
                    except Exception:
                        continue
                    name = self._frame_names.get(frame, "main" if frame is page.main_frame else "iframe")
                    for record in records or []:
                        self.emit(record_to_event(record, self.session_id, record.get("ctx") or name))
                        drained += 1
            except Exception:  # pragma: no cover
                continue
        return drained

    def pump(self) -> int:
        """Procesa lo pendiente de CDP y del proxy.

        Ambos sensores producen en otros hilos o en callbacks, y solo este punto
        escribe en el expediente: asi la cadena de hashes conserva un orden
        unico y verificable.
        """
        drained = self.observer.pump() if self.observer else 0
        if self.proxy is not None and self.proxy.running:
            drained += self.proxy.pump()
        return drained

    # ------------------------------------------------------------------
    def _start_proxy(self) -> None:
        """Arranca el proxy de interceptacion si el nivel lo pide.

        Que mitmproxy no este instalado no invalida la auditoria: se registra
        que ese sensor falta y la sesion continua con los otros tres. Lo que no
        se puede hacer es seguir como si estuviera, porque entonces la ausencia
        de hallazgos de contenido no significaria nada.
        """
        if not self.config.proxy_enabled:
            return
        from ..proxy_addon.runner import ProxyRunner

        runner = ProxyRunner(self.config, self.session_id, self.store,
                             self.emit, self.vault)
        if runner.start():
            self.proxy = runner
            return
        self.emit(Event(EventType.CHECKPOINT, self.session_id, sensor="proxy",
                        data={"name": "proxy-unavailable", "detail": runner.error,
                              "consequence": "La sesion continua sin interceptacion "
                                             "TLS: los cuerpos que CDP no entregue "
                                             "(multipart, flujos) no se podran "
                                             "examinar por contenido."}))
        self.proxy = runner  # se conserva para que el reporte explique la ausencia

    def wait(self, seconds: float, poll: float = 0.2) -> None:
        """Espera procesando eventos (no bloquea la captura)."""
        deadline = time.time() + seconds
        while time.time() < deadline:
            if self.page is not None and not self.page.is_closed():
                try:
                    self.page.wait_for_timeout(poll * 1000)
                except Exception:
                    time.sleep(poll)
            else:
                time.sleep(poll)
            self.pump()

    # ------------------------------------------------------------------
    # Navegacion y control de red
    # ------------------------------------------------------------------
    def goto(self, url: str, wait_until: str = "load", timeout: float = 30_000) -> None:
        assert self.page is not None
        if self.offline:
            # Navegar con la red aislada deja una pagina en blanco. Es la causa
            # habitual del sintoma "no carga la pagina" al reordenar las etapas.
            self.emit(Event(
                EventType.AGENT_ERROR, self.session_id, sensor="controller",
                data={"kind": "navigation-while-isolated", "url": url,
                      "error": "se esta navegando con la red aislada; la carga fallara. "
                               "Restablezca la red (etapa ONLINE) antes de navegar"}))
        try:
            self.page.goto(url, wait_until=wait_until, timeout=timeout)
            if self.isolation is not None:
                self.isolation.navigation_succeeded = True
        except Exception as exc:
            self.emit(Event(EventType.AGENT_ERROR, self.session_id, sensor="browser",
                            data={"kind": "navigation", "url": url, "error": str(exc)[:300]}))
        self.pump()

    @property
    def offline(self) -> bool:
        """True si la red del navegador esta aislada ahora mismo."""
        return self.isolation is not None and self.isolation.engaged

    def preload(self, timeout: float | None = None) -> bool:
        """Espera a que la red se calme, para poder aislar sin romper la pagina."""
        if self.isolation is None:
            return False
        return self.isolation.preload(self.page, timeout)

    def set_offline(self, offline: bool, reason: str = "") -> bool:
        """Aisla o restablece la red sin cerrar el navegador (FR-007).

        El aislamiento aborta las peticiones nuevas en lugar de apagar la pila
        de red: la pagina ya cargada sigue operativa y cada intento de salida
        queda registrado como evidencia. Devuelve el estado efectivo.
        """
        if self.isolation is None:
            return False
        if offline:
            if self.config.isolation.preload_before_isolating:
                self.isolation.preload(self.page)
            return self.isolation.engage(reason)
        return self.isolation.release(reason)

    def staged_offline_test(self, stages: list[Stage] | None = None) -> StagedOfflineTest:
        """Crea la prueba de firma por etapas sobre esta sesion."""
        if self.isolation is None:
            raise RuntimeError("el navegador no esta iniciado")
        return StagedOfflineTest(
            self, self.isolation, self.emit, self.session_id,
            stages=stages or stages_for(self.config))

    def checkpoint(self, name: str, detail: str = "") -> dict:
        record = self.store.add_checkpoint(
            name=name, network="OFFLINE" if self.offline else "ONLINE", detail=detail)
        self.emit(Event(EventType.CHECKPOINT, self.session_id, sensor="controller",
                        data={"name": name, "network": record["network"], "detail": detail}))
        return record

    def screenshot(self, name: str) -> dict | None:
        if not self.config.screenshots or self.page is None or self.page.is_closed():
            return None
        try:
            payload = self.page.screenshot(full_page=False)
        except Exception:  # pragma: no cover
            return None
        return self.store.add_evidence("screenshot", f"{name}.png", payload, subdir="screenshots")

    # ------------------------------------------------------------------
    # Inventario de scripts
    # ------------------------------------------------------------------
    def _attach_debugger(self, page: Page, context_name: str) -> None:
        """Usa el dominio Debugger para inventariar el codigo realmente parseado."""
        if not self.config.static_analysis:
            return
        try:
            cdp = page.context.new_cdp_session(page)
            self._cdp_sessions.append(cdp)
            cdp.on("Debugger.scriptParsed",
                   lambda params: self._script_ids.append((cdp, params.get("scriptId", ""), params.get("url", ""))))
            cdp.send("Debugger.enable", {})
        except Exception as exc:  # pragma: no cover
            self.emit(Event(EventType.AGENT_ERROR, self.session_id, sensor="cdp",
                            data={"error": f"Debugger no disponible: {exc}"[:200]}))

    def collect_scripts(self) -> list[ScriptRecord]:
        """Descarga el codigo fuente de los scripts parseados por el motor."""
        collected: list[ScriptRecord] = []
        pending = list(self._script_ids)
        self._script_ids.clear()
        for cdp, script_id, url in pending:
            if not script_id:
                continue
            if url.startswith(("chrome-extension:", "extensions::")):
                continue
            try:
                result = cdp.send("Debugger.getScriptSource", {"scriptId": script_id})
            except Exception:
                continue
            body = (result or {}).get("scriptSource") or ""
            if not body.strip():
                continue
            if "FirmaScope - Instrumentation Agent" in body[:4000]:
                continue  # el propio agente
            data = body.encode("utf-8", "replace")
            digest = hashlib.sha256(data).hexdigest()
            if digest in self._seen_scripts:
                continue
            self._seen_scripts.add(digest)
            inline = not url or url == (self.page.url if self.page else "")
            record = ScriptRecord(
                url=url or f"inline:{self.page.url if self.page else ''}",
                sha256=digest,
                size=len(data),
                third_party=bool(url) and domains.is_third_party(
                    url, self.config.target, self.config.first_party_domains),
                inline=inline,
                sourcemap=_sourcemap_url(body),
            )
            self.store.add_script(record, data)
            collected.append(record)
            self.emit(Event(EventType.SCRIPT_LOADED, self.session_id, sensor="cdp",
                            data={"url": record.url, "sha256": digest, "size": record.size,
                                  "third_party": record.third_party, "inline": inline,
                                  "sourcemap": record.sourcemap}))
        return collected

    # ------------------------------------------------------------------
    def versions(self) -> dict[str, str]:
        info = {
            "browser": self.browser_version,
            "browser_path": self.config.browser_path or "(playwright default)",
        }
        if self.proxy is not None:
            from ..proxy_addon.runner import version as mitm_version
            info["mitmproxy"] = mitm_version() or "(no instalado)"
        return info

    def proxy_summary(self) -> dict[str, Any]:
        """Estado del sensor de proxy, incluido el caso de que no exista."""
        if self.proxy is None:
            return {"enabled": False,
                    "detail": "nivel inferior a 4, o proxy desactivado"}
        return self.proxy.summary()


def _sourcemap_url(body: str) -> str:
    tail = body[-2048:]
    for marker in ("//# sourceMappingURL=", "//@ sourceMappingURL="):
        index = tail.rfind(marker)
        if index >= 0:
            return tail[index + len(marker):].split("\n", 1)[0].strip()[:300]
    return ""


def strip_worker_mark(url: str) -> str:
    """Quita la marca ``__fs_worker=1`` y deja el resto de la URL intacto."""
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
             if k != WORKER_MARK]
    return urlunsplit(parts._replace(query=urlencode(query, doseq=True)))
