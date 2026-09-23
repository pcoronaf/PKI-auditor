"""Orquestador de una sesion de auditoria.

Une los sensores en una sola sesion y decide, segun el nivel, que se ejecuta:

===== ==================================================================
 1     observacion de red
 2     + instrumentacion del navegador y analisis estatico
 3     + prueba de firma con la red aislada
 4     + proxy y correlacion completa
===== ==================================================================

El orden importa. La prueba de aislamiento va *despues* del recorrido normal,
porque desconectar la red antes de que la aplicacion cargue no demuestra nada
sobre la firma: demuestra que la pagina no carga.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .. import __version__
from ..audit_core.config import AuditConfig, AuditLevel, CredentialMode
from ..audit_core.events import Event, EventType
from ..audit_core.secrets import SecretVault
from ..correlation_engine import CorrelationEngine
from ..evidence_store.store import EvidenceStore
from ..instrumentation_agent.loader import agent_sha256
from ..report_engine import ReportInput, write_reports
from ..rule_engine import AuditContext, RuleEngine
from ..static_analyzer import analyze_scripts

#: Prefijo de los identificadores de sesion.
SESSION_PREFIX = "FS"


def new_session_id() -> str:
    token = uuid.uuid4().hex[:8].upper()
    return f"{SESSION_PREFIX}-{token[:4]}-{token[4:]}"


@dataclass
class AuditResult:
    """Lo que una sesion deja detras."""

    session_id: str
    output_dir: Path
    findings: list[Any] = field(default_factory=list)
    correlation: Any | None = None
    static: Any | None = None
    chain_ok: bool | None = None
    reports: dict[str, Path] = field(default_factory=dict)
    error: str = ""
    credentials_note: str = ""
    proxy_note: str = ""

    def actionable(self) -> list[Any]:
        return [f for f in self.findings
                if f.status.value in ("CONFIRMED", "OBSERVED", "POTENTIAL")]


class Auditor:
    """Ejecuta una sesion completa y escribe el expediente."""

    def __init__(self, config: AuditConfig, session_id: str | None = None,
                 on_event: Callable[[Event], None] | None = None):
        self.config = config
        self.session_id = session_id or new_session_id()
        self.on_event = on_event
        self.output_dir = Path(config.output_dir) / self.session_id
        self.vault = SecretVault()
        self.store = EvidenceStore(self.output_dir, self.session_id, vault=self.vault)
        self.credential: Any | None = None
        self.credentials_note = ""
        self.proxy: Any | None = None
        self.proxy_addon: Any | None = None
        self.proxy_note = ""

    # ------------------------------------------------------------------
    def run(self, dwell: float = 6.0, offline_dwell: float = 6.0) -> AuditResult:
        """Recorre el objetivo y produce el expediente y los reportes."""
        result = AuditResult(session_id=self.session_id, output_dir=self.output_dir)
        controller = None
        try:
            controller = self._browse(dwell, offline_dwell)
        except Exception as exc:
            result.error = f"{type(exc).__name__}: {exc}"
        finally:
            if controller is not None:
                try:
                    controller.stop()
                except Exception:  # pragma: no cover - cierre best-effort
                    pass
            # El proxy se detiene despues del navegador, para no cortar sus
            # ultimas peticiones, y siempre: su parada destruye la CA efimera.
            self._stop_proxy()

        result.credentials_note = self.credentials_note
        result.proxy_note = self.proxy_note
        try:
            result = self._analyze(result)
        finally:
            # La clave de sesion del vault se destruye siempre, incluso si el
            # analisis fallo: es material sensible con vida util acabada.
            self.vault.destroy()
            self.store.close_session()
            self.store.close()
        return result

    # ------------------------------------------------------------------
    def _browse(self, dwell: float, offline_dwell: float):
        """Recorre el objetivo con el navegador instrumentado."""
        from ..browser_controller.controller import BrowserController

        self._start_proxy()
        controller = BrowserController(
            self.config, self.session_id, self.store, self._emit, self.vault)
        controller.start()

        self.store.open_session(
            self.config.target, self.config.to_dict(),
            {"firmascope": __version__, "agent_sha256": agent_sha256(),
             **controller.versions()},
            note=self.config.note,
        )
        self._emit(Event(type=EventType.SESSION_START, session=self.session_id,
                         sensor="orchestrator", data={"target": self.config.target}))

        controller.goto(self.config.target)
        controller.checkpoint("pagina-cargada", "recorrido inicial")
        self._wait(controller, 1.0)
        controller.screenshot("cargada")

        self._provide_credentials(controller)
        self._wait(controller, dwell)
        controller.screenshot("tras-firmar")

        if self.config.offline_test:
            self._offline_test(controller, offline_dwell)

        controller.collect_scripts()
        self._emit(Event(type=EventType.SESSION_END, session=self.session_id,
                         sensor="orchestrator", data={}))
        return controller

    def _provide_credentials(self, controller) -> None:
        """Entrega credenciales sinteticas al sitio y dispara la firma.

        Esto es lo que hace observable el resto de la auditoria: hasta que el
        navegador maneja material privado, casi todas las reglas solo pueden
        decir ``INCONCLUSIVE``.

        El material se registra en el vault *antes* de entregarlo, para que
        cada una de sus representaciones (bruta, base64, hex...) este
        disponible como canario cuando los sensores examinen el trafico.
        """
        from ..browser_controller import forms
        from ..credentials import generator

        if self.config.credential_mode is not CredentialMode.SYNTHETIC:
            self.credentials_note = (
                "El operador aporta las credenciales; FirmaScope no rellena el formulario.")
            return

        credential = generator.generate()
        credential.write(self.output_dir / "credentials", stem="lab")
        credential.register(self.vault)
        self.credential = credential

        form = forms.detect(controller.page)
        if not form.usable:
            self.credentials_note = (
                "No se reconocio el formulario de firma: "
                + "; ".join(form.notes)
                + ". Usa --headed para conducir la sesion a mano."
            )
            controller.checkpoint("credenciales-no-entregadas", self.credentials_note)
            return

        forms.provide(controller.page, credential, form)
        controller.checkpoint("credenciales-entregadas",
                              "clave sintetica y contrasena introducidas en el formulario")
        clicked = forms.submit(controller.page, form)
        controller.checkpoint(
            "firma-solicitada" if clicked else "firma-no-disparada",
            "se pulso el boton de firma" if clicked
            else "no se encontro un boton de firma que pulsar")
        self.credentials_note = "Credenciales sinteticas entregadas al sitio."

    # ------------------------------------------------------------------
    # Proxy (nivel 4)
    # ------------------------------------------------------------------
    def _start_proxy(self) -> None:
        """Interpone mitmproxy si el nivel y la configuracion lo piden.

        Si no esta disponible, la sesion sigue con tres sensores y el
        manifiesto lo refleja: ``proxy.enabled`` queda en falso. Nunca se
        finge un sensor que no corrio.
        """
        if self.config.level < AuditLevel.FULL_CORRELATED or not self.config.proxy.enabled:
            return
        from ..proxy_addon import FirmaScopeAddon, ProxyServer, ProxyUnavailable

        self.proxy_addon = FirmaScopeAddon(
            self.session_id, self.config, vault=self.vault,
            capture_bodies=self.config.capture_bodies or self.config.proxy.capture_bodies)
        try:
            self.proxy = ProxyServer(self.proxy_addon, host=self.config.proxy.host,
                                     port=self.config.proxy.port).start()
        except ProxyUnavailable as exc:
            self.proxy = None
            self.proxy_addon = None
            self.config.proxy.enabled = False
            self.proxy_note = f"Proxy no disponible: {exc}. La sesion continuo sin el."
            return
        self.config.proxy.port = self.proxy.port
        self.proxy_note = f"Proxy de interceptacion activo en {self.proxy.url} (CA efimera)."

    def _drain_proxy(self) -> None:
        if self.proxy_addon is not None:
            self.proxy_addon.drain(self.store, self._emit)

    def _stop_proxy(self) -> None:
        if self.proxy is not None:
            try:
                self.proxy.stop()
            except Exception:  # pragma: no cover - cierre best-effort
                pass
        self._drain_proxy()
        self.proxy = None

    def _wait(self, controller, seconds: float) -> None:
        """Espera observando: el navegador drena agente y CDP, aqui el proxy."""
        controller.wait(seconds)
        self._drain_proxy()

    def _offline_test(self, controller, dwell: float) -> None:
        """Nivel 3: aislar la red y ver si la firma se completa igualmente.

        Se ejecuta al final, cuando la aplicacion ya cargo: desconectar antes
        solo demostraria que la pagina necesita red para cargar.
        """
        controller.checkpoint("antes-de-aislar", "fin del recorrido en linea")
        controller.set_offline(True, reason="prueba de firma local (nivel 3)")
        self._wait(controller, dwell)
        controller.screenshot("aislada")
        controller.checkpoint("durante-aislamiento", "red del navegador desconectada")
        controller.set_offline(False, reason="fin de la prueba de aislamiento")

    # ------------------------------------------------------------------
    def _analyze(self, result: AuditResult) -> AuditResult:
        """Analisis estatico, correlacion, reglas y reportes."""
        events = self.store.events()
        requests = self.store.requests()
        scripts = self.store.scripts()
        checkpoints = self.store.checkpoints()

        if self.config.static_analysis:
            result.static = analyze_scripts(
                scripts, lambda s: self.store.script_body(s.get("sha256", "")))

        result.correlation = CorrelationEngine(self.config).run(events, requests)

        engine = RuleEngine(extra_dirs=self.config.rules_dirs)
        context = AuditContext(
            config=self.config, events=events, requests=requests, scripts=scripts,
            checkpoints=checkpoints, static=result.static, correlation=result.correlation,
            canary_labels=self.vault.labels if self.vault.alive else set(),
        )
        result.findings = engine.evaluate(context)
        for finding in result.findings:
            self.store.add_finding(finding)

        ok, _ = self.store.verify_chain()
        result.chain_ok = ok

        try:
            result.reports = write_reports(
                ReportInput(
                    config=self.config,
                    session=self.store.session_info(),
                    findings=[f.to_dict() for f in result.findings],
                    correlation=result.correlation,
                    static=result.static,
                    requests=requests,
                    scripts=scripts,
                    checkpoints=checkpoints,
                    events=[e.to_dict() for e in events],
                    catalog=engine.catalog(),
                    chain_head=self.store.chain_head,
                    chain_ok=ok,
                    agent_sha256=agent_sha256(),
                ),
                self.output_dir,
                vault=self.vault if self.vault.alive else None,
            )
        except AssertionError as exc:
            # assert_no_secrets es la ultima barrera: si algo sensible llego
            # hasta el reporte, no se escribe. Se registra como error de la
            # sesion (el mensaje solo nombra etiqueta y codificacion) en lugar
            # de perder el resultado entero.
            result.reports = {}
            result.error = f"El reporte no se escribio: {exc}"
        return result

    # ------------------------------------------------------------------
    def _emit(self, event: Event) -> None:
        stored = self.store.add_event(event)
        if self.on_event is not None:
            self.on_event(stored)


def audit(target: str, level: AuditLevel | int | str = 4, **options: Any) -> AuditResult:
    """Atajo programatico equivalente a ``firmascope audit``."""
    config = AuditConfig(target=target, level=AuditLevel.parse(level), **options)
    return Auditor(config).run()
