"""Orquestador de una sesion de auditoria.

Coordina navegador, instrumentacion, analisis estatico, reglas, evidencias y
reporte. La CLI (y en el futuro la interfaz grafica) solo decide *cuando*
avanzar; el orden y las invariantes viven aqui.

Invariantes que esta clase garantiza:

* el vault de secretos se destruye siempre al terminar, incluso si algo falla;
* la red se restablece siempre antes de cerrar el navegador;
* el expediente se escribe aunque la sesion se cancele a medias: una auditoria
  interrumpida sigue siendo evidencia de lo que se observo hasta ese punto.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .. import __version__
from ..credentials import generator as credentials
from ..evidence_store.store import EvidenceStore, Finding
from ..instrumentation_agent.loader import agent_sha256
from .config import AuditConfig, CredentialMode, environment_info
from .events import Event, EventType
from .secrets import SecretVault


def new_session_id(output_dir: Path, now: time.struct_time | None = None) -> str:
    """Identificador legible y ordenable: ``FS-2026-0012``."""
    stamp = now or time.localtime()
    year = stamp.tm_year
    output_dir = Path(output_dir)
    existing = 0
    if output_dir.is_dir():
        existing = sum(1 for child in output_dir.iterdir()
                       if child.is_dir() and child.name.startswith(f"FS-{year}-"))
    return f"FS-{year}-{existing + 1:04d}"


@dataclass
class SessionStats:
    events: int = 0
    requests: int = 0
    scripts: int = 0
    blocked: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"events": self.events, "requests": self.requests,
                "scripts": self.scripts, "blocked_attempts": self.blocked}


class AuditSession:
    """Una sesion completa, de principio a expediente."""

    def __init__(self, config: AuditConfig,
                 on_event: Callable[[Event], None] | None = None,
                 session_id: str | None = None):
        self.config = config
        self.session_id = session_id or new_session_id(config.output_dir)
        self.root = Path(config.output_dir) / self.session_id
        self.vault = SecretVault()
        self.store = EvidenceStore(self.root, self.session_id, self.vault, config.privacy)
        self.credential: credentials.AuditCredential | None = None
        self.controller: Any | None = None
        self.static_report: Any | None = None
        self.findings: list[Finding] = []
        self.stats = SessionStats()
        self._on_event = on_event
        self._started_at = time.time()
        self._closed = False

        if on_event is not None:
            self.store.subscribe(on_event)

    # ------------------------------------------------------------------
    def emit(self, event: Event) -> Event:
        stored = self.store.add_event(event)
        self.stats.events += 1
        return stored

    # ------------------------------------------------------------------
    # Credenciales
    # ------------------------------------------------------------------
    def prepare_credentials(self, key_path: Path | None = None,
                            cert_path: Path | None = None,
                            password: str | None = None,
                            credentials_dir: Path | None = None) -> credentials.AuditCredential | None:
        """Prepara la credencial segun el modo configurado y la registra.

        Las representaciones buscables van al vault, que es memoria y nada mas.
        Es lo que permite detectar la transmision del material sin guardarlo.
        """
        mode = self.config.credential_mode
        if mode is CredentialMode.NONE:
            self.emit(Event(EventType.CHECKPOINT, self.session_id, sensor="orchestrator",
                            data={"name": "credentials", "mode": mode.value,
                                  "detail": "el operador aporta el material manualmente; "
                                            "sin canarios no hay deteccion por contenido"}))
            return None

        if mode is CredentialMode.SYNTHETIC:
            credential = credentials.generate()
            target_dir = Path(credentials_dir or (Path.cwd() / "fixtures" / "synthetic-efirma"))
            credential.write(target_dir)
        else:
            if not key_path or not cert_path or password is None:
                raise ValueError(
                    f"el modo '{mode.value}' requiere --key, --cert y la contrasena")
            if mode is CredentialMode.REAL:
                credential = credentials.load_real(Path(key_path), Path(cert_path), password)
            else:
                credential = credentials.load(Path(key_path), Path(cert_path), password,
                                              synthetic=False)

        credential.register(self.vault)
        self.credential = credential
        self.emit(Event(EventType.CHECKPOINT, self.session_id, sensor="orchestrator",
                        data={"name": "credentials", "mode": mode.value,
                              **credential.describe(self.config.privacy)}))
        return credential

    # ------------------------------------------------------------------
    # Navegador
    # ------------------------------------------------------------------
    def start_browser(self) -> Any:
        from ..browser_controller.controller import BrowserController

        self.controller = BrowserController(
            self.config, self.session_id, self.store, self.emit, self.vault).start()
        self.store.open_session(
            target=self.config.target or "(sin objetivo: lo proporciona el operador)",
            config=self.config.to_dict(),
            versions=self.versions(),
            note=self.config.note,
        )
        self.emit(Event(EventType.SESSION_START, self.session_id, sensor="orchestrator",
                        data={"session": self.session_id,
                              "target": self.config.target,
                              "level": int(self.config.level),
                              "credential_mode": self.config.credential_mode.value}))
        return self.controller

    def navigate(self, url: str) -> str:
        """Abre una URL, fijando el objetivo si aun no habia ninguno."""
        if self.controller is None:
            raise RuntimeError("el navegador no esta iniciado")
        resolved = self.config.set_target(url)
        self.controller.goto(resolved)
        self.emit(Event(EventType.NAVIGATION, self.session_id, sensor="orchestrator",
                        data={"url": resolved, "kind": "operator",
                              "is_target": resolved == self.config.target}))
        return resolved

    # ------------------------------------------------------------------
    # Analisis y reglas
    # ------------------------------------------------------------------
    def collect_and_analyze(self) -> Any:
        """Recoge los scripts y ejecuta el analisis estatico (nivel 2+)."""
        if self.controller is None:
            return None
        self.controller.drain_agent()
        self.controller.pump()
        collected = self.controller.collect_scripts()
        self.stats.scripts += len(collected)
        if not self.config.static_analysis:
            return None

        from ..static_analyzer.analyzer import analyze_scripts

        def read_body(script: dict[str, Any]) -> bytes | None:
            return self.store.script_body(script.get("sha256", ""))

        self.static_report = analyze_scripts(self.store.scripts(), read_body)
        return self.static_report

    def evaluate(self) -> list[Finding]:
        """Ejecuta el motor de reglas sobre todo lo observado."""
        from ..rule_engine.context import AuditContext
        from ..rule_engine.engine import RuleEngine

        context = AuditContext(
            config=self.config,
            events=self.store.events(),
            requests=self.store.requests(),
            scripts=self.store.scripts(),
            checkpoints=self.store.checkpoints(),
            static=self.static_report,
            canary_labels=self.vault.labels if self.vault.alive else set(),
        )
        engine = RuleEngine(extra_dirs=self.config.rules_dirs)
        self.findings = engine.evaluate(context)
        for finding in self.findings:
            self.store.add_finding(finding)
        return self.findings

    # ------------------------------------------------------------------
    def versions(self) -> dict[str, Any]:
        info: dict[str, Any] = {
            "firmascope": __version__,
            "agent_sha256": agent_sha256(),
            **environment_info(),
        }
        if self.controller is not None:
            info.update(self.controller.versions())
        return info

    def isolation_summary(self) -> dict[str, Any]:
        if self.controller is None or self.controller.isolation is None:
            return {}
        summary = self.controller.isolation.summary()
        self.stats.blocked = summary.get("blocked_count", 0)
        return summary

    # ------------------------------------------------------------------
    def finish(self, aborted: bool = False, reason: str = "") -> Path:
        """Cierra la sesion y escribe el expediente. Idempotente."""
        if self._closed:
            return self.root
        self._closed = True

        try:
            if self.controller is not None:
                # La red se restablece antes de cerrar: nunca se deja el
                # navegador aislado por un corte que nadie deshizo.
                if self.controller.isolation is not None:
                    self.controller.isolation.reconcile("ONLINE", "cierre de sesion")
                self.controller.drain_agent()
                self.controller.pump()
        except Exception:  # pragma: no cover - el cierre no debe fallar
            pass

        self.emit(Event(EventType.SESSION_END, self.session_id, sensor="orchestrator",
                        data={"aborted": aborted, "reason": reason,
                              "duration_s": round(time.time() - self._started_at, 3),
                              **self.stats.to_dict()}))

        isolation = self.isolation_summary()
        try:
            if self.controller is not None:
                self.controller.stop()
        except Exception:  # pragma: no cover
            pass

        from ..report_engine.exporter import write_package

        self.store.close_session()
        package = write_package(
            store=self.store,
            config=self.config,
            session_id=self.session_id,
            versions=self.versions(),
            static_report=self.static_report,
            isolation=isolation,
            credential=self.credential,
            aborted=aborted,
            abort_reason=reason,
        )
        self.store.close()
        # El vault muere con la sesion: la clave de correlacion y las
        # representaciones de los canarios no sobreviven al proceso.
        self.vault.destroy()
        return package

    def __enter__(self) -> "AuditSession":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.finish(aborted=exc_type is not None,
                    reason=f"{exc_type.__name__}: {exc}" if exc_type else "")
