"""Puente de la interfaz grafica: JSON por linea sobre entrada y salida estandar.

Por que stdio y no un puerto local
----------------------------------

La alternativa habitual es que el nucleo levante un servidor HTTP en localhost y
que la interfaz le hable por ``fetch``. Aqui seria una mala idea: FirmaScope
maneja la e.firma del operador, y un puerto abierto es alcanzable por cualquier
pagina que el usuario tenga abierta en cualquier navegador. Bastaria una peticion
desde un sitio cualquiera para pedirle al nucleo que arrancara una sesion, o para
leer el estado de la que esta en marcha.

Con stdio no hay superficie: el proceso lo lanza la interfaz como hijo y solo
ella puede escribirle. Es tambien lo que permite que la contrasena de la clave
viaje por el canal sin pasar por la red ni por la linea de comandos.

Protocolo
---------

Una linea JSON por mensaje. La interfaz envia peticiones::

    {"id": "7", "cmd": "validate", "args": {"answers": {...}}}

y el puente responde con el mismo ``id``::

    {"id": "7", "ok": true, "result": {...}}
    {"id": "7", "ok": false, "error": "..."}

Los eventos de la auditoria **no** se empujan: se recogen con ``poll``. Asi todo
ocurre en un solo hilo -- el mismo que controla Playwright, que no admite otro --
y el orden de la cadena de evidencias queda determinado por quien pregunta.

``stdout`` es solo protocolo
----------------------------

Playwright, mitmproxy y el propio Chromium escriben en la salida estandar sin
avisar. Una sola linea suya en medio del protocolo lo rompe, asi que el puente
se queda con el descriptor original para si y redirige ``sys.stdout`` a
``stderr``: lo que imprima cualquier otra cosa se vera en el log, no en el canal.
"""

from __future__ import annotations

import io
import json
import os
import sys
import traceback
from collections import deque
from pathlib import Path
from typing import Any, Callable

from .. import __version__
from ..audit_core import options as options_module
from ..audit_core.config import REAL_CREDENTIAL_WARNINGS, environment_info, proxy_available
from ..audit_core.events import Event
from ..audit_core.orchestrator import AuditSession
from ..browser_controller.isolation import StageAction

#: Numero maximo de eventos que se guardan si la interfaz tarda en preguntar.
MAX_PENDING_EVENTS = 5000

#: Version del protocolo. La interfaz la comprueba al arrancar: un puente mas
#: nuevo que la interfaz que lo lanza es un error de empaquetado, no algo que
#: deba descubrirse a mitad de una auditoria con la clave ya cargada.
PROTOCOL_VERSION = 1


class BridgeError(Exception):
    """Error que se devuelve a la interfaz sin matar el proceso."""


class Bridge:
    """Estado de una sesion de auditoria, manejado por comandos.

    No toca stdio: :func:`serve` se encarga de eso. Separarlos es lo que permite
    probar el protocolo entero sin lanzar procesos.
    """

    def __init__(self) -> None:
        self.session: AuditSession | None = None
        self.test: Any = None
        self.events: deque[dict[str, Any]] = deque(maxlen=MAX_PENDING_EVENTS)
        self.dropped = 0
        self.package: Path | None = None
        self.report: dict[str, Any] | None = None
        self.closed = False

    # ------------------------------------------------------------------
    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        """Atiende una peticion y devuelve la respuesta, sin lanzar excepciones."""
        request_id = request.get("id")
        command = str(request.get("cmd") or "")
        args = request.get("args") or {}
        if not isinstance(args, dict):
            return _fail(request_id, "args debe ser un objeto")

        handler = getattr(self, f"cmd_{command.replace('-', '_')}", None)
        if handler is None:
            return _fail(request_id, f"comando desconocido: {command!r}")
        try:
            return {"id": request_id, "ok": True, "result": handler(**args)}
        except BridgeError as exc:
            return _fail(request_id, str(exc))
        except TypeError as exc:
            return _fail(request_id, f"argumentos invalidos para {command}: {exc}")
        except Exception as exc:  # pragma: no cover - cualquier fallo se reporta
            return _fail(request_id, f"{type(exc).__name__}: {exc}",
                         traceback.format_exc(limit=6))

    # -- informacion ----------------------------------------------------
    def cmd_hello(self) -> dict[str, Any]:
        """Lo que la interfaz necesita antes de pintar nada."""
        return {
            "protocol": PROTOCOL_VERSION,
            "firmascope": __version__,
            "environment": environment_info(),
            "proxy_available": proxy_available(),
            "real_credential_warnings": list(REAL_CREDENTIAL_WARNINGS),
        }

    def cmd_schema(self) -> dict[str, Any]:
        return {"options": options_module.schema(),
                "defaults": options_module.defaults()}

    def cmd_validate(self, answers: dict[str, Any] | None = None) -> dict[str, Any]:
        answers = dict(answers or {})
        return {
            "problems": options_module.validate(answers),
            "visible": [o.id for o in options_module.visible_options(answers)],
            "needs_password": options_module.needs_password(answers),
        }

    def cmd_rules(self) -> dict[str, Any]:
        from ..rule_engine.engine import RuleEngine

        return {"rules": [
            {"id": m.id, "title": m.title, "category": m.category,
             "severity": m.severity.value, "summary": m.summary}
            for m in RuleEngine().rules
        ]}

    # -- sesion ---------------------------------------------------------
    def cmd_start(self, answers: dict[str, Any] | None = None,
                  password: str | None = None) -> dict[str, Any]:
        if self.session is not None:
            raise BridgeError("ya hay una sesion en marcha")
        answers = dict(answers or {})
        problems = options_module.validate(answers)
        if problems:
            raise BridgeError("; ".join(problems))
        setup = options_module.build_setup(answers, password)

        session = AuditSession(setup.config, on_event=self._collect)
        self.session = session
        credential = session.prepare_credentials(
            key_path=setup.key_path, cert_path=setup.cert_path,
            password=setup.password,
        )
        session.start_browser()
        if setup.config.has_target:
            session.navigate(setup.config.target)

        self.test = session.controller.staged_offline_test()
        stage = self.test.begin()
        return {
            "session": session.session_id,
            "root": str(session.root),
            "target": setup.config.target,
            "level": int(setup.config.level),
            "credential": self._credential_info(credential),
            "stages": self.test.describe(),
            "stage": _stage_info(stage, self.test),
            "sensors": {"proxy": bool(
                session.controller.proxy is not None
                and session.controller.proxy.running)},
        }

    def cmd_action(self, action: str = "next", reason: str = "") -> dict[str, Any]:
        test = self._require_test()
        stage = test.apply(StageAction.parse(action), reason)
        return {
            "stage": _stage_info(stage, test) if stage is not None else None,
            "finished": test.finished,
            "result": test.result().to_dict() if test.finished else None,
            "stages": test.describe(),
        }

    def cmd_poll(self) -> dict[str, Any]:
        """Avanza los sensores y entrega lo nuevo.

        Es el latido de la interfaz: sin el, los eventos de CDP y del agente se
        quedarian en sus colas hasta el siguiente comando.
        """
        session = self.session
        if session is None or session.controller is None:
            return {"events": [], "stats": {}, "dropped": self.dropped}
        try:
            session.controller.drain_agent()
            session.controller.pump()
        except Exception as exc:
            return {"events": self._take_events(), "stats": {},
                    "dropped": self.dropped, "warning": f"{type(exc).__name__}: {exc}"}
        return {
            "events": self._take_events(),
            "stats": session.stats.to_dict(),
            "dropped": self.dropped,
            "network": session.controller.isolation.network_state
            if session.controller.isolation else "",
        }

    def cmd_navigate(self, url: str = "") -> dict[str, Any]:
        session = self._require_session()
        if not url.strip():
            raise BridgeError("indique una direccion")
        if session.controller.offline:
            raise BridgeError(
                "la red esta aislada: la pagina no cargaria. Restablezca la red, o "
                "retroceda a una etapa en linea.")
        resolved = session.navigate(url)
        return {"url": resolved, "is_target": resolved == session.config.target,
                "target": session.config.target}

    def cmd_network(self, offline: bool = True, reason: str = "") -> dict[str, Any]:
        session = self._require_session()
        applied = session.controller.set_offline(
            bool(offline), reason or "orden del operador")
        return {"offline": session.controller.offline, "applied": bool(applied)}

    def cmd_live(self, option: str = "", value: Any = None) -> dict[str, Any]:
        session = self._require_session()
        described = options_module.apply_live_change(session.config, option, value)
        return {"applied": described, "isolation": session.config.isolation.to_dict()}

    def cmd_live_options(self) -> dict[str, Any]:
        """Que puede cambiarse con la sesion en marcha, y con que valor actual."""
        session = self._require_session()
        isolation = session.config.isolation
        current = {
            "isolation": isolation.mode.value,
            "allow_hosts": list(isolation.allow_hosts),
            "emulate_offline_flag": isolation.emulate_offline_flag,
        }
        return {"options": [o.to_dict() for o in options_module.LIVE_OPTIONS],
                "current": current}

    def cmd_status(self) -> dict[str, Any]:
        session = self.session
        if session is None:
            return {"running": False}
        test = self.test
        return {
            "running": True,
            "session": session.session_id,
            "target": session.config.target,
            "credential_mode": session.config.credential_mode.value,
            "events": session.stats.events,
            "requests": len(session.store.requests()),
            "stage": _stage_info(test.current(), test) if test is not None else None,
            "network": session.controller.isolation.network_state
            if session.controller and session.controller.isolation else "",
            "blocked": len(session.controller.isolation.blocked)
            if session.controller and session.controller.isolation else 0,
        }

    # -- cierre ---------------------------------------------------------
    def cmd_finish(self, aborted: bool = False, reason: str = "") -> dict[str, Any]:
        session = self._require_session()
        test = self.test
        if test is not None and not test.finished:
            # Cerrar sin pasar por la maquina de etapas dejaria el navegador
            # aislado si la sesion muere en una etapa sin red.
            test.apply(StageAction.ABORT, reason or "cerrado desde la interfaz")
            aborted = True
        try:
            session.collect_and_analyze()
            session.evaluate()
        except Exception as exc:
            self.events.append({"type": "BRIDGE_WARNING",
                                "data": {"detail": f"analisis incompleto: {exc}"}})
        package = session.finish(aborted=aborted, reason=reason)
        self.package = package
        report_path = package / "report.json"
        self.report = (json.loads(report_path.read_text(encoding="utf-8"))
                       if report_path.exists() else None)
        self.session = None
        self.test = None
        return {"package": str(package), "report": self.report,
                "html": str(package / "report.html")}

    def cmd_report(self) -> dict[str, Any]:
        if self.report is None:
            raise BridgeError("no hay reporte: la sesion no ha terminado")
        return {"package": str(self.package), "report": self.report}

    def cmd_shutdown(self) -> dict[str, Any]:
        if self.session is not None:
            try:
                self.cmd_finish(aborted=True, reason="interfaz cerrada")
            except Exception:  # pragma: no cover
                pass
        self.closed = True
        return {"closed": True}

    # ------------------------------------------------------------------
    def _collect(self, event: Event) -> None:
        if len(self.events) == self.events.maxlen:
            self.dropped += 1
        self.events.append(event.to_dict())

    def _take_events(self) -> list[dict[str, Any]]:
        items = list(self.events)
        self.events.clear()
        return items

    def _require_session(self) -> AuditSession:
        if self.session is None or self.session.controller is None:
            raise BridgeError("no hay ninguna sesion en marcha")
        return self.session

    def _require_test(self) -> Any:
        self._require_session()
        if self.test is None:
            raise BridgeError("la prueba por etapas no esta iniciada")
        return self.test

    def _credential_info(self, credential: Any) -> dict[str, Any]:
        """Lo que la interfaz debe mostrar al llegar a la etapa de firma.

        Con credencial sintetica incluye la contrasena: es de laboratorio y el
        operador tiene que escribirla en el portal. Con credencial propia o real
        **no** se devuelve nada de eso, ni aunque la interfaz lo pida.
        """
        if credential is None:
            return {"mode": self.session.config.credential_mode.value if self.session else ""}
        info: dict[str, Any] = {
            "mode": self.session.config.credential_mode.value if self.session else "",
            "synthetic": bool(credential.synthetic),
            "subject": credential.subject,
        }
        if credential.synthetic:
            info.update({
                "cert_path": str(credential.cert_path),
                "key_path": str(credential.key_path),
                "password": credential.password,
            })
        return info


# ----------------------------------------------------------------------
def _stage_info(stage: Any, test: Any) -> dict[str, Any] | None:
    if stage is None:
        return None
    index = test.current_index
    return {
        "name": stage.name,
        "title": stage.title,
        "instruction": stage.instruction,
        "network": stage.network,
        "index": index,
        "total": len(test.stages),
        "allow_back": bool(stage.allow_back and index > 0),
        "irreversible_note": stage.irreversible_note,
        "actual_network": test.isolation.network_state,
    }


def _fail(request_id: Any, message: str, detail: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {"id": request_id, "ok": False, "error": message}
    if detail:
        out["detail"] = detail
    return out


def serve(stdin: Any = None, stdout: Any = None) -> int:
    """Bucle de servicio sobre stdio. Devuelve el codigo de salida del proceso."""
    bridge = Bridge()
    reader = stdin or sys.stdin

    if stdout is None:
        # Se toma el descriptor original para el protocolo y se aparta
        # sys.stdout: lo que imprima Playwright o Chromium ira al log.
        fd = os.dup(1)
        os.dup2(2, 1)
        writer: Any = io.TextIOWrapper(os.fdopen(fd, "wb", 0), encoding="utf-8",
                                       write_through=True)
        sys.stdout = sys.stderr
    else:
        writer = stdout

    def send(message: dict[str, Any]) -> None:
        writer.write(json.dumps(message, ensure_ascii=False, default=str) + "\n")
        writer.flush()

    for line in reader:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            send(_fail(None, f"JSON invalido: {exc}"))
            continue
        if not isinstance(request, dict):
            send(_fail(None, "cada mensaje debe ser un objeto JSON"))
            continue
        send(bridge.handle(request))
        if bridge.closed:
            break

    if bridge.session is not None:  # pragma: no cover - cierre por EOF
        try:
            bridge.cmd_finish(aborted=True, reason="la interfaz cerro el canal")
        except Exception:
            pass
    return 0


def main(argv: list[str] | None = None) -> int:  # pragma: no cover
    return serve()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
