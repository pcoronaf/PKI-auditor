"""Estado del panel de control, compartido entre dos hilos.

El hilo principal conduce la auditoria (Playwright no admite otro) y escribe
aqui: la etapa en curso, lo que la persona debe hacer, lo que los sensores van
observando. El hilo del servidor HTTP lo lee para el panel y deja en el una
unica senal: "la persona pulso Siguiente etapa". Todo acceso pasa por un
cerrojo.

Lo que se muestra de cada evento sale del evento ya **guardado**, es decir,
ya redactado por el expediente: el panel no ve nada que no haya pasado por la
misma barrera que el disco.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..audit_core.events import EGRESS_EVENTS, PRIVATE_TAGS, Event, EventType
from ..network_analyzer import domains

PRIVATE_LABELS = frozenset(t.value for t in PRIVATE_TAGS)

#: Etapas del recorrido, en orden. "firmar-aislado" solo existe en nivel 3+.
STAGES: tuple[tuple[str, str], ...] = (
    ("abrir", "Abrir la plataforma"),
    ("preparar", "Preparacion"),
    ("firmar", "Firma"),
    ("firmar-aislado", "Firma con la red aislada"),
    ("analizar", "Analisis"),
    ("reporte", "Reporte"),
)

#: Eventos que merecen una linea en el panel, con su descripcion.
EVENT_LABELS: dict[EventType, str] = {
    EventType.PAGE_LOADED: "Pagina cargada",
    EventType.FILE_READ: "Lectura de archivo",
    EventType.PASSWORD_READ: "Lectura de la contrasena",
    EventType.CRYPTO_IMPORT: "Importacion de clave",
    EventType.CRYPTO_DECRYPT: "Descifrado",
    EventType.CRYPTO_ENCRYPT: "Cifrado",
    EventType.CRYPTO_DERIVE: "Derivacion de clave",
    EventType.CRYPTO_SIGN: "Firma",
    EventType.CRYPTO_EXPORT: "Exportacion de clave",
    EventType.CRYPTO_WRAP: "Envoltura de clave",
    EventType.CRYPTO_UNWRAP: "Desenvoltura de clave",
    EventType.NETWORK_REQUEST: "Peticion",
    EventType.PROXY_REQUEST: "Peticion vista por el proxy",
    EventType.BEACON_SEND: "sendBeacon",
    EventType.WEBSOCKET_SEND: "WebSocket",
    EventType.PROXY_WEBSOCKET: "WebSocket visto por el proxy",
    EventType.WEBTRANSPORT_SEND: "WebTransport",
    EventType.RTC_SEND: "WebRTC",
    EventType.FORM_SUBMIT: "Envio de formulario",
    EventType.NAVIGATION: "Navegacion",
    EventType.RESOURCE_URL_SET: "URL de recurso",
    EventType.STORAGE_WRITE: "Escritura en almacenamiento",
    EventType.NETWORK_OFF: "Red aislada",
    EventType.NETWORK_ON: "Red restablecida",
    EventType.AGENT_ERROR: "Aviso del sensor",
}

#: Maximo de eventos que conserva el panel (el expediente los guarda todos).
MAX_EVENTS = 400


@dataclass
class Counters:
    key_reads: int = 0
    crypto_ops: int = 0
    signatures: int = 0
    egress: int = 0
    egress_private: int = 0
    third_party: int = 0

    def to_dict(self) -> dict[str, int]:
        return dict(self.__dict__)


class PanelState:
    """Lo que el panel muestra y la unica orden que puede dar."""

    def __init__(self, target: str, level: int, offline_test: bool):
        self._lock = threading.Lock()
        self._advance = threading.Event()
        self._closed = threading.Event()
        self.target = target
        self.level = level
        self.stages = [{"id": sid, "title": title,
                        "status": "skipped" if sid == "firmar-aislado" and not offline_test
                        else "pending"}
                       for sid, title in STAGES]
        self.stage = ""
        self.waiting = False
        self.message = ""
        self.credential: dict[str, str] | None = None
        self.events: deque[dict[str, Any]] = deque(maxlen=MAX_EVENTS)
        self.counters = Counters()
        self.notes: list[str] = []
        self.result: dict[str, Any] | None = None
        self.report_path: str = ""
        self.started_at = time.time()

    # -- escrito por el hilo principal ----------------------------------
    def set_stage(self, stage_id: str) -> None:
        with self._lock:
            order = [s["id"] for s in self.stages]
            if stage_id not in order:
                return
            current = order.index(stage_id)
            for index, stage in enumerate(self.stages):
                if stage["status"] == "skipped":
                    continue
                if index < current:
                    # Una etapa que nunca llego a abrirse (nivel sin prueba de
                    # aislamiento, modo automatico) se marca omitida, no hecha.
                    stage["status"] = "done" if stage["status"] in ("active", "done") else "skipped"
                elif index == current:
                    stage["status"] = "active"
            self.stage = stage_id
            if stage_id not in ("preparar", "firmar", "firmar-aislado"):
                self.waiting = False
                self.message = ""

    def ask(self, stage_id: str, message: str, credential: Any | None = None) -> None:
        """La auditoria espera a la persona en esta etapa."""
        self.set_stage(stage_id)
        with self._lock:
            self._advance.clear()
            self.waiting = True
            self.message = message
            if credential is not None:
                # Rutas absolutas: se pegan en el selector de archivos del
                # navegador de auditoria, que no conoce el directorio actual.
                self.credential = {
                    "key_path": _absolute(credential.key_path),
                    "cert_path": _absolute(credential.cert_path),
                    "password": credential.password,
                }

    def stop_waiting(self) -> None:
        with self._lock:
            self.waiting = False

    def add_event(self, event: Event) -> None:
        """Resume un evento ya guardado (y por tanto ya redactado)."""
        label = EVENT_LABELS.get(event.type)
        tags = set(event.tags)
        private = bool(tags & PRIVATE_LABELS) or any(
            isinstance(m, dict) and m.get("label") in PRIVATE_LABELS
            for m in event.data.get("canary_matches") or [])
        third_party = bool(event.data.get("third_party"))
        with self._lock:
            self._count(event, private, third_party)
            if label is None:
                return
            url = str(event.data.get("url") or "")
            self.events.append({
                "seq": event.seq,
                "time": time.strftime("%H:%M:%S", time.localtime(event.timestamp)),
                "stage": self.stage,
                "label": label,
                "type": event.type.value,
                "sensor": event.sensor,
                "context": event.context,
                "tags": sorted(t for t in tags if t != "UNCLASSIFIED"),
                "host": domains.host_of(url) if url else "",
                "detail": _detail(event),
                "level": "private" if private and event.type in EGRESS_EVENTS
                else "third" if third_party and event.type in EGRESS_EVENTS
                else "warn" if event.type is EventType.AGENT_ERROR
                else "info",
            })

    def _count(self, event: Event, private: bool, third_party: bool) -> None:
        c = self.counters
        if event.type is EventType.FILE_READ and "KEY_FILE" in event.tags:
            c.key_reads += 1
        if event.type.value.startswith("CRYPTO_"):
            c.crypto_ops += 1
        if event.type is EventType.CRYPTO_SIGN:
            c.signatures += 1
        if event.type in EGRESS_EVENTS and event.sensor != "proxy":
            # El proxy ve las mismas salidas que CDP: contarlas dos veces
            # inflaria la cifra que la persona mira.
            c.egress += 1
            if private:
                c.egress_private += 1
            if third_party:
                c.third_party += 1

    def add_note(self, note: str) -> None:
        if note:
            with self._lock:
                self.notes.append(note)

    def finish(self, result: Any) -> None:
        """La auditoria termino: resumen de hallazgos y enlace al reporte."""
        self.set_stage("reporte")
        with self._lock:
            self.stages[-1]["status"] = "done"
            self.waiting = False
            self.message = ""
            findings = [
                {"rule_id": f.rule_id, "title": f.title, "status": f.status.value,
                 "severity": f.severity.value, "summary": f.summary}
                for f in getattr(result, "findings", [])
            ]
            self.result = {
                "error": getattr(result, "error", ""),
                "session_id": getattr(result, "session_id", ""),
                "output_dir": str(getattr(result, "output_dir", "")),
                "findings": findings,
                "actionable": sum(1 for f in findings
                                  if f["status"] in ("CONFIRMED", "OBSERVED", "POTENTIAL")),
            }
            html = (getattr(result, "reports", {}) or {}).get("html")
            self.report_path = str(html) if html else ""

    # -- escrito por el hilo del servidor -------------------------------
    def request_advance(self) -> bool:
        """La persona pulso "Siguiente etapa". Solo vale si se la esperaba."""
        with self._lock:
            if not self.waiting:
                return False
            self.waiting = False
        self._advance.set()
        return True

    def request_close(self) -> None:
        self._closed.set()

    # -- esperas ----------------------------------------------------------
    @property
    def advanced(self) -> bool:
        return self._advance.is_set()

    def wait_closed(self, timeout: float | None = None) -> bool:
        return self._closed.wait(timeout)

    # -- lectura ----------------------------------------------------------
    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "target": self.target,
                "level": self.level,
                "stage": self.stage,
                "stages": [dict(s) for s in self.stages],
                "waiting": self.waiting,
                "message": self.message,
                "credential": dict(self.credential) if self.credential else None,
                "counters": self.counters.to_dict(),
                "events": list(self.events),
                "notes": list(self.notes),
                "result": self.result,
                "has_report": bool(self.report_path),
                "elapsed": int(time.time() - self.started_at),
            }


def _absolute(path: Any) -> str:
    return str(Path(path).resolve()) if path else ""


def _detail(event: Event) -> str:
    data = event.data
    if event.type.value.startswith("CRYPTO_"):
        return str(data.get("algorithm") or "")
    if event.type is EventType.FILE_READ:
        size = data.get("size")
        return f"{size} bytes" if size else ""
    if event.type in EGRESS_EVENTS:
        method = str(data.get("method") or "")
        size = data.get("body_size") or 0
        return f"{method} {size} bytes".strip() if size else method
    if event.type is EventType.STORAGE_WRITE:
        return str(data.get("store") or "")
    if event.type is EventType.AGENT_ERROR:
        return str(data.get("kind") or data.get("handler") or "")[:60]
    return ""


def panel_operator(state: PanelState):
    """Operador para el modo manual: espera al boton del panel.

    Corre en el hilo principal y espera con ``step.wait``, que sigue drenando
    los sensores mientras la persona trabaja en el navegador de auditoria.
    """

    def operator(step) -> None:
        # El panel muestra las credenciales en su propio recuadro, con botones
        # de copiar; del mensaje basta la instruccion.
        message = step.message.split("\n", 1)[0] if step.credential is not None else step.message
        state.ask(step.step, message, step.credential)
        while not state.advanced:
            if step.page is None or step.page.is_closed():
                state.add_note("La ventana del navegador de auditoria se cerro; "
                               "se continua con lo observado.")
                state.stop_waiting()
                return
            step.wait(0.3)

    return operator
