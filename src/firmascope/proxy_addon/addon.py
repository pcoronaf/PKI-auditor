"""Addon de mitmproxy: el tercer sensor de red (nivel 4).

La instrumentacion ve lo que el JavaScript *pide* enviar; CDP ve lo que el
navegador *dice* que envia. El proxy ve lo que efectivamente sale por el
cable, ya codificado: el cuerpo multipart con sus fronteras, el contenido
tras la compresion, los frames de WebSocket tal cual. Es el unico de los tres
que no depende de la cooperacion del navegador, y por eso su coincidencia con
los otros dos es la corroboracion mas valiosa del expediente.

El addon vive partido en dos, y la particion no es estetica:

* **Lado mitmproxy** (``request``, ``websocket_message``): se ejecuta en el
  hilo y el bucle asyncio del proxy. Solo examina el cuerpo en memoria,
  busca canarios y **encola** un registro plano. No toca el expediente:
  SQLite no admite escrituras desde otro hilo, y un fallo aqui no debe
  cortar el trafico del sitio auditado.
* **Lado principal** (``drain``): lo invoca el orquestador en su hilo. Vacia
  la cola y convierte cada registro en ``RequestRecord`` + ``Event`` con el
  mismo formato que produce CDP, para que la correlacion los funda.

Los cuerpos no salen de la memoria salvo que el operador active
``capture_bodies``; lo que se encola son tamanos, digests y coincidencias de
canario, nunca el contenido.
"""

from __future__ import annotations

import hashlib
import queue
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from ..audit_core.config import AuditConfig
from ..audit_core.events import Event, EventType, Tag
from ..audit_core.secrets import SecretVault
from ..evidence_store.store import EvidenceStore, RequestRecord
from ..network_analyzer import canaries, domains

#: Cuerpo maximo examinado en busca de canarios. Mas alla se trunca: una
#: subida de varios megas no debe bloquear el bucle del proxy.
MAX_SCAN_BYTES = 4 * 1024 * 1024

#: Esquemas que el proxy no debe registrar como salida.
IGNORED_PREFIXES = ("data:", "blob:", "chrome-extension:")


@dataclass
class ProxyRecord:
    """Lo que el lado mitmproxy deja en la cola. Sin cuerpos."""

    kind: str                   # "request" | "websocket"
    timestamp: float
    method: str
    url: str
    headers: dict[str, str]
    content_type: str
    body_size: int
    body_digest: str
    canary_matches: list[dict[str, Any]] = field(default_factory=list)
    #: Solo si el operador activo capture_bodies; nunca en otro caso.
    body: bytes | None = None


class FirmaScopeAddon:
    """Addon de mitmproxy con cola hacia el hilo principal."""

    def __init__(self, session_id: str, config: AuditConfig,
                 vault: SecretVault | None = None, capture_bodies: bool = False):
        self.session_id = session_id
        self.config = config
        self.vault = vault
        self.capture_bodies = capture_bodies
        self._queue: "queue.Queue[ProxyRecord]" = queue.Queue()
        self.seen = 0
        self.errors = 0

    # ------------------------------------------------------------------
    # Lado mitmproxy (hilo del proxy)
    # ------------------------------------------------------------------
    def request(self, flow: Any) -> None:
        """Hook de mitmproxy: una peticion HTTP completa, antes de reenviarla."""
        try:
            request = flow.request
            url = request.pretty_url
            if url.startswith(IGNORED_PREFIXES):
                return
            # get_content deshace Content-Encoding: el canario se busca sobre
            # lo que el servidor recibira, no sobre el gzip.
            body = request.get_content(strict=False) or b""
            self._enqueue(
                kind="request",
                timestamp=float(request.timestamp_start or time.time()),
                method=request.method,
                url=url,
                headers=dict(request.headers.items()),
                content_type=request.headers.get("content-type", ""),
                body=body,
            )
        except Exception:
            # Un fallo del sensor jamas debe interrumpir el trafico auditado.
            self.errors += 1

    def websocket_message(self, flow: Any) -> None:
        """Hook de mitmproxy: un frame de WebSocket. Solo interesan los salientes."""
        try:
            message = flow.websocket.messages[-1]
            if not message.from_client:
                return
            self._enqueue(
                kind="websocket",
                timestamp=float(getattr(message, "timestamp", 0) or time.time()),
                method="WS",
                url=flow.request.pretty_url,
                headers={},
                content_type="",
                body=message.content or b"",
            )
        except Exception:
            self.errors += 1

    def _enqueue(self, *, kind: str, timestamp: float, method: str, url: str,
                 headers: dict[str, str], content_type: str, body: bytes) -> None:
        _, matches = canaries.classify(self.vault, body[:MAX_SCAN_BYTES], url)
        self._queue.put(ProxyRecord(
            kind=kind,
            timestamp=timestamp,
            method=method,
            url=url,
            headers=_clip_headers(headers),
            content_type=content_type,
            body_size=len(body),
            body_digest=hashlib.sha256(body).hexdigest() if body else "",
            canary_matches=matches,
            body=bytes(body) if (self.capture_bodies and body) else None,
        ))
        self.seen += 1

    # ------------------------------------------------------------------
    # Lado principal (hilo del orquestador)
    # ------------------------------------------------------------------
    def drain(self, store: EvidenceStore, emit: Callable[[Event], None]) -> int:
        """Vuelca la cola al expediente. Devuelve cuantos registros proceso."""
        processed = 0
        while True:
            try:
                record = self._queue.get_nowait()
            except queue.Empty:
                break
            try:
                self._persist(record, store, emit)
            except Exception as exc:  # pragma: no cover - robustez del sensor
                emit(Event(EventType.AGENT_ERROR, self.session_id, sensor="proxy",
                           data={"handler": record.kind, "error": str(exc)[:200]}))
            processed += 1
        return processed

    def _persist(self, record: ProxyRecord, store: EvidenceStore,
                 emit: Callable[[Event], None]) -> None:
        tags = sorted({m["label"] for m in record.canary_matches})
        if not tags and record.body_size > 0:
            tags = [Tag.UNCLASSIFIED.value]

        body_ref = ""
        if record.body is not None:
            evidence = store.add_evidence(
                "http-body", f"proxy-{record.method}-{_safe_name(record.url)}",
                record.body[: self.config.max_body_bytes])
            body_ref = evidence["path"]

        host = domains.host_of(record.url)
        third_party = domains.is_third_party(
            record.url, self.config.target, self.config.first_party_domains)

        request = RequestRecord(
            timestamp=record.timestamp,
            method=record.method,
            url=record.url,
            host=host,
            registrable=domains.registrable_domain(host),
            third_party=third_party,
            resource_type="websocket" if record.kind == "websocket" else "",
            headers=record.headers,
            body_size=record.body_size,
            body_digest=record.body_digest,
            body_ref=body_ref,
            tags=tags,
            sensor="proxy",
            context="proxy",
        )
        store.add_request(request)

        data: dict[str, Any] = {
            "url": record.url,
            "host": host,
            "method": record.method,
            "content_type": record.content_type,
            "third_party": third_party,
            "third_party_name": domains.third_party_name(record.url),
            "body_size": record.body_size,
            "body_digest": record.body_digest,
            "request_id": request.id,
        }
        if record.canary_matches:
            data["canary_matches"] = record.canary_matches

        event_type = (EventType.PROXY_WEBSOCKET if record.kind == "websocket"
                      else EventType.PROXY_REQUEST)
        emit(Event(event_type, self.session_id, timestamp=record.timestamp,
                   context="proxy", origin=host, sensor="proxy", tags=tags, data=data))


# ----------------------------------------------------------------------
def _clip_headers(headers: dict[str, Any]) -> dict[str, str]:
    """Cabeceras acotadas. Authorization y Cookie se omiten: no son evidencia
    de custodia de la clave y si son credenciales del operador."""
    out: dict[str, str] = {}
    for key, value in list(headers.items())[:40]:
        name = str(key)
        if name.lower() in ("authorization", "cookie", "proxy-authorization"):
            out[name[:64]] = "<omitida>"
            continue
        out[name[:64]] = str(value)[:256]
    return out


def _safe_name(url: str) -> str:
    tail = url.split("?")[0].rstrip("/").split("/")[-1] or "root"
    return "".join(c if c.isalnum() or c in "-._" else "_" for c in tail)[:40]
