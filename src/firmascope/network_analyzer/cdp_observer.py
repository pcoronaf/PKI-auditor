"""Observacion de red por Chrome DevTools Protocol (Nivel 1).

Equivale a la pestana Network de DevTools, pero con registro reproducible:
URL, metodo, cabeceras, cuerpo, tipo de recurso, initiator con pila de
llamadas, WebSocket, WebTransport, redirecciones, terceros, timestamp y
tamano.

Los cuerpos se analizan siempre en memoria (para buscar canarios y calcular
digests) pero solo se persisten si el operador habilita ``capture_bodies``.
"""

from __future__ import annotations

import base64
import hashlib
from collections import deque
from typing import Any, Callable

from ..audit_core.config import AuditConfig
from ..audit_core.events import Event, EventType, Tag
from ..audit_core.secrets import SecretVault
from ..evidence_store.store import EvidenceStore, RequestRecord
from . import domains

#: Tamano maximo de cuerpo que CDP devuelve en linea dentro de requestWillBeSent.
MAX_POST_DATA = 1024 * 1024


class NetworkObserver:
    """Adjunta sensores CDP a una pagina y normaliza lo observado."""

    def __init__(self, session_id: str, store: EvidenceStore, config: AuditConfig,
                 emit: Callable[[Event], None], vault: SecretVault | None = None):
        self.session_id = session_id
        self.store = store
        self.config = config
        self.emit = emit
        self.vault = vault
        self._pending: deque[tuple[str, dict[str, Any], str]] = deque()
        self._requests: dict[str, RequestRecord] = {}
        self._sockets: dict[str, str] = {}
        self._sessions: list[Any] = []
        self.request_count = 0

    # ------------------------------------------------------------------
    def attach(self, page, context_name: str = "main") -> None:
        """Habilita los dominios CDP necesarios sobre ``page``."""
        cdp = page.context.new_cdp_session(page)
        self._sessions.append(cdp)
        cdp.send("Network.enable", {
            "maxTotalBufferSize": 20 * 1024 * 1024,
            "maxResourceBufferSize": 10 * 1024 * 1024,
            "maxPostDataSize": MAX_POST_DATA,
        })
        cdp.send("Page.enable", {})
        events = [
            "Network.requestWillBeSent", "Network.responseReceived", "Network.loadingFinished",
            "Network.loadingFailed", "Network.webSocketCreated", "Network.webSocketFrameSent",
            "Network.webSocketFrameReceived", "Network.webSocketClosed",
            "Network.webTransportCreated", "Network.webTransportConnectionEstablished",
            "Network.webTransportClosed",
        ]
        for name in events:
            cdp.on(name, self._make_handler(name, context_name))

    def _make_handler(self, name: str, context_name: str):
        # Los handlers de Playwright (API sincrona) no deben invocar CDP: solo
        # encolan. El procesamiento ocurre en pump(), en el hilo principal.
        def handler(params):
            self._pending.append((name, params, context_name))
        return handler

    # ------------------------------------------------------------------
    def pump(self) -> int:
        """Procesa los eventos CDP encolados. Devuelve cuantos se procesaron."""
        processed = 0
        while self._pending:
            name, params, context_name = self._pending.popleft()
            try:
                self._dispatch(name, params, context_name)
            except Exception as exc:  # pragma: no cover - robustez del sensor
                self.emit(Event(EventType.AGENT_ERROR, self.session_id, sensor="cdp",
                                data={"handler": name, "error": str(exc)[:200]}))
            processed += 1
        return processed

    def _dispatch(self, name: str, params: dict[str, Any], context_name: str) -> None:
        method = name.split(".", 1)[1]
        getattr(self, f"_on_{method}", lambda *_: None)(params, context_name)

    # -- HTTP -----------------------------------------------------------
    def _on_requestWillBeSent(self, params: dict[str, Any], context_name: str) -> None:
        request = params.get("request", {})
        url = request.get("url", "")
        if url.startswith(("data:", "blob:", "chrome-extension:")):
            return
        initiator = params.get("initiator", {}) or {}
        stack = _flatten_stack(initiator.get("stack"))
        body = _post_data(request)
        tags, canaries = self._classify_body(body, url)

        body_ref = ""
        if body and self.config.capture_bodies:
            record = self.store.add_evidence(
                "http-body", f"{request.get('method', 'GET')}-{_safe_name(url)}",
                body[: self.config.max_body_bytes],
            )
            body_ref = record["path"]

        host = domains.host_of(url)
        record = RequestRecord(
            timestamp=params.get("wallTime") or params.get("timestamp") or 0.0,
            method=request.get("method", "GET"),
            url=url,
            host=host,
            registrable=domains.registrable_domain(host),
            third_party=domains.is_third_party(url, self.config.target, self.config.first_party_domains),
            resource_type=params.get("type", ""),
            initiator=initiator.get("type", ""),
            stack=stack,
            headers=_clip_headers(request.get("headers", {})),
            body_size=len(body) if body else 0,
            body_digest=hashlib.sha256(body).hexdigest() if body else "",
            body_ref=body_ref,
            tags=tags,
            redirect_from=(params.get("redirectResponse") or {}).get("url", ""),
            sensor="cdp",
            context=context_name,
        )
        self._requests[params.get("requestId", record.id)] = record
        self.store.add_request(record)
        self.request_count += 1

        data = {
            "url": url,
            "host": host,
            "method": record.method,
            "resource_type": record.resource_type,
            "initiator": record.initiator,
            "third_party": record.third_party,
            "third_party_name": domains.third_party_name(url),
            "body_size": record.body_size,
            "body_digest": record.body_digest,
            "request_id": record.id,
            "stack": stack[:5],
        }
        if canaries:
            data["canary_matches"] = [m.to_dict() for m in canaries]
        if record.redirect_from:
            data["redirect_from"] = record.redirect_from
        self.emit(Event(EventType.NETWORK_REQUEST, self.session_id, timestamp=record.timestamp,
                        context=context_name, origin=domains.host_of(url), sensor="cdp",
                        tags=tags, data=data))

    def _on_responseReceived(self, params: dict[str, Any], context_name: str) -> None:
        record = self._requests.get(params.get("requestId", ""))
        response = params.get("response", {})
        if record is not None:
            self.store.update_request(record.id, status=int(response.get("status", 0)))
        self.emit(Event(EventType.NETWORK_RESPONSE, self.session_id,
                        timestamp=params.get("timestamp") or 0.0, context=context_name,
                        sensor="cdp", data={
                            "url": response.get("url", ""),
                            "status": response.get("status"),
                            "mime_type": response.get("mimeType", ""),
                            "remote_ip": response.get("remoteIPAddress", ""),
                            "protocol": response.get("protocol", ""),
                            "request_id": record.id if record else "",
                        }))

    def _on_loadingFinished(self, params: dict[str, Any], context_name: str) -> None:
        record = self._requests.get(params.get("requestId", ""))
        if record is not None:
            self.store.update_request(record.id, response_size=int(params.get("encodedDataLength", 0)))

    def _on_loadingFailed(self, params: dict[str, Any], context_name: str) -> None:
        record = self._requests.get(params.get("requestId", ""))
        self.emit(Event(EventType.NETWORK_FAILED, self.session_id,
                        timestamp=params.get("timestamp") or 0.0, context=context_name, sensor="cdp",
                        data={
                            "url": record.url if record else "",
                            "error": params.get("errorText", ""),
                            "canceled": bool(params.get("canceled")),
                            "request_id": record.id if record else "",
                        }))

    # -- WebSocket ------------------------------------------------------
    def _on_webSocketCreated(self, params: dict[str, Any], context_name: str) -> None:
        url = params.get("url", "")
        self._sockets[params.get("requestId", "")] = url
        self.emit(Event(EventType.WEBSOCKET_CREATED, self.session_id, context=context_name, sensor="cdp",
                        data={"url": url, "host": domains.host_of(url),
                              "third_party": domains.is_third_party(url, self.config.target,
                                                                    self.config.first_party_domains)}))

    def _on_webSocketFrameSent(self, params: dict[str, Any], context_name: str) -> None:
        url = self._sockets.get(params.get("requestId", ""), "")
        payload = params.get("response", {}).get("payloadData", "")
        raw = _decode_frame(payload, params.get("response", {}))
        tags, canaries = self._classify_body(raw, url)
        data = {
            "url": url, "host": domains.host_of(url), "size": len(raw) if raw else 0,
            "opcode": params.get("response", {}).get("opcode"),
            "body_digest": hashlib.sha256(raw).hexdigest() if raw else "",
        }
        if canaries:
            data["canary_matches"] = [m.to_dict() for m in canaries]
        self.emit(Event(EventType.WEBSOCKET_SEND, self.session_id, context=context_name, sensor="cdp",
                        tags=tags, data=data))

    def _on_webSocketFrameReceived(self, params: dict[str, Any], context_name: str) -> None:
        return None

    def _on_webSocketClosed(self, params: dict[str, Any], context_name: str) -> None:
        return None

    # -- WebTransport ---------------------------------------------------
    def _on_webTransportCreated(self, params: dict[str, Any], context_name: str) -> None:
        url = params.get("url", "")
        self.emit(Event(EventType.WEBTRANSPORT_CREATED, self.session_id, context=context_name, sensor="cdp",
                        data={"url": url, "host": domains.host_of(url),
                              "third_party": domains.is_third_party(url, self.config.target,
                                                                    self.config.first_party_domains)}))

    def _on_webTransportConnectionEstablished(self, params: dict[str, Any], context_name: str) -> None:
        return None

    def _on_webTransportClosed(self, params: dict[str, Any], context_name: str) -> None:
        return None

    # ------------------------------------------------------------------
    def _classify_body(self, body: bytes | None, url: str) -> tuple[list[str], list]:
        """Etiqueta un cuerpo saliente buscando representaciones de canarios."""
        if not body:
            return [], []
        matches = self.vault.scan(body) if self.vault else []
        tags = sorted({m.label for m in matches})
        if not tags and body:
            tags = [Tag.UNCLASSIFIED.value]
        return tags, matches


# ----------------------------------------------------------------------
def _post_data(request: dict[str, Any]) -> bytes | None:
    data = request.get("postData")
    if isinstance(data, str):
        return data.encode("utf-8", "replace")
    entries = request.get("postDataEntries") or []
    chunks: list[bytes] = []
    for entry in entries:
        raw = entry.get("bytes")
        if raw:
            try:
                chunks.append(base64.b64decode(raw))
            except Exception:
                continue
    return b"".join(chunks) if chunks else None


def _decode_frame(payload: str, response: dict[str, Any]) -> bytes:
    if not payload:
        return b""
    # opcode 2 = binario (payloadData viene en base64)
    if response.get("opcode") == 2:
        try:
            return base64.b64decode(payload)
        except Exception:
            return payload.encode("utf-8", "replace")
    return payload.encode("utf-8", "replace")


def _clip_headers(headers: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in list(headers.items())[:40]:
        text = str(value)
        out[str(key)[:64]] = text[:256]
    return out


def _safe_name(url: str) -> str:
    tail = url.split("?")[0].rstrip("/").split("/")[-1] or "root"
    return "".join(c if c.isalnum() or c in "-._" else "_" for c in tail)[:40]


def _flatten_stack(stack: dict[str, Any] | None, limit: int = 8) -> list[dict[str, Any]]:
    """Aplana la pila de llamadas del initiator a una lista legible."""
    frames: list[dict[str, Any]] = []
    while stack and len(frames) < limit:
        for frame in stack.get("callFrames", []) or []:
            if len(frames) >= limit:
                break
            frames.append({
                "function": frame.get("functionName", "") or "(anonymous)",
                "url": frame.get("url", ""),
                "line": frame.get("lineNumber", 0) + 1,
                "column": frame.get("columnNumber", 0),
            })
        stack = stack.get("parent")
    return frames
