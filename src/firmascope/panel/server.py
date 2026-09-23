"""Servidor local del panel de control.

Sirve la pagina del panel, su estado y dos ordenes (siguiente etapa, cerrar)
en 127.0.0.1. El panel se abre en el navegador habitual del operador, fuera
del navegador de auditoria: el sitio auditado no puede verlo ni alterarlo.

Lo protegen tres cosas, porque cualquier pagina abierta en el equipo puede
intentar hablar con un puerto local:

* un **token** aleatorio en cada peticion; sin el, 403;
* la **cabecera Host** debe ser la del propio panel, contra DNS rebinding;
* las **ordenes** exigen el token en una cabecera propia (``X-FS-Token``), que
  una web ajena no puede anadir sin una comprobacion CORS que este servidor
  nunca concede.

La pagina lleva una politica CSP que solo permite su propio script (con
nonce) y peticiones a este mismo origen.
"""

from __future__ import annotations

import hmac
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .state import PanelState

PAGE = Path(__file__).parent / "page.html"


class PanelHandler(BaseHTTPRequestHandler):
    state: PanelState
    token: str
    nonce: str
    allowed_hosts: frozenset[str]

    def log_message(self, fmt: str, *args) -> None:  # pragma: no cover - ruido
        pass

    # -- control de acceso ------------------------------------------------
    def _authorized(self, *, header_only: bool = False) -> bool:
        if self.headers.get("Host", "") not in self.allowed_hosts:
            return False
        supplied = self.headers.get("X-FS-Token", "")
        if not supplied and not header_only:
            supplied = (parse_qs(urlsplit(self.path).query).get("t") or [""])[0]
        return bool(supplied) and hmac.compare_digest(supplied, self.token)

    def _deny(self) -> None:
        self._send(403, "text/plain; charset=utf-8", b"acceso denegado")

    # -- rutas ------------------------------------------------------------
    def do_GET(self) -> None:
        route = urlsplit(self.path).path
        if not self._authorized():
            self._deny()
            return
        if route == "/":
            page = PAGE.read_text(encoding="utf-8").replace("__NONCE__", self.nonce)
            self._send(200, "text/html; charset=utf-8", page.encode("utf-8"), csp=(
                f"default-src 'none'; script-src 'nonce-{self.nonce}'; "
                "style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; "
                "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"))
            return
        if route == "/api/state":
            self._send(200, "application/json",
                       json.dumps(self.state.snapshot(), ensure_ascii=False).encode("utf-8"))
            return
        if route == "/report":
            path = self.state.report_path
            if not path or not Path(path).is_file():
                self._send(404, "text/plain; charset=utf-8", b"el reporte aun no existe")
                return
            # El reporte es autocontenido y no ejecuta scripts: se sirve con
            # una CSP que lo garantiza.
            self._send(200, "text/html; charset=utf-8", Path(path).read_bytes(),
                       csp="default-src 'none'; style-src 'unsafe-inline'; img-src data:")
            return
        self._send(404, "text/plain; charset=utf-8", b"no encontrado")

    def do_POST(self) -> None:
        route = urlsplit(self.path).path
        # Las ordenes solo aceptan el token en la cabecera: un formulario o un
        # enlace de otra web no pueden anadirla.
        if not self._authorized(header_only=True):
            self._deny()
            return
        if route == "/api/next":
            accepted = self.state.request_advance()
            self._send(200 if accepted else 409, "application/json",
                       json.dumps({"accepted": accepted}).encode("utf-8"))
            return
        if route == "/api/close":
            self.state.request_close()
            self._send(200, "application/json", b'{"closed": true}')
            return
        self._send(404, "text/plain; charset=utf-8", b"no encontrado")

    # -- utilidades -------------------------------------------------------
    def _send(self, code: int, content_type: str, payload: bytes, csp: str = "") -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if csp:
            self.send_header("Content-Security-Policy", csp)
        self.end_headers()
        self.wfile.write(payload)


class PanelServer:
    """El servidor del panel, en un hilo propio."""

    def __init__(self, state: PanelState, host: str = "127.0.0.1", port: int = 0):
        self.state = state
        self.token = secrets.token_urlsafe(32)
        handler = type("BoundPanelHandler", (PanelHandler,), {
            "state": state, "token": self.token, "nonce": secrets.token_urlsafe(16),
            "allowed_hosts": frozenset(),
        })
        self.httpd = ThreadingHTTPServer((host, port), handler)
        bound = self.httpd.server_address[1]
        handler.allowed_hosts = frozenset({f"127.0.0.1:{bound}", f"localhost:{bound}"})
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return int(self.httpd.server_address[1])

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/?t={self.token}"

    def start(self) -> "PanelServer":
        self._thread = threading.Thread(target=self.httpd.serve_forever,
                                        name="firmascope-panel", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def __enter__(self) -> "PanelServer":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()
