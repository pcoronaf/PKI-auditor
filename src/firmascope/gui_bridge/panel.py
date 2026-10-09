"""Panel: la misma interfaz que la aplicacion Tauri, servida en 127.0.0.1.

Es otro *transporte* del mismo :class:`~firmascope.gui_bridge.bridge.Bridge`,
no otra interfaz: la pagina es ``firmascope/ui`` (la que empaqueta Tauri) y los
comandos son los mismos. Existe porque compilar la aplicacion exige Rust y, en
Linux, WebKitGTK; el panel solo necesita el navegador que ya tiene el operador.

El precio es un puerto local
----------------------------

Por eso el puente de Tauri usa stdio: un puerto es alcanzable por cualquier
pagina abierta en cualquier navegador del equipo, y por cualquier programa que
corra en el. El panel lo acepta como excepcion explicita (ver ``CLAUDE.md``),
con estas defensas:

* escucha solo en ``127.0.0.1``, en un puerto elegido al azar;
* la cabecera ``Host`` debe ser la del propio panel, contra DNS rebinding;
* cada orden exige un token aleatorio en la cabecera ``X-FS-Token``, que una
  pagina de otro origen no puede anadir sin una comprobacion CORS que este
  servidor nunca concede; se rechaza ademas cualquier ``Origin`` ajeno y
  cualquier cuerpo que no sea JSON;
* el token no viaja en la URL: la URL lleva un codigo de un solo uso que se
  canjea por el token. La URL aparece en la lista de procesos mientras
  arranca el navegador; el codigo, una vez canjeado, ya no sirve;
* la pagina se sirve con una CSP que solo permite sus propios ficheros.

Lo que no cubre: un programa que corra con el mismo usuario puede leer la
memoria del proceso de todos modos, y lo que viaja por el puerto (incluida la
contrasena de una e.firma propia) va sin cifrar por la interfaz de loopback.
:data:`PANEL_WARNING` lo dice al arrancar y en la propia pagina.

Hilos
-----

Playwright solo admite el hilo que lo arranco. El servidor HTTP corre en su
propio hilo y deja cada orden en una cola; el hilo principal las atiende de
una en una (:meth:`PanelServer.serve`), igual que el puente por stdio.
"""

from __future__ import annotations

import hmac
import json
import queue
import secrets
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .bridge import Bridge

#: La interfaz, la misma que empaqueta Tauri.
UI_DIR = Path(__file__).resolve().parent.parent / "ui"

#: Ficheros que el panel sirve. Una lista cerrada: nada de rutas arbitrarias.
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
}

#: Solo sus propios ficheros y peticiones a si misma.
CSP = ("default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
       "form-action 'none'; frame-ancestors 'none'")

#: Tamano maximo de una orden. Ninguna se acerca; el limite evita que una
#: peticion enorme retenga memoria.
MAX_BODY = 1 << 20

PANEL_WARNING = (
    "AVISO: el panel abre un puerto local en 127.0.0.1 para hablar con su "
    "navegador. Cualquier pagina web abierta y cualquier programa de este equipo "
    "pueden intentar conectarse a el. Lo protegen un codigo de un solo uso, un "
    "token por sesion y comprobaciones de origen, pero lo que viaja por el -- "
    "incluida la contrasena de una e.firma propia -- va sin cifrar dentro del "
    "equipo. No lo use en un equipo compartido. Si puede, use la aplicacion de "
    "escritorio (Tauri), que no abre ningun puerto. Cierre el panel con Ctrl-C "
    "en la terminal en cuanto termine."
)


@dataclass
class _Order:
    request: dict[str, Any]
    reply: "queue.Queue[dict[str, Any]]" = field(default_factory=lambda: queue.Queue(1))


class PanelHandler(BaseHTTPRequestHandler):
    """Atiende HTTP en el hilo del servidor. No toca el puente: encola."""

    panel: "PanelServer"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:  # pragma: no cover - ruido
        pass

    # -- control de acceso ----------------------------------------------
    def _host_ok(self) -> bool:
        return self.headers.get("Host", "") in self.panel.allowed_hosts

    def _same_origin(self) -> bool:
        """Una peticion de otro origen se rechaza aunque traiga el token."""
        origin = self.headers.get("Origin")
        if origin is not None and origin not in self.panel.allowed_origins:
            return False
        site = self.headers.get("Sec-Fetch-Site")
        return site is None or site in ("same-origin", "none")

    def _json_body(self) -> dict[str, Any] | None:
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            return None
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length <= 0 or length > MAX_BODY:
            return None
        try:
            body = json.loads(self.rfile.read(length))
        except ValueError:
            return None
        return body if isinstance(body, dict) else None

    # -- rutas ----------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        if not self._host_ok():
            self._send(403, b"acceso denegado")
            return
        entry = STATIC.get(urlsplit(self.path).path)
        if entry is None:
            self._send(404, b"no encontrado")
            return
        name, content_type = entry
        # Los ficheros estaticos no llevan nada secreto: se sirven sin token,
        # porque el navegador no puede anadirlo a una navegacion.
        self._send(200, (UI_DIR / name).read_bytes(), content_type, csp=True)

    def do_POST(self) -> None:  # noqa: N802
        if not (self._host_ok() and self._same_origin()):
            self._send(403, b"acceso denegado")
            return
        route = urlsplit(self.path).path
        body = self._json_body()
        if body is None:
            self._send(400, b"se esperaba un objeto JSON")
            return
        if route == "/api/bootstrap":
            token = self.panel.redeem(str(body.get("code") or ""))
            if token is None:
                self._reply(403, {"ok": False, "error": "codigo invalido o ya usado: "
                                  "abra la direccion que imprimio la terminal"})
                return
            self._reply(200, {"ok": True, "result": {"token": token}})
            return
        if route == "/api/call":
            supplied = self.headers.get("X-FS-Token", "")
            if not self.panel.token_ok(supplied):
                self._reply(403, {"ok": False, "error": "token invalido"})
                return
            self._reply(200, self.panel.submit(body))
            return
        self._send(404, b"no encontrado")

    # -- utilidades -----------------------------------------------------
    def _reply(self, code: int, payload: dict[str, Any]) -> None:
        self._send(code, json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _send(self, code: int, payload: bytes,
              content_type: str = "text/plain; charset=utf-8", csp: bool = False) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        if csp:
            self.send_header("Content-Security-Policy", CSP)
        self.end_headers()
        self.wfile.write(payload)


class PanelServer:
    """Servidor del panel. El hilo principal atiende las ordenes con :meth:`serve`."""

    #: Segundos que una peticion espera respuesta del hilo principal. Arrancar
    #: el navegador y el proxy puede tardar; una orden colgada mas que esto se
    #: da por perdida en lugar de dejar la pagina esperando para siempre.
    REPLY_TIMEOUT = 300.0

    def __init__(self, bridge: Bridge, host: str = "127.0.0.1", port: int = 0):
        self.bridge = bridge
        self._token = secrets.token_urlsafe(32)
        self._code: str | None = secrets.token_urlsafe(24)
        self._lock = threading.Lock()
        self._orders: "queue.Queue[_Order]" = queue.Queue()
        handler = type("BoundPanelHandler", (PanelHandler,), {"panel": self})
        self.httpd = ThreadingHTTPServer((host, port), handler)
        self.httpd.daemon_threads = True
        port = self.port
        self.allowed_hosts = frozenset({f"127.0.0.1:{port}", f"localhost:{port}"})
        self.allowed_origins = frozenset(f"http://{h}" for h in self.allowed_hosts)
        self._thread: threading.Thread | None = None

    # -- datos publicos -------------------------------------------------
    @property
    def port(self) -> int:
        return int(self.httpd.server_address[1])

    @property
    def url(self) -> str:
        """Direccion para el navegador, con el codigo de un solo uso."""
        return f"http://127.0.0.1:{self.port}/#code={self._code or ''}"

    # -- acceso ---------------------------------------------------------
    def redeem(self, code: str) -> str | None:
        """Canjea el codigo de un solo uso por el token de la sesion."""
        with self._lock:
            if self._code is None or not code or not hmac.compare_digest(code, self._code):
                return None
            self._code = None
            return self._token

    def token_ok(self, supplied: str) -> bool:
        return bool(supplied) and hmac.compare_digest(supplied, self._token)

    # -- ordenes --------------------------------------------------------
    def submit(self, request: dict[str, Any]) -> dict[str, Any]:
        """Encola una orden para el hilo principal y espera su respuesta."""
        order = _Order(request)
        self._orders.put(order)
        try:
            return order.reply.get(timeout=self.REPLY_TIMEOUT)
        except queue.Empty:
            return {"ok": False, "error": "el nucleo no respondio a tiempo"}

    def serve(self, poll: float = 0.25) -> None:
        """Atiende ordenes en el hilo actual hasta que el puente se cierre."""
        while not self.bridge.closed:
            try:
                order = self._orders.get(timeout=poll)
            except queue.Empty:
                continue
            order.reply.put(self.bridge.handle(order.request))

    # -- ciclo de vida --------------------------------------------------
    def start(self) -> "PanelServer":
        self._thread = threading.Thread(target=self.httpd.serve_forever,
                                        kwargs={"poll_interval": 0.1},
                                        name="firmascope-panel", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
