"""Servidor de las aplicaciones de laboratorio.

Sirve las cinco demos y los endpoints que necesitan para comportarse como
aplicaciones reales:

``/api/sign-receipt``   recibe la firma. Lo que todo sitio correcto hace.
``/api/server-sign``    recibe el .key y la contrasena, y firma en el servidor.
``/collect/...``        recolector de las demos que exfiltran.

Nada de lo recibido se escribe a disco. El servidor cuenta lo que llego y
descarta el contenido: un laboratorio que persistiera claves privadas seria
peor que el problema que ayuda a estudiar.
"""

from __future__ import annotations

import base64
import json
import re
import threading
from dataclasses import dataclass, field
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Any

APPS_DIR = Path(__file__).parent / "apps"

#: Nombres de las demos empaquetadas.
DEMOS = (
    "demo-safe",
    "demo-key-exfiltration",
    "demo-encrypted-exfiltration",
    "demo-server-sign",
    "demo-static-only",
)


@dataclass
class Received:
    """Contador de lo que llego a cada endpoint, sin guardar el contenido."""

    receipts: int = 0
    server_signs: int = 0
    collected: list[dict[str, Any]] = field(default_factory=list)

    def note_collection(self, path: str, size: int) -> None:
        self.collected.append({"path": path, "bytes": size})


class LabHandler(SimpleHTTPRequestHandler):
    """Maneja los ficheros estaticos y los endpoints del laboratorio."""

    received: Received
    quiet = True

    def log_message(self, fmt: str, *args) -> None:  # pragma: no cover - ruido
        if not self.quiet:
            super().log_message(fmt, *args)

    # -- rutas -----------------------------------------------------------
    def translate_path(self, path: str) -> str:
        clean = path.split("?", 1)[0].split("#", 1)[0]
        relative = clean.lstrip("/")
        if not relative:
            return str(APPS_DIR / "index.html")
        target = (APPS_DIR / relative).resolve()
        # Impide salir del directorio de las aplicaciones.
        if not str(target).startswith(str(APPS_DIR.resolve())):
            return str(APPS_DIR)
        if target.is_dir():
            return str(target / "index.html")
        return str(target)

    def do_GET(self) -> None:
        if self.path.split("?")[0] in ("/", "/index.html"):
            self._send(200, "text/html; charset=utf-8", _index_page().encode("utf-8"))
            return
        if self.path.split("?")[0] == "/__lab/received":
            self._send(200, "application/json",
                       json.dumps(self.received.__dict__, default=str).encode("utf-8"))
            return
        super().do_GET()

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""

        if path == "/api/sign-receipt":
            self.received.receipts += 1
            self._json(200, {"status": "ok", "bytes": len(body)})
            return

        if path == "/api/server-sign":
            self.received.server_signs += 1
            self._json(200, _server_sign(body, self.headers.get("Content-Type", "")))
            return

        if path.startswith("/collect"):
            # El recolector de las demos inseguras: cuenta y descarta.
            self.received.note_collection(path, len(body))
            self._json(200, {"status": "ok"})
            return

        self._json(404, {"error": "endpoint desconocido"})

    # -- utilidades -------------------------------------------------------
    def _send(self, code: int, content_type: str, payload: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _json(self, code: int, payload: dict[str, Any]) -> None:
        self._send(code, "application/json", json.dumps(payload).encode("utf-8"))


# ----------------------------------------------------------------------
# Firma en el servidor (demo-server-sign)
# ----------------------------------------------------------------------

def _server_sign(body: bytes, content_type: str) -> dict[str, Any]:
    """Firma con la clave que el navegador acaba de subir.

    Que esto funcione es justamente lo que hace peligroso al patron: el
    servidor demuestra tener todo lo necesario para firmar en nombre del
    titular, ahora y cuando quiera.
    """
    try:
        parts = _parse_multipart(body, content_type)
        key_bytes = parts.get("key", b"")
        password = parts.get("password", b"")
        document = parts.get("document", b"")
        if not key_bytes or not password:
            return {"error": "faltan la clave o la contrasena"}

        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        private_key = serialization.load_der_private_key(key_bytes, password=password)
        signature = private_key.sign(document, padding.PKCS1v15(), hashes.SHA256())
        return {
            "signature": base64.b64encode(signature).decode("ascii"),
            "signed_by": "servidor",
        }
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}


_BOUNDARY = re.compile(r'boundary="?([^";]+)"?', re.I)
_DISPOSITION = re.compile(rb'name="([^"]*)"')


def _parse_multipart(body: bytes, content_type: str) -> dict[str, bytes]:
    """Parser minimo de ``multipart/form-data``.

    Solo cubre lo que las demos envian. No pretende ser un parser general.
    """
    match = _BOUNDARY.search(content_type or "")
    if not match:
        return {}
    delimiter = b"--" + match.group(1).encode("ascii")
    out: dict[str, bytes] = {}
    for chunk in body.split(delimiter):
        if not chunk.strip() or chunk.strip() == b"--":
            continue
        head, _, payload = chunk.partition(b"\r\n\r\n")
        name = _DISPOSITION.search(head)
        if not name:
            continue
        out[name.group(1).decode("utf-8", "replace")] = payload.rstrip(b"\r\n")
    return out


# ----------------------------------------------------------------------
# Indice
# ----------------------------------------------------------------------

def _index_page() -> str:
    items = "".join(
        f'<li><a href="/{demo}/">{demo}</a></li>' for demo in DEMOS if (APPS_DIR / demo).is_dir()
    )
    return (
        '<!doctype html><html lang="es"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>Laboratorio de FirmaScope</title>"
        '<link rel="stylesheet" href="/shared/lab.css"></head><body><main>'
        "<h1>Laboratorio de FirmaScope</h1>"
        '<p class="warn">Aplicaciones de prueba. No uses credenciales reales: '
        "genera unas sinteticas con <code>firmascope credentials new</code>.</p>"
        f"<ul>{items}</ul></main></body></html>"
    )


# ----------------------------------------------------------------------
# Arranque
# ----------------------------------------------------------------------

class LabServer:
    """Servidor de laboratorio con ciclo de vida explicito."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0, quiet: bool = True):
        self.received = Received()
        handler = type("BoundLabHandler", (LabHandler,),
                       {"received": self.received, "quiet": quiet})
        self.httpd = HTTPServer((host, port), handler)
        self.thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return int(self.httpd.server_address[1])

    @property
    def base_url(self) -> str:
        host, port = self.httpd.server_address[0], self.port
        return f"http://{host}:{port}"

    def start(self) -> "LabServer":
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        if self.thread is not None:
            self.thread.join(timeout=5)

    def url_for(self, demo: str, **params: str) -> str:
        query = "&".join(f"{k}={v}" for k, v in params.items())
        return f"{self.base_url}/{demo}/" + (f"?{query}" if query else "")

    def __enter__(self) -> "LabServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


def serve(host: str = "127.0.0.1", port: int = 8000, quiet: bool = False) -> None:
    """Arranca el laboratorio en primer plano (``firmascope labs serve``)."""
    server = LabServer(host, port, quiet=quiet)
    print(f"Laboratorio de FirmaScope en {server.base_url}")
    print("Aplicaciones: " + ", ".join(DEMOS))
    print("Ctrl-C para detener.")
    try:
        server.httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.httpd.server_close()
