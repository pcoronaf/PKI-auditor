"""Servidor de las aplicaciones de laboratorio.

Levanta dos servidores en el mismo proceso:

* el *portal* (puerto 8765), que sirve las aplicaciones;
* el *recolector* (puerto 8766), un tercero distinto que recibe lo que las
  aplicaciones maliciosas exfiltran.

Son dos origenes separados a proposito: es lo que permite que el clasificador
de terceros de FirmaScope tenga algo que clasificar, y lo que hace que el
aislamiento de red tenga un destino que bloquear.

El recolector *registra* lo recibido para que las pruebas puedan comprobar que
la exfiltracion ocurrio de verdad, y nunca lo persiste en disco.
"""

from __future__ import annotations

import json
import threading
from functools import partial
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

APPS = Path(__file__).parent / "apps"
PORTAL_PORT = 8765
COLLECTOR_PORT = 8766

#: Banderas que sirve el portal. ``demo-static-only`` las consulta: ponerlas a
#: cierto convierte su ruta estatica en una exfiltracion observada, que es como
#: se comprueba que el nivel 1 y el nivel 2 coinciden cuando deben.
FLAGS: dict[str, Any] = {"collectKeyMaterial": False}

#: Cuenta de demo-login. Da acceso a la plataforma simulada, no a ninguna
#: e.firma: es el equivalente a la cuenta del operador en el portal.
LAB_LOGIN_USER = "operador"
LAB_LOGIN_PASSWORD = "laboratorio-firmascope"
LAB_SESSION_COOKIE = "fs_lab_session"

#: Rutas de demo-login que exigen sesion. La pagina de acceso no.
PROTECTED_PATHS = ("/demo-login/", "/demo-login/index.html", "/demo-login/app.js")

#: Sesiones validas: cookie -> token de acceso. Solo en memoria.
LAB_SESSIONS: dict[str, str] = {}

#: Pings autenticados que recibio demo-login. Es la verdad conocida de que la
#: auditoria corrio de verdad dentro de la sesion, y no ante la pagina de acceso.
LOGIN_PINGS: list[str] = []


class PortalHandler(SimpleHTTPRequestHandler):
    """Sirve las aplicaciones y responde a sus endpoints."""

    def log_message(self, fmt: str, *args: Any) -> None:  # silencio
        pass

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _session(self) -> str | None:
        """Cookie de sesion valida de demo-login, o ``None``."""
        from http.cookies import CookieError, SimpleCookie

        jar = SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
        except CookieError:
            return None
        morsel = jar.get(LAB_SESSION_COOKIE)
        return morsel.value if morsel is not None and morsel.value in LAB_SESSIONS else None

    def _redirect(self, location: str, status: int = 302, cookie: str = "") -> None:
        self.send_response(status)
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]
        if path in PROTECTED_PATHS and self._session() is None:
            self._redirect("/demo-login/login.html")
            return
        if path == "/api/me":
            session = self._session()
            if session is None:
                self._json(401, {"error": "sin sesion"})
            else:
                self._json(200, {"user": LAB_LOGIN_USER, "access_token": LAB_SESSIONS[session]})
            return
        if path == "/api/ping":
            from urllib.parse import parse_qs, urlsplit

            token = (parse_qs(urlsplit(self.path).query).get("access_token") or [""])[0]
            if self._session() is not None and token in LAB_SESSIONS.values():
                LOGIN_PINGS.append(token)
                self._json(200, {"ok": True})
            else:
                self._json(401, {"error": "token invalido"})
            return
        if self.path.startswith("/api/flags"):
            self._json(200, FLAGS)
            return
        if self.path == "/":
            apps = sorted(p.name for p in APPS.iterdir()
                          if p.is_dir() and p.name.startswith("demo-"))
            links = "".join(f'<li><a href="/{name}/">{name}</a></li>' for name in apps)
            body = (f"<!doctype html><meta charset=utf-8>"
                    f"<title>FirmaScope lab</title>"
                    f"<h1>Aplicaciones de laboratorio</h1>"
                    f"<p><strong>No use credenciales reales.</strong> Varias de estas "
                    f"aplicaciones envian la clave a un tercero a proposito. Use la "
                    f"credencial sintetica de <code>firmascope credentials new</code>.</p>"
                    f"<ul>{links}</ul>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if self.path.startswith("/api/login"):
            import secrets
            from urllib.parse import parse_qs

            form = parse_qs(body.decode("utf-8", "replace"))
            if ((form.get("username") or [""])[0] != LAB_LOGIN_USER
                    or (form.get("password") or [""])[0] != LAB_LOGIN_PASSWORD):
                self._json(401, {"error": "usuario o contrasena incorrectos"})
                return
            session = secrets.token_urlsafe(24)
            LAB_SESSIONS[session] = secrets.token_urlsafe(24)
            self._redirect("/demo-login/", 303,
                           f"{LAB_SESSION_COOKIE}={session}; HttpOnly; Path=/; SameSite=Lax")
            return
        if self.path.startswith("/api/sign-server-side"):
            # El portal recibe la clave y la usa. Firmar de verdad es lo que
            # hace concreto el riesgo de esta arquitectura: un servidor que
            # tiene el .key y la contrasena puede firmar cuando quiera, no solo
            # cuando el titular se lo pide. La clave no se guarda: el
            # laboratorio no necesita conservarla para demostrarlo.
            result = _sign_server_side(self.headers.get("Content-Type", ""), body)
            SERVER_SIDE.append({"bytes": len(body), "signed": "signature" in result})
            self._json(200 if "signature" in result else 400, result)
            return
        if self.path.startswith("/api/submit"):
            self._json(200, {"accepted": True})
            return
        self._json(404, {"error": "no such endpoint"})


#: Peticiones de firma del lado servidor, para las pruebas.
SERVER_SIDE: list[dict[str, Any]] = []


def _multipart_fields(content_type: str, body: bytes) -> dict[str, bytes]:
    """Campos de un cuerpo multipart/form-data, con la biblioteca estandar."""
    from email.parser import BytesParser
    from email.policy import HTTP

    message = BytesParser(policy=HTTP).parsebytes(
        f"Content-Type: {content_type}\r\n\r\n".encode() + body)
    fields: dict[str, bytes] = {}
    for part in message.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if name:
            fields[str(name)] = part.get_payload(decode=True) or b""
    return fields


def _sign_server_side(content_type: str, body: bytes) -> dict[str, Any]:
    """Firma el documento con la clave que subio el navegador."""
    import base64

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    if "multipart/form-data" not in content_type:
        return {"error": "se esperaba multipart/form-data"}
    fields = _multipart_fields(content_type, body)
    key_der = fields.get("private_key") or fields.get("key")
    password = fields.get("key_password") or fields.get("password")
    document = fields.get("document", b"")
    if not key_der or password is None:
        return {"error": "faltan la clave o la contrasena"}
    try:
        key = serialization.load_der_private_key(key_der, password=password.strip())
        signature = key.sign(document, padding.PKCS1v15(), hashes.SHA256())
    except Exception as exc:
        return {"error": f"no se pudo firmar: {type(exc).__name__}"}
    return {"signed": True, "where": "server",
            "signature": base64.b64encode(signature).decode()}
#: Lo que recibio el recolector, para las pruebas.
COLLECTED: list[dict[str, Any]] = []


class CollectorHandler(BaseHTTPRequestHandler):
    """El tercero que recibe la exfiltracion."""

    def log_message(self, fmt: str, *args: Any) -> None:
        pass

    def _record(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        COLLECTED.append({
            "method": self.command,
            "path": self.path,
            "size": len(body),
            "content_type": self.headers.get("Content-Type", ""),
        })
        self.send_response(204)
        # CORS abierto: el recolector de un atacante no se pone trabas.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    do_GET = do_POST = do_PUT = _record  # type: ignore[assignment]

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "*")
        self.end_headers()


def serve(portal_port: int = PORTAL_PORT,
          collector_port: int = COLLECTOR_PORT) -> tuple[ThreadingHTTPServer, ThreadingHTTPServer]:
    """Arranca ambos servidores en hilos de fondo y los devuelve."""
    portal = ThreadingHTTPServer(
        ("127.0.0.1", portal_port),
        partial(PortalHandler, directory=str(APPS)))
    collector = ThreadingHTTPServer(("127.0.0.1", collector_port), CollectorHandler)
    for server in (portal, collector):
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
    return portal, collector


def main() -> int:
    portal, collector = serve()
    print(f"portal      http://127.0.0.1:{portal.server_address[1]}/")
    print(f"recolector  http://127.0.0.1:{collector.server_address[1]}/")
    print("Ctrl-C para terminar.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print()
    finally:
        portal.shutdown()
        collector.shutdown()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
