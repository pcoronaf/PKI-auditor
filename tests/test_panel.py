"""El panel: la interfaz servida en 127.0.0.1, y las defensas de su puerto.

El panel es una excepcion aceptada a "la interfaz no abre puertos" (ver
CLAUDE.md). Estas pruebas fijan las condiciones de esa excepcion: que una
pagina de otro origen, un Host ajeno o alguien sin el token no consiguen nada,
que el codigo de la URL sirve una sola vez, y que el aviso de riesgo llega a la
pagina. Hablan HTTP directamente, como lo haria un atacante.
"""

from __future__ import annotations

import http.client
import json
import threading

import pytest

from firmascope.gui_bridge.bridge import Bridge
from firmascope.gui_bridge.panel import PANEL_WARNING, PanelServer


@pytest.fixture
def panel():
    bridge = Bridge(seed={"target": "portal.ejemplo.mx"}, notice=PANEL_WARNING)
    server = PanelServer(bridge).start()
    # El hilo principal de la prueba hace de cliente; las ordenes las atiende
    # otro hilo. Sin Playwright de por medio, cualquier hilo sirve.
    worker = threading.Thread(target=server.serve, daemon=True)
    worker.start()
    yield server
    bridge.handle({"id": 0, "cmd": "shutdown"})
    worker.join(timeout=5)
    server.stop()


def request(server, method, path, body=None, headers=None, host=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
    data = None if body is None else json.dumps(body).encode()
    sent = {"Host": host or f"127.0.0.1:{server.port}"}
    if data is not None:
        sent["Content-Type"] = "application/json"
    sent.update(headers or {})
    conn.request(method, path, body=data, headers=sent)
    res = conn.getresponse()
    payload = res.read()
    conn.close()
    return res, payload


def code_of(server) -> str:
    return server.url.split("#code=", 1)[1]


def token_of(server) -> str:
    res, payload = request(server, "POST", "/api/bootstrap", {"code": code_of(server)})
    assert res.status == 200, payload
    return json.loads(payload)["result"]["token"]


def call(server, token, cmd, args=None, headers=None):
    return request(server, "POST", "/api/call", {"cmd": cmd, "args": args or {}},
                   headers={"X-FS-Token": token, **(headers or {})})


# ----------------------------------------------------------------------

def test_escucha_solo_en_loopback(panel):
    assert panel.httpd.server_address[0] == "127.0.0.1"
    assert panel.url.startswith(f"http://127.0.0.1:{panel.port}/#code=")


def test_la_url_lleva_un_codigo_y_no_el_token(panel):
    """La URL aparece en la lista de procesos mientras arranca el navegador."""
    token = token_of(panel)
    assert token not in panel.url


def test_el_codigo_sirve_una_sola_vez(panel):
    token_of(panel)
    res, _ = request(panel, "POST", "/api/bootstrap", {"code": code_of(panel) or "x"})
    assert res.status == 403


def test_sirve_la_misma_interfaz_que_tauri_con_csp(panel):
    from firmascope.gui_bridge.panel import UI_DIR

    res, payload = request(panel, "GET", "/")
    assert res.status == 200
    assert payload == (UI_DIR / "index.html").read_bytes()
    csp = res.getheader("Content-Security-Policy")
    assert "script-src 'self'" in csp and "connect-src 'self'" in csp
    assert res.getheader("X-Frame-Options") == "DENY"


@pytest.mark.parametrize("path", ["/../pyproject.toml", "/bridge.py", "/ui/app.js",
                                  "/%2e%2e/secrets.py"])
def test_no_sirve_nada_fuera_de_la_interfaz(panel, path):
    res, _ = request(panel, "GET", path)
    assert res.status == 404


def test_un_host_ajeno_no_llega_ni_a_la_pagina(panel):
    """DNS rebinding: un dominio del atacante que resuelve a 127.0.0.1."""
    res, _ = request(panel, "GET", "/", host=f"atacante.ejemplo:{panel.port}")
    assert res.status == 403
    token = token_of(panel)
    res, _ = request(panel, "POST", "/api/call", {"cmd": "hello"},
                     headers={"X-FS-Token": token}, host="atacante.ejemplo")
    assert res.status == 403


def test_sin_token_no_hay_ordenes(panel):
    res, _ = request(panel, "POST", "/api/call", {"cmd": "hello"})
    assert res.status == 403
    res, _ = call(panel, "token-inventado", "hello")
    assert res.status == 403


@pytest.mark.parametrize("headers", [
    {"Origin": "https://atacante.ejemplo"},
    {"Origin": "null"},
    {"Sec-Fetch-Site": "cross-site"},
    {"Sec-Fetch-Site": "same-site"},
])
def test_otro_origen_no_da_ordenes_aunque_tenga_el_token(panel, headers):
    token = token_of(panel)
    res, _ = call(panel, token, "hello", headers=headers)
    assert res.status == 403


def test_solo_acepta_json(panel):
    """Un formulario HTML de otra web no puede enviar application/json sin CORS."""
    token = token_of(panel)
    conn = http.client.HTTPConnection("127.0.0.1", panel.port, timeout=10)
    conn.request("POST", "/api/call", body="cmd=hello", headers={
        "Host": f"127.0.0.1:{panel.port}", "X-FS-Token": token,
        "Content-Type": "application/x-www-form-urlencoded"})
    assert conn.getresponse().status == 400
    conn.close()


def test_con_el_token_habla_con_el_puente_y_trae_el_aviso(panel):
    token = token_of(panel)
    res, payload = call(panel, token, "hello")
    assert res.status == 200
    hello = json.loads(payload)["result"]
    assert hello["notice"] == PANEL_WARNING
    res, payload = call(panel, token, "schema")
    defaults = json.loads(payload)["result"]["defaults"]
    # Lo indicado en `audit URL --panel` precarga el formulario.
    assert defaults["target"] == "portal.ejemplo.mx"


def test_el_aviso_dice_el_riesgo_y_la_alternativa():
    texto = PANEL_WARNING.lower()
    assert "puerto local" in texto and "127.0.0.1" in texto
    assert "sin cifrar" in texto
    assert "compartido" in texto
    assert "tauri" in texto


def test_la_aplicacion_de_escritorio_no_trae_aviso():
    assert Bridge().cmd_hello()["notice"] == ""


def test_la_cli_ofrece_el_panel():
    from firmascope.cli.main import build_parser

    parser = build_parser()
    args = parser.parse_args(["panel", "portal.ejemplo.mx", "--no-browser"])
    assert args.func.__name__ == "cmd_panel" and args.no_browser
    args = parser.parse_args(["audit", "portal.ejemplo.mx", "--panel"])
    assert args.panel


# ----------------------------------------------------------------------
# Lo que la interfaz resalta lo decide el nucleo
# ----------------------------------------------------------------------

def test_la_salida_de_material_privado_la_marca_el_nucleo():
    from firmascope.audit_core.events import Event, EventType, Tag

    bridge = Bridge()
    bridge._collect(Event(EventType.NETWORK_REQUEST, "s", tags=[Tag.KEY_FILE],
                          data={"host": "recolector.ejemplo"}))
    bridge._collect(Event(EventType.NETWORK_REQUEST, "s", tags=[Tag.SIGNATURE]))
    bridge._collect(Event(EventType.FILE_READ, "s", tags=[Tag.KEY_FILE]))
    bridge._collect(Event(EventType.BEACON_SEND, "s", tags=[Tag.KEY_PASSWORD],
                          data={"blocked": True}))
    marcas = [e["private_egress"] for e in bridge._take_events()]
    # Leer la clave no es sacarla; enviar la firma tampoco. Un intento
    # bloqueado si cuenta: el sitio lo intento.
    assert marcas == [True, False, False, True]


def test_el_contador_de_peticiones_cuenta_lo_que_hay_en_el_expediente(tmp_path):
    """En el piloto del panel, la interfaz mostraba "0 peticiones" con el portal
    enviando decenas: el contador no lo incrementaba nadie."""
    from firmascope.audit_core.config import AuditConfig
    from firmascope.audit_core.orchestrator import AuditSession
    from firmascope.evidence_store.store import RequestRecord

    session = AuditSession(AuditConfig(target="https://portal.ejemplo.mx", output_dir=tmp_path))
    try:
        for _ in range(3):
            session.store.add_request(RequestRecord(
                timestamp=0.0, method="GET", url="https://portal.ejemplo.mx/api",
                host="portal.ejemplo.mx", registrable="ejemplo.mx"))
        assert session.live_stats()["requests"] == 3
    finally:
        session.store.close()
        session.vault.destroy()


def test_una_pestana_que_se_cierra_no_llena_la_terminal_de_trazas(capsys):
    """En Windows, cerrar el panel con ordenes en curso imprimia un
    ConnectionAbortedError por peticion."""
    import socket

    from firmascope.gui_bridge.panel import PanelHandler

    class Abortada:
        def write(self, _data):
            raise ConnectionAbortedError(10053, "conexion abortada")

    handler = PanelHandler.__new__(PanelHandler)
    handler.wfile = Abortada()
    handler.request_version = "HTTP/1.1"
    handler._headers_buffer = []
    handler.send_response = lambda *a, **k: None
    handler.send_header = lambda *a, **k: None
    handler.end_headers = lambda: None
    handler._send(200, b"{}")          # no lanza
    server = PanelServer(Bridge())
    try:
        try:
            raise ConnectionAbortedError(10053, "conexion abortada")
        except ConnectionAbortedError:
            with socket.socket() as sock:
                server.httpd.handle_error(sock, ("127.0.0.1", 1))
    finally:
        server.httpd.server_close()
    assert "Traceback" not in capsys.readouterr().err
