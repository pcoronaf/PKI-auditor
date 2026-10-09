"""El proxy: el sensor que ve el cuerpo que los otros no pueden.

La prueba que importa es la del cuerpo multipart. CDP entrega
``postData`` vacio para una subida ``multipart/form-data``, asi que sin proxy la
afirmacion "el .key salio" descansa solo en la procedencia que el agente
infiere. Con proxy se encuentra la representacion del canario dentro del cuerpo
que de verdad viajo, y eso es prueba de contenido.
"""

from __future__ import annotations

import http.client
import json
import time

import pytest

from firmascope.audit_core.config import AuditConfig, ProxyConfig, proxy_available
from firmascope.audit_core.events import Event, Tag
from firmascope.audit_core.secrets import SecretVault
from firmascope.evidence_store.store import EvidenceStore
from firmascope.proxy_addon.addon import FirmaScopeAddon, _clip_headers
from firmascope.proxy_addon.runner import ProxyRunner, free_port

SESSION = "FS-2099-0003"
SECRETO = b"CLAVE-PRIVADA-DE-PRUEBA-0123456789ABCDEF" * 4
PASSWORD = "FSCOPE-AUDIT-PWD-9999"

requiere_mitmproxy = pytest.mark.skipif(
    not proxy_available(), reason="mitmproxy no esta instalado")


# ----------------------------------------------------------------------
# Unitarias: no necesitan mitmproxy
# ----------------------------------------------------------------------

def test_las_credenciales_de_sesion_no_entran_en_el_expediente():
    salida = _clip_headers({
        "Content-Type": "application/json",
        "Cookie": "sesion=secreta",
        "Authorization": "Bearer abcdef",
    })
    assert salida["Content-Type"] == "application/json"
    assert "secreta" not in salida["Cookie"]
    assert "abcdef" not in salida["Authorization"]


def test_sin_vault_el_cuerpo_se_declara_opaco_y_no_inocuo():
    """No poder mirar no es haber mirado y no encontrar nada."""
    addon = FirmaScopeAddon(vault=None)
    tags, matches = addon._classify(b"x" * 500, "application/json")
    assert tags == [Tag.UNCLASSIFIED.value]
    assert matches == []
    assert addon.summary()["has_vault"] is False


def test_el_cuerpo_no_se_conserva_si_no_se_pidio():
    addon = FirmaScopeAddon(capture_bodies=False, max_body_bytes=1024)
    assert addon._keep(b"datos") is None
    permisivo = FirmaScopeAddon(capture_bodies=True, max_body_bytes=3)
    assert permisivo._keep(b"datos") == b"dat"


def test_el_proxy_del_nivel_4_se_decide_por_el_nivel():
    assert AuditConfig(target="https://x.mx", level=3).proxy_enabled is False
    assert AuditConfig(target="https://x.mx", level=4).proxy_enabled is proxy_available()
    # Una decision explicita del operador se respeta.
    apagado = AuditConfig(target="https://x.mx", level=4,
                          proxy=ProxyConfig(enabled=False))
    assert apagado.proxy_enabled is False


def test_con_credencial_real_el_proxy_no_persiste_cuerpos():
    """Un cuerpo guardado podria contener la clave: no es negociable."""
    config = AuditConfig(target="https://x.mx", level=4, credential_mode="real",
                         acknowledge_real_credentials=True,
                         proxy=ProxyConfig(enabled=True, capture_bodies=True))
    assert config.proxy.capture_bodies is False


# ----------------------------------------------------------------------
# Con mitmproxy en marcha
# ----------------------------------------------------------------------

@pytest.fixture
def proxy(tmp_path):
    vault = SecretVault()
    vault.register(Tag.KEY_FILE.value, SECRETO)
    vault.register(Tag.KEY_PASSWORD.value, PASSWORD, is_text=True)

    store = EvidenceStore(tmp_path, SESSION, vault)
    store.open_session(target="http://127.0.0.1:8765/", config={}, versions={}, note="")

    config = AuditConfig(target="http://127.0.0.1:8765/", level=4,
                         output_dir=tmp_path,
                         proxy=ProxyConfig(enabled=True, port=free_port()))
    eventos: list[Event] = []

    def emit(event):
        eventos.append(event)
        return store.add_event(event)

    runner = ProxyRunner(config, SESSION, store, emit, vault)
    assert runner.start(), runner.error
    runner.eventos = eventos          # para las aserciones
    runner.store_ref = store
    yield runner
    runner.stop()
    store.close_session()
    store.close()
    vault.destroy()


def _post(runner, url: str, body: bytes, content_type: str, host: str):
    conn = http.client.HTTPConnection(runner.host, runner.port, timeout=10)
    conn.request("POST", url, body=body,
                 headers={"Content-Type": content_type, "Host": host})
    response = conn.getresponse()
    response.read()
    return response.status


@requiere_mitmproxy
def test_encuentra_el_canario_en_un_cuerpo_json(proxy, lab):
    import base64

    cuerpo = json.dumps({"k": base64.b64encode(SECRETO).decode(),
                         "p": PASSWORD}).encode()
    assert _post(proxy, "http://localhost:8766/collect", cuerpo,
                 "application/json", "localhost:8766") == 204
    time.sleep(0.6)
    assert proxy.pump() >= 1

    salidas = [e for e in proxy.eventos if e.data.get("canary_matches")]
    assert salidas, "el proxy no encontro el canario en el cuerpo"
    etiquetas = set(salidas[0].tags)
    assert {Tag.KEY_FILE.value, Tag.KEY_PASSWORD.value} <= etiquetas
    codificaciones = {m["encoding"] for m in salidas[0].data["canary_matches"]}
    assert "base64" in codificaciones


@requiere_mitmproxy
def test_el_cuerpo_multipart_es_lo_que_este_sensor_aporta(proxy, lab):
    """Es el caso que CDP no puede entregar."""
    frontera = "----firmascopeTest"
    cuerpo = (
        f"--{frontera}\r\n"
        'Content-Disposition: form-data; name="private_key"; filename="k.key"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + SECRETO + (
        f"\r\n--{frontera}\r\n"
        'Content-Disposition: form-data; name="key_password"\r\n\r\n'
        f"{PASSWORD}\r\n--{frontera}--\r\n"
    ).encode()

    # El servidor del laboratorio intenta firmar con lo que recibe, y estos
    # bytes no son un .key valido: respondera 400. Da igual. Lo que se prueba
    # es lo que vio el proxy por el camino, no el veredicto del servidor.
    assert _post(proxy, "http://127.0.0.1:8765/api/sign-server-side", cuerpo,
                 f"multipart/form-data; boundary={frontera}",
                 "127.0.0.1:8765") in (200, 400)
    time.sleep(0.6)
    proxy.pump()

    salidas = [e for e in proxy.eventos if e.data.get("canary_matches")]
    assert salidas, "el .key dentro del multipart no se detecto"
    evento = salidas[0]
    assert evento.data.get("body_recovered_by_proxy") is True, \
        "no se marco que este cuerpo lo aporta el proxy"
    assert Tag.KEY_FILE.value in evento.tags
    # La prueba es de contenido: los bytes en bruto estaban ahi.
    assert any(m["encoding"] in ("raw", "raw-marker")
               for m in evento.data["canary_matches"])


@requiere_mitmproxy
def test_el_secreto_no_llega_al_expediente(proxy, lab):
    import base64

    cuerpo = json.dumps({"k": base64.b64encode(SECRETO).decode(),
                         "p": PASSWORD}).encode()
    _post(proxy, "http://localhost:8766/collect", cuerpo,
          "application/json", "localhost:8766")
    time.sleep(0.6)
    proxy.pump()
    proxy.store_ref.close_session()

    crudo = (proxy.store_ref.root / "session.sqlite").read_bytes()
    assert SECRETO not in crudo
    assert base64.b64encode(SECRETO) not in crudo
    assert PASSWORD.encode() not in crudo


@requiere_mitmproxy
def test_la_ca_efimera_se_destruye_al_parar(tmp_path):
    from pathlib import Path

    vault = SecretVault()
    store = EvidenceStore(tmp_path, SESSION, vault)
    store.open_session(target="http://127.0.0.1/", config={}, versions={}, note="")
    config = AuditConfig(target="http://127.0.0.1/", level=4, output_dir=tmp_path,
                         proxy=ProxyConfig(enabled=True, port=free_port()))
    runner = ProxyRunner(config, SESSION, store, lambda e: store.add_event(e), vault)
    assert runner.start(), runner.error

    confdir = Path(str(runner._confdir))
    assert confdir.is_dir()
    assert any(confdir.iterdir()), "mitmproxy no genero la CA"

    runner.stop()
    # La clave privada de la CA no sobrevive a la sesion que la creo.
    assert not confdir.exists()
    store.close_session()
    store.close()
    vault.destroy()


@requiere_mitmproxy
def test_el_resumen_dice_que_sensores_hubo(proxy, lab):
    resumen = proxy.summary()
    assert resumen["running"] is True
    assert resumen["has_vault"] is True
    assert resumen["ephemeral_ca"] is True
    assert resumen["mitmproxy"]
