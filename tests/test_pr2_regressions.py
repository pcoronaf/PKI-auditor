"""Regresiones de los fallos que el PR #2 encontro y que existian en main.

El PR #2 se construyo sobre una implementacion que ya no existe, de modo que no
se podia fusionar. Pero sus fallos si existian en el codigo actual: se
reprodujeron uno por uno antes de corregirlos.

Hay dos clases de prueba aqui:

* **regresiones**: fallan con el codigo anterior a la correccion (se comprobo
  ejecutandolas contra el main sin corregir);
* **salvaguardas**: pasan con ambos y vigilan que la correccion no se pase de
  largo. Se marcan en su docstring.
"""

from __future__ import annotations

import base64
import json
import urllib.parse

import pytest

from conftest import make_config
from firmascope.audit_core.config import AuditConfig, IsolationMode, IsolationPolicy
from firmascope.audit_core.events import Event, EventType, Tag
from firmascope.audit_core.secrets import SecretVault, redact, redact_url
from firmascope.rule_engine.context import AuditContext
from firmascope.rule_engine.engine import RuleEngine

T0 = 1_791_500_000.0
KEY = b"\x30\x82\x05\x35" + bytes(range(256)) * 5   # forma de un PKCS#8 cifrado


def _vault() -> SecretVault:
    vault = SecretVault()
    vault.register(Tag.KEY_FILE.value, KEY)
    return vault


def _pixel_url() -> str:
    b64 = base64.b64encode(KEY).decode()
    assert "+" in b64 or "/" in b64, "la clave de prueba debe producir caracteres escapables"
    return "https://tercero.example/p.gif?k=" + urllib.parse.quote(b64, safe="")


# ----------------------------------------------------------------------
# 1 y 2. La clave en la URL de un pixel
# ----------------------------------------------------------------------

def test_la_clave_escapada_en_una_url_se_reconoce():
    """encodeURIComponent convierte + / = en %2B %2F %3D: hay que decodificar."""
    vault = _vault()
    assert Tag.KEY_FILE.value in vault.labels_in(_pixel_url())


def test_la_url_con_la_clave_se_redacta_conservando_el_destino():
    """El reporte debe decir a donde salio la clave sin volver a escribirla."""
    vault = _vault()
    limpia = redact_url(_pixel_url(), vault)
    assert limpia.startswith("https://tercero.example/p.gif?")
    assert "<canary:KEY_FILE>" in limpia
    assert vault.labels_in(limpia) == set()


def test_la_redaccion_de_eventos_alcanza_las_urls():
    vault = _vault()
    limpio = redact({"url": _pixel_url(), "host": "tercero.example"}, vault)
    assert "tercero.example" in limpio["url"]
    # Se comprueba con la forma escapada explicita, no con el detector del
    # vault: usar el mismo detector que se esta probando dejaba pasar el fallo.
    escapada = urllib.parse.quote(base64.b64encode(KEY).decode(), safe="")
    assert escapada[100:160] not in json.dumps(limpio)


def test_las_peticiones_se_redactan_antes_de_escribirse(tmp_path):
    """Las peticiones no pasaban por la redaccion: la clave quedaba en disco."""
    from firmascope.evidence_store.store import EvidenceStore, RequestRecord

    vault = _vault()
    store = EvidenceStore(tmp_path, "FS-T", vault)
    store.open_session("https://portal.mx", {}, {})
    url = _pixel_url()
    store.add_request(RequestRecord(timestamp=T0, method="GET", url=url,
                                    headers={"Referer": url}, sensor="cdp"))
    store.close_session()
    store.close()
    crudo = (tmp_path / "session.sqlite").read_bytes()
    b64 = base64.b64encode(KEY).decode()
    assert urllib.parse.quote(b64, safe="").encode() not in crudo
    assert b64.encode() not in crudo


def test_los_sensores_de_red_buscan_en_la_url():
    from firmascope.network_analyzer.canaries import classify

    tags, matches = classify(_vault(), None, _pixel_url())
    assert Tag.KEY_FILE.value in tags
    assert all(m["location"] == "url" for m in matches)


# ----------------------------------------------------------------------
# 3. El sandbox de Chromium
# ----------------------------------------------------------------------

def test_el_sandbox_no_se_desactiva_por_omision():
    """--no-sandbox quitaba el aislamiento de Chromium en el equipo del operador."""
    assert "--no-sandbox" not in AuditConfig(target="https://x.mx").browser_args


def test_el_sandbox_solo_se_desactiva_como_root(monkeypatch):
    import firmascope.browser_controller.launch as launch

    monkeypatch.setattr(launch.os, "geteuid", lambda: 1000, raising=False)
    assert launch.sandbox_by_default() is True
    monkeypatch.setattr(launch.os, "geteuid", lambda: 0, raising=False)
    assert launch.sandbox_by_default() is False


def test_no_sandbox_nunca_se_cuela_por_los_argumentos():
    from firmascope.browser_controller.launch import launch_chromium

    captured = {}

    class FakeChromium:
        def launch(self, **kwargs):
            captured.update(kwargs)
            return object()

    class FakePlaywright:
        chromium = FakeChromium()

    launch_chromium(FakePlaywright(), headless=True,
                    args=["--no-sandbox", "--disable-sync"], sandbox=True)
    assert "--no-sandbox" not in captured["args"]
    assert captured["chromium_sandbox"] is True


# ----------------------------------------------------------------------
# 4 y 5. FS-NET-001
# ----------------------------------------------------------------------

def _ev(t, typ, tags=(), **data):
    return Event(typ, "S", sensor="agent", timestamp=T0 + t,
                 tags=[x.value for x in tags], data=data)


def _req(t, **extra):
    request = {"timestamp": T0 + t, "url": "https://analytics.example.net/c",
               "host": "analytics.example.net", "registrable_domain": "example.net",
               "third_party": True, "method": "POST", "body_size": 40}
    request.update(extra)
    return request


def _net001(events, requests, **config):
    context = AuditContext(config=make_config(target="https://portal.mx", **config),
                           events=events, requests=requests)
    return next(f.status.value for f in RuleEngine().evaluate(context)
                if f.rule_id == "FS-NET-001")


def test_leer_el_documento_no_es_acceder_a_la_clave():
    """El falso FS-NET-001 del primer piloto real del PR #2."""
    eventos = [_ev(0, EventType.FILE_READ, [Tag.DOCUMENT]),
               _ev(600, EventType.FILE_READ, [Tag.KEY_FILE])]
    assert _net001(eventos, [_req(300)]) == "NOT_OBSERVED"
    assert _net001(eventos, [_req(700)]) == "OBSERVED"


def test_leer_el_certificado_tampoco():
    eventos = [_ev(0, EventType.FILE_READ, [Tag.CERTIFICATE]),
               _ev(600, EventType.FILE_READ, [Tag.KEY_FILE])]
    assert _net001(eventos, [_req(300)]) == "NOT_OBSERVED"


def test_una_lectura_sin_clasificar_si_cuenta_por_prudencia():
    """Salvaguarda: restringir el acceso a la clave no debe ignorar lo dudoso."""
    eventos = [_ev(0, EventType.FILE_READ, [Tag.UNCLASSIFIED])]
    assert _net001(eventos, [_req(300)]) == "OBSERVED"


AISLADO = [_ev(0, EventType.FILE_READ, [Tag.KEY_FILE]),
           _ev(5, EventType.NETWORK_OFF), _ev(60, EventType.NETWORK_ON)]


def test_un_tercero_bloqueado_no_recibio_nada():
    assert _net001(AISLADO, [_req(10)]) == "NOT_OBSERVED"
    assert _net001(AISLADO, [_req(70)]) == "OBSERVED"


def test_un_tercero_en_la_lista_de_permitidos_si_recibio():
    """Salvaguarda: aqui la regla del PR #2 -- todo lo emitido sin red se ignora
    -- habria absuelto a un tercero que si recibio el trafico."""
    politica = IsolationPolicy(mode=IsolationMode.ALLOWLIST,
                               allow_hosts=["analytics.example.net"])
    assert _net001(AISLADO, [_req(10)], isolation=politica) == "OBSERVED"


# ----------------------------------------------------------------------
# 6. El reloj de CDP
# ----------------------------------------------------------------------

def test_las_respuestas_de_cdp_se_fechan_con_el_reloj_de_pared():
    from firmascope.network_analyzer.cdp_observer import NetworkObserver

    observer = NetworkObserver.__new__(NetworkObserver)
    observer._clock_offset = None
    # Antes de conocer la diferencia: hora de proceso, nunca 1970.
    assert observer._wall_time({"timestamp": 4786.9}) > 1_000_000_000
    observer._clock_offset = T0 - 4000.0
    assert observer._wall_time({"timestamp": 4786.9}) == pytest.approx(T0 + 786.9)


# ----------------------------------------------------------------------
# 7. Workers
# ----------------------------------------------------------------------

def test_la_marca_del_worker_no_llega_al_servidor():
    from firmascope.browser_controller.controller import strip_worker_mark

    assert strip_worker_mark("https://s.mx/w.js?__fs_worker=1") == "https://s.mx/w.js"
    assert strip_worker_mark("https://s.mx/w.js?v=3&__fs_worker=1") == "https://s.mx/w.js?v=3"


# ----------------------------------------------------------------------
# 8. Credenciales de sesion en las cabeceras
# ----------------------------------------------------------------------

def test_cdp_no_guarda_las_credenciales_de_sesion():
    """CDP guardaba Authorization y Cookie tal cual; el proxy si las omitia.

    En un portal real son las del operador: con ellas se le puede suplantar.
    """
    from firmascope.network_analyzer.cdp_observer import _clip_headers

    limpias = _clip_headers({"Authorization": "Bearer eyJhbGciOi.SECRETO",
                             "Cookie": "sesion=abc123", "Accept": "*/*"})
    assert "SECRETO" not in json.dumps(limpias)
    assert "abc123" not in json.dumps(limpias)
    assert limpias["Accept"] == "*/*"


def test_cdp_y_el_proxy_recortan_igual():
    """Dos recortes distintos fue lo que permitio el fallo."""
    from firmascope.network_analyzer.cdp_observer import _clip_headers as cdp
    from firmascope.proxy_addon.addon import _clip_headers as proxy

    cabeceras = {"Authorization": "x" * 40, "Set-Cookie": "a=b", "X-Api-Key": "k",
                 "Content-Type": "application/json"}
    assert cdp(cabeceras) == proxy(cabeceras)
