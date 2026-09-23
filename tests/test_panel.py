"""Pruebas del panel de control (sin navegador).

El panel escucha en un puerto local, y cualquier pagina abierta en el equipo
puede intentar hablarle. Se prueba sobre todo que sin el token no se obtiene
nada, que las ordenes no pueden venir de un formulario o un enlace ajeno, y
que el estado que expone sale de eventos ya redactados.
"""

from __future__ import annotations

import http.client
import json
import threading
import time
from types import SimpleNamespace

import pytest

from firmascope.audit_core.events import EventType, Tag
from firmascope.panel import PanelServer, PanelState, panel_operator

from conftest import egress, key_access, make_event


def credential():
    return SimpleNamespace(key_path="/tmp/lab.key", cert_path="/tmp/lab.cer",
                           password="contrasena-sintetica")


# ----------------------------------------------------------------------
# Estado
# ----------------------------------------------------------------------

def test_la_etapa_aislada_se_omite_por_debajo_del_nivel_3():
    state = PanelState("https://x.example", 2, offline_test=False)
    estados = {s["id"]: s["status"] for s in state.snapshot()["stages"]}
    assert estados["firmar-aislado"] == "skipped"


def test_las_etapas_avanzan_y_las_no_abiertas_quedan_omitidas():
    state = PanelState("https://x.example", 3, offline_test=True)
    state.set_stage("abrir")
    state.ask("firmar", "firma")          # se salta "preparar" (modo automatico)
    state.set_stage("analizar")
    estados = {s["id"]: s["status"] for s in state.snapshot()["stages"]}
    assert estados["abrir"] == "done"
    assert estados["preparar"] == "skipped"
    assert estados["firmar"] == "done"
    assert estados["firmar-aislado"] == "skipped"
    assert estados["analizar"] == "active"


def test_siguiente_etapa_solo_vale_cuando_se_espera_a_la_persona():
    state = PanelState("https://x.example", 3, offline_test=True)
    assert state.request_advance() is False
    state.ask("preparar", "prepara")
    assert state.snapshot()["waiting"] is True
    assert state.request_advance() is True
    assert state.advanced
    assert state.request_advance() is False, "un doble clic no debe saltar dos etapas"


def test_las_credenciales_se_muestran_solo_al_pedirlas():
    state = PanelState("https://x.example", 3, offline_test=True)
    state.ask("preparar", "prepara")
    assert state.snapshot()["credential"] is None
    state.ask("firmar", "firma", credential())
    assert state.snapshot()["credential"]["password"] == "contrasena-sintetica"


def test_las_rutas_de_las_credenciales_son_absolutas(tmp_path, monkeypatch):
    """Se pegan en el selector de archivos, que no sabe desde donde se lanzo."""
    monkeypatch.chdir(tmp_path)
    state = PanelState("https://x.example", 3, offline_test=True)
    state.ask("firmar", "firma", SimpleNamespace(key_path="audits/c/lab.key",
                                                 cert_path="audits/c/lab.cer", password="p"))
    cred = state.snapshot()["credential"]
    assert cred["key_path"] == str(tmp_path / "audits" / "c" / "lab.key")
    assert cred["cert_path"] == str(tmp_path / "audits" / "c" / "lab.cer")


def test_los_eventos_se_resumen_y_se_clasifican():
    state = PanelState("https://sitio.example", 3, offline_test=True)
    for event in key_access():
        state.add_event(event)
    state.add_event(egress(2.0, tags=[Tag.KEY_FILE], url="https://evil.example/c",
                           third_party=True))
    fuga = egress(2.1, tags=[Tag.KEY_FILE], url="https://evil.example/c", third_party=True)
    fuga.sensor = "proxy"
    state.add_event(fuga)
    state.add_event(egress(2.5, tags=[Tag.SIGNATURE], url="https://sitio.example/api"))
    state.add_event(make_event(EventType.NETWORK_RESPONSE, 3.0))   # ruido: no se lista

    snap = state.snapshot()
    niveles = [e["level"] for e in snap["events"] if e["type"] == "NETWORK_REQUEST"]
    assert niveles[0] == "private"
    assert niveles[-1] == "info"
    assert all(e["type"] != "NETWORK_RESPONSE" for e in snap["events"])
    c = snap["counters"]
    assert c["key_reads"] == 1
    assert c["egress"] == 2, "la vista del proxy no debe contarse dos veces"
    assert c["egress_private"] == 1
    assert c["third_party"] == 1


def test_el_resultado_final():
    state = PanelState("https://x.example", 3, offline_test=True)
    finding = SimpleNamespace(rule_id="FS-KEY-001", title="t",
                              status=SimpleNamespace(value="OBSERVED"),
                              severity=SimpleNamespace(value="CRITICAL"), summary="salio")
    state.finish(SimpleNamespace(findings=[finding], error="", session_id="FS-1",
                                 output_dir="/tmp/x", reports={}))
    snap = state.snapshot()
    assert snap["result"]["actionable"] == 1
    assert snap["stage"] == "reporte"
    assert snap["has_report"] is False


# ----------------------------------------------------------------------
# Operador
# ----------------------------------------------------------------------

def test_el_operador_espera_al_boton_sin_dejar_de_observar():
    state = PanelState("https://x.example", 3, offline_test=True)
    esperas = []
    page = SimpleNamespace(is_closed=lambda: False)
    step = SimpleNamespace(step="firmar", message="Firma con esto:\n  .key: /tmp/lab.key",
                           page=page, wait=lambda s: (esperas.append(s), time.sleep(0.01)),
                           credential=credential())

    threading.Timer(0.2, state.request_advance).start()
    panel_operator(state)(step)

    assert state.advanced
    assert len(esperas) > 1, "mientras espera debe seguir drenando los sensores"
    assert state.snapshot()["message"] == "Firma con esto:", (
        "las credenciales van en su recuadro, no repetidas en el mensaje")


def test_si_se_cierra_el_navegador_de_auditoria_se_continua():
    state = PanelState("https://x.example", 3, offline_test=True)
    step = SimpleNamespace(step="preparar", message="prepara",
                           page=SimpleNamespace(is_closed=lambda: True),
                           wait=lambda s: None, credential=None)
    panel_operator(state)(step)
    assert state.snapshot()["waiting"] is False
    assert "se cerro" in state.snapshot()["notes"][0]


# ----------------------------------------------------------------------
# Servidor y control de acceso
# ----------------------------------------------------------------------

@pytest.fixture
def panel():
    state = PanelState("https://sitio.example", 3, offline_test=True)
    with PanelServer(state) as server:
        yield server, state


def request(server, method, path, headers=None, host=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
    hdrs = {"Host": host or f"127.0.0.1:{server.port}"}
    hdrs.update(headers or {})
    conn.request(method, path, headers=hdrs)
    response = conn.getresponse()
    return response.status, dict(response.getheaders()), response.read()


def test_sin_token_no_se_obtiene_nada(panel):
    server, _ = panel
    for path in ("/", "/api/state", "/report"):
        assert request(server, "GET", path)[0] == 403
    assert request(server, "GET", "/api/state?t=token-falso")[0] == 403


def test_con_token_se_obtiene_el_estado(panel):
    server, _ = panel
    status, _, body = request(server, "GET", f"/api/state?t={server.token}")
    assert status == 200
    assert json.loads(body)["target"] == "https://sitio.example"


def test_un_host_ajeno_se_rechaza_aunque_lleve_el_token(panel):
    """DNS rebinding: una web ajena resuelve su dominio a 127.0.0.1."""
    server, _ = panel
    status, _, _ = request(server, "GET", f"/api/state?t={server.token}", host="evil.example")
    assert status == 403


def test_las_ordenes_exigen_el_token_en_cabecera(panel):
    """Un formulario o un enlace de otra web pueden poner el token en la URL,
    pero no pueden anadir una cabecera propia."""
    server, state = panel
    state.ask("preparar", "prepara")
    assert request(server, "POST", f"/api/next?t={server.token}")[0] == 403
    assert not state.advanced
    status, _, body = request(server, "POST", "/api/next", {"X-FS-Token": server.token})
    assert status == 200 and json.loads(body)["accepted"] is True
    assert state.advanced


def test_siguiente_fuera_de_tiempo_se_rechaza(panel):
    server, _ = panel
    status, _, _ = request(server, "POST", "/api/next", {"X-FS-Token": server.token})
    assert status == 409


def test_la_pagina_lleva_una_csp_estricta_con_nonce(panel):
    server, _ = panel
    status, headers, body = request(server, "GET", f"/?t={server.token}")
    csp = headers["Content-Security-Policy"]
    assert status == 200
    nonce = csp.split("'nonce-")[1].split("'")[0]
    assert f'<script nonce="{nonce}">'.encode() in body
    assert "__NONCE__" not in body.decode()
    assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp


def test_el_reporte_se_sirve_al_terminar(panel, tmp_path):
    server, state = panel
    assert request(server, "GET", f"/report?t={server.token}")[0] == 404
    html = tmp_path / "report.html"
    html.write_text("<!doctype html><title>r</title>")
    state.finish(SimpleNamespace(findings=[], error="", session_id="FS-1",
                                 output_dir=str(tmp_path), reports={"html": html}))
    status, headers, body = request(server, "GET", f"/report?t={server.token}")
    assert status == 200 and body.startswith(b"<!doctype html>")
    assert "script-src" not in headers["Content-Security-Policy"]


def test_cerrar_el_panel(panel):
    server, state = panel
    request(server, "POST", "/api/close", {"X-FS-Token": server.token})
    assert state.wait_closed(1.0)
