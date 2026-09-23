"""Pruebas del motor de correlacion.

Lo que se fija aqui es la pregunta causal: dada una salida, de donde venia lo
que salio. Y, sobre todo, que la cadena legitima de una e.firma
(S1+S2 -> S3, S3+S5 -> S6) no se confunda nunca con una exfiltracion.
"""

from __future__ import annotations

import pytest

from firmascope.audit_core.conclusions import Confidence
from firmascope.audit_core.events import EventType, Tag
from firmascope.correlation_engine import (
    VERDICT_EXFILTRATION,
    VERDICT_LEGITIMATE,
    VERDICT_UNCLASSIFIED,
    CorrelationEngine,
    correlate,
)

from conftest import egress, key_access, local_signature, make_event


# ----------------------------------------------------------------------
# Cadenas legitimas
# ----------------------------------------------------------------------

def test_enviar_la_firma_es_una_cadena_legitima():
    """S3 + S5 --sign--> S6. El producto de la operacion puede enviarse."""
    events = key_access() + local_signature() + [
        egress(2.0, tags=[Tag.SIGNATURE], url="https://sitio.example/api/recibo"),
    ]
    report = correlate(events)

    assert len(report.chains) == 1
    chain = report.chains[0]
    assert chain.verdict == VERDICT_LEGITIMATE
    assert not chain.private
    assert report.exfiltration_chains() == []


def test_enviar_el_certificado_es_legitimo():
    events = key_access() + [
        egress(2.0, tags=[Tag.CERTIFICATE], url="https://sitio.example/api/cert"),
    ]
    assert correlate(events).chains[0].verdict == VERDICT_LEGITIMATE


def test_la_cadena_de_firma_local_se_identifica():
    events = key_access() + local_signature() + [
        egress(2.0, tags=[Tag.SIGNATURE], url="https://sitio.example/api/recibo"),
    ]
    chain = correlate(events).local_signature_chain()
    assert chain is not None
    assert Tag.SIGNATURE.value in chain.labels


# ----------------------------------------------------------------------
# Exfiltracion
# ----------------------------------------------------------------------

def test_cadena_de_exfiltracion_directa():
    events = key_access() + [
        egress(2.0, tags=[Tag.KEY_FILE], url="https://evil.example/c",
               host="evil.example", body_size=2400),
    ]
    report = correlate(events)
    chain = report.chains[0]

    assert chain.verdict == VERDICT_EXFILTRATION
    assert chain.direct and not chain.derived
    assert chain.destination() == "evil.example"
    assert chain.private


def test_cadena_de_exfiltracion_derivada():
    """demo-encrypted-exfiltration: el contenido es opaco, la procedencia no."""
    events = key_access() + [
        egress(2.0, tags=[Tag.PRIVATE_KEY, Tag.DERIVED],
               url="https://evil.example/blob", host="evil.example"),
    ]
    chain = correlate(events).chains[0]
    assert chain.verdict == VERDICT_EXFILTRATION
    assert chain.derived and not chain.direct


def test_la_cadena_reconstruye_los_pasos_intermedios():
    """La narrativa del reporte: de donde salio y por donde paso."""
    events = key_access() + [
        egress(2.0, tags=[Tag.PRIVATE_KEY, Tag.DERIVED], url="https://evil.example/blob"),
    ]
    chain = correlate(events).chains[0]
    kinds = [step.kind for step in chain.steps]

    assert kinds[0] == "source"
    assert kinds[-1] == "egress"
    assert "transform" in kinds
    assert "descifrado" in chain.narrative()


def test_las_transformaciones_posteriores_a_la_salida_no_entran_en_la_cadena():
    events = key_access() + [
        egress(1.0, tags=[Tag.KEY_FILE], url="https://evil.example/c"),
        make_event(EventType.CRYPTO_SIGN, 5.0, tags=[Tag.SIGNATURE]),
    ]
    chain = correlate(events).chains[0]
    assert all(step.event.timestamp <= chain.egress.timestamp for step in chain.steps)
    assert EventType.CRYPTO_SIGN not in [step.event.type for step in chain.steps]


# ----------------------------------------------------------------------
# Corroboracion entre sensores
# ----------------------------------------------------------------------

def test_canario_corrobora_y_eleva_la_confianza():
    """Encontrar los bytes en el cuerpo es prueba directa, no reconstruccion."""
    events = key_access() + [
        egress(2.0, tags=[Tag.KEY_FILE], url="https://evil.example/c",
               canary_matches=[{"label": Tag.KEY_FILE.value, "encoding": "base64"}]),
    ]
    chain = correlate(events).chains[0]
    assert "canary" in chain.corroboration
    assert chain.confidence() is Confidence.HIGH


def test_canario_por_si_solo_atribuye_la_salida():
    """Aunque la instrumentacion no etiquetara la salida, el canario la delata."""
    events = key_access() + [
        egress(2.0, url="https://evil.example/c",
               canary_matches=[{"label": Tag.KEY_FILE.value, "encoding": "hex"}]),
    ]
    chain = correlate(events).chains[0]
    assert chain.verdict == VERDICT_EXFILTRATION
    assert Tag.KEY_FILE.value in chain.labels


def test_dos_sensores_sobre_la_misma_salida_se_correlacionan():
    events = key_access() + [
        egress(2.0, tags=[Tag.KEY_FILE], url="https://evil.example/c"),
    ]
    requests = [{
        "id": "r1", "url": "https://evil.example/c", "method": "POST",
        "timestamp": events[-1].timestamp + 0.05, "sensor": "proxy",
        "third_party": True, "registrable_domain": "evil.example",
    }]
    chain = correlate(events, requests).chains[0]

    assert chain.request is not None and chain.request["id"] == "r1"
    assert chain.third_party
    assert "agent" in chain.corroboration and "proxy" in chain.corroboration
    assert chain.confidence() is Confidence.HIGH
    assert len(correlate(events, requests).corroborated_chains()) == 1


def test_un_solo_sensor_no_alcanza_confianza_alta():
    events = key_access() + [egress(2.0, tags=[Tag.KEY_FILE], url="https://evil.example/c")]
    assert correlate(events).chains[0].confidence() is Confidence.MEDIUM


def test_peticion_con_url_distinta_no_se_empareja():
    events = key_access() + [egress(2.0, tags=[Tag.KEY_FILE], url="https://evil.example/c")]
    requests = [{"id": "r1", "url": "https://otro.example/x", "timestamp": 0, "sensor": "cdp"}]
    assert correlate(events, requests).chains[0].request is None


# ----------------------------------------------------------------------
# Tiempo
# ----------------------------------------------------------------------

def test_latencia_respecto_del_primer_acceso_a_la_clave():
    events = key_access() + [egress(3.0, tags=[Tag.KEY_FILE], url="https://evil.example/c")]
    assert correlate(events).chains[0].latency_ms == 3000


def test_marcas_monotonas_de_cdp_no_producen_latencias_absurdas():
    """CDP entrega tiempos desde el arranque del navegador, no epoch."""
    events = key_access() + [
        make_event(EventType.NETWORK_REQUEST, 0.0, tags=[Tag.KEY_FILE],
                   url="https://evil.example/c"),
    ]
    events[-1].timestamp = 1234.5   # monotono, no comparable
    assert correlate(events).chains[0].latency_ms is None


def test_sin_acceso_a_la_clave_no_hay_latencia():
    events = [egress(2.0, tags=[Tag.CERTIFICATE], url="https://sitio.example/cert")]
    report = correlate(events)
    assert report.first_key_access is None
    assert report.chains[0].latency_ms is None


# ----------------------------------------------------------------------
# Salidas no atribuibles
# ----------------------------------------------------------------------

def test_salida_sin_etiqueta_queda_como_no_atribuida():
    """Honestidad: no se inventa una procedencia que no se pudo establecer."""
    events = key_access() + [
        egress(2.0, url="https://cdn.tercero.example/a.js", body_size=9000),
    ]
    report = correlate(events)
    assert report.chains == []
    assert len(report.unattributed) == 1


def test_salida_sin_clasificar_no_se_cuenta_como_exfiltracion():
    events = key_access() + [
        egress(2.0, tags=[Tag.UNCLASSIFIED], url="https://evil.example/blob", body_size=4096),
    ]
    report = correlate(events)
    assert report.exfiltration_chains() == []
    assert len(report.unattributed) == 1


def test_etiqueta_de_documento_sola_es_legitima():
    events = [egress(2.0, tags=[Tag.DOCUMENT], url="https://sitio.example/api/doc")]
    assert correlate(events).chains[0].verdict == VERDICT_LEGITIMATE


def test_mezcla_de_etiquetas_privada_y_publica_es_exfiltracion():
    """Enviar la firma junto con la clave sigue siendo enviar la clave."""
    events = key_access() + [
        egress(2.0, tags=[Tag.SIGNATURE, Tag.KEY_FILE], url="https://evil.example/c"),
    ]
    assert correlate(events).chains[0].verdict == VERDICT_EXFILTRATION


# ----------------------------------------------------------------------
# Agregado y orden
# ----------------------------------------------------------------------

def test_las_exfiltraciones_van_primero():
    events = key_access() + local_signature() + [
        egress(2.0, tags=[Tag.SIGNATURE], url="https://sitio.example/api/recibo"),
        egress(2.5, tags=[Tag.KEY_FILE], url="https://evil.example/c"),
    ]
    chains = correlate(events).chains
    assert chains[0].verdict == VERDICT_EXFILTRATION
    assert chains[-1].verdict == VERDICT_LEGITIMATE


def test_resumen_y_serializacion(config):
    events = key_access() + local_signature() + [
        egress(2.0, tags=[Tag.SIGNATURE], url="https://sitio.example/api/recibo"),
        egress(2.5, tags=[Tag.KEY_FILE], url="https://evil.example/c",
               canary_matches=[{"label": Tag.KEY_FILE.value, "encoding": "base64"}]),
        egress(3.0, url="https://cdn.tercero.example/a.js"),
    ]
    report = CorrelationEngine(config).run(events)
    resumen = report.summary()

    assert resumen["exfiltration"] == 1
    assert resumen["legitimate"] == 1
    assert resumen["unattributed"] == 1
    assert resumen["transforms"] >= 2

    serializado = report.to_dict()
    assert serializado["summary"] == resumen
    assert serializado["chains"][0]["verdict"] == VERDICT_EXFILTRATION
    assert serializado["chains"][0]["narrative"]


def test_sesion_vacia():
    report = correlate([])
    assert report.chains == []
    assert report.first_key_access is None
    assert report.summary()["chains"] == 0


# ----------------------------------------------------------------------
# Integracion con el motor de reglas
# ----------------------------------------------------------------------

def test_el_contexto_de_reglas_acepta_el_informe_de_correlacion(config):
    """El motor de reglas recibe la correlacion en `context.correlation`."""
    from firmascope.rule_engine import AuditContext, RuleEngine

    events = key_access() + [egress(2.0, tags=[Tag.KEY_FILE], url="https://evil.example/c")]
    report = correlate(events, config=config)
    context = AuditContext(config=config, events=events, correlation=report)

    findings = {f.rule_id: f for f in RuleEngine().evaluate(context)}
    assert findings["FS-KEY-001"].status.value == "OBSERVED"
    assert context.correlation.exfiltration_chains()


# ----------------------------------------------------------------------
# Fusion de vistas de varios sensores
# ----------------------------------------------------------------------

def _view(sensor: str, offset: float, **kwargs):
    event = egress(offset, url="https://evil.example/c", body_size=3329, **kwargs)
    event.sensor = sensor
    return event


def test_una_peticion_vista_por_dos_sensores_es_una_sola_cadena():
    """Contar tres veces la misma exfiltracion seria inflar el reporte."""
    events = key_access() + [
        _view("agent", 2.0, tags=[Tag.KEY_FILE], host="evil.example:443"),
        _view("cdp", 2.05, host="evil.example"),
    ]
    report = correlate(events)

    assert len(report.chains) == 1
    chain = report.chains[0]
    assert set(chain.corroboration) >= {"agent", "cdp"}
    assert chain.confidence() is Confidence.HIGH


def test_la_fusion_combina_etiquetas_y_canarios_de_cada_sensor():
    """Cada sensor aporta lo que solo el puede ver."""
    events = key_access() + [
        _view("agent", 2.0, tags=[Tag.KEY_FILE]),
        _view("proxy", 2.05, canary_matches=[
            {"label": Tag.KEY_PASSWORD.value, "encoding": "utf8"}]),
    ]
    chain = correlate(events).chains[0]

    assert Tag.KEY_FILE.value in chain.labels       # lo aporto la instrumentacion
    assert Tag.KEY_PASSWORD.value in chain.labels   # lo aporto el proxy
    assert "canary" in chain.corroboration


def test_la_fusion_conserva_el_host_mas_especifico():
    """CDP da "evil.example" donde el agente da "evil.example:8443"."""
    events = key_access() + [
        _view("agent", 2.0, tags=[Tag.KEY_FILE], host="evil.example:8443"),
        _view("cdp", 2.05, host="evil.example"),
    ]
    assert correlate(events).chains[0].destination() == "evil.example:8443"


def test_dos_salidas_del_mismo_sensor_no_se_funden():
    """Dos peticiones identicas del mismo sensor son dos peticiones."""
    events = key_access() + [
        _view("agent", 2.0, tags=[Tag.KEY_FILE]),
        _view("agent", 3.0, tags=[Tag.KEY_FILE]),
    ]
    assert len(correlate(events).chains) == 2


def test_no_se_funden_salidas_de_distinto_tamano():
    """Mismo destino, cuerpos distintos: son envios distintos."""
    events = key_access() + [
        _view("agent", 2.0, tags=[Tag.KEY_FILE]),
        egress(2.1, tags=[Tag.KEY_FILE], url="https://evil.example/c", body_size=64),
    ]
    assert len(correlate(events).chains) == 2


def test_el_proxy_se_funde_aunque_mida_el_cuerpo_ya_codificado():
    """El proxy mide el multipart con sus fronteras; el agente, el FormData
    antes de codificarlo. Es la misma peticion y debe contar una vez."""
    events = key_access() + [
        _view("agent", 2.0, tags=[Tag.KEY_FILE]),
        egress(2.08, url="https://evil.example/c", body_size=3119,
               canary_matches=[{"label": Tag.KEY_FILE.value, "encoding": "raw"}]),
    ]
    events[-1].sensor = "proxy"
    chains = correlate(events).chains
    assert len(chains) == 1
    assert {"agent", "proxy", "canary"} <= set(chains[0].corroboration)


def test_vistas_de_sensores_distintos_alejadas_en_el_tiempo_no_se_funden():
    """Misma URL, sensores distintos, pero 30 s de separacion: dos envios."""
    events = key_access() + [
        _view("agent", 2.0, tags=[Tag.KEY_FILE]),
        _view("proxy", 32.0, tags=[Tag.KEY_FILE]),
    ]
    assert len(correlate(events).chains) == 2
