"""Correlacion de sensores: la diferencia entre "salio" y "lo intento".

Es la prueba del defecto mas peligroso que tuvo el proyecto. Una misma peticion
la ven varios sensores; solo el aislamiento sabe que la abortó. Si no se
reconcilian, el informe afirma que la clave salio cuando no salio, y con una
e.firma real eso lleva a revocar un certificado sin motivo.
"""

from __future__ import annotations

from firmascope.audit_core.events import Event, EventType, Tag
from firmascope.correlation_engine import correlate

SESSION = "FS-TEST-0001"
URL = "http://collector.example.net/collect"


def _request(sensor: str, *, blocked: bool = False, tags=(), digest: str = "abc123",
             size: int = 1899, host: str = "collector.example.net",
             timestamp: float = 1_700_000_000.0) -> Event:
    return Event(
        EventType.NETWORK_REQUEST, SESSION, sensor=sensor, timestamp=timestamp,
        tags=list(tags),
        data={"url": URL, "host": host, "method": "POST", "body_size": size,
              "body_digest": digest, "blocked": blocked},
    )


def test_una_peticion_vista_por_tres_sensores_es_una_sola_salida():
    index = correlate([
        _request("agent", tags=[Tag.KEY_PASSWORD.value]),
        _request("isolation", blocked=True, tags=[Tag.KEY_FILE.value]),
        _request("cdp", tags=[Tag.KEY_FILE.value]),
    ])
    assert len(index.groups) == 1, "la misma peticion se conto varias veces"
    group = index.groups[0]
    assert len(group.observations) == 3
    assert group.sensors == ("agent", "cdp", "isolation")


def test_el_aislamiento_niega_la_salida_para_todo_el_grupo():
    """El sensor que vio la peticion no es el que sabe como acabo."""
    agent = _request("agent", tags=[Tag.KEY_PASSWORD.value])
    index = correlate([agent, _request("isolation", blocked=True)])
    assert index.is_blocked(agent), \
        "el evento del agente sigue pareciendo una salida consumada"
    assert index.denied and not index.sent


def test_sin_aislamiento_la_salida_cuenta_como_consumada():
    agent = _request("agent", tags=[Tag.KEY_FILE.value])
    index = correlate([agent, _request("cdp", tags=[Tag.KEY_FILE.value])])
    assert not index.is_blocked(agent)
    assert index.sent and not index.denied


def test_las_etiquetas_de_los_sensores_se_suman():
    """El agente conoce la procedencia; CDP ve el cuerpo. Hacen falta las dos."""
    agent = _request("agent", tags=[Tag.KEY_PASSWORD.value])
    index = correlate([agent, _request("cdp", tags=[Tag.KEY_FILE.value])])
    assert index.enriched_tags(agent) == {Tag.KEY_PASSWORD.value, Tag.KEY_FILE.value}


def test_un_solo_representante_por_peticion():
    agent = _request("agent")
    cdp = _request("cdp")
    index = correlate([agent, cdp])
    primarios = [e for e in (agent, cdp) if index.is_primary(e)]
    assert len(primarios) == 1
    assert primarios[0].sensor == "agent", "el representante debe conocer la procedencia"


def test_dos_peticiones_iguales_del_mismo_sensor_son_dos_salidas():
    """Repetir el envio es exfiltrar dos veces, no verlo dos veces."""
    index = correlate([
        _request("agent", timestamp=1_700_000_000.0),
        _request("agent", timestamp=1_700_000_001.0),
    ])
    assert len(index.groups) == 2


def test_el_puerto_no_separa_lo_que_es_la_misma_peticion():
    """El agente reporta `host:puerto` y CDP a veces solo el host."""
    agent = _request("agent", host="collector.example.net:8766", digest="")
    cdp = _request("cdp", host="collector.example.net", digest="")
    index = correlate([agent, cdp])
    assert len(index.groups) == 1
    assert index.groups[0].netloc == "collector.example.net"
