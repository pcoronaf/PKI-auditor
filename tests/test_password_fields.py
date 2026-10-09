"""La contrasena de la cuenta del portal no es la de la e.firma.

En el primer piloto del panel, el operador inicio sesion en el portal dentro
del navegador auditado. El agente marca como KEY_PASSWORD todo campo de tipo
contrasena, y FS-PWD-001 dijo que la contrasena de la e.firma habia salido.
El proxy y CDP habian visto el cuerpo de esa peticion y la contrasena
registrada no estaba. Estas pruebas fijan cuando esa ausencia desmiente al
agente, y cuando no puede hacerlo.
"""

from __future__ import annotations

from firmascope.audit_core.conclusions import Status
from firmascope.audit_core.events import EventType, Tag
from firmascope.rule_engine.context import AuditContext
from firmascope.rule_engine.engine import RuleEngine

from conftest import egress, key_access, make_event

LOGIN = "https://portal.ejemplo.mx/api/login"
KEY_PASSWORD_LENGTH = 21


def login_password(offset: float = 0.0, length: int = 12) -> list:
    return [make_event(EventType.PASSWORD_READ, offset, tags=[Tag.KEY_PASSWORD],
                       length=length, input_id="clave-cuenta")]


def login_post(offset: float, *, agent_tags=None, cdp_matches=None, cdp_size=67):
    """El inicio de sesion visto por el agente (procedencia) y por CDP (bytes)."""
    agent = egress(offset, tags=agent_tags or [Tag.KEY_PASSWORD], url=LOGIN,
                   host="portal.ejemplo.mx", body_size=67)
    agent.sensor = "agent"
    cdp = egress(offset + 0.01, tags=[Tag.UNCLASSIFIED], url=LOGIN,
                 host="portal.ejemplo.mx", body_size=cdp_size,
                 canary_matches=cdp_matches or [])
    cdp.sensor = "cdp"
    return [agent, cdp]


def pwd(config, events, *, canaries=(Tag.KEY_PASSWORD.value, Tag.KEY_FILE.value),
        length=KEY_PASSWORD_LENGTH):
    context = AuditContext(config=config, events=events, canary_labels=set(canaries),
                           key_password_length=length)
    return {f.rule_id: f for f in RuleEngine().evaluate(context)}["FS-PWD-001"], context


def test_el_login_del_portal_no_es_la_contrasena_de_la_efirma(config):
    eventos = login_password(0) + login_post(1) + key_access(150)
    hallazgo, _ = pwd(config, eventos)
    assert hallazgo.status is Status.NOT_OBSERVED
    assert "Otro campo de contrasena" in hallazgo.detail


def test_la_contrasena_de_la_cuenta_no_adelanta_el_acceso_a_la_clave(config):
    """FS-NET-001 toma como referencia el primer acceso a la clave."""
    eventos = login_password(0) + login_post(1) + key_access(150)
    _, context = pwd(config, eventos)
    assert context.first_key_access().timestamp >= eventos[-4].timestamp


def test_sin_credencial_registrada_no_hay_nada_que_desmienta(config):
    """Sin canario, la ausencia en el cuerpo no prueba nada: manda el agente."""
    eventos = login_password(0) + login_post(1) + key_access(150)
    hallazgo, _ = pwd(config, eventos, canaries=(), length=None)
    assert hallazgo.status is Status.OBSERVED


def test_un_dato_transformado_puede_ocultar_el_canario(config):
    """Cifrado o hash propio: el canario no aparece y aun asi la contrasena salio."""
    eventos = login_password(0) + login_post(
        1, agent_tags=[Tag.KEY_PASSWORD, Tag.DERIVED]) + key_access(150)
    hallazgo, _ = pwd(config, eventos)
    assert hallazgo.status is Status.OBSERVED


def test_si_el_canario_esta_en_el_cuerpo_salio(config):
    eventos = key_access(0) + login_post(
        1, cdp_matches=[{"label": Tag.KEY_PASSWORD.value, "encoding": "utf8"}])
    hallazgo, _ = pwd(config, eventos)
    assert hallazgo.status is Status.OBSERVED


def test_un_cuerpo_que_nadie_vio_no_desmiente_nada(config):
    """CDP no entrega los cuerpos multipart: tamano cero no es "no estaba"."""
    eventos = key_access(0) + login_post(1, cdp_size=0)
    hallazgo, _ = pwd(config, eventos)
    assert hallazgo.status is Status.OBSERVED


def test_un_campo_que_llega_a_la_longitud_de_la_efirma_cuenta(config):
    """La longitud solo descarta; si coincide, el campo puede ser el de la firma."""
    eventos = login_password(0, length=KEY_PASSWORD_LENGTH)
    _, context = pwd(config, eventos)
    assert not context.other_password_fields()
    assert context.observed_password()
