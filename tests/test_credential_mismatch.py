"""El piloto con la e.firma real (FS-2026-0007).

La sesion estaba en modo sintetico y el operador cargo en el portal su e.firma
real, con una contrasena de 8 caracteres. Nada lo advirtio, y el reporte
afirmo "Password access: NOT OBSERVED": descarto la lectura de la contrasena
real por no medir 21, como la sintetica. Ademas eligio aislamiento "solo
terceros", y la tabla de localidad llamo OFFLINE a una ventana en la que el
portal hablaba con su servidor.

Estas pruebas reproducen esa sesion con eventos y fijan lo que el reporte
debe decir.
"""

from __future__ import annotations

import hashlib
from types import SimpleNamespace

from firmascope.audit_core.conclusions import Status
from firmascope.audit_core.config import IsolationMode, IsolationPolicy
from firmascope.audit_core.events import Event, EventType, Tag, foreign_key_digest
from firmascope.browser_controller.isolation import (
    DEFAULT_STAGES,
    processing_locality,
    stages_for,
)
from firmascope.rule_engine.context import AuditContext
from firmascope.rule_engine.engine import RuleEngine

from conftest import egress, local_signature, make_config, make_event

REGISTERED_KEY = b"llave sintetica registrada"
REGISTERED_SHA = hashlib.sha256(REGISTERED_KEY).hexdigest()
FOREIGN_SHA = hashlib.sha256(b"la e.firma real del operador").hexdigest()
LOGIN = "https://api.portal.example/api/login"
SIGN = "https://api.portal.example/api/getMassiveSign"


def key_chosen(offset: float, sha256: str) -> list[Event]:
    return [
        make_event(EventType.FILE_SELECTED, offset, tags=[Tag.KEY_FILE],
                   name="Claveprivada_FIEL.key", size=1298, sha256=sha256),
        make_event(EventType.FILE_READ, offset + 0.1, tags=[Tag.KEY_FILE],
                   method="Blob.arrayBuffer", size=1298),
    ]


def typed(offset: float, field: str, length: int) -> list[Event]:
    """Lecturas mientras se escribe: el framework lee el campo en cada tecla."""
    return [make_event(EventType.PASSWORD_READ, offset + i * 0.2, tags=[Tag.KEY_PASSWORD],
                       length=i + 1, input_id=field) for i in range(length)]


def post(offset: float, url: str, tags, size: int) -> list[Event]:
    """La peticion vista por el agente (procedencia) y por CDP (bytes, sin canario)."""
    agent = egress(offset, tags=tags, url=url, host="api.portal.example", body_size=size)
    agent.sensor = "agent"
    cdp = egress(offset + 0.01, tags=[Tag.UNCLASSIFIED], url=url,
                 host="api.portal.example", body_size=size)
    cdp.sensor = "cdp"
    return [agent, cdp]


def pilot_session(key_sha: str) -> list[Event]:
    """Inicio de sesion (13 caracteres), y despues la firma con otra contrasena (8)."""
    return (typed(0, "cuenta", 13)
            + post(5, LOGIN, [Tag.KEY_PASSWORD], 67)
            + key_chosen(150, key_sha)
            + typed(152, "efirma", 8)
            + post(160, SIGN, [Tag.UNCLASSIFIED], 1004))


def context_for(events, config=None) -> AuditContext:
    return AuditContext(config=config or make_config(), events=events,
                        canary_labels={Tag.KEY_PASSWORD.value, Tag.KEY_FILE.value},
                        key_password_length=21, key_sha256=REGISTERED_SHA)


def findings(context) -> dict:
    return {f.rule_id: f for f in RuleEngine().evaluate(context)}


def locality(context) -> dict[str, str]:
    """Como la calcula el reporte (``exporter.build_report``)."""
    return processing_locality(
        [e for e in context.events if not context.is_other_password_read(e)],
        context.offline_windows(), context.config.isolation.window_label())


# ----------------------------------------------------------------------
# Una llave que no es la registrada
# ----------------------------------------------------------------------

def test_se_reconoce_un_key_que_no_es_el_registrado():
    elegido = key_chosen(0, FOREIGN_SHA)[0]
    assert foreign_key_digest(elegido, REGISTERED_SHA) == FOREIGN_SHA
    assert foreign_key_digest(key_chosen(0, REGISTERED_SHA)[0], REGISTERED_SHA) is None
    # Tal como lo guarda el expediente: el SHA-256 del .key registrado es una
    # representacion de su canario y llega marcado. Es el mismo .key.
    assert foreign_key_digest(key_chosen(0, "<canary:KEY_FILE>")[0], REGISTERED_SHA) is None
    assert foreign_key_digest(key_chosen(0, "fp:0123456789abcdef0123")[0],
                              REGISTERED_SHA) == "fp:0123456789abcdef0123"
    # Sin digest de alguno de los dos lados no se afirma nada.
    assert foreign_key_digest(key_chosen(0, "")[0], REGISTERED_SHA) is None
    assert foreign_key_digest(elegido, None) is None


def test_con_otra_llave_la_contrasena_en_uso_no_se_descarta_por_longitud():
    """El fallo del piloto: la contrasena real (8) se tomo por la de la cuenta."""
    context = context_for(pilot_session(FOREIGN_SHA))
    assert context.foreign_key_used()
    assert context.observed_password()
    assert locality(context)["Password access"] != "NOT OBSERVED"

    hallazgo = findings(context)["FS-PWD-001"]
    assert "no llego a usar" not in hallazgo.summary, hallazgo.summary
    assert hallazgo.status is Status.NOT_OBSERVED


def test_con_otra_llave_el_inicio_de_sesion_sigue_sin_ser_la_efirma():
    """Sin canarios de la llave en uso, el contenido no desmiente al agente: lo
    hace el orden. El campo de la cuenta se leyo antes de elegir ningun .key."""
    context = context_for(pilot_session(FOREIGN_SHA))
    hallazgo = findings(context)["FS-PWD-001"]
    assert hallazgo.status is not Status.OBSERVED, hallazgo.summary
    assert "Otro campo de contrasena" in hallazgo.detail


def test_con_otra_llave_la_ausencia_del_canario_no_absuelve():
    """Si la contrasena de la llave en uso sale, el canario de la registrada no
    esta en el cuerpo, y eso no debe desmentir la etiqueta del agente."""
    eventos = pilot_session(FOREIGN_SHA) + post(170, SIGN, [Tag.KEY_PASSWORD], 300)
    hallazgo = findings(context_for(eventos))["FS-PWD-001"]
    assert hallazgo.status is Status.OBSERVED


def test_con_la_llave_registrada_se_conserva_el_criterio_de_longitud():
    """Control: con el .key registrado, un campo de 8 no es el de 21."""
    context = context_for(pilot_session(REGISTERED_SHA))
    assert not context.foreign_key_used()
    assert locality(context)["Password access"] == "NOT OBSERVED"


def test_el_reporte_avisa_de_la_llave_ajena(tmp_path):
    from firmascope.evidence_store.store import EvidenceStore
    from firmascope.report_engine.exporter import build_report

    config = make_config()
    credential = SimpleNamespace(password="x" * 21, key_der=REGISTERED_KEY,
                                 describe=lambda *_: {})
    store = EvidenceStore(tmp_path, "s")
    for event in pilot_session(FOREIGN_SHA):
        store.add_event(event)
    report = build_report(store, config, "s", {}, credential=credential)
    store.close()

    assert any(".key distinto" in w for w in report["warnings"]), report["warnings"]
    assert report["processing_locality"]["Password access"] != "NOT OBSERVED"


def test_la_sesion_avisa_en_vivo_al_elegir_otra_llave(tmp_path, credential):
    from firmascope.audit_core.orchestrator import AuditSession

    session = AuditSession(make_config(output_dir=tmp_path))
    session.prepare_credentials(credentials_dir=tmp_path / "cred")
    # Como en las pruebas de laboratorio: se registra otra credencial despues.
    session.credential = credential
    credential.register(session.vault)
    propia = hashlib.sha256(credential.key_der).hexdigest()

    for evento in key_chosen(0, propia) + key_chosen(1, FOREIGN_SHA) + key_chosen(2, FOREIGN_SHA):
        evento.session = session.session_id
        session.emit(evento)
    avisos = [e for e in session.store.events(types=[EventType.CHECKPOINT])
              if e.data.get("name") == "credential-mismatch"]
    session.store.close()
    assert len(avisos) == 1, "el aviso debe darse una vez por llave ajena"
    assert "no es el de esta sesion" in avisos[0].data["message"]


# ----------------------------------------------------------------------
# Aislamiento parcial: "solo terceros" no es sin red
# ----------------------------------------------------------------------

def isolated(mode: IsolationMode, allow=()):
    return make_config(isolation=IsolationPolicy(mode=mode, allow_hosts=list(allow)))


def signed_in_window() -> list[Event]:
    return ([make_event(EventType.NETWORK_OFF, 0)] + key_chosen(1, REGISTERED_SHA)
            + local_signature(2) + [make_event(EventType.NETWORK_ON, 5)])


def test_solo_terceros_no_confirma_firma_local():
    """El servidor del portal seguia alcanzable: la firma pudo apoyarse en el."""
    context = context_for(signed_in_window(), isolated(IsolationMode.THIRD_PARTY))
    hallazgo = findings(context)["FS-LOCAL-001"]
    assert hallazgo.status is Status.INCONCLUSIVE, hallazgo.summary
    assert "parcial" in hallazgo.summary


def test_aislamiento_total_si_confirma_firma_local():
    context = context_for(signed_in_window(), isolated(IsolationMode.FULL))
    assert findings(context)["FS-LOCAL-001"].status is Status.CONFIRMED


def test_la_localidad_no_llama_offline_a_una_ventana_sin_terceros():
    tabla = locality(context_for(signed_in_window(), isolated(IsolationMode.THIRD_PARTY)))
    assert tabla["Private key access"] == "SIN TERCEROS"
    assert tabla["Signature generation"] == "SIN TERCEROS"
    assert locality(context_for(signed_in_window(), isolated(IsolationMode.FULL))
                    )["Private key access"] == "OFFLINE"


def test_alcance_del_aislamiento():
    assert IsolationPolicy(mode=IsolationMode.FULL).is_total()
    assert IsolationPolicy(mode=IsolationMode.ALLOWLIST).is_total()
    assert not IsolationPolicy(mode=IsolationMode.ALLOWLIST, allow_hosts=["a.mx"]).is_total()
    assert not IsolationPolicy(mode=IsolationMode.THIRD_PARTY).is_total()


def test_las_etapas_no_prometen_firma_local_con_aislamiento_parcial():
    parcial = {s.name: s for s in stages_for(isolated(IsolationMode.THIRD_PARTY))}
    assert [s.name for s in parcial.values()] == [s.name for s in DEFAULT_STAGES]
    assert "es local" not in parcial["sign"].instruction
    assert "no prueba" in parcial["sign"].instruction
    total = {s.name: s for s in stages_for(isolated(IsolationMode.FULL))}
    assert total["sign"].title == "Firmar con la red aislada"


def test_el_manifiesto_distingue_el_aislamiento_parcial():
    from firmascope.report_engine.exporter import _network_mode

    assert _network_mode(isolated(IsolationMode.FULL), 1) == "OFFLINE-TESTED"
    assert _network_mode(isolated(IsolationMode.THIRD_PARTY), 1) == "PARTIAL-ISOLATION-TESTED"
    assert _network_mode(isolated(IsolationMode.THIRD_PARTY), 0) == "ONLINE"
