"""Expediente: secretos que no se guardan y una cadena que detecta cambios."""

from __future__ import annotations

import json
import sqlite3

from firmascope.audit_core.config import AuditConfig, PrivacyPolicy
from firmascope.audit_core.events import Event, EventType, Tag
from firmascope.audit_core.secrets import SecretVault, redact
from firmascope.evidence_store.store import EvidenceStore

SESSION = "FS-2099-0001"


def _store(root, vault=None, privacy=None):
    store = EvidenceStore(root, SESSION, vault, privacy)
    store.open_session(target="https://portal.ejemplo.mx/firma",
                       config={}, versions={}, note="prueba")
    return store


def test_la_cadena_detecta_la_alteracion_y_nombra_el_registro(tmp_path):
    store = _store(tmp_path)
    for index in range(3):
        store.add_event(Event(EventType.CHECKPOINT, SESSION, sensor="test",
                              data={"n": index}))
    store.close_session()
    assert store.verify_chain() == (True, None)
    store.close()

    con = sqlite3.connect(tmp_path / "session.sqlite")
    con.execute("UPDATE events SET data_json=? WHERE seq=2", (json.dumps({"n": 99}),))
    con.commit()
    con.close()

    again = EvidenceStore(tmp_path, SESSION)
    ok, seq = again.verify_chain()
    assert not ok
    # El numero devuelto debe ser el del evento, no el indice de la lista: es
    # lo que el operador busca en timeline.json.
    assert seq == 2
    assert again.event_at(seq)["seq"] == 2
    again.close()


def test_el_expediente_se_identifica_por_su_contenido(tmp_path):
    """Un expediente copiado a otra carpeta sigue sabiendo quien es."""
    store = _store(tmp_path)
    store.close_session()
    store.close()
    otro = EvidenceStore(tmp_path, "nombre-de-carpeta-distinto")
    assert otro.session_info().get("id") == SESSION
    otro.close()


def test_la_contrasena_nunca_llega_al_expediente(tmp_path, vault):
    """El canario vive en memoria; lo que se escribe va redactado."""
    password = "FSCOPE-AUDIT-SECRETO-1234"
    vault.register(Tag.KEY_PASSWORD.value, password, is_text=True)
    store = _store(tmp_path, vault)
    store.add_event(Event(EventType.NETWORK_REQUEST, SESSION, sensor="agent",
                          data={"url": "https://x.mx/a", "body_preview": password}))
    store.close_session()
    store.close()
    crudo = (tmp_path / "session.sqlite").read_bytes()
    assert password.encode() not in crudo


def test_el_rfc_del_nombre_de_archivo_se_redacta_con_material_del_operador():
    """El nombre de archivo de una e.firma del SAT contiene el RFC del titular."""
    politica = PrivacyPolicy.for_real_credentials()
    salida = redact({"name": "stage:load", "file": "FIEL_XAXX010101000.key"},
                    None, politica)
    assert salida["file"] == "<redactado.key>"
    # Un nombre de etapa no es un nombre de archivo y no debe tocarse.
    assert salida["name"] == "stage:load"


def test_la_politica_de_privacidad_depende_del_origen_del_material():
    """Solo la credencial sintetica tiene metadatos inocuos."""
    sintetica = AuditConfig(target="https://x.mx", credential_mode="synthetic")
    propia = AuditConfig(target="https://x.mx", credential_mode="own-test")
    real = AuditConfig(target="https://x.mx", credential_mode="real",
                       acknowledge_real_credentials=True)

    assert not sintetica.privacy.redact_filenames
    assert propia.privacy.redact_filenames, \
        "una credencial 'de prueba' del operador sigue llevando su RFC en el nombre"
    assert real.privacy.redact_filenames
    assert not real.privacy.publish_global_digests
    # Con credencial real, persistir cuerpos no es negociable.
    assert not real.capture_bodies


def test_el_modo_real_exige_consentimiento_explicito():
    import pytest
    with pytest.raises(ValueError):
        AuditConfig(target="https://x.mx", credential_mode="real")


def test_el_vault_muere_con_la_sesion(vault):
    vault.register(Tag.KEY_PASSWORD.value, "FSCOPE-AUDIT-OTRO-9999", is_text=True)
    assert vault.alive
    assert vault.scan(b"...FSCOPE-AUDIT-OTRO-9999...")
    vault.destroy()
    assert not vault.alive
