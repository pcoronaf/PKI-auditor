"""Pruebas del nucleo: eventos, proteccion de secretos y expediente.

Estos modulos se habian validado a mano durante el desarrollo. Aqui quedan
fijados, porque son los que sostienen las dos promesas mas fuertes de la
herramienta: que ningun secreto se escribe a disco, y que el expediente puede
verificarse despues.
"""

from __future__ import annotations

import json

import pytest

from firmascope.audit_core.conclusions import SEVERITY_ORDER, Status
from firmascope.audit_core.config import AuditConfig, AuditLevel, CredentialMode
from firmascope.audit_core.events import Event, EventType, Tag
from firmascope.audit_core.secrets import (
    SecretVault,
    assert_no_secrets,
    looks_like_private_key,
    redact,
)
from firmascope.evidence_store import chain
from firmascope.evidence_store.store import (
    EvidenceStore,
    Finding,
    RequestRecord,
    ScriptRecord,
)

from conftest import make_event


# ----------------------------------------------------------------------
# Modelo de eventos
# ----------------------------------------------------------------------

def test_evento_serializa_y_vuelve():
    original = make_event(EventType.CRYPTO_SIGN, 1.0, tags=[Tag.SIGNATURE], algorithm="RSA")
    restored = Event.from_dict(json.loads(original.to_json()))
    assert restored.type is EventType.CRYPTO_SIGN
    assert restored.tags == [Tag.SIGNATURE.value]
    assert restored.data["algorithm"] == "RSA"


def test_etiquetas_privadas():
    assert make_event(EventType.FILE_READ, tags=[Tag.KEY_FILE]).has_private_tag()
    assert make_event(EventType.CRYPTO_SIGN, tags=[Tag.SIGNATURE]).has_private_tag() is False
    assert make_event(EventType.NETWORK_REQUEST, tags=[Tag.CERTIFICATE]).has_private_tag() is False


def test_orden_de_severidad_de_los_estados():
    """CONFIRMED pesa mas que OBSERVED, y NOT_OBSERVED es el suelo."""
    assert SEVERITY_ORDER[Status.CONFIRMED] > SEVERITY_ORDER[Status.OBSERVED]
    assert SEVERITY_ORDER[Status.OBSERVED] > SEVERITY_ORDER[Status.POTENTIAL]
    assert SEVERITY_ORDER[Status.NOT_OBSERVED] == 0


# ----------------------------------------------------------------------
# Configuracion por niveles
# ----------------------------------------------------------------------

@pytest.mark.parametrize("entrada,esperado", [
    (1, AuditLevel.NETWORK_OBSERVER),
    ("network", AuditLevel.NETWORK_OBSERVER),
    ("l2", AuditLevel.CODE_ANALYZER),
    ("offline", AuditLevel.LOCAL_SIGNING_TEST),
    ("full", AuditLevel.FULL_CORRELATED),
])
def test_parseo_de_niveles(entrada, esperado):
    assert AuditLevel.parse(entrada) is esperado


def test_nivel_desconocido_falla():
    with pytest.raises(ValueError):
        AuditLevel.parse("nivel-inventado")


def test_capacidades_por_nivel():
    nivel1 = AuditConfig(target="https://x.example", level=1, browser_path=None)
    assert nivel1.network_observation and not nivel1.static_analysis and not nivel1.offline_test

    nivel3 = AuditConfig(target="https://x.example", level=3, browser_path=None)
    assert nivel3.static_analysis and nivel3.offline_test and not nivel3.proxy_enabled


def test_captura_de_cuerpos_desactivada_por_defecto():
    """Proteccion de secretos: capturar cuerpos es una decision explicita."""
    assert AuditConfig(target="https://x.example", browser_path=None).capture_bodies is False


def test_credenciales_sinteticas_por_defecto():
    config = AuditConfig(target="https://x.example", browser_path=None)
    assert config.credential_mode is CredentialMode.SYNTHETIC


# ----------------------------------------------------------------------
# Vault de secretos
# ----------------------------------------------------------------------

def test_fingerprint_es_estable_y_opaco():
    with SecretVault() as vault:
        secreto = b"contrasena-de-laboratorio"
        fp = vault.register(Tag.KEY_PASSWORD, secreto)
        assert fp.startswith("fp:")
        assert vault.fingerprint(secreto) == fp
        assert "contrasena" not in fp


def test_fingerprints_difieren_entre_sesiones():
    """La clave de sesion es aleatoria: los fingerprints no son correlacionables."""
    with SecretVault() as a, SecretVault() as b:
        assert a.fingerprint(b"x") != b.fingerprint(b"x")


def test_canario_se_encuentra_en_base64():
    """El caso real: el .key sale codificado, no en bruto."""
    import base64
    raw = bytes(range(256)) * 4
    with SecretVault() as vault:
        vault.register(Tag.KEY_FILE, raw)
        cuerpo = b'{"data":"' + base64.b64encode(raw) + b'"}'
        encodings = {m.encoding for m in vault.scan(cuerpo)}
        assert "base64" in encodings
        assert Tag.KEY_FILE.value in vault.labels_in(cuerpo)


def test_canario_se_encuentra_en_hex():
    raw = bytes(range(64)) * 4
    with SecretVault() as vault:
        vault.register(Tag.KEY_FILE, raw)
        assert "hex" in {m.encoding for m in vault.scan(raw.hex().encode())}


def test_cuerpo_limpio_no_produce_coincidencias():
    with SecretVault() as vault:
        vault.register(Tag.KEY_PASSWORD, "secreto-de-laboratorio")
        assert vault.scan(b'{"status":"ok","signature":"AAAA"}') == []


def test_vault_destruido_deja_de_operar():
    vault = SecretVault()
    vault.register(Tag.KEY_PASSWORD, "x" * 20)
    vault.destroy()
    assert not vault.alive
    assert vault.scan(b"x" * 20) == []
    with pytest.raises(RuntimeError):
        vault.fingerprint(b"x")


def test_redaccion_sustituye_material_sensible():
    with SecretVault() as vault:
        vault.register(Tag.KEY_PASSWORD, "contrasena-secreta-de-laboratorio")
        limpio = redact({"body": "pwd=contrasena-secreta-de-laboratorio", "url": "/api"}, vault)
        assert "contrasena-secreta-de-laboratorio" not in json.dumps(limpio)


def test_deteccion_de_clave_privada_pem():
    assert looks_like_private_key(b"-----BEGIN PRIVATE KEY-----\nAAAA\n")
    assert looks_like_private_key(b"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n")
    assert not looks_like_private_key(b"-----BEGIN CERTIFICATE-----\nAAAA\n")


def test_assert_no_secrets_es_la_ultima_barrera():
    """Se invoca antes de escribir: si algo se escapo, la escritura falla."""
    with SecretVault() as vault:
        vault.register(Tag.KEY_PASSWORD, "contrasena-secreta-de-laboratorio")
        assert_no_secrets('{"status":"ok"}', vault)  # no levanta
        with pytest.raises(Exception):
            assert_no_secrets('{"pwd":"contrasena-secreta-de-laboratorio"}', vault)


# ----------------------------------------------------------------------
# Expediente
# ----------------------------------------------------------------------

@pytest.fixture
def store(tmp_path):
    store = EvidenceStore(tmp_path, "sesion-de-prueba")
    store.open_session("https://sitio.example/firmar", {"level": 4}, {"firmascope": "0.1.0"})
    yield store
    store.close()


def test_expediente_guarda_y_devuelve_eventos(store):
    store.add_event(make_event(EventType.FILE_READ, 0.0, tags=[Tag.KEY_FILE], name="fiel.key"))
    store.add_event(make_event(EventType.CRYPTO_SIGN, 1.0, tags=[Tag.SIGNATURE]))

    todos = store.events()
    assert len(todos) == 2
    assert [e.seq for e in todos] == sorted(e.seq for e in todos)
    assert store.events([EventType.CRYPTO_SIGN])[0].type is EventType.CRYPTO_SIGN


def test_cadena_de_hashes_se_verifica(store):
    for i in range(12):
        store.add_event(make_event(EventType.NETWORK_REQUEST, float(i),
                                   url=f"https://sitio.example/{i}"))
    ok, primera_rota = store.verify_chain()
    assert ok and primera_rota is None


def test_cadena_detecta_manipulacion(store, tmp_path):
    """Sin esto, el expediente no seria evidencia sino un registro cualquiera."""
    for i in range(6):
        store.add_event(make_event(EventType.NETWORK_REQUEST, float(i),
                                   url=f"https://sitio.example/{i}"))
    store.close()

    import sqlite3
    db = sqlite3.connect(str(tmp_path / "session.sqlite"))
    db.execute("UPDATE events SET data_json = "
               "REPLACE(data_json, 'sitio.example/3', 'otro.example/3')")
    db.commit()
    db.close()

    reopened = EvidenceStore(tmp_path, "sesion-de-prueba")
    ok, primera_rota = reopened.verify_chain()
    reopened.close()
    assert not ok
    assert primera_rota is not None


def test_expediente_registra_peticiones_y_scripts(store):
    store.add_request(RequestRecord(
        timestamp=1.0, method="POST", url="https://cdn.tercero.example/a",
        host="cdn.tercero.example", registrable="tercero.example", third_party=True))
    store.add_script(ScriptRecord(
        url="https://sitio.example/app.js", sha256="a" * 64, size=100), b"const x = 1;")

    assert store.requests()[0]["third_party"] is True
    assert store.scripts()[0]["sha256"] == "a" * 64
    assert store.script_body("a" * 64) == b"const x = 1;"


def test_expediente_registra_hallazgos(store):
    from firmascope.audit_core.conclusions import Confidence, Severity

    store.add_finding(Finding(
        rule_id="FS-KEY-001", title="Clave transmitida", status=Status.OBSERVED,
        severity=Severity.CRITICAL, confidence=Confidence.HIGH,
        summary="La clave salio del navegador."))
    guardados = store.findings()
    assert guardados[0]["rule_id"] == "FS-KEY-001"
    assert guardados[0]["status"] == "OBSERVED"


def test_checkpoints_registran_el_estado_de_red(store):
    store.add_checkpoint("antes-de-firmar", "offline", "red aislada", timestamp=1.0)
    store.add_checkpoint("despues-de-firmar", "online", timestamp=2.0)
    nombres = [c["name"] for c in store.checkpoints()]
    assert nombres == ["antes-de-firmar", "despues-de-firmar"]


def test_el_expediente_no_escribe_secretos(tmp_path):
    """La promesa central: nada de lo registrado en el vault llega al disco."""
    vault = SecretVault()
    vault.register(Tag.KEY_PASSWORD, "contrasena-secreta-de-laboratorio")

    root = tmp_path / "expediente"
    store = EvidenceStore(root, "sesion-secretos", vault=vault)
    store.open_session("https://sitio.example", {"level": 4}, {})
    store.add_event(make_event(
        EventType.NETWORK_REQUEST, 0.0, url="https://evil.example/c",
        body="pwd=contrasena-secreta-de-laboratorio"))
    store.close()

    escritos = [p for p in root.rglob("*") if p.is_file()]
    assert escritos, "el expediente no escribio nada: la prueba seria vacua"
    for path in escritos:
        assert b"contrasena-secreta-de-laboratorio" not in path.read_bytes(), (
            f"se escribio un secreto en {path.name}")


# ----------------------------------------------------------------------
# Cadena de integridad, a nivel de funcion
# ----------------------------------------------------------------------

def test_canonical_es_independiente_del_orden_de_claves():
    assert chain.canonical({"b": 1, "a": 2}) == chain.canonical({"a": 2, "b": 1})


def test_link_encadena_el_hash_anterior():
    h1 = chain.link(chain.GENESIS, {"n": 1})
    h2 = chain.link(h1, {"n": 2})
    assert h1 != h2
    assert chain.link(h1, {"n": 2}) == h2
    assert chain.link("otro", {"n": 2}) != h2


def test_verify_localiza_el_primer_registro_roto():
    payloads = [{"n": i} for i in range(5)]
    records, prev = [], chain.GENESIS
    for payload in payloads:
        current = chain.link(prev, payload)
        records.append((payload, prev, current))
        prev = current

    ok, roto = chain.verify(records)
    assert ok and roto is None

    records[2] = ({"n": 99}, records[2][1], records[2][2])
    ok, roto = chain.verify(records)
    assert not ok and roto == 2
