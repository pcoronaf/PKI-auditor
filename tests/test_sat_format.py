"""El .key sintetico con el cifrado de una e.firma del SAT.

En el primer piloto sobre un portal real, la biblioteca FIEL del portal no
podia leer la llave sintetica (AES) y el sitio se quedaba cargando sin llegar
a firmar. jsrsasign hasta la version 8 lanza "this only supports TripleDES"
con cualquier llave que no sea la del SAT.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest
from cryptography.hazmat.primitives import serialization

from firmascope.credentials import generate
from firmascope.credentials.sat_format import (
    OID_DES_EDE3_CBC,
    OID_PBES2,
    OID_PBKDF2,
    SAT_ITERATIONS,
    _oid,
    encrypt_pkcs8_sat,
)


def test_por_omision_la_llave_tiene_el_formato_del_sat():
    cred = generate()
    for oid in (OID_PBES2, OID_PBKDF2, OID_DES_EDE3_CBC):
        assert _oid(oid) in cred.key_der, oid
    # 2048 iteraciones (0x0800), como el SAT, y sin PRF explicito: HMAC-SHA1.
    assert b"\x02\x02\x08\x00" in cred.key_der
    assert SAT_ITERATIONS == 2048
    assert b"\x2a\x86\x48\x86\xf7\x0d\x02\x09" not in cred.key_der  # hmacWithSHA256
    assert b"\x60\x86\x48\x01\x65\x03\x04\x01\x2a" not in cred.key_der  # aes-256-cbc


def test_la_llave_sat_se_descifra_con_su_contrasena():
    cred = generate()
    key = serialization.load_der_private_key(cred.key_der, password=cred.password.encode())
    plain = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption())
    assert plain == cred.key_plain_der
    with pytest.raises(ValueError):
        serialization.load_der_private_key(cred.key_der, password=b"otra")


@pytest.mark.skipif(shutil.which("openssl") is None, reason="sin openssl")
def test_openssl_la_lee_como_una_llave_del_sat(tmp_path):
    cred = generate()
    path = tmp_path / "audit.key"
    path.write_bytes(cred.key_der)
    out = subprocess.run(["openssl", "asn1parse", "-inform", "DER", "-in", str(path)],
                         capture_output=True, text=True, check=True).stdout
    assert "PBES2" in out and "PBKDF2" in out and "des-ede3-cbc" in out


def test_aes_sigue_disponible_para_los_laboratorios_webcrypto():
    cred = generate(key_format="aes")
    assert _oid(OID_DES_EDE3_CBC) not in cred.key_der
    serialization.load_der_private_key(cred.key_der, password=cred.password.encode())


def test_un_formato_desconocido_se_rechaza():
    with pytest.raises(ValueError):
        generate(key_format="des")


def test_el_relleno_cubre_bloques_exactos():
    """Un PKCS#8 de longitud multiplo de 8 lleva un bloque entero de relleno."""
    cred = generate()
    plain = cred.key_plain_der[: len(cred.key_plain_der) // 8 * 8]
    assert len(encrypt_pkcs8_sat(plain, "x" * 12)) > len(plain)
