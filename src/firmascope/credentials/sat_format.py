"""El ``.key`` sintetico con el mismo cifrado que una e.firma del SAT.

Una llave del SAT es un PKCS#8 cifrado (EncryptedPrivateKeyInfo) con PBES2,
PBKDF2-HMAC-SHA1 con 2048 iteraciones y 3DES (DES-EDE3-CBC). ``cryptography``
solo escribe PKCS#8 cifrado con AES-256 y PBKDF2-HMAC-SHA256, y las bibliotecas
FIEL de los portales (jsrsasign, versiones antiguas de forge) solo aceptan el
formato del SAT.

En el primer piloto sobre un portal real, la llave sintetica en AES hacia
fallar la biblioteca del portal antes de llegar a firmar: el sitio se quedaba
"cargando" y la auditoria no observaba lo que el portal haria con una llave de
verdad. Una credencial de prueba solo sirve si el portal la trata como trataria
la del usuario, hasta donde lo permite no ser del SAT.

3DES esta obsoleto como cifrado, y aqui no protege nada: la llave es sintetica
y su contrasena se muestra en pantalla. Se usa porque es el formato que el
portal espera.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:  # cryptography >= 43
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:  # pragma: no cover - versiones anteriores
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

#: Iteraciones de PBKDF2 en las llaves que emite el SAT.
SAT_ITERATIONS = 2048

OID_PBES2 = "1.2.840.113549.1.5.13"
OID_PBKDF2 = "1.2.840.113549.1.5.12"
OID_DES_EDE3_CBC = "1.2.840.113549.3.7"


# ----------------------------------------------------------------------
# DER minimo: lo justo para EncryptedPrivateKeyInfo
# ----------------------------------------------------------------------

def _length(size: int) -> bytes:
    if size < 0x80:
        return bytes([size])
    raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _length(len(value)) + value


def _sequence(*items: bytes) -> bytes:
    return _tlv(0x30, b"".join(items))


def _octets(value: bytes) -> bytes:
    return _tlv(0x04, value)


def _integer(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big")
    return _tlv(0x02, raw)


def _oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    body = bytearray([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append(0x80 | (part & 0x7F))
            part >>= 7
        body.extend(reversed(chunk))
    return _tlv(0x06, bytes(body))


# ----------------------------------------------------------------------

def encrypt_pkcs8_sat(plain_pkcs8_der: bytes, password: str,
                      iterations: int = SAT_ITERATIONS) -> bytes:
    """Cifra un PKCS#8 en claro como lo hace el SAT."""
    salt = os.urandom(8)
    iv = os.urandom(8)
    key = PBKDF2HMAC(algorithm=hashes.SHA1(), length=24, salt=salt,
                     iterations=iterations).derive(password.encode("utf-8"))
    padder = padding.PKCS7(64).padder()
    padded = padder.update(plain_pkcs8_der) + padder.finalize()
    encryptor = Cipher(TripleDES(key), modes.CBC(iv)).encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()

    # PBKDF2-params sin `prf`: el valor por omision es hmacWithSHA1, y el SAT
    # tampoco lo escribe.
    kdf = _sequence(_oid(OID_PBKDF2), _sequence(_octets(salt), _integer(iterations)))
    scheme = _sequence(_oid(OID_DES_EDE3_CBC), _octets(iv))
    algorithm = _sequence(_oid(OID_PBES2), _sequence(kdf, scheme))
    return _sequence(algorithm, _octets(encrypted))
