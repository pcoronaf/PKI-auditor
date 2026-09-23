"""Credenciales sinteticas de laboratorio (canarios).

FirmaScope nunca debe promover el uso de credenciales productivas. Estas
credenciales imitan la *forma* de una e.firma del SAT (un ``.key`` con la
clave privada cifrada en PKCS#8 y un ``.cer`` X.509 en DER) pero no pretenden
ser certificados validos: el sujeto lo declara explicitamente.

Su proposito es identificar representaciones del secreto en el trafico y
permitir pruebas repetibles.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ..audit_core.events import Tag
from ..audit_core.secrets import SecretVault

PASSWORD_PREFIX = "FSCOPE-AUDIT-"
PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # sin caracteres ambiguos

#: Texto que deja constancia de que la credencial no es una e.firma real.
SYNTHETIC_MARKER = "FIRMASCOPE SYNTHETIC LABORATORY CREDENTIAL - NOT A SAT CERTIFICATE"

#: Variante corta para el Common Name (X.509 limita cada atributo a 64 bytes).
SYNTHETIC_CN = "FIRMASCOPE SYNTHETIC - NOT A SAT CERTIFICATE"


def generate_password(length: int = 8) -> str:
    return PASSWORD_PREFIX + "".join(secrets.choice(PASSWORD_ALPHABET) for _ in range(length))


@dataclass
class SyntheticCredential:
    """Par ``.key`` / ``.cer`` sintetico mas su contrasena."""

    password: str
    key_der: bytes            # PKCS#8 cifrado con la contrasena (equivalente al .key)
    key_plain_der: bytes      # PKCS#8 sin cifrar (lo que veria un exfiltrador)
    cert_der: bytes           # X.509 DER (equivalente al .cer)
    public_der: bytes
    serial: int
    subject: str
    not_before: datetime
    not_after: datetime
    key_path: Path | None = None
    cert_path: Path | None = None
    fingerprints: dict[str, str] = field(default_factory=dict)

    # -- persistencia ---------------------------------------------------
    def write(self, directory: Path, stem: str = "audit") -> "SyntheticCredential":
        """Escribe ``audit.key`` y ``audit.cer`` en ``directory``.

        Se escriben fuera del expediente de evidencias: son material de
        laboratorio que el operador entrega al sitio auditado, no evidencia.
        """
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        self.key_path = directory / f"{stem}.key"
        self.cert_path = directory / f"{stem}.cer"
        self.key_path.write_bytes(self.key_der)
        self.cert_path.write_bytes(self.cert_der)
        try:
            self.key_path.chmod(0o600)
        except OSError:  # pragma: no cover - sistemas sin permisos POSIX
            pass
        return self

    def describe(self) -> dict[str, Any]:
        """Metadatos publicables en el manifiesto (sin secretos)."""
        return {
            "synthetic": True,
            "marker": SYNTHETIC_MARKER,
            "subject": self.subject,
            "serial": str(self.serial),
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "key_file": str(self.key_path) if self.key_path else "",
            "cert_file": str(self.cert_path) if self.cert_path else "",
            "key_sha256": hashlib.sha256(self.key_der).hexdigest(),
            "cert_sha256": hashlib.sha256(self.cert_der).hexdigest(),
            "password_length": len(self.password),
            "password_fingerprint": self.fingerprints.get(Tag.KEY_PASSWORD.value, ""),
            "key_fingerprint": self.fingerprints.get(Tag.KEY_FILE.value, ""),
        }

    def register(self, vault: SecretVault) -> dict[str, str]:
        """Registra todas las representaciones buscables en el vault."""
        self.fingerprints = {
            Tag.KEY_FILE.value: vault.register(Tag.KEY_FILE, self.key_der),
            Tag.PRIVATE_KEY.value: vault.register(Tag.PRIVATE_KEY, self.key_plain_der),
            Tag.KEY_PASSWORD.value: vault.register(Tag.KEY_PASSWORD, self.password),
            # El certificado es material publico y comparte el modulo RSA con la
            # clave: sin marcadores interiores para no contaminar otras etiquetas.
            Tag.CERTIFICATE.value: vault.register(Tag.CERTIFICATE, self.cert_der, include_markers=False),
        }
        return dict(self.fingerprints)


def generate(key_size: int = 2048, password: str | None = None,
             rfc: str = "FSCO000000XX0", days: int = 365) -> SyntheticCredential:
    """Genera una credencial sintetica completa."""
    password = password or generate_password()
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, SYNTHETIC_CN),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FirmaScope Laboratory"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Synthetic laboratory credential"),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, rfc),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "MX"),
    ])
    now = datetime.now(timezone.utc)
    serial = x509.random_serial_number()
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)               # autofirmado: no encadena con el SAT
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment=False,
                          data_encipherment=False, key_agreement=False, key_cert_sign=False,
                          crl_sign=False, encipher_only=False, decipher_only=False),
            critical=True,
        )
        .add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier("1.3.6.1.4.1.57264.9999.1"),
                SYNTHETIC_MARKER.encode("ascii"),
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    key_der = key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
    )
    key_plain_der = key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return SyntheticCredential(
        password=password,
        key_der=key_der,
        key_plain_der=key_plain_der,
        cert_der=certificate.public_bytes(serialization.Encoding.DER),
        public_der=public_der,
        serial=serial,
        subject=SYNTHETIC_CN,
        not_before=now,
        not_after=now + timedelta(days=days),
    )


def load(key_path: Path, cert_path: Path, password: str) -> SyntheticCredential:
    """Carga credenciales de prueba aportadas por el operador.

    Se usan exactamente igual que las sinteticas: solo se derivan
    representaciones para correlacion, nunca se escriben en el expediente.
    """
    key_der = Path(key_path).read_bytes()
    cert_der = Path(cert_path).read_bytes()
    private = serialization.load_der_private_key(key_der, password=password.encode("utf-8"))
    try:
        certificate = x509.load_der_x509_certificate(cert_der)
    except ValueError:
        certificate = x509.load_pem_x509_certificate(cert_der)
    plain = private.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return SyntheticCredential(
        password=password,
        key_der=key_der,
        key_plain_der=plain,
        cert_der=cert_der,
        public_der=private.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo),
        serial=certificate.serial_number,
        subject=certificate.subject.rfc4514_string(),
        not_before=certificate.not_valid_before_utc,
        not_after=certificate.not_valid_after_utc,
        key_path=Path(key_path),
        cert_path=Path(cert_path),
    )
