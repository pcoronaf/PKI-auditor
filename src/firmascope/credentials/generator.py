"""Credenciales de laboratorio (canarios) y carga de la e.firma del operador.

FirmaScope nunca debe promover el uso de credenciales productivas. Las
credenciales sinteticas imitan la *forma* de una e.firma del SAT (un ``.key``
con la clave privada cifrada en PKCS#8 y un ``.cer`` X.509 en DER) pero no
pretenden ser certificados validos: el sujeto lo declara explicitamente.

Hay un caso legitimo en que eso no basta: el operador necesita firmar en ese
portal de todas formas y quiere saber que hace con su clave. Para eso existe
:func:`load_real`, con las guardas que describe ``docs/real-credentials.md``.
"""

from __future__ import annotations

import hashlib
import secrets
import warnings
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
class AuditCredential:
    """Par ``.key`` / ``.cer`` usado en la auditoria, mas su contrasena.

    Puede ser sintetica (generada por FirmaScope) o real (la e.firma del
    operador). El campo ``synthetic`` gobierna lo que esta permitido hacer con
    ella: una credencial real nunca se escribe a disco ni publica digests
    globales.

    ``key_plain_der`` contiene la clave privada descifrada. Vive solo en memoria
    y existe por un motivo concreto: sin ella no se puede detectar la
    exfiltracion de la clave *ya descifrada* (FS-KEY-002), que es justo el caso
    que una inspeccion de red no ve.
    """

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
    #: False para una e.firma real del operador.
    synthetic: bool = True

    @property
    def is_real(self) -> bool:
        return not self.synthetic

    # -- persistencia ---------------------------------------------------
    def write(self, directory: Path, stem: str = "audit") -> "AuditCredential":
        """Escribe ``audit.key`` y ``audit.cer`` en ``directory``.

        Se escriben fuera del expediente de evidencias: son material de
        laboratorio que el operador entrega al sitio auditado, no evidencia.

        Una credencial real no se escribe nunca: ya existe en el disco del
        operador y copiarla solo multiplicaria el numero de copias de su clave.
        """
        if not self.synthetic:
            raise ValueError(
                "FirmaScope no escribe credenciales reales a disco. La e.firma ya existe "
                "en su equipo; se usa desde su ubicacion original."
            )
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

    def describe(self, privacy: Any | None = None) -> dict[str, Any]:
        """Metadatos publicables en el manifiesto (sin secretos).

        Con una credencial real y ``publish_global_digests=False``, los digests
        globales se sustituyen por fingerprints de sesion y las rutas de archivo
        se omiten: el nombre de archivo de una e.firma contiene el RFC, y el
        SHA-256 del ``.key`` es un identificador estable del titular.
        """
        publish_digests = True
        if privacy is not None:
            publish_digests = bool(getattr(privacy, "publish_global_digests", True))

        info: dict[str, Any] = {
            "synthetic": self.synthetic,
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "password_length": len(self.password),
            "password_fingerprint": self.fingerprints.get(Tag.KEY_PASSWORD.value, ""),
            "key_fingerprint": self.fingerprints.get(Tag.KEY_FILE.value, ""),
        }
        if self.synthetic:
            info["marker"] = SYNTHETIC_MARKER
            info["subject"] = self.subject
            info["serial"] = str(self.serial)
            info["key_file"] = str(self.key_path) if self.key_path else ""
            info["cert_file"] = str(self.cert_path) if self.cert_path else ""
        else:
            # De una credencial real solo se publica lo que no identifica a su
            # titular: que era real, su ventana de validez y su huella de sesion.
            info["marker"] = "CREDENCIAL REAL DEL OPERADOR - metadatos redactados"
            info["subject"] = "<redactado>"
            info["serial"] = "<redactado>"
            info["key_file"] = "<redactado>"
            info["cert_file"] = "<redactado>"
        if publish_digests:
            info["key_sha256"] = hashlib.sha256(self.key_der).hexdigest()
            info["cert_sha256"] = hashlib.sha256(self.cert_der).hexdigest()
        return info

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
             rfc: str = "FSCO000000XX0", days: int = 365) -> "AuditCredential":
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
    return AuditCredential(
        password=password,
        key_der=key_der,
        key_plain_der=key_plain_der,
        cert_der=certificate.public_bytes(serialization.Encoding.DER),
        public_der=public_der,
        serial=serial,
        subject=SYNTHETIC_CN,
        not_before=now,
        not_after=now + timedelta(days=days),
        synthetic=True,
    )


def _load_private_key(raw: bytes, password: str):
    """Carga un ``.key`` en DER o PEM, cifrado o no.

    Una e.firma del SAT es PKCS#8 cifrado en DER, pero un operador puede haber
    convertido la suya a PEM, de modo que se admiten las cuatro combinaciones.
    """
    secret = password.encode("utf-8") if password else None
    attempts = (
        (serialization.load_der_private_key, secret),
        (serialization.load_pem_private_key, secret),
        (serialization.load_der_private_key, None),
        (serialization.load_pem_private_key, None),
    )
    errors: list[str] = []
    for loader, key_password in attempts:
        try:
            return loader(raw, password=key_password)
        except Exception as exc:
            errors.append(f"{loader.__name__}: {type(exc).__name__}")
    raise ValueError(
        "no se pudo abrir el archivo .key. Revise que la contrasena corresponda a esa "
        "clave y que el archivo sea el .key de la e.firma (PKCS#8). Intentos: "
        + "; ".join(errors)
    )


def _load_certificate(raw: bytes):
    try:
        return x509.load_der_x509_certificate(raw)
    except Exception:
        return x509.load_pem_x509_certificate(raw)


def _validity(certificate) -> tuple[datetime, datetime]:
    """Ventana de validez, compatible entre versiones de ``cryptography``."""
    try:
        return certificate.not_valid_before_utc, certificate.not_valid_after_utc
    except AttributeError:  # pragma: no cover - cryptography < 42
        before = certificate.not_valid_before.replace(tzinfo=timezone.utc)
        after = certificate.not_valid_after.replace(tzinfo=timezone.utc)
        return before, after


def load(key_path: Path, cert_path: Path, password: str,
         synthetic: bool = False) -> AuditCredential:
    """Carga credenciales aportadas por el operador (de prueba o reales).

    Solo se leen: nunca se copian al expediente ni se reescriben. De ellas se
    derivan las representaciones buscables que permiten detectar su
    transmision, y esas representaciones viven exclusivamente en memoria.

    Lanza ``ValueError`` si la contrasena no abre la clave, en lugar de empezar
    una auditoria que no podria detectar nada.
    """
    key_raw = Path(key_path).read_bytes()
    cert_raw = Path(cert_path).read_bytes()
    private = _load_private_key(key_raw, password)
    certificate = _load_certificate(cert_raw)

    # La clave y el certificado deben ser el mismo par: auditar con un .cer que
    # no corresponde al .key produciria correlaciones falsas.
    if private.public_key().public_numbers() != certificate.public_key().public_numbers():
        raise ValueError(
            "el .cer no corresponde al .key: sus claves publicas no coinciden. "
            "Verifique que ambos archivos son de la misma e.firma."
        )

    plain = private.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    not_before, not_after = _validity(certificate)
    return AuditCredential(
        password=password,
        key_der=key_raw,
        key_plain_der=plain,
        cert_der=cert_raw,
        public_der=private.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo),
        serial=certificate.serial_number,
        subject=certificate.subject.rfc4514_string(),
        not_before=not_before,
        not_after=not_after,
        key_path=Path(key_path),
        cert_path=Path(cert_path),
        synthetic=synthetic,
    )


def load_real(key_path: Path, cert_path: Path, password: str) -> AuditCredential:
    """Carga la e.firma real del operador.

    Identica a :func:`load`, con el nombre explicito para que el modo real sea
    visible en el codigo que lo invoca. La credencial resultante se marca como
    no sintetica, lo que impide escribirla a disco y activa la redaccion de sus
    metadatos en el expediente.

    Avisa por ``warnings`` si el certificado esta fuera de su ventana de
    validez: firmar con una e.firma vencida falla en el portal y confundiria el
    resultado de la auditoria con un problema del sitio.
    """
    credential = load(key_path, cert_path, password, synthetic=False)
    now = datetime.now(timezone.utc)
    if now < credential.not_before or now > credential.not_after:
        warnings.warn(
            "el certificado esta fuera de su ventana de validez "
            f"({credential.not_before.date()} a {credential.not_after.date()}); "
            "un fallo de firma puede deberse a esto y no al sitio auditado",
            RuntimeWarning,
            stacklevel=2,
        )
    return credential


#: Nombre historico. ``AuditCredential`` cubre tambien la credencial real.
SyntheticCredential = AuditCredential
