"""Proteccion de secretos y correlacion por canarios.

Principio de la especificacion: *los secretos observados no se escriben a
disco*. Para poder correlacionar un dato saliente con su procedencia,
FirmaScope calcula fingerprints HMAC con una clave de sesion aleatoria que
vive exclusivamente en memoria y se destruye al terminar la sesion.

El :class:`SecretVault` tambien conoce las *representaciones* de cada canario
(raw, base64, hex, url-encoded, sha256...) para poder buscarlas dentro de
cuerpos HTTP sin necesidad de guardar el secreto en el expediente.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Iterable

from .events import Tag

#: Claves de diccionario que jamas deben viajar a disco dentro de ``Event.data``.
FORBIDDEN_KEYS = frozenset(
    {
        "password",
        "passwd",
        "pass",
        "contrasena",
        "contrasenia",
        "clave",
        "secret",
        "privatekey",
        "private_key",
        "keydata",
        "key_data",
        "pin",
        "token",
        "body",
        "postdata",
        "post_data",
        "payload",
        "value",
        "plaintext",
    }
)

#: Longitud maxima de cualquier cadena persistida dentro de ``Event.data``.
MAX_STRING = 512

#: Nombres de archivo de material criptografico. Se redactan conservando la
#: extension, porque saber que era un ``.key`` es evidencia y el nombre no.
CREDENTIAL_FILE_PATTERN = re.compile(
    r"^\s*(?:.*[\\/])?(.+?)(\.(?:key|cer|crt|cert|pem|p12|pfx|der|p8))\s*$", re.I)

#: RFC mexicano (persona fisica o moral). El nombre de archivo de una e.firma
#: del SAT lo contiene, de modo que publicarlo identificaria al titular.
RFC_PATTERN = re.compile(r"\b[A-Z&N]{3,4}\d{6}[A-Z0-9]{3}\b", re.I)

#: CURP, por si aparece en un formulario de firma.
CURP_PATTERN = re.compile(r"\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b", re.I)

#: Claves cuyo valor es un digest global. En modo real se sustituyen por un
#: fingerprint HMAC de sesion: sirve igual para correlacionar dentro de la
#: auditoria, pero no vincula el expediente con una persona concreta.
DIGEST_KEYS = frozenset({"sha256", "key_sha256", "cert_sha256", "body_digest", "digest"})

#: Cadenas que no deben pasar por el detector de identificadores: un digest o
#: un fingerprint puede contener por azar algo con forma de RFC.
_OPAQUE_VALUE = re.compile(r"^(?:fp:)?[0-9a-f]{24,}$", re.I)


def redact_filename(value: str) -> str | None:
    """Devuelve ``<redactado.key>`` si el valor parece un archivo de credencial."""
    match = CREDENTIAL_FILE_PATTERN.match(value)
    if match is None:
        return None
    return f"<redactado{match.group(2).lower()}>"


def redact_personal_ids(value: str) -> str:
    """Sustituye RFC y CURP dentro de un texto libre."""
    if _OPAQUE_VALUE.match(value.strip()):
        return value
    value = RFC_PATTERN.sub("<redactado:rfc>", value)
    return CURP_PATTERN.sub("<redactado:curp>", value)


@dataclass(frozen=True)
class Representation:
    """Una codificacion concreta de un canario, buscable en trafico."""

    label: str          # KEY_FILE, KEY_PASSWORD, ...
    encoding: str       # raw, base64, hex, url, utf8, sha256-hex, ...
    needle: bytes

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self.needle)


@dataclass(frozen=True)
class CanaryMatch:
    """Coincidencia de una representacion de canario dentro de un blob."""

    label: str
    encoding: str
    offset: int
    length: int

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "encoding": self.encoding,
            "offset": self.offset,
            "length": self.length,
        }


def _b64(data: bytes) -> bytes:
    return base64.b64encode(data)


def _b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def _hex(data: bytes) -> bytes:
    return binascii.hexlify(data)


def representations(label: str, raw: bytes, *, is_text: bool,
                    include_markers: bool = True) -> list[Representation]:
    """Deriva las representaciones buscables de un canario.

    Cubre la lista de la especificacion: SHA256(KEY), marcador raw, base64,
    hex, url-encoded, base64 de la contrasena y UTF-8 de la contrasena.
    """

    reps: list[Representation] = []

    def add(encoding: str, needle: bytes, minimum: int = 8) -> None:
        if len(needle) >= minimum:
            reps.append(Representation(label, encoding, needle))

    digest = hashlib.sha256(raw).digest()

    if is_text:
        add("utf8", raw, minimum=4)
        add("url", urllib.parse.quote(raw.decode("utf-8", "replace")).encode(), minimum=4)
        add("base64", _b64(raw), minimum=4)
        add("base64url", _b64url(raw), minimum=4)
        add("hex", _hex(raw), minimum=6)
        add("utf16le", raw.decode("utf-8", "replace").encode("utf-16-le"), minimum=8)
    else:
        add("raw", raw, minimum=16)
        add("base64", _b64(raw), minimum=16)
        add("base64url", _b64url(raw), minimum=16)
        add("hex", _hex(raw), minimum=16)
        if include_markers:
            # Un fragmento interior estable permite detectar el material aunque
            # viaje troceado. No se usa para material publico (certificados),
            # porque el modulo RSA aparece tanto en el .cer como en el .key.
            marker = raw[len(raw) // 2 : len(raw) // 2 + 32] if len(raw) >= 64 else raw
            add("raw-marker", marker, minimum=16)
            b64 = _b64(raw)
            if len(b64) >= 96:
                add("base64-marker", b64[len(b64) // 2 : len(b64) // 2 + 48], minimum=16)

    add("sha256-hex", _hex(digest), minimum=16)
    add("sha256-base64", _b64(digest), minimum=16)
    return reps


class SecretVault:
    """Guarda secretos de laboratorio en memoria y solo emite fingerprints.

    El vault se usa con las credenciales *sinteticas* generadas por
    FirmaScope. Si el operador decide usar sus propias credenciales de prueba,
    el mismo mecanismo aplica: nada de lo registrado aqui se serializa.
    """

    def __init__(self) -> None:
        self._session_key: bytes | None = os.urandom(32)
        self._reps: list[Representation] = []
        self._labels: set[str] = set()

    # -- ciclo de vida --------------------------------------------------
    @property
    def alive(self) -> bool:
        return self._session_key is not None

    def destroy(self) -> None:
        """Destruye la clave de sesion y las representaciones en memoria."""
        self._session_key = None
        for rep in self._reps:
            del rep  # libera la referencia local; el GC hace el resto
        self._reps = []
        self._labels = set()

    def __enter__(self) -> "SecretVault":
        return self

    def __exit__(self, *exc) -> None:
        self.destroy()

    # -- registro -------------------------------------------------------
    def register(self, label: str | Tag, raw: bytes | str, *, is_text: bool | None = None,
                 include_markers: bool = True) -> str:
        """Registra un canario y devuelve su fingerprint HMAC."""
        if not self.alive:
            raise RuntimeError("SecretVault destruido")
        label = label.value if isinstance(label, Tag) else str(label)
        if isinstance(raw, str):
            if is_text is None:
                is_text = True
            raw = raw.encode("utf-8")
        elif is_text is None:
            is_text = False
        self._reps.extend(representations(label, raw, is_text=is_text, include_markers=include_markers))
        self._labels.add(label)
        return self.fingerprint(raw)

    @property
    def labels(self) -> set[str]:
        return set(self._labels)

    # -- fingerprints ---------------------------------------------------
    def fingerprint(self, data: bytes | str) -> str:
        """HMAC(session-key, data) truncado: identificador efimero y opaco."""
        if not self.alive:
            raise RuntimeError("SecretVault destruido")
        if isinstance(data, str):
            data = data.encode("utf-8")
        mac = hmac.new(self._session_key, data, hashlib.sha256).hexdigest()
        return f"fp:{mac[:32]}"

    # -- busqueda -------------------------------------------------------
    def scan(self, blob: bytes | str) -> list[CanaryMatch]:
        """Busca representaciones de canarios dentro de un blob."""
        if not self.alive or not self._reps:
            return []
        if isinstance(blob, str):
            blob = blob.encode("utf-8", "replace")
        matches: list[CanaryMatch] = []
        seen: set[tuple[str, str]] = set()
        for rep in self._reps:
            key = (rep.label, rep.encoding)
            if key in seen:
                continue
            idx = blob.find(rep.needle)
            if idx >= 0:
                matches.append(CanaryMatch(rep.label, rep.encoding, idx, len(rep.needle)))
                seen.add(key)
        return matches

    def labels_in(self, blob: bytes | str) -> set[str]:
        """Etiquetas presentes en ``blob`` o en sus formas decodificadas.

        Una clave en base64 dentro de una URL llega escapada por
        ``encodeURIComponent`` (``+`` -> ``%2B``, ``/`` -> ``%2F``). Buscar solo
        la forma cruda la dejaba pasar o no segun los bytes de cada clave: un
        fallo intermitente que escribia la clave en el expediente. Toda
        comprobacion previa a escribir a disco usa esta funcion.
        """
        labels: set[str] = set()
        for variant in decoded_variants(blob):
            labels |= {m.label for m in self.scan(variant)}
        return labels


def decoded_variants(blob: bytes | str) -> list[bytes | str]:
    """``blob`` y, si parece escapado para URL, sus formas decodificadas."""
    variants: list[bytes | str] = [blob]
    text = blob.decode("utf-8", "replace") if isinstance(blob, bytes) else blob
    if "%" in text or "+" in text:
        for decoded in (urllib.parse.unquote(text), urllib.parse.unquote_plus(text)):
            if decoded != text and decoded not in variants:
                variants.append(decoded)
    return variants


def redact_url(url: str, vault: "SecretVault | None") -> str:
    """Una URL apta para el expediente.

    Si la query o el fragmento llevan material sensible se sustituyen por un
    marcador, conservando esquema, host y ruta: el reporte tiene que poder
    decir *a donde* salio el material sin volver a escribirlo.
    """
    if not url or vault is None or not vault.alive:
        return url
    labels = vault.labels_in(url)
    if not labels:
        return url
    marker = "<canary:" + ",".join(sorted(labels)) + ">"
    parts = urllib.parse.urlsplit(url)
    if vault.labels_in(parts.scheme + "://" + parts.netloc + parts.path):
        return marker
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, marker, ""))


# ----------------------------------------------------------------------
# Redaccion defensiva
# ----------------------------------------------------------------------

_LONG_B64 = re.compile(rb"[A-Za-z0-9+/=]{120,}")
_PEM = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")


def looks_like_private_key(blob: bytes) -> bool:
    """Heuristica: el blob parece material de clave privada en claro."""
    if _PEM.search(blob):
        return True
    # PKCS#8 / EncryptedPrivateKeyInfo empiezan con SEQUENCE de tamano largo.
    return blob[:1] == b"\x30" and len(blob) > 256


def redact(data: dict, vault: SecretVault | None = None, privacy=None) -> dict:
    """Devuelve una copia segura de ``data`` apta para persistirse.

    - elimina claves de la denylist;
    - trunca cadenas largas;
    - sustituye cualquier aparicion de un canario por un marcador;
    - con una :class:`~firmascope.audit_core.config.PrivacyPolicy` activa,
      redacta nombres de archivo de credenciales, identificadores fiscales y
      digests globales.

    La deteccion de nombres de archivo es por *contenido*, no por nombre de
    clave: asi se redacta ``FIEL_XAXX010101000.key`` sin tocar campos legitimos
    como el ``name`` de un checkpoint.
    """

    redact_names = bool(privacy is not None and getattr(privacy, "redact_filenames", False))
    redact_ids = bool(privacy is not None and getattr(privacy, "redact_personal_ids", False))
    hide_digests = bool(privacy is not None
                        and not getattr(privacy, "publish_global_digests", True))

    def clean_value(value, key: str = ""):
        if isinstance(value, str):
            if vault is not None and vault.alive:
                if "://" in value[:16]:
                    # Una URL con la clave en la query conserva su destino:
                    # es la mitad util del hallazgo.
                    cleaned = redact_url(value, vault)
                    if cleaned != value:
                        return cleaned
                labels = vault.labels_in(value)
                if labels:
                    return "<canary:" + ",".join(sorted(labels)) + ">"
            if hide_digests and key.lower() in DIGEST_KEYS and value:
                if vault is not None and vault.alive:
                    return vault.fingerprint(value)
                return "<redactado:digest>"
            if redact_names:
                as_file = redact_filename(value)
                if as_file is not None:
                    return as_file
            if redact_ids:
                value = redact_personal_ids(value)
            if len(value) > MAX_STRING:
                return value[:MAX_STRING] + f"...<truncated {len(value)} bytes>"
            return value
        if isinstance(value, (int, float, bool)) or value is None:
            return value
        if isinstance(value, dict):
            return {k: clean_value(v, k) for k, v in value.items()
                    if k.lower() not in FORBIDDEN_KEYS}
        if isinstance(value, (list, tuple)):
            return [clean_value(v, key) for v in value][:200]
        return clean_value(str(value), key)

    return {k: clean_value(v, k) for k, v in data.items() if k.lower() not in FORBIDDEN_KEYS}


def assert_no_secrets(payload: str, vault: SecretVault | None) -> None:
    """Invariante de seguridad usada en pruebas y en el exportador."""
    if vault is None or not vault.alive:
        return
    hits = [hit for variant in decoded_variants(payload) for hit in vault.scan(variant)]
    if hits:
        raise AssertionError(
            "material sensible a punto de escribirse a disco: "
            + ", ".join(f"{m.label}/{m.encoding}" for m in hits)
        )


def iter_strings(obj) -> Iterable[str]:  # pragma: no cover - utilidad
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from iter_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from iter_strings(v)
