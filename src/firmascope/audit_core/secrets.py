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
        return {m.label for m in self.scan(blob)}


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


def redact(data: dict, vault: SecretVault | None = None) -> dict:
    """Devuelve una copia segura de ``data`` apta para persistirse.

    - elimina claves de la denylist;
    - trunca cadenas largas;
    - sustituye cualquier aparicion de un canario por un marcador.
    """

    def clean_value(value):
        if isinstance(value, str):
            if vault is not None and vault.alive:
                labels = vault.labels_in(value)
                if labels:
                    return "<canary:" + ",".join(sorted(labels)) + ">"
            if len(value) > MAX_STRING:
                return value[:MAX_STRING] + f"...<truncated {len(value)} bytes>"
            return value
        if isinstance(value, (int, float, bool)) or value is None:
            return value
        if isinstance(value, dict):
            return {k: clean_value(v) for k, v in value.items() if k.lower() not in FORBIDDEN_KEYS}
        if isinstance(value, (list, tuple)):
            return [clean_value(v) for v in value][:200]
        return clean_value(str(value))

    return {k: clean_value(v) for k, v in data.items() if k.lower() not in FORBIDDEN_KEYS}


def assert_no_secrets(payload: str, vault: SecretVault | None) -> None:
    """Invariante de seguridad usada en pruebas y en el exportador."""
    if vault is None or not vault.alive:
        return
    hits = vault.scan(payload)
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
