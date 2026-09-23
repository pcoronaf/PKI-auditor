"""Encadenamiento por hashes del expediente de evidencias (NFR-003).

Cada registro persistido se encadena con el anterior:

    hash_n = SHA256(hash_{n-1} || canonical_json(registro_n))

El hash final (``head``) se publica en ``manifest.json``. Cualquier
modificacion posterior de un evento rompe la cadena de forma detectable.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

GENESIS = "0" * 64


def canonical(payload: dict[str, Any]) -> str:
    """Serializacion canonica y estable de un registro."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def link(prev_hash: str, payload: dict[str, Any]) -> str:
    """Calcula el hash del registro encadenado al anterior."""
    material = prev_hash.encode("ascii") + canonical(payload).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def verify(records: Iterable[tuple[dict[str, Any], str, str]]) -> tuple[bool, int | None]:
    """Verifica una secuencia ``(payload, prev_hash, hash)``.

    Devuelve ``(ok, indice_del_primer_registro_roto)``.
    """
    expected_prev = GENESIS
    for index, (payload, prev_hash, digest) in enumerate(records):
        if prev_hash != expected_prev:
            return False, index
        if link(prev_hash, payload) != digest:
            return False, index
        expected_prev = digest
    return True, None


def file_digest(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(65536), b""):
            h.update(block)
    return h.hexdigest()
