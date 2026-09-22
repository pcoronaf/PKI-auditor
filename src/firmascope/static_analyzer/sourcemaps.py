"""Soporte de source maps.

Cuando un bundle publica su source map, FirmaScope puede traducir la linea de
un hallazgo a su fichero y linea originales, de modo que el reporte cite
``crypto-client.js:438`` y no ``bundle.min.js:1``.

Solo se leen source maps que ya estan en el expediente (en linea, como
``data:``, o descargados por el operador). El analizador nunca sale a la red
por su cuenta: la herramienta no debe generar trafico no solicitado hacia el
sitio auditado.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any

#: Alfabeto base64 usado por las VLQ de los source maps.
_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_B64_INDEX = {char: index for index, char in enumerate(_B64)}


def decode_vlq(segment: str) -> list[int]:
    """Decodifica un segmento VLQ base64 a una lista de enteros."""
    values: list[int] = []
    shift = 0
    accumulator = 0
    for char in segment:
        digit = _B64_INDEX.get(char)
        if digit is None:
            raise ValueError(f"caracter VLQ invalido: {char!r}")
        continuation = digit & 32
        digit &= 31
        accumulator += digit << shift
        if continuation:
            shift += 5
            continue
        negative = accumulator & 1
        value = accumulator >> 1
        values.append(-value if negative else value)
        accumulator = 0
        shift = 0
    return values


@dataclass
class SourceMap:
    """Source map decodificado, consultable por linea generada."""

    sources: list[str]
    #: ``{linea_generada: (fichero_original, linea_original)}``
    lines: dict[int, tuple[str, int]]

    def original(self, generated_line: int) -> tuple[str, int] | None:
        """Devuelve ``(fichero, linea)`` original para una linea generada."""
        if generated_line in self.lines:
            return self.lines[generated_line]
        # El mapeo puede no cubrir la linea exacta: se usa la anterior conocida.
        candidates = [line for line in self.lines if line <= generated_line]
        if not candidates:
            return None
        return self.lines[max(candidates)]

    def describe(self, generated_line: int, fallback: str) -> str:
        mapped = self.original(generated_line)
        if mapped is None:
            return f"{fallback}:{generated_line}"
        return f"{mapped[0]}:{mapped[1]}"


def parse(raw: str | bytes | dict[str, Any]) -> SourceMap | None:
    """Parsea un source map (v3). Devuelve ``None`` si no es utilizable."""
    try:
        if isinstance(raw, (str, bytes)):
            document = json.loads(raw)
        else:
            document = raw
        if not isinstance(document, dict) or "mappings" not in document:
            return None
        sources = [str(s) for s in document.get("sources", [])]
        mappings = str(document.get("mappings", ""))
    except Exception:
        return None

    lines: dict[int, tuple[str, int]] = {}
    source_index = 0
    original_line = 0
    for generated_line, group in enumerate(mappings.split(";"), start=1):
        if not group:
            continue
        for segment in group.split(","):
            if not segment:
                continue
            try:
                fields = decode_vlq(segment)
            except ValueError:
                continue
            if len(fields) < 4:
                continue
            source_index += fields[1]
            original_line += fields[2]
            if 0 <= source_index < len(sources) and generated_line not in lines:
                lines[generated_line] = (sources[source_index], original_line + 1)
    if not lines:
        return None
    return SourceMap(sources=sources, lines=lines)


def parse_inline(sourcemap_url: str) -> SourceMap | None:
    """Parsea un source map embebido como ``data:`` en el comentario final."""
    if not sourcemap_url.startswith("data:"):
        return None
    try:
        header, _, payload = sourcemap_url.partition(",")
        if ";base64" in header:
            decoded = base64.b64decode(payload)
        else:
            from urllib.parse import unquote

            decoded = unquote(payload).encode("utf-8")
        return parse(decoded)
    except Exception:
        return None
