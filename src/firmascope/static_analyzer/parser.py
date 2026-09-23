"""Envoltura de tree-sitter para JavaScript.

El analizador estatico degrada de forma elegante: si tree-sitter no esta
disponible o un script no puede parsearse, :func:`parse` devuelve ``None`` y el
analizador cae a un barrido por patrones con confianza baja. Un fallo de
analisis nunca debe romper una auditoria.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Iterator

try:  # pragma: no cover - depende del entorno
    import tree_sitter_javascript as _ts_javascript
    from tree_sitter import Language, Parser

    _IMPORTED = True
except Exception:  # pragma: no cover
    _ts_javascript = None
    Language = Parser = None  # type: ignore[assignment]
    _IMPORTED = False


def available() -> bool:
    """True si el AST esta disponible en este entorno."""
    return _IMPORTED and _language() is not None


@lru_cache(maxsize=1)
def _language() -> Any:
    if not _IMPORTED:
        return None
    raw = _ts_javascript.language()
    for attempt in (lambda: Language(raw), lambda: Language(raw, "javascript")):
        try:
            return attempt()
        except Exception:
            continue
    return None  # pragma: no cover


def _new_parser() -> Any:
    language = _language()
    if language is None:  # pragma: no cover
        return None
    # La API del binding ha cambiado entre versiones; se prueban las tres formas.
    try:
        return Parser(language)
    except Exception:
        pass
    try:
        parser = Parser()
        parser.language = language
        return parser
    except Exception:
        pass
    try:  # pragma: no cover - versiones antiguas
        parser = Parser()
        parser.set_language(language)
        return parser
    except Exception:
        return None


def parse(source: bytes) -> Any | None:
    """Devuelve el arbol sintactico, o ``None`` si no se pudo parsear."""
    parser = _new_parser()
    if parser is None:
        return None
    try:
        return parser.parse(source)
    except Exception:  # pragma: no cover - fuentes patologicas
        return None


# ----------------------------------------------------------------------
# Utilidades sobre nodos
# ----------------------------------------------------------------------

#: Tipos de nodo que introducen un nuevo ambito de funcion.
FUNCTION_TYPES = frozenset(
    {
        "function_declaration",
        "function_expression",
        "function",
        "generator_function",
        "generator_function_declaration",
        "arrow_function",
        "method_definition",
    }
)


def text(node: Any, source: bytes) -> str:
    """Texto fuente de un nodo, acotado para no arrastrar bundles enteros."""
    if node is None:
        return ""
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8", "replace")
    except Exception:  # pragma: no cover
        return ""


def snippet(node: Any, source: bytes, limit: int = 160) -> str:
    """Fragmento de codigo en una sola linea, apto para un reporte."""
    raw = " ".join(text(node, source).split())
    return raw if len(raw) <= limit else raw[: limit - 3] + "..."


def line_of(node: Any) -> int:
    try:
        return int(node.start_point[0]) + 1
    except Exception:  # pragma: no cover
        return 0


def column_of(node: Any) -> int:
    try:
        return int(node.start_point[1])
    except Exception:  # pragma: no cover
        return 0


def walk(node: Any) -> Iterator[Any]:
    """Recorrido en preorden de todo el subarbol."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def walk_scoped(node: Any, stop_types: frozenset[str] = FUNCTION_TYPES) -> Iterator[Any]:
    """Recorrido que no desciende a funciones anidadas.

    Permite analizar el cuerpo de una funcion sin mezclar el estado de las
    funciones que declara en su interior (que se analizan por separado).
    """
    stack = list(reversed(node.children))
    while stack:
        current = stack.pop()
        yield current
        if current.type in stop_types:
            continue
        stack.extend(reversed(current.children))


def find_all(node: Any, types: frozenset[str] | set[str]) -> list[Any]:
    return [n for n in walk(node) if n.type in types]


def field(node: Any, name: str) -> Any | None:
    try:
        return node.child_by_field_name(name)
    except Exception:  # pragma: no cover
        return None


def node_key(node: Any) -> tuple[int, int, str]:
    """Identificador estable de un nodo dentro de un mismo arbol."""
    return (node.start_byte, node.end_byte, node.type)
