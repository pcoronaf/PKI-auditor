"""Cabeceras aptas para el expediente.

Las credenciales de sesion -- ``Authorization``, ``Cookie``, ``Set-Cookie`` --
no son evidencia de nada que FirmaScope audite, y en un portal real son las del
operador: escribirlas en el expediente dejaria en disco con que suplantarle.
Se conserva que estaban y cuanto median, que es lo unico util.

CDP y el proxy usaban cada uno su propio recorte, y solo el del proxy omitia
estas cabeceras. Ahora comparten esta funcion para no volver a divergir.
"""

from __future__ import annotations

from typing import Any

SENSITIVE_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-csrf-token", "x-xsrf-token", "x-api-key",
})

MAX_HEADERS = 40
MAX_VALUE = 256


def clip_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    """Cabeceras recortadas y sin credenciales de sesion."""
    out: dict[str, str] = {}
    for name, value in list((headers or {}).items())[:MAX_HEADERS]:
        text = str(value)
        key = str(name)[:64]
        if key.lower() in SENSITIVE_HEADERS:
            out[key] = f"<{len(text)} bytes omitidos>"
            continue
        out[key] = text[:MAX_VALUE]
    return out
