"""Sesion autenticada del operador en la plataforma auditada.

Muchas plataformas de firma exigen iniciar sesion antes de llegar al
formulario. FirmaScope no pide ni guarda esa contrasena: el operador inicia
sesion a mano en un navegador visible (``firmascope login``) y la herramienta
guarda solo el estado resultante — cookies y almacenamiento local — para que
la auditoria arranque ya dentro (``firmascope audit --session``).

Ese fichero es una credencial: mientras la sesion siga activa en la
plataforma, permite entrar en la cuenta. Por eso:

* se escribe con permisos 0600;
* sus valores se registran en el vault como protegidos, de modo que la
  redaccion y la barrera final impiden que lleguen al expediente;
* nunca se copia al expediente; el manifiesto solo registra que la sesion
  estaba autenticada.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable


class SessionStateError(ValueError):
    """El fichero de sesion no existe o no tiene el formato esperado."""


def load_session_state(path: Path | str) -> dict[str, Any]:
    """Lee y valida un fichero de sesion de Playwright (``storage_state``)."""
    path = Path(path)
    if not path.is_file():
        raise SessionStateError(f"no existe el fichero de sesion: {path}")
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SessionStateError(f"el fichero de sesion no es JSON valido: {exc}") from exc
    if not isinstance(state, dict) or not isinstance(state.get("cookies", []), list) \
            or not isinstance(state.get("origins", []), list):
        raise SessionStateError("el fichero no parece un estado de sesion de FirmaScope")
    state.setdefault("cookies", [])
    state.setdefault("origins", [])
    return state


def session_secrets(state: dict[str, Any]) -> list[str]:
    """Valores del estado que no deben llegar nunca al disco.

    Todas las cookies, y los valores de almacenamiento local, donde muchas
    aplicaciones guardan su token de acceso.
    """
    values: list[str] = []
    for cookie in state.get("cookies", []):
        value = str(cookie.get("value", "")) if isinstance(cookie, dict) else ""
        if value:
            values.append(value)
    for origin in state.get("origins", []):
        if not isinstance(origin, dict):
            continue
        for item in origin.get("localStorage", []) or []:
            value = str(item.get("value", "")) if isinstance(item, dict) else ""
            if value:
                values.append(value)
    return values


def describe_session(state: dict[str, Any]) -> dict[str, Any]:
    """Resumen publicable: cuantas cookies y de que dominios. Sin valores."""
    domains = sorted({str(c.get("domain", "")).lstrip(".")
                      for c in state.get("cookies", []) if isinstance(c, dict)})
    origins = sorted(str(o.get("origin", "")) for o in state.get("origins", [])
                     if isinstance(o, dict))
    return {"cookies": len(state.get("cookies", [])), "cookie_domains": domains,
            "storage_origins": origins}


def write_session_state(state: dict[str, Any], path: Path | str) -> Path:
    """Escribe el estado con permisos 0600 desde el primer byte."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    try:
        path.chmod(0o600)
    except OSError:  # pragma: no cover - sistemas sin permisos POSIX
        pass
    return path


def capture_session(url: str, path: Path | str,
                    wait_for_operator: Callable[[Any], None],
                    headless: bool = False,
                    browser_path: str | None = None,
                    browser_args: list[str] | None = None,
                    sandbox: bool | None = None) -> dict[str, Any]:
    """Abre ``url``, espera a que el operador inicie sesion y guarda el estado.

    ``wait_for_operator(page)`` vuelve cuando el operador termino. La CLI
    espera a que pulse Enter; las pruebas inician sesion por programa. La
    contrasena de la plataforma la escribe el operador en el navegador: esta
    funcion nunca la ve.
    """
    from playwright.sync_api import sync_playwright

    from .launch import launch_chromium

    with sync_playwright() as playwright:
        browser = launch_chromium(playwright, headless=headless, executable_path=browser_path,
                                  args=browser_args or (), sandbox=sandbox)
        try:
            context = browser.new_context()
            page = context.new_page()
            page.goto(url)
            wait_for_operator(page)
            state = context.storage_state()
        finally:
            browser.close()
    write_session_state(state, path)
    return describe_session(state)
