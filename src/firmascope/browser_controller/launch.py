"""Arranque de Chromium: un unico punto, con el sandbox activado.

Playwright desactiva el sandbox de Chromium por defecto: salvo que se le pida
``chromium_sandbox=True`` de forma explicita, anade ``--no-sandbox`` siempre.
En un contenedor que corre como root no queda otra, porque Chromium se niega a
arrancar con sandbox. Pero en el equipo del operador desactivarlo quita el
aislamiento entre el sistema y el sitio auditado, justo mientras se carga un
sitio de internet.

Por eso todo arranque pasa por aqui: sandbox activado salvo como root o por
decision explicita del operador (``--no-sandbox``), y los errores de arranque
traducidos a lo que hay que hacer para resolverlos.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Iterable


class BrowserLaunchError(RuntimeError):
    """Chromium no pudo arrancar; el mensaje dice que hacer."""


def sandbox_by_default() -> bool:
    """El sandbox se usa siempre, salvo al ejecutar como root."""
    geteuid = getattr(os, "geteuid", None)
    return not (geteuid is not None and geteuid() == 0)


def launch_chromium(playwright: Any, *, headless: bool, executable_path: str | None = None,
                    args: Iterable[str] = (), proxy: dict[str, str] | None = None,
                    sandbox: bool | None = None) -> Any:
    """Arranca Chromium con el sandbox que corresponde."""
    use_sandbox = sandbox_by_default() if sandbox is None else sandbox
    kwargs: dict[str, Any] = {
        "headless": headless,
        # --no-sandbox nunca se cuela por los argumentos: lo decide
        # chromium_sandbox, en un solo sitio.
        "args": [a for a in args if a != "--no-sandbox"],
        "chromium_sandbox": use_sandbox,
    }
    if executable_path:
        kwargs["executable_path"] = executable_path
    if proxy:
        kwargs["proxy"] = proxy
    try:
        return playwright.chromium.launch(**kwargs)
    except Exception as exc:
        raise BrowserLaunchError(explain_launch_failure(str(exc), headless)) from exc


def explain_launch_failure(message: str, headless: bool = True) -> str:
    """Traduce el error de Playwright a lo que el operador tiene que hacer."""
    lowered = message.lower()
    venv_bin = Path(sys.executable).parent

    if "error while loading shared libraries" in lowered or "missing dependencies" in lowered:
        return ("A Chromium le faltan bibliotecas del sistema. En Linux o WSL, instalalas con:\n"
                f"    sudo {venv_bin / 'playwright'} install-deps chromium\n"
                "y vuelve a intentarlo.")
    if "executable doesn't exist" in lowered or "please run the following command" in lowered:
        return ("No hay un Chromium instalado para Playwright. Instalalo con:\n"
                "    playwright install chromium")
    if "no usable sandbox" in lowered or ("sandbox" in lowered and "namespace" in lowered):
        return ("Chromium no puede activar su sandbox en este sistema. Si confias en el "
                "entorno, repite con --no-sandbox (menos seguro: el sitio auditado queda "
                "menos aislado del sistema).")
    if not headless and ("x server" in lowered or "$display" in lowered or "wayland" in lowered):
        return ("No hay una pantalla donde abrir el navegador. En WSL hace falta WSLg "
                "(Windows 11); si no lo tienes, ejecuta FirmaScope directamente en Windows.")
    first = next((line for line in message.splitlines() if line.strip()), message)
    return f"Chromium no pudo arrancar: {first.strip()}"
