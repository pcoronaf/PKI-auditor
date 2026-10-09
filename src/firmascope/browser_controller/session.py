"""Sesion autenticada del operador en el portal auditado.

Muchos portales de firma exigen iniciar sesion antes de llegar al formulario.
Hacerlo dentro del navegador auditado tiene dos problemas: la contrasena de la
cuenta pasa por la instrumentacion, y las cookies resultantes no las conoce el
vault, asi que nada impide que acaben en el expediente.

Por eso el inicio de sesion va aparte (``firmascope login``, o el boton de la
interfaz grafica): un navegador limpio y sin instrumentar, en el que el
operador inicia sesion a mano. FirmaScope nunca ve la contrasena; guarda solo
el estado resultante --cookies y almacenamiento local-- para que la auditoria
arranque ya dentro (``firmascope audit --session``).

Ese fichero es una credencial: mientras la sesion siga activa en el portal,
permite entrar en la cuenta. Por eso:

* se escribe con permisos 0600 desde el primer byte;
* sus valores se protegen en el vault antes de que arranque el navegador
  auditado, de modo que la redaccion y la barrera final les impiden llegar al
  expediente;
* el manifiesto solo registra que la sesion estaba autenticada, nunca la ruta
  ni el contenido.

Portado del PR #2, sobre el arranque comun de :mod:`.launch`.
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
    path = Path(path).expanduser()
    if not path.is_file():
        raise SessionStateError(f"no existe el fichero de sesion: {path}")
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SessionStateError(f"el fichero de sesion no es JSON valido: {exc}") from exc
    if not isinstance(state, dict) or not isinstance(state.get("cookies", []), list) \
            or not isinstance(state.get("origins", []), list):
        raise SessionStateError("el fichero no parece una sesion guardada por FirmaScope")
    state.setdefault("cookies", [])
    state.setdefault("origins", [])
    return state


def session_secrets(state: dict[str, Any]) -> list[str]:
    """Valores del estado que no deben llegar nunca a disco.

    Todas las cookies, y los valores del almacenamiento local, donde muchas
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


def default_session_path(url: str) -> Path:
    """Donde guardar la sesion si el operador no dice otra cosa.

    En el directorio personal y no en el de trabajo: el de trabajo suele ser
    un repositorio, y un ``git add .`` publicaria la sesion.
    """
    from urllib.parse import urlsplit

    host = urlsplit(url if "://" in url else f"https://{url}").hostname or "portal"
    safe = "".join(c if c.isalnum() or c in "-." else "_" for c in host)
    return Path.home() / ".firmascope" / "sesiones" / f"{safe}.json"


def write_session_state(state: dict[str, Any], path: Path | str) -> Path:
    """Escribe el estado con permisos 0600 desde el primer byte.

    Crear el fichero y despues restringirlo dejaria un instante en que otro
    usuario del equipo podria leer la sesion.
    """
    path = Path(path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    try:
        # O_CREAT no cambia los permisos de un fichero que ya existia.
        path.chmod(0o600)
    except OSError:  # pragma: no cover - sistemas sin permisos POSIX
        pass
    return path


class LoginCapture:
    """Navegador limpio en el que el operador inicia sesion a mano.

    Dos pasos, para que cada interfaz espere a su manera: la CLI con Enter, la
    interfaz grafica con un boton (el puente atiende un comando por vez y no
    puede bloquearse esperando a la persona).
    """

    def __init__(self, url: str, *, headless: bool = False,
                 browser_path: str | None = None,
                 browser_args: list[str] | None = None,
                 sandbox: bool | None = None):
        from ..audit_core.config import default_chromium_path

        self.url = url
        self.headless = headless
        # El mismo Chromium que la auditoria: una sesion iniciada en otro
        # navegador podria no ser valida en este.
        self.browser_path = browser_path or default_chromium_path()
        self.browser_args = list(browser_args or [])
        self.sandbox = sandbox
        self.page: Any = None
        self._playwright: Any = None
        self._browser: Any = None
        self._context: Any = None

    @property
    def open(self) -> bool:
        return self._browser is not None

    def start(self) -> "LoginCapture":
        from playwright.sync_api import sync_playwright

        from .launch import launch_chromium

        self._playwright = sync_playwright().start()
        try:
            self._browser = launch_chromium(
                self._playwright, headless=self.headless,
                executable_path=self.browser_path, args=self.browser_args,
                sandbox=self.sandbox)
            # Contexto efimero y sin instrumentar: aqui se escribe la
            # contrasena de la cuenta, y no tiene nada que auditar.
            self._context = self._browser.new_context()
            self.page = self._context.new_page()
            self.page.goto(self.url)
        except Exception:
            self.close()
            raise
        return self

    def save(self, path: Path | str) -> dict[str, Any]:
        """Guarda el estado actual, cierra el navegador y devuelve el resumen."""
        if self._context is None:
            raise RuntimeError("no hay un inicio de sesion en curso")
        try:
            state = self._context.storage_state()
        finally:
            self.close()
        write_session_state(state, path)
        return describe_session(state)

    def close(self) -> None:
        for step in (getattr(self._browser, "close", None),
                     getattr(self._playwright, "stop", None)):
            if step is None:
                continue
            try:
                step()
            except Exception:  # pragma: no cover - el cierre no debe fallar
                pass
        self._browser = self._context = self._playwright = self.page = None


def capture_session(url: str, path: Path | str,
                    wait_for_operator: Callable[[Any], None], **kwargs: Any) -> dict[str, Any]:
    """Abre ``url``, espera a que el operador inicie sesion y guarda el estado.

    ``wait_for_operator(page)`` vuelve cuando el operador termino: la CLI
    espera Enter; las pruebas inician sesion por programa.
    """
    capture = LoginCapture(url, **kwargs).start()
    try:
        wait_for_operator(capture.page)
    except BaseException:
        capture.close()
        raise
    return capture.save(path)
