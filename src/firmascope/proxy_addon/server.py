"""Ciclo de vida del proxy de interceptacion.

mitmproxy corre en un hilo propio con su propio bucle asyncio; el navegador
se configura para salir a traves de el. Dos garantias importan:

* **CA efimera.** El directorio de configuracion de mitmproxy — donde vive la
  autoridad certificadora que firma los certificados interceptados — se crea
  en un directorio temporal por sesion y se borra al detener el proxy. La CA
  nunca se instala en el almacen del sistema: el navegador de auditoria la
  acepta porque su contexto se abre con ``ignore_https_errors``, y ese
  contexto muere con la sesion.
* **Degradacion explicita.** Si mitmproxy no esta instalado, el nivel 4 sigue
  funcionando con tres sensores en lugar de cuatro, y el manifiesto lo dice.
  Nunca se finge un sensor que no corrio.
"""

from __future__ import annotations

import asyncio
import shutil
import socket
import tempfile
import threading
import time
from typing import Any

from .addon import FirmaScopeAddon

#: Segundos maximos esperando a que el proxy acepte conexiones.
STARTUP_TIMEOUT = 15.0


def available() -> bool:
    """True si mitmproxy esta instalado en este entorno."""
    try:
        import mitmproxy.tools.dump  # noqa: F401
    except Exception:
        return False
    return True


def free_port(host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


class ProxyUnavailable(RuntimeError):
    """mitmproxy no esta instalado o no pudo arrancar."""


class ProxyServer:
    """mitmproxy en segundo plano, con el addon de FirmaScope cargado."""

    def __init__(self, addon: FirmaScopeAddon, host: str = "127.0.0.1", port: int = 0):
        self.addon = addon
        self.host = host
        self.port = port or free_port(host)
        self.confdir: str | None = None
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._master: Any | None = None
        self._ready = threading.Event()
        self._error: BaseException | None = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    # ------------------------------------------------------------------
    def start(self) -> "ProxyServer":
        if not available():
            raise ProxyUnavailable(
                "mitmproxy no esta instalado; instala el extra: pip install 'firmascope[proxy]'")
        self.confdir = tempfile.mkdtemp(prefix="firmascope-ca-")
        self._thread = threading.Thread(target=self._run, name="firmascope-proxy", daemon=True)
        self._thread.start()

        if not self._ready.wait(STARTUP_TIMEOUT):
            self.stop()
            raise ProxyUnavailable("el proxy no arranco a tiempo")
        if self._error is not None:
            self.stop()
            raise ProxyUnavailable(f"el proxy fallo al arrancar: {self._error}")
        self._wait_listening()
        return self

    def _run(self) -> None:
        from mitmproxy import options
        from mitmproxy.tools.dump import DumpMaster

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop

        async def main() -> None:
            opts = options.Options(
                listen_host=self.host,
                listen_port=self.port,
                confdir=self.confdir,
            )
            # El master exige un bucle en marcha: por eso se crea aqui dentro.
            master = DumpMaster(opts, with_termlog=False, with_dumper=False)
            master.addons.add(self.addon)
            self._master = master
            self._ready.set()
            await master.run()

        try:
            loop.run_until_complete(main())
        except BaseException as exc:  # pragma: no cover - fallo de arranque
            self._error = exc
            self._ready.set()
        finally:
            # mitmproxy deja vigilantes de conexion en marcha al apagarse;
            # se cancelan y se esperan para que el bucle cierre limpio.
            try:
                pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                loop.close()
            except Exception:  # pragma: no cover
                pass

    def _wait_listening(self) -> None:
        deadline = time.monotonic() + STARTUP_TIMEOUT
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((self.host, self.port), timeout=0.5):
                    return
            except OSError:
                time.sleep(0.1)
        self.stop()
        raise ProxyUnavailable(f"el proxy no acepta conexiones en {self.url}")

    # ------------------------------------------------------------------
    def stop(self) -> None:
        """Detiene el proxy y destruye la CA efimera."""
        if self._master is not None and self._loop is not None and not self._loop.is_closed():
            try:
                self._loop.call_soon_threadsafe(self._master.shutdown)
            except RuntimeError:  # pragma: no cover - bucle ya cerrado
                pass
        if self._thread is not None:
            self._thread.join(timeout=10)
        self._master = None
        if self.confdir:
            # La clave privada de la CA vive aqui. Que desaparezca con la
            # sesion es la mitad de la promesa de "CA efimera".
            shutil.rmtree(self.confdir, ignore_errors=True)
            self.confdir = None

    def __enter__(self) -> "ProxyServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
