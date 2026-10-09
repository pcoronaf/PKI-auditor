"""Arranque y parada del proxy de interceptacion dentro del proceso.

mitmproxy se ejecuta en su propio bucle de asyncio, en un hilo de fondo, para
que el addon pueda consultar el vault sin que las representaciones de la
credencial salgan nunca de la memoria del proceso.

La CA es **efimera**: vive en un directorio temporal que se borra al cerrar la
sesion. FirmaScope no instala certificados en el almacen del sistema, porque una
CA de auditoria que sobrevive a la auditoria es una puerta abierta: cualquiera
que obtenga su clave privada puede suplantar cualquier sitio para ese usuario.
El navegador acepta esta CA solo porque el contexto de Playwright se abre con
``ignore_https_errors``, y ese contexto muere con la sesion.
"""

from __future__ import annotations

import asyncio
import shutil
import socket
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable

from ..audit_core.config import AuditConfig
from ..audit_core.events import Event, EventType
from ..audit_core.secrets import SecretVault
from ..evidence_store.store import EvidenceStore, RequestRecord
from ..network_analyzer import domains
from .addon import FirmaScopeAddon


def available() -> bool:
    """``True`` si mitmproxy esta instalado."""
    try:
        import mitmproxy  # noqa: F401
    except Exception:
        return False
    return True


def version() -> str:
    try:
        from mitmproxy import version as mitm_version
        return str(mitm_version.VERSION)
    except Exception:
        return ""


def free_port(host: str = "127.0.0.1") -> int:
    """Reserva un puerto libre.

    Se elige aqui y no se deja en 0 porque el navegador necesita la direccion
    del proxy *antes* de arrancar, y preguntarsela a mitmproxy despues
    obligaria a esperar a que su servidor estuviera escuchando.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


class ProxyRunner:
    """Ciclo de vida del proxy y volcado de lo observado al expediente."""

    def __init__(self, config: AuditConfig, session_id: str, store: EvidenceStore,
                 emit: Callable[[Event], None], vault: SecretVault | None = None):
        self.config = config
        self.session_id = session_id
        self.store = store
        self.emit = emit
        self.vault = vault

        self.addon = FirmaScopeAddon(
            vault=vault,
            capture_bodies=config.proxy.capture_bodies,
            max_body_bytes=config.max_body_bytes,
        )
        self.host = config.proxy.host
        self.port = config.proxy.port or 0
        self.running = False
        self.error = ""
        self._master: Any = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._confdir: Path | None = None
        self._owns_confdir = False
        #: id de observacion -> id del registro escrito en el expediente.
        self._records: dict[str, str] = {}
        self.request_count = 0

    # ------------------------------------------------------------------
    @property
    def server(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self, timeout: float = 20.0) -> bool:
        """Arranca el proxy. Devuelve ``False`` y deja ``error`` si no pudo."""
        if not available():
            self.error = ("mitmproxy no esta instalado. Instalelo con "
                          "`pip install 'firmascope[proxy]'` o baje a nivel 3.")
            return False

        from mitmproxy.options import Options
        from mitmproxy.tools.dump import DumpMaster

        if not self.port:
            self.port = free_port(self.host)
        if self.config.proxy.confdir:
            self._confdir = Path(self.config.proxy.confdir)
            self._confdir.mkdir(parents=True, exist_ok=True)
        else:
            self._confdir = Path(tempfile.mkdtemp(prefix="firmascope-ca-"))
            self._owns_confdir = True

        ready = threading.Event()

        async def serve() -> None:
            # DumpMaster construye primitivas de asyncio, asi que debe crearse
            # con el bucle ya en marcha y no antes de arrancarlo.
            options = Options(
                listen_host=self.host,
                listen_port=self.port,
                confdir=str(self._confdir),
                # El proxy observa; no valida la cadena del sitio. Un
                # certificado caducado del portal no debe interrumpir la
                # auditoria: queda registrado y la sesion continua.
                ssl_insecure=True,
            )
            master = DumpMaster(options, with_termlog=False, with_dumper=False)
            master.addons.add(self.addon)
            self._master = master
            ready.set()
            await master.run()

        def run() -> None:
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                self._loop = loop
                loop.run_until_complete(serve())
            except Exception as exc:  # pragma: no cover - depende del entorno
                self.error = f"{type(exc).__name__}: {exc}"
                ready.set()
            finally:
                self.running = False

        self._thread = threading.Thread(target=run, name="firmascope-proxy", daemon=True)
        self._thread.start()
        if not ready.wait(timeout) or self.error:
            self.error = self.error or "el proxy no arranco en el tiempo previsto"
            self.stop()
            return False

        if not self._wait_listening(timeout):
            self.error = f"el proxy no acepta conexiones en {self.server}"
            self.stop()
            return False
        if not self._wait_ca(timeout):
            self.error = f"el proxy no genero su CA en {self._confdir}"
            self.stop()
            return False

        self.running = True
        self.emit(Event(EventType.CHECKPOINT, self.session_id, sensor="proxy",
                        data={"name": "proxy-start", "server": self.server,
                              "mitmproxy": version(),
                              "ephemeral_ca": self._owns_confdir,
                              "ca_dir": str(self._confdir),
                              "capture_bodies": self.config.proxy.capture_bodies}))
        return True

    def _wait_listening(self, timeout: float) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.error:
                return False
            try:
                with socket.create_connection((self.host, self.port), timeout=0.5):
                    return True
            except OSError:
                time.sleep(0.1)
        return False

    def _wait_ca(self, timeout: float) -> bool:
        """Espera a que mitmproxy haya escrito su CA.

        mitmproxy la genera en su hook ``running``, a la vez que empieza a
        escuchar: ver el puerto abierto no basta. Una conexion TLS que llegue
        antes no podria interceptarse, y su contenido quedaria sin observar
        sin que nada lo dijera.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.error:
                return False
            if self._confdir is not None and any(self._confdir.glob("*-ca.pem")):
                return True
            time.sleep(0.05)
        return False

    # ------------------------------------------------------------------
    def pump(self) -> int:
        """Escribe en el expediente lo que el proxy haya observado.

        Se llama desde el hilo principal: es el unico que escribe, de modo que
        la cadena de hashes conserva un orden unico y verificable.
        """
        observations, updates = self.addon.drain()
        for observation in observations:
            self._write(observation)
        for update in updates:
            record_id = self._records.get(update.observation_id)
            if record_id and update.status is not None:
                self.store.update_request(record_id, status=update.status)
        return len(observations)

    def _write(self, observation) -> None:
        host = observation.host or domains.host_of(observation.url)
        body_ref = ""
        if observation.body:
            record = self.store.add_evidence(
                "proxy-body", f"{observation.method}-{host}", observation.body)
            body_ref = record["path"]

        record = RequestRecord(
            timestamp=observation.timestamp,
            method=observation.method,
            url=observation.url,
            host=host,
            registrable=domains.registrable_domain(host),
            third_party=domains.is_third_party(
                observation.url, self.config.target, self.config.first_party_domains),
            resource_type="",
            initiator="proxy",
            headers=observation.headers,
            body_size=observation.body_size,
            body_digest=observation.body_digest,
            body_ref=body_ref,
            tags=list(observation.tags),
            sensor="proxy",
        )
        self.store.add_request(record)
        self._records[observation.id] = record.id
        self.request_count += 1

        data: dict[str, Any] = {
            "url": observation.url,
            "host": host,
            "method": observation.method,
            "third_party": record.third_party,
            "third_party_name": domains.third_party_name(observation.url),
            "body_size": observation.body_size,
            "body_digest": observation.body_digest,
            "content_type": observation.content_type,
            "tls": observation.tls,
            "request_id": record.id,
        }
        if observation.canary_matches:
            data["canary_matches"] = observation.canary_matches
        if observation.body_recovered:
            # Es el aporte propio de este sensor: un cuerpo que CDP no entrega.
            data["body_recovered_by_proxy"] = True
        self.emit(Event(EventType.NETWORK_REQUEST, self.session_id,
                        timestamp=observation.timestamp, sensor="proxy",
                        origin=host, tags=list(observation.tags), data=data))

    # ------------------------------------------------------------------
    def summary(self) -> dict[str, Any]:
        info = {
            "enabled": True,
            "running": self.running,
            "server": self.server,
            "mitmproxy": version(),
            "ephemeral_ca": self._owns_confdir,
            "requests_written": self.request_count,
            **self.addon.summary(),
        }
        if self.error:
            info["error"] = self.error
        return info

    def stop(self) -> None:
        """Para el proxy y destruye la CA efimera. Idempotente."""
        self.pump() if self.running else None
        master, loop = self._master, self._loop
        if master is not None and loop is not None and loop.is_running():
            try:
                loop.call_soon_threadsafe(master.shutdown)
            except Exception:  # pragma: no cover
                pass
        if self._thread is not None:
            self._thread.join(timeout=10)
        self.running = False
        self._master = None
        self._loop = None

        if self._owns_confdir and self._confdir is not None:
            # La clave privada de la CA no sobrevive a la sesion que la creo.
            shutil.rmtree(self._confdir, ignore_errors=True)
            self._confdir = None
