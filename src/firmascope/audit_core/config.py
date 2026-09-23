"""Configuracion de una sesion de auditoria."""

from __future__ import annotations

import enum
import os
import platform
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


class AuditLevel(enum.IntEnum):
    """Niveles del modelo de auditoria por capas."""

    NETWORK_OBSERVER = 1     # DevTools Network automatizado y reproducible
    CODE_ANALYZER = 2        # analisis estatico + instrumentacion dinamica
    LOCAL_SIGNING_TEST = 3   # prueba de firma con red aislada
    FULL_CORRELATED = 4      # todo lo anterior + proxy + correlacion

    @classmethod
    def parse(cls, value: str | int) -> "AuditLevel":
        if isinstance(value, int):
            return cls(value)
        text = str(value).strip().lower()
        aliases = {
            "1": cls.NETWORK_OBSERVER, "network": cls.NETWORK_OBSERVER,
            "network-only": cls.NETWORK_OBSERVER, "l1": cls.NETWORK_OBSERVER,
            "2": cls.CODE_ANALYZER, "code": cls.CODE_ANALYZER, "l2": cls.CODE_ANALYZER,
            "3": cls.LOCAL_SIGNING_TEST, "offline": cls.LOCAL_SIGNING_TEST,
            "local": cls.LOCAL_SIGNING_TEST, "l3": cls.LOCAL_SIGNING_TEST,
            "4": cls.FULL_CORRELATED, "full": cls.FULL_CORRELATED,
            "complete": cls.FULL_CORRELATED, "l4": cls.FULL_CORRELATED,
        }
        if text not in aliases:
            raise ValueError(f"nivel de auditoria desconocido: {value!r}")
        return aliases[text]


class CredentialMode(str, enum.Enum):
    """Que credenciales se ofrecen al sitio auditado."""

    SYNTHETIC = "synthetic"   # credenciales de laboratorio generadas por FirmaScope
    OWN_TEST = "own-test"     # credenciales de prueba aportadas por el operador
    NONE = "none"             # el operador introduce todo manualmente


def default_chromium_path() -> str | None:
    """Localiza un Chromium utilizable sin descargar nada.

    Orden: variable de entorno, instalacion de Playwright presente en el
    sistema, y finalmente ``None`` para dejar que Playwright decida.
    """

    env = os.environ.get("FIRMASCOPE_CHROMIUM_PATH")
    if env and Path(env).exists():
        return env
    roots = [os.environ.get("PLAYWRIGHT_BROWSERS_PATH"), "/opt/pw-browsers"]
    candidates: list[Path] = []
    for root in roots:
        if not root:
            continue
        base = Path(root)
        if not base.is_dir():
            continue
        for pattern in ("chromium-*/chrome-linux/chrome",
                        "chromium-*/chrome-linux64/chrome",
                        "chromium-*/chrome-win/chrome.exe",
                        "chromium-*/chrome-mac/Chromium.app/Contents/MacOS/Chromium"):
            candidates.extend(base.glob(pattern))
    if not candidates:
        return None
    # La revision mas alta suele ser la mas reciente.
    def revision(p: Path) -> int:
        for part in p.parts:
            if part.startswith("chromium-") and part[9:].isdigit():
                return int(part[9:])
        return 0
    return str(sorted(candidates, key=revision)[-1])


@dataclass
class ProxyConfig:
    """Configuracion del proxy de interceptacion (nivel 4)."""

    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 0                 # 0 = puerto libre elegido en tiempo de ejecucion
    #: CA efimera: FirmaScope no instala certificados permanentes en el sistema.
    ephemeral_ca: bool = True
    #: Captura de cuerpos completos. Desactivada por defecto (proteccion de secretos).
    capture_bodies: bool = False
    confdir: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditConfig:
    """Parametros completos de una sesion, replicados en ``manifest.json``."""

    target: str
    level: AuditLevel = AuditLevel.FULL_CORRELATED
    output_dir: Path = Path("audits")
    headless: bool = True
    browser_path: str | None = field(default_factory=default_chromium_path)
    browser_args: list[str] = field(default_factory=list)
    #: Sandbox de Chromium. None = activado salvo al ejecutar como root
    #: (ver browser_controller.launch); False solo por decision explicita.
    sandbox: bool | None = None
    viewport: tuple[int, int] = (1280, 900)
    #: Segundos maximos de sesion interactiva antes de cerrar automaticamente.
    max_duration: float = 900.0
    #: Captura completa de cuerpos HTTP. Desactivada por defecto.
    capture_bodies: bool = False
    #: Bytes maximos por cuerpo cuando ``capture_bodies`` esta activo.
    max_body_bytes: int = 64 * 1024
    credential_mode: CredentialMode = CredentialMode.SYNTHETIC
    #: Directorios adicionales con paquetes de reglas YAML.
    rules_dirs: list[Path] = field(default_factory=list)
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    #: Captura de pantalla en cada hito relevante.
    screenshots: bool = True
    #: Dominios considerados "propios" ademas del dominio del objetivo.
    first_party_domains: list[str] = field(default_factory=list)
    #: Ventana temporal (ms) para correlacionar egress con acceso a la clave.
    correlation_window_ms: int = 5000
    #: Etiqueta libre del operador para identificar la prueba.
    note: str = ""
    #: Estado de una sesion autenticada (``firmascope login``). Es una
    #: credencial: nunca se copia al expediente.
    session_state: Path | None = None
    #: El operador conduce la firma a mano; FirmaScope espera y observa.
    manual: bool = False

    def __post_init__(self) -> None:
        self.output_dir = Path(self.output_dir)
        self.level = AuditLevel(self.level)
        self.rules_dirs = [Path(p) for p in self.rules_dirs]
        if self.session_state is not None:
            self.session_state = Path(self.session_state)
        if self.manual:
            # Conducir la sesion a mano exige ver el navegador.
            self.headless = False
        if self.level >= AuditLevel.FULL_CORRELATED and self.proxy.port == 0:
            self.proxy.enabled = self.proxy.enabled or False

    # -- capacidades derivadas del nivel --------------------------------
    @property
    def network_observation(self) -> bool:
        return True

    @property
    def instrumentation(self) -> bool:
        return self.level >= AuditLevel.CODE_ANALYZER

    @property
    def static_analysis(self) -> bool:
        return self.level >= AuditLevel.CODE_ANALYZER

    @property
    def offline_test(self) -> bool:
        return self.level >= AuditLevel.LOCAL_SIGNING_TEST

    @property
    def proxy_enabled(self) -> bool:
        return self.proxy.enabled and self.level >= AuditLevel.FULL_CORRELATED

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "level": int(self.level),
            "level_name": self.level.name,
            "headless": self.headless,
            "browser_path": self.browser_path,
            "browser_args": list(self.browser_args),
            "sandbox": self.sandbox,
            "capture_bodies": self.capture_bodies,
            "max_body_bytes": self.max_body_bytes,
            "credential_mode": self.credential_mode.value,
            "screenshots": self.screenshots,
            "first_party_domains": list(self.first_party_domains),
            "correlation_window_ms": self.correlation_window_ms,
            "proxy": self.proxy.to_dict(),
            "note": self.note,
            # Solo el hecho, nunca la ruta ni el contenido del fichero.
            "authenticated_session": self.session_state is not None,
            "manual": self.manual,
            "capabilities": {
                "network_observation": self.network_observation,
                "instrumentation": self.instrumentation,
                "static_analysis": self.static_analysis,
                "offline_test": self.offline_test,
                "proxy": self.proxy_enabled,
            },
        }


def environment_info() -> dict[str, Any]:
    """Datos del entorno para reproducibilidad (NFR-002)."""
    return {
        "os": f"{platform.system()} {platform.release()}",
        "os_detail": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
    }
