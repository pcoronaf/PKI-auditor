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
    #: e.firma real del operador. Requiere consentimiento explicito y activa el
    #: endurecimiento de :class:`PrivacyPolicy`.
    REAL = "real"
    NONE = "none"             # el operador introduce todo manualmente

    @classmethod
    def parse(cls, value: str) -> "CredentialMode":
        text = str(value).strip().lower()
        aliases = {
            "synthetic": cls.SYNTHETIC, "sintetica": cls.SYNTHETIC,
            "sintetico": cls.SYNTHETIC, "test": cls.SYNTHETIC, "lab": cls.SYNTHETIC,
            "own-test": cls.OWN_TEST, "own": cls.OWN_TEST, "propia": cls.OWN_TEST,
            "prueba": cls.OWN_TEST,
            "real": cls.REAL, "efirma": cls.REAL, "e.firma": cls.REAL,
            "produccion": cls.REAL, "production": cls.REAL,
            "none": cls.NONE, "manual": cls.NONE, "ninguna": cls.NONE,
        }
        if text not in aliases:
            raise ValueError(f"modo de credencial desconocido: {value!r}")
        return aliases[text]

    @property
    def is_real(self) -> bool:
        return self is CredentialMode.REAL


class IsolationMode(str, enum.Enum):
    """Alcance del aislamiento de red durante la prueba de firma local."""

    NONE = "none"                  # sin aislamiento
    FULL = "full"                  # se bloquea toda salida
    THIRD_PARTY = "third-party"    # solo se bloquean los terceros
    ALLOWLIST = "allowlist"        # se bloquea todo salvo los hosts permitidos

    @classmethod
    def parse(cls, value: str) -> "IsolationMode":
        text = str(value).strip().lower()
        aliases = {
            "none": cls.NONE, "off": cls.NONE, "ninguno": cls.NONE,
            "full": cls.FULL, "all": cls.FULL, "total": cls.FULL,
            "third-party": cls.THIRD_PARTY, "thirdparty": cls.THIRD_PARTY,
            "terceros": cls.THIRD_PARTY,
            "allowlist": cls.ALLOWLIST, "allow": cls.ALLOWLIST, "lista": cls.ALLOWLIST,
        }
        if text not in aliases:
            raise ValueError(f"modo de aislamiento desconocido: {value!r}")
        return aliases[text]


@dataclass
class IsolationPolicy:
    """Como se corta la red sin romper la pagina ya cargada.

    El aislamiento se implementa interceptando y abortando peticiones nuevas,
    no apagando la pila de red del navegador. La diferencia es importante:

    * la pagina ya cargada sigue viva y puede completar la firma;
    * cada intento de salida bloqueado queda registrado como evidencia, en
      lugar de desaparecer;
    * el aislamiento puede ser granular (solo terceros, o con lista de
      excepciones) en lugar de todo o nada.
    """

    mode: IsolationMode = IsolationMode.FULL
    #: Hosts alcanzables aun durante el aislamiento (modo ``allowlist``).
    allow_hosts: list[str] = field(default_factory=list)
    #: Emular ``navigator.onLine == false`` y disparar el evento ``offline``.
    #: Fiel a un corte real, pero algunas aplicaciones se niegan a operar sin
    #: conexion: desactivelo si el sitio bloquea la firma por ese motivo.
    emulate_offline_flag: bool = True
    #: Esperar a que la red se calme antes de aislar, para que todos los
    #: recursos esten ya en cache. Es lo que evita la pagina en blanco.
    preload_before_isolating: bool = True
    #: Segundos de espera de inactividad de red durante la precarga.
    preload_timeout: float = 15.0
    #: Leer el cuerpo de los intentos bloqueados para buscar canarios en ellos.
    #: Un intento de exfiltracion bloqueado es evidencia de primer orden.
    inspect_blocked_bodies: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "allow_hosts": list(self.allow_hosts),
            "emulate_offline_flag": self.emulate_offline_flag,
            "preload_before_isolating": self.preload_before_isolating,
            "preload_timeout": self.preload_timeout,
            "inspect_blocked_bodies": self.inspect_blocked_bodies,
        }


@dataclass(frozen=True)
class PrivacyPolicy:
    """Que se redacta antes de escribir cualquier cosa en el expediente.

    Con credenciales sinteticas los metadatos son inocuos. Con una e.firma real
    no lo son: el nombre de archivo de una e.firma del SAT **contiene el RFC**
    del titular, y el SHA-256 del ``.key`` es un identificador estable de esa
    persona. En modo ``real`` ambos se redactan.
    """

    #: Sustituir nombres de archivo por su extension y tamano.
    redact_filenames: bool = False
    #: Buscar y sustituir identificadores fiscales (RFC/CURP) en cualquier texto.
    redact_personal_ids: bool = False
    #: Publicar digests globales (SHA-256) del material. En modo real se
    #: sustituyen por fingerprints HMAC validos solo dentro de la sesion.
    publish_global_digests: bool = True

    @classmethod
    def for_real_credentials(cls) -> "PrivacyPolicy":
        return cls(redact_filenames=True, redact_personal_ids=True,
                   publish_global_digests=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "redact_filenames": self.redact_filenames,
            "redact_personal_ids": self.redact_personal_ids,
            "publish_global_digests": self.publish_global_digests,
        }


def normalize_url(url: str) -> str:
    """Normaliza lo que el operador escribe en la interfaz.

    Acepta ``ejemplo.com.mx``, ``www.ejemplo.com.mx/firma`` o una URL completa.
    Sin esquema asume ``https``: un auditor de firma electronica no debe
    degradar silenciosamente a HTTP.
    """
    text = (url or "").strip().strip('"').strip("'")
    if not text:
        return ""
    if text.startswith(("http://", "https://", "file://", "about:")):
        return text
    if text.startswith("//"):
        return "https:" + text
    return "https://" + text


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

    #: URL del objetivo. Puede quedar vacia: el operador la proporciona desde la
    #: interfaz, o navegando en el propio navegador. La clasificacion de terceros
    #: queda inactiva hasta que se conoce (ver :meth:`set_target`).
    target: str = ""
    level: AuditLevel = AuditLevel.FULL_CORRELATED
    output_dir: Path = Path("audits")
    headless: bool = True
    browser_path: str | None = field(default_factory=default_chromium_path)
    browser_args: list[str] = field(default_factory=lambda: ["--no-sandbox"])
    viewport: tuple[int, int] = (1280, 900)
    #: Segundos maximos de sesion interactiva antes de cerrar automaticamente.
    max_duration: float = 900.0
    #: Captura completa de cuerpos HTTP. Desactivada por defecto.
    capture_bodies: bool = False
    #: Bytes maximos por cuerpo cuando ``capture_bodies`` esta activo.
    max_body_bytes: int = 64 * 1024
    credential_mode: CredentialMode = CredentialMode.SYNTHETIC
    #: Consentimiento explicito para usar una e.firma real. Sin el, el modo
    #: ``real`` se rechaza: no debe poder activarse por descuido.
    acknowledge_real_credentials: bool = False
    #: Que se redacta antes de escribir en el expediente.
    privacy: PrivacyPolicy = field(default_factory=PrivacyPolicy)
    #: Como se corta la red en la prueba de firma local.
    isolation: IsolationPolicy = field(default_factory=IsolationPolicy)
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

    def __post_init__(self) -> None:
        self.output_dir = Path(self.output_dir)
        self.level = AuditLevel(self.level)
        self.rules_dirs = [Path(p) for p in self.rules_dirs]
        self.credential_mode = CredentialMode(self.credential_mode)
        if self.level >= AuditLevel.FULL_CORRELATED and self.proxy.port == 0:
            self.proxy.enabled = self.proxy.enabled or False
        if self.credential_mode.is_real:
            self._harden_for_real_credentials()

    def _harden_for_real_credentials(self) -> None:
        """Endurecimiento no negociable del modo ``real``.

        Con una e.firma real, varias comodidades de depuracion se convierten en
        fugas: un cuerpo HTTP persistido puede contener la clave, y el nombre de
        archivo de una e.firma del SAT contiene el RFC del titular. Estas
        restricciones se aplican aunque el operador pida lo contrario, porque el
        dano no seria reversible.
        """
        if not self.acknowledge_real_credentials:
            raise ValueError(
                "credential_mode='real' requiere acknowledge_real_credentials=True. "
                "El modo real usa su e.firma de produccion contra un sitio que todavia "
                "no ha sido caracterizado; confirmelo de forma explicita."
            )
        self.capture_bodies = False
        self.max_body_bytes = 0
        self.proxy.capture_bodies = False
        self.privacy = PrivacyPolicy.for_real_credentials()

    # -- objetivo diferido ----------------------------------------------
    @property
    def has_target(self) -> bool:
        return bool(self.target.strip())

    def set_target(self, url: str) -> str:
        """Fija el objetivo cuando el operador lo proporciona en marcha.

        Solo el primer objetivo cuenta: es el que define que es "primera parte"
        para el resto de la sesion. Las navegaciones posteriores a otros
        dominios siguen siendo terceros, que es lo correcto.
        """
        url = normalize_url(url)
        if not url:
            raise ValueError("URL vacia")
        if not self.has_target:
            self.target = url
        return url

    # -- riesgos del modo real ------------------------------------------
    def real_credential_warnings(self) -> list[str]:
        """Riesgos residuales que el operador debe conocer antes de empezar.

        FirmaScope *detecta* la exfiltracion; no la impide. Con credenciales
        reales, la deteccion llega cuando la clave ya salio.
        """
        if not self.credential_mode.is_real:
            return []
        warnings = [
            "FirmaScope observa, no bloquea: si el sitio transmite su clave, el hallazgo "
            "llegara despues de que haya salido.",
            "Si la auditoria reporta FS-KEY-001, FS-KEY-002 o FS-PWD-001, asuma la "
            "credencial como comprometida y revoque la e.firma.",
            "El expediente no guarda su clave ni su contrasena, y redacta nombres de "
            "archivo e identificadores fiscales. Aun asi, no comparta el expediente sin "
            "revisarlo.",
        ]
        if self.isolation.mode is IsolationMode.NONE:
            warnings.append(
                "Sin aislamiento de red, la clave se usara con el sitio conectado. "
                "Considere la prueba por etapas: la firma ocurre con la red cortada, "
                "que es la unica forma de limitar la exposicion durante la prueba."
            )
        return warnings

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
            "capture_bodies": self.capture_bodies,
            "max_body_bytes": self.max_body_bytes,
            "credential_mode": self.credential_mode.value,
            "real_credentials_acknowledged": self.acknowledge_real_credentials,
            "privacy": self.privacy.to_dict(),
            "isolation": self.isolation.to_dict(),
            "screenshots": self.screenshots,
            "first_party_domains": list(self.first_party_domains),
            "correlation_window_ms": self.correlation_window_ms,
            "proxy": self.proxy.to_dict(),
            "note": self.note,
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
