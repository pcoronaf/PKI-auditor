"""Esquema declarativo de las opciones de una auditoria.

Las opciones no se declaran dentro de la interfaz que las pregunta. Se declaran
aqui una sola vez, y cada interfaz las *renderiza*:

* la CLI las pinta como un asistente de texto con menus numerados;
* la interfaz grafica (Tauri) las pintara como campos y radio buttons;
* un script puede construirlas directamente desde argumentos.

Asi las tres comparten exactamente el mismo conjunto de opciones, los mismos
valores por defecto, las mismas dependencias entre campos y las mismas
validaciones. Anadir una opcion es anadir una entrada en
:data:`AUDIT_OPTIONS`, no tocar tres interfaces.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .config import (
    AuditConfig,
    AuditLevel,
    CredentialMode,
    IsolationMode,
    IsolationPolicy,
    normalize_url,
)


class OptionKind(str, enum.Enum):
    """Como se pide un valor. Determina el control que pinta cada interfaz."""

    TEXT = "text"        # campo de texto libre
    CHOICE = "choice"    # una de varias opciones (radio buttons)
    MULTI = "multi"      # lista de valores (chips, o separados por coma)
    BOOL = "bool"        # casilla
    PATH = "path"        # ruta de archivo (selector de archivo en la GUI)


@dataclass(frozen=True)
class Choice:
    """Una alternativa de una opcion de tipo ``CHOICE``."""

    value: str
    label: str
    help: str = ""
    #: Marca las alternativas que exigen una decision consciente del operador.
    #: La GUI deberia pintarlas en rojo y pedir confirmacion.
    danger: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"value": self.value, "label": self.label, "help": self.help,
                "danger": self.danger}


@dataclass(frozen=True)
class Option:
    """Una opcion configurable de la auditoria."""

    id: str
    label: str
    kind: OptionKind
    help: str = ""
    default: Any = None
    choices: tuple[Choice, ...] = ()
    required: bool = False
    placeholder: str = ""
    #: Se pregunta solo si este predicado sobre las respuestas es cierto.
    #: Permite que la interfaz oculte campos irrelevantes en lugar de
    #: preguntarlos y descartarlos.
    depends_on: Callable[[dict[str, Any]], bool] | None = None
    #: Se puede cambiar con la auditoria en marcha, sin reiniciar la sesion.
    live: bool = False
    #: Agrupacion para la interfaz: basico o avanzado.
    group: str = "basico"

    def visible(self, answers: dict[str, Any]) -> bool:
        return self.depends_on is None or bool(self.depends_on(answers))

    def to_dict(self) -> dict[str, Any]:
        """Serializacion para una interfaz que no sea Python (p. ej. Tauri)."""
        return {
            "id": self.id,
            "label": self.label,
            "kind": self.kind.value,
            "help": self.help,
            "default": self.default,
            "choices": [c.to_dict() for c in self.choices],
            "required": self.required,
            "placeholder": self.placeholder,
            "live": self.live,
            "group": self.group,
            "conditional": self.depends_on is not None,
        }


# ----------------------------------------------------------------------
# Predicados de dependencia
# ----------------------------------------------------------------------

def _needs_credential_files(answers: dict[str, Any]) -> bool:
    return str(answers.get("credentials", "")) in ("own-test", "real")


def _is_real_credential(answers: dict[str, Any]) -> bool:
    return str(answers.get("credentials", "")) == "real"


def _is_not_real_credential(answers: dict[str, Any]) -> bool:
    return not _is_real_credential(answers)


def _is_allowlist(answers: dict[str, Any]) -> bool:
    return str(answers.get("isolation", "")) == "allowlist"


def _has_isolation(answers: dict[str, Any]) -> bool:
    return str(answers.get("isolation", "")) != "none"


# ----------------------------------------------------------------------
# El esquema
# ----------------------------------------------------------------------

AUDIT_OPTIONS: tuple[Option, ...] = (
    Option(
        id="target",
        label="Sitio a auditar",
        kind=OptionKind.TEXT,
        help="Puede dejarse vacio: podra abrir la pagina desde la interfaz una vez "
             "iniciada la sesion, o escribirla en la barra del navegador.",
        default="",
        placeholder="portal.ejemplo.mx",
    ),
    Option(
        id="level",
        label="Nivel de auditoria",
        kind=OptionKind.CHOICE,
        default="4",
        help="Que se observa. El nivel 4 incluye los anteriores.",
        # En orden natural, no con el valor por defecto primero: una interfaz
        # que numera las alternativas haria que teclear "2" seleccionara otro
        # nivel que el 2. El valor por defecto se senala, no se reordena.
        choices=(
            Choice("1", "Solo red",
                   "Equivale a DevTools Network, pero con registro reproducible."),
            Choice("2", "Analisis de codigo",
                   "Que podria hacer el codigo aunque no ocurra en esta ejecucion."),
            Choice("3", "Prueba de firma sin conexion",
                   "Comprueba si la firma se completa con la red aislada."),
            Choice("4", "Auditoria completa",
                   "Instrumentacion, red, analisis de codigo y prueba sin conexion."),
        ),
    ),
    Option(
        id="credentials",
        label="Credencial a usar",
        kind=OptionKind.CHOICE,
        default="synthetic",
        help="Con que material se prueba el portal.",
        choices=(
            Choice("synthetic", "Credencial sintetica de laboratorio",
                   "FirmaScope genera un .key y un .cer con la forma de una e.firma. "
                   "Si el portal los exfiltra, no ha perdido nada."),
            Choice("own-test", "Credencial de prueba propia",
                   "Un par .key/.cer suyo que no sea de produccion."),
            Choice("real", "Mi e.firma real",
                   "Su credencial de produccion. Requiere confirmacion explicita y "
                   "activa el endurecimiento de privacidad.",
                   danger=True),
            Choice("none", "Ninguna: la introduzco a mano",
                   "Sin canarios registrados no hay deteccion por contenido; solo "
                   "quedara la instrumentacion del navegador."),
        ),
    ),
    Option(
        id="key_path",
        label="Archivo .key",
        kind=OptionKind.PATH,
        required=True,
        depends_on=_needs_credential_files,
        placeholder="~/efirma/mi.key",
    ),
    Option(
        id="cert_path",
        label="Archivo .cer",
        kind=OptionKind.PATH,
        required=True,
        depends_on=_needs_credential_files,
        placeholder="~/efirma/mi.cer",
    ),
    Option(
        id="accept_real_risk",
        label="Acepto los riesgos de usar mi e.firma real",
        kind=OptionKind.BOOL,
        default=False,
        required=True,
        depends_on=_is_real_credential,
        help="FirmaScope observa, no bloquea: si el portal transmite su clave, el "
             "hallazgo llegara despues de que haya salido. Firme dentro de la ventana "
             "de aislamiento para limitar la exposicion.",
    ),
    Option(
        id="isolation",
        label="Aislamiento de red durante la firma",
        kind=OptionKind.CHOICE,
        default="full",
        live=True,
        help="Como se corta la salida de red en la etapa de firma.",
        choices=(
            Choice("full", "Total",
                   "Se bloquea toda salida. Es la prueba mas concluyente."),
            Choice("third-party", "Solo terceros",
                   "El portal sigue alcanzable; se bloquean los demas dominios."),
            Choice("allowlist", "Lista de permitidos",
                   "Se bloquea todo salvo los hosts que indique."),
            Choice("none", "Sin aislamiento",
                   "No se corta la red. No podra demostrarse firma local."),
        ),
    ),
    Option(
        id="allow_hosts",
        label="Hosts alcanzables durante el aislamiento",
        kind=OptionKind.MULTI,
        default=(),
        live=True,
        depends_on=_is_allowlist,
        placeholder="portal.ejemplo.mx, cdn.ejemplo.mx",
    ),
    Option(
        id="emulate_offline_flag",
        label="Emular navigator.onLine = false",
        kind=OptionKind.BOOL,
        default=True,
        live=True,
        depends_on=_has_isolation,
        help="Fiel a un corte real. Desactivelo si el portal se niega a firmar "
             "porque cree que no hay conexion.",
        group="avanzado",
    ),
    Option(
        id="first_party",
        label="Dominios propios adicionales",
        kind=OptionKind.MULTI,
        default=(),
        help="Dominios que no deben contarse como terceros (CDN propio, API propia).",
        placeholder="api.ejemplo.mx",
        group="avanzado",
    ),
    Option(
        id="capture_bodies",
        label="Guardar cuerpos HTTP en el expediente",
        kind=OptionKind.BOOL,
        default=False,
        depends_on=_is_not_real_credential,
        help="Util para depurar. Se fuerza a NO con credencial real, porque un cuerpo "
             "persistido podria contener su clave.",
        group="avanzado",
    ),
    Option(
        id="headless",
        label="Navegador sin ventana",
        kind=OptionKind.BOOL,
        default=False,
        help="No recomendado: la firma necesita que usted interactue con la pagina.",
        group="avanzado",
    ),
    Option(
        id="output_dir",
        label="Directorio de expedientes",
        kind=OptionKind.PATH,
        default="audits",
        group="avanzado",
    ),
    Option(
        id="note",
        label="Nota de la prueba",
        kind=OptionKind.TEXT,
        default="",
        help="Etiqueta libre que queda en el manifiesto para identificar esta corrida.",
        placeholder="prueba previa al alta del tramite",
        group="avanzado",
    ),
)

#: Indice por identificador.
OPTIONS_BY_ID: dict[str, Option] = {option.id: option for option in AUDIT_OPTIONS}

#: Opciones que pueden cambiarse con la sesion en marcha.
LIVE_OPTIONS: tuple[Option, ...] = tuple(o for o in AUDIT_OPTIONS if o.live)


def schema() -> list[dict[str, Any]]:
    """Esquema serializable, para una interfaz fuera de Python."""
    return [option.to_dict() for option in AUDIT_OPTIONS]


def defaults() -> dict[str, Any]:
    """Respuestas iniciales con los valores por defecto del esquema."""
    answers: dict[str, Any] = {}
    for option in AUDIT_OPTIONS:
        if option.kind is OptionKind.MULTI:
            answers[option.id] = list(option.default or ())
        else:
            answers[option.id] = option.default
    return answers


def visible_options(answers: dict[str, Any], group: str | None = None) -> list[Option]:
    """Opciones aplicables a las respuestas actuales."""
    return [o for o in AUDIT_OPTIONS
            if o.visible(answers) and (group is None or o.group == group)]


# ----------------------------------------------------------------------
# Validacion
# ----------------------------------------------------------------------

def validate(answers: dict[str, Any]) -> list[str]:
    """Devuelve la lista de problemas. Vacia significa que se puede arrancar."""
    problems: list[str] = []
    for option in visible_options(answers):
        value = answers.get(option.id)
        if option.kind is OptionKind.BOOL:
            if option.required and not value:
                problems.append(f"{option.label}: es necesario aceptarlo para continuar.")
            continue
        if option.required and (value is None or str(value).strip() == ""):
            problems.append(f"{option.label}: falta.")
            continue
        if option.kind is OptionKind.PATH and value and option.id in ("key_path", "cert_path"):
            if not Path(str(value)).expanduser().is_file():
                problems.append(f"{option.label}: no existe el archivo {value}.")
        if option.kind is OptionKind.CHOICE and value is not None:
            allowed = {c.value for c in option.choices}
            if str(value) not in allowed:
                problems.append(
                    f"{option.label}: {value!r} no es una opcion valida "
                    f"({', '.join(sorted(allowed))}).")
    if _is_allowlist(answers) and not answers.get("allow_hosts"):
        problems.append("Lista de permitidos: indique al menos un host, o elija otro "
                        "modo de aislamiento.")
    return problems


# ----------------------------------------------------------------------
# Respuestas -> configuracion
# ----------------------------------------------------------------------

@dataclass
class SetupResult:
    """Lo que produce cualquier interfaz de configuracion.

    La contrasena viaja aparte y nunca dentro de ``answers``: ese diccionario
    es serializable y podria acabar en un log o en el estado de una GUI.
    """

    config: AuditConfig
    key_path: Path | None = None
    cert_path: Path | None = None
    password: str | None = None
    answers: dict[str, Any] = field(default_factory=dict)


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.replace(";", ",").split(",") if part.strip()]
    return [str(v).strip() for v in value if str(v).strip()]


def build_config(answers: dict[str, Any]) -> AuditConfig:
    """Construye la configuracion a partir de las respuestas del esquema."""
    problems = validate(answers)
    if problems:
        raise ValueError("; ".join(problems))

    isolation = IsolationPolicy(
        mode=IsolationMode.parse(str(answers.get("isolation") or "full")),
        allow_hosts=_as_list(answers.get("allow_hosts")),
        emulate_offline_flag=bool(answers.get("emulate_offline_flag", True)),
    )
    return AuditConfig(
        target=normalize_url(str(answers.get("target") or "")),
        level=AuditLevel.parse(str(answers.get("level") or "4")),
        output_dir=Path(str(answers.get("output_dir") or "audits")),
        headless=bool(answers.get("headless", False)),
        capture_bodies=bool(answers.get("capture_bodies", False)),
        credential_mode=CredentialMode.parse(str(answers.get("credentials") or "synthetic")),
        acknowledge_real_credentials=bool(answers.get("accept_real_risk", False)),
        isolation=isolation,
        first_party_domains=_as_list(answers.get("first_party")),
        note=str(answers.get("note") or ""),
    )


def build_setup(answers: dict[str, Any], password: str | None = None) -> SetupResult:
    """Empaqueta configuracion, rutas de credencial y contrasena."""
    config = build_config(answers)
    key_path = answers.get("key_path")
    cert_path = answers.get("cert_path")
    return SetupResult(
        config=config,
        key_path=Path(str(key_path)).expanduser() if key_path else None,
        cert_path=Path(str(cert_path)).expanduser() if cert_path else None,
        password=password,
        answers=dict(answers),
    )


def needs_password(answers: dict[str, Any]) -> bool:
    return _needs_credential_files(answers)


# ----------------------------------------------------------------------
# Cambios en marcha
# ----------------------------------------------------------------------

def apply_live_change(config: AuditConfig, option_id: str, value: Any) -> str:
    """Aplica en caliente una opcion marcada como ``live``.

    Devuelve una descripcion del cambio. Lanza ``ValueError`` si la opcion no
    puede cambiarse con la sesion en marcha: cambiar el nivel o la credencial a
    mitad de una auditoria invalidaria lo ya observado, asi que se rechaza en
    lugar de permitir un expediente incoherente.
    """
    option = OPTIONS_BY_ID.get(option_id)
    if option is None:
        raise ValueError(f"opcion desconocida: {option_id}")
    if not option.live:
        raise ValueError(
            f"'{option.label}' no puede cambiarse con la sesion en marcha: "
            "cambiaria el significado de lo ya registrado. Termine esta auditoria "
            "y lance otra."
        )

    if option_id == "isolation":
        mode = IsolationMode.parse(str(value))
        config.isolation.mode = mode
        return f"aislamiento: {mode.value}"
    if option_id == "allow_hosts":
        config.isolation.allow_hosts = _as_list(value)
        return f"hosts permitidos: {', '.join(config.isolation.allow_hosts) or '(ninguno)'}"
    if option_id == "emulate_offline_flag":
        config.isolation.emulate_offline_flag = bool(value)
        return f"navigator.onLine emulado: {config.isolation.emulate_offline_flag}"
    raise ValueError(f"opcion '{option_id}' marcada como live pero sin implementacion")
