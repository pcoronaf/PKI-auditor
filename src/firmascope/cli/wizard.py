"""Asistente de configuracion interactivo.

Pinta el esquema de :mod:`firmascope.audit_core.options` como una interfaz de
texto. No conoce ninguna opcion concreta: recorre el esquema, respeta las
dependencias entre campos y valida con las reglas declaradas alli.

Consecuencia practica: cuando se anada una opcion al esquema, este asistente la
preguntara sin tocar este archivo, y la futura interfaz grafica la pintara sin
tocar el suyo.
"""

from __future__ import annotations

import getpass
import sys
from typing import Any

from ..audit_core.config import REAL_CREDENTIAL_WARNINGS
from ..audit_core.options import (
    AUDIT_OPTIONS,
    OPTIONS_BY_ID,
    Option,
    OptionKind,
    SetupResult,
    build_setup,
    defaults,
    needs_password,
    validate,
    visible_options,
)

WIDTH = 72


# ----------------------------------------------------------------------
# Presentacion
# ----------------------------------------------------------------------

def _rule(char: str = "-") -> str:
    return char * WIDTH


def _header() -> None:
    print()
    print(_rule("="))
    print("FirmaScope - configuracion de la auditoria")
    print(_rule("="))
    print("Pulse Enter para aceptar el valor entre corchetes.")


def _wrap(text: str, indent: str = "      ") -> str:
    """Ajuste de linea simple, sin dependencias."""
    words = text.split()
    lines: list[str] = []
    current = indent
    for word in words:
        if len(current) + len(word) + 1 > WIDTH:
            lines.append(current.rstrip())
            current = indent + word + " "
        else:
            current += word + " "
    if current.strip():
        lines.append(current.rstrip())
    return "\n".join(lines)


def _show_value(option: Option, value: Any) -> str:
    if option.kind is OptionKind.BOOL:
        return "si" if value else "no"
    if option.kind is OptionKind.MULTI:
        items = list(value or [])
        return ", ".join(items) if items else "(ninguno)"
    if option.kind is OptionKind.CHOICE:
        for choice in option.choices:
            if choice.value == str(value):
                return choice.label
        return str(value)
    text = str(value) if value not in (None, "") else "(vacio)"
    return text


# ----------------------------------------------------------------------
# Preguntas por tipo
# ----------------------------------------------------------------------

def _ask_choice(option: Option, current: Any) -> Any:
    print()
    print(option.label)
    if option.help:
        print(_wrap(option.help, "  "))
    print()
    for index, choice in enumerate(option.choices, start=1):
        marker = "o"
        if str(current) == choice.value:
            marker = "*"
        flag = "  [requiere confirmacion]" if choice.danger else ""
        print(f"  {index}) {marker} {choice.label}{flag}")
        if choice.help:
            print(_wrap(choice.help))
    default_index = 1
    for index, choice in enumerate(option.choices, start=1):
        if str(current) == choice.value:
            default_index = index
            break
    while True:
        raw = input(f"\n  Eleccion [{default_index}]: ").strip()
        if not raw:
            return option.choices[default_index - 1].value
        if raw.isdigit() and 1 <= int(raw) <= len(option.choices):
            return option.choices[int(raw) - 1].value
        lowered = raw.lower()
        for choice in option.choices:
            if choice.value == lowered:
                return choice.value
        print("  Opcion no valida.")


def _ask_bool(option: Option, current: Any) -> bool:
    print()
    print(option.label)
    if option.help:
        print(_wrap(option.help, "  "))
    suffix = "[S/n]" if current else "[s/N]"
    while True:
        raw = input(f"  {suffix}: ").strip().lower()
        if not raw:
            return bool(current)
        if raw in ("s", "si", "sí", "y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print("  Responda s o n.")


def _ask_text(option: Option, current: Any) -> str:
    print()
    print(option.label)
    if option.help:
        print(_wrap(option.help, "  "))
    hint = str(current) if current not in (None, "") else (option.placeholder or "")
    label = f"  Valor [{hint}]: " if hint else "  Valor: "
    raw = input(label).strip()
    if not raw:
        return str(current) if current not in (None, "") else ""
    return raw


def _ask_path(option: Option, current: Any) -> str:
    from pathlib import Path

    while True:
        value = _ask_text(option, current)
        if not value:
            if option.required:
                print("  Es obligatorio.")
                continue
            return ""
        resolved = Path(value).expanduser()
        if option.id in ("key_path", "cert_path") and not resolved.is_file():
            print(f"  No existe el archivo: {resolved}")
            continue
        return str(resolved)


def _ask_multi(option: Option, current: Any) -> list[str]:
    print()
    print(option.label)
    if option.help:
        print(_wrap(option.help, "  "))
    hint = ", ".join(current or []) or (option.placeholder or "")
    label = f"  Separe con comas [{hint}]: " if hint else "  Separe con comas: "
    raw = input(label).strip()
    if not raw:
        return list(current or [])
    return [part.strip() for part in raw.replace(";", ",").split(",") if part.strip()]


def ask(option: Option, current: Any) -> Any:
    if option.kind is OptionKind.CHOICE:
        return _ask_choice(option, current)
    if option.kind is OptionKind.BOOL:
        return _ask_bool(option, current)
    if option.kind is OptionKind.MULTI:
        return _ask_multi(option, current)
    if option.kind is OptionKind.PATH:
        return _ask_path(option, current)
    return _ask_text(option, current)


# ----------------------------------------------------------------------
# Confirmacion de credencial real
# ----------------------------------------------------------------------

def confirm_real_credentials() -> bool:
    """Confirmacion informada. Devuelve True si el operador escribe ACEPTO."""
    print()
    print(_rule("="))
    print("USO DE SU e.firma REAL")
    print(_rule("="))
    for warning in REAL_CREDENTIAL_WARNINGS:
        print(_wrap("- " + warning, "  "))
    print()
    print(_wrap("Recomendacion: audite primero con credencial sintetica para "
                "caracterizar el portal. Si continua con la real, firme dentro de la "
                "etapa aislada: es la unica forma de limitar la exposicion. "
                "Vea docs/real-credentials.md.", "  "))
    print()
    return input("  Escriba ACEPTO para continuar: ").strip() == "ACEPTO"


# ----------------------------------------------------------------------
# Revision
# ----------------------------------------------------------------------

def _review(answers: dict[str, Any]) -> list[Option]:
    options = visible_options(answers)
    print()
    print(_rule("="))
    print("Resumen de la auditoria")
    print(_rule("="))
    width = max(len(o.label) for o in options)
    for index, option in enumerate(options, start=1):
        value = _show_value(option, answers.get(option.id))
        tag = " (avanzado)" if option.group == "avanzado" else ""
        print(f"  {index:>2}. {option.label.ljust(width)}  {value}{tag}")
    return options


# ----------------------------------------------------------------------
# Asistente
# ----------------------------------------------------------------------

def run_setup(seed: dict[str, Any] | None = None,
              ask_advanced: bool | None = None) -> SetupResult | None:
    """Ejecuta el asistente. Devuelve ``None`` si el operador cancela.

    ``seed`` permite precargar respuestas desde argumentos de linea de comandos:
    lo ya indicado no se vuelve a preguntar como si no se hubiera dicho, solo
    aparece como valor por defecto.
    """
    answers = defaults()
    answers.update({k: v for k, v in (seed or {}).items() if v not in (None, "")})

    _header()

    # Opciones basicas, en el orden del esquema.
    for option in AUDIT_OPTIONS:
        if option.group != "basico" or not option.visible(answers):
            continue
        if option.id == "accept_real_risk":
            continue  # tiene su propio flujo de confirmacion
        answers[option.id] = ask(option, answers.get(option.id))
        if option.id == "credentials" and answers[option.id] == "real":
            answers["accept_real_risk"] = confirm_real_credentials()
            if not answers["accept_real_risk"]:
                print("\n  Cancelado. Considere --credentials synthetic.")
                return None

    # Opciones avanzadas, solo si se piden.
    show_advanced = ask_advanced
    if show_advanced is None:
        print()
        show_advanced = _ask_bool(
            Option(id="_adv", label="Revisar opciones avanzadas",
                   kind=OptionKind.BOOL,
                   help="Aislamiento fino, cuerpos HTTP, navegador sin ventana, "
                        "directorio de salida y nota de la prueba."),
            False)
    if show_advanced:
        for option in AUDIT_OPTIONS:
            if option.group == "avanzado" and option.visible(answers):
                answers[option.id] = ask(option, answers.get(option.id))

    # Revision y arranque.
    while True:
        options = _review(answers)
        problems = validate(answers)
        if problems:
            print()
            print("  Falta corregir:")
            for problem in problems:
                print(_wrap("- " + problem, "    "))
        print()
        prompt = "  [Enter] iniciar   [numero] editar   [c] cancelar: "
        raw = input(prompt).strip().lower()
        if raw in ("c", "cancel", "cancelar", "q"):
            print("\n  Cancelado.")
            return None
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            option = options[int(raw) - 1]
            if option.id == "accept_real_risk":
                answers[option.id] = confirm_real_credentials()
            else:
                answers[option.id] = ask(option, answers.get(option.id))
                if option.id == "credentials" and answers[option.id] == "real" \
                        and not answers.get("accept_real_risk"):
                    answers["accept_real_risk"] = confirm_real_credentials()
            continue
        if raw:
            print("  No entendi. Enter para iniciar, un numero para editar, c para cancelar.")
            continue
        if problems:
            print("  Corrija lo anterior antes de iniciar.")
            continue
        break

    password = None
    if needs_password(answers):
        print()
        password = getpass.getpass("  Contrasena de la clave privada: ")

    return build_setup(answers, password)


# ----------------------------------------------------------------------
# Cambios en marcha
# ----------------------------------------------------------------------

def live_menu(config) -> str | None:
    """Menu de las opciones que pueden cambiarse con la sesion en marcha.

    Devuelve una descripcion del cambio aplicado, o ``None`` si no se cambio
    nada. Las opciones no modificables se enumeran igualmente, para que quede
    claro que existen y por que no se pueden tocar aqui.
    """
    from ..audit_core.options import LIVE_OPTIONS, apply_live_change

    current = {
        "isolation": config.isolation.mode.value,
        "allow_hosts": list(config.isolation.allow_hosts),
        "emulate_offline_flag": config.isolation.emulate_offline_flag,
    }
    print()
    print("  Opciones modificables en marcha:")
    for index, option in enumerate(LIVE_OPTIONS, start=1):
        print(f"    {index}) {option.label}: {_show_value(option, current.get(option.id))}")
    fixed = [o.label for o in AUDIT_OPTIONS if not o.live]
    print(f"    Fijas para esta sesion: {', '.join(fixed[:4])}...")
    print("    (cambiarlas invalidaria lo ya registrado; lance otra auditoria)")

    raw = input("\n  Numero a cambiar, o Enter para volver: ").strip()
    if not raw or not raw.isdigit():
        return None
    index = int(raw)
    if not 1 <= index <= len(LIVE_OPTIONS):
        print("  Opcion no valida.")
        return None

    option = LIVE_OPTIONS[index - 1]
    value = ask(option, current.get(option.id))
    try:
        described = apply_live_change(config, option.id, value)
    except ValueError as exc:
        print(f"  {exc}")
        return None
    print(f"  Aplicado: {described}")
    return described


def interactive_possible() -> bool:
    """True si hay una terminal con la que conversar."""
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:  # pragma: no cover
        return False
