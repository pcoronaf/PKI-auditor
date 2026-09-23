"""Interfaz de linea de ordenes de FirmaScope.

    firmascope audit <url> [--level N]     audita un objetivo
    firmascope labs serve                  arranca las aplicaciones de laboratorio
    firmascope credentials new             genera credenciales sinteticas
    firmascope rules [--json]              muestra el catalogo de reglas
    firmascope verify <expediente>         verifica la cadena de integridad
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from .. import __version__
from ..audit_core.conclusions import Status
from ..audit_core.config import AuditConfig, AuditLevel, CredentialMode

#: Marcador por estado, en ASCII para no depender de la fuente del terminal.
STATUS_MARK = {
    Status.CONFIRMED.value: "[!!]",
    Status.OBSERVED.value: "[!]",
    Status.POTENTIAL.value: "[?]",
    Status.NOT_OBSERVED.value: "[ ]",
    Status.INCONCLUSIVE.value: "[-]",
}

ADVERTENCIA = (
    "FirmaScope es una herramienta defensiva. Usala sobre sitios propios o con "
    "autorizacion de prueba, y con credenciales sinteticas. No uses tu e.firma real."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="firmascope",
        description="Auditor defensivo de custodia de claves privadas en aplicaciones "
                    "web de firma electronica (e.firma del SAT).",
        epilog=ADVERTENCIA,
    )
    parser.add_argument("--version", action="version", version=f"FirmaScope {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # -- audit ----------------------------------------------------------
    audit = sub.add_parser("audit", help="audita un objetivo", epilog=ADVERTENCIA)
    audit.add_argument("target", help="URL de la aplicacion de firma a auditar")
    audit.add_argument("-l", "--level", default="4",
                       help="nivel de auditoria: 1..4, o network/code/offline/full")
    audit.add_argument("-o", "--output", default="audits", type=Path,
                       help="directorio de expedientes (por defecto: audits/)")
    audit.add_argument("--headed", action="store_true",
                       help="mostrar el navegador; necesario para operar el sitio a mano")
    audit.add_argument("--dwell", type=float, default=6.0,
                       help="segundos de observacion tras cargar la pagina")
    audit.add_argument("--offline-dwell", type=float, default=6.0,
                       help="segundos de observacion con la red aislada (nivel 3+)")
    audit.add_argument("--capture-bodies", action="store_true",
                       help="persistir los cuerpos HTTP (desactivado por defecto)")
    audit.add_argument("--proxy", action=argparse.BooleanOptionalAction, default=None,
                       help="interponer mitmproxy. Por defecto: activo en nivel 4 si "
                            "mitmproxy esta instalado")
    audit.add_argument("--rules", action="append", type=Path, default=[],
                       metavar="DIR", help="directorio adicional con reglas YAML")
    audit.add_argument("--first-party", action="append", default=[], metavar="DOMINIO",
                       help="dominio adicional considerado propio")
    audit.add_argument("--note", default="", help="etiqueta libre del operador")
    audit.add_argument("--json", action="store_true",
                       help="emitir el resultado como JSON en lugar de texto")

    # -- labs -----------------------------------------------------------
    labs = sub.add_parser("labs", help="aplicaciones de laboratorio")
    labs_sub = labs.add_subparsers(dest="labs_command", required=True)
    serve = labs_sub.add_parser("serve", help="arranca el servidor de laboratorio")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("-v", "--verbose", action="store_true", help="registrar cada peticion")
    labs_sub.add_parser("list", help="lista las aplicaciones disponibles")

    # -- credentials ----------------------------------------------------
    creds = sub.add_parser("credentials", help="credenciales sinteticas de laboratorio")
    creds_sub = creds.add_subparsers(dest="credentials_command", required=True)
    new = creds_sub.add_parser("new", help="genera un par .key/.cer de laboratorio")
    new.add_argument("-o", "--output", type=Path, default=Path("credentials"))
    new.add_argument("--stem", default="lab", help="nombre base de los ficheros")
    new.add_argument("--key-size", type=int, default=2048)
    new.add_argument("--password", default=None,
                     help="contrasena de la clave (por defecto, una aleatoria)")

    # -- rules ----------------------------------------------------------
    rules = sub.add_parser("rules", help="catalogo de reglas")
    rules.add_argument("--json", action="store_true")
    rules.add_argument("--rules", action="append", type=Path, default=[], metavar="DIR")

    # -- verify ---------------------------------------------------------
    verify = sub.add_parser("verify", help="verifica la integridad de un expediente")
    verify.add_argument("path", type=Path, help="directorio del expediente")

    return parser


# ----------------------------------------------------------------------
# Ordenes
# ----------------------------------------------------------------------

def cmd_audit(args: argparse.Namespace) -> int:
    from ..audit_core.config import ProxyConfig
    from .orchestrator import Auditor

    try:
        level = AuditLevel.parse(args.level)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    config = AuditConfig(
        target=args.target,
        level=level,
        output_dir=args.output,
        headless=not args.headed,
        capture_bodies=args.capture_bodies,
        rules_dirs=list(args.rules),
        first_party_domains=list(args.first_party),
        proxy=ProxyConfig(enabled=_proxy_wanted(args.proxy, level)),
        credential_mode=CredentialMode.SYNTHETIC,
        note=args.note,
    )

    if args.proxy and level < AuditLevel.FULL_CORRELATED:
        print("aviso: --proxy solo tiene efecto en nivel 4; se ignora.", file=sys.stderr)

    if not args.json:
        print(f"FirmaScope {__version__} — nivel {int(level)} ({level.name})")
        print(f"Objetivo: {config.target}")
        if args.headed:
            print("Navegador visible: opera el sitio a mano; la sesion se analiza al cerrarse.")
        print()

    auditor = Auditor(config)
    result = auditor.run(dwell=args.dwell, offline_dwell=args.offline_dwell)

    if args.json:
        print(json.dumps(_result_json(result), indent=2, ensure_ascii=False, default=str))
    else:
        _print_result(result)

    if result.error:
        return 1
    return 0


def _proxy_wanted(flag: bool | None, level: AuditLevel) -> bool:
    """El nivel 4 incluye el proxy salvo que se desactive o no este instalado.

    Pedirlo explicitamente sin tenerlo instalado no es un error fatal: el
    orquestador lo registra y la sesion sigue con tres sensores.
    """
    if level < AuditLevel.FULL_CORRELATED or flag is False:
        return False
    if flag is True:
        return True
    from ..proxy_addon import available
    return available()


def cmd_labs(args: argparse.Namespace) -> int:
    from ..labs.server import DEMOS, serve

    if args.labs_command == "list":
        for demo in DEMOS:
            print(demo)
        return 0

    print(ADVERTENCIA)
    print()
    serve(args.host, args.port, quiet=not args.verbose)
    return 0


def cmd_credentials(args: argparse.Namespace) -> int:
    from ..credentials import generator

    credential = generator.generate(key_size=args.key_size, password=args.password)
    credential.write(args.output, stem=args.stem)
    info = credential.describe()

    print("Credenciales sinteticas de laboratorio generadas.")
    print(f"  archivo .key:  {info['key_file']}")
    print(f"  archivo .cer:  {info['cert_file']}")
    print(f"  sujeto:        {info['subject']}")
    print(f"  serie:         {info['serial']}")
    print(f"  vigencia:      {info['not_before'][:10]} .. {info['not_after'][:10]}")
    print(f"  SHA-256 .key:  {info['key_sha256']}")
    print(f"  SHA-256 .cer:  {info['cert_sha256']}")
    print()
    # La contrasena se imprime porque el operador tiene que escribirla en el
    # sitio auditado. Es material sintetico: no protege nada real. Por eso
    # `describe()` la excluye del manifiesto y aqui se muestra aparte.
    print(f"  contrasena:    {credential.password}")
    print()
    print("El sujeto del certificado declara que NO es una credencial del SAT.")
    print(ADVERTENCIA)
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    from ..rule_engine import RuleEngine

    catalog = RuleEngine(extra_dirs=args.rules).catalog()
    if args.json:
        print(json.dumps(catalog, indent=2, ensure_ascii=False))
        return 0

    width = max((len(entry["id"]) for entry in catalog), default=12)
    current = ""
    # El catalogo llega ordenado por identificador; para leerlo conviene
    # agruparlo por categoria sin romper el orden dentro de cada una.
    for entry in sorted(catalog, key=lambda e: (e["category"], e["id"])):
        if entry["category"] != current:
            current = entry["category"]
            print(f"\n{current.upper()}")
        estado = "" if entry["enabled"] else "  (deshabilitada)"
        print(f"  {entry['id']:<{width}}  {entry['severity']:<8}  {entry['title']}{estado}")
    print(f"\n{len(catalog)} reglas.")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    from ..evidence_store.store import EvidenceStore

    path = Path(args.path)
    if not (path / "session.sqlite").exists():
        print(f"error: no hay un expediente en {path}", file=sys.stderr)
        return 2

    store = EvidenceStore(path, path.name)
    try:
        info = store.session_info()
        ok, broken = store.verify_chain()
        total = len(store.events())
    finally:
        store.close()

    print(f"Expediente: {path}")
    print(f"  sesion:    {info.get('id', '?')}")
    print(f"  objetivo:  {info.get('target', '?')}")
    print(f"  eventos:   {total}")
    if ok:
        print("  cadena:    verificada")
        return 0
    print(f"  cadena:    ROTA a partir del registro {broken}")
    print()
    print("El expediente fue modificado despues de crearse. Sus conclusiones no")
    print("pueden sostenerse sin volver a ejecutar la auditoria.")
    return 1


# ----------------------------------------------------------------------
# Presentacion
# ----------------------------------------------------------------------

def _result_json(result: Any) -> dict[str, Any]:
    return {
        "session_id": result.session_id,
        "output_dir": str(result.output_dir),
        "chain_verified": result.chain_ok,
        "error": result.error,
        "proxy_note": result.proxy_note,
        "credentials_note": result.credentials_note,
        "reports": {k: str(v) for k, v in result.reports.items()},
        "findings": [f.to_dict() for f in result.findings],
    }


def _print_result(result: Any) -> None:
    if result.error:
        print(f"La sesion termino con un error: {result.error}")
        print("Se analizo lo capturado hasta ese momento.\n")
    for note in (result.proxy_note, result.credentials_note):
        if note:
            print(note)
    if result.proxy_note or result.credentials_note:
        print()

    for finding in result.findings:
        mark = STATUS_MARK.get(finding.status.value, "[ ]")
        print(f"{mark} {finding.rule_id:<14} {finding.status.value:<14} {finding.summary}")

    actionable = result.actionable()
    print()
    print(f"{len(result.findings)} reglas evaluadas, {len(actionable)} con hallazgo.")
    if result.correlation is not None:
        chains = result.correlation.exfiltration_chains()
        if chains:
            print(f"{len(chains)} cadenas de exfiltracion reconstruidas:")
            for chain in chains[:5]:
                print(f"    -> {chain.destination()}: {chain.narrative()}")

    if not actionable:
        print()
        print("No se observo transmision de material privado en esta ejecucion.")
        print("Eso NO demuestra que no pueda ocurrir: describe unicamente lo ocurrido")
        print("aqui, con esta configuracion y este recorrido.")

    print()
    print(f"Expediente: {result.output_dir}")
    for kind, path in result.reports.items():
        print(f"  {kind}: {path}")
    if result.chain_ok is False:
        print("  AVISO: la cadena de integridad del expediente no verifica.")


# ----------------------------------------------------------------------

def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "audit": cmd_audit,
        "labs": cmd_labs,
        "credentials": cmd_credentials,
        "rules": cmd_rules,
        "verify": cmd_verify,
    }
    try:
        return handlers[args.command](args)
    except KeyboardInterrupt:
        print("\nInterrumpido.", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
