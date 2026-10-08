"""Interfaz de linea de comandos de FirmaScope.

    firmascope audit [URL]        auditar un sitio (la URL puede darse despues)
    firmascope credentials new    generar una credencial sintetica de laboratorio
    firmascope rules              listar el catalogo de reglas
    firmascope verify DIR         verificar la cadena de evidencias de un expediente
    firmascope version

Durante una auditoria el control es interactivo. En cada etapa se acepta:

    next / n     continuar a la siguiente etapa
    back / b     regresar a la etapa anterior
    retry / r    repetir la etapa actual
    cancel / q   cancelar el proceso (restablece la red y cierra el expediente)
    url <URL>    abrir una pagina (si no se dio URL al arrancar, o para navegar)
    offline      cortar la red ahora
    online       restablecer la red ahora
    status       estado actual de la sesion
    stages       lista de etapas
    help

``next``, ``back`` y ``cancel`` son las tres acciones que una interfaz grafica
mapea a sus botones: :class:`~firmascope.browser_controller.isolation.StageAction`
es el contrato entre ambas.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from .. import __version__
from ..audit_core.config import (
    AuditConfig,
    AuditLevel,
    CredentialMode,
    IsolationMode,
    IsolationPolicy,
    normalize_url,
)
from ..audit_core.events import Event, EventType
from ..audit_core.orchestrator import AuditSession
from ..browser_controller.isolation import Stage, StageAction

#: Eventos que merece la pena mostrar en vivo en la terminal.
LIVE_EVENTS = frozenset({
    EventType.FILE_SELECTED, EventType.FILE_READ, EventType.PASSWORD_READ,
    EventType.CRYPTO_IMPORT, EventType.CRYPTO_DECRYPT, EventType.CRYPTO_SIGN,
    EventType.CRYPTO_EXPORT, EventType.CRYPTO_WRAP, EventType.STORAGE_WRITE,
    EventType.NETWORK_OFF, EventType.NETWORK_ON, EventType.BEACON_SEND,
    EventType.WEBSOCKET_SEND, EventType.FORM_SUBMIT,
})


# ----------------------------------------------------------------------
# Presentacion
# ----------------------------------------------------------------------

def _print_event(event: Event) -> None:
    if event.type not in LIVE_EVENTS:
        return
    tags = ",".join(event.tags)
    detail = ""
    if event.type in (EventType.NETWORK_OFF, EventType.NETWORK_ON):
        detail = str(event.data.get("reason", ""))
    else:
        host = event.data.get("host") or event.data.get("store") or ""
        size = event.data.get("body_size") or event.data.get("size") or ""
        blocked = " [BLOQUEADO]" if event.data.get("blocked") else ""
        detail = f"{host} {size}{blocked}".strip()
    print(f"  . {event.type.value:<18} {detail:<44} {tags}", flush=True)


def _banner(stage: Stage, index: int, total: int, network: str) -> None:
    print()
    print(f"-- Etapa {index + 1}/{total}: {stage.title}  [red: {network}] "
          + "-" * max(0, 24 - len(stage.title)))
    print(f"   {stage.instruction}")
    if stage.irreversible_note:
        print(f"   aviso: {stage.irreversible_note}")
    options = ["next", "retry", "cancel"]
    if stage.allow_back and index > 0:
        options.insert(1, "back")
    print(f"   acciones: {' | '.join(options)}   (o url/offline/online/status/help)")


HELP_TEXT = """
  next   / n    continuar a la siguiente etapa
  back   / b    regresar a la etapa anterior
  retry  / r    repetir esta etapa
  cancel / q    cancelar el proceso y cerrar el expediente
  url <URL>     abrir una pagina en el navegador auditado
  offline       cortar la red ahora (sin cambiar de etapa)
  online        restablecer la red ahora
  status        resumen del estado de la sesion
  stages        listado de etapas
  help          esta ayuda
"""


# ----------------------------------------------------------------------
# Controlador interactivo de etapas
# ----------------------------------------------------------------------

class InteractiveStageController:
    """Traduce las ordenes del operador en acciones de etapa.

    Las ordenes que no cambian de etapa (abrir una URL, forzar el estado de
    red, consultar el estado) se atienden sin salir del bucle, de modo que el
    operador puede proporcionar la pagina en cualquier momento.
    """

    def __init__(self, session: AuditSession):
        self.session = session

    def __call__(self, stage: Stage, index: int, test) -> StageAction:
        total = len(test.stages)
        _banner(stage, index, total, test.isolation.network_state)
        while True:
            try:
                raw = input("firmascope> ").strip()
            except EOFError:
                print()
                return StageAction.ABORT
            if not raw:
                return StageAction.CONTINUE

            command, _, argument = raw.partition(" ")
            command = command.lower()
            argument = argument.strip()

            if command in ("url", "open", "goto", "abrir"):
                self._navigate(argument)
                continue
            if command in ("offline", "off"):
                ok = self.session.controller.set_offline(True, "orden del operador")
                print("   red aislada." if ok else "   no se pudo aislar (vea el aviso).")
                continue
            if command in ("online", "on"):
                self.session.controller.set_offline(False, "orden del operador")
                print("   red restablecida.")
                continue
            if command in ("status", "estado"):
                self._status(stage, index, total, test)
                continue
            if command in ("stages", "etapas"):
                for item in test.describe():
                    mark = ">" if item["index"] == index else " "
                    print(f"   {mark} {item['index'] + 1}. {item['title']} "
                          f"[{item['network']}]")
                continue
            if command in ("help", "h", "?", "ayuda"):
                print(HELP_TEXT)
                continue

            try:
                return StageAction.parse(command)
            except ValueError:
                print(f"   orden desconocida: {command!r}. Escriba 'help'.")

    # ------------------------------------------------------------------
    def _navigate(self, argument: str) -> None:
        if not argument:
            print("   uso: url <direccion>")
            return
        if self.session.controller.offline:
            print("   la red esta aislada: la pagina no cargaria. "
                  "Use 'online' primero, o retroceda a una etapa en linea.")
            return
        try:
            resolved = self.session.navigate(argument)
            print(f"   abierto: {resolved}")
            if resolved == self.session.config.target:
                print(f"   objetivo de la sesion fijado en {resolved}")
        except Exception as exc:
            print(f"   no se pudo abrir: {exc}")

    def _status(self, stage: Stage, index: int, total: int, test) -> None:
        session = self.session
        print(f"   sesion:     {session.session_id}")
        print(f"   objetivo:   {session.config.target or '(sin fijar)'}")
        print(f"   etapa:      {index + 1}/{total} {stage.name}")
        print(f"   red:        {test.isolation.network_state}")
        print(f"   credencial: {session.config.credential_mode.value}")
        print(f"   observado:  {session.stats.events} eventos, "
              f"{len(session.store.requests())} peticiones")
        blocked = len(test.isolation.blocked)
        if blocked:
            print(f"   bloqueados: {blocked} intentos de salida durante el aislamiento")


# ----------------------------------------------------------------------
# Comandos
# ----------------------------------------------------------------------

def _build_config(args: argparse.Namespace) -> AuditConfig:
    policy = IsolationPolicy(
        mode=IsolationMode.parse(args.isolation),
        allow_hosts=list(args.allow_host or []),
        emulate_offline_flag=not args.no_offline_flag,
    )
    return AuditConfig(
        target=normalize_url(args.url) if args.url else "",
        level=AuditLevel.parse(args.level),
        output_dir=Path(args.output),
        headless=args.headless,
        capture_bodies=args.capture_bodies,
        credential_mode=CredentialMode.parse(args.credentials),
        acknowledge_real_credentials=args.i_accept_real_credential_risk,
        isolation=policy,
        first_party_domains=list(args.first_party or []),
        note=args.note or "",
    )


def _confirm_real_credentials(config: AuditConfig) -> bool:
    """Confirmacion informada antes de usar una e.firma real."""
    print()
    print("=" * 72)
    print("MODO CREDENCIAL REAL")
    print("=" * 72)
    for warning in config.real_credential_warnings():
        print(f"  - {warning}")
    print()
    print("  Recomendacion: ejecute primero la auditoria con credenciales")
    print("  sinteticas (--credentials synthetic) para caracterizar el sitio.")
    print("  Si decide continuar con la real, la prueba por etapas firma con la")
    print("  red cortada, que es la unica forma de limitar la exposicion.")
    print()
    answer = input("Escriba ACEPTO para continuar: ").strip()
    if answer != "ACEPTO":
        print("Cancelado.")
        return False
    return True


def cmd_audit(args: argparse.Namespace) -> int:
    try:
        config = _build_config(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        if "acknowledge_real_credentials" in str(exc):
            print("Anada --i-accept-real-credential-risk para confirmarlo.", file=sys.stderr)
        return 2

    if config.credential_mode.is_real and not _confirm_real_credentials(config):
        return 1

    if config.credential_mode in (CredentialMode.OWN_TEST, CredentialMode.REAL):
        if not args.key or not args.cert:
            print("error: --key y --cert son obligatorios con ese modo de credencial",
                  file=sys.stderr)
            return 2

    password: str | None = None
    if config.credential_mode in (CredentialMode.OWN_TEST, CredentialMode.REAL):
        password = getpass.getpass("Contrasena de la clave privada: ")

    session = AuditSession(config, on_event=_print_event)
    print(f"FirmaScope {__version__} - sesion {session.session_id}")
    print(f"Expediente: {session.root}")

    aborted = False
    reason = ""
    package = session.root
    try:
        credential = session.prepare_credentials(
            key_path=Path(args.key) if args.key else None,
            cert_path=Path(args.cert) if args.cert else None,
            password=password,
            credentials_dir=Path(args.credentials_dir) if args.credentials_dir else None,
        )
        if credential is not None and credential.synthetic:
            print()
            print("Credencial sintetica de laboratorio generada:")
            print(f"  .cer         {credential.cert_path}")
            print(f"  .key         {credential.key_path}")
            print(f"  contrasena   {credential.password}")
            print("  (no es un certificado del SAT; sirve solo para la prueba)")

        session.start_browser()

        if config.has_target:
            session.navigate(config.target)
        else:
            print()
            print("No se indico URL. Escriba 'url <direccion>' para abrir el sitio,")
            print("o navegue directamente en la ventana del navegador.")

        test = session.controller.staged_offline_test()
        result = test.run(InteractiveStageController(session))
        aborted = result.aborted
        reason = result.abort_reason

        session.collect_and_analyze()
        session.evaluate()
    except KeyboardInterrupt:
        aborted = True
        reason = "interrumpido con Ctrl-C"
        print("\nInterrumpido: se cierra el expediente con lo observado.")
    except Exception as exc:  # pragma: no cover - cualquier fallo debe cerrar bien
        aborted = True
        reason = f"{type(exc).__name__}: {exc}"
        print(f"\nerror: {reason}", file=sys.stderr)
    finally:
        try:
            package = session.finish(aborted=aborted, reason=reason)
        except Exception as exc:  # pragma: no cover
            print(f"\nerror al cerrar el expediente: {exc}", file=sys.stderr)

    report_path = package / "report.json"
    if not report_path.exists():
        print(f"\nExpediente parcial en {package} (sin reporte).")
        return 1

    from ..report_engine.exporter import text_summary

    report = json.loads(report_path.read_text(encoding="utf-8"))
    print()
    print(text_summary(report))
    print()
    print(f"Expediente: {package}")
    print(f"Reporte:    {package / 'report.html'}")
    return 1 if aborted else 0


def cmd_credentials_new(args: argparse.Namespace) -> int:
    from ..credentials import generate

    credential = generate()
    directory = Path(args.output)
    credential.write(directory)
    print("Credencial sintetica de laboratorio:")
    print(f"  .cer         {credential.cert_path}")
    print(f"  .key         {credential.key_path}")
    print(f"  contrasena   {credential.password}")
    print(f"  sujeto       {credential.subject}")
    print()
    print("No es un certificado del SAT y no pretende serlo. Uselo para probar")
    print("portales de firma sin exponer su e.firma.")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    from ..rule_engine.engine import RuleEngine

    engine = RuleEngine()
    for meta in engine.rules:
        if args.category and meta.category != args.category:
            continue
        print(f"{meta.id:<16} {meta.severity.value:<9} {meta.category:<9} {meta.title}")
        if args.verbose:
            print(f"    {meta.summary}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    from ..evidence_store.store import EvidenceStore

    root = Path(args.directory)
    if not (root / "session.sqlite").exists():
        print(f"error: no hay expediente en {root}", file=sys.stderr)
        return 2
    store = EvidenceStore(root, root.name)
    ok, broken = store.verify_chain()
    info = store.session_info()
    store.close()

    print(f"Expediente: {root}")
    print(f"Sesion:     {info.get('id', root.name)}")
    print(f"Objetivo:   {info.get('target', '')}")
    if ok:
        print("Cadena de evidencias: INTACTA")
        return 0
    print(f"Cadena de evidencias: ROTA en el registro {broken}")
    print("El expediente fue modificado despues de generarse.")
    return 1


# ----------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="firmascope",
        description="Auditor defensivo de custodia de claves privadas en aplicaciones "
                    "web de firma electronica.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--version", action="version", version=f"firmascope {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="auditar un sitio de firma electronica")
    audit.add_argument("url", nargs="?", default=None,
                       help="URL del objetivo. Si se omite, se proporciona desde la interfaz.")
    audit.add_argument("--level", default="4",
                       help="nivel de auditoria: 1 red, 2 codigo, 3 offline, 4 completo")
    audit.add_argument("--credentials", default="synthetic",
                       help="synthetic | own-test | real | none")
    audit.add_argument("--key", default=None, help="ruta del archivo .key")
    audit.add_argument("--cert", default=None, help="ruta del archivo .cer")
    audit.add_argument("--credentials-dir", default=None,
                       help="donde escribir la credencial sintetica generada")
    audit.add_argument("--i-accept-real-credential-risk", action="store_true",
                       help="requerido por --credentials real")
    audit.add_argument("--isolation", default="full",
                       help="full | third-party | allowlist | none")
    audit.add_argument("--allow-host", action="append", default=[],
                       help="host alcanzable durante el aislamiento (modo allowlist)")
    audit.add_argument("--no-offline-flag", action="store_true",
                       help="no emular navigator.onLine=false durante el aislamiento")
    audit.add_argument("--first-party", action="append", default=[],
                       help="dominio adicional considerado propio")
    audit.add_argument("--capture-bodies", action="store_true",
                       help="persistir cuerpos HTTP (ignorado con credencial real)")
    audit.add_argument("--headless", action="store_true",
                       help="sin ventana. No recomendado: la firma requiere interaccion.")
    audit.add_argument("--output", default="audits", help="directorio de expedientes")
    audit.add_argument("--note", default="", help="etiqueta libre para identificar la prueba")
    audit.set_defaults(func=cmd_audit)

    creds = sub.add_parser("credentials", help="credenciales sinteticas de laboratorio")
    creds_sub = creds.add_subparsers(dest="action", required=True)
    creds_new = creds_sub.add_parser("new", help="generar una credencial nueva")
    creds_new.add_argument("--output", default="fixtures/synthetic-efirma",
                           help="directorio donde escribir .key y .cer")
    creds_new.set_defaults(func=cmd_credentials_new)

    rules = sub.add_parser("rules", help="listar el catalogo de reglas")
    rules.add_argument("--category", default=None,
                       help="efirma | crypto | network | storage | code")
    rules.add_argument("-v", "--verbose", action="store_true")
    rules.set_defaults(func=cmd_rules)

    verify = sub.add_parser("verify", help="verificar la cadena de evidencias")
    verify.add_argument("directory", help="directorio del expediente")
    verify.set_defaults(func=cmd_verify)

    version = sub.add_parser("version", help="mostrar la version")
    version.set_defaults(func=lambda _a: (print(f"firmascope {__version__}"), 0)[1])

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        print("\nInterrumpido.")
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
