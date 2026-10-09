"""Interfaz de linea de comandos de FirmaScope.

    firmascope audit [URL]        auditar un sitio (la URL puede darse despues)
    firmascope audit URL --auto   auditar sin operador (credencial sintetica)
    firmascope login URL          iniciar sesion en el portal y guardarla para auditar
    firmascope panel [URL]        la interfaz grafica en el navegador (abre un puerto local)
    firmascope options            listar las opciones configurables
    firmascope credentials new    generar una credencial sintetica de laboratorio
    firmascope rules              listar el catalogo de reglas
    firmascope labs list|serve    aplicaciones de laboratorio
    firmascope verify DIR         verificar la cadena de evidencias de un expediente
    firmascope version

``firmascope audit`` no exige ningun argumento. Si hay terminal, abre un
asistente que pregunta todo lo que define la auditoria -- sitio, nivel, tipo de
credencial, aislamiento de red -- y permite revisarlo y corregirlo antes de
arrancar. Los argumentos de linea de comandos siguen funcionando, pero ahora
*precargan* las respuestas del asistente en lugar de ser la unica forma de
indicarlas; con ``--no-interactive`` no se pregunta nada, para guiones.

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
from typing import Any

from .. import __version__
from ..audit_core.events import Event, EventType
from ..audit_core.options import SetupResult, build_setup, defaults, needs_password, schema
from ..audit_core.orchestrator import AuditSession
from ..browser_controller.isolation import Stage, StageAction
from . import wizard

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
    print(f"  · {event.type.value:<18} {detail:<44} {tags}", flush=True)


def _banner(stage: Stage, index: int, total: int, network: str) -> None:
    print()
    print(f"── Etapa {index + 1}/{total}: {stage.title}  [red: {network}] "
          + "─" * max(0, 24 - len(stage.title)))
    print(f"   {stage.instruction}")
    if stage.irreversible_note:
        print(f"   aviso: {stage.irreversible_note}")
    options = ["next", "retry", "cancel"]
    if stage.allow_back and index > 0:
        options.insert(1, "back")
    print(f"   acciones: {' | '.join(options)}   (o url/offline/online/config/status/help)")


HELP_TEXT = """
  next   / n    continuar a la siguiente etapa
  back   / b    regresar a la etapa anterior
  retry  / r    repetir esta etapa
  cancel / q    cancelar el proceso y cerrar el expediente
  url <URL>     abrir una pagina en el navegador auditado
  offline       cortar la red ahora (sin cambiar de etapa)
  online        restablecer la red ahora
  config        cambiar opciones modificables en marcha (aislamiento, permitidos)
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

    def __init__(self, session: AuditSession, credential: Any = None):
        self.session = session
        self.credential = credential

    def _credential_hint(self, stage: Stage) -> None:
        """Al llegar a la firma, recuerda que material usar.

        Es el momento en que la especificacion muestra "Private-key input
        detected": el operador tiene que elegir un archivo, y lo que necesita en
        pantalla es la ruta del material de prueba, no un menu.
        """
        if stage.name != "sign" or self.credential is None:
            return
        if self.credential.synthetic:
            print("   Use la credencial sintetica de laboratorio:")
            print(f"     .cer  {self.credential.cert_path}")
            print(f"     .key  {self.credential.key_path}")
            print(f"     clave {self.credential.password}")
        else:
            print("   Use su propia credencial. FirmaScope ya conoce sus "
                  "representaciones y detectara si sale del navegador.")

    def __call__(self, stage: Stage, index: int, test) -> StageAction:
        total = len(test.stages)
        _banner(stage, index, total, test.isolation.network_state)
        self._credential_hint(stage)
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
            if command in ("config", "opciones", "options"):
                wizard.live_menu(self.session.config)
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

def _seed_from_args(args: argparse.Namespace) -> dict[str, Any]:
    """Traduce los argumentos indicados a respuestas del esquema.

    Solo se siembra lo que el operador escribio de verdad: lo demas lo aporta el
    esquema como valor por defecto, de modo que el asistente no presente como
    elegido algo que nadie eligio.
    """
    seed: dict[str, Any] = {}
    direct = {
        "url": "target", "level": "level", "credentials": "credentials",
        "key": "key_path", "cert": "cert_path", "isolation": "isolation",
        "output": "output_dir", "note": "note", "session": "session_file",
    }
    for flag, option_id in direct.items():
        value = getattr(args, flag, None)
        if value:
            seed[option_id] = value
    if getattr(args, "allow_host", None):
        seed["allow_hosts"] = list(args.allow_host)
    if getattr(args, "first_party", None):
        seed["first_party"] = list(args.first_party)
    if getattr(args, "no_offline_flag", False):
        seed["emulate_offline_flag"] = False
    if getattr(args, "capture_bodies", False):
        seed["capture_bodies"] = True
    if getattr(args, "headless", False):
        seed["headless"] = True
    if getattr(args, "i_accept_real_credential_risk", False):
        seed["accept_real_risk"] = True
    if getattr(args, "auto", False):
        seed["autopilot"] = True
    return seed


def _resolve_setup(args: argparse.Namespace) -> SetupResult | None:
    """Obtiene la configuracion: por asistente interactivo o desde argumentos."""
    seed = _seed_from_args(args)
    # El piloto automatico existe para no tener a nadie delante: preguntar la
    # configuracion por terminal le quitaria el sentido.
    interactive = (not args.no_interactive and not getattr(args, "auto", False)
                   and wizard.interactive_possible())

    if interactive:
        return wizard.run_setup(seed)

    # Modo no interactivo: el esquema aporta los valores por defecto.
    answers = defaults()
    answers.update(seed)

    if getattr(args, "auto", False):
        # En el asistente, desactivar un campo que quedo oculto es lo correcto:
        # el operador cambio de idea. Aqui `--auto` es una orden explicita, y
        # descartarla en silencio para seguir en modo interactivo -- sin nadie
        # delante -- seria peor que negarse.
        from ..audit_core.config import CredentialMode
        from ..browser_controller.autopilot import AutopilotRefused, check_allowed

        try:
            check_allowed(CredentialMode.parse(str(answers.get("credentials") or "synthetic")))
        except (AutopilotRefused, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return None
    password = None
    if needs_password(answers):
        password = getpass.getpass("Contrasena de la clave privada: ")
    try:
        return build_setup(answers, password)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        if "Acepto los riesgos" in str(exc):
            print("Anada --i-accept-real-credential-risk, o configure de forma "
                  "interactiva sin --no-interactive.", file=sys.stderr)
        return None


def cmd_audit(args: argparse.Namespace) -> int:
    if getattr(args, "panel", False):
        # Los argumentos indicados precargan el formulario del panel, como
        # precargan el asistente de texto.
        return cmd_panel(args)
    setup = _resolve_setup(args)
    if setup is None:
        return 2
    config = setup.config
    password = setup.password
    if getattr(args, "no_sandbox", False):
        config.sandbox = False
    if getattr(args, "dwell", None) is not None:
        config.dwell = float(args.dwell)
    if getattr(args, "offline_dwell", None) is not None:
        config.offline_dwell = float(args.offline_dwell)

    session = AuditSession(config, on_event=_print_event)
    print(f"FirmaScope {__version__} · sesion {session.session_id}")
    print(f"Expediente: {session.root}")

    aborted = False
    reason = ""
    package = session.root
    try:
        credential = session.prepare_credentials(
            key_path=setup.key_path,
            cert_path=setup.cert_path,
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
        if config.autopilot:
            from ..browser_controller.autopilot import Autopilot

            print("\nPiloto automatico: las etapas avanzan solas.")
            controller = Autopilot(session, config.dwell, config.offline_dwell)
        else:
            controller = InteractiveStageController(session, credential)
        result = test.run(controller)
        if config.autopilot and not controller.signed:
            print("aviso: no se pudo disparar la firma en el portal "
                  f"({'; '.join(controller.notes) or 'formulario no reconocido'}). "
                  "Las reglas que dependen del material privado seran INCONCLUSIVE.")
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


def cmd_login(args: argparse.Namespace) -> int:
    """Inicio de sesion a mano, fuera de la auditoria."""
    from ..audit_core.config import QUIET_BROWSER_ARGS, default_chromium_path, normalize_url
    from ..browser_controller.session import capture_session, default_session_path

    url = normalize_url(args.url)
    target = Path(args.save).expanduser() if args.save else default_session_path(url)
    print("Se abrira un navegador sin instrumentar. Inicie sesion en el portal como")
    print("siempre. FirmaScope no ve su contrasena: solo guarda las cookies y el")
    print("almacenamiento local de la sesion resultante.")

    def wait_for_enter(_page) -> None:
        input("\nCuando haya iniciado sesion, pulse Enter aqui... ")

    try:
        summary = capture_session(
            url, target, wait_for_enter, browser_path=default_chromium_path(),
            browser_args=list(QUIET_BROWSER_ARGS),
            sandbox=False if args.no_sandbox else None)
    except (KeyboardInterrupt, EOFError):
        print("\nCancelado: no se guardo nada.")
        return 130
    except Exception as exc:
        print(f"error: no se pudo guardar la sesion: {exc}", file=sys.stderr)
        return 1

    domains = ", ".join(summary["cookie_domains"]) or "ningun dominio"
    print(f"\nSesion guardada en {target} (permisos 0600): "
          f"{summary['cookies']} cookies de {domains}.")
    if not summary["cookies"]:
        print("aviso: no se guardo ninguna cookie; compruebe que el inicio de sesion termino.")
    print("Este fichero permite entrar en su cuenta mientras la sesion siga activa.")
    print("No lo copie a ningun repositorio; al terminar, cierre la sesion en el portal")
    print("y borre el fichero.")
    print(f"\nPara auditar con ella:  firmascope audit {url} --session {target}")
    return 0


def cmd_panel(args: argparse.Namespace) -> int:
    """La interfaz grafica servida en 127.0.0.1, para abrirla en el navegador.

    Es la misma interfaz y el mismo puente que la aplicacion de escritorio; lo
    que cambia es el transporte, y con el, el riesgo: un puerto local.
    """
    import textwrap
    import webbrowser

    from ..gui_bridge.bridge import Bridge
    from ..gui_bridge.panel import PANEL_WARNING, PanelServer

    bridge = Bridge(seed=_seed_from_args(args), notice=PANEL_WARNING)
    try:
        server = PanelServer(bridge, port=getattr(args, "port", 0) or 0).start()
    except OSError as exc:
        print(f"error: no se pudo abrir el panel: {exc}", file=sys.stderr)
        return 1

    rule = "!" * 78
    print(rule)
    for line in textwrap.wrap(PANEL_WARNING, 76):
        print(f"! {line}")
    print(rule)
    print()
    print(f"Panel: {server.url}")
    print("La direccion sirve una sola vez: si la abre otro, usted vera 'codigo")
    print("invalido' y sabra que alguien se adelanto. Cierre el panel y vuelva a abrirlo.")
    if not getattr(args, "no_browser", False):
        webbrowser.open(server.url)
    print("Ctrl-C para cerrar el panel (cierra tambien el expediente en curso).")

    try:
        server.serve()
    except KeyboardInterrupt:
        print("\nCerrando el panel...")
    finally:
        if not bridge.closed:
            bridge.handle({"id": 0, "cmd": "shutdown"})
        server.stop()
    if bridge.package is not None:
        print(f"Expediente: {bridge.package}")
    return 0


def cmd_credentials_new(args: argparse.Namespace) -> int:
    from ..credentials import generate

    credential = generate(password=args.password or None, key_format=args.format)
    directory = Path(args.output)
    credential.write(directory, stem=args.stem)
    print("Credencial sintetica de laboratorio:")
    print(f"  .cer         {credential.cert_path}")
    print(f"  .key         {credential.key_path}")
    print(f"  contrasena   {credential.password}")
    print(f"  sujeto       {credential.subject}")
    print()
    print("No es un certificado del SAT y no pretende serlo. Uselo para probar")
    print("portales de firma sin exponer su e.firma.")
    return 0


def cmd_options(args: argparse.Namespace) -> int:
    """Muestra las opciones que la interfaz puede ofrecer.

    Con ``--json`` vuelca el esquema tal cual: es el contrato que consume una
    interfaz grafica para pintar los mismos campos que el asistente de texto,
    sin duplicar la lista de opciones ni sus valores por defecto.
    """
    items = schema()
    if args.json:
        print(json.dumps(items, indent=2, ensure_ascii=False, default=str))
        return 0

    for group in ("basico", "avanzado"):
        rows = [item for item in items if item["group"] == group]
        if not rows:
            continue
        print(f"[{group}]")
        for item in rows:
            marks = []
            if item["required"]:
                marks.append("obligatorio")
            if item["conditional"]:
                marks.append("condicional")
            if item["live"]:
                marks.append("modificable en marcha")
            suffix = f"  ({', '.join(marks)})" if marks else ""
            default = item["default"]
            shown = default if default not in (None, "", [], ()) else "-"
            print(f"  {item['id']:<22} {item['kind']:<7} {str(shown):<12} "
                  f"{item['label']}{suffix}")
            for choice in item["choices"]:
                flag = "  [requiere confirmacion]" if choice["danger"] else ""
                print(f"      - {choice['value']:<12} {choice['label']}{flag}")
        print()
    print("Todas se preguntan en el asistente de 'firmascope audit'. Los "
          "argumentos de linea de comandos solo precargan la respuesta.")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    from ..rule_engine.engine import RuleEngine

    engine = RuleEngine(extra_dirs=[Path(d) for d in (args.rules or [])])
    selected = [m for m in engine.rules
                if not args.category or m.category == args.category]
    if args.json:
        print(json.dumps([
            {"id": m.id, "title": m.title, "category": m.category,
             "severity": m.severity.value, "summary": m.summary}
            for m in selected], indent=2, ensure_ascii=False))
        return 0
    for meta in selected:
        print(f"{meta.id:<16} {meta.severity.value:<9} {meta.category:<9} {meta.title}")
        if args.verbose:
            print(f"    {meta.summary}")
    return 0


def cmd_labs_list(args: argparse.Namespace) -> int:
    from ..labs import server as lab

    apps = sorted(p.name for p in lab.APPS.iterdir()
                  if p.is_dir() and p.name.startswith("demo-"))
    for name in apps:
        print(f"{name:<30} http://127.0.0.1:{lab.PORTAL_PORT}/{name}/")
    print(f"\nrecolector de terceros: http://127.0.0.1:{lab.COLLECTOR_PORT}/")
    return 0


def cmd_labs_serve(args: argparse.Namespace) -> int:
    import threading

    from ..labs import server as lab

    portal, collector = lab.serve(args.port, args.collector_port)
    print(f"portal      http://127.0.0.1:{portal.server_address[1]}/")
    print(f"recolector  http://127.0.0.1:{collector.server_address[1]}/")
    print("Aplicaciones de laboratorio: no use credenciales reales con ellas.")
    print("Ctrl-C para terminar.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print()
    finally:
        portal.shutdown()
        collector.shutdown()
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
    culprit = store.event_at(broken) if broken is not None else None
    store.close()

    print(f"Expediente: {root}")
    print(f"Sesion:     {info.get('id', root.name)}")
    print(f"Objetivo:   {info.get('target', '')}")
    if ok:
        print("Cadena de evidencias: INTACTA")
        return 0
    print(f"Cadena de evidencias: ROTA a partir del evento seq={broken}")
    if culprit:
        print(f"  evento: {culprit['type']}  id={culprit['id']}  "
              f"sensor={culprit['sensor']}")
    print("El expediente fue modificado despues de generarse. Los registros")
    print("anteriores a ese punto siguen siendo verificables; los posteriores no.")
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
    audit.add_argument("--level", default=None,
                       help="nivel de auditoria: 1 red, 2 codigo, 3 offline, 4 completo")
    audit.add_argument("--credentials", default=None,
                       help="synthetic | own-test | real | none")
    audit.add_argument("--key", default=None, help="ruta del archivo .key")
    audit.add_argument("--cert", default=None, help="ruta del archivo .cer")
    audit.add_argument("--credentials-dir", default=None,
                       help="donde escribir la credencial sintetica generada")
    audit.add_argument("--i-accept-real-credential-risk", action="store_true",
                       help="requerido por --credentials real")
    audit.add_argument("--isolation", default=None,
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
    audit.add_argument("--output", default=None, help="directorio de expedientes")
    audit.add_argument("--note", default=None,
                       help="etiqueta libre para identificar la prueba")
    audit.add_argument("--session", default=None,
                       help="sesion del portal guardada con 'firmascope login'")
    audit.add_argument("--no-sandbox", action="store_true",
                       help="desactivar el sandbox de Chromium. Solo si el sistema no lo "
                            "admite: el sitio auditado queda menos aislado del equipo.")
    audit.add_argument("--auto", action="store_true",
                       help="piloto automatico: recorre las etapas y rellena el "
                            "formulario con la credencial sintetica. Solo con "
                            "credencial sintetica.")
    audit.add_argument("--dwell", type=float, default=None,
                       help="segundos por etapa en piloto automatico (3)")
    audit.add_argument("--offline-dwell", type=float, default=None,
                       help="segundos en la etapa de firma en piloto automatico (4)")
    audit.add_argument("--panel", action="store_true",
                       help="abrir la interfaz grafica en el navegador en lugar del "
                            "asistente de texto. Abre un puerto local: ver 'panel --help'.")
    audit.add_argument("--no-interactive", action="store_true",
                       help="no preguntar nada: usar los argumentos y los valores por "
                            "defecto del esquema. Para guiones y canalizaciones.")
    audit.set_defaults(func=cmd_audit)

    login = sub.add_parser(
        "login", help="iniciar sesion en el portal a mano y guardar la sesion",
        epilog="El fichero guardado permite entrar en la cuenta mientras la sesion siga "
               "activa: guardelo fuera de cualquier repositorio y borrelo al terminar.")
    login.add_argument("url", help="URL de inicio de sesion del portal")
    login.add_argument("--save", default=None, metavar="FICHERO",
                       help="donde guardar la sesion (por defecto, "
                            "~/.firmascope/sesiones/<host>.json)")
    login.add_argument("--no-sandbox", action="store_true",
                       help="desactivar el sandbox de Chromium (ver 'audit --help')")
    login.set_defaults(func=cmd_login)

    panel = sub.add_parser(
        "panel", help="la interfaz grafica en el navegador (abre un puerto local)",
        description="Sirve en 127.0.0.1 la misma interfaz que la aplicacion de "
                    "escritorio, para usarla sin compilarla.",
        epilog="Riesgo: el panel abre un puerto local, alcanzable por cualquier "
               "pagina o programa del equipo. Lo protegen un codigo de un solo uso, "
               "un token y comprobaciones de origen, pero no lo use en un equipo "
               "compartido. La aplicacion de escritorio no abre ningun puerto.")
    panel.add_argument("url", nargs="?", default=None,
                       help="sitio a auditar; puede indicarse despues en la pagina")
    panel.add_argument("--port", type=int, default=0,
                       help="puerto local (por defecto, uno libre al azar)")
    panel.add_argument("--no-browser", action="store_true",
                       help="no abrir el navegador; solo imprimir la direccion")
    panel.set_defaults(func=cmd_panel)

    creds = sub.add_parser("credentials", help="credenciales sinteticas de laboratorio")
    creds_sub = creds.add_subparsers(dest="action", required=True)
    creds_new = creds_sub.add_parser("new", help="generar una credencial nueva")
    creds_new.add_argument("-o", "--output", default="fixtures/synthetic-efirma",
                           help="directorio donde escribir .key y .cer")
    creds_new.add_argument("--password", default=None,
                           help="contrasena fija, para pruebas repetibles")
    creds_new.add_argument("--stem", default="audit",
                           help="nombre base de los archivos (audit.key, audit.cer)")
    creds_new.add_argument("--format", choices=("sat", "aes"), default="sat",
                           help="cifrado del .key: sat (3DES, como una e.firma real; por "
                                "omision) o aes")
    creds_new.set_defaults(func=cmd_credentials_new)

    options_cmd = sub.add_parser(
        "options", help="listar las opciones configurables desde la interfaz")
    options_cmd.add_argument("--json", action="store_true",
                             help="volcar el esquema para una interfaz grafica")
    options_cmd.set_defaults(func=cmd_options)

    rules = sub.add_parser("rules", help="listar el catalogo de reglas")
    rules.add_argument("--category", default=None,
                       help="efirma | crypto | network | storage | code")
    rules.add_argument("-v", "--verbose", action="store_true")
    rules.add_argument("--json", action="store_true", help="salida JSON")
    rules.add_argument("--rules", action="append", default=[],
                       help="directorio adicional con paquetes de reglas YAML")
    rules.set_defaults(func=cmd_rules)

    labs = sub.add_parser("labs", help="aplicaciones de laboratorio")
    labs_sub = labs.add_subparsers(dest="action", required=True)
    labs_list = labs_sub.add_parser("list", help="listar las aplicaciones")
    labs_list.set_defaults(func=cmd_labs_list)
    labs_serve = labs_sub.add_parser("serve", help="servir el laboratorio")
    labs_serve.add_argument("--port", type=int, default=8765)
    labs_serve.add_argument("--collector-port", type=int, default=8766)
    labs_serve.set_defaults(func=cmd_labs_serve)

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
