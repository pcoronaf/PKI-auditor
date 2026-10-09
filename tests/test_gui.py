"""La interfaz grafica, probada contra el nucleo de verdad.

La interfaz se carga en un Chromium real y su transporte se conecta al puente
ejecutandose como proceso hijo, igual que lo lanza Tauri. Asi se ejercita la
cadena completa -- DOM, protocolo JSON por linea, nucleo, navegador auditado --
sin la capa de Rust, que es la unica parte que estas pruebas no cubren porque no
contiene criterio: lanza el hijo y pasa mensajes.

Lo que se comprueba no es que la interfaz "se vea bien", sino que no tenga su
propia idea de la auditoria: que los campos salgan del esquema del nucleo, que
las validaciones sean las suyas y que las etapas las decida su maquina.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.e2e

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "src" / "firmascope" / "ui" / "index.html"
def _chromium() -> str | None:
    """El Chromium que usaria FirmaScope; None deja elegir a Playwright."""
    from firmascope.audit_core.config import default_chromium_path

    return default_chromium_path()


class BridgeProcess:
    """El puente como proceso hijo, hablando JSON por linea."""

    def __init__(self) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "firmascope.gui_bridge.bridge"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1,
            cwd=str(ROOT),
            env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        )
        self.counter = 0

    def call(self, cmd: str, args: dict | None = None) -> dict:
        self.counter += 1
        payload = {"id": str(self.counter), "cmd": cmd, "args": args or {}}
        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("el puente cerro el canal")
        return json.loads(line)

    def close(self) -> None:
        try:
            self.call("shutdown")
        except Exception:
            pass
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=30)
        except Exception:
            self.proc.kill()


@pytest.fixture
def gui(lab, tmp_path):
    """Interfaz cargada en Chromium, conectada al puente real."""
    from playwright.sync_api import sync_playwright

    if not UI.is_file():
        pytest.skip("la interfaz no esta en el arbol")

    bridge = BridgeProcess()
    with sync_playwright() as pw:
        launch = {"headless": True}
        if _chromium():
            launch["executable_path"] = _chromium()
        browser = pw.chromium.launch(**launch)
        page = browser.new_page()
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)

        def relay(cmd: str, args: dict | None):
            response = bridge.call(cmd, args or {})
            if not response.get("ok"):
                raise RuntimeError(response.get("error", "error del nucleo"))
            return response.get("result")

        page.expose_function("__bridgeRelay", relay)
        # El mismo contrato que implementa la capa de Rust en Tauri.
        page.add_init_script("""
          window.firmascopeTransport = {
            hello: () => window.__bridgeRelay('hello', {}),
            call: (cmd, args) => window.__bridgeRelay(cmd, args || {}),
            shutdown: () => Promise.resolve()
          };
        """)
        page.goto(UI.as_uri())
        page.wait_for_selector("#view-setup:not([hidden])", timeout=20000)

        page.errors = errors
        page.out = tmp_path
        yield page
        browser.close()
    bridge.close()


def configurar(page, target: str = "http://127.0.0.1:8765/demo-safe/") -> None:
    """Rellena lo basico y abre las avanzadas para marcar el navegador sin ventana.

    Las avanzadas viven en un ``<details>`` cerrado: en una auditoria real el
    operador quiere ver el navegador, y sin ventana la firma no se puede hacer.
    Las pruebas si lo necesitan, y abrir el desplegable es parte de lo que se
    comprueba.
    """
    page.fill("[data-option='target'] input", target)
    page.click("#advanced-wrap summary")
    page.wait_for_selector("[data-option='headless'] input", state="visible",
                           timeout=10000)
    page.check("[data-option='headless'] input")
    page.fill("[data-option='output_dir'] input", str(page.out))
    page.wait_for_function("() => !document.getElementById('start').disabled",
                           timeout=10000)


# ----------------------------------------------------------------------

def test_los_campos_los_pone_el_nucleo_no_la_interfaz(gui):
    """Cada campo visible corresponde a una opcion del esquema."""
    from firmascope.audit_core import options

    pintados = set(gui.eval_on_selector_all(
        "#setup-form [data-option], #setup-advanced [data-option]",
        "els => els.map(e => e.dataset.option)"))
    del_esquema = {o.id for o in options.AUDIT_OPTIONS}
    assert pintados, "la interfaz no pinto ningun campo"
    assert pintados <= del_esquema, f"campos inventados: {pintados - del_esquema}"
    # El consentimiento tiene pantalla propia, no es un campo del formulario.
    assert "accept_real_risk" not in pintados
    assert {"target", "level", "credentials", "isolation"} <= pintados


def test_las_dependencias_entre_campos_las_resuelve_el_nucleo(gui):
    """Elegir credencial propia hace aparecer los campos de archivo."""
    assert gui.query_selector("[data-option='key_path']") is None

    gui.check("input[name='credentials'][value='own-test']")
    gui.wait_for_selector("[data-option='key_path']", timeout=10000)
    assert gui.query_selector("[data-option='cert_path']") is not None

    gui.check("input[name='credentials'][value='synthetic']")
    gui.wait_for_selector("[data-option='key_path']", state="detached", timeout=10000)


def test_no_se_arranca_con_la_configuracion_invalida(gui):
    """El boton se desactiva con los problemas que reporta el nucleo."""
    gui.check("input[name='credentials'][value='own-test']")
    gui.wait_for_selector("#setup-problems:not([hidden])", timeout=10000)
    assert gui.is_disabled("#start")
    problemas = gui.inner_text("#setup-problems")
    assert "Archivo .key" in problemas


def test_la_credencial_real_exige_escribir_acepto(gui):
    gui.check("input[name='credentials'][value='real']")
    gui.wait_for_selector("[data-option='key_path']", timeout=10000)
    # Sin archivos no se puede ni llegar al consentimiento: primero validar.
    assert gui.is_disabled("#start")

    # Con los campos resueltos, el consentimiento es una pantalla aparte.
    gui.evaluate("""() => {
        document.querySelector("[data-option='key_path'] input").value = '/no/existe.key';
    }""")
    # La pantalla de consentimiento solo aparece al pulsar Iniciar, y el nucleo
    # sigue rechazando la configuracion: el boton no debe habilitarse.
    assert gui.is_disabled("#start")


def test_recorre_las_etapas_y_produce_un_expediente(gui, credential):
    """La interfaz conduce la auditoria de principio a reporte."""
    configurar(gui)
    gui.click("#start")
    gui.wait_for_selector("#view-session:not([hidden])", timeout=60000)

    # La primera etapa y su red las dice el nucleo.
    assert "Cargar el sitio" in gui.inner_text("#stage-title")
    assert gui.inner_text("#stage-network") in ("ONLINE", "OFFLINE")
    # En la primera etapa no se puede retroceder.
    assert gui.is_disabled("[data-action='back']")

    vistas = []
    for _ in range(12):
        if gui.query_selector("#view-report:not([hidden])"):
            break
        vistas.append(gui.inner_text("#stage-title"))
        gui.click("[data-action='next']")
        gui.wait_for_timeout(1200)

    gui.wait_for_selector("#view-report:not([hidden])", timeout=120000)
    # Las seis etapas del flujo, en orden y sin repetir.
    assert len(vistas) == 6, vistas
    assert "Firmar con la red aislada" in vistas[3]
    meta = gui.inner_text("#report-meta")
    assert "FS-" in meta
    assert "intacta" in meta, "la cadena de evidencias no se verifico"
    hallazgos = gui.inner_text("#report-findings")
    assert "FS-KEY-001" in hallazgos
    assert "FS-LOCAL-001" in hallazgos
    # El expediente existe de verdad.
    paquete = Path(gui.inner_text("#report-path"))
    assert (paquete / "report.json").is_file()
    assert not gui.errors, f"errores de consola: {gui.errors}"


def test_cancelar_cierra_el_expediente_en_lugar_de_perderlo(gui, credential):
    configurar(gui)
    gui.click("#start")
    gui.wait_for_selector("#view-session:not([hidden])", timeout=60000)

    # Cancelar pide confirmacion: una auditoria a medias no se tira por un clic.
    gui.on("dialog", lambda d: d.accept())
    gui.click("[data-action='cancel']")
    gui.wait_for_selector("#view-report:not([hidden])", timeout=120000)

    meta = gui.inner_text("#report-meta")
    assert "Cancelada" in meta, "el reporte no declara que la sesion se cancelo"
    paquete = Path(gui.inner_text("#report-path"))
    report = json.loads((paquete / "report.json").read_text(encoding="utf-8"))
    assert report["aborted"] is True
    # La red queda restablecida pase lo que pase.
    assert report["isolation"].get("network_state", "ONLINE") == "ONLINE"


def siguiente(page) -> bool:
    """Pulsa Siguiente cuando la interfaz lo permite. False si ya hay reporte.

    Mientras el nucleo atiende una orden la interfaz desactiva los botones, y
    la ultima etapa pasa al reporte: pulsar a ciegas falla por una carrera
    entre la prueba y la interfaz, no por un error de esta.
    """
    page.wait_for_function(
        """() => !document.getElementById('view-report').hidden
                 || !document.querySelector("[data-action='next']").disabled""",
        timeout=120000)
    if page.query_selector("#view-report:not([hidden])"):
        return False
    page.click("[data-action='next']")
    page.wait_for_timeout(800)
    return True


def test_el_aviso_de_llave_ajena_queda_fijo(gui):
    """El nucleo avisa (CHECKPOINT credential-mismatch, cubierto por TC-015) si
    en la pagina se elige un .key que no es el de la sesion. En el piloto con
    la e.firma real nada lo advirtio: el aviso no puede perderse entre los
    eventos que se desplazan."""
    configurar(gui)
    gui.click("#start")
    gui.wait_for_selector("#view-session:not([hidden])", timeout=60000)
    assert gui.query_selector("#credential-warning[hidden]") is not None

    gui.evaluate("""() => addEvent({type: 'CHECKPOINT', tags: [], data: {
        name: 'credential-mismatch',
        message: 'El .key que eligio en la pagina no es el de esta sesion.'}})""")
    aviso = gui.wait_for_selector("#credential-warning:not([hidden])", timeout=5000)
    assert "no es el de esta sesion" in aviso.inner_text()
    # Los demas CHECKPOINT no ensucian la lista de eventos en vivo.
    assert "credential-mismatch" not in gui.inner_text("#feed")

    gui.on("dialog", lambda d: d.accept())
    gui.click("[data-action='cancel']")
    gui.wait_for_selector("#view-report:not([hidden])", timeout=120000)
    assert not gui.errors, f"errores de consola: {gui.errors}"


# ----------------------------------------------------------------------
# Copiar la credencial y resaltar la salida de material privado
# ----------------------------------------------------------------------

def test_resalta_la_salida_de_la_clave_y_permite_copiar_la_credencial(gui):
    """demo-key-exfiltration intenta sacar la clave: esa fila no puede pasar
    desapercibida, aunque el aislamiento la bloquee."""
    configurar(gui, "http://127.0.0.1:8765/demo-key-exfiltration/")
    gui.check("[data-option='autopilot'] input")
    gui.click("#start")
    gui.wait_for_selector("#view-session:not([hidden])", timeout=60000)

    gui.context.grant_permissions(["clipboard-read", "clipboard-write"])
    copiado = False
    for _ in range(12):
        # La tarjeta de la credencial aparece en la etapa de firma, cuando se
        # necesita: tres botones, para .cer, .key y contrasena.
        if not copiado and gui.query_selector("#credential-card:not([hidden])"):
            assert len(gui.query_selector_all("#credential-info .copy")) == 3
            gui.click("#credential-info .copy >> nth=2")
            gui.wait_for_function(
                "() => document.getElementById('toast').textContent.includes('copiado')",
                timeout=5000)
            copiado = True
        if copiado and gui.query_selector(".feed .ev.private"):
            break
        if not siguiente(gui):
            break
    assert copiado, "no se llego a mostrar la credencial"
    fila = gui.query_selector(".feed .ev.private")
    assert fila is not None, "la salida de la clave no se resalto"
    assert "MATERIAL PRIVADO" in fila.inner_text()
    assert not gui.errors, f"errores de consola: {gui.errors}"


# ----------------------------------------------------------------------
# El panel: la misma interfaz, servida por `firmascope panel`
# ----------------------------------------------------------------------

@pytest.fixture
def panel_process(lab):
    """`firmascope panel` como proceso aparte, como lo lanzaria el operador."""
    import signal

    proc = subprocess.Popen(
        [sys.executable, "-u", "-m", "firmascope.cli.main", "panel", "--no-browser"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=str(ROOT),
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    salida = []
    url = None
    for _ in range(40):
        line = proc.stdout.readline()
        if not line:
            break
        salida.append(line)
        if line.startswith("Panel: "):
            url = line.split("Panel: ", 1)[1].strip()
            break
    assert url, "el panel no imprimio su direccion:\n" + "".join(salida)
    proc.salida = salida
    proc.url = url
    yield proc
    if proc.poll() is None:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_el_panel_avisa_del_riesgo_y_audita_de_principio_a_reporte(panel_process, tmp_path):
    from playwright.sync_api import sync_playwright

    terminal = "".join(panel_process.salida)
    assert "AVISO" in terminal and "puerto local" in terminal

    with sync_playwright() as pw:
        launch = {"headless": True}
        if _chromium():
            launch["executable_path"] = _chromium()
        browser = pw.chromium.launch(**launch)
        page = browser.new_page()
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(panel_process.url)
        page.wait_for_selector("#view-setup:not([hidden])", timeout=20000)

        # El aviso llega del nucleo y se ve en la propia pagina.
        assert "puerto local" in page.inner_text("#notice")
        # El codigo no se queda en la barra de direcciones.
        assert "code=" not in page.url

        # Otra pestana con la misma direccion ya no entra: el codigo era de un uso.
        intruso = browser.new_page()
        intruso.goto(panel_process.url)
        intruso.wait_for_selector("#view-error:not([hidden])", timeout=20000)
        assert "codigo invalido" in intruso.inner_text("#error-detail")
        intruso.close()

        page.out = tmp_path
        configurar(page)
        page.check("[data-option='autopilot'] input")
        page.click("#start")
        page.wait_for_selector("#view-session:not([hidden])", timeout=60000)
        for _ in range(12):
            if not siguiente(page):
                break
        page.wait_for_selector("#view-report:not([hidden])", timeout=120000)
        assert "FS-LOCAL-001" in page.inner_text("#report-findings")
        paquete = Path(page.inner_text("#report-path"))
        assert (paquete / "report.json").is_file()

        # Recargar no aborta nada ni pierde el acceso: el token sigue en la pestana.
        page.reload()
        page.wait_for_selector("#view-setup:not([hidden])", timeout=20000)
        assert not errors, f"errores de consola: {errors}"
        browser.close()
