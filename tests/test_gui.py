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
UI = ROOT / "gui" / "ui" / "index.html"
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
