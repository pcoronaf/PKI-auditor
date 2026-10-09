"""Pruebas de extremo a extremo contra el laboratorio (TC-001 .. TC-011).

Son las unicas pruebas que pueden responder si FirmaScope *funciona*: lanzan un
Chromium real contra las aplicaciones de laboratorio y comparan los hallazgos
con la verdad conocida, que el propio laboratorio registra -- si el recolector
de terceros recibio los bytes o no.

Esa comparacion es lo que distingue una prueba de una ilusion: un informe que
dice "la clave salio" es correcto solo si el recolector la tiene, y uno que dice
"se impidio" es correcto solo si no la tiene.
"""

from __future__ import annotations

import base64
import json
import urllib.parse

import pytest

from firmascope.audit_core.config import (
    AuditConfig,
    IsolationMode,
    IsolationPolicy,
    ProxyConfig,
    proxy_available,
)
from firmascope.audit_core.orchestrator import AuditSession
from firmascope.browser_controller.isolation import StageAction

pytestmark = pytest.mark.e2e


def run_audit(app: str, output_dir, credential, *, isolation: str = "full",
              credentials_dir=None, level: int = 4, proxy: bool | None = None):
    """Audita una aplicacion de laboratorio de principio a expediente."""
    config = AuditConfig(
        target=f"http://127.0.0.1:8765/{app}/",
        headless=True,
        output_dir=output_dir,
        note=f"prueba {app}",
        level=level,
        isolation=IsolationPolicy(mode=IsolationMode.parse(isolation)),
        proxy=ProxyConfig(enabled=proxy),
    )
    session = AuditSession(config)

    def drive(stage, index, test):
        page = session.controller.page
        if stage.name == "prepare":
            page.wait_for_selector("#sign", timeout=15000)
        elif stage.name == "sign":
            page.set_input_files("#cer-file", str(credential.cert_path))
            page.set_input_files("#key-file", str(credential.key_path))
            page.fill("#password", credential.password)
            page.click("#sign")
            page.wait_for_timeout(3000)
        elif stage.name == "submit":
            if page.query_selector("#submit:not([hidden])"):
                try:
                    page.click("#submit", timeout=4000)
                except Exception:
                    pass
            page.wait_for_timeout(1500)
        return StageAction.CONTINUE

    try:
        session.prepare_credentials(credentials_dir=credentials_dir)
        # La credencial del laboratorio es la misma en todas las pruebas: se
        # registra en el vault para que los canarios la reconozcan.
        session.credential = credential
        credential.register(session.vault)
        session.start_browser()
        session.navigate(config.target)
        session.controller.staged_offline_test().run(drive)
        session.collect_and_analyze()
        session.evaluate()
    finally:
        package = session.finish()
    return json.loads((package / "report.json").read_text(encoding="utf-8"))


def finding(report, rule_id):
    for item in report["findings"]:
        if item["rule_id"] == rule_id:
            return item
    raise AssertionError(f"la regla {rule_id} no emitio ningun hallazgo")


def status(report, rule_id):
    return finding(report, rule_id)["status"]


def report_requests(output_dir, report):
    """Peticiones del expediente que acompana a este reporte."""
    path = output_dir / report["session"] / "requests.json"
    return json.loads(path.read_text(encoding="utf-8"))


# ----------------------------------------------------------------------

def test_tc001_firma_local_correcta(lab, tmp_path, credential):
    """La aplicacion correcta no debe producir ninguna acusacion."""
    lab.COLLECTED.clear()
    report = run_audit("demo-safe", tmp_path, credential)

    assert not lab.COLLECTED, "el laboratorio registro una salida que no deberia existir"
    assert status(report, "FS-KEY-001") == "NOT_OBSERVED"
    assert status(report, "FS-KEY-002") == "NOT_OBSERVED"
    assert status(report, "FS-PWD-001") == "NOT_OBSERVED"
    # La afirmacion positiva: la firma se produjo con la red cortada.
    assert status(report, "FS-LOCAL-001") == "CONFIRMED"


def test_tc002_exfiltracion_de_clave_detectada(lab, tmp_path, credential):
    """La aplicacion que funciona *y* se lleva la clave."""
    lab.COLLECTED.clear()
    report = run_audit("demo-key-exfiltration", tmp_path, credential,
                       isolation="none")

    assert lab.COLLECTED, "el laboratorio no registro la exfiltracion"
    assert status(report, "FS-KEY-001") == "OBSERVED"
    assert status(report, "FS-PWD-001") == "OBSERVED"
    assert "salio" in finding(report, "FS-KEY-001")["summary"]
    assert status(report, "FS-NET-001") == "OBSERVED"


def test_tc003_el_aislamiento_distingue_lo_impedido_de_lo_consumado(
        lab, tmp_path, credential):
    """El mismo sitio, con la red cortada en la etapa de firma.

    El hallazgo no puede decir que la clave salio, porque no salio. Decirlo
    llevaria a revocar una e.firma sin motivo.
    """
    lab.COLLECTED.clear()
    report = run_audit("demo-key-exfiltration", tmp_path, credential,
                       isolation="full")

    assert not lab.COLLECTED, "el aislamiento no impidio la salida"
    hallazgo = finding(report, "FS-KEY-001")
    assert hallazgo["status"] == "OBSERVED"
    assert "intento" in hallazgo["summary"]
    assert "salio del navegador" not in hallazgo["summary"]
    assert "BLOQUEADO" in hallazgo["detail"]
    assert "[ENVIADO]" not in hallazgo["detail"]
    assert status(report, "FS-LOCAL-001") == "CONFIRMED"


def test_tc004_firma_en_servidor(lab, tmp_path, credential):
    """La arquitectura honesta pero equivocada: multipart con el .key."""
    lab.SERVER_SIDE.clear()
    report = run_audit("demo-server-sign", tmp_path, credential, isolation="none")

    assert lab.SERVER_SIDE, "el servidor no recibio el material"
    assert status(report, "FS-KEY-001") == "OBSERVED"
    assert status(report, "FS-PWD-001") == "OBSERVED"
    # No hubo ninguna firma en el navegador: no se puede confirmar localidad.
    assert status(report, "FS-LOCAL-001") in ("NOT_OBSERVED", "INCONCLUSIVE")
    # El codigo tambien lo dice, no solo el trafico.
    assert status(report, "FS-CODE-001") == "POTENTIAL"


def test_tc005_exfiltracion_cifrada(lab, tmp_path, credential):
    """La clave sale cifrada: el canario no la encuentra, la procedencia si.

    Es el caso que derrota a la inspeccion de red. Lo que se afirma aqui es mas
    debil que en TC-002, y debe serlo: lo que viaja es material derivado.
    """
    lab.COLLECTED.clear()
    report = run_audit("demo-encrypted-exfiltration", tmp_path, credential,
                       isolation="none")

    assert lab.COLLECTED, "el laboratorio no registro ninguna salida"
    assert status(report, "FS-NET-001") == "OBSERVED"
    # El contenido es opaco, asi que la transmision directa no se puede afirmar.
    assert status(report, "FS-KEY-001") == "NOT_OBSERVED"
    # Pero la salida de material derivado del secreto si se observo.
    assert status(report, "FS-PWD-001") == "OBSERVED"


def test_tc006_codigo_que_puede_exfiltrar_sin_hacerlo(lab, tmp_path, credential):
    """Las dos afirmaciones a la vez, y ninguna contradice a la otra.

    Es el proposito de la herramienta: distinguir "no lo observe" de "no puede
    ocurrir". Una inspeccion de red solo puede dar la primera.
    """
    lab.COLLECTED.clear()
    report = run_audit("demo-static-only", tmp_path, credential)

    assert not lab.COLLECTED
    assert status(report, "FS-KEY-001") == "NOT_OBSERVED"
    assert status(report, "FS-CODE-001") == "POTENTIAL"
    detalle = finding(report, "FS-CODE-001")["detail"]
    assert "sendBeacon" in detalle or "fetch" in detalle


@pytest.mark.skipif(not proxy_available(), reason="mitmproxy no esta instalado")
def test_tc007_el_proxy_prueba_el_contenido_que_cdp_no_entrega(
        lab, tmp_path, credential):
    """Nivel 4: la subida multipart del .key, probada por contenido.

    Sin proxy, "el .key salio" descansa en la procedencia que la
    instrumentacion infiere, porque CDP entrega el cuerpo vacio. Con proxy se
    encuentra el canario dentro del cuerpo que viajo de verdad.
    """
    lab.SERVER_SIDE.clear()
    report = run_audit("demo-server-sign", tmp_path, credential,
                       isolation="none", level=4, proxy=True)

    assert lab.SERVER_SIDE, "el servidor no recibio el material"
    assert report["sensors"]["proxy"] is True
    assert report["sensors"]["bodies_recovered_by_proxy"] >= 1, \
        "el proxy no recupero ningun cuerpo que CDP no entregara"

    # La prueba de contenido: el canario aparece en el cuerpo multipart.
    pruebas = [q for q in report_requests(tmp_path, report)
               if q["sensor"] == "proxy" and "KEY_FILE" in q["tags"]]
    assert pruebas, "ninguna peticion del proxy quedo etiquetada con KEY_FILE"
    assert status(report, "FS-KEY-001") == "OBSERVED"


@pytest.mark.skipif(not proxy_available(), reason="mitmproxy no esta instalado")
def test_el_expediente_declara_lo_que_no_pudo_observarse(lab, tmp_path, credential):
    """Sin proxy, el reporte dice que faltó ese sensor en lugar de callarlo."""
    report = run_audit("demo-safe", tmp_path, credential, level=4, proxy=False)
    assert report["sensors"]["proxy"] is False
    assert "limitation" in report["sensors"]
    assert "multipart" in report["sensors"]["limitation"]


def test_el_trafico_del_navegador_no_se_imputa_al_sitio(lab, tmp_path, credential):
    """Chromium habla con sus propios servicios; eso no es del portal.

    Imputarlo convertiria cualquier auditoria en un hallazgo de terceros.
    """
    report = run_audit("demo-safe", tmp_path, credential)
    imputados = set(report["third_parties_after_key_access"])
    for host in report.get("browser_infrastructure", {}):
        assert host not in imputados, f"{host} es del navegador, no del sitio"


def test_el_expediente_es_verificable_y_trae_el_informe(lab, tmp_path, credential):
    from firmascope.evidence_store.store import EvidenceStore

    report = run_audit("demo-safe", tmp_path, credential)
    package = tmp_path / report["session"]
    for name in ("manifest.json", "timeline.json", "requests.json",
                 "findings.json", "report.json", "report.html"):
        assert (package / name).is_file(), f"falta {name} en el expediente"

    store = EvidenceStore(package, report["session"])
    assert store.verify_chain() == (True, None)
    store.close()


# ----------------------------------------------------------------------
# Piloto automatico: la auditoria sin nadie delante
# ----------------------------------------------------------------------

def run_autopilot(app: str, output_dir, *, isolation: str = "full", session_state=None):
    """Audita sin operador, como `firmascope audit URL --auto --headless`."""
    from firmascope.browser_controller.autopilot import Autopilot

    config = AuditConfig(
        target=f"http://127.0.0.1:8765/{app}/",
        headless=True,
        output_dir=output_dir,
        isolation=IsolationPolicy(mode=IsolationMode.parse(isolation)),
        autopilot=True,
        dwell=1.0,
        offline_dwell=3.0,
        session_state=session_state,
    )
    session = AuditSession(config)
    pilot = None
    try:
        session.prepare_credentials(credentials_dir=output_dir / "credenciales")
        session.start_browser()
        session.navigate(config.target)
        pilot = Autopilot(session, config.dwell, config.offline_dwell)
        session.controller.staged_offline_test().run(pilot)
        session.collect_and_analyze()
        session.evaluate()
    finally:
        package = session.finish()
    report = json.loads((package / "report.json").read_text(encoding="utf-8"))
    return report, pilot


def test_tc008_el_piloto_audita_sin_operador(lab, tmp_path):
    """Nadie toca el formulario: lo detecta, lo rellena y firma el piloto.

    Con la red cortada en la etapa de firma, el intento de exfiltracion queda
    bloqueado y el informe lo dice, igual que en TC-003 con operador.
    """
    lab.COLLECTED.clear()
    report, pilot = run_autopilot("demo-key-exfiltration", tmp_path)

    assert pilot.signed, f"el piloto no disparo la firma: {pilot.notes}"
    assert pilot.sent, "el piloto no envio la firma en la etapa de envio"
    assert not lab.COLLECTED, "el aislamiento no impidio la salida"
    hallazgo = finding(report, "FS-KEY-001")
    assert hallazgo["status"] == "OBSERVED"
    assert "intento" in hallazgo["summary"]
    assert status(report, "FS-LOCAL-001") == "CONFIRMED"


def test_el_piloto_no_acusa_a_un_sitio_correcto(lab, tmp_path):
    lab.COLLECTED.clear()
    report, pilot = run_autopilot("demo-safe", tmp_path)
    assert pilot.signed
    assert not lab.COLLECTED
    for regla in ("FS-KEY-001", "FS-KEY-002", "FS-PWD-001"):
        assert status(report, regla) == "NOT_OBSERVED", regla
    assert status(report, "FS-LOCAL-001") == "CONFIRMED"


def test_el_piloto_se_niega_con_una_credencial_que_no_es_sintetica():
    """Rellenar una e.firma propia sin nadie delante no se permite."""
    with pytest.raises(ValueError):
        AuditConfig(target="https://x.mx", credential_mode="own-test", autopilot=True)


# ----------------------------------------------------------------------
# Laboratorios que llegaron con el PR #2
# ----------------------------------------------------------------------

def test_tc009_la_clave_en_un_pixel_se_detecta_y_no_llega_al_expediente(lab, tmp_path):
    """GET sin cuerpo: la clave en la query string de un pixel de seguimiento."""
    lab.COLLECTED.clear()
    report, pilot = run_autopilot("demo-side-channels", tmp_path, isolation="none")

    assert pilot.signed
    assert any("pixel" in c["path"] for c in lab.COLLECTED), "el pixel no salio"
    assert status(report, "FS-KEY-001") == "OBSERVED"
    assert status(report, "FS-PWD-001") == "OBSERVED"

    # La clave salio, pero no puede quedar escrita en el expediente.
    cred_dir = tmp_path / "credenciales"
    key_der = next(cred_dir.glob("*.key")).read_bytes()
    b64 = base64.b64encode(key_der).decode()
    crudo = b"".join(p.read_bytes() for p in (tmp_path / report["session"]).rglob("*")
                     if p.is_file())
    for forma in (b64, urllib.parse.quote(b64, safe=""),
                  urllib.parse.quote(b64, safe="")[200:260]):
        assert forma.encode() not in crudo


def test_tc010_un_worker_instrumentado_sigue_funcionando(lab, tmp_path):
    """La instrumentacion no puede romper el sitio que audita."""
    lab.COLLECTED.clear()
    report, pilot = run_autopilot("demo-worker", tmp_path, isolation="none")

    assert pilot.signed
    assert [c for c in lab.COLLECTED if c["path"] == "/collect/worker"], \
        "el worker no llego a ejecutarse: la instrumentacion lo rompio"
    assert status(report, "FS-KEY-001") == "OBSERVED"


# ----------------------------------------------------------------------
# Portales con inicio de sesion (portado del PR #2)
# ----------------------------------------------------------------------

def capture_lab_session(path):
    """`firmascope login` sobre demo-login, con el operador sustituido por codigo."""
    from firmascope.browser_controller.session import capture_session
    from firmascope.labs import server as lab_server

    def iniciar_sesion(page):
        page.fill("#username", lab_server.LAB_LOGIN_USER)
        page.fill("#account-password", lab_server.LAB_LOGIN_PASSWORD)
        page.click("#login")
        # La aplicacion guarda su token de acceso en localStorage al cargar;
        # la sesion se guarda despues, como haria quien espera a ver el portal.
        page.wait_for_function("localStorage.getItem('access_token') !== null",
                               timeout=15000)

    return capture_session("http://127.0.0.1:8765/demo-login/", path, iniciar_sesion,
                           headless=True)


def test_tc011_auditoria_dentro_de_una_sesion_iniciada(lab, tmp_path):
    """La auditoria corre dentro de la sesion, y la sesion no llega al expediente.

    La verdad conocida es doble: el portal registro pings autenticados (la
    auditoria vio el formulario real, no la pagina de acceso), y ninguna forma
    de la cookie ni del token aparece en ningun fichero del expediente, aunque
    la aplicacion los envia en la cabecera Cookie, en Authorization y en la URL.
    """
    from firmascope.browser_controller.session import load_session_state

    sesion = tmp_path / "sesion.json"
    resumen = capture_lab_session(sesion)
    assert resumen["cookies"] >= 1
    estado = load_session_state(sesion)
    cookie = next(c["value"] for c in estado["cookies"]
                  if c["name"] == lab.LAB_SESSION_COOKIE)
    token = lab.LAB_SESSIONS[cookie]

    lab.COLLECTED.clear()
    lab.LOGIN_PINGS.clear()
    report, pilot = run_autopilot("demo-login", tmp_path / "audits", session_state=sesion)

    assert pilot.signed, f"el piloto no llego al formulario: {pilot.notes}"
    assert token in lab.LOGIN_PINGS, "la auditoria no corrio dentro de la sesion"
    assert not lab.COLLECTED
    for regla in ("FS-KEY-001", "FS-KEY-002", "FS-PWD-001"):
        assert status(report, regla) == "NOT_OBSERVED", regla
    assert status(report, "FS-LOCAL-001") == "CONFIRMED"

    expediente = tmp_path / "audits" / report["session"]
    crudo = b"".join(p.read_bytes() for p in expediente.rglob("*") if p.is_file())
    for valor in (cookie, token):
        for forma in (valor, urllib.parse.quote(valor, safe=""),
                      base64.b64encode(valor.encode()).decode()):
            assert forma.encode() not in crudo, f"la sesion llego al expediente: {forma[:8]}..."
    assert str(sesion).encode() not in crudo, "el expediente revela donde esta la sesion"
    manifest = json.loads((expediente / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["audit_configuration"]["authenticated_session"] is True


def test_sin_sesion_el_portal_no_muestra_el_formulario(lab, tmp_path):
    """El control: sin --session el piloto se queda en la pagina de acceso."""
    lab.LOGIN_PINGS.clear()
    report, pilot = run_autopilot("demo-login", tmp_path, isolation="none")
    assert not pilot.signed
    assert not lab.LOGIN_PINGS
    assert status(report, "FS-LOCAL-001") != "CONFIRMED"


def test_tc012_la_contrasena_de_la_cuenta_no_es_la_de_la_efirma(lab, tmp_path, credential):
    """El primer piloto del panel: iniciar sesion en el portal *dentro* del
    navegador auditado se reporto como "la contrasena de la e.firma salio".

    La instrumentacion marca cualquier campo de tipo contrasena; los sensores
    que ven el cuerpo deciden si lo que viajo era la contrasena registrada.
    """
    lab.LOGIN_PINGS.clear()
    config = AuditConfig(target="http://127.0.0.1:8765/demo-login/", headless=True,
                         output_dir=tmp_path, isolation=IsolationPolicy(mode=IsolationMode.FULL))
    session = AuditSession(config)

    def drive(stage, index, test):
        page = session.controller.page
        if stage.name == "prepare":
            # El operador inicia sesion en el propio navegador auditado.
            page.wait_for_selector("#account-password", timeout=15000)
            page.fill("#username", lab.LAB_LOGIN_USER)
            page.fill("#account-password", lab.LAB_LOGIN_PASSWORD)
            page.click("#login")
            page.wait_for_selector("#sign", timeout=15000)
            page.wait_for_timeout(1000)
        elif stage.name == "sign":
            page.set_input_files("#cer-file", str(credential.cert_path))
            page.set_input_files("#key-file", str(credential.key_path))
            page.fill("#password", credential.password)
            page.click("#sign")
            page.wait_for_timeout(3000)
        elif stage.name == "submit":
            if page.query_selector("#submit:not([disabled])"):
                page.click("#submit")
            page.wait_for_timeout(1500)
        return StageAction.CONTINUE

    try:
        session.prepare_credentials(credentials_dir=tmp_path / "cred")
        session.credential = credential
        credential.register(session.vault)
        session.start_browser()
        session.navigate(config.target)
        session.controller.staged_offline_test().run(drive)
        session.collect_and_analyze()
        session.evaluate()
    finally:
        package = session.finish()
    report = json.loads((package / "report.json").read_text(encoding="utf-8"))

    assert lab.LOGIN_PINGS, "el inicio de sesion no llego a hacerse"
    hallazgo = finding(report, "FS-PWD-001")
    assert hallazgo["status"] == "NOT_OBSERVED", hallazgo["summary"]
    assert "Otro campo de contrasena" in hallazgo["detail"]
    # Y la firma, que es lo que se audita, sigue siendo local.
    assert status(report, "FS-LOCAL-001") == "CONFIRMED"
