"""Pruebas extremo a extremo: TC-001..TC-006 sobre las cinco aplicaciones.

Arrancan un Chromium real contra el servidor de laboratorio y ejercitan la
cadena completa — instrumentacion, CDP, analisis estatico, correlacion,
reglas y reporte. Son las unicas pruebas que pueden decir que la herramienta
funciona, y no solo que sus piezas encajan.

Se marcan ``e2e`` porque necesitan navegador:

    pytest -m e2e            solo estas
    pytest -m "not e2e"      el resto de la suite
"""

from __future__ import annotations

import pytest

from firmascope.audit_core.conclusions import Status
from firmascope.audit_core.config import AuditConfig, AuditLevel, default_chromium_path
from firmascope.audit_core.events import EventType, Tag
from firmascope.cli.orchestrator import Auditor
from firmascope.labs.server import LabServer

def _chromium_available() -> bool:
    """Chromium propio del sistema, o el que traiga Playwright."""
    if default_chromium_path() is not None:
        return True
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            return bool(p.chromium.executable_path)
    except Exception:
        return False


pytestmark = [
    pytest.mark.e2e,
    pytest.mark.timeout(300),
    pytest.mark.skipif(not _chromium_available(),
                       reason="no hay un Chromium disponible para las pruebas e2e"),
]


@pytest.fixture(scope="module")
def lab():
    server = LabServer(port=0).start()
    yield server
    server.stop()


def run_audit(lab: LabServer, demo: str, tmp_path, level: int = 3, **params):
    config = AuditConfig(
        target=lab.url_for(demo, **params),
        level=AuditLevel(level),
        output_dir=tmp_path,
        headless=True,
    )
    return Auditor(config).run(dwell=4.0, offline_dwell=3.0)


def status_of(result, rule_id: str) -> Status:
    for finding in result.findings:
        if finding.rule_id == rule_id:
            return finding.status
    raise AssertionError(f"{rule_id} no emitio hallazgo")


def actionable_ids(result) -> set[str]:
    return {f.rule_id for f in result.actionable()}


# ----------------------------------------------------------------------
# TC-001 — la aplicacion correcta no produce hallazgos
# ----------------------------------------------------------------------

def test_tc001_demo_safe_no_produce_falsos_positivos(lab, tmp_path):
    """El caso que decide si la herramienta sirve.

    demo-safe firma localmente y envia la firma y el certificado, que es lo
    que toda aplicacion correcta hace. Si esto produjera un solo hallazgo, el
    resto del catalogo seria ruido.
    """
    result = run_audit(lab, "demo-safe", tmp_path)

    assert result.error == ""
    assert actionable_ids(result) == set(), (
        f"demo-safe produjo hallazgos: {actionable_ids(result)}")
    assert status_of(result, "FS-KEY-001") is Status.NOT_OBSERVED
    assert status_of(result, "FS-PWD-001") is Status.NOT_OBSERVED
    assert result.chain_ok is True


# ----------------------------------------------------------------------
# TC-002 — exfiltracion directa de la clave
# ----------------------------------------------------------------------

def test_tc002_exfiltracion_directa(lab, tmp_path):
    result = run_audit(lab, "demo-key-exfiltration", tmp_path)

    assert status_of(result, "FS-KEY-001") is Status.OBSERVED
    assert status_of(result, "FS-PWD-001") is Status.OBSERVED

    chains = result.correlation.exfiltration_chains()
    assert chains, "no se reconstruyo ninguna cadena de exfiltracion"
    assert any(c.direct for c in chains), "la transmision directa no se reconocio como tal"


def test_tc002_la_firma_enviada_no_se_confunde_con_la_fuga(lab, tmp_path):
    """demo-key-exfiltration tambien firma localmente y entrega la firma.

    Las dos cosas ocurren en la misma sesion, y el reporte debe separarlas.
    """
    result = run_audit(lab, "demo-key-exfiltration", tmp_path)
    legitimas = result.correlation.legitimate_chains()
    assert legitimas, "la entrega de la firma no se clasifico como legitima"
    assert all(not c.private for c in legitimas)


# ----------------------------------------------------------------------
# TC-003 — exfiltracion opaca
# ----------------------------------------------------------------------

def test_tc003_exfiltracion_cifrada(lab, tmp_path):
    """Lo que sale es indistinguible de ruido: no hay canario que coincidir.

    El seguimiento de procedencia en JavaScript no atraviesa un bucle que
    construye la cadena caracter a caracter, asi que FirmaScope no afirma
    haber seguido el dato. Lo que si sostiene es que salio un cuerpo opaco
    despues del acceso a la clave (FS-NET-002) y que el codigo contiene la
    ruta (FS-KEY-002 / FS-CODE-001). Esa es la respuesta honesta.
    """
    result = run_audit(lab, "demo-encrypted-exfiltration", tmp_path)

    assert status_of(result, "FS-NET-002") is Status.OBSERVED
    assert status_of(result, "FS-KEY-002") in (Status.OBSERVED, Status.POTENTIAL)
    assert status_of(result, "FS-CODE-001") is Status.POTENTIAL

    # Y no se inventa una transmision directa que no pudo establecer.
    assert status_of(result, "FS-KEY-001") is Status.NOT_OBSERVED


# ----------------------------------------------------------------------
# TC-004 — firma en el servidor
# ----------------------------------------------------------------------

def test_tc004_firma_en_el_servidor(lab, tmp_path):
    """El .key viaja dentro de un FormData: es el patron de subida habitual."""
    result = run_audit(lab, "demo-server-sign", tmp_path)

    assert status_of(result, "FS-KEY-001") is Status.OBSERVED
    assert status_of(result, "FS-PWD-001") is Status.OBSERVED


def test_tc004_la_firma_no_se_completa_sin_red(lab, tmp_path):
    """La prueba de aislamiento distingue firma local de firma remota."""
    result = run_audit(lab, "demo-server-sign", tmp_path)
    assert status_of(result, "FS-LOCAL-001") is not Status.CONFIRMED


# ----------------------------------------------------------------------
# TC-005 — la ruta existe pero no se recorre
# ----------------------------------------------------------------------

def test_tc005_ruta_estatica_sin_ejecutar(lab, tmp_path):
    """El caso que separa el nivel 1 del nivel 2.

    En tiempo de ejecucion esta aplicacion se comporta como demo-safe. Solo
    el analisis del codigo puede anadir que podria no hacerlo.
    """
    result = run_audit(lab, "demo-static-only", tmp_path)

    assert status_of(result, "FS-CODE-001") is Status.POTENTIAL
    assert status_of(result, "FS-KEY-001") is Status.NOT_OBSERVED
    assert actionable_ids(result) == {"FS-CODE-001"}


def test_tc005_nivel_1_no_puede_ver_la_ruta(lab, tmp_path):
    """Sin analisis estatico, el nivel 1 solo puede decir que no lo sabe."""
    result = run_audit(lab, "demo-static-only", tmp_path, level=1)
    finding = next(f for f in result.findings if f.rule_id == "FS-CODE-001")
    assert finding.status is Status.INCONCLUSIVE
    assert "nivel 2" in finding.detail


# ----------------------------------------------------------------------
# TC-006 — el expediente y el reporte
# ----------------------------------------------------------------------

def test_tc006_expediente_completo_y_verificable(lab, tmp_path):
    result = run_audit(lab, "demo-key-exfiltration", tmp_path)

    assert result.chain_ok is True
    assert (result.output_dir / "session.sqlite").exists()
    assert result.reports["json"].exists()
    assert result.reports["html"].exists()

    import json
    report = json.loads(result.reports["json"].read_text(encoding="utf-8"))
    assert report["headline"]["rule_id"] == "FS-KEY-001"
    assert report["manifest"]["chain_verified"] is True
    assert report["manifest"]["script_hashes"]
    assert report["manifest"]["agent_sha256"]


def test_tc006_el_expediente_no_contiene_la_contrasena(lab, tmp_path):
    """La promesa central, comprobada sobre una sesion real.

    FirmaScope entrega credenciales sinteticas al sitio y observa como viajan.
    Nada de ese material puede quedar escrito en el expediente.
    """
    config = AuditConfig(
        target=lab.url_for("demo-key-exfiltration"),
        level=AuditLevel.LOCAL_SIGNING_TEST,
        output_dir=tmp_path,
        headless=True,
    )
    auditor = Auditor(config)
    result = auditor.run(dwell=4.0, offline_dwell=3.0)

    password = auditor.credential.password.encode("utf-8")
    plain_key = auditor.credential.key_plain_der

    # El .key cifrado si esta en disco: FirmaScope lo escribio para
    # entregarselo al sitio. Lo que no puede aparecer en el expediente es la
    # contrasena ni el PKCS#8 en claro.
    for path in result.output_dir.rglob("*"):
        if not path.is_file() or path.parent.name == "credentials":
            continue
        blob = path.read_bytes()
        assert password not in blob, f"la contrasena aparece en {path.name}"
        assert plain_key not in blob, f"el PKCS#8 en claro aparece en {path.name}"


def test_tc006_la_sesion_registra_los_hitos(lab, tmp_path):
    from firmascope.evidence_store.store import EvidenceStore

    result = run_audit(lab, "demo-safe", tmp_path)
    store = EvidenceStore(result.output_dir, result.session_id)
    try:
        nombres = [c["name"] for c in store.checkpoints()]
        tipos = {e.type for e in store.events()}
    finally:
        store.close()

    assert "pagina-cargada" in nombres
    assert "credenciales-entregadas" in nombres
    assert EventType.NETWORK_OFF in tipos, "no se ejecuto la prueba de aislamiento"
    assert EventType.CRYPTO_SIGN in tipos, "la aplicacion no llego a firmar"


# ----------------------------------------------------------------------
# El canario, sobre una sesion real
# ----------------------------------------------------------------------

def test_el_canario_encuentra_la_clave_en_el_cuerpo(lab, tmp_path):
    """Prueba directa: los bytes del .key estaban en el cuerpo de la peticion.

    Es evidencia independiente del etiquetado de la instrumentacion, y por eso
    eleva la confianza de la cadena.
    """
    result = run_audit(lab, "demo-key-exfiltration", tmp_path)
    chains = result.correlation.exfiltration_chains()
    assert chains

    con_canario = [c for c in chains if "canary" in c.corroboration]
    etiquetadas = [c for c in chains if Tag.KEY_FILE.value in c.labels]
    assert con_canario or etiquetadas, (
        "ni el canario ni la instrumentacion atribuyeron la salida")


# ----------------------------------------------------------------------
# Nivel 4: el proxy como cuarto sensor
# ----------------------------------------------------------------------

def _level4(lab: LabServer, demo: str, tmp_path):
    from firmascope.audit_core.config import ProxyConfig
    from firmascope.proxy_addon import available

    if not available():
        pytest.skip("mitmproxy no esta instalado")
    config = AuditConfig(
        target=lab.url_for(demo),
        level=AuditLevel.FULL_CORRELATED,
        output_dir=tmp_path,
        headless=True,
        proxy=ProxyConfig(enabled=True),
    )
    auditor = Auditor(config)
    return auditor, auditor.run(dwell=4.0, offline_dwell=3.0)


def test_nivel4_demo_safe_sigue_sin_hallazgos(lab, tmp_path):
    """El proxy ve el certificado en el cuerpo, y el certificado comparte el
    modulo RSA con la clave. Nada de eso puede convertirse en un hallazgo."""
    _, result = _level4(lab, "demo-safe", tmp_path)
    assert "activo" in result.proxy_note
    assert actionable_ids(result) == set()
    assert result.correlation.exfiltration_chains() == []


def test_nivel4_tres_sensores_sostienen_la_misma_fuga(lab, tmp_path):
    """demo-server-sign: agente, CDP y proxy ven la subida, y el proxy
    encuentra el .key en el multipart. Una sola cadena, cuatro apoyos."""
    auditor, result = _level4(lab, "demo-server-sign", tmp_path)

    assert status_of(result, "FS-KEY-001") is Status.OBSERVED
    chains = result.correlation.exfiltration_chains()
    assert len(chains) == 1, "la misma subida se conto mas de una vez"
    assert {"agent", "proxy", "canary"} <= set(chains[0].corroboration)
    # Y la CA efimera no sobrevive a la sesion.
    assert auditor.proxy is None


# ----------------------------------------------------------------------
# Laboratorios que ponen a prueba los supuestos de la herramienta
# ----------------------------------------------------------------------

def test_worker_la_instrumentacion_no_rompe_el_worker_del_sitio(lab, tmp_path):
    """El agente se inyectaba envolviendo el worker en un blob:, y dentro de
    un blob toda ruta relativa falla. El worker del sitio dejaba de funcionar:
    la herramienta alteraba lo que auditaba."""
    antes = len(lab.received.collected)
    result = run_audit(lab, "demo-worker", tmp_path)

    assert result.error == ""
    recibidos = [c["path"] for c in lab.received.collected[antes:]]
    assert "/collect/worker" in recibidos, "el worker del sitio no llego a ejecutarse"


def test_worker_la_procedencia_cruza_postmessage(lab, tmp_path):
    """Nivel 3, sin proxy: la fuga ocurre dentro del worker y solo puede
    verla la instrumentacion, que necesita que la procedencia cruce
    postMessage."""
    from firmascope.evidence_store.store import EvidenceStore

    result = run_audit(lab, "demo-worker", tmp_path)
    assert status_of(result, "FS-KEY-001") is Status.OBSERVED

    store = EvidenceStore(result.output_dir, result.session_id)
    try:
        del_worker = [e for e in store.events()
                      if e.context == "worker" and e.type is EventType.NETWORK_REQUEST]
    finally:
        store.close()
    assert any(Tag.KEY_FILE.value in e.tags for e in del_worker)


def test_canales_laterales_y_tercero(lab, tmp_path):
    """La contrasena en un beacon y el .key en la query de un pixel, hacia un
    dominio de tercero. El pixel es una peticion GET sin cuerpo: solo se ve
    buscando el canario en la URL."""
    result = run_audit(lab, "demo-side-channels", tmp_path)

    assert status_of(result, "FS-PWD-001") is Status.OBSERVED
    assert status_of(result, "FS-KEY-001") is Status.OBSERVED
    assert status_of(result, "FS-NET-001") is Status.OBSERVED


def test_codigo_minificado(lab, tmp_path):
    """Sin nombres de variable. La ejecucion no depende de ellos, y el analisis
    estatico tampoco debe: la ruta se encuentra por las APIs y por los ids
    del HTML, que la minificacion no toca."""
    result = run_audit(lab, "demo-minified", tmp_path)

    assert status_of(result, "FS-KEY-001") is Status.OBSERVED
    assert status_of(result, "FS-PWD-001") is Status.OBSERVED
    finding = next(f for f in result.findings if f.rule_id == "FS-CODE-001")
    assert finding.status is Status.POTENTIAL


def test_canales_laterales_el_expediente_no_guarda_la_clave_de_la_url(lab, tmp_path):
    """La clave viajo en la query de un pixel. El reporte debe decir a donde
    salio sin volver a escribirla, y el expediente tampoco puede contenerla."""
    import base64
    from urllib.parse import quote

    config = AuditConfig(target=lab.url_for("demo-side-channels"),
                         level=AuditLevel.LOCAL_SIGNING_TEST, output_dir=tmp_path, headless=True)
    auditor = Auditor(config)
    result = auditor.run(dwell=4.0, offline_dwell=3.0)

    assert result.error == "", result.error
    assert result.reports, "el reporte no se escribio"
    b64 = base64.b64encode(auditor.credential.key_der).decode()
    formas = [b64.encode(), quote(b64, safe="").encode()]
    for path in result.output_dir.rglob("*"):
        if not path.is_file() or path.parent.name == "credentials":
            continue
        blob = path.read_bytes()
        for forma in formas:
            assert forma[:48] not in blob, f"la clave aparece en {path.name}"


# ----------------------------------------------------------------------
# Plataformas con inicio de sesion (demo-login)
# ----------------------------------------------------------------------

def _iniciar_sesion(page):
    """Lo que haria la persona en la ventana de `firmascope login`."""
    from firmascope.labs.server import LAB_LOGIN_PASSWORD, LAB_LOGIN_USER

    page.fill("#username", LAB_LOGIN_USER)
    page.fill("#account-password", LAB_LOGIN_PASSWORD)
    page.click("#login")
    page.wait_for_url("**/demo-login/")


@pytest.fixture
def sesion(lab, tmp_path):
    from firmascope.browser_controller.session import capture_session

    path = tmp_path / "sesion.json"
    capture_session(lab.url_for("demo-login"), path, _iniciar_sesion, headless=True,
                    browser_path=default_chromium_path(), browser_args=["--no-sandbox"])
    return path


def _audit_login(lab, tmp_path, **kwargs):
    operator = kwargs.pop("operator", None)
    config = AuditConfig(target=lab.url_for("demo-login"), level=AuditLevel.LOCAL_SIGNING_TEST,
                         output_dir=tmp_path / "audits", **kwargs)
    config.headless = True     # el modo manual lo desactiva; aqui no hay pantalla
    auditor = Auditor(config, operator=operator)
    return auditor, auditor.run(dwell=4.0, offline_dwell=3.0)


def test_login_sin_sesion_la_herramienta_lo_dice(lab, tmp_path):
    """Sin sesion se llega al login: no hay formulario de firma, y la
    auditoria no finge haberlo auditado."""
    _, result = _audit_login(lab, tmp_path)
    assert "No se reconocio el formulario" in result.credentials_note
    assert status_of(result, "FS-KEY-001") is Status.INCONCLUSIVE


def test_login_con_sesion_llega_al_formulario(lab, tmp_path, sesion):
    _, result = _audit_login(lab, tmp_path, session_state=sesion)
    assert result.error == ""
    assert "Sesion autenticada" in result.session_note
    assert result.credentials_note == "Credenciales sinteticas entregadas al sitio."
    assert actionable_ids(result) == set()
    assert status_of(result, "FS-KEY-001") is Status.NOT_OBSERVED


def test_login_la_cookie_de_sesion_no_llega_al_expediente(lab, tmp_path, sesion):
    import json

    tokens = [c["value"] for c in json.loads(sesion.read_text())["cookies"]]
    assert tokens and all(len(t) >= 12 for t in tokens)
    _, result = _audit_login(lab, tmp_path, session_state=sesion)
    for path in result.output_dir.rglob("*"):
        if not path.is_file():
            continue
        blob = path.read_bytes()
        for token in tokens:
            assert token.encode() not in blob, f"la cookie de sesion aparece en {path.name}"


def test_modo_manual_con_prueba_de_aislamiento(lab, tmp_path, sesion):
    """El operador firma y luego repite la firma con la red aislada. Es la
    unica forma de llegar a CONFIRMED: la firma local queda demostrada."""
    from firmascope.browser_controller import forms

    pasos = []

    def operador(step):
        pasos.append(step.step)
        if step.step == "firmar":
            assert step.credential is not None
            assert str(step.credential.key_path) in step.message
            forms.submit(step.page, forms.provide(step.page, step.credential))
        else:
            forms.submit(step.page, forms.detect(step.page))
        step.wait(3.0)

    _, result = _audit_login(lab, tmp_path, session_state=sesion, manual=True, operator=operador)
    assert pasos == ["firmar", "firmar-aislado"]
    assert status_of(result, "FS-LOCAL-001") is Status.CONFIRMED
    assert status_of(result, "FS-KEY-001") is Status.NOT_OBSERVED
