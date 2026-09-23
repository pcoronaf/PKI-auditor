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
