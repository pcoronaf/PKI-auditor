"""Pruebas de extremo a extremo contra el laboratorio (TC-001 .. TC-006).

Son las unicas pruebas que pueden responder si FirmaScope *funciona*: lanzan un
Chromium real contra las aplicaciones de laboratorio y comparan los hallazgos
con la verdad conocida, que el propio laboratorio registra -- si el recolector
de terceros recibio los bytes o no.

Esa comparacion es lo que distingue una prueba de una ilusion: un informe que
dice "la clave salio" es correcto solo si el recolector la tiene, y uno que dice
"se impidio" es correcto solo si no la tiene.
"""

from __future__ import annotations

import json

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
