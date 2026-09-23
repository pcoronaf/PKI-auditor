"""Pruebas de la CLI y del servidor de laboratorio (sin navegador)."""

from __future__ import annotations

import json
import urllib.request

import pytest

from firmascope.cli.main import build_parser, main
from firmascope.labs.server import DEMOS, LabServer


def run(capsys, *argv: str) -> tuple[int, str, str]:
    """Ejecuta la CLI y devuelve (codigo, stdout, stderr).

    `capsys.readouterr()` vacia los buffers, asi que hay que recoger ambos
    aqui: una segunda lectura en la prueba llegaria en blanco.
    """
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# ----------------------------------------------------------------------
# Parser
# ----------------------------------------------------------------------

def test_el_nivel_por_defecto_es_el_completo():
    args = build_parser().parse_args(["audit", "https://sitio.example"])
    assert args.level == "4"


def test_los_cuerpos_no_se_capturan_salvo_peticion_expresa():
    args = build_parser().parse_args(["audit", "https://sitio.example"])
    assert args.capture_bodies is False


def test_el_navegador_es_headless_salvo_peticion_expresa():
    args = build_parser().parse_args(["audit", "https://sitio.example"])
    assert args.headed is False


def test_sin_subcomando_falla():
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_nivel_invalido_devuelve_error(capsys):
    code, _, err = run(capsys, "audit", "https://sitio.example", "--level", "inventado")
    assert code == 2
    assert "desconocido" in err


# ----------------------------------------------------------------------
# rules
# ----------------------------------------------------------------------

def test_rules_lista_el_catalogo(capsys):
    code, out, err = run(capsys, "rules")
    assert code == 0
    assert "FS-KEY-001" in out
    assert "12 reglas." in out


def test_rules_agrupa_cada_categoria_una_sola_vez(capsys):
    _, out, _ = run(capsys, "rules")
    categorias = [line.strip() for line in out.splitlines()
                  if line and not line.startswith(" ") and line.strip().isupper()]
    assert len(categorias) == len(set(categorias)), f"categorias repetidas: {categorias}"


def test_rules_json_es_valido(capsys):
    code, out, err = run(capsys, "rules", "--json")
    catalogo = json.loads(out)
    assert code == 0
    assert len(catalogo) == 12
    assert all({"id", "title", "severity", "category"} <= set(e) for e in catalogo)


def test_rules_incorpora_paquetes_externos(capsys, tmp_path):
    (tmp_path / "extra.yaml").write_text(
        "id: FS-OP-001\ntitle: Regla del operador\ncategory: efirma\nsummary: x\n",
        encoding="utf-8")
    _, out, _ = run(capsys, "rules", "--rules", str(tmp_path))
    assert "FS-OP-001" in out


# ----------------------------------------------------------------------
# credentials
# ----------------------------------------------------------------------

def test_credentials_new_escribe_el_par_y_muestra_la_contrasena(capsys, tmp_path):
    code, out, err = run(capsys, "credentials", "new", "-o", str(tmp_path), "--stem", "lab")
    assert code == 0
    assert (tmp_path / "lab.key").exists()
    assert (tmp_path / "lab.cer").exists()
    # El operador necesita la contrasena para escribirla en el sitio auditado.
    assert "contrasena:" in out
    assert "NOT A SAT CERTIFICATE" in out


def test_credentials_new_acepta_una_contrasena_dada(capsys, tmp_path):
    _, out, _ = run(capsys, "credentials", "new", "-o", str(tmp_path),
                 "--password", "contrasena-de-prueba")
    assert "contrasena-de-prueba" in out


# ----------------------------------------------------------------------
# labs
# ----------------------------------------------------------------------

def test_labs_list(capsys):
    code, out, err = run(capsys, "labs", "list")
    assert code == 0
    for demo in DEMOS:
        assert demo in out


# ----------------------------------------------------------------------
# verify
# ----------------------------------------------------------------------

def test_verify_sin_expediente(capsys, tmp_path):
    code, _, err = run(capsys, "verify", str(tmp_path))
    assert code == 2
    assert "no hay un expediente" in err


def test_verify_expediente_intacto(capsys, tmp_path):
    from firmascope.audit_core.events import EventType
    from firmascope.evidence_store.store import EvidenceStore
    from conftest import make_event

    store = EvidenceStore(tmp_path, tmp_path.name)
    store.open_session("https://sitio.example", {"level": 4}, {})
    for i in range(5):
        store.add_event(make_event(EventType.NETWORK_REQUEST, float(i),
                                   url=f"https://sitio.example/{i}"))
    store.close_session()
    store.close()

    code, out, err = run(capsys, "verify", str(tmp_path))
    assert code == 0
    assert "verificada" in out


def test_verify_detecta_un_expediente_manipulado(capsys, tmp_path):
    import sqlite3

    from firmascope.audit_core.events import EventType
    from firmascope.evidence_store.store import EvidenceStore
    from conftest import make_event

    store = EvidenceStore(tmp_path, tmp_path.name)
    store.open_session("https://sitio.example", {"level": 4}, {})
    for i in range(5):
        store.add_event(make_event(EventType.NETWORK_REQUEST, float(i),
                                   url=f"https://sitio.example/{i}"))
    store.close_session()
    store.close()

    db = sqlite3.connect(str(tmp_path / "session.sqlite"))
    db.execute("UPDATE events SET data_json = "
               "REPLACE(data_json, 'sitio.example/2', 'otro.example/2')")
    db.commit()
    db.close()

    code, out, err = run(capsys, "verify", str(tmp_path))
    assert code == 1
    assert "ROTA" in out
    assert "pueden sostenerse sin volver a ejecutar" in out


# ----------------------------------------------------------------------
# Servidor de laboratorio
# ----------------------------------------------------------------------

@pytest.fixture
def lab():
    server = LabServer(port=0).start()
    yield server
    server.stop()


def _get(url: str) -> tuple[int, bytes]:
    with urllib.request.urlopen(url, timeout=10) as response:
        return response.status, response.read()


def _post(url: str, data: bytes, content_type: str = "application/json") -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=data, method="POST",
                                     headers={"Content-Type": content_type})
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.status, response.read()


def test_el_laboratorio_sirve_las_aplicaciones(lab):
    for demo in DEMOS:
        if demo == "demo-login":
            continue   # exige sesion: ver test_demo_login_sin_sesion_redirige
        status, body = _get(lab.url_for(demo))
        assert status == 200
        assert demo.encode() in body
        assert b"<script src=" in body


def test_el_laboratorio_sirve_la_biblioteca_compartida(lab):
    status, body = _get(f"{lab.base_url}/shared/efirma.js")
    assert status == 200
    assert b"loadPrivateKey" in body


def test_el_indice_avisa_de_no_usar_credenciales_reales(lab):
    _, body = _get(lab.base_url + "/")
    assert "credenciales reales".encode() in body


def test_el_recolector_cuenta_pero_no_guarda(lab):
    """Un laboratorio que persistiera claves seria peor que el problema."""
    _post(f"{lab.base_url}/collect/key", b'{"keyFile":"AAAA"}')
    assert lab.received.collected == [{"path": "/collect/key", "bytes": 18}]
    # El contenido no se conserva en ninguna parte del registro.
    assert "AAAA" not in json.dumps(lab.received.__dict__)


def test_el_endpoint_de_recibo_acepta_la_firma(lab):
    status, _ = _post(f"{lab.base_url}/api/sign-receipt", b'{"signature":"AAAA"}')
    assert status == 200
    assert lab.received.receipts == 1


def test_el_laboratorio_no_sirve_fuera_de_su_directorio(lab):
    with pytest.raises(Exception):
        _get(f"{lab.base_url}/../../../etc/passwd")


def test_el_servidor_firma_con_la_clave_que_le_suben(lab):
    """Lo que hace peligroso al patron: el servidor puede firmar cuando quiera."""
    import base64

    from firmascope.credentials import generator

    credential = generator.generate(key_size=2048)
    boundary = "----firmascopetest"
    document = b"documento de prueba"
    parts = [
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"key\"; "
        f"filename=\"lab.key\"\r\n\r\n".encode() + credential.key_der + b"\r\n",
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n"
        f"{credential.password}\r\n".encode(),
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"document\"\r\n\r\n".encode()
        + document + b"\r\n",
        f"--{boundary}--\r\n".encode(),
    ]
    status, body = _post(f"{lab.base_url}/api/server-sign", b"".join(parts),
                         f"multipart/form-data; boundary={boundary}")
    result = json.loads(body)

    assert status == 200
    assert "signature" in result, result
    assert base64.b64decode(result["signature"])
    assert lab.received.server_signs == 1


def test_el_pixel_cuenta_la_query_pero_no_la_guarda(lab):
    """El material viaja en la URL; el recolector solo registra su tamano."""
    status, body = _get(f"{lab.base_url}/collect/pixel.gif?k=AAAABBBBCCCC")
    assert status == 200
    assert body.startswith(b"GIF89a")
    assert lab.received.collected == [{"path": "/collect/pixel.gif", "bytes": 14}]
    assert "AAAABBBBCCCC" not in json.dumps(lab.received.__dict__)


def test_demo_login_sin_sesion_redirige_al_login(lab):
    status, body = _get(lab.url_for("demo-login"))
    assert status == 200
    assert b"Iniciar sesion" in body
    assert b"key-file" not in body


def test_demo_login_rechaza_credenciales_incorrectas(lab):
    import urllib.error
    with pytest.raises(urllib.error.HTTPError) as err:
        _post(f"{lab.base_url}/api/login", b"username=operador&password=otra",
              "application/x-www-form-urlencoded")
    assert err.value.code == 401
    assert lab.sessions == set()
