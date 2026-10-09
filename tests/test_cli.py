"""La linea de ordenes y el laboratorio.

Portadas de la rama principal y adaptadas a esta CLI. Donde las dos CLI
tomaron decisiones distintas a proposito, la prueba comprueba la de esta:

* el navegador abre ventana por omision, porque la auditoria interactiva
  necesita que el operador cargue su ``.key`` en el portal; ``--headless`` es
  para integracion continua, normalmente junto a ``--auto``;
* los argumentos *precargan* el asistente en lugar de fijar valores, asi que
  el nivel por defecto se comprueba en la configuracion resuelta y no en el
  argumento.
"""

from __future__ import annotations

import json
import sqlite3
import urllib.error
import urllib.request

import pytest

from firmascope.cli.main import build_parser, main

DEMOS = ("demo-safe", "demo-key-exfiltration", "demo-encrypted-exfiltration",
         "demo-server-sign", "demo-static-only")


def run(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# ----------------------------------------------------------------------
# Parser y configuracion resuelta
# ----------------------------------------------------------------------

def test_el_nivel_por_defecto_es_el_completo():
    from firmascope.audit_core import options
    from firmascope.cli.main import _seed_from_args

    args = build_parser().parse_args(["audit", "https://sitio.example"])
    answers = options.defaults()
    answers.update(_seed_from_args(args))
    assert int(options.build_config(answers).level) == 4


def test_los_cuerpos_no_se_capturan_salvo_peticion_expresa():
    args = build_parser().parse_args(["audit", "https://sitio.example"])
    assert args.capture_bodies is False


def test_sin_ventana_solo_si_se_pide():
    """La auditoria interactiva necesita ver el navegador."""
    args = build_parser().parse_args(["audit", "https://sitio.example"])
    assert args.headless is False
    args = build_parser().parse_args(["audit", "https://sitio.example", "--headless"])
    assert args.headless is True


def test_sin_subcomando_falla():
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_nivel_invalido_devuelve_error(capsys):
    code, _, err = run(capsys, "audit", "https://sitio.example",
                       "--level", "inventado", "--no-interactive")
    assert code == 2
    assert "no es una opcion valida" in err


def test_el_piloto_automatico_rechaza_credenciales_que_no_son_sinteticas(capsys):
    """Rellenar una e.firma propia sin nadie delante no se permite."""
    code, _, err = run(capsys, "audit", "https://sitio.example", "--auto",
                       "--credentials", "none")
    assert code == 2
    assert "sintetica" in err


# ----------------------------------------------------------------------
# rules
# ----------------------------------------------------------------------

def test_rules_lista_el_catalogo(capsys):
    code, out, _ = run(capsys, "rules")
    assert code == 0
    assert "FS-KEY-001" in out
    assert len([l for l in out.splitlines() if l.startswith("FS-")]) == 12


def test_rules_json_es_valido(capsys):
    code, out, _ = run(capsys, "rules", "--json")
    catalogo = json.loads(out)
    assert code == 0
    assert len(catalogo) == 12
    assert all({"id", "title", "severity", "category"} <= set(e) for e in catalogo)


def test_rules_filtra_por_categoria(capsys):
    _, out, _ = run(capsys, "rules", "--json", "--category", "efirma")
    assert {e["category"] for e in json.loads(out)} == {"efirma"}


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
    code, out, _ = run(capsys, "credentials", "new", "-o", str(tmp_path), "--stem", "lab")
    assert code == 0
    assert (tmp_path / "lab.key").exists()
    assert (tmp_path / "lab.cer").exists()
    # El operador necesita la contrasena para escribirla en el sitio auditado.
    assert "contrasena" in out
    assert "NOT A SAT CERTIFICATE" in out


def test_credentials_new_acepta_una_contrasena_dada(capsys, tmp_path):
    _, out, _ = run(capsys, "credentials", "new", "-o", str(tmp_path),
                    "--password", "contrasena-de-prueba")
    assert "contrasena-de-prueba" in out


# ----------------------------------------------------------------------
# labs
# ----------------------------------------------------------------------

def test_labs_list(capsys):
    code, out, _ = run(capsys, "labs", "list")
    assert code == 0
    for demo in DEMOS:
        assert demo in out


# ----------------------------------------------------------------------
# verify
# ----------------------------------------------------------------------

def _expediente(tmp_path):
    from conftest import make_event
    from firmascope.audit_core.events import EventType
    from firmascope.evidence_store.store import EvidenceStore

    store = EvidenceStore(tmp_path, tmp_path.name)
    store.open_session("https://sitio.example", {"level": 4}, {})
    for i in range(5):
        store.add_event(make_event(EventType.NETWORK_REQUEST, float(i),
                                   url=f"https://sitio.example/{i}"))
    store.close_session()
    store.close()


def test_verify_sin_expediente(capsys, tmp_path):
    code, _, err = run(capsys, "verify", str(tmp_path))
    assert code == 2
    assert "no hay expediente" in err


def test_verify_expediente_intacto(capsys, tmp_path):
    _expediente(tmp_path)
    code, out, _ = run(capsys, "verify", str(tmp_path))
    assert code == 0
    assert "INTACTA" in out


def test_verify_detecta_un_expediente_manipulado(capsys, tmp_path):
    _expediente(tmp_path)
    db = sqlite3.connect(str(tmp_path / "session.sqlite"))
    db.execute("UPDATE events SET data_json = "
               "REPLACE(data_json, 'sitio.example/2', 'otro.example/2')")
    db.commit()
    db.close()

    code, out, _ = run(capsys, "verify", str(tmp_path))
    assert code == 1
    assert "ROTA" in out
    # Nombra el registro alterado: es lo que el operador busca despues.
    assert "seq=" in out


# ----------------------------------------------------------------------
# El servidor de laboratorio
# ----------------------------------------------------------------------

BASE = "http://127.0.0.1:8765"
COLLECTOR = "http://127.0.0.1:8766"


def _get(url: str) -> tuple[int, bytes]:
    with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310
        return response.status, response.read()


def _post(url: str, body: bytes, content_type: str = "application/json") -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=body,
                                     headers={"Content-Type": content_type})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


@pytest.fixture
def sin_proxy(monkeypatch):
    """El entorno puede tener un proxy de salida; el laboratorio es local."""
    for var in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("no_proxy", "*")


def test_el_laboratorio_sirve_las_cinco_aplicaciones(lab, sin_proxy):
    for demo in DEMOS:
        status, body = _get(f"{BASE}/{demo}/")
        assert status == 200
        assert demo.encode() in body
        assert b"/shared/flow.js" in body


def test_el_laboratorio_sirve_la_biblioteca_compartida(lab, sin_proxy):
    status, body = _get(f"{BASE}/shared/efirma.js")
    assert status == 200
    assert b"loadPrivateKey" in body


def test_el_indice_avisa_de_no_usar_credenciales_reales(lab, sin_proxy):
    _, body = _get(BASE + "/")
    assert "credenciales reales".encode() in body


def test_el_recolector_cuenta_pero_no_guarda(lab, sin_proxy):
    """Un laboratorio que persistiera claves seria peor que el problema."""
    lab.COLLECTED.clear()
    _post(f"{COLLECTOR}/collect", b'{"keyFile":"AAAA"}')
    assert lab.COLLECTED == [{"method": "POST", "path": "/collect", "size": 18,
                              "content_type": "application/json"}]
    # El contenido no se conserva en ninguna parte del registro.
    assert "AAAA" not in json.dumps(lab.COLLECTED)


def test_el_endpoint_de_envio_acepta_la_firma(lab, sin_proxy):
    status, _ = _post(f"{BASE}/api/submit", b'{"signature":"AAAA"}')
    assert status == 200


def test_el_laboratorio_no_sirve_fuera_de_su_directorio(lab, sin_proxy):
    import socket

    with socket.create_connection(("127.0.0.1", 8765), timeout=5) as sock:
        sock.sendall(b"GET /../../../etc/passwd HTTP/1.0\r\nHost: x\r\n\r\n")
        data = b""
        while chunk := sock.recv(4096):
            data += chunk
    assert b"root:" not in data
    assert data.split(b"\r\n", 1)[0].split()[1] in (b"400", b"403", b"404")


def test_el_servidor_firma_con_la_clave_que_le_suben(lab, sin_proxy, credential):
    """Lo que hace peligroso al patron: el servidor puede firmar cuando quiera."""
    import base64

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    lab.SERVER_SIDE.clear()
    boundary = "----firmascopetest"
    document = b"documento de prueba"
    parts = [
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"private_key\"; "
        f"filename=\"lab.key\"\r\n\r\n".encode() + credential.key_path.read_bytes() + b"\r\n",
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"key_password\"\r\n\r\n"
        f"{credential.password}\r\n".encode(),
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"document\"\r\n\r\n".encode()
        + document + b"\r\n",
        f"--{boundary}--\r\n".encode(),
    ]
    status, body = _post(f"{BASE}/api/sign-server-side", b"".join(parts),
                         f"multipart/form-data; boundary={boundary}")
    result = json.loads(body)

    assert status == 200, result
    signature = base64.b64decode(result["signature"])
    # La firma es valida con el certificado del titular: el servidor firmo
    # en su nombre sin que el navegador hiciera nada mas.
    from cryptography import x509

    x509.load_der_x509_certificate(credential.cert_der).public_key().verify(
        signature, document, padding.PKCS1v15(), hashes.SHA256())
    assert lab.SERVER_SIDE[-1]["signed"] is True
