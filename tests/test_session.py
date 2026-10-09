"""Sesion autenticada del operador: login aparte, --session y valores protegidos.

La sesion de la cuenta del operador en el portal es una credencial. Estas
pruebas fijan las tres promesas que hace FirmaScope sobre ella: no llega al
expediente por ninguna via, no se confunde con una fuga, y el fichero que la
guarda no queda legible para otros usuarios del equipo.
"""

from __future__ import annotations

import base64
import json
import os
import stat
import urllib.parse
from pathlib import Path

import pytest

from firmascope.audit_core import options
from firmascope.audit_core.config import AuditConfig
from firmascope.audit_core.secrets import SecretVault, assert_no_secrets, redact
from firmascope.browser_controller.session import (
    SessionStateError,
    default_session_path,
    describe_session,
    load_session_state,
    session_secrets,
    write_session_state,
)
from firmascope.evidence_store.store import EvidenceStore, RequestRecord, ScriptRecord

COOKIE = "s3cr3t-cookie-de-sesion-0123456789"
TOKEN = "eyJhbGciOiJIUzI1NiJ9.token-de-acceso.firma"

STATE = {
    "cookies": [
        {"name": "sid", "value": COOKIE, "domain": ".portal.ejemplo.mx", "path": "/"},
        {"name": "lang", "value": "es", "domain": "portal.ejemplo.mx", "path": "/"},
    ],
    "origins": [
        {"origin": "https://portal.ejemplo.mx",
         "localStorage": [{"name": "access_token", "value": TOKEN}]},
    ],
}


@pytest.fixture
def protected_vault(vault):
    for value in session_secrets(STATE):
        vault.protect(value)
    return vault


# ----------------------------------------------------------------------
# El fichero de sesion
# ----------------------------------------------------------------------

@pytest.mark.skipif(os.name != "posix", reason="permisos POSIX")
def test_el_fichero_de_sesion_no_es_legible_por_otros(tmp_path):
    path = tmp_path / "sesion.json"
    # Un fichero previo con permisos abiertos: O_CREAT no los cambiaria.
    path.write_text("{}")
    path.chmod(0o644)
    write_session_state(STATE, path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert load_session_state(path)["cookies"][0]["value"] == COOKIE


def test_la_ruta_por_defecto_no_esta_en_el_directorio_de_trabajo():
    """El directorio de trabajo suele ser un repositorio: un `git add .` la publicaria."""
    path = default_session_path("https://portal.ejemplo.mx/login")
    assert path.is_relative_to(Path.home())
    assert not path.is_relative_to(Path.cwd()) or Path.cwd() == Path.home()
    assert path.name == "portal.ejemplo.mx.json"


def test_un_fichero_que_no_es_una_sesion_se_rechaza(tmp_path):
    with pytest.raises(SessionStateError):
        load_session_state(tmp_path / "no-existe.json")
    roto = tmp_path / "roto.json"
    roto.write_text("no es json")
    with pytest.raises(SessionStateError):
        load_session_state(roto)
    raro = tmp_path / "raro.json"
    raro.write_text(json.dumps({"cookies": "no es una lista"}))
    with pytest.raises(SessionStateError):
        load_session_state(raro)


def test_el_resumen_no_lleva_valores():
    summary = describe_session(STATE)
    assert summary["cookies"] == 2
    assert summary["cookie_domains"] == ["portal.ejemplo.mx"]
    assert COOKIE not in json.dumps(summary) and TOKEN not in json.dumps(summary)


def test_se_protegen_cookies_y_almacenamiento_local():
    assert set(session_secrets(STATE)) == {COOKIE, "es", TOKEN}


# ----------------------------------------------------------------------
# Valores protegidos en el vault
# ----------------------------------------------------------------------

def test_un_valor_protegido_no_es_un_canario(protected_vault):
    """Una cookie viaja en cada peticion legitima: no puede clasificar trafico."""
    assert protected_vault.scan(f"Cookie: sid={COOKIE}") == []
    assert protected_vault.labels == set()
    assert protected_vault.labels_in(f"sid={COOKIE}") == {"SESSION"}


def test_los_valores_cortos_no_se_protegen(protected_vault):
    """`lang=es` aparece en cualquier parte: redactarlo destrozaria el expediente."""
    assert protected_vault.protected_count == 2
    assert protected_vault.labels_in("idioma es") == set()


@pytest.mark.parametrize("forma", [
    TOKEN,
    urllib.parse.quote(TOKEN, safe=""),
    base64.b64encode(TOKEN.encode()).decode(),
])
def test_la_barrera_final_detiene_la_sesion_en_cualquier_forma(protected_vault, forma):
    with pytest.raises(AssertionError):
        assert_no_secrets(f'{{"x": "{forma}"}}', protected_vault)


def test_la_redaccion_conserva_el_destino_de_la_url(protected_vault):
    url = f"https://portal.ejemplo.mx/api/ping?access_token={urllib.parse.quote(TOKEN)}"
    clean = redact({"url": url}, protected_vault)["url"]
    assert clean.startswith("https://portal.ejemplo.mx/api/ping?")
    assert TOKEN not in clean and urllib.parse.quote(TOKEN) not in clean


def test_el_vault_destruido_olvida_los_valores_protegidos(vault):
    vault.protect(COOKIE)
    vault.destroy()
    assert vault.protected_count == 0


# ----------------------------------------------------------------------
# Nada de la sesion llega a disco
# ----------------------------------------------------------------------

def _expediente(root: Path) -> bytes:
    return b"".join(p.read_bytes() for p in root.rglob("*") if p.is_file())


def test_ninguna_via_del_store_escribe_la_sesion(tmp_path, protected_vault):
    """Peticion, cabeceras, script en linea y cuerpo capturado."""
    store = EvidenceStore(tmp_path, "s", protected_vault)
    store.add_request(RequestRecord(
        timestamp=0.0, method="GET",
        url=f"https://portal.ejemplo.mx/api/ping?access_token={TOKEN}",
        host="portal.ejemplo.mx", registrable="ejemplo.mx",
        headers={"x-trace": COOKIE}))
    script = f'window.__SESSION__ = "{COOKIE}";'.encode()
    store.add_script(ScriptRecord(url="inline:x", sha256="ab" * 32, size=len(script)),
                     script)
    store.add_evidence("http-body", "POST-x", f'{{"token": "{TOKEN}"}}'.encode())
    store.close()

    crudo = _expediente(tmp_path)
    for valor in (COOKIE, TOKEN):
        assert valor.encode() not in crudo
    assert b"<protegido:SESSION>" in crudo


def test_los_canarios_si_se_conservan_en_un_cuerpo_capturado(tmp_path, vault, credential):
    """El enmascarado es solo para la sesion: un cuerpo con la clave sintetica
    es la prueba de la fuga, y quitarla del cuerpo la borraria."""
    credential.register(vault)
    vault.protect(COOKIE)
    store = EvidenceStore(tmp_path, "s", vault)
    body = credential.key_der + COOKIE.encode()
    record = store.add_evidence("http-body", "POST-x", body)
    store.close()
    guardado = (tmp_path / record["path"]).read_bytes()
    assert credential.key_der in guardado
    assert COOKIE.encode() not in guardado


# ----------------------------------------------------------------------
# Configuracion, opciones e interfaces
# ----------------------------------------------------------------------

def test_el_manifiesto_dice_que_hubo_sesion_pero_no_donde(tmp_path):
    path = tmp_path / "secreta" / "sesion.json"
    config = AuditConfig(target="https://portal.ejemplo.mx", session_state=path)
    manifest = json.dumps(config.to_dict())
    assert config.to_dict()["authenticated_session"] is True
    assert "secreta" not in manifest and "sesion.json" not in manifest


def test_la_opcion_valida_el_fichero_antes_de_arrancar(tmp_path):
    answers = options.defaults()
    answers.update(target="portal.ejemplo.mx", session_file=str(tmp_path / "no-existe.json"))
    assert any("Sesion" in p for p in options.validate(answers))

    path = write_session_state(STATE, tmp_path / "sesion.json")
    answers["session_file"] = str(path)
    assert options.validate(answers) == []
    assert options.build_config(answers).session_state == path


def test_sin_sesion_la_configuracion_no_cambia():
    answers = options.defaults()
    answers["target"] = "portal.ejemplo.mx"
    config = options.build_config(answers)
    assert config.session_state is None
    assert config.to_dict()["authenticated_session"] is False


def test_la_cli_ofrece_login_y_siembra_la_sesion(tmp_path):
    from firmascope.cli.main import _seed_from_args, build_parser

    parser = build_parser()
    args = parser.parse_args(["login", "portal.ejemplo.mx", "--save", str(tmp_path / "s.json")])
    assert args.func.__name__ == "cmd_login"
    args = parser.parse_args(["audit", "portal.ejemplo.mx", "--session", "s.json"])
    assert _seed_from_args(args)["session_file"] == "s.json"


def test_el_puente_no_audita_con_un_inicio_de_sesion_a_medias():
    """Dos Playwright en el mismo hilo no conviven, y la sesion aun no existe."""
    from firmascope.gui_bridge.bridge import Bridge

    bridge = Bridge()

    class Abierto:
        closed = False

        def close(self):
            self.closed = True

    abierto = Abierto()
    bridge.login = abierto
    respuesta = bridge.handle({"id": 1, "cmd": "start",
                               "args": {"answers": {"target": "portal.ejemplo.mx"}}})
    assert not respuesta["ok"] and "inicio de sesion" in respuesta["error"]
    assert bridge.handle({"id": 2, "cmd": "login_cancel"})["ok"]
    assert abierto.closed and bridge.login is None
    assert not bridge.handle({"id": 3, "cmd": "login_save"})["ok"]
