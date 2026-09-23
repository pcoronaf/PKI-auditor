"""Pruebas de la sesion autenticada del operador (sin navegador).

El fichero de sesion es una credencial: permite entrar en la cuenta mientras
la sesion siga activa. Lo que se fija aqui es que la herramienta lo trata como
tal — permisos restrictivos, valores protegidos, nada de ellos en el disco
del expediente — y que las cookies no se confunden con canarios.
"""

from __future__ import annotations

import json
import os
import stat

import pytest

from firmascope.audit_core.config import AuditConfig
from firmascope.audit_core.events import EventType, Tag
from firmascope.audit_core.secrets import SecretVault, assert_no_secrets, redact
from firmascope.browser_controller.session import (
    SessionStateError,
    describe_session,
    load_session_state,
    session_secrets,
    write_session_state,
)
from firmascope.cli.main import main
from firmascope.evidence_store.store import EvidenceStore, RequestRecord

from conftest import make_event

TOKEN = "tok_5f0c9a1e7b2d4c68a9e3f1b7"

ESTADO = {
    "cookies": [
        {"name": "sid", "value": TOKEN, "domain": ".plataforma.example", "path": "/"},
        {"name": "lang", "value": "es", "domain": "plataforma.example", "path": "/"},
    ],
    "origins": [
        {"origin": "https://plataforma.example",
         "localStorage": [{"name": "access_token", "value": "eyJhbGciOiJIUzI1NiJ9.abc.def"}]},
    ],
}


# ----------------------------------------------------------------------
# El fichero de sesion
# ----------------------------------------------------------------------

def test_se_escribe_con_permisos_restrictivos(tmp_path):
    path = write_session_state(ESTADO, tmp_path / "sesion.json")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert load_session_state(path) == ESTADO


def test_fichero_inexistente(tmp_path):
    with pytest.raises(SessionStateError):
        load_session_state(tmp_path / "no-existe.json")


def test_fichero_que_no_es_una_sesion(tmp_path):
    (tmp_path / "x.json").write_text('["no", "es", "una", "sesion"]')
    with pytest.raises(SessionStateError):
        load_session_state(tmp_path / "x.json")
    (tmp_path / "y.json").write_text("{esto no es json")
    with pytest.raises(SessionStateError):
        load_session_state(tmp_path / "y.json")


def test_valores_a_proteger_incluyen_cookies_y_almacenamiento():
    valores = session_secrets(ESTADO)
    assert TOKEN in valores
    assert "eyJhbGciOiJIUzI1NiJ9.abc.def" in valores


def test_el_resumen_no_contiene_valores():
    resumen = describe_session(ESTADO)
    assert resumen["cookies"] == 2
    assert resumen["cookie_domains"] == ["plataforma.example"]
    assert TOKEN not in json.dumps(resumen)


# ----------------------------------------------------------------------
# Proteccion en el vault
# ----------------------------------------------------------------------

def test_un_valor_protegido_se_redacta():
    with SecretVault() as vault:
        assert vault.protect(TOKEN)
        limpio = redact({"url": f"https://plataforma.example/api?t={TOKEN}", "nota": TOKEN}, vault)
    texto = json.dumps(limpio)
    assert TOKEN not in texto
    assert "canary:SESSION" in texto
    assert limpio["url"].startswith("https://plataforma.example/api?")


def test_la_barrera_final_bloquea_un_valor_protegido():
    with SecretVault() as vault:
        vault.protect(TOKEN)
        with pytest.raises(AssertionError):
            assert_no_secrets(json.dumps({"cookie": TOKEN}), vault)


def test_un_valor_protegido_no_es_un_canario():
    """La cookie viaja en cada peticion autenticada: si clasificara el trafico,
    todas las salidas legitimas parecerian fugas."""
    with SecretVault() as vault:
        vault.protect(TOKEN)
        assert vault.scan(f"cuerpo con {TOKEN}") == []
        assert vault.labels == set()


def test_valores_cortos_no_se_protegen():
    """Una cookie 'es' aparece en cualquier parte y no es una credencial."""
    with SecretVault() as vault:
        assert vault.protect("es") is False
        assert vault.labels_in("idioma es espanol") == set()


def test_el_expediente_no_guarda_la_sesion(tmp_path):
    vault = SecretVault()
    for value in session_secrets(ESTADO):
        vault.protect(value)
    store = EvidenceStore(tmp_path, "sesion", vault=vault)
    store.open_session("https://plataforma.example", {"level": 3}, {})
    store.add_request(RequestRecord(
        timestamp=1.0, method="GET", url=f"https://plataforma.example/api?t={TOKEN}",
        headers={"Referer": f"https://plataforma.example/?t={TOKEN}"}))
    store.add_event(make_event(EventType.NETWORK_REQUEST, 1.0,
                               url=f"https://plataforma.example/api?t={TOKEN}"))
    store.close()
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert TOKEN.encode() not in path.read_bytes(), f"el token aparece en {path.name}"


# ----------------------------------------------------------------------
# Configuracion y CLI
# ----------------------------------------------------------------------

def test_el_manifiesto_solo_dice_que_habia_sesion(tmp_path):
    ruta = write_session_state(ESTADO, tmp_path / "secreto" / "sesion.json")
    config = AuditConfig(target="https://plataforma.example", browser_path=None,
                         session_state=ruta)
    texto = json.dumps(config.to_dict())
    assert config.to_dict()["authenticated_session"] is True
    assert "secreto" not in texto and TOKEN not in texto


def test_el_modo_manual_muestra_el_navegador():
    config = AuditConfig(target="https://x.example", browser_path=None, manual=True)
    assert config.headless is False


def test_el_modo_manual_exige_un_operador(tmp_path):
    from firmascope.cli.orchestrator import Auditor
    config = AuditConfig(target="https://x.example", browser_path=None, manual=True,
                         output_dir=tmp_path)
    with pytest.raises(ValueError):
        Auditor(config)


def test_audit_rechaza_una_sesion_invalida(tmp_path, capsys):
    (tmp_path / "mala.json").write_text("{roto")
    code = main(["audit", "https://x.example", "--session", str(tmp_path / "mala.json")])
    assert code == 2
    assert "sesion" in capsys.readouterr().err


def test_headed_ya_no_promete_lo_que_no_hace():
    """--headed decia 'opera el sitio a mano', pero no esperaba a nadie."""
    from firmascope.cli.main import build_parser
    ayuda = build_parser()._subparsers._group_actions[0].choices["audit"].format_help()
    assert "--manual" in ayuda
    assert "opera el sitio a mano" not in ayuda


class _FakeChromium:
    def __init__(self, error: str | None = None):
        self.kwargs = None
        self.error = error

    def launch(self, **kwargs):
        self.kwargs = kwargs
        if self.error:
            raise RuntimeError(self.error)
        return "navegador"


class _FakePlaywright:
    def __init__(self, error: str | None = None):
        self.chromium = _FakeChromium(error)


def test_el_sandbox_se_pide_explicitamente_a_playwright(monkeypatch):
    """Playwright anade --no-sandbox salvo que se le pida chromium_sandbox=True.
    No basta con no anadirlo nosotros: hay que pedir el sandbox."""
    import firmascope.browser_controller.launch as launch_mod

    monkeypatch.setattr(launch_mod.os, "geteuid", lambda: 1000, raising=False)
    fake = _FakePlaywright()
    launch_mod.launch_chromium(fake, headless=True, args=["--no-sandbox", "--lang=es"])
    assert fake.chromium.kwargs["chromium_sandbox"] is True
    assert "--no-sandbox" not in fake.chromium.kwargs["args"]
    assert "--lang=es" in fake.chromium.kwargs["args"]


def test_como_root_el_sandbox_se_desactiva(monkeypatch):
    import firmascope.browser_controller.launch as launch_mod

    monkeypatch.setattr(launch_mod.os, "geteuid", lambda: 0, raising=False)
    fake = _FakePlaywright()
    launch_mod.launch_chromium(fake, headless=True)
    assert fake.chromium.kwargs["chromium_sandbox"] is False


def test_el_operador_puede_desactivarlo_explicitamente(monkeypatch):
    import firmascope.browser_controller.launch as launch_mod

    monkeypatch.setattr(launch_mod.os, "geteuid", lambda: 1000, raising=False)
    fake = _FakePlaywright()
    launch_mod.launch_chromium(fake, headless=True, sandbox=False)
    assert fake.chromium.kwargs["chromium_sandbox"] is False


@pytest.mark.parametrize("error,pista", [
    ("error while loading shared libraries: libnspr4.so: cannot open shared object file",
     "install-deps chromium"),
    ("Executable doesn't exist at /home/x/.cache/ms-playwright/chromium-1/chrome",
     "playwright install chromium"),
    ("No usable sandbox! Update your kernel", "--no-sandbox"),
])
def test_los_errores_de_arranque_dicen_que_hacer(error, pista):
    from firmascope.browser_controller.launch import BrowserLaunchError, launch_chromium

    with pytest.raises(BrowserLaunchError) as exc:
        launch_chromium(_FakePlaywright(error), headless=False)
    assert pista in str(exc.value)


def test_la_cli_expone_no_sandbox_como_decision_explicita():
    from firmascope.cli.main import build_parser
    args = build_parser().parse_args(["audit", "https://x.example"])
    assert args.sandbox is None
    args = build_parser().parse_args(["audit", "https://x.example", "--no-sandbox"])
    assert args.sandbox is False
