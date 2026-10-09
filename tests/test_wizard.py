"""El asistente: lo que el operador ve y puede corregir.

Se prueba con respuestas guionizadas en lugar de un terminal real, de modo que
las rutas que importan -- revisar, corregir, cancelar y la confirmacion de la
credencial real -- queden cubiertas sin depender de un pty.
"""

from __future__ import annotations

import builtins

import pytest

from firmascope.audit_core.config import CredentialMode, IsolationMode
from firmascope.cli import wizard


@pytest.fixture
def teclear(monkeypatch):
    """Sustituye input() por una lista de respuestas."""
    def _teclear(respuestas):
        pendientes = list(respuestas)
        def fake_input(prompt=""):
            if not pendientes:
                raise AssertionError(f"el asistente pidio mas de lo previsto: {prompt!r}")
            return pendientes.pop(0)
        monkeypatch.setattr(builtins, "input", fake_input)
        return pendientes
    return _teclear


def test_todo_por_defecto_produce_una_configuracion_valida(teclear):
    restantes = teclear(["portal.ejemplo.mx", "", "", "", "", ""])
    setup = wizard.run_setup()
    assert setup is not None
    assert setup.config.target == "https://portal.ejemplo.mx"
    assert int(setup.config.level) == 4
    assert setup.config.credential_mode is CredentialMode.SYNTHETIC
    assert not restantes


def test_el_numero_tecleado_es_el_nivel_y_no_la_posicion(teclear):
    """Teclear "2" debe elegir el nivel 2, no la segunda alternativa listada."""
    teclear(["sitio.mx", "2", "", "", "", ""])
    setup = wizard.run_setup()
    assert int(setup.config.level) == 2


def test_se_puede_cancelar_en_la_revision(teclear):
    teclear(["sitio.mx", "", "", "", "", "c"])
    assert wizard.run_setup() is None


def test_se_puede_corregir_desde_la_revision(teclear):
    """[numero] edita ese campo y vuelve al resumen."""
    teclear([
        "primero.mx", "", "", "", "",   # basicas + avanzadas (no)
        "1", "segundo.mx",              # editar el campo 1
        "",                             # iniciar
    ])
    setup = wizard.run_setup()
    assert setup is not None
    assert setup.config.target == "https://segundo.mx"


def test_la_credencial_propia_pide_los_archivos_y_la_contrasena(
        teclear, credential, monkeypatch):
    """Con credencial propia aparecen los campos .key/.cer, que deben existir.

    La contrasena se pide aparte y nunca por el mismo camino que el resto de
    las respuestas: va por getpass, no se hace eco y no entra en `answers`.
    """
    monkeypatch.setattr(wizard.getpass, "getpass", lambda prompt="": "secreto")
    restantes = teclear([
        "sitio.mx", "", "2",             # sitio, nivel por defecto, own-test
        str(credential.key_path),
        str(credential.cert_path),
        "", "",                          # aislamiento, avanzadas (no)
        "",                              # iniciar
    ])
    setup = wizard.run_setup()
    assert setup is not None
    assert setup.config.credential_mode is CredentialMode.OWN_TEST
    assert setup.password == "secreto"
    assert setup.key_path and setup.cert_path
    assert "secreto" not in str(setup.answers)
    assert not restantes


def test_no_arranca_con_un_archivo_que_no_existe(teclear, credential, tmp_path):
    """El campo se vuelve a pedir en lugar de arrancar con una ruta invalida."""
    inexistente = tmp_path / "no-esta.key"
    restantes = teclear([
        "sitio.mx", "", "2",
        str(inexistente),                # rechazado: no existe
        str(credential.key_path),        # segundo intento, valido
        str(credential.cert_path),
        "", "",
        "",
    ])
    import firmascope.cli.wizard as mod
    teclear_pwd = lambda prompt="": "x"
    mod.getpass.getpass, original = teclear_pwd, mod.getpass.getpass
    try:
        setup = wizard.run_setup()
    finally:
        mod.getpass.getpass = original
    assert setup is not None
    assert str(setup.key_path) == str(credential.key_path)
    assert not restantes


def test_la_credencial_real_exige_escribir_acepto(teclear):
    """Un "si" no basta: hay que escribir la palabra."""
    teclear(["sitio.mx", "", "3", "si"])
    assert wizard.run_setup() is None, "se acepto el modo real sin la confirmacion"


def test_la_semilla_no_se_vuelve_a_preguntar_como_si_no_se_hubiera_dicho(teclear):
    """Lo indicado por argumento aparece como valor por defecto."""
    teclear(["", "", "", "", "", ""])
    setup = wizard.run_setup(seed={"target": "sembrado.mx", "level": "3"})
    assert setup.config.target == "https://sembrado.mx"
    assert int(setup.config.level) == 3


def test_el_menu_en_marcha_solo_ofrece_lo_que_puede_cambiarse(teclear, monkeypatch):
    from firmascope.audit_core import options

    config = options.build_config(options.defaults())
    teclear(["1", "2"])   # cambiar el aislamiento -> "Solo terceros"
    descrito = wizard.live_menu(config)
    assert descrito
    assert config.isolation.mode is IsolationMode.THIRD_PARTY
    # El nivel y la credencial no estan en el menu: no son modificables.
    assert {o.id for o in options.LIVE_OPTIONS}.isdisjoint({"level", "credentials"})
