"""Coherencia de la interfaz, sin navegador.

Son comprobaciones baratas que atrapan la clase de error que mas se cuela en una
interfaz: un identificador renombrado en el HTML y no en el JS, un boton sin
manejador, o -- lo importante aqui -- que la interfaz empiece a decidir por su
cuenta cosas que debe preguntar al nucleo.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "gui" / "ui"

if not (UI / "index.html").is_file():  # pragma: no cover
    pytest.skip("la interfaz no esta en el arbol", allow_module_level=True)

HTML = (UI / "index.html").read_text(encoding="utf-8")
JS = (UI / "app.js").read_text(encoding="utf-8")
CSS = (UI / "app.css").read_text(encoding="utf-8")


def test_todo_identificador_que_usa_el_js_existe_en_el_html():
    usados = set(re.findall(r"\$\('([a-z0-9-]+)'\)", JS))
    declarados = set(re.findall(r'id="([a-z0-9-]+)"', HTML))
    assert usados, "el JS no referencia ningun identificador"
    assert usados <= declarados, f"ausentes en el HTML: {sorted(usados - declarados)}"


def test_todo_boton_tiene_manejador():
    en_html = set(re.findall(r'data-action="([a-z-]+)"', HTML))
    manejadas = set(re.findall(r"^\s*'?([a-z-]+)'?:\s", JS, re.M))
    assert en_html, "no hay botones con accion"
    assert en_html <= manejadas, f"sin manejador: {sorted(en_html - manejadas)}"


def test_las_vistas_declaradas_en_el_js_existen():
    vistas = set(re.findall(r"'(view-[a-z]+)'", JS))
    declaradas = set(re.findall(r'id="(view-[a-z]+)"', HTML))
    assert vistas == declaradas, (
        f"solo en JS: {sorted(vistas - declaradas)}; "
        f"solo en HTML: {sorted(declaradas - vistas)}")


def test_los_estados_de_conclusion_coinciden_con_el_nucleo():
    """Si el nucleo anade un estado, la interfaz debe saber pintarlo."""
    from firmascope.audit_core.conclusions import Status

    # STATUS_LABEL puede tener varias entradas por linea.
    etiquetados = set(re.findall(r"\b([A-Z_]+):\s*'", JS))
    con_estilo = set(re.findall(r"\.finding\.([A-Z_]+)", CSS))
    del_nucleo = {s.value for s in Status}
    assert del_nucleo <= etiquetados, \
        f"sin etiqueta en la interfaz: {sorted(del_nucleo - etiquetados)}"
    assert del_nucleo <= con_estilo, \
        f"sin estilo en la interfaz: {sorted(del_nucleo - con_estilo)}"


def test_la_interfaz_no_construye_campos_a_mano():
    """Los campos salen del esquema, no de una lista en el JS.

    Si la interfaz construyera o leyera campos por identificador, habria dos
    catalogos y podrian discrepar. Se buscan las dos formas en que eso
    ocurriria: seleccionar un campo por `data-option` y leer `state.answers`
    con un identificador literal. Las excepciones son decisiones de
    presentacion, no de contenido.
    """
    from firmascope.audit_core import options

    permitidas = {
        "credentials",         # decide si hace falta la pantalla de consentimiento
        "accept_real_risk",    # tiene pantalla propia, no es un campo del form
        "key_path", "cert_path",   # extensiones del selector de archivos
        "session_file",        # extension, y el boton de iniciar sesion a su lado
    }
    construidos = set(re.findall(r"data-option='([a-z_]+)'", JS))
    construidos |= set(re.findall(r"answers\[['\"]([a-z_]+)['\"]\]", JS))
    construidos |= set(re.findall(r"answers\.([a-z_]+)\b", JS))
    del_esquema = {o.id for o in options.AUDIT_OPTIONS}
    inventados = construidos - del_esquema
    assert not inventados, f"campos que el esquema no tiene: {sorted(inventados)}"
    assert construidos <= permitidas, (
        "la interfaz maneja campos por identificador en lugar de por esquema: "
        f"{sorted(construidos - permitidas)}")


def test_los_tipos_de_campo_del_esquema_estan_todos_soportados():
    from firmascope.audit_core.options import OptionKind

    for kind in OptionKind:
        assert f"'{kind.value}'" in JS, f"la interfaz no sabe pintar {kind.value}"


def test_la_interfaz_no_abre_ningun_puerto_ni_pide_a_la_red():
    """Un puerto o un fetch externo serian superficie que no debe existir."""
    assert "fetch(" not in JS
    assert "XMLHttpRequest" not in JS
    assert "WebSocket" not in JS
    assert "localhost" not in JS
    assert not re.search(r'src="https?://', HTML)
    assert not re.search(r'href="https?://', HTML)


def test_el_protocolo_que_habla_la_interfaz_es_el_del_nucleo():
    from firmascope.gui_bridge.bridge import PROTOCOL_VERSION

    rust = (ROOT / "gui" / "src-tauri" / "src" / "main.rs").read_text(encoding="utf-8")
    declarado = re.search(r"const PROTOCOL: u64 = (\d+);", rust)
    assert declarado, "la capa de Rust no declara version de protocolo"
    assert int(declarado.group(1)) == PROTOCOL_VERSION


def test_todo_comando_que_envia_la_interfaz_existe_en_el_puente():
    from firmascope.gui_bridge.bridge import Bridge

    enviados = set(re.findall(r"call\('([a-z_]+)'", JS))
    enviados |= set(re.findall(r"__bridgeRelay\('([a-z_]+)'", JS))
    disponibles = {name[4:] for name in dir(Bridge) if name.startswith("cmd_")}
    assert enviados, "la interfaz no envia ningun comando"
    assert enviados <= disponibles, \
        f"comandos inexistentes: {sorted(enviados - disponibles)}"
