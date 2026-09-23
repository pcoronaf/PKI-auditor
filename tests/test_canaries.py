"""Pruebas de la busqueda de canarios en lo que sale por la red.

Los sensores de red buscaban el material solo en el cuerpo. Una peticion GET
no tiene cuerpo, y un pixel de seguimiento lleva el .key en la query string:
era una exfiltracion invisible para CDP y para el proxy.
"""

from __future__ import annotations

import base64
from urllib.parse import quote

import pytest

from firmascope.audit_core.events import Tag
from firmascope.audit_core.secrets import SecretVault
from firmascope.network_analyzer.canaries import classify

KEY = bytes(range(256)) * 6


@pytest.fixture
def vault():
    with SecretVault() as v:
        v.register(Tag.KEY_FILE, KEY)
        v.register(Tag.KEY_PASSWORD, "contrasena-de-laboratorio")
        yield v


def test_el_key_en_la_query_de_un_pixel(vault):
    """El caso de demo-side-channels: base64 dentro de encodeURIComponent."""
    url = "https://tercero.example/p.gif?k=" + quote(base64.b64encode(KEY).decode(), safe="")
    assert "%2B" in url or "%2F" in url, "la prueba necesita base64 con caracteres escapados"

    tags, matches = classify(vault, None, url)
    assert Tag.KEY_FILE.value in tags
    assert all(m["location"] == "url" for m in matches)


def test_la_contrasena_en_la_query(vault):
    tags, _ = classify(vault, b"", "https://tercero.example/t?p=contrasena-de-laboratorio")
    assert tags == [Tag.KEY_PASSWORD.value]


def test_el_cuerpo_se_sigue_examinando(vault):
    tags, matches = classify(vault, base64.b64encode(KEY), "https://evil.example/c")
    assert Tag.KEY_FILE.value in tags
    assert matches[0]["location"] == "body"


def test_una_url_limpia_sin_cuerpo_no_se_etiqueta(vault):
    """Toda peticion tiene URL: una URL sin canario no es UNCLASSIFIED."""
    assert classify(vault, None, "https://sitio.example/app.js?v=3") == ([], [])


def test_un_cuerpo_sin_canario_es_unclassified(vault):
    tags, matches = classify(vault, b'{"ok":true}', "https://sitio.example/api")
    assert tags == [Tag.UNCLASSIFIED.value]
    assert matches == []


def test_sin_vault_no_hay_coincidencias():
    assert classify(None, b"x" * 10, "https://sitio.example/?a=b") == ([Tag.UNCLASSIFIED.value], [])


def test_la_misma_coincidencia_no_se_duplica(vault):
    """URL cruda y decodificada pueden encontrar lo mismo: se cuenta una vez."""
    url = "https://t.example/?p=contrasena-de-laboratorio"
    _, matches = classify(vault, None, url)
    claves = [(m["label"], m["encoding"]) for m in matches]
    assert len(claves) == len(set(claves))
