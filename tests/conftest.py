"""Fixturas comunes de las pruebas de FirmaScope.

Las pruebas unitarias no tocan la red ni el navegador. Las marcadas ``e2e``
levantan el laboratorio y un Chromium real: son las unicas que pueden
responder si la herramienta *funciona*, porque comparan los hallazgos con la
verdad conocida del laboratorio (si el recolector recibio los bytes o no).
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture(scope="session")
def credential(tmp_path_factory):
    """Credencial sintetica compartida: generarla cuesta un RSA de 2048."""
    from firmascope.credentials import generate

    cred = generate()
    cred.write(tmp_path_factory.mktemp("efirma"))
    return cred


@pytest.fixture
def vault():
    from firmascope.audit_core.secrets import SecretVault

    store = SecretVault()
    yield store
    store.destroy()


@pytest.fixture(scope="session")
def lab():
    """Portal de laboratorio y recolector de terceros, en hilos de fondo."""
    from firmascope.labs import server as lab_server

    portal, collector = lab_server.serve()
    time.sleep(0.3)
    yield lab_server
    portal.shutdown()
    collector.shutdown()


def analyze_source(source: str):
    """Analiza un fragmento de JavaScript y devuelve el informe estatico."""
    from firmascope.static_analyzer.analyzer import analyze_scripts

    body = source.encode("utf-8")
    scripts = [{"sha256": "probe", "url": "https://site.test/probe.js", "size": len(body)}]
    return analyze_scripts(scripts, lambda _s: body)
