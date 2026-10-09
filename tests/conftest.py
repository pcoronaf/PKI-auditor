"""Fixturas comunes de las pruebas de FirmaScope.

Las pruebas unitarias no tocan la red ni el navegador. Las marcadas ``e2e``
levantan el laboratorio y un Chromium real: son las unicas que pueden
responder si la herramienta *funciona*, porque comparan los hallazgos con la
verdad conocida del laboratorio (si el recolector recibio los bytes o no).
"""

from __future__ import annotations

import itertools
import sys
import time
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from firmascope.audit_core.config import AuditConfig, AuditLevel  # noqa: E402
from firmascope.audit_core.events import Event, EventType, Tag  # noqa: E402


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


# ----------------------------------------------------------------------
# Constructores de eventos y configuracion (de la rama principal)
# ----------------------------------------------------------------------

#: Instante base de las sesiones sinteticas (epoch plausible, ver MIN_EPOCH).
T0 = 1_750_000_000.0

LABS_DIR = Path(__file__).resolve().parents[1] / "src" / "firmascope" / "labs" / "apps"

_counter = itertools.count()


def make_event(event_type: EventType, offset: float = 0.0, *,
               tags: list[Tag | str] | None = None,
               session: str = "test-session",
               **data: Any) -> Event:
    """Evento sintetico con marca temporal relativa a :data:`T0`."""
    return Event(
        type=event_type,
        session=session,
        timestamp=T0 + offset,
        tags=list(tags or []),
        data=dict(data),
        seq=next(_counter),
    )


def key_access(offset: float = 0.0) -> list[Event]:
    """Secuencia minima de acceso a material privado.

    Es el ancla temporal de casi todas las reglas: sin ella el contexto no
    puede distinguir NOT_OBSERVED de INCONCLUSIVE.
    """
    return [
        make_event(EventType.FILE_READ, offset,
                   tags=[Tag.KEY_FILE], name="fiel.key", size=1702),
        make_event(EventType.PASSWORD_READ, offset + 0.1,
                   tags=[Tag.KEY_PASSWORD], field="password"),
        make_event(EventType.CRYPTO_DECRYPT, offset + 0.2,
                   tags=[Tag.KEY_FILE, Tag.PRIVATE_KEY], algorithm="AES-CBC"),
        make_event(EventType.CRYPTO_IMPORT, offset + 0.3,
                   tags=[Tag.PRIVATE_KEY], format="pkcs8", extractable=False),
    ]


def local_signature(offset: float = 1.0) -> list[Event]:
    """Firma generada dentro del navegador."""
    return [
        make_event(EventType.CRYPTO_SIGN, offset,
                   tags=[Tag.SIGNATURE], algorithm="RSASSA-PKCS1-v1_5"),
    ]


def egress(offset: float, *, tags: list[Tag | str] | None = None,
           url: str = "https://sitio.example/api", host: str = "sitio.example",
           body_size: int = 512, canary_matches: list[dict] | None = None,
           **data: Any) -> Event:
    """Peticion saliente etiquetada."""
    return make_event(EventType.NETWORK_REQUEST, offset, tags=tags,
                      url=url, host=host, method="POST", body_size=body_size,
                      canary_matches=canary_matches or [], **data)


def make_config(**overrides: Any) -> AuditConfig:
    params: dict[str, Any] = {
        "target": "https://sitio.example/firmar",
        "level": AuditLevel.FULL_CORRELATED,
        "headless": True,
        "browser_path": None,
    }
    params.update(overrides)
    return AuditConfig(**params)


@pytest.fixture
def config() -> AuditConfig:
    return make_config()


@pytest.fixture
def lab_sources() -> dict[str, bytes]:
    """Codigo de las cinco aplicaciones de laboratorio, por nombre de demo."""
    out: dict[str, bytes] = {}
    for demo in sorted(p for p in LABS_DIR.iterdir() if p.name.startswith("demo-")):
        out[demo.name] = (demo / "app.js").read_bytes()
    return out
