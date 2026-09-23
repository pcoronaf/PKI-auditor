"""Utilidades compartidas por la suite.

Las pruebas construyen sesiones sinteticas: en lugar de arrancar un navegador,
fabrican la lista de eventos que la instrumentacion habria producido. Eso
permite fijar el comportamiento del motor de reglas — que es donde viven las
afirmaciones del reporte — sin depender de Chromium.
"""

from __future__ import annotations

import itertools
from pathlib import Path
from typing import Any

import pytest

from firmascope.audit_core.config import AuditConfig, AuditLevel
from firmascope.audit_core.events import Event, EventType, Tag

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
