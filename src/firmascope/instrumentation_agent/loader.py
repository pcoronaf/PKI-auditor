"""Carga e inyeccion del agente de instrumentacion."""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from ..audit_core.events import Event, EventType

AGENT_PATH = Path(__file__).parent / "agent.js"

#: Nombre del binding expuesto por Playwright/CDP para recibir eventos.
DEFAULT_CHANNEL = "__firmascope_report"


@lru_cache(maxsize=1)
def agent_source() -> str:
    return AGENT_PATH.read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def agent_sha256() -> str:
    """Hash del agente, registrado en ``manifest.json`` (reproducibilidad)."""
    return hashlib.sha256(agent_source().encode("utf-8")).hexdigest()


def build_init_script(session_id: str, channel: str = DEFAULT_CHANNEL,
                      context: str | None = None, max_queue: int = 5000) -> str:
    """Genera el script que se inyecta antes del JavaScript del sitio.

    El agente recibe su propia fuente en ``__FS_AGENT_SRC__`` para poder
    reinyectarse dentro de los workers que la aplicacion cree.
    """
    source = agent_source()
    config: dict[str, Any] = {"session": session_id, "channel": channel, "maxQueue": max_queue}
    if context:
        config["context"] = context
    return (
        "globalThis.__FIRMASCOPE_CONFIG__=" + json.dumps(config) + ";\n"
        "globalThis.__FS_AGENT_SRC__=" + json.dumps(source) + ";\n"
        + source
    )


def record_to_event(record: dict[str, Any], session_id: str, context_hint: str = "") -> Event:
    """Convierte un registro emitido por el agente en un :class:`Event`."""
    raw_type = str(record.get("t", "AGENT_ERROR"))
    try:
        event_type = EventType(raw_type)
    except ValueError:
        event_type = EventType.AGENT_ERROR
    data = dict(record.get("data") or {})
    if record.get("href"):
        data.setdefault("href", record["href"])
    if record.get("relayed_from"):
        data.setdefault("relayed_from", record["relayed_from"])
    context = context_hint or str(record.get("ctx") or "main")
    return Event(
        type=event_type,
        session=session_id,
        timestamp=float(record.get("ts") or 0.0),
        context=context,
        origin=str(record.get("origin") or ""),
        source=str(record.get("src") or ""),
        sensor="agent",
        tags=list(record.get("tags") or []),
        data=data,
    )
