"""Contexto de evaluacion del motor de reglas.

Agrupa todo lo que una regla puede necesitar (eventos, peticiones, scripts,
analisis estatico, checkpoints) y ofrece consultas temporales elementales:
cuando se accedio por primera vez a la clave, que salio despues, si el
navegador estaba aislado en un instante dado.

Las preguntas de *causalidad* (reconstruir la cadena completa de procedencia)
son competencia del motor de correlacion, que se inyecta en ``correlation``
cuando esta disponible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from ..audit_core.config import AuditConfig
from ..audit_core.events import (
    EGRESS_EVENTS,
    KEY_ACCESS_EVENTS,
    Event,
    EventType,
    Tag,
)
from ..network_analyzer import domains
from ..static_analyzer.analyzer import StaticReport

#: Marca temporal minima considerada "epoch plausible" (2001-09-09).
#: Algunos eventos de CDP traen tiempos monotonos desde el arranque del
#: navegador; compararlos con tiempos de pared produciria ordenes falsos.
MIN_EPOCH = 1_000_000_000.0

#: Codificaciones de canario que demuestran transmision *directa* del material.
DIRECT_ENCODINGS = frozenset(
    {"raw", "raw-marker", "base64", "base64url", "base64-marker", "hex", "utf8", "url", "utf16le"}
)

#: Tipos de cuerpo que se consideran binarios opacos.
BINARY_BODY_TYPES = frozenset({"ArrayBuffer", "Blob", "Uint8Array", "Int8Array", "DataView", "TypedArray"})


@dataclass
class AuditContext:
    """Entrada unica de todas las reglas."""

    config: AuditConfig
    events: list[Event] = field(default_factory=list)
    requests: list[dict[str, Any]] = field(default_factory=list)
    scripts: list[dict[str, Any]] = field(default_factory=list)
    checkpoints: list[dict[str, Any]] = field(default_factory=list)
    static: StaticReport | None = None
    correlation: Any | None = None
    #: Etiquetas de canario registradas en el vault de la sesion.
    canary_labels: set[str] = field(default_factory=set)

    # -- consultas basicas ----------------------------------------------
    def events_of(self, *types: EventType) -> list[Event]:
        wanted = set(types)
        return [e for e in self.events if e.type in wanted]

    def events_with_tag(self, *tags: Tag | str) -> list[Event]:
        wanted = {t.value if isinstance(t, Tag) else t for t in tags}
        return [e for e in self.events if wanted & set(e.tags)]

    def egress_events(self) -> list[Event]:
        return [e for e in self.events if e.type in EGRESS_EVENTS]

    def key_access_events(self) -> list[Event]:
        return [e for e in self.events if e.type in KEY_ACCESS_EVENTS]

    # -- tiempo ----------------------------------------------------------
    @staticmethod
    def usable_time(event_or_ts: Event | float | None) -> float | None:
        """Devuelve la marca temporal si es comparable, o ``None``."""
        if event_or_ts is None:
            return None
        ts = event_or_ts.timestamp if isinstance(event_or_ts, Event) else float(event_or_ts)
        return ts if ts >= MIN_EPOCH else None

    def first_key_access(self) -> Event | None:
        """Primer evento que implica acceso a material privado."""
        candidates = [e for e in self.key_access_events() if self.usable_time(e) is not None]
        return min(candidates, key=lambda e: e.timestamp) if candidates else None

    def observed_key_material(self) -> bool:
        """True si la sesion llego a manejar material privado.

        Si nunca ocurrio, las reglas sobre egress de la clave no pueden
        concluir nada: el estado correcto es ``INCONCLUSIVE``, no
        ``NOT_OBSERVED``.
        """
        if self.key_access_events():
            return True
        return bool(self.events_with_tag(Tag.KEY_FILE, Tag.PRIVATE_KEY))

    def observed_password(self) -> bool:
        return bool(self.events_of(EventType.PASSWORD_READ)) or bool(
            self.events_with_tag(Tag.KEY_PASSWORD))

    def after_key_access(self, events: Iterable[Event]) -> list[Event]:
        """Filtra los eventos posteriores al primer acceso a la clave."""
        anchor = self.first_key_access()
        if anchor is None:
            return []
        start = anchor.timestamp
        out = []
        for event in events:
            ts = self.usable_time(event)
            if ts is not None and ts >= start:
                out.append(event)
        return out

    def within_window(self, events: Iterable[Event], window_ms: int | None = None) -> list[Event]:
        """Eventos dentro de la ventana de correlacion tras el acceso a la clave."""
        anchor = self.first_key_access()
        if anchor is None:
            return []
        window = (window_ms if window_ms is not None else self.config.correlation_window_ms) / 1000.0
        return [e for e in self.after_key_access(events)
                if e.timestamp - anchor.timestamp <= window]

    # -- estado de red ---------------------------------------------------
    def offline_windows(self) -> list[tuple[float, float | None]]:
        """Intervalos ``(inicio, fin)`` en los que la red estuvo aislada."""
        windows: list[tuple[float, float | None]] = []
        start: float | None = None
        for event in sorted(self.events, key=lambda e: e.timestamp):
            if event.type is EventType.NETWORK_OFF and start is None:
                start = event.timestamp
            elif event.type is EventType.NETWORK_ON and start is not None:
                windows.append((start, event.timestamp))
                start = None
        if start is not None:
            windows.append((start, None))
        return windows

    def offline_at(self, timestamp: float) -> bool:
        for start, end in self.offline_windows():
            if timestamp >= start and (end is None or timestamp <= end):
                return True
        return False

    def offline_test_ran(self) -> bool:
        return bool(self.offline_windows())

    def events_while_offline(self, events: Iterable[Event]) -> list[Event]:
        return [e for e in events if self.offline_at(e.timestamp)]

    # -- egress etiquetado -----------------------------------------------
    def canary_matches(self, event: Event) -> list[dict[str, Any]]:
        matches = event.data.get("canary_matches")
        return list(matches) if isinstance(matches, list) else []

    def direct_egress(self, *labels: Tag | str) -> list[Event]:
        """Egress que transporta el material *tal cual* (sin transformar).

        Dos fuentes de evidencia independientes:

        * el proxy o CDP encontraron una representacion del canario en el
          cuerpo (prueba directa: los bytes estaban ahi);
        * la instrumentacion etiqueto el dato y no lo marco como derivado.
        """
        wanted = {t.value if isinstance(t, Tag) else t for t in labels}
        out: list[Event] = []
        for event in self.egress_events():
            tags = set(event.tags)
            matches = self.canary_matches(event)
            if any(m.get("label") in wanted and m.get("encoding") in DIRECT_ENCODINGS for m in matches):
                out.append(event)
                continue
            if wanted & tags and Tag.DERIVED.value not in tags:
                out.append(event)
        return out

    def derived_egress(self, *labels: Tag | str) -> list[Event]:
        """Egress que transporta datos *derivados* del material indicado."""
        wanted = {t.value if isinstance(t, Tag) else t for t in labels}
        out: list[Event] = []
        for event in self.egress_events():
            tags = set(event.tags)
            if wanted & tags and Tag.DERIVED.value in tags:
                out.append(event)
        return out

    def any_egress(self, *labels: Tag | str) -> list[Event]:
        wanted = {t.value if isinstance(t, Tag) else t for t in labels}
        out: list[Event] = []
        for event in self.egress_events():
            if wanted & set(event.tags):
                out.append(event)
                continue
            if any(m.get("label") in wanted for m in self.canary_matches(event)):
                out.append(event)
        return out

    def unclassified_binary_egress(self) -> list[Event]:
        """Salidas binarias sin clasificar: candidatas a exfiltracion opaca."""
        out: list[Event] = []
        for event in self.egress_events():
            tags = set(event.tags)
            if tags - {Tag.UNCLASSIFIED.value}:
                continue  # ya esta clasificado por otra via
            size = int(event.data.get("body_size") or event.data.get("size") or 0)
            if size < 64:
                continue
            body_type = str(event.data.get("body_type") or "")
            content_type = str(event.data.get("content_type") or "")
            if body_type in BINARY_BODY_TYPES or "octet-stream" in content_type:
                out.append(event)
        return out

    # -- almacenamiento ---------------------------------------------------
    def storage_writes(self, store: str | None = None, labels: Sequence[Tag | str] = ()) -> list[Event]:
        wanted = {t.value if isinstance(t, Tag) else t for t in labels}
        out: list[Event] = []
        for event in self.events_of(EventType.STORAGE_WRITE):
            if store and str(event.data.get("store", "")).lower() != store.lower():
                continue
            if wanted and not (wanted & set(event.tags)):
                continue
            out.append(event)
        return out

    # -- terceros ----------------------------------------------------------
    def third_party_requests(self) -> list[dict[str, Any]]:
        return [r for r in self.requests if r.get("third_party")]

    def third_parties_after_key_access(self) -> dict[str, list[dict[str, Any]]]:
        """Dominios de tercero que recibieron trafico tras el acceso a la clave."""
        anchor = self.first_key_access()
        if anchor is None:
            return {}
        grouped: dict[str, list[dict[str, Any]]] = {}
        for request in self.third_party_requests():
            ts = self.usable_time(request.get("timestamp"))
            if ts is None or ts < anchor.timestamp:
                continue
            domain = request.get("registrable_domain") or domains.host_of(request.get("url", ""))
            grouped.setdefault(domain, []).append(request)
        return grouped

    def third_party_names(self) -> dict[str, str]:
        names: dict[str, str] = {}
        for request in self.third_party_requests():
            domain = request.get("registrable_domain") or ""
            if domain and domain not in names:
                names[domain] = domains.third_party_name(request.get("url", "")) or domain
        return names

    # -- utilidades para construir evidencia ------------------------------
    @staticmethod
    def event_evidence(event: Event, note: str = "") -> dict[str, Any]:
        return {
            "type": "event",
            "event_id": event.id,
            "seq": event.seq,
            "event_type": event.type.value,
            "timestamp": round(event.timestamp, 3),
            "context": event.context,
            "source": event.source,
            "sensor": event.sensor,
            "tags": list(event.tags),
            "url": event.data.get("url", ""),
            "note": note,
        }

    @staticmethod
    def request_evidence(request: dict[str, Any], note: str = "") -> dict[str, Any]:
        return {
            "type": "request",
            "request_id": request.get("id", ""),
            "method": request.get("method", ""),
            "url": request.get("url", ""),
            "timestamp": request.get("timestamp"),
            "body_size": request.get("body_size", 0),
            "third_party": bool(request.get("third_party")),
            "note": note,
        }

    @staticmethod
    def code_evidence(path: Any, note: str = "") -> dict[str, Any]:
        return {
            "type": "code",
            "file": path.file_label,
            "url": path.url,
            "line": path.sink_line,
            "source": path.source.name,
            "sink": path.sink_name,
            "snippet": path.sink_snippet,
            "transforms": list(path.transforms),
            "call_chain": list(path.call_chain),
            "confidence": path.confidence.value,
            "note": note,
        }
