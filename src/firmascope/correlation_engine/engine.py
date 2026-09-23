"""Motor de correlacion.

El :class:`~firmascope.rule_engine.context.AuditContext` responde preguntas
locales: que salio, cuando, con que etiqueta. Este modulo responde la pregunta
*causal*: reconstruir, para cada salida, la cadena completa desde el material
original hasta el canal por el que salio.

    S1 KEY_FILE + S2 KEY_PASSWORD --decrypt--> S3 PRIVATE_KEY
    S3 + S5 DOCUMENT              --sign-->    S6 SIGNATURE

La primera cadena es la operacion legitima de una e.firma. La segunda es lo
que todo sitio correcto hace y debe poder enviar. Una cadena que termina en un
canal de salida transportando S1, S2 o S3 es una exfiltracion, y el motor no
necesita interpretar el contenido transmitido para afirmarlo: le basta con la
procedencia.

Tres cosas hace este motor que ningun sensor aislado puede hacer:

1. **Encadenar**: unir los eventos de una sesion en la secuencia de
   transformaciones que llevo del .key al canal de salida.
2. **Corroborar**: la misma salida puede verla la instrumentacion (que la
   etiqueta), CDP (que la observa) y el proxy (que encuentra el canario en el
   cuerpo). Tres sensores independientes sobre el mismo hecho sostienen una
   conclusion que uno solo no sostiene.
3. **Atribuir en el tiempo**: situar cada salida respecto del primer acceso al
   material privado, que es el instante que da sentido al resto.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from ..audit_core.config import AuditConfig
from ..audit_core.conclusions import Confidence
from ..audit_core.events import (
    EGRESS_EVENTS,
    PRIVATE_TAGS,
    Event,
    EventType,
    Tag,
    is_key_access,
)
from ..network_analyzer import domains

PRIVATE_LABELS = frozenset(t.value for t in PRIVATE_TAGS)

#: Material que una aplicacion correcta si debe poder enviar.
PUBLIC_LABELS = frozenset({Tag.SIGNATURE.value, Tag.CERTIFICATE.value, Tag.DOCUMENT.value})

#: Eventos que transforman material conservando (o cambiando) su procedencia.
TRANSFORM_EVENTS = frozenset(
    {
        EventType.CRYPTO_DECRYPT,
        EventType.CRYPTO_ENCRYPT,
        EventType.CRYPTO_IMPORT,
        EventType.CRYPTO_EXPORT,
        EventType.CRYPTO_WRAP,
        EventType.CRYPTO_UNWRAP,
        EventType.CRYPTO_DERIVE,
        EventType.CRYPTO_DIGEST,
        EventType.CRYPTO_SIGN,
    }
)

#: Eventos que introducen material sensible en la pagina.
SOURCE_EVENTS = frozenset(
    {EventType.FILE_READ, EventType.FILE_SELECTED, EventType.PASSWORD_READ}
)

#: Descripcion legible de cada transformacion, para la narrativa del reporte.
TRANSFORM_NAMES = {
    EventType.CRYPTO_DECRYPT: "descifrado",
    EventType.CRYPTO_ENCRYPT: "cifrado",
    EventType.CRYPTO_IMPORT: "importacion de clave",
    EventType.CRYPTO_EXPORT: "exportacion de clave",
    EventType.CRYPTO_WRAP: "envoltura de clave",
    EventType.CRYPTO_UNWRAP: "desenvoltura de clave",
    EventType.CRYPTO_DERIVE: "derivacion",
    EventType.CRYPTO_DIGEST: "resumen criptografico",
    EventType.CRYPTO_SIGN: "firma",
}

#: Tolerancia (segundos) para dar por identico un egress visto por dos sensores.
MATCH_TOLERANCE_S = 2.0

#: Marca temporal minima considerada epoch plausible (ver AuditContext.MIN_EPOCH).
MIN_EPOCH = 1_000_000_000.0

VERDICT_EXFILTRATION = "exfiltration"
VERDICT_LEGITIMATE = "legitimate"
VERDICT_UNCLASSIFIED = "unclassified"


# ----------------------------------------------------------------------
# Estructuras
# ----------------------------------------------------------------------

@dataclass
class Step:
    """Un eslabon de la cadena de procedencia."""

    event: Event
    kind: str              # "source" | "transform" | "egress"
    description: str
    labels: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "description": self.description,
            "labels": list(self.labels),
            "event_id": self.event.id,
            "seq": self.event.seq,
            "event_type": self.event.type.value,
            "timestamp": round(self.event.timestamp, 3),
            "context": self.event.context,
            "source": self.event.source,
            "sensor": self.event.sensor,
        }


@dataclass
class Chain:
    """Cadena reconstruida desde el material hasta un canal de salida."""

    egress: Event
    steps: list[Step]
    labels: list[str]
    #: El material salio tal cual (o en codificacion reversible).
    direct: bool
    #: Lo que salio es una transformacion del material, no el material.
    derived: bool
    #: Sensores independientes que sostienen la salida: agent, cdp, proxy, canary.
    corroboration: list[str]
    #: Milisegundos entre el primer acceso al material y la salida.
    latency_ms: int | None
    verdict: str
    #: Peticion de red correlacionada, si algun sensor de red la vio.
    request: dict[str, Any] | None = None

    @property
    def private(self) -> bool:
        return bool(set(self.labels) & PRIVATE_LABELS)

    @property
    def third_party(self) -> bool:
        return bool(self.request and self.request.get("third_party"))

    def destination(self) -> str:
        host = str(self.egress.data.get("host") or "")
        if host:
            return host
        url = str(self.egress.data.get("url") or "")
        return domains.host_of(url) or url

    def confidence(self) -> Confidence:
        """Confianza sostenida por el numero de sensores independientes.

        Un canario encontrado en el cuerpo es prueba directa — los bytes
        estaban ahi. El etiquetado de la instrumentacion es una reconstruccion,
        fiable pero aproximada. Dos sensores coincidiendo valen mas que uno.
        """
        if "canary" in self.corroboration:
            return Confidence.HIGH
        if len(self.corroboration) >= 2:
            return Confidence.HIGH
        return Confidence.MEDIUM

    def narrative(self) -> str:
        """La cadena en una linea, para el reporte."""
        return " -> ".join(step.description for step in self.steps)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "labels": list(self.labels),
            "direct": self.direct,
            "derived": self.derived,
            "private": self.private,
            "third_party": self.third_party,
            "destination": self.destination(),
            "latency_ms": self.latency_ms,
            "corroboration": list(self.corroboration),
            "confidence": self.confidence().value,
            "narrative": self.narrative(),
            "steps": [step.to_dict() for step in self.steps],
            "request_id": (self.request or {}).get("id", ""),
        }


@dataclass
class CorrelationReport:
    """Resultado del motor de correlacion."""

    chains: list[Chain] = field(default_factory=list)
    first_key_access: Event | None = None
    #: Transformaciones observadas, en orden (para la narrativa del reporte).
    transforms: list[Step] = field(default_factory=list)
    #: Salidas que no pudieron atribuirse a ninguna procedencia.
    unattributed: list[Event] = field(default_factory=list)

    # -- consultas -------------------------------------------------------
    def exfiltration_chains(self) -> list[Chain]:
        return [c for c in self.chains if c.verdict == VERDICT_EXFILTRATION]

    def legitimate_chains(self) -> list[Chain]:
        return [c for c in self.chains if c.verdict == VERDICT_LEGITIMATE]

    def chains_with_label(self, *labels: Tag | str) -> list[Chain]:
        wanted = {t.value if isinstance(t, Tag) else t for t in labels}
        return [c for c in self.chains if wanted & set(c.labels)]

    def direct_chains(self, *labels: Tag | str) -> list[Chain]:
        return [c for c in self.chains_with_label(*labels) if c.direct]

    def derived_chains(self, *labels: Tag | str) -> list[Chain]:
        return [c for c in self.chains_with_label(*labels) if c.derived]

    def corroborated_chains(self) -> list[Chain]:
        """Cadenas sostenidas por mas de un sensor independiente."""
        return [c for c in self.chains if len(c.corroboration) >= 2]

    def local_signature_chain(self) -> Chain | None:
        """La cadena legitima S3 + S5 --sign--> S6, si se observo."""
        for chain in self.chains:
            if Tag.SIGNATURE.value in chain.labels and chain.verdict == VERDICT_LEGITIMATE:
                return chain
        return None

    def summary(self) -> dict[str, Any]:
        return {
            "chains": len(self.chains),
            "exfiltration": len(self.exfiltration_chains()),
            "legitimate": len(self.legitimate_chains()),
            "corroborated": len(self.corroborated_chains()),
            "unattributed": len(self.unattributed),
            "transforms": len(self.transforms),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "first_key_access": (
                round(self.first_key_access.timestamp, 3) if self.first_key_access else None),
            "chains": [c.to_dict() for c in self.chains],
            "transforms": [t.to_dict() for t in self.transforms],
            "unattributed": [
                {
                    "event_id": e.id,
                    "event_type": e.type.value,
                    "url": e.data.get("url", ""),
                    "body_size": e.data.get("body_size", 0),
                    "timestamp": round(e.timestamp, 3),
                }
                for e in self.unattributed
            ],
        }


# ----------------------------------------------------------------------
# Motor
# ----------------------------------------------------------------------

class CorrelationEngine:
    """Reconstruye las cadenas de procedencia de una sesion."""

    def __init__(self, config: AuditConfig | None = None):
        self.config = config

    @property
    def window_s(self) -> float:
        ms = self.config.correlation_window_ms if self.config else 5000
        return ms / 1000.0

    # ------------------------------------------------------------------
    def run(self, events: Sequence[Event],
            requests: Sequence[dict[str, Any]] = ()) -> CorrelationReport:
        ordered = sorted(events, key=lambda e: (e.timestamp, e.seq))
        report = CorrelationReport()

        sources = [e for e in ordered if e.type in SOURCE_EVENTS or _is_source_tagged(e)]
        transforms = [e for e in ordered if e.type in TRANSFORM_EVENTS]
        report.transforms = [
            Step(event=e, kind="transform", description=_describe_transform(e),
                 labels=list(e.tags))
            for e in transforms
        ]
        report.first_key_access = _first_key_access(ordered)

        egresses = _merge_sensor_views([e for e in ordered if e.type in EGRESS_EVENTS])
        for egress in egresses:
            chain = self._chain_for(egress, sources, transforms, report.first_key_access, requests)
            if chain is None:
                report.unattributed.append(egress)
            else:
                report.chains.append(chain)

        report.chains.sort(key=_chain_sort_key)
        return report

    # ------------------------------------------------------------------
    def _chain_for(self, egress: Event, sources: Sequence[Event],
                   transforms: Sequence[Event], anchor: Event | None,
                   requests: Sequence[dict[str, Any]]) -> Chain | None:
        labels = _labels_of(egress)
        if not labels:
            return None

        egress_ts = _usable(egress.timestamp)
        earlier = [t for t in transforms if not _after(t, egress_ts)]

        # 1. Cierre transitivo hacia atras.
        #
        # Lo que sale etiquetado PRIVATE_KEY no se leyo de ningun fichero: se
        # produjo descifrando el .key con la contrasena. Para que la cadena
        # llegue hasta el material original hay que recorrer las
        # transformaciones en orden inverso, incorporando en cada una las
        # etiquetas de sus entradas.
        relevant = set(labels)
        for transform in sorted(earlier, key=lambda e: (-e.timestamp, -e.seq)):
            transform_labels = _labels_of(transform)
            if transform_labels & relevant:
                relevant |= transform_labels

        steps: list[Step] = []

        # 2. Origenes: los eventos que introdujeron este material en la pagina.
        for source in sources:
            # Un origen posterior a la salida no pudo alimentarla: en una
            # plataforma real el mismo documento se carga varias veces, y cada
            # envio solo puede narrar las lecturas que lo precedieron.
            if not (_labels_of(source) & relevant) or _after(source, egress_ts):
                continue
            steps.append(Step(event=source, kind="source",
                              description=_describe_source(source),
                              labels=sorted(_labels_of(source))))

        # 3. Transformaciones anteriores a la salida que tocaron el material.
        for transform in earlier:
            if not (_labels_of(transform) & relevant):
                continue
            steps.append(Step(event=transform, kind="transform",
                              description=_describe_transform(transform),
                              labels=sorted(_labels_of(transform))))

        steps.sort(key=lambda s: (s.event.timestamp, s.event.seq))

        # 4. La salida. Sus etiquetas — no las del cierre — son las que
        #    determinan el veredicto: el cierre sirve para narrar, no para
        #    acusar.
        steps.append(Step(event=egress, kind="egress",
                          description=_describe_egress(egress),
                          labels=sorted(labels)))

        request = _match_request(egress, requests)
        corroboration = _corroboration(egress, request)
        derived = Tag.DERIVED.value in egress.tags
        direct = _is_direct(egress, labels, derived)

        return Chain(
            egress=egress,
            steps=steps,
            labels=sorted(labels),
            direct=direct,
            derived=derived,
            corroboration=corroboration,
            latency_ms=_latency_ms(anchor, egress),
            verdict=_verdict(labels),
            request=request,
        )


# ----------------------------------------------------------------------
# Auxiliares
# ----------------------------------------------------------------------

def _merge_sensor_views(egresses: Sequence[Event]) -> list[Event]:
    """Funde las vistas que distintos sensores tienen de una misma salida.

    En nivel 3 o 4 una sola peticion la ven la instrumentacion (que la
    etiqueta), CDP (que la observa) y el proxy (que le busca canarios). Sin
    fundirlas, el reporte contaria tres exfiltraciones donde hubo una, y ese
    recuento inflado es justo lo que una herramienta de auditoria no puede
    permitirse.

    Criterio, conservador:

    * solo se funden vistas de **sensores distintos** sobre la **misma URL**:
      dos salidas vistas por el mismo sensor son dos salidas, aunque
      coincidan en todo;
    * las vistas deben estar **proximas en el tiempo** (``MATCH_TOLERANCE_S``).
      El tamano no sirve como criterio principal: el proxy mide el cuerpo tal
      como viaja por el cable — un multipart con sus fronteras — mientras que
      el agente estima el tamano del FormData antes de codificarlo, y CDP a
      veces no llega a verlo;
    * solo cuando las marcas temporales no son comparables (tiempos monotonos
      de CDP) se recurre a exigir el mismo tamano de cuerpo.
    """
    by_url: dict[str, list[Event]] = {}
    order: list[str] = []
    passthrough: list[Event] = []
    for event in egresses:
        url = str(event.data.get("url") or "")
        if not url:
            passthrough.append(event)
            continue
        if url not in by_url:
            order.append(url)
        by_url.setdefault(url, []).append(event)

    merged: list[Event] = list(passthrough)
    for url in order:
        bucket = by_url[url]
        if len(bucket) == 1:
            merged.extend(bucket)
            continue

        # Cada ranura es un envio; admite como mucho una vista por sensor.
        slots: list[dict[str, Event]] = []
        for event in sorted(bucket, key=lambda e: (e.timestamp, e.seq)):
            sensor = event.sensor or "?"
            candidates = [
                (distance, slot) for slot in slots
                if sensor not in slot
                for distance in [_slot_distance(slot, event)]
                if distance is not None
            ]
            if candidates:
                slot = min(candidates, key=lambda c: c[0])[1]
            else:
                slot = {}
                slots.append(slot)
            slot[sensor] = event

        for slot in slots:
            merged.append(_fuse(list(slot.values())))

    merged.sort(key=lambda e: (e.timestamp, e.seq))
    return merged


def _slot_distance(slot: dict[str, Event], event: Event) -> float | None:
    """Distancia de una vista a un envio ya agrupado, o None si no encaja."""
    ts = _usable(event.timestamp)
    size = int(event.data.get("body_size") or 0)
    best: float | None = None
    for other in slot.values():
        other_ts = _usable(other.timestamp)
        if ts is not None and other_ts is not None:
            gap = abs(ts - other_ts)
            if gap > MATCH_TOLERANCE_S:
                return None
            best = gap if best is None else min(best, gap)
        elif size and size == int(other.data.get("body_size") or 0):
            best = MATCH_TOLERANCE_S if best is None else best
        else:
            return None
    return best


def _fuse(views: list[Event]) -> Event:
    """Combina varias vistas de la misma salida en un unico evento.

    Se conserva la vista mas informativa y se le anaden las etiquetas y los
    canarios que aportaron las demas, mas la lista de sensores que la
    sostienen.
    """
    if len(views) == 1:
        return views[0]

    primary = max(views, key=lambda e: (len(_labels_of(e)), len(e.data.get("canary_matches") or [])))
    fused = Event(
        type=primary.type,
        session=primary.session,
        timestamp=min((_usable(v.timestamp) or v.timestamp) for v in views),
        context=primary.context,
        origin=primary.origin,
        source=primary.source or next((v.source for v in views if v.source), ""),
        sensor=primary.sensor,
        tags=list(primary.tags),
        data=dict(primary.data),
        id=primary.id,
        seq=primary.seq,
    )
    for view in views:
        for tag in view.tags:
            if tag not in fused.tags:
                fused.tags.append(tag)

    matches = list(fused.data.get("canary_matches") or [])
    seen = {(m.get("label"), m.get("encoding")) for m in matches if isinstance(m, dict)}
    for view in views:
        for match in view.data.get("canary_matches") or []:
            if not isinstance(match, dict):
                continue
            key = (match.get("label"), match.get("encoding"))
            if key not in seen:
                seen.add(key)
                matches.append(match)
    if matches:
        fused.data["canary_matches"] = matches

    # El host mas especifico gana: CDP suele dar "127.0.0.1" donde el agente
    # da "127.0.0.1:8000".
    hosts = [str(v.data.get("host") or "") for v in views]
    fused.data["host"] = max(hosts, key=len) if any(hosts) else fused.data.get("host", "")
    fused.data["sensors"] = sorted({v.sensor for v in views if v.sensor})
    return fused


def _after(event: Event, reference: float | None) -> bool:
    """True si el evento es posterior a la referencia, cuando son comparables."""
    ts = _usable(event.timestamp)
    if ts is None or reference is None:
        return False
    return ts > reference


def _usable(timestamp: float | None) -> float | None:
    """Descarta marcas monotonas de CDP, que no son comparables con epoch."""
    if timestamp is None:
        return None
    return timestamp if timestamp >= MIN_EPOCH else None


def _labels_of(event: Event) -> set[str]:
    """Etiquetas de procedencia del evento, incluidas las de los canarios."""
    labels = {t for t in event.tags if t != Tag.DERIVED.value}
    for match in event.data.get("canary_matches") or []:
        if isinstance(match, dict) and match.get("label"):
            labels.add(str(match["label"]))
    labels.discard(Tag.UNCLASSIFIED.value)
    return labels


def _is_source_tagged(event: Event) -> bool:
    return bool(_labels_of(event) & PRIVATE_LABELS) and event.type in SOURCE_EVENTS


def _first_key_access(events: Sequence[Event]) -> Event | None:
    for event in events:
        if _usable(event.timestamp) is None:
            continue
        if is_key_access(event):
            return event
    return None


def _latency_ms(anchor: Event | None, egress: Event) -> int | None:
    if anchor is None:
        return None
    start = _usable(anchor.timestamp)
    end = _usable(egress.timestamp)
    if start is None or end is None or end < start:
        # Una salida anterior al acceso a la clave no tiene latencia respecto
        # de el (p. ej. subir un documento antes de firmar).
        return None
    return int((end - start) * 1000)


def _is_direct(egress: Event, labels: set[str], derived: bool) -> bool:
    """Una salida es directa si transporta el material sin oscurecerlo.

    El canario encontrado en el cuerpo es la prueba mas fuerte: los bytes
    estaban ahi, en una codificacion reversible. A falta de canario, se toma
    el etiquetado de la instrumentacion, que marca DERIVED lo que transformo.
    """
    from ..rule_engine.context import DIRECT_ENCODINGS

    for match in egress.data.get("canary_matches") or []:
        if not isinstance(match, dict):
            continue
        if match.get("label") in labels and match.get("encoding") in DIRECT_ENCODINGS:
            return True
    return not derived


def _verdict(labels: set[str]) -> str:
    if labels & PRIVATE_LABELS:
        return VERDICT_EXFILTRATION
    if labels and labels <= PUBLIC_LABELS:
        return VERDICT_LEGITIMATE
    return VERDICT_UNCLASSIFIED


def _corroboration(egress: Event, request: dict[str, Any] | None) -> list[str]:
    """Sensores independientes que sostienen esta salida."""
    sensors: list[str] = []
    # `sensors` lo deja _fuse cuando varias vistas se combinaron en una.
    for sensor in egress.data.get("sensors") or ([egress.sensor] if egress.sensor else []):
        if sensor and sensor not in sensors:
            sensors.append(str(sensor))
    if request and request.get("sensor") and request["sensor"] not in sensors:
        sensors.append(str(request["sensor"]))
    if egress.data.get("canary_matches"):
        sensors.append("canary")
    return sensors


def _match_request(egress: Event, requests: Sequence[dict[str, Any]]) -> dict[str, Any] | None:
    """Empareja la salida con la peticion que vieron CDP o el proxy.

    Se exige coincidencia de URL; el tiempo solo desempata, porque las marcas
    de CDP no siempre son comparables con las del agente.
    """
    url = str(egress.data.get("url") or "")
    if not url:
        return None
    candidates = [r for r in requests if str(r.get("url", "")) == url]
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]

    egress_ts = _usable(egress.timestamp)
    if egress_ts is None:
        return candidates[0]

    def distance(request: dict[str, Any]) -> float:
        ts = _usable(request.get("timestamp"))
        return abs(ts - egress_ts) if ts is not None else float("inf")

    best = min(candidates, key=distance)
    return best if distance(best) <= MATCH_TOLERANCE_S else candidates[0]


def _describe_source(event: Event) -> str:
    if event.type is EventType.PASSWORD_READ:
        return "lectura de la contrasena de la clave"
    name = str(event.data.get("name") or event.data.get("method") or "")
    size = event.data.get("size")
    detail = f" ({size} bytes)" if size else ""
    return f"lectura de {name or 'archivo'}{detail}"


def _describe_transform(event: Event) -> str:
    name = TRANSFORM_NAMES.get(event.type, event.type.value.lower())
    algorithm = str(event.data.get("algorithm") or "")
    return f"{name} ({algorithm})" if algorithm else name


def _describe_egress(event: Event) -> str:
    host = event.data.get("host") or domains.host_of(str(event.data.get("url") or ""))
    size = event.data.get("body_size") or 0
    kinds = {
        EventType.NETWORK_REQUEST: "peticion HTTP",
        EventType.BEACON_SEND: "sendBeacon",
        EventType.WEBSOCKET_SEND: "WebSocket",
        EventType.WEBTRANSPORT_SEND: "WebTransport",
        EventType.RTC_SEND: "canal WebRTC",
        EventType.FORM_SUBMIT: "envio de formulario",
        EventType.NAVIGATION: "navegacion",
        EventType.RESOURCE_URL_SET: "URL de recurso",
        EventType.PROXY_REQUEST: "peticion vista por el proxy",
    }
    kind = kinds.get(event.type, event.type.value)
    destination = f" hacia {host}" if host else ""
    detail = f" ({size} bytes)" if size else ""
    return f"{kind}{destination}{detail}"


def _chain_sort_key(chain: Chain) -> tuple:
    verdict_rank = {VERDICT_EXFILTRATION: 0, VERDICT_UNCLASSIFIED: 1, VERDICT_LEGITIMATE: 2}
    return (
        verdict_rank.get(chain.verdict, 3),
        0 if chain.direct else 1,
        chain.latency_ms if chain.latency_ms is not None else 1 << 30,
    )


def correlate(events: Iterable[Event], requests: Sequence[dict[str, Any]] = (),
              config: AuditConfig | None = None) -> CorrelationReport:
    """Atajo funcional para usos puntuales y para las pruebas."""
    return CorrelationEngine(config).run(list(events), requests)
