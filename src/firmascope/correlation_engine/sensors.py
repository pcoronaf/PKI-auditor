"""Correlacion de observaciones de una misma salida de red.

Una sola peticion HTTP la ven hasta cuatro sensores distintos:

* el **agente** en la pagina, que la intercepta en ``fetch``/XHR antes de que
  salga y conoce la procedencia del dato (las etiquetas S1-S6);
* el **CDP**, que la ve como peticion del navegador y conoce el cuerpo tal como
  se envio;
* el **aislamiento**, que la aborta cuando la red esta cortada y es el unico que
  sabe que **no salio**;
* el **proxy**, cuando esta activo.

Cada sensor aporta algo que los otros no tienen, y ninguno ve el cuadro
completo. Contarlos por separado produce dos errores graves en direcciones
opuestas: multiplica una exfiltracion por el numero de sensores que la vieron,
y -- mucho peor -- permite que un intento **bloqueado** se reporte como
material enviado, porque el sensor que lo nego no es el mismo que lo vio.

Este modulo agrupa las observaciones de una misma peticion y deja una sola
conclusion por peticion. La regla de decision no es estadistica:

    si cualquier sensor con autoridad para negarla la nego, no salio.

El aislamiento tiene esa autoridad porque aborta la peticion en el navegador:
si abortó, los bytes no llegaron a la red. Los demas sensores observan la
*intencion* de enviar, que es anterior al resultado.

El expediente no se modifica: las observaciones crudas siguen encadenadas tal
como se registraron, y esta correlacion es una capa de interpretacion sobre
ellas. Si el operador discute la conclusion, puede recomputarla.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlsplit

from ..audit_core.events import EGRESS_EVENTS, Event, EventType

#: Sensores cuya negativa es concluyente: abortaron la peticion ellos mismos.
DENYING_SENSORS = frozenset({"isolation"})

#: Sensores que ven el cuerpo tal como salio y buscan en el los canarios. Si
#: uno de ellos vio el cuerpo y el canario no estaba, la etiqueta del agente
#: queda contradicha: el agente marca por el *tipo* de campo, ellos por los bytes.
CONTENT_SENSORS = frozenset({"proxy", "cdp"})

#: Ventana en la que dos observaciones pueden ser la misma peticion.
DEFAULT_WINDOW_S = 15.0

#: Preferencia de sensor al elegir el representante de un grupo. El agente va
#: primero porque es el unico que conoce la procedencia del dato.
SENSOR_RANK = {"agent": 0, "proxy": 1, "cdp": 2, "isolation": 3}


def _netloc(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    return parts.netloc.lower()


def _path(url: str) -> str:
    try:
        return urlsplit(url).path or "/"
    except ValueError:
        return ""


@dataclass
class EgressGroup:
    """Las observaciones de una misma salida, con una sola conclusion."""

    key: str
    url: str
    netloc: str
    method: str
    body_size: int
    observations: list[Event] = field(default_factory=list)

    @property
    def sensors(self) -> tuple[str, ...]:
        return tuple(sorted({e.sensor for e in self.observations if e.sensor}))

    @property
    def blocked(self) -> bool:
        """``True`` si algun sensor con autoridad nego la salida."""
        for event in self.observations:
            if event.data.get("blocked") and event.sensor in DENYING_SENSORS:
                return True
        return False

    @property
    def denied_by(self) -> tuple[str, ...]:
        return tuple(sorted({e.sensor for e in self.observations
                             if e.data.get("blocked") and e.sensor in DENYING_SENSORS}))

    @property
    def tags(self) -> set[str]:
        """Union de las etiquetas: cada sensor etiqueta lo que puede ver."""
        out: set[str] = set()
        for event in self.observations:
            out.update(event.tags)
        return out

    @property
    def canary_matches(self) -> list[dict[str, Any]]:
        """Union de las coincidencias de canario, sin repetir codificacion."""
        seen: set[tuple[str, str]] = set()
        out: list[dict[str, Any]] = []
        for event in self.observations:
            matches = event.data.get("canary_matches")
            if not isinstance(matches, list):
                continue
            for match in matches:
                mark = (str(match.get("label", "")), str(match.get("encoding", "")))
                if mark in seen:
                    continue
                seen.add(mark)
                out.append(match)
        return out

    def content_lacks(self, label: str) -> bool:
        """``True`` si un sensor de contenido vio el cuerpo y ``label`` no estaba.

        Solo cuenta un cuerpo visto de verdad (tamano mayor que cero): CDP no
        entrega los cuerpos multipart, y un cuerpo que nadie vio no contradice
        nada. Lo decide quien vio los bytes, igual que la negativa del
        aislamiento la decide quien aborto la peticion.
        """
        seen_body = any(e.sensor in CONTENT_SENSORS and int(e.data.get("body_size") or 0) > 0
                        for e in self.observations)
        if not seen_body:
            return False
        return not any(str(m.get("label", "")) == label for m in self.canary_matches)

    @property
    def primary(self) -> Event:
        """Observacion que representa al grupo ante las reglas.

        Se elige la del sensor mas informativo, no la primera en el tiempo: lo
        que las reglas necesitan es la procedencia del dato.
        """
        return min(self.observations,
                   key=lambda e: (SENSOR_RANK.get(e.sensor, 9), e.timestamp))

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "url": self.url,
            "host": self.netloc,
            "method": self.method,
            "body_size": self.body_size,
            "sensors": list(self.sensors),
            "observations": len(self.observations),
            "blocked": self.blocked,
            "denied_by": list(self.denied_by),
            "tags": sorted(self.tags),
            "event_ids": [e.id for e in self.observations],
        }


class CorrelationIndex:
    """Resultado de correlacionar las salidas de una sesion."""

    def __init__(self, groups: list[EgressGroup]):
        self.groups = groups
        self._by_event: dict[str, EgressGroup] = {}
        for group in groups:
            for event in group.observations:
                self._by_event[event.id] = group

    # ------------------------------------------------------------------
    def group_of(self, event: Event) -> EgressGroup | None:
        return self._by_event.get(event.id)

    def is_blocked(self, event: Event) -> bool:
        """``True`` si la peticion que este evento observa no llego a salir."""
        group = self._by_event.get(event.id)
        if group is not None:
            return group.blocked
        return bool(event.data.get("blocked"))

    def is_primary(self, event: Event) -> bool:
        """``True`` si este evento representa a su grupo.

        Permite que las reglas recorran las salidas sin contar la misma
        peticion una vez por sensor.
        """
        group = self._by_event.get(event.id)
        return group is None or group.primary.id == event.id

    def enriched_tags(self, event: Event) -> set[str]:
        group = self._by_event.get(event.id)
        return set(group.tags) if group is not None else set(event.tags)

    def enriched_matches(self, event: Event) -> list[dict[str, Any]]:
        group = self._by_event.get(event.id)
        if group is None:
            matches = event.data.get("canary_matches")
            return list(matches) if isinstance(matches, list) else []
        return group.canary_matches

    # ------------------------------------------------------------------
    @property
    def sent(self) -> list[EgressGroup]:
        return [g for g in self.groups if not g.blocked]

    @property
    def denied(self) -> list[EgressGroup]:
        return [g for g in self.groups if g.blocked]

    def summary(self) -> dict[str, Any]:
        multi = [g for g in self.groups if len(g.observations) > 1]
        return {
            "requests": len(self.groups),
            "observations": sum(len(g.observations) for g in self.groups),
            "corroborated": len(multi),
            "sent": len(self.sent),
            "blocked": len(self.denied),
            "groups": [g.to_dict() for g in self.groups],
        }


def _keys_for(event: Event) -> list[str]:
    """Claves por las que una observacion puede unirse a un grupo, de fuerte a debil."""
    data = event.data
    url = str(data.get("url") or "")
    digest = str(data.get("body_digest") or "")
    size = int(data.get("body_size") or 0)
    netloc = _netloc(url) or str(data.get("host") or "").lower()
    # El host del agente incluye el puerto y el de CDP no siempre: la clave se
    # construye desde la URL, que ambos reportan completa.
    keys: list[str] = []
    if digest:
        keys.append(f"digest:{digest}")
    if url:
        keys.append(f"url:{netloc}{_path(url)}:{size}")
    if netloc:
        keys.append(f"host:{netloc}:{data.get('method', '')}:{size}")
    return keys


def correlate(events: Iterable[Event],
              window_s: float = DEFAULT_WINDOW_S) -> CorrelationIndex:
    """Agrupa las observaciones de salida que corresponden a la misma peticion.

    Solo se agrupan observaciones de sensores *distintos*: dos peticiones reales
    e identicas desde el mismo sensor son dos salidas, no una vista dos veces.
    """
    egress = [e for e in events
              if e.type in EGRESS_EVENTS or e.type is EventType.NETWORK_REQUEST]
    egress.sort(key=lambda e: e.timestamp)

    groups: list[EgressGroup] = []
    index: dict[str, list[EgressGroup]] = {}

    for event in egress:
        keys = _keys_for(event)
        target: EgressGroup | None = None
        for key in keys:
            for candidate in index.get(key, []):
                if event.sensor and event.sensor in {o.sensor for o in candidate.observations}:
                    continue
                newest = max(o.timestamp for o in candidate.observations)
                if abs(event.timestamp - newest) > window_s:
                    continue
                target = candidate
                break
            if target is not None:
                break

        if target is None:
            url = str(event.data.get("url") or "")
            target = EgressGroup(
                key=keys[0] if keys else f"event:{event.id}",
                url=url,
                netloc=_netloc(url) or str(event.data.get("host") or "").lower(),
                method=str(event.data.get("method") or ""),
                body_size=int(event.data.get("body_size") or 0),
            )
            groups.append(target)

        target.observations.append(event)
        if not target.url and event.data.get("url"):
            target.url = str(event.data["url"])
            target.netloc = _netloc(target.url) or target.netloc
        if not target.body_size:
            target.body_size = int(event.data.get("body_size") or 0)
        for key in keys:
            index.setdefault(key, []).append(target)

    return CorrelationIndex(groups)
