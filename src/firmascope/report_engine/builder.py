"""Construccion del reporte estructurado.

El reporte tiene una sola responsabilidad y es delicada: presentar lo que la
sesion sostiene, ni mas ni menos. Tres decisiones de diseno lo gobiernan:

* **No hay puntuacion global.** FirmaScope no emite un "85/100" ni un semaforo
  de sitio seguro. Un numero invita a compararlo con otro numero, y ninguna de
  las preguntas que la herramienta responde admite esa aritmetica.
* **Cada hallazgo lleva su estado y lo que el estado significa.** El lector no
  tiene que recordar la diferencia entre ``NOT_OBSERVED`` y ``INCONCLUSIVE``:
  el reporte la lleva escrita al lado.
* **El titular se construye con los hechos mas fuertes disponibles**, y si no
  hay ninguno lo dice en lugar de rellenar.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Sequence

from .. import __version__
from ..audit_core.conclusions import SEVERITY_ORDER, STATUS_MEANING, Severity, Status
from ..audit_core.config import AuditConfig, environment_info

#: Orden de presentacion de las severidades.
SEVERITY_RANK = {
    Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
    Severity.LOW: 3, Severity.INFO: 4,
}

#: Aviso que acompana a todo el reporte. Es el principio final de la
#: especificacion, y no es decorativo: es la frase que separa esta herramienta
#: de un escaner que reparte aprobados.
GLOBAL_CAVEAT = (
    "Este reporte describe lo ocurrido durante una ejecucion concreta, con una "
    "configuracion y un recorrido concretos. Que algo no se observara no demuestra "
    "que no pueda ocurrir: demuestra que no ocurrio aqui."
)


@dataclass
class ReportInput:
    """Todo lo que el reporte necesita de una sesion."""

    config: AuditConfig
    session: dict[str, Any] = field(default_factory=dict)
    findings: Sequence[dict[str, Any]] = ()
    correlation: Any | None = None
    static: Any | None = None
    requests: Sequence[dict[str, Any]] = ()
    scripts: Sequence[dict[str, Any]] = ()
    checkpoints: Sequence[dict[str, Any]] = ()
    events: Sequence[dict[str, Any]] = ()
    catalog: Sequence[dict[str, Any]] = ()
    chain_head: str = ""
    chain_ok: bool | None = None
    agent_sha256: str = ""


def build_report(data: ReportInput) -> dict[str, Any]:
    """Reporte estructurado, serializable a ``report.json``."""
    findings = _sorted_findings(data.findings)
    correlation = data.correlation.to_dict() if data.correlation is not None else None

    return {
        "firmascope": {
            "version": __version__,
            "generated_at": round(time.time(), 3),
        },
        "caveat": GLOBAL_CAVEAT,
        "target": data.config.target,
        "level": {
            "value": int(data.config.level),
            "name": data.config.level.name,
            "capabilities": data.config.to_dict()["capabilities"],
        },
        "headline": _headline(findings, data),
        "summary": _summary(findings, data),
        "findings": findings,
        "status_meanings": {status.value: text for status, text in STATUS_MEANING.items()},
        "correlation": correlation,
        "static": data.static.to_dict() if data.static is not None else None,
        "network": _network_section(data.requests),
        "scripts": _scripts_section(data.scripts),
        "checkpoints": list(data.checkpoints),
        "timeline": list(data.events),
        "catalog": list(data.catalog),
        "manifest": _manifest(data),
    }


# ----------------------------------------------------------------------
# Secciones
# ----------------------------------------------------------------------

def _sorted_findings(findings: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    def key(finding: dict[str, Any]) -> tuple:
        status = _status_of(finding)
        severity = _severity_of(finding)
        return (
            -SEVERITY_ORDER.get(status, 0),
            SEVERITY_RANK.get(severity, 5),
            str(finding.get("rule_id", "")),
        )

    out = []
    for finding in sorted(findings, key=key):
        item = dict(finding)
        item["status_meaning"] = STATUS_MEANING.get(_status_of(finding), "")
        out.append(item)
    return out


def _summary(findings: Sequence[dict[str, Any]], data: ReportInput) -> dict[str, Any]:
    counts: dict[str, int] = {status.value: 0 for status in Status}
    for finding in findings:
        counts[_status_of(finding).value] = counts.get(_status_of(finding).value, 0) + 1

    correlation = data.correlation
    return {
        "by_status": counts,
        "rules_evaluated": len(findings),
        "actionable": sum(
            1 for f in findings
            if _status_of(f) in (Status.CONFIRMED, Status.OBSERVED, Status.POTENTIAL)
        ),
        "exfiltration_chains": (
            len(correlation.exfiltration_chains()) if correlation is not None else None),
        "third_party_domains": len({
            r.get("registrable_domain") for r in data.requests if r.get("third_party")
        }),
        "scripts_analyzed": data.static.parsed if data.static is not None else 0,
    }


def _headline(findings: Sequence[dict[str, Any]], data: ReportInput) -> dict[str, Any]:
    """La conclusion que el lector se lleva si no lee nada mas.

    Se construye con el hallazgo mas fuerte disponible. Si no hay ninguno por
    encima de ``NOT_OBSERVED``, el titular lo dice — y dice tambien que eso no
    es un aprobado.
    """
    strongest = next(
        (f for f in findings
         if _status_of(f) in (Status.CONFIRMED, Status.OBSERVED, Status.POTENTIAL)),
        None,
    )
    if strongest is None:
        evaluadas = len(findings)
        return {
            "status": Status.NOT_OBSERVED.value,
            "title": "No se observo transmision de material privado en esta ejecucion.",
            "detail": (
                f"Las {evaluadas} reglas del catalogo se evaluaron sin encontrar transmision, "
                "persistencia ni rutas de codigo hacia canales de salida. "
                + GLOBAL_CAVEAT
            ),
            "rule_id": "",
        }
    return {
        "status": _status_of(strongest).value,
        "title": str(strongest.get("summary", "")),
        "detail": STATUS_MEANING.get(_status_of(strongest), ""),
        "rule_id": str(strongest.get("rule_id", "")),
    }


def _network_section(requests: Sequence[dict[str, Any]]) -> dict[str, Any]:
    by_domain: dict[str, dict[str, Any]] = {}
    for request in requests:
        domain = str(request.get("registrable_domain") or request.get("host") or "?")
        entry = by_domain.setdefault(domain, {
            "domain": domain,
            "third_party": bool(request.get("third_party")),
            "requests": 0,
            "bytes_sent": 0,
        })
        entry["requests"] += 1
        entry["bytes_sent"] += int(request.get("body_size") or 0)

    domains = sorted(by_domain.values(), key=lambda d: (not d["third_party"], -d["requests"]))
    return {
        "total": len(requests),
        "third_party": sum(1 for r in requests if r.get("third_party")),
        "domains": domains,
    }


def _scripts_section(scripts: Sequence[dict[str, Any]]) -> dict[str, Any]:
    return {
        "total": len(scripts),
        "third_party": sum(1 for s in scripts if s.get("third_party")),
        "inventory": [
            {
                "url": s.get("url", ""),
                "sha256": s.get("sha256", ""),
                "size": s.get("size", 0),
                "third_party": bool(s.get("third_party")),
                "inline": bool(s.get("inline")),
            }
            for s in scripts
        ],
    }


def _manifest(data: ReportInput) -> dict[str, Any]:
    """Todo lo necesario para reproducir la sesion (NFR-002)."""
    session = data.session or {}
    return {
        "session_id": session.get("id", ""),
        "target": data.config.target,
        "started_at": session.get("started_at"),
        "ended_at": session.get("ended_at"),
        "note": session.get("note", "") or data.config.note,
        "firmascope_version": __version__,
        "environment": environment_info(),
        "config": data.config.to_dict(),
        "agent_sha256": data.agent_sha256,
        "script_hashes": {s.get("sha256", ""): s.get("url", "") for s in data.scripts},
        "chain_head": data.chain_head,
        "chain_verified": data.chain_ok,
    }


# ----------------------------------------------------------------------
# Normalizacion
# ----------------------------------------------------------------------

def _status_of(finding: dict[str, Any]) -> Status:
    raw = finding.get("status")
    if isinstance(raw, Status):
        return raw
    try:
        return Status(str(raw))
    except ValueError:
        return Status.INCONCLUSIVE


def _severity_of(finding: dict[str, Any]) -> Severity:
    raw = finding.get("severity")
    if isinstance(raw, Severity):
        return raw
    try:
        return Severity(str(raw))
    except ValueError:
        return Severity.MEDIUM
