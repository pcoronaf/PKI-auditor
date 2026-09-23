"""Motor de reglas.

Carga el catalogo YAML, ejecuta el evaluador registrado de cada regla sobre el
:class:`~firmascope.rule_engine.context.AuditContext` y produce
:class:`~firmascope.evidence_store.store.Finding`.

Principio de diseno: **toda regla habilitada emite un hallazgo**, incluso
cuando no observa nada. Un reporte que dice explicitamente

    Clave privada transmitida directamente: NOT OBSERVED

es mas util, y mas honesto, que un reporte que calla. El estado
``INCONCLUSIVE`` se reserva para cuando la sesion ni siquiera ejercito la
condicion (por ejemplo, evaluar el egress de la clave sin haber llegado a
cargar una clave).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

from ..audit_core.conclusions import SEVERITY_ORDER, Confidence, Severity
from ..evidence_store.store import Finding
from . import builtin  # noqa: F401  (registra los evaluadores integrados)
from .context import AuditContext
from .registry import RuleResult, evaluator_for

#: Catalogo empaquetado con FirmaScope.
BUILTIN_RULES_DIR = Path(__file__).parent / "rules"


@dataclass
class RuleMeta:
    """Metadatos declarativos de una regla."""

    id: str
    title: str
    category: str = "general"
    severity: Severity = Severity.MEDIUM
    summary: str = ""
    description: str = ""
    rationale: str = ""
    references: list[str] = field(default_factory=list)
    enabled: bool = True
    source_file: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any], source_file: str = "") -> "RuleMeta":
        try:
            severity = Severity(str(raw.get("severity", "MEDIUM")).upper())
        except ValueError:
            severity = Severity.MEDIUM
        return cls(
            id=str(raw["id"]).strip(),
            title=str(raw.get("title", raw["id"])),
            category=str(raw.get("category", "general")),
            severity=severity,
            summary=str(raw.get("summary", "")),
            description=str(raw.get("description", "")).strip(),
            rationale=str(raw.get("rationale", "")).strip(),
            references=[str(r) for r in (raw.get("references") or [])],
            enabled=bool(raw.get("enabled", True)),
            source_file=source_file,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity.value,
            "summary": self.summary,
            "description": self.description,
            "rationale": self.rationale,
            "references": list(self.references),
            "enabled": self.enabled,
        }


def load_rule_files(directory: Path) -> list[RuleMeta]:
    """Carga todas las reglas de un directorio (recursivo)."""
    metas: list[RuleMeta] = []
    if not directory.is_dir():
        return metas
    for path in sorted(directory.rglob("*.yaml")) + sorted(directory.rglob("*.yml")):
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        entries = document if isinstance(document, list) else [document]
        for entry in entries:
            if not isinstance(entry, dict) or "id" not in entry:
                continue
            try:
                metas.append(RuleMeta.from_dict(entry, str(path)))
            except Exception:
                continue
    return metas


class RuleEngine:
    """Evalua el catalogo completo sobre una sesion."""

    def __init__(self, extra_dirs: Iterable[Path] = ()):
        self.rules: list[RuleMeta] = []
        self._load(BUILTIN_RULES_DIR)
        for directory in extra_dirs:
            self._load(Path(directory))

    def _load(self, directory: Path) -> None:
        by_id = {meta.id: meta for meta in self.rules}
        for meta in load_rule_files(directory):
            # Un paquete externo puede redefinir una regla integrada.
            by_id[meta.id] = meta
        self.rules = sorted(by_id.values(), key=lambda m: m.id)

    # ------------------------------------------------------------------
    def evaluate(self, context: AuditContext) -> list[Finding]:
        findings: list[Finding] = []
        for meta in self.rules:
            if not meta.enabled:
                continue
            findings.append(self._evaluate_one(meta, context))
        findings.sort(key=_finding_sort_key)
        return findings

    def _evaluate_one(self, meta: RuleMeta, context: AuditContext) -> Finding:
        evaluator = evaluator_for(meta.id)
        if evaluator is None:
            result = RuleResult.inconclusive(
                "Regla declarada sin evaluador registrado.",
                "El catalogo define esta regla pero FirmaScope no tiene logica para "
                "evaluarla en esta version. No se puede concluir nada sobre la sesion.",
            )
        else:
            try:
                result = evaluator(context, meta) or RuleResult.inconclusive(
                    "El evaluador no produjo veredicto.")
            except Exception as exc:  # una regla rota no debe tumbar la auditoria
                result = RuleResult.inconclusive(
                    "La evaluacion de la regla fallo.",
                    f"Error interno al evaluar {meta.id}: {type(exc).__name__}: {exc}",
                )
        return Finding(
            rule_id=meta.id,
            title=meta.title,
            status=result.status,
            severity=result.severity or meta.severity,
            confidence=result.confidence or Confidence.MEDIUM,
            summary=result.summary or meta.summary,
            detail=_compose_detail(meta, result),
            evidence=result.evidence,
        )

    # ------------------------------------------------------------------
    def catalog(self) -> list[dict[str, Any]]:
        """Catalogo publicable, para documentacion y para el reporte."""
        return [meta.to_dict() for meta in self.rules]

    def rule_ids(self) -> list[str]:
        return [meta.id for meta in self.rules]


def _compose_detail(meta: RuleMeta, result: RuleResult) -> str:
    parts: list[str] = []
    if result.detail:
        parts.append(result.detail)
    if meta.description:
        parts.append(meta.description)
    if meta.rationale:
        parts.append("Por que importa: " + meta.rationale)
    return "\n\n".join(parts)


def _finding_sort_key(finding: Finding) -> tuple:
    severity_rank = {
        Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
        Severity.LOW: 3, Severity.INFO: 4,
    }
    return (
        -SEVERITY_ORDER.get(finding.status, 0),
        severity_rank.get(finding.severity, 5),
        finding.rule_id,
    )
