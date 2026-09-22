"""Registro de evaluadores de reglas.

Los metadatos de cada regla viven en YAML (``rules/<categoria>/FS-*.yaml``) y
su logica de evaluacion se registra aqui por identificador. Separar ambas
cosas permite que un operador anada reglas propias sin tocar el codigo, y que
el catalogo publicado sea legible sin leer Python (NFR-004).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from ..audit_core.conclusions import Confidence, Severity, Status


@dataclass
class RuleResult:
    """Veredicto de una regla sobre una sesion."""

    status: Status
    summary: str
    detail: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)
    confidence: Confidence | None = None
    severity: Severity | None = None

    @classmethod
    def inconclusive(cls, summary: str, detail: str = "") -> "RuleResult":
        return cls(status=Status.INCONCLUSIVE, summary=summary, detail=detail,
                   confidence=Confidence.LOW)

    @classmethod
    def not_observed(cls, summary: str, detail: str = "") -> "RuleResult":
        return cls(status=Status.NOT_OBSERVED, summary=summary, detail=detail,
                   confidence=Confidence.MEDIUM)


#: ``{rule_id: evaluador}``. El evaluador recibe ``(context, meta)``.
REGISTRY: dict[str, Callable[..., RuleResult | None]] = {}


def rule(rule_id: str) -> Callable:
    """Decorador que asocia una funcion evaluadora a un identificador."""

    def decorator(func: Callable[..., RuleResult | None]) -> Callable[..., RuleResult | None]:
        REGISTRY[rule_id] = func
        return func

    return decorator


def evaluator_for(rule_id: str) -> Callable[..., RuleResult | None] | None:
    return REGISTRY.get(rule_id)
