"""Motor de reglas y catalogo FS-*."""

from .context import AuditContext
from .engine import BUILTIN_RULES_DIR, RuleEngine, RuleMeta, load_rule_files
from .registry import REGISTRY, RuleResult, rule

__all__ = [
    "BUILTIN_RULES_DIR",
    "REGISTRY",
    "AuditContext",
    "RuleEngine",
    "RuleMeta",
    "RuleResult",
    "load_rule_files",
    "rule",
]
