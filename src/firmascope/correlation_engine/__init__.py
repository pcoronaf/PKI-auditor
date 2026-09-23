"""Motor de correlacion: reconstruccion de cadenas de procedencia."""

from .engine import (
    VERDICT_EXFILTRATION,
    VERDICT_LEGITIMATE,
    VERDICT_UNCLASSIFIED,
    Chain,
    CorrelationEngine,
    CorrelationReport,
    Step,
    correlate,
)

__all__ = [
    "VERDICT_EXFILTRATION",
    "VERDICT_LEGITIMATE",
    "VERDICT_UNCLASSIFIED",
    "Chain",
    "CorrelationEngine",
    "CorrelationReport",
    "Step",
    "correlate",
]
