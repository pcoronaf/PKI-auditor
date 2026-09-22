"""Analisis estatico de JavaScript: inventario, AST, sources/sinks, taint."""

from .analyzer import (
    MAX_SCRIPT_BYTES,
    ScriptSignals,
    StaticReport,
    analyze_scripts,
    analyze_source,
    detect_signals,
)
from .taint import SourceRef, StaticPath

__all__ = [
    "MAX_SCRIPT_BYTES",
    "ScriptSignals",
    "SourceRef",
    "StaticPath",
    "StaticReport",
    "analyze_scripts",
    "analyze_source",
    "detect_signals",
]
