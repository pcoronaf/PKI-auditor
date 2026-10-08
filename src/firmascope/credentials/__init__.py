"""Credenciales de laboratorio (canarios) y carga de la e.firma del operador."""

from .generator import (
    SYNTHETIC_CN,
    SYNTHETIC_MARKER,
    AuditCredential,
    SyntheticCredential,
    generate,
    generate_password,
    load,
    load_real,
)

__all__ = [
    "SYNTHETIC_CN",
    "SYNTHETIC_MARKER",
    "AuditCredential",
    "SyntheticCredential",
    "generate",
    "generate_password",
    "load",
    "load_real",
]
