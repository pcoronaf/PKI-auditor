"""Generacion de reportes: JSON estructurado y HTML autocontenido."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..audit_core.secrets import SecretVault, assert_no_secrets
from .builder import GLOBAL_CAVEAT, ReportInput, build_report
from .html import render_html

__all__ = [
    "GLOBAL_CAVEAT",
    "ReportInput",
    "build_report",
    "render_html",
    "write_reports",
]


def write_reports(data: ReportInput, output_dir: Path,
                  vault: SecretVault | None = None) -> dict[str, Path]:
    """Escribe ``report.json`` y ``report.html`` y devuelve sus rutas.

    Antes de tocar el disco, el reporte serializado pasa por
    :func:`~firmascope.audit_core.secrets.assert_no_secrets`. Es la ultima
    barrera: si un secreto llego hasta aqui, la escritura falla en lugar de
    producir un fichero que no deberia existir.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    report = build_report(data)
    serialized = json.dumps(report, indent=2, ensure_ascii=False, default=str)
    assert_no_secrets(serialized, vault)

    markup = render_html(report)
    assert_no_secrets(markup, vault)

    json_path = output_dir / "report.json"
    html_path = output_dir / "report.html"
    json_path.write_text(serialized, encoding="utf-8")
    html_path.write_text(markup, encoding="utf-8")
    return {"json": json_path, "html": html_path}
