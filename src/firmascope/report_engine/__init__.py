"""Generacion de reportes JSON y HTML autocontenidos."""

from .exporter import build_report, render_html, text_summary, write_package

__all__ = ["build_report", "render_html", "text_summary", "write_package"]
