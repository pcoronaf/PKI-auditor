"""Analizador estatico de JavaScript (Nivel 2).

Toma el inventario de scripts recogido por el controlador de navegador y
responde: *que podria hacer este codigo aunque no haya ocurrido durante esta
ejecucion*.

Produce un :class:`StaticReport` con rutas source -> transform -> sink, senales
por script (criptografia, almacenamiento, comunicaciones) y el inventario con
hashes, que el motor de reglas convierte en hallazgos ``POTENTIAL``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from ..audit_core.conclusions import Confidence
from . import catalog, parser
from .taint import ScriptAnalysis, SourceRef, StaticPath

#: Tamano maximo de script analizado. Los bundles enormes se truncan para que
#: una auditoria no se bloquee en un fichero de varios megabytes.
MAX_SCRIPT_BYTES = 3 * 1024 * 1024


@dataclass
class ScriptSignals:
    """Indicios de alto nivel presentes en un script."""

    webcrypto: bool = False
    storage: bool = False
    network: bool = False
    workers: bool = False
    dynamic_eval: bool = False
    file_access: bool = False
    password_access: bool = False

    def to_dict(self) -> dict[str, bool]:
        return {
            "webcrypto": self.webcrypto,
            "storage": self.storage,
            "network": self.network,
            "workers": self.workers,
            "dynamic_eval": self.dynamic_eval,
            "file_access": self.file_access,
            "password_access": self.password_access,
        }

    def any_signal(self) -> bool:
        return any(self.to_dict().values())


SIGNAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("webcrypto", re.compile(r"crypto\s*\.\s*subtle|SubtleCrypto|importKey|deriveKey", re.I)),
    ("storage", re.compile(r"localStorage|sessionStorage|indexedDB|IDBObjectStore|caches\s*\.", re.I)),
    ("network", re.compile(r"\bfetch\s*\(|XMLHttpRequest|sendBeacon|new\s+WebSocket|WebTransport", re.I)),
    ("workers", re.compile(r"new\s+Worker|new\s+SharedWorker|serviceWorker\s*\.\s*register", re.I)),
    ("dynamic_eval", re.compile(r"\beval\s*\(|new\s+Function\s*\(", re.I)),
    ("file_access", re.compile(r"FileReader|\.files\s*\[|readAsArrayBuffer|\.arrayBuffer\s*\(", re.I)),
    ("password_access", re.compile(r"type\s*=\s*.?password|getElementById\(.{0,2}[^)]*pass", re.I)),
)


@dataclass
class StaticReport:
    """Resultado agregado del analisis estatico."""

    paths: list[StaticPath] = field(default_factory=list)
    signals: dict[str, ScriptSignals] = field(default_factory=dict)
    scripts: list[dict[str, Any]] = field(default_factory=list)
    parsed: int = 0
    failed: int = 0
    skipped: int = 0
    ast_available: bool = True

    # -- consultas usadas por el motor de reglas ------------------------
    def private_paths(self) -> list[StaticPath]:
        """Rutas que llevan material privado hasta un sumidero."""
        return [p for p in self.paths if p.private]

    def paths_to_channel(self, channel: str) -> list[StaticPath]:
        return [p for p in self.paths if p.channel == channel]

    def paths_with_label(self, label: str) -> list[StaticPath]:
        return [p for p in self.paths if label in p.labels]

    def best_confidence(self, paths: Iterable[StaticPath]) -> Confidence:
        order = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}
        best = Confidence.LOW
        for path in paths:
            if order[path.confidence] > order[best]:
                best = path.confidence
        return best

    def scripts_with(self, signal: str) -> list[dict[str, Any]]:
        out = []
        for script in self.scripts:
            info = self.signals.get(script.get("sha256", ""))
            if info is not None and getattr(info, signal, False):
                out.append(script)
        return out

    def third_party_scripts(self) -> list[dict[str, Any]]:
        return [s for s in self.scripts if s.get("third_party")]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ast_available": self.ast_available,
            "scripts_parsed": self.parsed,
            "scripts_failed": self.failed,
            "scripts_skipped": self.skipped,
            "paths": [p.to_dict() for p in self.paths],
            "signals": {sha: info.to_dict() for sha, info in self.signals.items()},
        }


# ----------------------------------------------------------------------
def detect_signals(source: str) -> ScriptSignals:
    signals = ScriptSignals()
    for name, pattern in SIGNAL_PATTERNS:
        if pattern.search(source):
            setattr(signals, name, True)
    return signals


def analyze_source(source: bytes, file_label: str, url: str = "") -> list[StaticPath]:
    """Analiza un unico script. Util para pruebas unitarias."""
    if parser.available():
        try:
            return ScriptAnalysis(source, file_label, url).run()
        except Exception:
            pass
    return _fallback_scan(source, file_label, url)


def analyze_scripts(scripts: list[dict[str, Any]],
                    read_body: Callable[[dict[str, Any]], bytes | None]) -> StaticReport:
    """Analiza todo el inventario de scripts de una sesion."""
    report = StaticReport(ast_available=parser.available())
    for script in scripts:
        report.scripts.append(script)
        body = None
        try:
            body = read_body(script)
        except Exception:
            body = None
        if not body:
            report.skipped += 1
            continue
        if len(body) > MAX_SCRIPT_BYTES:
            body = body[:MAX_SCRIPT_BYTES]
        label = _label_for(script)
        text = body.decode("utf-8", "replace")
        report.signals[script.get("sha256", label)] = detect_signals(text)
        try:
            paths = analyze_source(body, label, script.get("url", ""))
            report.parsed += 1
        except Exception:
            report.failed += 1
            continue
        report.paths.extend(paths)
    report.paths.sort(key=_path_sort_key)
    return report


def _label_for(script: dict[str, Any]) -> str:
    url = script.get("url", "") or ""
    if url.startswith("inline:"):
        return f"inline:{script.get('sha256', '')[:8]}"
    tail = url.split("?")[0].rstrip("/").split("/")[-1]
    return tail or url or script.get("sha256", "")[:12]


def _path_sort_key(path: StaticPath) -> tuple:
    rank = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}
    return (0 if path.private else 1, rank[path.confidence], path.file_label, path.sink_line)


# ----------------------------------------------------------------------
# Modo degradado: sin AST
# ----------------------------------------------------------------------

_SOURCE_HINT = re.compile(
    r"(readAsArrayBuffer|readAsText|\.files\s*\[|FileReader|importKey|subtle\s*\.\s*decrypt"
    r"|type\s*=\s*.?password)", re.I)
_SINK_HINT = re.compile(
    r"(fetch\s*\(|\.send\s*\(|sendBeacon\s*\(|setItem\s*\(|\.put\s*\(|\.src\s*=|location\s*\.\s*href\s*=)",
    re.I)


def _fallback_scan(source: bytes, file_label: str, url: str) -> list[StaticPath]:
    """Barrido por patrones cuando el AST no esta disponible.

    Solo puede establecer co-ocurrencia dentro del mismo fichero, asi que la
    confianza es siempre baja y el hallazgo resultante debe leerse como
    "merece revision manual", no como una ruta demostrada.
    """
    text = source.decode("utf-8", "replace")
    source_match = _SOURCE_HINT.search(text)
    sink_match = _SINK_HINT.search(text)
    if not source_match or not sink_match:
        return []
    labels = catalog.infer_labels(text[: 20000])
    if not labels:
        return []
    line = text.count("\n", 0, source_match.start()) + 1
    sink_line = text.count("\n", 0, sink_match.start()) + 1
    return [StaticPath(
        source=SourceRef(f"patron: {source_match.group(1)}", "name", line,
                         text[source_match.start():source_match.start() + 120].replace("\n", " ")),
        sink_name=f"patron: {sink_match.group(1).strip()}",
        sink_snippet=text[sink_match.start():sink_match.start() + 120].replace("\n", " "),
        sink_line=sink_line,
        channel="unknown",
        labels=sorted(labels),
        transforms=[],
        confidence=Confidence.LOW,
        call_chain=[],
        file_label=file_label,
        url=url,
        hops=0,
        derived=False,
    )]
