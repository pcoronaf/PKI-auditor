"""Reporte HTML autocontenido.

Sin CSS remoto, sin fuentes externas, sin JavaScript de terceros: un reporte de
auditoria que pide recursos a la red seria una contradiccion, y ademas filtraria
a un tercero que alguien esta auditando un sitio y cuando.

Todo el contenido dinamico pasa por :func:`esc`. El reporte incluye texto
tomado del sitio auditado (URLs, fragmentos de codigo), que es precisamente el
material del que hay que desconfiar.
"""

from __future__ import annotations

import html
import json
from typing import Any, Iterable

from ..audit_core.conclusions import Status

STATUS_CLASS = {
    Status.CONFIRMED.value: "confirmed",
    Status.OBSERVED.value: "observed",
    Status.POTENTIAL.value: "potential",
    Status.NOT_OBSERVED.value: "not-observed",
    Status.INCONCLUSIVE.value: "inconclusive",
}

STATUS_LABEL = {
    Status.CONFIRMED.value: "CONFIRMADO",
    Status.OBSERVED.value: "OBSERVADO",
    Status.POTENTIAL.value: "POTENCIAL",
    Status.NOT_OBSERVED.value: "NO OBSERVADO",
    Status.INCONCLUSIVE.value: "NO CONCLUYENTE",
}

CSS = """
:root {
  color-scheme: light dark;
  --bg: #ffffff; --fg: #17191c; --muted: #5b6168; --line: #e3e6ea;
  --card: #f7f8fa; --accent: #1f4f8f;
  --confirmed: #8c1d1d; --observed: #b3410f; --potential: #8a6a08;
  --not-observed: #2c6b3f; --inconclusive: #5b6168;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14171a; --fg: #e8eaed; --muted: #9aa3ad; --line: #2b3137;
    --card: #1b1f24; --accent: #79a9e8;
    --confirmed: #f08b8b; --observed: #f0ae7d; --potential: #e3c874;
    --not-observed: #86ca9e; --inconclusive: #9aa3ad;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 0 16px 64px; background: var(--bg); color: var(--fg);
  font: 15px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
main { max-width: 62rem; margin: 0 auto; }
h1 { font-size: 1.6rem; margin: 2rem 0 0.25rem; }
h2 { font-size: 1.15rem; margin: 2.5rem 0 0.75rem; padding-bottom: 0.3rem;
     border-bottom: 1px solid var(--line); }
h3 { font-size: 1rem; margin: 1.25rem 0 0.35rem; }
p { margin: 0.5rem 0; }
code, pre, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
pre { background: var(--card); padding: 0.75rem; border-radius: 6px; overflow-x: auto;
      font-size: 0.82rem; line-height: 1.5; white-space: pre-wrap; word-break: break-word; }
.sub { color: var(--muted); margin: 0 0 1rem; }
.caveat { background: var(--card); border-left: 3px solid var(--accent);
          padding: 0.75rem 1rem; border-radius: 0 6px 6px 0; margin: 1.5rem 0; }
.headline { border: 1px solid var(--line); border-radius: 8px; padding: 1rem 1.25rem;
            margin: 1.5rem 0; background: var(--card); }
.headline h2 { border: 0; margin: 0.4rem 0 0.5rem; font-size: 1.25rem; }
.badge { display: inline-block; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.06em;
         padding: 0.2rem 0.55rem; border-radius: 999px; border: 1px solid currentColor; }
.confirmed { color: var(--confirmed); }
.observed { color: var(--observed); }
.potential { color: var(--potential); }
.not-observed { color: var(--not-observed); }
.inconclusive { color: var(--inconclusive); }
.tiles { display: flex; flex-wrap: wrap; gap: 0.6rem; margin: 1rem 0; padding: 0; list-style: none; }
.tiles li { border: 1px solid var(--line); border-radius: 6px; padding: 0.5rem 0.8rem;
            min-width: 8.5rem; background: var(--card); }
.tiles .n { display: block; font-size: 1.35rem; font-weight: 600; }
.tiles .k { color: var(--muted); font-size: 0.78rem; }
.finding { border: 1px solid var(--line); border-radius: 8px; padding: 0.9rem 1.1rem;
           margin: 0.75rem 0; }
.finding header { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.6rem; }
.finding .rule { color: var(--muted); font-size: 0.8rem; }
.meaning { color: var(--muted); font-size: 0.86rem; font-style: italic; margin-top: 0.5rem; }
table { border-collapse: collapse; width: 100%; font-size: 0.86rem; margin: 0.75rem 0; }
th, td { text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid var(--line);
         vertical-align: top; word-break: break-word; }
th { color: var(--muted); font-weight: 600; font-size: 0.78rem; text-transform: uppercase;
     letter-spacing: 0.04em; }
.chain { border-left: 2px solid var(--line); padding-left: 0.9rem; margin: 0.75rem 0; }
.chain .narrative { font-size: 0.86rem; }
.right { text-align: right; }
footer { color: var(--muted); font-size: 0.82rem; margin-top: 3rem;
         border-top: 1px solid var(--line); padding-top: 1rem; }
details { margin: 0.5rem 0; }
summary { cursor: pointer; color: var(--accent); font-size: 0.88rem; }
@media (max-width: 640px) { body { padding: 0 12px 48px; } .tiles li { flex: 1 1 8rem; } }
"""


def esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def render_html(report: dict[str, Any]) -> str:
    """Genera el reporte HTML completo a partir del reporte estructurado."""
    parts: list[str] = [
        "<!doctype html>",
        '<html lang="es"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>FirmaScope — {esc(report.get('target', ''))}</title>",
        f"<style>{CSS}</style></head><body><main>",
    ]
    parts.append(_header(report))
    parts.append(_headline(report))
    parts.append(_summary(report))
    parts.append(_findings(report))
    parts.append(_correlation(report))
    parts.append(_network(report))
    parts.append(_scripts(report))
    parts.append(_checkpoints(report))
    parts.append(_manifest(report))
    parts.append(_footer(report))
    parts.append("</main></body></html>")
    return "\n".join(p for p in parts if p)


# ----------------------------------------------------------------------
# Secciones
# ----------------------------------------------------------------------

def _header(report: dict[str, Any]) -> str:
    level = report.get("level", {})
    return (
        "<h1>FirmaScope</h1>"
        f"<p class=\"sub\">Auditoria de custodia de claves privadas &mdash; "
        f"<span class=\"mono\">{esc(report.get('target', ''))}</span><br>"
        f"Nivel {esc(level.get('value', ''))} ({esc(level.get('name', ''))})</p>"
        f"<div class=\"caveat\">{esc(report.get('caveat', ''))}</div>"
    )


def _headline(report: dict[str, Any]) -> str:
    headline = report.get("headline") or {}
    status = str(headline.get("status", ""))
    rule = headline.get("rule_id") or ""
    rule_html = f" <span class=\"rule mono\">{esc(rule)}</span>" if rule else ""
    return (
        "<div class=\"headline\">"
        f"<span class=\"badge {STATUS_CLASS.get(status, 'inconclusive')}\">"
        f"{esc(STATUS_LABEL.get(status, status))}</span>{rule_html}"
        f"<h2>{esc(headline.get('title', ''))}</h2>"
        f"<p>{esc(headline.get('detail', ''))}</p>"
        "</div>"
    )


def _summary(report: dict[str, Any]) -> str:
    summary = report.get("summary") or {}
    by_status = summary.get("by_status") or {}
    tiles = [
        ("Reglas evaluadas", summary.get("rules_evaluated", 0)),
        ("Con hallazgo", summary.get("actionable", 0)),
        ("Scripts analizados", summary.get("scripts_analyzed", 0)),
        ("Dominios de tercero", summary.get("third_party_domains", 0)),
    ]
    if summary.get("exfiltration_chains") is not None:
        tiles.insert(2, ("Cadenas de exfiltracion", summary["exfiltration_chains"]))

    items = "".join(
        f"<li><span class=\"n\">{esc(value)}</span><span class=\"k\">{esc(label)}</span></li>"
        for label, value in tiles
    )
    status_rows = "".join(
        f"<tr><td><span class=\"badge {STATUS_CLASS.get(status, 'inconclusive')}\">"
        f"{esc(STATUS_LABEL.get(status, status))}</span></td>"
        f"<td class=\"right mono\">{esc(count)}</td>"
        f"<td>{esc((report.get('status_meanings') or {}).get(status, ''))}</td></tr>"
        for status, count in by_status.items() if count
    )
    return (
        "<h2>Resumen</h2>"
        f"<ul class=\"tiles\">{items}</ul>"
        "<table><thead><tr><th>Estado</th><th class=\"right\">Reglas</th>"
        f"<th>Significado</th></tr></thead><tbody>{status_rows}</tbody></table>"
    )


def _findings(report: dict[str, Any]) -> str:
    findings = report.get("findings") or []
    if not findings:
        return ""
    blocks = []
    for finding in findings:
        status = str(finding.get("status", ""))
        evidence = finding.get("evidence") or []
        evidence_html = ""
        if evidence:
            evidence_html = (
                "<details><summary>Evidencia "
                f"({len(evidence)})</summary><pre>{esc(_pretty(evidence))}</pre></details>"
            )
        blocks.append(
            "<article class=\"finding\">"
            "<header>"
            f"<span class=\"badge {STATUS_CLASS.get(status, 'inconclusive')}\">"
            f"{esc(STATUS_LABEL.get(status, status))}</span>"
            f"<strong>{esc(finding.get('title', ''))}</strong>"
            f"<span class=\"rule mono\">{esc(finding.get('rule_id', ''))} &middot; "
            f"{esc(finding.get('severity', ''))} &middot; "
            f"confianza {esc(finding.get('confidence', ''))}</span>"
            "</header>"
            f"<p>{esc(finding.get('summary', ''))}</p>"
            f"<pre>{esc(finding.get('detail', ''))}</pre>"
            f"<p class=\"meaning\">{esc(finding.get('status_meaning', ''))}</p>"
            f"{evidence_html}"
            "</article>"
        )
    return "<h2>Hallazgos</h2>" + "".join(blocks)


def _correlation(report: dict[str, Any]) -> str:
    correlation = report.get("correlation")
    if not correlation:
        return ""
    chains = correlation.get("chains") or []
    if not chains:
        return (
            "<h2>Cadenas de procedencia</h2>"
            "<p>No se reconstruyo ninguna cadena: no se observaron salidas con procedencia "
            "atribuible.</p>"
        )
    blocks = []
    for chain in chains:
        latency = chain.get("latency_ms")
        # Sin latencia (salida previa al acceso a la clave, o marcas no
        # comparables) no se afirma nada sobre el instante.
        when = f" &middot; {latency} ms tras el acceso a la clave" if latency is not None else ""
        steps = "".join(
            f"<tr><td class=\"mono\">{esc(step.get('kind', ''))}</td>"
            f"<td>{esc(step.get('description', ''))}</td>"
            f"<td class=\"mono\">{esc(', '.join(step.get('labels') or []))}</td>"
            f"<td class=\"mono\">{esc(step.get('sensor', ''))}</td></tr>"
            for step in chain.get("steps") or []
        )
        blocks.append(
            "<div class=\"chain\">"
            f"<h3>{esc(chain.get('verdict', ''))} &rarr; {esc(chain.get('destination', ''))}</h3>"
            f"<p class=\"narrative mono\">{esc(chain.get('narrative', ''))}</p>"
            f"<p class=\"meaning\">{'transmision directa' if chain.get('direct') else 'dato derivado'}"
            f"{when} &middot; confianza {esc(chain.get('confidence', ''))}"
            f" &middot; sensores: {esc(', '.join(chain.get('corroboration') or []))}</p>"
            "<table><thead><tr><th>Paso</th><th>Descripcion</th><th>Etiquetas</th>"
            f"<th>Sensor</th></tr></thead><tbody>{steps}</tbody></table>"
            "</div>"
        )
    return "<h2>Cadenas de procedencia</h2>" + "".join(blocks)


def _network(report: dict[str, Any]) -> str:
    network = report.get("network") or {}
    domains = network.get("domains") or []
    if not domains:
        return ""
    rows = "".join(
        f"<tr><td class=\"mono\">{esc(d.get('domain', ''))}</td>"
        f"<td>{'tercero' if d.get('third_party') else 'propio'}</td>"
        f"<td class=\"right mono\">{esc(d.get('requests', 0))}</td>"
        f"<td class=\"right mono\">{esc(d.get('bytes_sent', 0))}</td></tr>"
        for d in domains
    )
    return (
        "<h2>Red</h2>"
        f"<p>{esc(network.get('total', 0))} peticiones observadas, "
        f"{esc(network.get('third_party', 0))} hacia terceros.</p>"
        "<table><thead><tr><th>Dominio</th><th>Clasificacion</th>"
        "<th class=\"right\">Peticiones</th><th class=\"right\">Bytes enviados</th>"
        f"</tr></thead><tbody>{rows}</tbody></table>"
    )


def _scripts(report: dict[str, Any]) -> str:
    scripts = report.get("scripts") or {}
    inventory = scripts.get("inventory") or []
    if not inventory:
        return ""
    rows = "".join(
        f"<tr><td class=\"mono\">{esc(s.get('url', ''))}</td>"
        f"<td>{'tercero' if s.get('third_party') else 'propio'}</td>"
        f"<td class=\"right mono\">{esc(s.get('size', 0))}</td>"
        f"<td class=\"mono\">{esc(str(s.get('sha256', ''))[:16])}</td></tr>"
        for s in inventory
    )
    return (
        "<h2>Scripts</h2>"
        f"<p>{esc(scripts.get('total', 0))} scripts inventariados, "
        f"{esc(scripts.get('third_party', 0))} de terceros. El hash permite verificar que el "
        "codigo analizado es el que se ejecuto.</p>"
        "<table><thead><tr><th>URL</th><th>Origen</th><th class=\"right\">Bytes</th>"
        f"<th>SHA-256</th></tr></thead><tbody>{rows}</tbody></table>"
    )


def _checkpoints(report: dict[str, Any]) -> str:
    checkpoints = report.get("checkpoints") or []
    if not checkpoints:
        return ""
    rows = "".join(
        f"<tr><td>{esc(c.get('name', ''))}</td><td class=\"mono\">{esc(c.get('network', ''))}</td>"
        f"<td>{esc(c.get('detail', ''))}</td></tr>"
        for c in checkpoints
    )
    return (
        "<h2>Hitos de la sesion</h2>"
        "<table><thead><tr><th>Hito</th><th>Red</th><th>Detalle</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def _manifest(report: dict[str, Any]) -> str:
    manifest = report.get("manifest") or {}
    verified = manifest.get("chain_verified")
    estado = {True: "verificada", False: "ROTA", None: "no verificada"}[verified]
    return (
        "<h2>Reproducibilidad</h2>"
        "<p>El expediente encadena cada evento con el anterior. Cabeza de la cadena: "
        f"<span class=\"mono\">{esc(str(manifest.get('chain_head', ''))[:32])}</span> "
        f"({esc(estado)}).</p>"
        f"<details><summary>Manifiesto completo</summary><pre>{esc(_pretty(manifest))}</pre></details>"
    )


def _footer(report: dict[str, Any]) -> str:
    meta = report.get("firmascope") or {}
    return (
        "<footer>"
        f"Generado por FirmaScope {esc(meta.get('version', ''))}. "
        "FirmaScope es una herramienta defensiva: audita sitios propios o con autorizacion de "
        "prueba, usando credenciales sinteticas. No emite calificaciones de &laquo;sitio "
        "seguro&raquo;."
        "</footer>"
    )


def _pretty(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, default=str, sort_keys=True)
