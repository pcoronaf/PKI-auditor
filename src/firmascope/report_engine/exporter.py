"""Escritura del expediente de auditoria y del reporte.

Produce la estructura de la especificacion y, con ella, un reporte JSON
estructurado y un HTML autocontenido (sin un solo recurso externo: el reporte
de una auditoria de seguridad no debe llamar a nadie al abrirse).

El reporte no lleva puntuacion global. Por cada propiedad evaluada publica un
estado y la evidencia que lo sostiene.
"""

from __future__ import annotations

import html
import json
import time
from pathlib import Path
from typing import Any

from ..audit_core.conclusions import STATUS_MEANING, Status
from ..audit_core.config import AuditConfig
from ..evidence_store.store import EvidenceStore

#: Orden de presentacion de los hallazgos.
STATUS_ORDER = {
    Status.CONFIRMED.value: 0,
    Status.OBSERVED.value: 1,
    Status.POTENTIAL.value: 2,
    Status.INCONCLUSIVE.value: 3,
    Status.NOT_OBSERVED.value: 4,
}

STATUS_LABEL = {
    Status.CONFIRMED.value: "CONFIRMADO",
    Status.OBSERVED.value: "OBSERVADO",
    Status.POTENTIAL.value: "POTENCIAL",
    Status.NOT_OBSERVED.value: "NO OBSERVADO",
    Status.INCONCLUSIVE.value: "SIN CONCLUIR",
}


def _dump(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str),
                    encoding="utf-8")


def _browser_infrastructure(requests: list[dict[str, Any]]) -> dict[str, int]:
    """Destinos propios del navegador, no imputados al sitio auditado."""
    from ..network_analyzer import domains

    counts: dict[str, int] = {}
    for request in requests:
        host = str(request.get("host") or "")
        if host and domains.is_browser_infrastructure(host):
            counts[host] = counts.get(host, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def _network_mode(config: AuditConfig, windows: int) -> str:
    """Modo de red del manifiesto: OFFLINE-TESTED solo si el aislamiento fue total."""
    if not windows:
        return "ONLINE"
    if config.isolation.is_total():
        return "OFFLINE-TESTED"
    return "PARTIAL-ISOLATION-TESTED"


def _sensors(events: list[Any], proxy: dict[str, Any] | None) -> dict[str, Any]:
    """Que sensores aportaron observaciones, y que no pudo verse sin ellos."""
    active = {e.sensor for e in events if e.sensor}
    proxy = proxy or {}
    recovered = sum(1 for e in events if e.data.get("body_recovered_by_proxy"))
    info: dict[str, Any] = {
        "agent": "agent" in active,
        "cdp": "cdp" in active,
        "isolation": "isolation" in active,
        "proxy": bool(proxy.get("running")),
        "bodies_recovered_by_proxy": recovered,
    }
    notes: list[str] = []
    if not info["agent"]:
        notes.append(
            "Sin instrumentacion en la pagina (nivel 1): no se observo la lectura del "
            ".key ni de la contrasena, asi que las reglas de procedencia quedan sin "
            "concluir. Es tambien la prueba de control: si el sitio funciona aqui y no "
            "con instrumentacion, la instrumentacion lo altera.")
    if not info["proxy"]:
        notes.append(
            "Sin interceptacion TLS, los cuerpos que el navegador no entrega al "
            "depurador (subidas multipart, flujos) no se examinaron por contenido. "
            "La procedencia que aporta la instrumentacion sigue siendo valida; lo "
            "que no hay es prueba de contenido para esas peticiones.")
    elif proxy.get("error"):
        notes.append(str(proxy["error"]))
    if notes:
        info["limitation"] = " ".join(notes)
    return info


def build_report(store: EvidenceStore, config: AuditConfig, session_id: str,
                 versions: dict[str, Any], static_report: Any = None,
                 isolation: dict[str, Any] | None = None,
                 credential: Any = None, aborted: bool = False,
                 abort_reason: str = "",
                 proxy: dict[str, Any] | None = None) -> dict[str, Any]:
    """Construye el reporte estructurado a partir del expediente."""
    from ..browser_controller.isolation import processing_locality
    from ..rule_engine.context import AuditContext

    findings = store.findings()
    context = AuditContext.from_store(store, config, static=static_report, credential=credential)
    events, requests, scripts = context.events, context.requests, context.scripts
    offline_windows = context.offline_windows()
    third_parties = context.third_parties_after_key_access()
    names = context.third_party_names()

    integrity_ok, broken_at = store.verify_chain()

    return {
        "session": session_id,
        "generated_at": time.time(),
        "target": config.target or "",
        "aborted": aborted,
        "abort_reason": abort_reason,
        "level": {"value": int(config.level), "name": config.level.name},
        "credential_mode": config.credential_mode.value,
        "credential": credential.describe(config.privacy) if credential is not None else {},
        "versions": versions,
        "integrity": {
            "chain_head": store.chain_head,
            "verified": integrity_ok,
            "broken_at_index": broken_at,
        },
        "counts": {
            "events": len(events),
            "requests": len(requests),
            "scripts": len(scripts),
            "findings": len(findings),
            "offline_windows": len(offline_windows),
        },
        # La contrasena de la cuenta del portal no es "acceso a la contrasena"
        # de la e.firma: mismo criterio que las reglas.
        "processing_locality": processing_locality(
            [e for e in events if not context.is_other_password_read(e)], offline_windows,
            config.isolation.window_label()),
        "isolation": isolation or {},
        # Que sensores estuvieron activos acota lo que el expediente puede
        # afirmar. Sin proxy, un cuerpo que el navegador no entrego no se pudo
        # examinar, y eso debe leerse junto a los hallazgos.
        "sensors": _sensors(events, proxy),
        "proxy": proxy or {"enabled": False},
        # Lo excluido de la atribucion, dicho en voz alta: un expediente que
        # filtra trafico sin declararlo no es verificable.
        "browser_infrastructure": _browser_infrastructure(requests),
        "third_parties_after_key_access": {
            domain: {"name": names.get(domain, domain), "requests": len(items)}
            for domain, items in sorted(third_parties.items(), key=lambda kv: -len(kv[1]))
        },
        "findings": sorted(findings, key=lambda f: (STATUS_ORDER.get(f["status"], 9),
                                                    f["rule_id"])),
        "static_analysis": static_report.to_dict() if static_report is not None else {},
        "status_meaning": {status.value: text for status, text in STATUS_MEANING.items()},
        "warnings": config.real_credential_warnings() + _credential_mismatch_warnings(context),
    }


def _credential_mismatch_warnings(context: Any) -> list[str]:
    """Aviso, al frente del reporte, de que la credencial en uso no era la registrada."""
    if not context.foreign_key_used():
        return []
    return [
        "En la pagina se cargo un .key distinto del de la credencial de la sesion "
        f"({context.config.credential_mode.value}). Las busquedas por contenido (canarios) "
        "son de la credencial registrada y no dicen nada del material que se uso; la "
        "contrasena de ese .key no estaba protegida en el vault, y su longitud no sirve para "
        "distinguirla de otras. Si era una e.firma real, repita la auditoria en modo "
        "credencial real, que la registra y la protege."
    ]


def write_package(store: EvidenceStore, config: AuditConfig, session_id: str,
                  versions: dict[str, Any], static_report: Any = None,
                  isolation: dict[str, Any] | None = None, credential: Any = None,
                  aborted: bool = False, abort_reason: str = "",
                  proxy: dict[str, Any] | None = None) -> Path:
    """Escribe el expediente completo y devuelve su directorio."""
    root = store.root
    root.mkdir(parents=True, exist_ok=True)

    events = store.events()
    report = build_report(store, config, session_id, versions, static_report,
                          isolation, credential, aborted, abort_reason, proxy)

    _dump(root / "timeline.json", [e.to_dict() for e in events])
    _dump(root / "requests.json", store.requests())
    _dump(root / "findings.json", store.findings())
    _dump(root / "script-hashes.json", [
        {"url": s["url"], "sha256": s["sha256"], "size": s["size"],
         "third_party": s["third_party"], "inline": s["inline"], "path": s["path"]}
        for s in store.scripts()
    ])
    _dump(root / "report.json", report)

    manifest = {
        "session": session_id,
        "target": config.target or "",
        "started_at": store.session_info().get("started_at"),
        "ended_at": time.time(),
        "firmascope_version": versions.get("firmascope", ""),
        "agent_sha256": versions.get("agent_sha256", ""),
        "browser": versions.get("browser", ""),
        "browser_path": versions.get("browser_path", ""),
        "os": versions.get("os", ""),
        "python": versions.get("python", ""),
        "audit_configuration": config.to_dict(),
        "network_mode": _network_mode(config, report["counts"]["offline_windows"]),
        "credential": report["credential"],
        "scripts_sha256": {s["url"]: s["sha256"] for s in store.scripts()},
        "proxy": config.proxy.to_dict(),
        "evidence": store.evidence(),
        "chain_head": store.chain_head,
        "chain_algorithm": "SHA256(prev_hash || canonical_json(event))",
        "aborted": aborted,
        "abort_reason": abort_reason,
    }
    _dump(root / "manifest.json", manifest)
    (root / "report.html").write_text(render_html(report), encoding="utf-8")
    return root


# ----------------------------------------------------------------------
# Resumen de consola
# ----------------------------------------------------------------------

def _wrap_text(text: str, indent: str = "  ", width: int = 76) -> str:
    """Ajuste de linea simple para el resumen de terminal."""
    out: list[str] = []
    current = ""
    for word in text.split():
        if len(current) + len(word) + 1 > width - len(indent):
            out.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        out.append(current)
    return ("\n" + indent).join(out)


def text_summary(report: dict[str, Any]) -> str:
    """Resumen legible para la terminal."""
    lines: list[str] = []
    lines.append(f"Sesion:     {report['session']}")
    lines.append(f"Objetivo:   {report['target'] or '(ninguno)'}")
    lines.append(f"Nivel:      {report['level']['value']} ({report['level']['name']})")
    lines.append(f"Credencial: {report['credential_mode']}")
    if report["aborted"]:
        lines.append(f"CANCELADA:  {report['abort_reason']}")
    counts = report["counts"]
    lines.append(f"Observado:  {counts['events']} eventos, {counts['requests']} peticiones, "
                 f"{counts['scripts']} scripts")

    locality = report.get("processing_locality") or {}
    if locality:
        lines.append("")
        lines.append("Localidad del procesamiento")
        width = max(len(k) for k in locality)
        for label, state in locality.items():
            lines.append(f"  {label.ljust(width)}  {state}")

    isolation = report.get("isolation") or {}
    blocked = isolation.get("blocked_count", 0)
    if blocked:
        private = isolation.get("blocked_with_private_data", 0)
        lines.append("")
        lines.append(f"Intentos de salida bloqueados por el aislamiento: {blocked}"
                     + (f" ({private} con material privado)" if private else ""))

    # Que sensores hubo acota lo que el expediente puede afirmar, asi que se
    # dice antes de los hallazgos y no en una nota al pie.
    sensors = report.get("sensors") or {}
    if sensors:
        activos = [name for name in ("agent", "cdp", "isolation", "proxy")
                   if sensors.get(name)]
        lines.append("")
        lines.append(f"Sensores activos: {', '.join(activos) or 'ninguno'}")
        recovered = sensors.get("bodies_recovered_by_proxy") or 0
        if recovered:
            lines.append(f"  Cuerpos que solo el proxy pudo examinar: {recovered}")
        if sensors.get("limitation"):
            lines.append("  " + _wrap_text(sensors["limitation"], "  "))

    lines.append("")
    lines.append("Hallazgos")
    for finding in report["findings"]:
        label = STATUS_LABEL.get(finding["status"], finding["status"])
        lines.append(f"  [{label:<13}] {finding['rule_id']}  {finding['title']}")
        if finding["status"] not in (Status.NOT_OBSERVED.value, Status.INCONCLUSIVE.value):
            lines.append(f"      {finding['summary']}")

    third = report.get("third_parties_after_key_access") or {}
    if third:
        lines.append("")
        lines.append("Terceros con trafico tras el acceso a la clave")
        for domain, info in third.items():
            lines.append(f"  {domain} ({info['name']}): {info['requests']} peticiones")

    integrity = report["integrity"]
    lines.append("")
    lines.append(f"Cadena de evidencias: {'intacta' if integrity['verified'] else 'ROTA'}"
                 f"  head={integrity['chain_head'][:16]}")

    for warning in report.get("warnings") or []:
        lines.append(f"  aviso: {warning}")
    return "\n".join(lines)


# ----------------------------------------------------------------------
# HTML autocontenido
# ----------------------------------------------------------------------

_CSS = """
:root{color-scheme:light dark;--fg:#16181d;--bg:#f7f8fa;--card:#fff;--line:#dcdfe4;
--muted:#6b7280;--accent:#0b62d0;--crit:#b3261e;--warn:#9a6700;--ok:#1a7f37;--info:#4b5563}
@media(prefers-color-scheme:dark){:root{--fg:#e8eaed;--bg:#15171b;--card:#1d2026;
--line:#333945;--muted:#9aa3b2;--accent:#6aa9ff;--crit:#ff6b5e;--warn:#e3b341;--ok:#56d364}}
*{box-sizing:border-box}
body{margin:0;padding:32px 20px;background:var(--bg);color:var(--fg);line-height:1.55;
font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:860px;margin:0 auto}
h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.05rem;margin:28px 0 10px}
.sub{color:var(--muted);font-size:.875rem;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:16px 18px;margin-bottom:14px}
.kv{display:grid;grid-template-columns:minmax(140px,auto) 1fr;gap:4px 16px;font-size:.9rem}
.kv dt{color:var(--muted)}.kv dd{margin:0;overflow-wrap:anywhere}
table{width:100%;border-collapse:collapse;font-size:.875rem}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}
.badge{display:inline-block;padding:1px 9px;border-radius:999px;font-size:.72rem;
font-weight:700;letter-spacing:.03em;white-space:nowrap}
.CONFIRMED{background:var(--ok);color:#fff}.OBSERVED{background:var(--crit);color:#fff}
.POTENTIAL{background:var(--warn);color:#fff}.NOT_OBSERVED{background:transparent;
color:var(--muted);border:1px solid var(--line)}.INCONCLUSIVE{background:var(--info);color:#fff}
.finding{border-left:3px solid var(--line);padding-left:14px;margin:16px 0}
.finding.OBSERVED,.finding.CONFIRMED{border-left-color:var(--crit)}
.finding.POTENTIAL{border-left-color:var(--warn)}
.finding h3{font-size:.95rem;margin:0 0 4px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.finding p{margin:4px 0}
pre{background:rgba(127,127,127,.12);padding:11px;border-radius:6px;overflow:auto;
font-size:.78rem;white-space:pre-wrap;word-break:break-word}
.note{border-left:3px solid var(--warn);padding:8px 12px;background:rgba(227,179,65,.12);
border-radius:0 6px 6px 0;font-size:.875rem;margin:10px 0}
code{font-size:.84rem}
footer{color:var(--muted);font-size:.8rem;margin-top:32px;border-top:1px solid var(--line);
padding-top:14px}
"""


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _isolation_scope(isolation: dict[str, Any], counts: dict[str, Any]) -> str:
    """Alcance del aislamiento, junto al numero de ventanas: una ventana "solo
    terceros" no es una ventana sin red."""
    mode = (isolation.get("policy") or {}).get("mode")
    if not counts.get("offline_windows") or not mode:
        return ""
    if mode == "third-party":
        return " (solo terceros: el servidor del sitio seguia alcanzable)"
    if mode == "allowlist" and (isolation.get("policy") or {}).get("allow_hosts"):
        return " (lista de permitidos: esos hosts seguian alcanzables)"
    return " (total)"


def render_html(report: dict[str, Any]) -> str:
    """Reporte HTML autocontenido, sin recursos externos."""
    session = _esc(report["session"])
    rows: list[str] = []

    for finding in report["findings"]:
        status = finding["status"]
        label = STATUS_LABEL.get(status, status)
        evidence = finding.get("evidence") or []
        detail = _esc(finding.get("detail", "")).replace("\n", "<br>")
        rows.append(f"""
      <div class="finding {_esc(status)}">
        <h3><span class="badge {_esc(status)}">{_esc(label)}</span>
            <code>{_esc(finding['rule_id'])}</code> {_esc(finding['title'])}</h3>
        <p>{_esc(finding['summary'])}</p>
        <p class="sub">severidad {_esc(finding['severity'])} &middot;
           confianza {_esc(finding['confidence'])} &middot;
           {len(evidence)} elementos de evidencia</p>
        <details><summary>Detalle</summary><p>{detail}</p></details>
      </div>""")

    locality = report.get("processing_locality") or {}
    locality_rows = "".join(
        f"<tr><td>{_esc(k)}</td><td><strong>{_esc(v)}</strong></td></tr>"
        for k, v in locality.items())

    third = report.get("third_parties_after_key_access") or {}
    third_rows = "".join(
        f"<tr><td>{_esc(d)}</td><td>{_esc(i['name'])}</td><td>{i['requests']}</td></tr>"
        for d, i in third.items()) or "<tr><td colspan=3>Ninguno.</td></tr>"

    isolation = report.get("isolation") or {}
    blocked = isolation.get("blocked_attempts") or []
    blocked_rows = "".join(
        f"<tr><td>{_esc(b.get('method'))}</td><td>{_esc(b.get('host'))}</td>"
        f"<td>{b.get('body_size', 0)}</td><td>{_esc(', '.join(b.get('tags') or []))}</td></tr>"
        for b in blocked[:50]) or "<tr><td colspan=4>Ninguno.</td></tr>"

    sensors = report.get("sensors") or {}
    sensor_labels = {
        "agent": "Instrumentacion en la pagina",
        "cdp": "Red por DevTools (CDP)",
        "isolation": "Aislamiento de red",
        "proxy": "Interceptacion TLS (proxy)",
    }
    sensor_rows = "".join(
        f"<tr><td>{_esc(label)}</td>"
        f"<td><strong>{'activo' if sensors.get(key) else 'ausente'}</strong></td></tr>"
        for key, label in sensor_labels.items()) or \
        "<tr><td colspan=2>Sin informacion de sensores.</td></tr>"
    recovered = sensors.get("bodies_recovered_by_proxy") or 0
    sensor_note = ""
    if sensors.get("limitation"):
        sensor_note = f'<div class="note">{_esc(sensors["limitation"])}</div>'
    elif recovered:
        sensor_note = (f'<p class="sub">{recovered} cuerpos pudieron examinarse solo '
                       f'gracias al proxy: el depurador del navegador no los entrega.</p>')

    infrastructure = report.get("browser_infrastructure") or {}
    infra_rows = "".join(f"<tr><td>{_esc(h)}</td><td>{n}</td></tr>"
                         for h, n in infrastructure.items())
    infra_html = ""
    if infra_rows:
        infra_html = f"""
  <h2>Trafico del propio navegador</h2>
  <div class="card">
    <p class="sub">Destinos de los servicios de Chromium (actualizaciones,
    autocompletado, deteccion de phishing). Quedan registrados pero <strong>no se
    imputan al sitio auditado</strong>: no los pidio el portal.</p>
    <table><thead><tr><th>Destino</th><th>Peticiones</th></tr></thead>
    <tbody>{infra_rows}</tbody></table></div>"""

    warnings_html = "".join(f'<div class="note">{_esc(w)}</div>'
                            for w in report.get("warnings") or [])
    aborted_html = (f'<div class="note">Sesion cancelada: '
                    f'{_esc(report["abort_reason"])}. El expediente contiene lo observado '
                    f'hasta ese punto.</div>') if report.get("aborted") else ""

    integrity = report["integrity"]
    counts = report["counts"]

    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FirmaScope {session}</title>
<style>{_CSS}</style></head>
<body><main>
  <h1>Reporte de auditoria {session}</h1>
  <p class="sub">{_esc(report['target'] or 'sin objetivo registrado')} &middot;
     nivel {_esc(report['level']['value'])} ({_esc(report['level']['name'])}) &middot;
     credencial {_esc(report['credential_mode'])}</p>

  {aborted_html}{warnings_html}

  <div class="card"><dl class="kv">
    <dt>Eventos</dt><dd>{counts['events']}</dd>
    <dt>Peticiones</dt><dd>{counts['requests']}</dd>
    <dt>Scripts</dt><dd>{counts['scripts']}</dd>
    <dt>Ventanas de aislamiento</dt><dd>{counts['offline_windows']}{_esc(_isolation_scope(isolation, counts))}</dd>
    <dt>Navegador</dt><dd>{_esc(report['versions'].get('browser', ''))}</dd>
    <dt>Agente SHA-256</dt><dd><code>{_esc(report['versions'].get('agent_sha256', ''))}</code></dd>
    <dt>Cadena</dt><dd>{'intacta' if integrity['verified'] else 'ROTA'}
        <code>{_esc(integrity['chain_head'][:32])}</code></dd>
  </dl></div>

  <h2>Sensores de esta sesion</h2>
  <div class="card">
    <p class="sub">Lo que el expediente puede afirmar depende de lo que se pudo
    observar. Un sensor ausente no deja hallazgos vacios: deja preguntas sin
    responder.</p>
    <table><tbody>{sensor_rows}</tbody></table>
    {sensor_note}
  </div>

  <h2>Localidad del procesamiento</h2>
  <div class="card"><table><tbody>{locality_rows or
      '<tr><td colspan=2>Sin hitos observados.</td></tr>'}</tbody></table></div>

  <h2>Hallazgos</h2>
  {''.join(rows) or '<div class="card">Sin hallazgos.</div>'}

  <h2>Terceros con trafico tras el acceso a la clave</h2>
  <div class="card"><table>
    <thead><tr><th>Dominio</th><th>Servicio</th><th>Peticiones</th></tr></thead>
    <tbody>{third_rows}</tbody></table></div>

  <h2>Intentos de salida bloqueados por el aislamiento</h2>
  <div class="card"><table>
    <thead><tr><th>Metodo</th><th>Destino</th><th>Bytes</th><th>Etiquetas</th></tr></thead>
    <tbody>{blocked_rows}</tbody></table></div>
{infra_html}

  <footer>
    <p>FirmaScope {_esc(report['versions'].get('firmascope', ''))}. Este reporte describe
    lo observado durante una ejecucion concreta. <strong>No observado no equivale a
    imposible.</strong></p>
    <p>El expediente no contiene la clave privada ni la contrasena: la correlacion se hizo
    con fingerprints HMAC de una clave de sesion que ya fue destruida.</p>
  </footer>
</main></body></html>
"""
