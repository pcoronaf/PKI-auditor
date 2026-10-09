"""Lo que cada nivel ofrece: etapas, aislamiento e instrumentacion.

En el segundo piloto, con "Solo red" (nivel 1) la interfaz seguia preguntando
el aislamiento, el flujo ofrecia "Aislar la red" y "Firmar con la red aislada"
sin cortar nada, y el agente se inyectaba igual: el nivel 1, que es la prueba
de control de "la instrumentacion no altera el sitio", no lo era.
"""

from __future__ import annotations

import pytest

from firmascope.audit_core import options
from firmascope.audit_core.config import AuditConfig, IsolationMode, IsolationPolicy
from firmascope.browser_controller.isolation import stages_for


def respuestas(**valores):
    answers = options.defaults()
    answers.update(target="portal.ejemplo.mx", **valores)
    return answers


@pytest.mark.parametrize("nivel", ["1", "2"])
def test_sin_prueba_sin_conexion_no_se_pregunta_el_aislamiento(nivel):
    visibles = {o.id for o in options.visible_options(respuestas(level=nivel))}
    assert not visibles & {"isolation", "allow_hosts", "emulate_offline_flag"}
    # Un aislamiento elegido antes de bajar de nivel no se arrastra.
    config = options.build_config(respuestas(level=nivel, isolation="full"))
    assert config.isolation.mode is IsolationMode.NONE


@pytest.mark.parametrize("nivel", ["3", "4"])
def test_con_prueba_sin_conexion_si(nivel):
    visibles = {o.id for o in options.visible_options(respuestas(level=nivel))}
    assert "isolation" in visibles


@pytest.mark.parametrize("nivel,modo,esperado", [
    (1, "full", ["load", "prepare", "sign", "submit"]),
    (2, "full", ["load", "prepare", "sign", "submit"]),
    (4, "none", ["load", "prepare", "sign", "submit"]),
    (3, "full", ["load", "prepare", "isolate", "sign", "restore", "submit"]),
    (4, "third-party", ["load", "prepare", "isolate", "sign", "restore", "submit"]),
])
def test_las_etapas_dependen_del_nivel_y_del_aislamiento(nivel, modo, esperado):
    config = AuditConfig(target="https://x.mx", level=nivel,
                         isolation=IsolationPolicy(mode=IsolationMode.parse(modo)))
    etapas = stages_for(config)
    assert [s.name for s in etapas] == esperado
    if "isolate" not in esperado:
        # Ninguna etapa pide una red que no se va a cortar.
        assert all(s.network == "ONLINE" for s in etapas)
        firma = next(s for s in etapas if s.name == "sign")
        assert "no prueba donde se firma" in firma.instruction
