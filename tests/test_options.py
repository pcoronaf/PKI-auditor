"""Esquema de opciones: el contrato entre el nucleo y cualquier interfaz."""

from __future__ import annotations

import pytest

from firmascope.audit_core import options
from firmascope.audit_core.config import CredentialMode, IsolationMode


def test_el_esquema_es_serializable_para_una_interfaz_grafica():
    """La GUI consume el esquema; si no es JSON, no hay contrato."""
    import json

    data = json.dumps(options.schema(), default=str)
    assert json.loads(data)
    for item in options.schema():
        assert item["id"] and item["kind"] and item["label"]
        assert item["group"] in ("basico", "avanzado")


def test_sin_argumentos_se_puede_auditar_sin_objetivo():
    """`firmascope audit` debe arrancar y recibir la pagina desde la interfaz."""
    config = options.build_config(options.defaults())
    assert config.target == ""
    assert not config.has_target
    assert config.set_target("portal.ejemplo.mx") == "https://portal.ejemplo.mx"


def test_los_campos_dependientes_solo_se_piden_cuando_aplican():
    respuestas = options.defaults()
    visibles = {o.id for o in options.visible_options(respuestas)}
    assert "key_path" not in visibles, "no se piden archivos para la credencial sintetica"

    respuestas["credentials"] = "own-test"
    visibles = {o.id for o in options.visible_options(respuestas)}
    assert {"key_path", "cert_path"} <= visibles

    respuestas["isolation"] = "allowlist"
    visibles = {o.id for o in options.visible_options(respuestas)}
    assert "allow_hosts" in visibles


def test_la_credencial_real_no_se_acepta_sin_consentimiento():
    respuestas = options.defaults()
    respuestas.update({"credentials": "real", "key_path": "/tmp/a.key",
                       "cert_path": "/tmp/a.cer"})
    problemas = options.validate(respuestas)
    assert any("riesgo" in p.lower() or "acepto" in p.lower() for p in problemas), problemas

    respuestas["accept_real_risk"] = True
    assert not [p for p in options.validate(respuestas)
                if "acepto" in p.lower() or "riesgo" in p.lower()]


def test_lo_que_cambiaria_el_significado_de_lo_registrado_no_se_cambia_en_marcha():
    config = options.build_config(options.defaults())
    with pytest.raises(ValueError):
        options.apply_live_change(config, "credentials", "real")
    with pytest.raises(ValueError):
        options.apply_live_change(config, "level", "1")


def test_el_aislamiento_si_se_puede_ajustar_en_marcha():
    config = options.build_config(options.defaults())
    descripcion = options.apply_live_change(config, "isolation", "third-party")
    assert config.isolation.mode is IsolationMode.THIRD_PARTY
    assert descripcion


def test_la_contrasena_no_viaja_en_las_respuestas_serializables(credential):
    respuestas = options.defaults()
    respuestas.update({"credentials": "own-test",
                       "key_path": str(credential.key_path),
                       "cert_path": str(credential.cert_path)})
    setup = options.build_setup(respuestas, "secreto")
    assert setup.password == "secreto"
    assert "secreto" not in str(setup.answers)
    assert setup.config.credential_mode is CredentialMode.OWN_TEST


def test_los_argumentos_de_la_cli_solo_precargan_el_asistente():
    """Un argumento no debe fijar nada que el operador no haya elegido."""
    from firmascope.cli.main import _seed_from_args, build_parser

    args = build_parser().parse_args(["audit", "--level", "2"])
    seed = _seed_from_args(args)
    assert seed == {"level": "2"}, seed
