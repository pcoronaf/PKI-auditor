/*
 * Arranque comun de las aplicaciones de laboratorio.
 *
 * Cada demo implementa `firmarDocumento(keyBytes, password, cerBytes)` y este
 * fichero se encarga del resto: leer los ficheros, preparar el documento y
 * enrutar errores al registro de la pagina.
 *
 * El destino de exfiltracion de las demos inseguras es configurable con
 * `?collector=<url>`. Por defecto apunta a `/collect` del propio origen, de
 * modo que el laboratorio funciona sin red externa; pasar un host distinto
 * permite ejercitar tambien la clasificacion de terceros.
 */

/* Documento de ejemplo: lo que un sitio real haria firmar. */
const LAB_DOCUMENT =
  'FirmaScope laboratorio\n' +
  'Documento de prueba para ejercitar la instrumentacion.\n' +
  'No tiene valor legal alguno.\n';

function labParams() {
  return new URLSearchParams(location.search);
}

/* URL a la que las demos inseguras envian lo que no deberian enviar. */
function collectorUrl(path) {
  const base = labParams().get('collector') || '';
  if (!base) { return path; }
  return base.replace(/\/+$/, '') + path;
}

/* URL del servicio legitimo al que toda demo entrega la firma. */
function serviceUrl(path) {
  const base = labParams().get('service') || '';
  if (!base) { return path; }
  return base.replace(/\/+$/, '') + path;
}

function showDocument() {
  const el = document.getElementById('document');
  if (el) { el.textContent = LAB_DOCUMENT; }
}

/*
 * Conecta el boton de firma. `handler` recibe el material ya leido y es lo
 * unico que cambia entre demos.
 */
function labMain(handler) {
  showDocument();
  const button = document.getElementById('sign');
  if (!button) { return; }
  button.addEventListener('click', async function () {
    const keyInput = document.getElementById('key-file');
    const cerInput = document.getElementById('cer-file');
    const keyFile = keyInput && keyInput.files[0];
    const cerFile = cerInput && cerInput.files[0];
    const password = document.getElementById('password').value;

    if (!keyFile) { setStatus('Selecciona el archivo .key.', 'error'); return; }
    if (!password) { setStatus('Escribe la contrasena de la clave.', 'error'); return; }

    button.disabled = true;
    setStatus('Firmando...', 'info');
    try {
      const keyBytes = await readFile(keyFile);
      const cerBytes = cerFile ? await readFile(cerFile) : null;
      await handler(keyBytes, password, cerBytes);
    } catch (error) {
      setStatus('Error: ' + (error && error.message ? error.message : error), 'error');
      log('ERROR ' + error);
    } finally {
      button.disabled = false;
    }
  });
}

/* Entrega de la firma al servicio. Legitima: `signature` es el producto S6. */
async function entregarFirma(signature, cerBytes) {
  const body = JSON.stringify({
    document: LAB_DOCUMENT,
    signature: toBase64(signature),
    certificate: cerBytes ? toBase64(cerBytes) : null
  });
  await fetch(serviceUrl('/api/sign-receipt'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body
  });
  log('firma entregada al servicio (' + body.length + ' bytes)');
}
