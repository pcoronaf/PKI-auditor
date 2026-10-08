/*
 * Flujo comun de las aplicaciones de laboratorio.
 *
 * Las cinco aplicaciones comparten la misma interaccion y se diferencian solo
 * en lo que hacen con el material. Esa diferencia vive en el `app.js` de cada
 * una y nada mas.
 *
 * La firma y el envio estan separados en dos pulsaciones a proposito: es lo
 * que permite que la prueba por etapas de FirmaScope firme con la red aislada
 * y envie despues, con la red restablecida. Un portal que los une en un solo
 * clic no puede distinguir "la firma necesita la red" de "el envio necesita la
 * red", y esa es justamente la pregunta de la auditoria.
 */

/* Documento fijo: que la firma sea reproducible entre sesiones. */
const LAB_DOCUMENT =
  '||1.1|A|FIRMASCOPE-LAB|2026-01-01T00:00:00|' +
  'Cadena original de laboratorio, no fiscal||';

/*
 * `options.onSign` recibe `(state, documento)` y devuelve lo que haya que
 * enviar despues. `options.onSubmit` recibe eso y lo envia; si no se da, la
 * aplicacion no tiene segundo paso (es el caso de la firma en servidor).
 */
function labSetup(options) {
  const onSign = typeof options === 'function' ? options : options.onSign;
  const onSubmit = typeof options === 'function' ? null : options.onSubmit;

  const state = { cer: null, key: null, password: '', pending: null };
  const docEl = document.getElementById('document');
  if (docEl) { docEl.textContent = LAB_DOCUMENT; }

  const submitButton = document.getElementById('submit');
  if (submitButton && !onSubmit) { submitButton.hidden = true; }

  document.getElementById('cer-file').addEventListener('change', function (e) {
    state.cer = e.target.files[0] || null;
    if (state.cer) { log('.cer seleccionado: ' + state.cer.name); }
  });
  document.getElementById('key-file').addEventListener('change', function (e) {
    state.key = e.target.files[0] || null;
    if (state.key) { log('.key seleccionado: ' + state.key.name); }
  });

  document.getElementById('sign').addEventListener('click', async function () {
    state.password = document.getElementById('password').value;
    if (!state.key || !state.cer || !state.password) {
      setStatus('Faltan el .cer, el .key o la contrasena.', 'error');
      return;
    }
    setStatus('Procesando...', 'info');
    try {
      state.pending = await onSign(state, LAB_DOCUMENT);
      if (onSubmit && submitButton) {
        submitButton.disabled = false;
        setStatus('Firma lista. Pulse "Enviar firma al servidor".', 'ok');
      }
    } catch (err) {
      setStatus('Error: ' + (err && err.message ? err.message : err), 'error');
      log('error: ' + err);
    }
  });

  if (onSubmit && submitButton) {
    submitButton.addEventListener('click', async function () {
      if (!state.pending) {
        setStatus('No hay firma que enviar.', 'error');
        return;
      }
      setStatus('Enviando...', 'info');
      try {
        const ok = await onSubmit(state.pending, LAB_DOCUMENT);
        setStatus(ok ? 'Firma enviada.' : 'El servidor rechazo el envio.',
                  ok ? 'ok' : 'error');
      } catch (err) {
        setStatus('El envio fallo: ' + (err && err.message ? err.message : err), 'error');
        log('envio fallido: ' + err);
      }
    });
  }
}

/* Envio del resultado legitimo: solo la firma y el certificado. */
async function labSubmitSignature(pending) {
  const response = await fetch('/api/submit', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      document: LAB_DOCUMENT,
      signature: toBase64(pending.signature),
      certificate: toBase64(pending.certificate)
    })
  });
  return response.ok;
}
