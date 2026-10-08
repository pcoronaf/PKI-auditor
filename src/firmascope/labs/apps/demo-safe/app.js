/*
 * demo-safe: la arquitectura correcta.
 *
 * La clave privada se descifra y se usa dentro del navegador. Lo unico que
 * cruza la red es la firma y el certificado, que son publicos por definicion.
 *
 * Es el caso que FirmaScope debe declarar NOT_OBSERVED en FS-KEY-001,
 * FS-KEY-002 y FS-PWD-001, y CONFIRMED en FS-LOCAL-001: la firma se genera con
 * la red aislada, asi que no pudo necesitar al servidor para producirla.
 */

labSetup({
  onSign: async function (state, documentText) {
    const keyBytes = await readFile(state.key);
    const cerBytes = await readFile(state.cer);

    const loaded = await loadPrivateKey(keyBytes, state.password);
    log('clave privada importada (no extraible)');

    const signature = await signDocument(loaded.key, documentText);
    log('firma generada: ' + signature.byteLength + ' bytes');

    return { signature: signature, certificate: cerBytes };
  },
  onSubmit: async function (pending) {
    const ok = await labSubmitSignature(pending);
    log('enviado al servidor: firma + certificado, nada mas');
    return ok;
  }
});
