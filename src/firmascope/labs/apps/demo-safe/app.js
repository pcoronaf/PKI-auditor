/*
 * demo-safe — comportamiento correcto.
 *
 * La clave privada se descifra y se usa dentro del navegador. Al servicio solo
 * viaja el producto legitimo de la operacion: la firma y el certificado, que
 * es material publico.
 *
 * Resultado esperado de la auditoria:
 *   FS-KEY-001 / FS-KEY-002 / FS-PWD-001 / FS-PWD-002 -> NOT_OBSERVED
 *   FS-LOCAL-001 -> CONFIRMED con la red aislada (nivel 3)
 */

labMain(async function (keyBytes, password, cerBytes) {
  const loaded = await loadPrivateKey(keyBytes, password);
  log('clave privada importada (no extraible)');

  const signature = await signDocument(loaded.key, LAB_DOCUMENT);
  log('documento firmado localmente (' + signature.byteLength + ' bytes)');

  await entregarFirma(signature, cerBytes);
  setStatus('Firmado localmente. Solo se envio la firma.', 'ok');
});
