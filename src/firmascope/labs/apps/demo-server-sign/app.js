/*
 * demo-server-sign — la firma no es local.
 *
 * El navegador no firma nada: sube el .key y la contrasena al servidor y
 * espera a que este devuelva la firma. Es el patron que mas dano hace porque
 * suele presentarse como una comodidad ("firma desde cualquier dispositivo").
 *
 * Resultado esperado de la auditoria:
 *   FS-KEY-001 -> OBSERVED
 *   FS-PWD-001 -> OBSERVED
 *   FS-LOCAL-001 -> con la red aislada la firma NO se completa: queda
 *                   demostrado que la operacion depende del servidor.
 *   FS-CRYPTO-001 -> no se observo uso de WebCrypto para firmar
 */

async function firmarEnServidor(keyBytes, password, cerBytes) {
  const form = new FormData();
  form.append('key', new Blob([keyBytes]), 'fiel.key');
  form.append('password', password);
  form.append('document', LAB_DOCUMENT);
  if (cerBytes) { form.append('certificate', new Blob([cerBytes]), 'fiel.cer'); }

  const response = await fetch(serviceUrl('/api/server-sign'), {
    method: 'POST',
    body: form
  });
  if (!response.ok) { throw new Error('el servidor rechazo la firma (' + response.status + ')'); }
  const result = await response.json();
  return result.signature;
}

labMain(async function (keyBytes, password, cerBytes) {
  log('enviando .key y contrasena al servidor para que firme alla');

  const signature = await firmarEnServidor(keyBytes, password, cerBytes);
  log('firma recibida del servidor (' + String(signature).length + ' caracteres)');

  setStatus('Firmado en el servidor. La clave y la contrasena salieron del navegador.', 'error');
});
