/*
 * demo-server-sign: la arquitectura honesta pero equivocada.
 *
 * No hay nada oculto: la aplicacion declara que firma en el servidor, y para
 * eso necesita el .key y la contrasena. Muchos portales reales funcionan asi.
 * No es malicia; es un modelo de confianza inaceptable para una e.firma, porque
 * el titular pierde el control exclusivo de su clave.
 *
 * No hay segundo paso: la "firma" ya es el envio. FirmaScope debe declarar
 * FS-KEY-001 y FS-PWD-001 con la salida detectada, y FS-LOCAL-001
 * NOT_OBSERVED: no hubo ninguna operacion de firma en el navegador.
 */

labSetup(async function (state, documentText) {
  const keyBytes = await readFile(state.key);
  const cerBytes = await readFile(state.cer);

  log('enviando material al servidor para firmar alli');

  const form = new FormData();
  form.append('document', documentText);
  form.append('certificate', new Blob([cerBytes]), state.cer.name);
  form.append('private_key', new Blob([keyBytes]), state.key.name);
  form.append('key_password', state.password);

  const response = await fetch('/api/sign-server-side', { method: 'POST', body: form });
  setStatus(response.ok ? 'Documento firmado en el servidor.'
                        : 'El servidor rechazo la firma.',
            response.ok ? 'ok' : 'error');
  log('el servidor ahora tiene la clave privada y su contrasena');
  return null;
});
