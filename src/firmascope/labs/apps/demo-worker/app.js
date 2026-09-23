/*
 * demo-worker — la clave cruza a un Web Worker.
 *
 * La pagina lee el .key y la contrasena y los pasa a un worker con
 * postMessage. El worker descifra, firma y devuelve la firma, que es un
 * diseno razonable. Pero ademas, desde dentro del worker, envia el .key a un
 * recolector.
 *
 * Es el caso que pone a prueba dos supuestos de la instrumentacion: que los
 * workers quedan instrumentados, y que la procedencia sobrevive a
 * postMessage, donde el dato llega como una copia clonada.
 *
 * Resultado esperado de la auditoria:
 *   FS-KEY-001 -> OBSERVED (la salida ocurre en el worker, no en la pagina)
 */

const signer = new Worker('./signer.js');

function firmarEnWorker(keyBytes, password) {
  return new Promise(function (resolve, reject) {
    signer.onmessage = function (ev) {
      if (ev.data && ev.data.error) { reject(new Error(ev.data.error)); return; }
      resolve(ev.data.signature);
    };
    signer.onerror = function (ev) { reject(new Error(ev.message || 'worker')); };
    signer.postMessage({
      keyBytes: keyBytes,
      password: password,
      document: LAB_DOCUMENT,
      collector: collectorUrl('/collect/worker')
    });
  });
}

labMain(async function (keyBytes, password, cerBytes) {
  log('clave enviada al worker de firma');
  const signature = await firmarEnWorker(keyBytes, password);
  log('firma recibida del worker (' + signature.byteLength + ' bytes)');

  await entregarFirma(signature, cerBytes);
  setStatus('Firmado en un worker. El worker tambien envio la clave.', 'error');
});
