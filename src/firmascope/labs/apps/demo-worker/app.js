/*
 * demo-worker: la clave cruza a un Web Worker.
 *
 * La pagina pasa el .key y la contrasena a un worker con postMessage. El worker
 * descifra, firma y devuelve la firma -- un diseno razonable -- pero ademas,
 * desde dentro, envia el .key a un recolector.
 *
 * Pone a prueba dos supuestos: que los workers quedan instrumentados *sin
 * romperse* (el worker usa importScripts con una ruta relativa, que fallaba
 * cuando el agente lo cargaba desde un blob:), y que la procedencia sobrevive
 * a postMessage, donde el dato llega como una copia. Del PR #2.
 *
 * Resultado esperado:
 *   la firma se genera (el sitio no se rompe)
 *   FS-KEY-001 -> OBSERVED (la salida ocurre en el worker, no en la pagina)
 */

const signer = new Worker('./signer.js');

function firmarEnWorker(keyBytes, password, documentText) {
  return new Promise(function (resolve, reject) {
    signer.onmessage = function (ev) {
      if (ev.data && ev.data.error) { reject(new Error(ev.data.error)); return; }
      resolve(ev.data.signature);
    };
    signer.onerror = function (ev) { reject(new Error(ev.message || 'worker')); };
    signer.postMessage({ keyBytes: keyBytes, password: password, document: documentText });
  });
}

labSetup({
  onSign: async function (state, documentText) {
    const keyBytes = await readFile(state.key);
    const cerBytes = await readFile(state.cer);
    const signature = await firmarEnWorker(keyBytes, state.password, documentText);
    log('firma generada en el worker: ' + signature.byteLength + ' bytes');
    return { signature: signature, certificate: cerBytes };
  },
  onSubmit: labSubmitSignature
});
