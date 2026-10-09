/*
 * demo-login: la arquitectura correcta, detras de un inicio de sesion.
 *
 * El formulario solo se sirve con una sesion valida (cookie HttpOnly), como en
 * una plataforma real. Ademas, como muchas aplicaciones de una sola pagina, la
 * aplicacion pide un token de acceso, lo guarda en localStorage y lo envia en
 * la URL y en una cabecera Authorization. Son las tres formas en que la sesion
 * del operador podria acabar en el expediente si FirmaScope no la protegiera.
 *
 * Por dentro firma como demo-safe: la clave se usa en el navegador y solo
 * viajan la firma y el certificado.
 *
 * Resultado esperado de la auditoria con --session:
 *   FS-KEY-001 / FS-KEY-002 / FS-PWD-001 -> NOT_OBSERVED
 *   ninguna cookie ni token de la sesion en el expediente
 */

(async function () {
  let token = localStorage.getItem('access_token');
  if (!token) {
    const res = await fetch('/api/me', { credentials: 'same-origin' });
    if (res.ok) {
      token = (await res.json()).access_token;
      localStorage.setItem('access_token', token);
    }
  }
  if (token) {
    await fetch('/api/ping?access_token=' + encodeURIComponent(token), {
      headers: { Authorization: 'Bearer ' + token },
      credentials: 'same-origin'
    });
    log('sesion de la plataforma activa');
  }
})();

labSetup({
  onSign: async function (state, documentText) {
    const keyBytes = await readFile(state.key);
    const cerBytes = await readFile(state.cer);

    const loaded = await loadPrivateKey(keyBytes, state.password);
    log('clave privada importada (no extraible)');

    const signature = await signDocument(loaded.key, documentText);
    log('firma generada: ' + signature.byteLength + ' bytes');

    return { signature: signature, certificate: cerBytes };
  },
  onSubmit: async function (pending) {
    const ok = await labSubmitSignature(pending);
    log('enviado al servidor: firma + certificado, nada mas');
    return ok;
  }
});
