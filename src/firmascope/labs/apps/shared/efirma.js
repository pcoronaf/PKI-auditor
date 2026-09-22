/*
 * Biblioteca comun de las aplicaciones de laboratorio de FirmaScope.
 *
 * Implementa el flujo real de una e.firma en el navegador:
 *   .key (PKCS#8 cifrado, PBES2) + contrasena -> PKCS#8 en claro
 *   -> CryptoKey privada -> sign(documento) -> firma
 *
 * NO es codigo de produccion: existe para ejercitar la instrumentacion.
 */

/* ---------------- DER minimo ---------------- */
function derParse(bytes, offset) {
  offset = offset || 0;
  const tag = bytes[offset];
  let pos = offset + 1;
  let length = bytes[pos++];
  if (length & 0x80) {
    const count = length & 0x7f;
    length = 0;
    for (let i = 0; i < count; i++) { length = (length << 8) | bytes[pos++]; }
  }
  const node = { tag: tag, start: offset, headerEnd: pos, length: length, end: pos + length, children: [] };
  const constructed = (tag & 0x20) !== 0;
  if (constructed) {
    let cursor = pos;
    while (cursor < node.end) {
      const child = derParse(bytes, cursor);
      node.children.push(child);
      cursor = child.end;
    }
  } else {
    node.value = bytes.slice(pos, node.end);
  }
  return node;
}

function oidToString(bytes) {
  const parts = [Math.floor(bytes[0] / 40), bytes[0] % 40];
  let value = 0;
  for (let i = 1; i < bytes.length; i++) {
    value = (value << 7) | (bytes[i] & 0x7f);
    if (!(bytes[i] & 0x80)) { parts.push(value); value = 0; }
  }
  return parts.join('.');
}

function intOf(bytes) {
  let value = 0;
  for (let i = 0; i < bytes.length; i++) { value = (value << 8) | bytes[i]; }
  return value;
}

const PRF_BY_OID = {
  '1.2.840.113549.2.7': 'SHA-1',
  '1.2.840.113549.2.9': 'SHA-256',
  '1.2.840.113549.2.11': 'SHA-512'
};
const CIPHER_BY_OID = {
  '2.16.840.1.101.3.4.1.2': { name: 'AES-CBC', length: 128 },
  '2.16.840.1.101.3.4.1.42': { name: 'AES-CBC', length: 256 }
};

/* Descifra un PKCS#8 cifrado (PBES2 + PBKDF2 + AES-CBC). */
async function decryptPkcs8(keyBytes, password) {
  const root = derParse(new Uint8Array(keyBytes));
  const algorithm = root.children[0];
  const params = algorithm.children[1];
  const kdf = params.children[0];
  const kdfParams = kdf.children[1];
  const salt = kdfParams.children[0].value;
  const iterations = intOf(kdfParams.children[1].value);
  let prf = 'SHA-1';
  for (const child of kdfParams.children) {
    if (child.tag === 0x30 && child.children.length && child.children[0].tag === 0x06) {
      prf = PRF_BY_OID[oidToString(child.children[0].value)] || prf;
    }
  }
  const scheme = params.children[1];
  const cipher = CIPHER_BY_OID[oidToString(scheme.children[0].value)] || { name: 'AES-CBC', length: 256 };
  const iv = scheme.children[1].value;
  const ciphertext = root.children[1].value;

  const material = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt, iterations: iterations, hash: prf },
    material, { name: cipher.name, length: cipher.length }, false, ['decrypt']);
  return crypto.subtle.decrypt({ name: cipher.name, iv: iv }, aesKey, ciphertext);
}

/* Carga un .key y devuelve la CryptoKey privada lista para firmar. */
async function loadPrivateKey(keyBytes, password) {
  const pkcs8 = await decryptPkcs8(keyBytes, password);
  const key = await crypto.subtle.importKey(
    'pkcs8', pkcs8, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  return { key: key, pkcs8: pkcs8 };
}

async function signDocument(privateKey, text) {
  const data = new TextEncoder().encode(text);
  return crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, data);
}

function readFile(file) {
  return new Promise(function (resolve, reject) {
    const reader = new FileReader();
    reader.onload = function () { resolve(reader.result); };
    reader.onerror = function () { reject(reader.error); };
    reader.readAsArrayBuffer(file);
  });
}

function toBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) { binary += String.fromCharCode(bytes[i]); }
  return btoa(binary);
}

function fromBase64(text) {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) { bytes[i] = binary.charCodeAt(i); }
  return bytes;
}

function setStatus(text, state) {
  const el = document.getElementById('status');
  if (el) { el.textContent = text; el.dataset.state = state || 'info'; }
}

function log(line) {
  const el = document.getElementById('log');
  if (el) { el.textContent += line + '\n'; }
}
