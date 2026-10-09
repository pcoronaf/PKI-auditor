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

/* ------------------------------------------------------------------ */
/* 3DES (DES-EDE3-CBC), el cifrado de las llaves del SAT.               */
/*                                                                      */
/* WebCrypto no ofrece 3DES: cualquier portal real que descifre la llave */
/* en el navegador lo hace con JavaScript (jsrsasign, forge o codigo     */
/* propio). Los laboratorios hacen lo mismo, porque la credencial        */
/* sintetica tiene el formato del SAT: en el primer piloto, una llave en */
/* AES hizo fallar la biblioteca del portal antes de llegar a firmar.    */
/* Implementacion directa de FIPS 46-3, solo para descifrar; material de */
/* laboratorio, no rapido ni resistente a canales laterales.             */
/* ------------------------------------------------------------------ */
const DES_TABLES = (function () {
  const PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61,
    53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4];
  const PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20,
    13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36,
    29, 32];
  const SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
  const IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22,
    14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11,
    3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7];
  const FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22,
    62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19,
    59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25];
  const E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16,
    17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1];
  const P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3,
    9, 19, 13, 30, 6, 22, 11, 4, 25];
  const S = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11,
      9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5,
      11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10,
      6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2,
      11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14,
      12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7,
      4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12,
      1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8,
      9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10,
      3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13,
      6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14,
      0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10,
      11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12,
      2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7,
      9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11,
      0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13,
      15, 12, 9, 0, 3, 5, 6, 11]
  ];
  return { PC1: PC1, PC2: PC2, SHIFTS: SHIFTS, IP: IP, FP: FP, E: E, P: P, S: S };
})();

/* Bits como arrays de 0/1: lento, pero imposible de equivocar al leerlo. */
function desBits(bytes) {
  const out = [];
  for (let i = 0; i < bytes.length; i++) {
    for (let b = 7; b >= 0; b--) { out.push((bytes[i] >> b) & 1); }
  }
  return out;
}

function desBytes(bits) {
  const out = new Uint8Array(bits.length / 8);
  for (let i = 0; i < out.length; i++) {
    let v = 0;
    for (let b = 0; b < 8; b++) { v = (v << 1) | bits[i * 8 + b]; }
    out[i] = v;
  }
  return out;
}

function desPermute(bits, table) { return table.map(function (p) { return bits[p - 1]; }); }

function desSubkeys(key8) {
  const T = DES_TABLES;
  const k = desPermute(desBits(key8), T.PC1);
  let c = k.slice(0, 28);
  let d = k.slice(28);
  const keys = [];
  for (let r = 0; r < 16; r++) {
    for (let s = 0; s < T.SHIFTS[r]; s++) { c.push(c.shift()); d.push(d.shift()); }
    keys.push(desPermute(c.concat(d), T.PC2));
  }
  return keys;
}

function desFeistel(right, subkey) {
  const T = DES_TABLES;
  const x = desPermute(right, T.E).map(function (bit, i) { return bit ^ subkey[i]; });
  const out = [];
  for (let s = 0; s < 8; s++) {
    const six = x.slice(s * 6, s * 6 + 6);
    const row = (six[0] << 1) | six[5];
    const col = (six[1] << 3) | (six[2] << 2) | (six[3] << 1) | six[4];
    const v = T.S[s][row * 16 + col];
    out.push((v >> 3) & 1, (v >> 2) & 1, (v >> 1) & 1, v & 1);
  }
  return desPermute(out, T.P);
}

function desBlock(block8, subkeys, decrypt) {
  const T = DES_TABLES;
  const bits = desPermute(desBits(block8), T.IP);
  let left = bits.slice(0, 32);
  let right = bits.slice(32);
  for (let r = 0; r < 16; r++) {
    const key = subkeys[decrypt ? 15 - r : r];
    const f = desFeistel(right, key);
    const next = left.map(function (bit, i) { return bit ^ f[i]; });
    left = right;
    right = next;
  }
  return desBytes(desPermute(right.concat(left), T.FP));
}

/* Descifra DES-EDE3-CBC y quita el relleno PKCS#7. */
function desEde3CbcDecrypt(key24, iv8, data) {
  const k1 = desSubkeys(key24.slice(0, 8));
  const k2 = desSubkeys(key24.slice(8, 16));
  const k3 = desSubkeys(key24.slice(16, 24));
  const out = new Uint8Array(data.length);
  let prev = iv8;
  for (let off = 0; off < data.length; off += 8) {
    const block = data.slice(off, off + 8);
    // EDE: descifrar es D(k1, E(k2, D(k3, x))).
    const plain = desBlock(desBlock(desBlock(block, k3, true), k2, false), k1, true);
    for (let i = 0; i < 8; i++) { out[off + i] = plain[i] ^ prev[i]; }
    prev = block;
  }
  const pad = out[out.length - 1];
  if (pad < 1 || pad > 8) { throw new Error('contrasena incorrecta o llave danada'); }
  for (let i = out.length - pad; i < out.length; i++) {
    if (out[i] !== pad) { throw new Error('contrasena incorrecta o llave danada'); }
  }
  return out.slice(0, out.length - pad);
}


const OID_DES_EDE3_CBC = '1.2.840.113549.3.7';

/* Descifra un PKCS#8 cifrado: PBES2 + PBKDF2 + AES-CBC (WebCrypto) o 3DES (SAT). */
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
  const schemeOid = oidToString(scheme.children[0].value);
  const iv = scheme.children[1].value;
  const ciphertext = root.children[1].value;

  if (schemeOid === OID_DES_EDE3_CBC) {
    const bitsMaterial = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    const derived = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: salt, iterations: iterations, hash: prf }, bitsMaterial, 192);
    return desEde3CbcDecrypt(new Uint8Array(derived), iv, ciphertext).buffer;
  }

  const cipher = CIPHER_BY_OID[schemeOid] || { name: 'AES-CBC', length: 256 };
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
