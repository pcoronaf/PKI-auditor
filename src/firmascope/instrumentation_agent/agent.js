/*
 * FirmaScope - Instrumentation Agent
 * ----------------------------------
 * Se inyecta ANTES del JavaScript de la aplicacion auditada, en cada contexto
 * de ejecucion (documento principal, iframes, dedicated/shared workers).
 *
 * Su funcion es OBSERVAR operaciones, no almacenar secretos: los eventos que
 * produce contienen tipos, tamanos, algoritmos y etiquetas de procedencia,
 * nunca el contenido de la clave privada ni de la contrasena.
 *
 * El seguimiento de procedencia (taint) vive exclusivamente en la memoria de
 * la pagina y desaparece cuando el contexto se destruye.
 *
 * Marcadores sustituidos por el loader de Python:
 *   __FIRMASCOPE_CONFIG__   objeto de configuracion
 *   __FS_AGENT_SRC__        fuente del propio agente (para instrumentar workers)
 */
(function () {
  'use strict';

  var G = typeof globalThis !== 'undefined' ? globalThis : self;
  if (G.__FIRMASCOPE__) { return; }

  var CFG = G.__FIRMASCOPE_CONFIG__ || {};
  var SESSION = CFG.session || 'FS-UNKNOWN';
  var CHANNEL = CFG.channel || '__firmascope_report';
  var MAX_QUEUE = CFG.maxQueue || 5000;
  var MAX_TAINTED_STRINGS = 64;

  /* ---------------------------------------------------------------- */
  /* Referencias originales (capturadas antes de que el sitio las toque) */
  /* ---------------------------------------------------------------- */
  var O = {
    defineProperty: Object.defineProperty,
    getOwnPropertyDescriptor: Object.getOwnPropertyDescriptor,
    keys: Object.keys,
    stringify: JSON.stringify,
    now: (typeof performance !== 'undefined' && performance.now)
      ? performance.now.bind(performance) : function () { return Date.now(); },
    dateNow: Date.now,
    apply: Function.prototype.apply,
    subtle: (G.crypto && G.crypto.subtle) || null,
    fetch: G.fetch,
    Blob: G.Blob,
    FileReader: G.FileReader,
    URL: G.URL,
    TextDecoder: G.TextDecoder,
    btoa: G.btoa,
    atob: G.atob
  };
  var nativeDigest = O.subtle && O.subtle.digest ? O.subtle.digest.bind(O.subtle) : null;

  /* ---------------------------------------------------------------- */
  /* Identificacion del contexto                                       */
  /* ---------------------------------------------------------------- */
  var IS_WINDOW = typeof window !== 'undefined' && typeof document !== 'undefined';
  var IS_WORKER = !IS_WINDOW && typeof WorkerGlobalScope !== 'undefined'
    && typeof self !== 'undefined' && self instanceof WorkerGlobalScope;
  var IS_SERVICE_WORKER = IS_WORKER && typeof ServiceWorkerGlobalScope !== 'undefined'
    && self instanceof ServiceWorkerGlobalScope;
  var IS_SHARED_WORKER = IS_WORKER && typeof SharedWorkerGlobalScope !== 'undefined'
    && self instanceof SharedWorkerGlobalScope;

  var CONTEXT = CFG.context
    || (IS_SERVICE_WORKER ? 'service-worker'
      : IS_SHARED_WORKER ? 'shared-worker'
        : IS_WORKER ? 'worker'
          : (IS_WINDOW && window.top !== window.self) ? 'iframe' : 'main');

  function originOf() {
    try { return (G.location && G.location.origin) || ''; } catch (e) { return ''; }
  }
  function hrefOf() {
    try { return (G.location && G.location.href) || ''; } catch (e) { return ''; }
  }

  /* ---------------------------------------------------------------- */
  /* Transporte de eventos                                             */
  /* ---------------------------------------------------------------- */
  var queue = [];
  var relayPort = null;      // puerto de un SharedWorker, si aplica
  var dropped = 0;

  function push(record) {
    if (queue.length >= MAX_QUEUE) { dropped++; return; }
    queue.push(record);
    flush();
  }

  function flush() {
    if (!queue.length) { return; }
    var sink = null;
    if (typeof G[CHANNEL] === 'function') {
      sink = function (rec) { try { G[CHANNEL](O.stringify(rec)); } catch (e) { /* ignorado */ } };
    } else if (IS_WORKER && !IS_SHARED_WORKER && !IS_SERVICE_WORKER && typeof self.postMessage === 'function') {
      sink = function (rec) { try { self.postMessage({ __firmascope__: rec }); } catch (e) { /* ignorado */ } };
    } else if (relayPort) {
      sink = function (rec) { try { relayPort.postMessage({ __firmascope__: rec }); } catch (e) { /* ignorado */ } };
    }
    if (!sink) { return; }   // se quedara en la cola hasta que Python la drene
    var pending = queue;
    queue = [];
    for (var i = 0; i < pending.length; i++) { sink(pending[i]); }
  }

  function emit(type, data, tags, source) {
    push({
      t: type,
      ts: O.dateNow() / 1000,
      ctx: CONTEXT,
      origin: originOf(),
      href: hrefOf(),
      src: source || callsite(),
      tags: tags || [],
      data: data || {}
    });
  }

  /* Ubicacion en codigo del llamante, saltando los frames del propio agente. */
  function callsite() {
    try {
      var stack = new Error().stack;
      if (!stack) { return ''; }
      var lines = stack.split('\n');
      for (var i = 1; i < lines.length; i++) {
        var line = lines[i];
        if (line.indexOf('firmascope') !== -1 || line.indexOf('__FS') !== -1) { continue; }
        var m = line.match(/((?:https?|blob|file|data):[^\s)]+|<anonymous>):(\d+):(\d+)/);
        if (m) {
          var url = m[1];
          var short = url.length > 120 ? url.slice(0, 60) + '...' + url.slice(-40) : url;
          var tail = short.split('/').pop() || short;
          return tail + ':' + m[2];
        }
      }
    } catch (e) { /* ignorado */ }
    return '';
  }

  function stackFrames(limit) {
    try {
      return (new Error().stack || '').split('\n').slice(2, 2 + (limit || 6))
        .map(function (l) { return l.trim().slice(0, 240); });
    } catch (e) { return []; }
  }

  /* ---------------------------------------------------------------- */
  /* Registro de procedencia (taint)                                   */
  /* ---------------------------------------------------------------- */
  var LBL = {
    KEY_FILE: 'KEY_FILE',
    KEY_PASSWORD: 'KEY_PASSWORD',
    PRIVATE_KEY: 'PRIVATE_KEY',
    CERTIFICATE: 'CERTIFICATE',
    DOCUMENT: 'DOCUMENT',
    SIGNATURE: 'SIGNATURE',
    DERIVED: 'DERIVED'
  };
  var PRIVATE = [LBL.KEY_FILE, LBL.KEY_PASSWORD, LBL.PRIVATE_KEY];

  var objTaint = new WeakMap();
  var strTaint = [];   // [{ value, labels }] - memoria de pagina, nunca se emite

  function uniq(list) {
    var out = [];
    for (var i = 0; i < list.length; i++) {
      if (list[i] && out.indexOf(list[i]) === -1) { out.push(list[i]); }
    }
    return out;
  }

  function derive(labels) {
    if (!labels || !labels.length) { return []; }
    return uniq(labels.concat([LBL.DERIVED]));
  }

  function isPrivate(labels) {
    for (var i = 0; i < (labels || []).length; i++) {
      if (PRIVATE.indexOf(labels[i]) !== -1) { return true; }
    }
    return false;
  }

  function taint(value, labels) {
    if (!labels || !labels.length || value === null || value === undefined) { return value; }
    labels = uniq(labels);
    try {
      if (typeof value === 'string') {
        if (value.length >= 4 && value.length <= 8192) {
          for (var i = 0; i < strTaint.length; i++) {
            if (strTaint[i].value === value) {
              strTaint[i].labels = uniq(strTaint[i].labels.concat(labels));
              return value;
            }
          }
          strTaint.push({ value: value, labels: labels });
          if (strTaint.length > MAX_TAINTED_STRINGS) { strTaint.shift(); }
        }
        return value;
      }
      if (typeof value === 'object' || typeof value === 'function') {
        var prev = objTaint.get(value) || [];
        objTaint.set(value, uniq(prev.concat(labels)));
        // Vistas tipadas y su ArrayBuffer comparten procedencia.
        if (ArrayBuffer.isView(value) && value.buffer) {
          var pb = objTaint.get(value.buffer) || [];
          objTaint.set(value.buffer, uniq(pb.concat(labels)));
        }
      }
    } catch (e) { /* objetos no extensibles */ }
    return value;
  }

  function labelsOf(value, depth) {
    depth = depth || 0;
    if (value === null || value === undefined || depth > 3) { return []; }
    var out = [];
    try {
      if (typeof value === 'string') {
        for (var i = 0; i < strTaint.length; i++) {
          var entry = strTaint[i];
          if (value === entry.value || (entry.value.length >= 6 && value.indexOf(entry.value) !== -1)) {
            out = out.concat(entry.labels);
          }
        }
        return uniq(out);
      }
      if (typeof value !== 'object' && typeof value !== 'function') { return []; }

      var direct = objTaint.get(value);
      if (direct) { out = out.concat(direct); }

      if (ArrayBuffer.isView(value) && value.buffer) {
        var bufLabels = objTaint.get(value.buffer);
        if (bufLabels) { out = out.concat(bufLabels); }
      }
      if (G.URLSearchParams && value instanceof G.URLSearchParams) {
        value.forEach(function (v, k) { out = out.concat(labelsOf(v, depth + 1)); out = out.concat(labelsOf(k, depth + 1)); });
      } else if (G.FormData && value instanceof G.FormData) {
        var it = value.entries();
        for (var e = it.next(); !e.done; e = it.next()) {
          out = out.concat(labelsOf(e.value[0], depth + 1));
          out = out.concat(labelsOf(e.value[1], depth + 1));
        }
      } else if (Array.isArray(value)) {
        for (var a = 0; a < Math.min(value.length, 50); a++) { out = out.concat(labelsOf(value[a], depth + 1)); }
      } else if (!(value instanceof ArrayBuffer) && !ArrayBuffer.isView(value)
        && !(G.Blob && value instanceof G.Blob) && !(G.CryptoKey && value instanceof G.CryptoKey)) {
        var keys = O.keys(value);
        for (var k = 0; k < Math.min(keys.length, 50); k++) {
          out = out.concat(labelsOf(value[keys[k]], depth + 1));
        }
      }
    } catch (e) { /* ignorado */ }
    return uniq(out);
  }

  /* ---------------------------------------------------------------- */
  /* Utilidades de medida                                              */
  /* ---------------------------------------------------------------- */
  function byteLength(value) {
    try {
      if (value === null || value === undefined) { return 0; }
      if (typeof value === 'string') { return value.length; }
      if (value instanceof ArrayBuffer) { return value.byteLength; }
      if (ArrayBuffer.isView(value)) { return value.byteLength; }
      if (G.Blob && value instanceof G.Blob) { return value.size; }
      if (G.URLSearchParams && value instanceof G.URLSearchParams) { return value.toString().length; }
      if (G.FormData && value instanceof G.FormData) {
        var total = 0;
        var it = value.entries();
        for (var e = it.next(); !e.done; e = it.next()) { total += byteLength(e.value[1]) + String(e.value[0]).length; }
        return total;
      }
      if (typeof value === 'object') { return O.stringify(value).length; }
    } catch (err) { /* ignorado */ }
    return 0;
  }

  function describe(value) {
    if (value === null || value === undefined) { return 'none'; }
    if (typeof value === 'string') { return 'string'; }
    if (value instanceof ArrayBuffer) { return 'ArrayBuffer'; }
    if (ArrayBuffer.isView(value)) { return value.constructor ? value.constructor.name : 'TypedArray'; }
    if (G.Blob && value instanceof G.Blob) { return 'Blob'; }
    if (G.FormData && value instanceof G.FormData) { return 'FormData'; }
    if (G.URLSearchParams && value instanceof G.URLSearchParams) { return 'URLSearchParams'; }
    if (G.ReadableStream && value instanceof G.ReadableStream) { return 'ReadableStream'; }
    return typeof value;
  }

  /* Digest SHA-256 asincrono usando la implementacion nativa capturada. */
  function digestOf(value, callback) {
    if (!nativeDigest) { callback(''); return; }
    try {
      var buf = null;
      if (value instanceof ArrayBuffer) { buf = value; }
      else if (ArrayBuffer.isView(value)) { buf = value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength); }
      else if (typeof value === 'string') { buf = new TextEncoder().encode(value).buffer; }
      if (!buf || buf.byteLength === 0 || buf.byteLength > 8 * 1024 * 1024) { callback(''); return; }
      nativeDigest('SHA-256', buf).then(function (out) {
        var bytes = new Uint8Array(out);
        var hex = '';
        for (var i = 0; i < bytes.length; i++) { hex += ('0' + bytes[i].toString(16)).slice(-2); }
        callback(hex);
      }, function () { callback(''); });
    } catch (e) { callback(''); }
  }

  function absolute(url) {
    try { return new O.URL(String(url), hrefOf()).href; } catch (e) { return String(url); }
  }

  function hostOf(url) {
    try { return new O.URL(absolute(url)).host; } catch (e) { return ''; }
  }

  /* ---------------------------------------------------------------- */
  /* Clasificacion de material sensible por nombre / contenido         */
  /* ---------------------------------------------------------------- */
  function labelForFile(file) {
    var name = (file && file.name ? String(file.name) : '').toLowerCase();
    if (/\.key$/.test(name) || /\bkey\b/.test(name) && !/\.cer$/.test(name)) { return LBL.KEY_FILE; }
    if (/\.(cer|crt|cert|der)$/.test(name)) { return LBL.CERTIFICATE; }
    if (/\.(pem|p12|pfx|p8)$/.test(name)) { return LBL.KEY_FILE; }
    return LBL.DOCUMENT;
  }

  /* ---------------------------------------------------------------- */
  /* Envoltura generica                                                */
  /* ---------------------------------------------------------------- */
  function wrap(target, name, factory) {
    if (!target) { return false; }
    var original = target[name];
    if (typeof original !== 'function') { return false; }
    var replacement = factory(original);
    try {
      O.defineProperty(replacement, 'name', { value: name, configurable: true });
      O.defineProperty(replacement, 'length', { value: original.length, configurable: true });
      replacement.toString = function () { return original.toString(); };
      target[name] = replacement;
      return true;
    } catch (e) { return false; }
  }

  var failures = [];
  function guard(label, fn) {
    try { fn(); } catch (e) { failures.push(label + ': ' + (e && e.message)); }
  }

  /* ================================================================ */
  /* SOURCES: archivos                                                 */
  /* ================================================================ */
  guard('file-input', function () {
    if (!IS_WINDOW) { return; }
    var seen = new WeakSet();
    var onChange = function (ev) {
      var el = ev.target;
      if (!el || el.tagName !== 'INPUT' || el.type !== 'file' || !el.files) { return; }
      for (var i = 0; i < el.files.length; i++) {
        (function (file) {
          if (seen.has(file)) { return; }
          seen.add(file);
          var label = labelForFile(file);
          taint(file, [label]);
          var record = {
            name: String(file.name).slice(0, 120),
            size: file.size,
            mime: file.type || '',
            accept: el.accept || '',
            input_id: el.id || el.name || ''
          };
          if (file.slice && file.size <= 4 * 1024 * 1024) {
            file.arrayBuffer().then(function (buf) {
              taint(buf, [label]);
              digestOf(buf, function (hex) {
                record.sha256 = hex;
                emit('FILE_SELECTED', record, [label]);
              });
            }, function () { emit('FILE_SELECTED', record, [label]); });
          } else {
            emit('FILE_SELECTED', record, [label]);
          }
        })(el.files[i]);
      }
    };
    document.addEventListener('change', onChange, true);
    document.addEventListener('drop', function (ev) {
      try {
        var dt = ev.dataTransfer;
        if (dt && dt.files) {
          for (var i = 0; i < dt.files.length; i++) {
            var f = dt.files[i];
            var label = labelForFile(f);
            taint(f, [label]);
            emit('FILE_SELECTED', { name: String(f.name).slice(0, 120), size: f.size, via: 'drop' }, [label]);
          }
        }
      } catch (e) { /* ignorado */ }
    }, true);
  });

  guard('FileReader', function () {
    if (!G.FileReader) { return; }
    var methods = ['readAsArrayBuffer', 'readAsText', 'readAsDataURL', 'readAsBinaryString'];
    methods.forEach(function (method) {
      wrap(G.FileReader.prototype, method, function (original) {
        return function (blob) {
          var self_ = this;
          var labels = labelsOf(blob);
          if (!labels.length && blob && blob.name) { labels = [labelForFile(blob)]; }
          var source = callsite();
          emit('FILE_READ', {
            method: method,
            size: blob && blob.size ? blob.size : 0,
            mime: (blob && blob.type) || '',
            name: (blob && blob.name) ? String(blob.name).slice(0, 120) : ''
          }, labels, source);
          try {
            self_.addEventListener('loadend', function () {
              try { taint(self_.result, labels); } catch (e) { /* ignorado */ }
            }, { once: true, capture: true });
          } catch (e) { /* ignorado */ }
          return original.apply(this, arguments);
        };
      });
    });
  });

  guard('Blob', function () {
    if (!G.Blob) { return; }
    ['arrayBuffer', 'text'].forEach(function (method) {
      wrap(G.Blob.prototype, method, function (original) {
        return function () {
          var labels = labelsOf(this);
          if (!labels.length && this.name) { labels = [labelForFile(this)]; }
          if (labels.length) {
            emit('FILE_READ', { method: 'Blob.' + method, size: this.size, mime: this.type || '' }, labels);
          }
          return original.apply(this, arguments).then(function (result) {
            return taint(result, labels);
          });
        };
      });
    });
    // Un Blob construido a partir de material etiquetado hereda la procedencia.
    var NativeBlob = G.Blob;
    function FSBlob(parts, options) {
      var instance = new NativeBlob(parts || [], options);
      var labels = labelsOf(parts);
      if (labels.length) { taint(instance, derive(labels)); }
      return instance;
    }
    FSBlob.prototype = NativeBlob.prototype;
    try { G.Blob = FSBlob; } catch (e) { /* ignorado */ }
  });

  /* ================================================================ */
  /* SOURCES: contrasena                                               */
  /* ================================================================ */
  guard('password', function () {
    if (!IS_WINDOW || !G.HTMLInputElement) { return; }
    var descriptor = O.getOwnPropertyDescriptor(G.HTMLInputElement.prototype, 'value');
    if (!descriptor || !descriptor.get) { return; }
    var lastEmit = 0;
    O.defineProperty(G.HTMLInputElement.prototype, 'value', {
      configurable: true,
      enumerable: descriptor.enumerable,
      get: function () {
        var value = descriptor.get.call(this);
        try {
          if (this.type === 'password' && typeof value === 'string' && value.length) {
            taint(value, [LBL.KEY_PASSWORD]);
            var now = O.dateNow();
            if (now - lastEmit > 250) {
              lastEmit = now;
              emit('PASSWORD_READ', {
                length: value.length,
                input_id: this.id || this.name || '',
                autocomplete: this.autocomplete || ''
              }, [LBL.KEY_PASSWORD]);
            }
          }
        } catch (e) { /* ignorado */ }
        return value;
      },
      set: function (v) { return descriptor.set.call(this, v); }
    });
  });

  /* ================================================================ */
  /* WebCrypto                                                         */
  /* ================================================================ */
  guard('webcrypto', function () {
    if (!O.subtle) { return; }
    var subtle = O.subtle;

    function algName(algorithm) {
      if (!algorithm) { return ''; }
      if (typeof algorithm === 'string') { return algorithm; }
      return String(algorithm.name || '');
    }

    function keyInfo(key) {
      if (!key) { return {}; }
      if (G.CryptoKey && key instanceof G.CryptoKey) {
        return {
          key_type: key.type || '',
          extractable: !!key.extractable,
          usages: (key.usages || []).slice(0, 8),
          key_algorithm: key.algorithm ? String(key.algorithm.name || '') : ''
        };
      }
      return { key_type: 'raw-material' };
    }

    function labelForKey(key, inputLabels) {
      var labels = labelsOf(key).concat(inputLabels || []);
      if (G.CryptoKey && key instanceof G.CryptoKey && key.type === 'private') {
        labels = labels.concat([LBL.PRIVATE_KEY]);
      }
      if (G.CryptoKey && key instanceof G.CryptoKey && key.type === 'public') {
        labels = labels.concat([LBL.CERTIFICATE]);
      }
      return uniq(labels);
    }

    wrap(subtle, 'importKey', function (original) {
      return function (format, keyData, algorithm, extractable, usages) {
        var labels = labelsOf(keyData);
        var source = callsite();
        var promise = original.apply(this, arguments);
        return promise.then(function (key) {
          var outLabels = labelForKey(key, labels);
          taint(key, outLabels);
          emit('CRYPTO_IMPORT', {
            format: String(format),
            algorithm: algName(algorithm),
            extractable: !!extractable,
            usages: (usages || []).slice(0, 8),
            input_bytes: byteLength(keyData),
            key_type: key && key.type ? key.type : ''
          }, outLabels, source);
          return key;
        }, function (err) {
          emit('CRYPTO_IMPORT', { format: String(format), algorithm: algName(algorithm), error: String(err && err.name) },
            labels, source);
          throw err;
        });
      };
    });

    [['decrypt', 'CRYPTO_DECRYPT'], ['encrypt', 'CRYPTO_ENCRYPT'], ['sign', 'CRYPTO_SIGN'],
     ['verify', 'CRYPTO_VERIFY'], ['digest', 'CRYPTO_DIGEST']].forEach(function (pair) {
      var method = pair[0], eventType = pair[1];
      wrap(subtle, method, function (original) {
        return function () {
          var args = arguments;
          var source = callsite();
          var algorithm, key, data;
          if (method === 'digest') { algorithm = args[0]; data = args[1]; }
          else if (method === 'verify') { algorithm = args[0]; key = args[1]; data = args[3]; }
          else { algorithm = args[0]; key = args[1]; data = args[2]; }

          var dataLabels = labelsOf(data);
          var keyLabels = key ? labelForKey(key, []) : [];
          var inLabels = uniq(dataLabels.concat(keyLabels));
          var info = keyInfo(key);
          var promise = original.apply(this, args);
          return promise.then(function (result) {
            var outLabels;
            if (method === 'sign') {
              outLabels = uniq([LBL.SIGNATURE].concat(derive(inLabels)));
            } else if (method === 'decrypt') {
              // .key cifrado + contrasena -> clave privada en claro
              outLabels = derive(inLabels);
              if (inLabels.indexOf(LBL.KEY_FILE) !== -1) { outLabels = uniq(outLabels.concat([LBL.PRIVATE_KEY])); }
            } else {
              outLabels = derive(inLabels);
            }
            taint(result, outLabels);
            var payload = {
              algorithm: algName(algorithm),
              input_bytes: byteLength(data),
              output_bytes: byteLength(result)
            };
            for (var k in info) { if (Object.prototype.hasOwnProperty.call(info, k)) { payload[k] = info[k]; } }
            emit(eventType, payload, outLabels, source);
            return result;
          }, function (err) {
            emit(eventType, { algorithm: algName(algorithm), error: String(err && err.name) }, inLabels, source);
            throw err;
          });
        };
      });
    });

    wrap(subtle, 'exportKey', function (original) {
      return function (format, key) {
        var source = callsite();
        var labels = labelForKey(key, []);
        var info = keyInfo(key);
        return original.apply(this, arguments).then(function (result) {
          var outLabels = derive(labels);
          taint(result, outLabels);
          emit('CRYPTO_EXPORT', {
            format: String(format),
            output_bytes: byteLength(result),
            key_type: info.key_type || '',
            extractable: info.extractable,
            key_algorithm: info.key_algorithm || ''
          }, outLabels, source);
          return result;
        });
      };
    });

    wrap(subtle, 'wrapKey', function (original) {
      return function (format, key, wrappingKey, algorithm) {
        var source = callsite();
        var labels = labelForKey(key, []);
        return original.apply(this, arguments).then(function (result) {
          var outLabels = derive(labels);
          taint(result, outLabels);
          emit('CRYPTO_WRAP', {
            format: String(format),
            algorithm: algName(algorithm),
            output_bytes: byteLength(result),
            key_type: (key && key.type) || ''
          }, outLabels, source);
          return result;
        });
      };
    });

    wrap(subtle, 'unwrapKey', function (original) {
      return function (format, wrappedKey) {
        var source = callsite();
        var labels = labelsOf(wrappedKey);
        return original.apply(this, arguments).then(function (key) {
          var outLabels = labelForKey(key, derive(labels));
          taint(key, outLabels);
          emit('CRYPTO_UNWRAP', {
            format: String(format),
            key_type: (key && key.type) || '',
            extractable: !!(key && key.extractable)
          }, outLabels, source);
          return key;
        });
      };
    });

    ['deriveKey', 'deriveBits'].forEach(function (method) {
      wrap(subtle, method, function (original) {
        return function (algorithm, base) {
          var source = callsite();
          var labels = labelsOf(base).concat(labelsOf(algorithm));
          return original.apply(this, arguments).then(function (result) {
            var outLabels = derive(labels);
            taint(result, outLabels);
            emit('CRYPTO_DERIVE', {
              method: method, algorithm: algName(algorithm), output_bytes: byteLength(result)
            }, outLabels, source);
            return result;
          });
        };
      });
    });

    wrap(subtle, 'generateKey', function (original) {
      return function (algorithm, extractable, usages) {
        var source = callsite();
        return original.apply(this, arguments).then(function (result) {
          try {
            if (result && result.privateKey) { taint(result.privateKey, [LBL.PRIVATE_KEY]); }
          } catch (e) { /* ignorado */ }
          emit('CRYPTO_GENERATE', {
            algorithm: algName(algorithm), extractable: !!extractable, usages: (usages || []).slice(0, 8)
          }, [], source);
          return result;
        });
      };
    });
  });

  /* Propagacion a traves de codificadores frecuentes. */
  guard('encoders', function () {
    if (G.TextEncoder) {
      wrap(G.TextEncoder.prototype, 'encode', function (original) {
        return function (input) {
          var out = original.apply(this, arguments);
          return taint(out, labelsOf(input));
        };
      });
    }
    if (G.TextDecoder) {
      wrap(G.TextDecoder.prototype, 'decode', function (original) {
        return function (input) {
          var out = original.apply(this, arguments);
          return taint(out, labelsOf(input));
        };
      });
    }
    if (typeof G.btoa === 'function') {
      G.btoa = (function (original) {
        return function (input) { return taint(original.call(G, input), labelsOf(input)); };
      })(G.btoa);
    }
    if (typeof G.atob === 'function') {
      G.atob = (function (original) {
        return function (input) { return taint(original.call(G, input), labelsOf(input)); };
      })(G.atob);
    }
    wrap(JSON, 'stringify', function (original) {
      return function (value) {
        var out = original.apply(this, arguments);
        try { return taint(out, labelsOf(value)); } catch (e) { return out; }
      };
    });
  });

  /* ================================================================ */
  /* SINKS: red                                                        */
  /* ================================================================ */
  function reportEgress(type, info, body, source) {
    var labels = labelsOf(body);
    if (info.url) { labels = uniq(labels.concat(labelsOf(String(info.url)))); }
    var size = byteLength(body);
    var payload = {
      url: info.url ? absolute(info.url) : '',
      host: info.url ? hostOf(info.url) : '',
      method: info.method || '',
      kind: info.kind || '',
      body_type: describe(body),
      body_size: size,
      private_data: isPrivate(labels),
      stack: stackFrames(5)
    };
    if (info.extra) {
      for (var k in info.extra) {
        if (Object.prototype.hasOwnProperty.call(info.extra, k)) { payload[k] = info.extra[k]; }
      }
    }
    if (!labels.length && size > 0) { labels = ['UNCLASSIFIED']; }
    if (body !== null && body !== undefined && size > 0 && size <= 2 * 1024 * 1024) {
      digestOf(body, function (hex) {
        if (hex) { payload.body_digest = hex; }
        emit(type, payload, labels, source);
      });
    } else {
      emit(type, payload, labels, source);
    }
  }

  guard('fetch', function () {
    if (typeof G.fetch !== 'function') { return; }
    var original = G.fetch;
    G.fetch = function (input, init) {
      var source = callsite();
      var url = '', method = 'GET', body = null;
      try {
        if (G.Request && input instanceof G.Request) {
          url = input.url; method = input.method;
          body = (init && init.body !== undefined) ? init.body : null;
        } else {
          url = String(input);
          method = (init && init.method) || 'GET';
          body = init ? init.body : null;
        }
      } catch (e) { /* ignorado */ }
      reportEgress('NETWORK_REQUEST', { url: url, method: method, kind: 'fetch' }, body, source);
      return original.apply(this, arguments);
    };
    try { G.fetch.toString = function () { return original.toString(); }; } catch (e) { /* ignorado */ }
  });

  guard('xhr', function () {
    if (!G.XMLHttpRequest) { return; }
    var proto = G.XMLHttpRequest.prototype;
    wrap(proto, 'open', function (original) {
      return function (method, url) {
        try { this.__fs_method = method; this.__fs_url = url; } catch (e) { /* ignorado */ }
        return original.apply(this, arguments);
      };
    });
    wrap(proto, 'send', function (original) {
      return function (body) {
        reportEgress('NETWORK_REQUEST', {
          url: this.__fs_url || '', method: this.__fs_method || 'GET', kind: 'xhr'
        }, body === undefined ? null : body, callsite());
        return original.apply(this, arguments);
      };
    });
  });

  guard('beacon', function () {
    if (!G.navigator || typeof G.navigator.sendBeacon !== 'function') { return; }
    wrap(G.navigator, 'sendBeacon', function (original) {
      return function (url, data) {
        reportEgress('BEACON_SEND', { url: url, method: 'POST', kind: 'beacon' }, data, callsite());
        return original.apply(this, arguments);
      };
    });
  });

  guard('websocket', function () {
    if (!G.WebSocket) { return; }
    var Native = G.WebSocket;
    function FSWebSocket(url, protocols) {
      var instance = protocols === undefined ? new Native(url) : new Native(url, protocols);
      emit('WEBSOCKET_CREATED', { url: absolute(url), host: hostOf(url) }, [], callsite());
      return instance;
    }
    FSWebSocket.prototype = Native.prototype;
    ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED'].forEach(function (k) { FSWebSocket[k] = Native[k]; });
    wrap(Native.prototype, 'send', function (original) {
      return function (data) {
        reportEgress('WEBSOCKET_SEND', { url: this.url, kind: 'websocket' }, data, callsite());
        return original.apply(this, arguments);
      };
    });
    try { G.WebSocket = FSWebSocket; } catch (e) { /* ignorado */ }
  });

  guard('webtransport', function () {
    if (!G.WebTransport) { return; }
    var Native = G.WebTransport;
    function FSWebTransport(url, options) {
      var instance = new Native(url, options);
      emit('WEBTRANSPORT_CREATED', { url: absolute(url), host: hostOf(url) }, [], callsite());
      try {
        var datagrams = instance.datagrams;
        if (datagrams && datagrams.writable) {
          var nativeGetWriter = datagrams.writable.getWriter.bind(datagrams.writable);
          datagrams.writable.getWriter = function () {
            var writer = nativeGetWriter();
            var nativeWrite = writer.write.bind(writer);
            writer.write = function (chunk) {
              reportEgress('WEBTRANSPORT_SEND', { url: url, kind: 'datagram' }, chunk, callsite());
              return nativeWrite(chunk);
            };
            return writer;
          };
        }
      } catch (e) { /* ignorado */ }
      return instance;
    }
    FSWebTransport.prototype = Native.prototype;
    try { G.WebTransport = FSWebTransport; } catch (e) { /* ignorado */ }
  });

  guard('rtc', function () {
    if (!G.RTCDataChannel) { return; }
    wrap(G.RTCDataChannel.prototype, 'send', function (original) {
      return function (data) {
        reportEgress('RTC_SEND', { url: this.label || '', kind: 'rtc-datachannel' }, data, callsite());
        return original.apply(this, arguments);
      };
    });
  });

  guard('form', function () {
    if (!IS_WINDOW || !G.HTMLFormElement) { return; }
    function formPayload(form) {
      try { return new G.FormData(form); } catch (e) { return null; }
    }
    wrap(G.HTMLFormElement.prototype, 'submit', function (original) {
      return function () {
        reportEgress('FORM_SUBMIT', {
          url: this.action || hrefOf(), method: (this.method || 'GET').toUpperCase(), kind: 'form.submit',
          extra: { enctype: this.enctype || '' }
        }, formPayload(this), callsite());
        return original.apply(this, arguments);
      };
    });
    document.addEventListener('submit', function (ev) {
      var form = ev.target;
      if (!form || form.tagName !== 'FORM') { return; }
      reportEgress('FORM_SUBMIT', {
        url: form.action || hrefOf(), method: (form.method || 'GET').toUpperCase(), kind: 'submit-event',
        extra: { enctype: form.enctype || '' }
      }, formPayload(form), callsite());
    }, true);
  });

  /* URLs y navegaciones capaces de sacar datos por la barra de direcciones. */
  guard('url-sinks', function () {
    if (!IS_WINDOW) { return; }
    [['HTMLImageElement', 'src', 'image.src'], ['HTMLScriptElement', 'src', 'script.src'],
     ['HTMLIFrameElement', 'src', 'iframe.src'], ['HTMLAnchorElement', 'href', 'anchor.href'],
     ['HTMLLinkElement', 'href', 'link.href']].forEach(function (entry) {
      var ctor = G[entry[0]];
      if (!ctor) { return; }
      var descriptor = O.getOwnPropertyDescriptor(ctor.prototype, entry[1]);
      if (!descriptor || !descriptor.set) { return; }
      O.defineProperty(ctor.prototype, entry[1], {
        configurable: true,
        enumerable: descriptor.enumerable,
        get: descriptor.get,
        set: function (value) {
          try {
            var labels = labelsOf(String(value));
            if (labels.length) {
              emit('RESOURCE_URL_SET', {
                url: absolute(value), host: hostOf(value), kind: entry[2], private_data: isPrivate(labels)
              }, labels, callsite());
            }
          } catch (e) { /* ignorado */ }
          return descriptor.set.call(this, value);
        }
      });
    });

    wrap(G, 'open', function (original) {
      return function (url) {
        var labels = url ? labelsOf(String(url)) : [];
        if (labels.length) {
          emit('NAVIGATION', { url: absolute(url), host: hostOf(url), kind: 'window.open' }, labels, callsite());
        }
        return original.apply(this, arguments);
      };
    });
    if (G.location && typeof G.location.assign === 'function') {
      wrap(G.location, 'assign', function (original) {
        return function (url) {
          var labels = labelsOf(String(url));
          if (labels.length) {
            emit('NAVIGATION', { url: absolute(url), host: hostOf(url), kind: 'location.assign' }, labels, callsite());
          }
          return original.apply(this, arguments);
        };
      });
    }
  });

  /* ================================================================ */
  /* SINKS: almacenamiento                                             */
  /* ================================================================ */
  guard('storage', function () {
    if (G.Storage) {
      wrap(G.Storage.prototype, 'setItem', function (original) {
        return function (key, value) {
          try {
            var labels = uniq(labelsOf(value).concat(labelsOf(String(key))));
            var kind = (IS_WINDOW && this === G.sessionStorage) ? 'sessionStorage' : 'localStorage';
            emit('STORAGE_WRITE', {
              store: kind, key: String(key).slice(0, 120), value_size: byteLength(value),
              private_data: isPrivate(labels)
            }, labels, callsite());
          } catch (e) { /* ignorado */ }
          return original.apply(this, arguments);
        };
      });
    }
    if (G.IDBObjectStore) {
      ['put', 'add'].forEach(function (method) {
        wrap(G.IDBObjectStore.prototype, method, function (original) {
          return function (value, key) {
            try {
              var labels = labelsOf(value);
              emit('STORAGE_WRITE', {
                store: 'indexedDB', object_store: this.name || '', method: method,
                value_size: byteLength(value), private_data: isPrivate(labels)
              }, labels, callsite());
            } catch (e) { /* ignorado */ }
            return original.apply(this, arguments);
          };
        });
      });
    }
    if (G.Cache) {
      wrap(G.Cache.prototype, 'put', function (original) {
        return function (request, response) {
          try {
            emit('STORAGE_WRITE', {
              store: 'cacheStorage', key: String(request && request.url ? request.url : request).slice(0, 200)
            }, [], callsite());
          } catch (e) { /* ignorado */ }
          return original.apply(this, arguments);
        };
      });
    }
    if (IS_WINDOW && G.Document) {
      var cookieDescriptor = O.getOwnPropertyDescriptor(G.Document.prototype, 'cookie');
      if (cookieDescriptor && cookieDescriptor.set) {
        O.defineProperty(G.Document.prototype, 'cookie', {
          configurable: true,
          get: cookieDescriptor.get,
          set: function (value) {
            try {
              var labels = labelsOf(String(value));
              if (labels.length) {
                emit('STORAGE_WRITE', {
                  store: 'cookie', value_size: String(value).length, private_data: isPrivate(labels)
                }, labels, callsite());
              }
            } catch (e) { /* ignorado */ }
            return cookieDescriptor.set.call(this, value);
          }
        });
      }
    }
  });

  /* ================================================================ */
  /* Workers: instrumentacion de contextos hijos                       */
  /* ================================================================ */
  function agentSource() {
    try { return G.__FS_AGENT_SRC__ || ''; } catch (e) { return ''; }
  }

  function workerShim(url, options) {
    var src = agentSource();
    if (!src || !G.Blob || !O.URL || !O.URL.createObjectURL) { return null; }
    var absoluteUrl = absolute(url);
    var childConfig = {};
    for (var k in CFG) { if (Object.prototype.hasOwnProperty.call(CFG, k)) { childConfig[k] = CFG[k]; } }
    childConfig.context = null;   // el hijo detecta su propio tipo de contexto
    var isModule = !!(options && options.type === 'module');
    var prelude = 'self.__FIRMASCOPE_CONFIG__=' + O.stringify(childConfig) + ';'
      + 'self.__FS_AGENT_SRC__=' + O.stringify(src) + ';'
      + '(0,eval)(self.__FS_AGENT_SRC__);';
    var body = isModule
      ? prelude + 'await import(' + O.stringify(absoluteUrl) + ');'
      : prelude + 'importScripts(' + O.stringify(absoluteUrl) + ');';
    try {
      return O.URL.createObjectURL(new O.Blob([body], { type: 'text/javascript' }));
    } catch (e) { return null; }
  }

  function attachWorkerRelay(target) {
    try {
      target.addEventListener('message', function (ev) {
        if (ev && ev.data && ev.data.__firmascope__) {
          if (typeof ev.stopImmediatePropagation === 'function') { ev.stopImmediatePropagation(); }
          var record = ev.data.__firmascope__;
          record.relayed_from = CONTEXT;
          push(record);
        }
      }, true);
    } catch (e) { /* ignorado */ }
  }

  guard('workers', function () {
    if (!IS_WINDOW && !IS_WORKER) { return; }
    if (G.Worker) {
      var NativeWorker = G.Worker;
      function FSWorker(url, options) {
        var shimmed = null;
        try { shimmed = workerShim(url, options); } catch (e) { shimmed = null; }
        var instance = new NativeWorker(shimmed || url, options);
        emit('CONTEXT_CREATED', {
          kind: 'worker', url: absolute(url), instrumented: !!shimmed,
          type: (options && options.type) || 'classic'
        }, []);
        attachWorkerRelay(instance);
        return instance;
      }
      FSWorker.prototype = NativeWorker.prototype;
      try { G.Worker = FSWorker; } catch (e) { /* ignorado */ }
    }
    if (G.SharedWorker) {
      var NativeShared = G.SharedWorker;
      function FSSharedWorker(url, options) {
        var shimmed = null;
        try { shimmed = workerShim(url, options); } catch (e) { shimmed = null; }
        var instance = new NativeShared(shimmed || url, options);
        emit('CONTEXT_CREATED', { kind: 'shared-worker', url: absolute(url), instrumented: !!shimmed }, []);
        try { attachWorkerRelay(instance.port); instance.port.start(); } catch (e) { /* ignorado */ }
        return instance;
      }
      FSSharedWorker.prototype = NativeShared.prototype;
      try { G.SharedWorker = FSSharedWorker; } catch (e) { /* ignorado */ }
    }
    if (IS_WINDOW && G.navigator && G.navigator.serviceWorker) {
      wrap(G.navigator.serviceWorker, 'register', function (original) {
        return function (url, options) {
          // Un ServiceWorker no admite blob: como script; se registra el hecho
          // para que el reporte lo marque como contexto no instrumentado.
          emit('CONTEXT_CREATED', {
            kind: 'service-worker', url: absolute(url), instrumented: false,
            note: 'service worker no instrumentado por el agente'
          }, []);
          return original.apply(this, arguments);
        };
      });
    }
  });

  /* En un SharedWorker, el primer puerto conectado sirve de canal de relevo. */
  if (IS_SHARED_WORKER) {
    try {
      var nativeOnConnect = null;
      O.defineProperty(self, 'onconnect', {
        configurable: true,
        get: function () { return nativeOnConnect; },
        set: function (handler) { nativeOnConnect = handler; }
      });
      self.addEventListener('connect', function (ev) {
        if (!relayPort && ev.ports && ev.ports.length) { relayPort = ev.ports[0]; flush(); }
      }, true);
    } catch (e) { /* ignorado */ }
  }

  /* ================================================================ */
  /* API interna para el controlador de Python                         */
  /* ================================================================ */
  G.__FIRMASCOPE__ = {
    version: '0.1.0',
    session: SESSION,
    context: CONTEXT,
    drain: function () { var out = queue; queue = []; return out; },
    pending: function () { return queue.length; },
    dropped: function () { return dropped; },
    failures: function () { return failures.slice(); },
    flush: flush,
    /* Marca de procedencia manual: la usan las credenciales sinteticas. */
    mark: function (value, labels) { return taint(value, labels); },
    labels: function (value) { return labelsOf(value); },
    emit: emit
  };

  emit('CONTEXT_CREATED', {
    kind: CONTEXT, url: hrefOf(), agent: '0.1.0', hook_failures: failures.slice(0, 10)
  }, []);

  if (IS_WINDOW) {
    try {
      var kick = function () { flush(); };
      document.addEventListener('readystatechange', kick, true);
      window.addEventListener('load', function () {
        emit('PAGE_LOADED', { url: hrefOf(), title: (document.title || '').slice(0, 200) }, []);
      }, true);
      setInterval(kick, 250);
    } catch (e) { /* ignorado */ }
  } else {
    try { setInterval(flush, 250); } catch (e) { /* ignorado */ }
  }
})();
