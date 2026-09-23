"""Catalogo de sources, transforms y sinks (Nivel 2).

Responde a la pregunta de la especificacion: *que podria hacer el codigo aunque
no haya ocurrido durante esta ejecucion*. Las listas reproducen las de la
especificacion y son extensibles (NFR-004): anadir un sink nuevo es anadir una
entrada aqui.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..audit_core.events import Tag


@dataclass(frozen=True)
class CallPattern:
    """Patron de llamada reconocible en el AST."""

    #: Nombre legible que aparece en el reporte, p. ej. ``FileReader.readAsArrayBuffer``.
    name: str
    #: Nombre final de la llamada (``readAsArrayBuffer``) o de la propiedad (``value``).
    member: str
    #: Subcadenas que, de estar presentes, refuerzan la identificacion del objeto.
    object_hints: tuple[str, ...] = ()
    #: Etiquetas fijas que aporta el patron (vacio = se infieren del texto).
    labels: tuple[str, ...] = ()
    #: Indices de argumentos que transportan el dato sensible (para sinks).
    data_args: tuple[int, ...] = ()
    #: Indice del argumento que contiene la URL de destino (para sinks de red).
    url_arg: int | None = None
    #: Canal al que pertenece el sink: network, storage, navigation, dom.
    channel: str = ""


# ----------------------------------------------------------------------
# SOURCES
# ----------------------------------------------------------------------

#: Llamadas que introducen material sensible en el programa.
SOURCE_CALLS: tuple[CallPattern, ...] = (
    CallPattern("FileReader.readAsArrayBuffer", "readAsArrayBuffer"),
    CallPattern("FileReader.readAsText", "readAsText"),
    CallPattern("FileReader.readAsDataURL", "readAsDataURL"),
    CallPattern("FileReader.readAsBinaryString", "readAsBinaryString"),
    CallPattern("Blob.arrayBuffer", "arrayBuffer"),
    CallPattern("Blob.text", "text", object_hints=("file", "blob", "key", "cer")),
    CallPattern("crypto.subtle.importKey", "importKey", labels=()),
    CallPattern("crypto.subtle.decrypt", "decrypt"),
    CallPattern("crypto.subtle.unwrapKey", "unwrapKey"),
    CallPattern("crypto.subtle.deriveKey", "deriveKey"),
    CallPattern("crypto.subtle.deriveBits", "deriveBits"),
    CallPattern("crypto.subtle.exportKey", "exportKey", labels=(Tag.PRIVATE_KEY.value,)),
    CallPattern("crypto.subtle.sign", "sign", labels=(Tag.SIGNATURE.value,)),
)

#: Lecturas de propiedad que introducen material sensible.
SOURCE_PROPERTIES: tuple[CallPattern, ...] = (
    CallPattern("input.files", "files"),
    CallPattern("FileReader.result", "result"),
    CallPattern("input.value", "value", object_hints=("password", "passwd", "pwd", "contrasen", "clave")),
    CallPattern("CryptoKey.privateKey", "privateKey", labels=(Tag.PRIVATE_KEY.value,)),
)

#: Llamadas de WebCrypto que transforman material manteniendo su procedencia.
CRYPTO_TRANSFORMS = frozenset(
    {
        "encrypt", "decrypt", "sign", "digest", "wrapKey", "unwrapKey",
        "deriveBits", "deriveKey", "importKey", "exportKey",
    }
)

#: Transformaciones *reversibles*: cambian la representacion, no el contenido.
#:
#: Un .key en base64 sigue siendo el .key — quien reciba esos bytes tiene la
#: clave. Por eso atravesar una de estas funciones no convierte el dato en
#: "derivado": la transmision se sigue considerando directa (FS-KEY-001).
REVERSIBLE_TRANSFORMS = frozenset(
    {
        "btoa", "atob", "encodeURI", "encodeURIComponent", "decodeURIComponent",
        "stringify", "parse", "encode", "decode", "toBase64", "fromBase64",
        "toString", "slice", "subarray", "join", "concat", "map", "from",
        "hex", "toHex", "fromHex", "buffer", "bytes", "serialize", "pack",
    }
)

#: Transformaciones que *oscurecen* el dato: el contenido deja de ser legible
#: para quien observa el canal. La procedencia se conserva, pero la salida ya
#: no es el material original (FS-KEY-002).
OBSCURING_TRANSFORMS = frozenset(
    {
        "compress", "deflate", "gzip", "cipher", "seal", "wrap", "obfuscate",
        "encrypt", "digest", "wrapKey", "deriveBits", "deriveKey",
    }
)

#: Funciones que transforman un valor sin perder su procedencia.
TRANSFORMS = REVERSIBLE_TRANSFORMS | OBSCURING_TRANSFORMS

#: Constructores que envuelven datos conservando la procedencia.
TRANSFORM_CONSTRUCTORS = frozenset({"Blob", "File", "FormData", "URLSearchParams", "Uint8Array", "DataView"})

#: Consultas al DOM cuyo selector literal delata que elemento se obtiene.
#:
#: La minificacion borra los nombres de variable (``keyInput`` pasa a ser
#: ``n``), pero no puede tocar los ids del HTML: ``getElementById("key-file")``
#: sobrevive intacto y dice de que campo se trata.
DOM_LOOKUPS = frozenset(
    {"getElementById", "querySelector", "querySelectorAll", "getElementsByName",
     "getElementsByClassName"}
)

#: Propiedades de un campo de formulario que entregan su contenido.
DOM_CONTENT_PROPERTIES = frozenset({"value", "files"})

#: Metodos que *acumulan* el argumento dentro del objeto receptor.
#:
#: A diferencia de una transformacion, aqui el dato no se consume: pasa a
#: formar parte del receptor. Un ``FormData`` al que se le anadio el .key
#: transporta el .key, y enviarlo equivale a enviar la clave. Sin esta regla
#: el patron ``form.append('key', blob); fetch(url, {body: form})`` — el mas
#: comun para subir un fichero — quedaria fuera del analisis.
ACCUMULATOR_METHODS = frozenset(
    {"append", "set", "add", "push", "unshift", "enqueue", "insert", "write"}
)


# ----------------------------------------------------------------------
# SINKS
# ----------------------------------------------------------------------

SINK_CALLS: tuple[CallPattern, ...] = (
    CallPattern("fetch", "fetch", data_args=(1,), url_arg=0, channel="network"),
    CallPattern("XMLHttpRequest.send", "send", object_hints=("xhr", "request", "req", "xmlhttp"),
                data_args=(0,), channel="network"),
    CallPattern("navigator.sendBeacon", "sendBeacon", data_args=(1,), url_arg=0, channel="network"),
    CallPattern("WebSocket.send", "send", object_hints=("ws", "socket", "websocket"),
                data_args=(0,), channel="network"),
    CallPattern("RTCDataChannel.send", "send", object_hints=("channel", "datachannel", "dc", "rtc"),
                data_args=(0,), channel="network"),
    CallPattern("WebTransport.write", "write", object_hints=("writer", "stream", "datagram"),
                data_args=(0,), channel="network"),
    CallPattern("HTMLFormElement.submit", "submit", object_hints=("form",), data_args=(), channel="network"),
    CallPattern("localStorage.setItem", "setItem", object_hints=("localstorage",),
                data_args=(1,), channel="storage"),
    CallPattern("sessionStorage.setItem", "setItem", object_hints=("sessionstorage",),
                data_args=(1,), channel="storage"),
    CallPattern("Storage.setItem", "setItem", data_args=(1,), channel="storage"),
    CallPattern("IDBObjectStore.put", "put", object_hints=("store", "objectstore", "db", "idb"),
                data_args=(0,), channel="storage"),
    CallPattern("IDBObjectStore.add", "add", object_hints=("store", "objectstore", "db", "idb"),
                data_args=(0,), channel="storage"),
    CallPattern("Cache.put", "put", object_hints=("cache",), data_args=(1,), channel="storage"),
    CallPattern("window.open", "open", object_hints=("window", "self", "top"),
                data_args=(0,), url_arg=0, channel="navigation"),
    CallPattern("location.assign", "assign", object_hints=("location",),
                data_args=(0,), url_arg=0, channel="navigation"),
    CallPattern("location.replace", "replace", object_hints=("location",),
                data_args=(0,), url_arg=0, channel="navigation"),
    CallPattern("Worker.postMessage", "postMessage", data_args=(0,), channel="worker"),
)

#: Asignaciones a propiedades que sacan datos del documento.
SINK_ASSIGNMENTS: tuple[CallPattern, ...] = (
    CallPattern("image.src", "src", object_hints=("img", "image"), channel="dom"),
    CallPattern("script.src", "src", object_hints=("script",), channel="dom"),
    CallPattern("iframe.src", "src", object_hints=("iframe", "frame"), channel="dom"),
    CallPattern("element.src", "src", channel="dom"),
    CallPattern("anchor.href", "href", object_hints=("a", "anchor", "link"), channel="dom"),
    CallPattern("location.href", "href", object_hints=("location",), channel="navigation"),
    CallPattern("document.cookie", "cookie", object_hints=("document",), channel="storage"),
    CallPattern("element.action", "action", object_hints=("form",), channel="network"),
)

#: Nombres de funcion que, por si solos, sugieren un canal de salida.
EGRESS_NAME_HINTS = (
    "upload", "send", "post", "report", "track", "telemetry", "beacon",
    "submit", "sync", "publish", "emit", "log",
)


# ----------------------------------------------------------------------
# Inferencia de etiquetas por texto
# ----------------------------------------------------------------------

#: Heuristicas de nombre. El orden importa: la primera coincidencia gana.
NAME_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"passw|passwd|\bpwd\b|contrase|\bclave\b|passphrase|\bpin\b", re.I), Tag.KEY_PASSWORD.value),
    (re.compile(r"private[_-]?key|privkey|\.key\b|key[_-]?file|key[_-]?bytes|key[_-]?data|llave|pkcs8|pkcs#8",
                re.I), Tag.KEY_FILE.value),
    (re.compile(r"certific|\.cer\b|\bcer[_-]?file\b|\bcrt\b|\bx509\b", re.I), Tag.CERTIFICATE.value),
    (re.compile(r"signature|\bfirma\b|signed[_-]?data|\bsello\b", re.I), Tag.SIGNATURE.value),
    (re.compile(r"document|documento|payload|\bxml\b|\bpdf\b|cadena[_-]?original", re.I), Tag.DOCUMENT.value),
)

#: Nombres que parecen clave pero son material publico: evitan falsos positivos.
PUBLIC_KEY_PATTERN = re.compile(r"public[_-]?key|pubkey|api[_-]?key|key[_-]?code|keyboard|keydown|keyup|keypress",
                                re.I)


def infer_labels(text: str) -> set[str]:
    """Deduce etiquetas de procedencia a partir del texto de una expresion.

    Es una heuristica deliberadamente conservadora: el material publico
    (``publicKey``, ``apiKey``) queda excluido, y los hallazgos que dependen
    unicamente de esta inferencia se reportan con confianza baja.
    """
    if not text:
        return set()
    if PUBLIC_KEY_PATTERN.search(text):
        return set()
    labels: set[str] = set()
    for pattern, label in NAME_PATTERNS:
        if pattern.search(text):
            labels.add(label)
    return labels


def match_pattern(patterns: tuple[CallPattern, ...], member: str, object_text: str) -> CallPattern | None:
    """Busca el patron mas especifico que encaje con ``member``.

    Un patron con ``object_hints`` solo encaja si alguna pista aparece en el
    texto del objeto; se prefiere siempre sobre el patron generico equivalente.
    """
    generic: CallPattern | None = None
    lowered = (object_text or "").lower()
    for pattern in patterns:
        if pattern.member != member:
            continue
        if not pattern.object_hints:
            generic = generic or pattern
            continue
        if any(hint in lowered for hint in pattern.object_hints):
            return pattern
    return generic


def is_transform(name: str) -> bool:
    return name in TRANSFORMS or name in CRYPTO_TRANSFORMS


def obscures(name: str) -> bool:
    """True si la transformacion vuelve opaco el contenido transmitido.

    Determina si una salida se reporta como transmision *directa* del material
    (FS-KEY-001) o como salida de un dato *derivado* de el (FS-KEY-002). El
    nombre puede venir cualificado (``crypto.subtle.encrypt``), asi que se
    compara tambien el ultimo segmento.
    """
    if not name:
        return False
    return name in OBSCURING_TRANSFORMS or name.rsplit(".", 1)[-1] in OBSCURING_TRANSFORMS


def looks_like_egress_name(name: str) -> bool:
    lowered = (name or "").lower()
    return any(hint in lowered for hint in EGRESS_NAME_HINTS)
