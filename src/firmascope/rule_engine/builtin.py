"""Evaluadores del catalogo FS-* integrado.

Cada funcion responde a una pregunta verificable sobre la sesion y devuelve un
:class:`~firmascope.rule_engine.registry.RuleResult`. Ninguna afirma mas de lo
que la evidencia sostiene: la distincion entre ``NOT_OBSERVED`` (no ocurrio en
esta ejecucion) e ``INCONCLUSIVE`` (la sesion ni siquiera ejercito la
condicion) es deliberada.
"""

from __future__ import annotations

from typing import Any, Iterable, Sequence

from ..audit_core.conclusions import Confidence, Severity, Status
from ..audit_core.events import Event, EventType, Tag
from .context import AuditContext
from .registry import RuleResult, rule

#: Aviso que acompana a todo NOT_OBSERVED, por el principio final de la
#: especificacion: "no observe transmision" no es "no puede transmitirse".
NOT_OBSERVED_CAVEAT = (
    "No observado no equivale a imposible: este resultado describe unicamente "
    "lo ocurrido durante esta ejecucion, con esta configuracion y este recorrido."
)


# ----------------------------------------------------------------------
# Utilidades
# ----------------------------------------------------------------------

def _hosts(events: Iterable[Event], limit: int = 4) -> list[str]:
    seen: list[str] = []
    for event in events:
        host = str(event.data.get("host") or "")
        if not host:
            url = str(event.data.get("url") or "")
            host = url.split("//", 1)[-1].split("/", 1)[0] if "//" in url else url
        if host and host not in seen:
            seen.append(host)
        if len(seen) >= limit:
            break
    return seen


def _destinations(events: Sequence[Event]) -> str:
    hosts = _hosts(events)
    if not hosts:
        return "un destino no identificado"
    return ", ".join(hosts)


def _delta_ms(context: AuditContext, event: Event) -> int | None:
    anchor = context.first_key_access()
    if anchor is None:
        return None
    ts = context.usable_time(event)
    if ts is None:
        return None
    return int((ts - anchor.timestamp) * 1000)


def _evidence(context: AuditContext, events: Sequence[Event], note: str = "",
              limit: int = 12) -> list[dict[str, Any]]:
    return [context.event_evidence(event, note) for event in events[:limit]]


def _channel_label(event: Event) -> str:
    kinds = {
        EventType.NETWORK_REQUEST: "peticion HTTP",
        EventType.BEACON_SEND: "sendBeacon",
        EventType.WEBSOCKET_SEND: "WebSocket",
        EventType.WEBTRANSPORT_SEND: "WebTransport",
        EventType.RTC_SEND: "canal WebRTC",
        EventType.FORM_SUBMIT: "envio de formulario",
        EventType.NAVIGATION: "navegacion",
        EventType.RESOURCE_URL_SET: "URL de recurso",
        EventType.PROXY_REQUEST: "peticion vista por el proxy",
    }
    return kinds.get(event.type, event.type.value)


def _static_private_paths(context: AuditContext, channels: Sequence[str] = ()) -> list[Any]:
    if context.static is None:
        return []
    paths = context.static.private_paths()
    if channels:
        paths = [p for p in paths if p.channel in channels]
    return paths


# ----------------------------------------------------------------------
# Clave privada
# ----------------------------------------------------------------------

@rule("FS-KEY-001")
def key_file_transmitted(context: AuditContext, meta) -> RuleResult:
    hits = context.direct_egress(Tag.KEY_FILE, Tag.PRIVATE_KEY)
    if hits:
        detail_lines = []
        for event in hits[:6]:
            matches = context.canary_matches(event)
            encodings = ", ".join(sorted({m.get("encoding", "") for m in matches})) or "etiquetado por instrumentacion"
            detail_lines.append(
                f"- {_channel_label(event)} hacia {event.data.get('host') or event.data.get('url', '')} "
                f"({event.data.get('body_size', 0)} bytes; evidencia: {encodings})"
            )
        return RuleResult(
            status=Status.OBSERVED,
            summary=f"El material de la clave privada salio del navegador hacia {_destinations(hits)}.",
            detail="Salidas observadas:\n" + "\n".join(detail_lines),
            evidence=_evidence(context, hits, "transmision directa de material de clave"),
            confidence=Confidence.HIGH,
            severity=Severity.CRITICAL,
        )
    if not context.observed_key_material():
        return RuleResult.inconclusive(
            "La sesion no llego a procesar material de clave privada.",
            "No se observo lectura del .key ni operaciones con una clave privada, de modo "
            "que no hay base para afirmar ni negar que el sitio la transmita.",
        )
    return RuleResult.not_observed(
        "No se observo transmision directa del archivo .key ni de la clave privada.",
        NOT_OBSERVED_CAVEAT,
    )


@rule("FS-KEY-002")
def key_derived_transmitted(context: AuditContext, meta) -> RuleResult:
    hits = context.derived_egress(Tag.KEY_FILE, Tag.PRIVATE_KEY)
    if hits:
        lines = []
        for event in hits[:6]:
            delta = _delta_ms(context, event)
            when = f", {delta} ms despues del acceso a la clave" if delta is not None else ""
            lines.append(
                f"- {_channel_label(event)} hacia {event.data.get('host') or event.data.get('url', '')} "
                f"({event.data.get('body_size', 0)} bytes{when})"
            )
        return RuleResult(
            status=Status.OBSERVED,
            summary=(f"Salieron datos derivados de la clave privada hacia {_destinations(hits)}. "
                     "El contenido puede ser opaco, pero su procedencia esta establecida."),
            detail=("La instrumentacion siguio la procedencia del dato desde el material privado "
                    "hasta el canal de salida. No es necesario interpretar el contenido "
                    "transmitido para afirmar de donde procede.\n\n" + "\n".join(lines)),
            evidence=_evidence(context, hits, "dato derivado de material privado"),
            confidence=Confidence.HIGH,
            severity=Severity.CRITICAL,
        )

    paths = [p for p in _static_private_paths(context, ("network", "navigation", "dom", "worker"))
             if p.derived]
    if paths:
        return RuleResult(
            status=Status.POTENTIAL,
            summary=("El codigo contiene una ruta que transforma material privado y lo envia, "
                     "pero no se observo su ejecucion."),
            detail="\n".join(f"- {p.file_label}:{p.sink_line} {p.source.name} -> "
                             f"{' -> '.join(p.transforms) or 'sin transformacion'} -> {p.sink_name}"
                             for p in paths[:6]),
            evidence=[context.code_evidence(p, "ruta estatica con transformacion") for p in paths[:8]],
            confidence=context.static.best_confidence(paths) if context.static else Confidence.LOW,
        )

    if not context.observed_key_material():
        return RuleResult.inconclusive(
            "La sesion no llego a procesar material de clave privada.",
            "Sin acceso observado a la clave no puede evaluarse la salida de datos derivados.",
        )
    return RuleResult.not_observed(
        "No se observaron salidas de datos derivados de la clave privada.",
        NOT_OBSERVED_CAVEAT + " El seguimiento de procedencia en JavaScript es aproximado: "
        "una transformacion fuera de las APIs instrumentadas podria no quedar etiquetada.",
    )


# ----------------------------------------------------------------------
# Contrasena
# ----------------------------------------------------------------------

@rule("FS-PWD-001")
def password_transmitted(context: AuditContext, meta) -> RuleResult:
    hits = context.any_egress(Tag.KEY_PASSWORD)
    if hits:
        direct = context.direct_egress(Tag.KEY_PASSWORD)
        nature = ("en claro o en una codificacion reversible" if direct
                  else "de forma derivada (transformada)")
        return RuleResult(
            status=Status.OBSERVED,
            summary=f"La contrasena de la clave privada salio del navegador hacia {_destinations(hits)}.",
            detail=(f"La transmision se observo {nature}. La contrasena de la e.firma protege la "
                    "clave privada: su envio al servidor implica que el servidor puede usar la "
                    "clave si tambien dispone del .key."),
            evidence=_evidence(context, hits, "transmision de la contrasena"),
            confidence=Confidence.HIGH if direct else Confidence.MEDIUM,
            severity=Severity.CRITICAL,
        )
    if not context.observed_password():
        return RuleResult.inconclusive(
            "La sesion no llego a usar la contrasena de la clave privada.",
            "No se observo lectura de un campo de contrasena relacionado con la firma.",
        )
    return RuleResult.not_observed(
        "No se observo transmision de la contrasena.",
        NOT_OBSERVED_CAVEAT,
    )


@rule("FS-PWD-002")
def password_persisted(context: AuditContext, meta) -> RuleResult:
    hits = context.storage_writes(labels=(Tag.KEY_PASSWORD,))
    if hits:
        stores = sorted({str(e.data.get("store", "?")) for e in hits})
        return RuleResult(
            status=Status.OBSERVED,
            summary=f"La contrasena se escribio en almacenamiento del navegador: {', '.join(stores)}.",
            detail=("El material persistido sobrevive al cierre de la pestana y queda accesible "
                    "a cualquier script del mismo origen, incluidos los de terceros."),
            evidence=_evidence(context, hits, "escritura de la contrasena en almacenamiento"),
            confidence=Confidence.HIGH,
            severity=Severity.HIGH,
        )
    if not context.observed_password():
        return RuleResult.inconclusive(
            "La sesion no llego a usar la contrasena de la clave privada.")
    return RuleResult.not_observed(
        "No se observo persistencia de la contrasena en el almacenamiento del navegador.",
        NOT_OBSERVED_CAVEAT,
    )


# ----------------------------------------------------------------------
# WebCrypto
# ----------------------------------------------------------------------

@rule("FS-CRYPTO-001")
def private_key_exported(context: AuditContext, meta) -> RuleResult:
    hits = [e for e in context.events_of(EventType.CRYPTO_EXPORT)
            if str(e.data.get("key_type", "")) == "private" or e.has_tag(Tag.PRIVATE_KEY)]
    if hits:
        return RuleResult(
            status=Status.OBSERVED,
            summary="La aplicacion exporto una clave privada fuera del objeto CryptoKey.",
            detail=("exportKey() sobre una clave privada devuelve el material en bruto al "
                    "JavaScript de la pagina. A partir de ese momento cualquier ruta de codigo "
                    "puede copiarlo o transmitirlo."),
            evidence=_evidence(context, hits, "exportacion de clave privada"),
            confidence=Confidence.HIGH,
            severity=Severity.HIGH,
        )
    if not context.events_of(EventType.CRYPTO_IMPORT, EventType.CRYPTO_SIGN,
                             EventType.CRYPTO_GENERATE, EventType.CRYPTO_UNWRAP):
        return RuleResult.inconclusive(
            "No se observaron operaciones de WebCrypto en la sesion.",
            "El sitio podria realizar la criptografia con una biblioteca propia en lugar de "
            "WebCrypto; en ese caso esta regla no puede pronunciarse.",
        )
    return RuleResult.not_observed(
        "No se observo la exportacion de ninguna clave privada.",
        NOT_OBSERVED_CAVEAT,
    )


@rule("FS-CRYPTO-002")
def extractable_private_key(context: AuditContext, meta) -> RuleResult:
    hits: list[Event] = []
    for event in context.events_of(EventType.CRYPTO_IMPORT, EventType.CRYPTO_UNWRAP,
                                   EventType.CRYPTO_GENERATE):
        if not bool(event.data.get("extractable")):
            continue
        key_type = str(event.data.get("key_type", ""))
        algorithm = str(event.data.get("algorithm", "")).upper()
        asymmetric = algorithm.startswith(("RSA", "EC", "ED"))
        if key_type == "private" or event.has_tag(Tag.PRIVATE_KEY) or (
                event.type is EventType.CRYPTO_GENERATE and asymmetric):
            hits.append(event)
    if hits:
        return RuleResult(
            status=Status.OBSERVED,
            summary="Se creo una clave privada marcada como extraible (extractable=true).",
            detail=("Una CryptoKey privada no extraible no puede volver a JavaScript: el "
                    "navegador impide leer su material. Marcarla extraible renuncia a esa "
                    "garantia sin necesidad, salvo que la aplicacion tenga que serializarla."),
            evidence=_evidence(context, hits, "clave privada extraible"),
            confidence=Confidence.HIGH,
            severity=Severity.MEDIUM,
        )
    if not context.events_of(EventType.CRYPTO_IMPORT, EventType.CRYPTO_UNWRAP,
                             EventType.CRYPTO_GENERATE):
        return RuleResult.inconclusive(
            "No se observo la creacion de ninguna clave con WebCrypto.")
    return RuleResult.not_observed(
        "Las claves privadas observadas se crearon como no extraibles.",
        NOT_OBSERVED_CAVEAT,
    )


# ----------------------------------------------------------------------
# Firma local
# ----------------------------------------------------------------------

@rule("FS-LOCAL-001")
def local_signature(context: AuditContext, meta) -> RuleResult:
    signatures = context.events_of(EventType.CRYPTO_SIGN)
    offline = context.events_while_offline(signatures)
    if offline:
        windows = context.offline_windows()
        return RuleResult(
            status=Status.CONFIRMED,
            summary="Se genero una firma con la red del navegador aislada.",
            detail=("Firma local demostrada bajo las condiciones registradas en el manifiesto. "
                    "Esto establece que la operacion criptografica puede completarse sin red; "
                    "NO significa que el sitio sea seguro ni que no transmita nada en otras "
                    f"circunstancias. Ventanas de aislamiento: {len(windows)}."),
            evidence=_evidence(context, offline, "firma generada con la red aislada"),
            confidence=Confidence.HIGH,
            severity=Severity.INFO,
        )
    if not context.offline_test_ran():
        return RuleResult.inconclusive(
            "No se ejecuto la prueba de aislamiento de red.",
            "Ejecute la auditoria en nivel 3 o superior para comprobar si la firma se completa "
            "con el navegador desconectado.",
        )
    if signatures:
        return RuleResult(
            status=Status.NOT_OBSERVED,
            summary="Hubo operaciones de firma, pero ninguna durante el aislamiento de red.",
            detail=("Puede deberse a que la aplicacion necesita red en ese punto del flujo, o a "
                    "que el recorrido de la prueba no llego a firmar con la red desconectada. "
                    + NOT_OBSERVED_CAVEAT),
            evidence=_evidence(context, signatures, "firma observada en linea"),
            confidence=Confidence.MEDIUM,
        )
    return RuleResult.inconclusive(
        "No se observo ninguna operacion de firma en la sesion.",
        "Sin una firma observada no puede evaluarse donde se realiza.",
    )


# ----------------------------------------------------------------------
# Red
# ----------------------------------------------------------------------

@rule("FS-NET-001")
def third_party_after_key_access(context: AuditContext, meta) -> RuleResult:
    grouped = context.third_parties_after_key_access()
    if grouped:
        names = context.third_party_names()
        lines = [f"- {domain} ({names.get(domain, domain)}): {len(items)} peticiones"
                 for domain, items in sorted(grouped.items(), key=lambda kv: -len(kv[1]))]
        evidence = []
        for items in grouped.values():
            evidence.extend(context.request_evidence(item, "tercero tras el acceso a la clave")
                            for item in items[:3])
        return RuleResult(
            status=Status.OBSERVED,
            summary=(f"{len(grouped)} dominios de tercero recibieron trafico despues de que el "
                     "navegador accediera al material de la clave."),
            detail=("Este hallazgo es descriptivo, no acusatorio: un CDN o un servicio de "
                    "analitica pueden recibir trafico legitimo en ese momento. Lo relevante es "
                    "que el reporte permita revisar quien recibio que y cuando.\n\n"
                    + "\n".join(lines[:10])),
            evidence=evidence[:12],
            confidence=Confidence.HIGH,
            severity=Severity.MEDIUM,
        )
    if context.first_key_access() is None:
        return RuleResult.inconclusive(
            "No se observo acceso al material de la clave, asi que no hay un instante de "
            "referencia para clasificar el trafico posterior.")
    return RuleResult.not_observed(
        "Ningun dominio de tercero recibio trafico tras el acceso al material de la clave.",
        NOT_OBSERVED_CAVEAT,
    )


@rule("FS-NET-002")
def unclassified_binary_egress(context: AuditContext, meta) -> RuleResult:
    candidates = context.after_key_access(context.unclassified_binary_egress())
    if candidates:
        lines = []
        for event in candidates[:6]:
            delta = _delta_ms(context, event)
            when = f"{delta} ms despues del acceso a la clave" if delta is not None else "instante no comparable"
            lines.append(f"- {_channel_label(event)} hacia "
                         f"{event.data.get('host') or event.data.get('url', '')}: "
                         f"{event.data.get('body_size', 0)} bytes, {when}")
        return RuleResult(
            status=Status.OBSERVED,
            summary=(f"{len(candidates)} salidas binarias sin clasificar ocurrieron tras el "
                     "acceso al material de la clave."),
            detail=("FirmaScope no pudo establecer la procedencia de estos datos: podrian ser "
                    "legitimos o ser material sensible cifrado antes de salir. Merecen revision "
                    "manual, especialmente si el destino es un tercero.\n\n" + "\n".join(lines)),
            evidence=_evidence(context, candidates, "salida binaria sin clasificar"),
            confidence=Confidence.MEDIUM,
            severity=Severity.MEDIUM,
        )
    if context.first_key_access() is None:
        return RuleResult.inconclusive(
            "No se observo acceso al material de la clave.")
    return RuleResult.not_observed(
        "No se observaron salidas binarias sin clasificar tras el acceso a la clave.",
        NOT_OBSERVED_CAVEAT,
    )


# ----------------------------------------------------------------------
# Persistencia
# ----------------------------------------------------------------------

def _storage_rule(context: AuditContext, store: str, human: str) -> RuleResult:
    hits = context.storage_writes(store=store, labels=(Tag.KEY_FILE, Tag.PRIVATE_KEY))
    if hits:
        return RuleResult(
            status=Status.OBSERVED,
            summary=f"Se escribio material de clave privada en {human}.",
            detail=("El material persiste tras cerrar la pestana y queda al alcance de cualquier "
                    "script del mismo origen. Una clave privada no deberia sobrevivir a la "
                    "operacion de firma."),
            evidence=_evidence(context, hits, f"escritura en {human}"),
            confidence=Confidence.HIGH,
            severity=Severity.HIGH,
        )
    if not context.observed_key_material():
        return RuleResult.inconclusive(
            "La sesion no llego a procesar material de clave privada.")
    return RuleResult.not_observed(
        f"No se observo material de clave privada en {human}.",
        NOT_OBSERVED_CAVEAT,
    )


@rule("FS-STORAGE-001")
def private_material_in_indexeddb(context: AuditContext, meta) -> RuleResult:
    return _storage_rule(context, "indexedDB", "IndexedDB")


@rule("FS-STORAGE-002")
def private_material_in_localstorage(context: AuditContext, meta) -> RuleResult:
    return _storage_rule(context, "localStorage", "localStorage")


# ----------------------------------------------------------------------
# Analisis estatico
# ----------------------------------------------------------------------

@rule("FS-CODE-001")
def potential_key_to_network_path(context: AuditContext, meta) -> RuleResult:
    if context.static is None:
        return RuleResult.inconclusive(
            "No se ejecuto el analisis estatico.",
            "Ejecute la auditoria en nivel 2 o superior para analizar el codigo cargado.",
        )
    paths = _static_private_paths(context, ("network", "navigation", "dom", "worker"))
    if paths:
        lines = []
        for path in paths[:8]:
            chain = " -> ".join(path.call_chain) if path.call_chain else "(cadena no reconstruida)"
            transforms = " -> ".join(path.transforms) if path.transforms else "sin transformacion"
            lines.append(
                f"- {path.file_label}:{path.sink_line} [{path.confidence.value}]\n"
                f"    source:    {path.source.name} ({path.source.snippet})\n"
                f"    transform: {transforms}\n"
                f"    sink:      {path.sink_name} ({path.sink_snippet})\n"
                f"    llamadas:  {chain}"
            )
        observed = bool(context.any_egress(Tag.KEY_FILE, Tag.PRIVATE_KEY, Tag.KEY_PASSWORD))
        note = ("\n\nAdemas, en esta ejecucion se observo salida de material sensible: "
                "vease FS-KEY-001, FS-KEY-002 o FS-PWD-001." if observed else
                "\n\nNinguna de estas rutas se ejecuto durante la sesion. Que el codigo pueda "
                "hacerlo no prueba que lo haga.")
        return RuleResult(
            status=Status.POTENTIAL,
            summary=(f"El codigo cargado contiene {len(paths)} rutas capaces de llevar material "
                     "sensible hasta un canal de salida."),
            detail="\n".join(lines) + note,
            evidence=[context.code_evidence(p, "ruta source-to-sink") for p in paths[:12]],
            confidence=context.static.best_confidence(paths),
            severity=Severity.HIGH,
        )
    if not context.static.ast_available:
        return RuleResult.inconclusive(
            "El analisis estatico se ejecuto en modo degradado (sin AST).",
            "Instale tree-sitter-javascript para el analisis completo de rutas.",
        )
    if context.static.parsed == 0:
        return RuleResult.inconclusive(
            "No se analizo ningun script.",
            "No se recupero codigo fuente del inventario de scripts de la sesion.",
        )
    return RuleResult.not_observed(
        f"No se identificaron rutas de material sensible hacia canales de salida en "
        f"{context.static.parsed} scripts analizados.",
        "El analisis es aproximado: el codigo minificado, el despacho dinamico y las rutas que "
        "atraviesan bibliotecas de terceros pueden ocultar flujos reales. " + NOT_OBSERVED_CAVEAT,
    )
