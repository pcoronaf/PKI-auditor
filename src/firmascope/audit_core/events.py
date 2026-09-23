"""Modelo de eventos normalizado.

Todos los sensores (instrumentacion de navegador, CDP, proxy, analisis
estatico) producen instancias de :class:`Event`. El modelo es deliberadamente
plano y serializable a JSON para que el expediente de auditoria pueda leerse
con herramientas externas.

Regla invariante: un evento describe *operaciones*, nunca secretos. El
contenido de la clave privada o de la contrasena jamas debe aparecer en
``Event.data``; ver :mod:`firmascope.audit_core.secrets`.
"""

from __future__ import annotations

import enum
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


class EventType(str, enum.Enum):
    """Tipos de evento reconocidos por el motor de correlacion."""

    # Ciclo de vida de la sesion / contextos de ejecucion
    SESSION_START = "SESSION_START"
    SESSION_END = "SESSION_END"
    PAGE_LOADED = "PAGE_LOADED"
    CONTEXT_CREATED = "CONTEXT_CREATED"
    CHECKPOINT = "CHECKPOINT"

    # Material sensible
    FILE_SELECTED = "FILE_SELECTED"
    FILE_READ = "FILE_READ"
    PASSWORD_READ = "PASSWORD_READ"

    # WebCrypto
    CRYPTO_IMPORT = "CRYPTO_IMPORT"
    CRYPTO_DECRYPT = "CRYPTO_DECRYPT"
    CRYPTO_ENCRYPT = "CRYPTO_ENCRYPT"
    CRYPTO_SIGN = "CRYPTO_SIGN"
    CRYPTO_VERIFY = "CRYPTO_VERIFY"
    CRYPTO_EXPORT = "CRYPTO_EXPORT"
    CRYPTO_WRAP = "CRYPTO_WRAP"
    CRYPTO_UNWRAP = "CRYPTO_UNWRAP"
    CRYPTO_DERIVE = "CRYPTO_DERIVE"
    CRYPTO_DIGEST = "CRYPTO_DIGEST"
    CRYPTO_GENERATE = "CRYPTO_GENERATE"

    # Canales de salida
    NETWORK_REQUEST = "NETWORK_REQUEST"
    NETWORK_RESPONSE = "NETWORK_RESPONSE"
    NETWORK_FAILED = "NETWORK_FAILED"
    WEBSOCKET_CREATED = "WEBSOCKET_CREATED"
    WEBSOCKET_SEND = "WEBSOCKET_SEND"
    WEBTRANSPORT_CREATED = "WEBTRANSPORT_CREATED"
    WEBTRANSPORT_SEND = "WEBTRANSPORT_SEND"
    BEACON_SEND = "BEACON_SEND"
    RTC_SEND = "RTC_SEND"
    FORM_SUBMIT = "FORM_SUBMIT"
    NAVIGATION = "NAVIGATION"
    RESOURCE_URL_SET = "RESOURCE_URL_SET"

    # Persistencia
    STORAGE_WRITE = "STORAGE_WRITE"

    # Estado de red controlado por el auditor
    NETWORK_OFF = "NETWORK_OFF"
    NETWORK_ON = "NETWORK_ON"

    # Sensores auxiliares
    SCRIPT_LOADED = "SCRIPT_LOADED"
    PROXY_REQUEST = "PROXY_REQUEST"
    PROXY_WEBSOCKET = "PROXY_WEBSOCKET"
    CANARY_MATCH = "CANARY_MATCH"
    AGENT_ERROR = "AGENT_ERROR"


#: Eventos que representan un canal capaz de sacar datos del navegador.
EGRESS_EVENTS = frozenset(
    {
        EventType.NETWORK_REQUEST,
        EventType.WEBSOCKET_SEND,
        EventType.WEBTRANSPORT_SEND,
        EventType.BEACON_SEND,
        EventType.RTC_SEND,
        EventType.FORM_SUBMIT,
        EventType.NAVIGATION,
        EventType.RESOURCE_URL_SET,
        EventType.PROXY_REQUEST,
        EventType.PROXY_WEBSOCKET,
    }
)

#: Eventos que implican acceso a material privado dentro del navegador.
KEY_ACCESS_EVENTS = frozenset(
    {
        EventType.FILE_READ,
        EventType.PASSWORD_READ,
        EventType.CRYPTO_IMPORT,
        EventType.CRYPTO_DECRYPT,
        EventType.CRYPTO_UNWRAP,
    }
)


class Tag(str, enum.Enum):
    """Etiquetas de procedencia (modelo S1..S6 de la especificacion)."""

    KEY_FILE = "KEY_FILE"            # S1 - bytes del archivo .key
    KEY_PASSWORD = "KEY_PASSWORD"    # S2 - contrasena de la clave
    PRIVATE_KEY = "PRIVATE_KEY"      # S3 - clave privada descifrada / CryptoKey
    CERTIFICATE = "CERTIFICATE"      # S4 - certificado .cer (material publico)
    DOCUMENT = "DOCUMENT"            # S5 - documento a firmar
    SIGNATURE = "SIGNATURE"          # S6 - firma resultante

    #: Marca que el dato no es el material original sino una transformacion.
    DERIVED = "DERIVED"
    #: El dato no pudo clasificarse (binario opaco, origen desconocido).
    UNCLASSIFIED = "UNCLASSIFIED"


#: Subconjunto de etiquetas que nunca deberian abandonar el navegador.
PRIVATE_TAGS = frozenset({Tag.KEY_FILE, Tag.KEY_PASSWORD, Tag.PRIVATE_KEY})

#: Etiquetas que no dicen nada sobre la naturaleza del dato.
_NEUTRAL_TAGS = frozenset({Tag.UNCLASSIFIED.value, Tag.DERIVED.value})


def is_key_access(event: "Event") -> bool:
    """True si el evento es un acceso a material privado.

    Leer un fichero o importar una clave solo cuenta si lo leido es privado.
    En una plataforma real el operador carga antes documentos (un PDF, un XML)
    y el certificado, que es publico: tomarlos como "acceso a la clave"
    adelantaria el instante de referencia de las reglas temporales y haria
    sospechoso el trafico anterior a la firma. Una lectura sin clasificar se
    sigue contando, por prudencia.
    """
    if event.type not in KEY_ACCESS_EVENTS:
        return False
    if event.type in (EventType.FILE_READ, EventType.CRYPTO_IMPORT):
        known = set(event.tags) - _NEUTRAL_TAGS
        return not known or bool(known & {t.value for t in PRIVATE_TAGS})
    return True


def now() -> float:
    """Marca temporal de pared, en segundos con fraccion (epoch)."""
    return time.time()


@dataclass
class Event:
    """Evento normalizado producido por cualquier sensor."""

    type: EventType
    session: str
    timestamp: float = field(default_factory=now)
    #: Contexto de ejecucion: ``main``, ``iframe-3``, ``worker-17``, ``proxy``...
    context: str = "main"
    #: Origen web del contexto que genero el evento.
    origin: str = ""
    #: Ubicacion en codigo (``signer.js:438``) cuando el sensor puede obtenerla.
    source: str = ""
    #: Sensor que emitio el evento (``agent``, ``cdp``, ``proxy``, ``static``).
    sensor: str = "agent"
    tags: list[str] = field(default_factory=list)
    #: Metadatos redactados. Nunca contiene secretos en claro.
    data: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    #: Numero de secuencia asignado por el almacen de evidencias.
    seq: int = 0

    def __post_init__(self) -> None:
        if isinstance(self.type, str):
            self.type = EventType(self.type)
        self.tags = [t.value if isinstance(t, Tag) else str(t) for t in self.tags]

    # -- utilidades -----------------------------------------------------
    def has_tag(self, tag: Tag | str) -> bool:
        value = tag.value if isinstance(tag, Tag) else tag
        return value in self.tags

    def has_private_tag(self) -> bool:
        return any(t.value in self.tags for t in PRIVATE_TAGS)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "seq": self.seq,
            "timestamp": round(self.timestamp, 3),
            "session": self.session,
            "type": self.type.value,
            "context": self.context,
            "origin": self.origin,
            "source": self.source,
            "sensor": self.sensor,
            "tags": list(self.tags),
            "data": self.data,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Event":
        return cls(
            type=EventType(raw["type"]),
            session=raw.get("session", ""),
            timestamp=float(raw.get("timestamp", 0.0)),
            context=raw.get("context", "main"),
            origin=raw.get("origin", ""),
            source=raw.get("source", ""),
            sensor=raw.get("sensor", "agent"),
            tags=list(raw.get("tags", [])),
            data=dict(raw.get("data", {})),
            id=raw.get("id", uuid.uuid4().hex),
            seq=int(raw.get("seq", 0)),
        )
