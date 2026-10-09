"""Addon de mitmproxy: el sensor que ve el cuerpo que el navegador cifro.

Por que hace falta un cuarto sensor
-----------------------------------

CDP ve las peticiones del navegador, pero no siempre su cuerpo. El caso que lo
demuestra es el mas comun de todos: una subida ``multipart/form-data`` con el
``.key`` dentro. Ahi ``Network.requestWillBeSent`` llega con ``postData``
vacio, porque el cuerpo es un flujo que Chromium no materializa para el
depurador. El agente en la pagina sabe que el dato *venia* de la clave, pero no
puede probar que los bytes salieran; CDP ve que algo salio, pero no que era.

El proxy cierra esa brecha: termina el TLS y ve el cuerpo exacto que viajo. Eso
convierte una inferencia de procedencia en una prueba de contenido -- encontrar
la representacion del canario dentro del cuerpo demuestra que los bytes estaban
ahi.

Por que se ejecuta dentro del proceso
-------------------------------------

Para buscar los canarios hay que conocerlos, y los canarios son el material de
la credencial. Un ``mitmdump -s addon.py`` aparte obligaria a pasarle esas
representaciones por archivo, variable de entorno o socket: tres formas de
sacar de la memoria exactamente lo que la herramienta promete no sacar. El
addon se ejecuta en el mismo proceso y consulta el vault directamente.

Cargado con ``mitmdump -s`` tambien funciona, pero sin vault: registra
metadatos y digests, y no puede afirmar nada sobre el contenido. El reporte lo
dice en lugar de callarlo.

Concurrencia
------------

mitmproxy corre en su propio bucle de asyncio, en otro hilo. El expediente es
SQLite y una cadena de hashes: escribir desde dos hilos romperia el orden de la
cadena, que es justamente lo que la hace verificable. El addon por tanto **no
escribe**: encola observaciones y el hilo principal las vuelca con
:meth:`drain`, igual que hace el observador de CDP con sus eventos.
"""

from __future__ import annotations

import hashlib
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from ..audit_core.events import Tag
from ..audit_core.secrets import SecretVault

#: Cuerpos mayores que esto no se escanean enteros: se busca en los extremos,
#: donde un payload de exfiltracion pone casi siempre su carga.
MAX_SCAN_BYTES = 8 * 1024 * 1024

#: Limite de destinos con fallo de TLS que se detallan en el resumen.
MAX_TLS_FAILURES = 20

#: Tipos de contenido cuyo cuerpo no vale la pena escanear.
SKIP_CONTENT_TYPES = ("image/", "video/", "audio/", "font/")


@dataclass
class ProxyUpdate:
    """Resultado de una peticion ya encolada: llega despues que ella."""

    observation_id: str
    status: int | None = None
    response_size: int | None = None


@dataclass
class ProxyObservation:
    """Una peticion vista por el proxy, lista para que el hilo principal la escriba."""

    id: str
    timestamp: float
    method: str
    url: str
    host: str
    headers: dict[str, str]
    body: bytes | None
    body_size: int
    body_digest: str
    content_type: str
    tags: list[str] = field(default_factory=list)
    canary_matches: list[dict[str, Any]] = field(default_factory=list)
    http_version: str = ""
    tls: bool = False
    #: Cierto si el cuerpo no estaba disponible para CDP: es el aporte propio
    #: del proxy y la razon de que exista este sensor.
    body_recovered: bool = False


class FirmaScopeAddon:
    """Addon de mitmproxy que observa los cuerpos salientes.

    Es deliberadamente pasivo: no modifica, no bloquea y no reescribe nada. El
    aislamiento de red es trabajo del controlador del navegador, que aborta la
    peticion antes de que llegue aqui. Un proxy que tambien bloqueara haria
    ambiguo el registro: no se sabria cual de los dos la detuvo.
    """

    def __init__(self, vault: SecretVault | None = None,
                 capture_bodies: bool = False, max_body_bytes: int = 0):
        self.vault = vault
        self.capture_bodies = capture_bodies
        self.max_body_bytes = max_body_bytes
        self._queue: deque[ProxyObservation] = deque()
        self._updates: deque[ProxyUpdate] = deque()
        #: id(flow) -> id de la observacion, para unir la respuesta con su peticion.
        self._in_flight: dict[int, str] = {}
        self._lock = threading.Lock()
        self.seen = 0
        self.scanned = 0
        self.with_canaries = 0
        self.tls_failures: list[dict[str, Any]] = []
        self._tls_by_host: dict[str, dict[str, Any]] = {}

    # -- interfaz para el hilo principal --------------------------------
    def drain(self) -> tuple[list[ProxyObservation], list[ProxyUpdate]]:
        """Extrae lo observado hasta ahora. Unico punto de contacto entre hilos."""
        with self._lock:
            items = list(self._queue)
            updates = list(self._updates)
            self._queue.clear()
            self._updates.clear()
        return items, updates

    def summary(self) -> dict[str, Any]:
        return {
            "requests_seen": self.seen,
            "bodies_scanned": self.scanned,
            "requests_with_canaries": self.with_canaries,
            "tls_failures": list(self.tls_failures),
            "tls_failure_hosts": len(self._tls_by_host),
            "has_vault": self.vault is not None and self.vault.alive,
        }

    # -- ganchos de mitmproxy -------------------------------------------
    def request(self, flow) -> None:  # pragma: no cover - lo llama mitmproxy
        try:
            self._observe(flow)
        except Exception:
            # Un fallo del sensor no debe romper la navegacion de la sesion.
            pass

    def response(self, flow) -> None:  # pragma: no cover - lo llama mitmproxy
        """La respuesta llega despues de que la peticion ya se encolo.

        No se modifica la observacion -- el hilo principal puede haberla escrito
        ya, y reescribir un registro encadenado romperia la cadena. Se encola
        una actualizacion, que el expediente aplica como tal.
        """
        try:
            with self._lock:
                observation_id = self._in_flight.pop(id(flow), None)
            if observation_id is None:
                return
            update = ProxyUpdate(
                observation_id=observation_id,
                status=int(flow.response.status_code),
                response_size=len(flow.response.raw_content or b""),
            )
            with self._lock:
                self._updates.append(update)
        except Exception:
            pass

    def tls_failed_client(self, data) -> None:  # pragma: no cover
        """Un fallo de TLS del cliente deja un hueco en la observacion.

        Si el navegador rechaza la CA efimera, ese destino deja de verse y el
        silencio podria leerse como ausencia de trafico. Se registra para que el
        reporte pueda decir que ahi no hay observacion, en lugar de nada.
        """
        try:
            sni = str(getattr(data.context.client, "sni", "") or "")
            with self._lock:
                # Se agrupa por destino: un cliente que reintenta no debe
                # convertir un hueco en veinte.
                entry = self._tls_by_host.get(sni)
                if entry is None:
                    entry = {"sni": sni, "attempts": 0,
                             "error": str(getattr(data, "conn", None)
                                          and data.conn.error or "")}
                    self._tls_by_host[sni] = entry
                    if len(self._tls_by_host) <= MAX_TLS_FAILURES:
                        self.tls_failures.append(entry)
                entry["attempts"] += 1
        except Exception:
            pass

    # -- interno ---------------------------------------------------------
    def _observe(self, flow) -> None:
        request = flow.request
        body = request.raw_content or b""
        content_type = request.headers.get("content-type", "")

        tags, matches = self._classify(body, content_type)
        observation = ProxyObservation(
            id=uuid.uuid4().hex,
            timestamp=getattr(request, "timestamp_start", 0.0) or 0.0,
            method=request.method,
            url=request.pretty_url,
            host=request.pretty_host,
            headers=_clip_headers(dict(request.headers)),
            body=self._keep(body),
            body_size=len(body),
            body_digest=hashlib.sha256(body).hexdigest() if body else "",
            content_type=content_type,
            tags=tags,
            canary_matches=[m.to_dict() for m in matches],
            http_version=str(getattr(request, "http_version", "")),
            tls=request.scheme == "https",
            # multipart y los flujos son precisamente los que CDP no entrega.
            body_recovered=bool(body) and (
                "multipart/form-data" in content_type
                or "application/octet-stream" in content_type
                or request.headers.get("transfer-encoding", "") == "chunked"
            ),
        )

        self.seen += 1
        if matches:
            self.with_canaries += 1
        with self._lock:
            self._in_flight[id(flow)] = observation.id
            self._queue.append(observation)

    def _keep(self, body: bytes) -> bytes | None:
        """Devuelve el cuerpo solo si el operador habilito su persistencia."""
        if not body or not self.capture_bodies or self.max_body_bytes <= 0:
            return None
        return body[: self.max_body_bytes]

    def _classify(self, body: bytes, content_type: str) -> tuple[list[str], list]:
        """Busca representaciones de canarios dentro del cuerpo."""
        if not body:
            return [], []
        if any(content_type.startswith(prefix) for prefix in SKIP_CONTENT_TYPES):
            return [], []
        if self.vault is None or not self.vault.alive:
            # Sin vault no se puede afirmar nada del contenido. Se dice que el
            # cuerpo es opaco, que es verdad, en lugar de sugerir que es inocuo.
            return [Tag.UNCLASSIFIED.value], []

        self.scanned += 1
        matches = self.vault.scan(_scannable(body))
        tags = sorted({m.label for m in matches})
        return (tags or [Tag.UNCLASSIFIED.value]), matches


def _scannable(body: bytes) -> bytes:
    """Recorta un cuerpo enorme conservando sus extremos."""
    if len(body) <= MAX_SCAN_BYTES:
        return body
    half = MAX_SCAN_BYTES // 2
    return body[:half] + body[-half:]


def _clip_headers(headers: dict[str, str], limit: int = 512) -> dict[str, str]:
    """Cabeceras recortadas y sin credenciales de sesion."""
    sensitive = {"authorization", "cookie", "proxy-authorization", "set-cookie"}
    out: dict[str, str] = {}
    for name, value in list(headers.items())[:40]:
        lowered = name.lower()
        if lowered in sensitive:
            out[name] = f"<{len(value)} bytes omitidos>"
            continue
        out[name] = value[:limit]
    return out


#: mitmproxy busca una lista llamada ``addons`` al cargar un script. Permite
#: ``mitmdump -s addon.py`` para inspeccion manual, sin vault y por tanto sin
#: deteccion por contenido.
addons = [FirmaScopeAddon()]
