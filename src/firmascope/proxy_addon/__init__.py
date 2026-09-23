"""Integracion opcional con mitmproxy: el sensor de red de nivel 4.

mitmproxy es una dependencia opcional (``pip install 'firmascope[proxy]'``).
Este paquete se importa sin ella; solo ``ProxyServer.start`` la exige.
"""

from .addon import FirmaScopeAddon, ProxyRecord
from .server import ProxyServer, ProxyUnavailable, available

__all__ = ["FirmaScopeAddon", "ProxyRecord", "ProxyServer", "ProxyUnavailable", "available"]
