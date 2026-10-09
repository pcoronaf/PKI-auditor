"""Integracion opcional con mitmproxy: el sensor de red de nivel 4.

mitmproxy es una dependencia opcional (``pip install 'firmascope[proxy]'``).
Este paquete se importa sin ella; solo :meth:`ProxyRunner.start` la exige.
"""

from .addon import FirmaScopeAddon, ProxyObservation, ProxyUpdate
from .runner import ProxyRunner, available, version

__all__ = ["FirmaScopeAddon", "ProxyObservation", "ProxyRunner", "ProxyUpdate",
           "available", "version"]
