"""FirmaScope: auditor defensivo de custodia de claves privadas en aplicaciones web.

FirmaScope observa como una aplicacion web procesa material criptografico
sensible (.key, .cer, contrasena, documento) durante una operacion de firma
electronica, y produce evidencia reproducible en lugar de una calificacion
generica de "seguro" / "inseguro".
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
