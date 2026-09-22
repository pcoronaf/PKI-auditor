"""Estados de conclusion.

FirmaScope no emite un score generico. Por cada propiedad evaluada emite uno
de estos estados, y la diferencia entre ellos es el nucleo etico de la
herramienta: ``NOT_OBSERVED`` nunca significa "imposible".
"""

from __future__ import annotations

import enum


class Status(str, enum.Enum):
    #: Demostrado experimentalmente bajo las condiciones de la prueba.
    CONFIRMED = "CONFIRMED"
    #: Ocurrio durante esta ejecucion.
    OBSERVED = "OBSERVED"
    #: El codigo contiene una ruta viable, pero no se ejecuto en esta sesion.
    POTENTIAL = "POTENTIAL"
    #: No se observo durante esta ejecucion. NO equivale a imposible.
    NOT_OBSERVED = "NOT_OBSERVED"
    #: No hay evidencia suficiente para afirmar ni negar.
    INCONCLUSIVE = "INCONCLUSIVE"


#: Orden de severidad para presentacion (mayor = mas relevante para el lector).
SEVERITY_ORDER = {
    Status.CONFIRMED: 4,
    Status.OBSERVED: 3,
    Status.POTENTIAL: 2,
    Status.INCONCLUSIVE: 1,
    Status.NOT_OBSERVED: 0,
}

#: Texto normativo que acompana a cada estado en los reportes.
STATUS_MEANING = {
    Status.CONFIRMED: (
        "Demostrado experimentalmente bajo las condiciones registradas en el manifiesto."
    ),
    Status.OBSERVED: "Ocurrio durante esta ejecucion de la prueba.",
    Status.POTENTIAL: (
        "El codigo cargado contiene una ruta viable; no se observo su ejecucion."
    ),
    Status.NOT_OBSERVED: (
        "No se observo durante esta ejecucion. No constituye prueba de imposibilidad."
    ),
    Status.INCONCLUSIVE: "No existe evidencia suficiente para concluir.",
}


class Severity(str, enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
