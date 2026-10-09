"""Piloto automatico: recorrer las etapas sin nadie delante.

Una auditoria interactiva necesita a una persona que cargue el ``.key`` en el
portal. Eso es lo correcto con una e.firma propia, pero impide lo que mas valor
tiene a escala: auditar un portal cada noche, en integracion continua, o volver
a auditarlo tras cada despliegue para ver si su comportamiento cambio.

El piloto hace lo que haria el operador -- esperar a que carguen los recursos,
rellenar el formulario de firma con la red cortada, enviar la firma con la red
restablecida -- sobre la misma maquina de etapas que usan la CLI y la interfaz.
No hay un tercer camino que pudiera, por ejemplo, olvidar restablecer la red.

Solo con credencial sintetica
-----------------------------

El piloto se niega a funcionar con cualquier otra credencial. Rellenar
automaticamente una e.firma real en un portal sin caracterizar seria entregar
la clave sin que nadie vea a quien. La credencial sintetica no es de nadie: si
el portal la exfiltra, no se ha perdido nada y la auditoria ya tiene su
respuesta.
"""

from __future__ import annotations

import time
from typing import Any

from ..audit_core.config import CredentialMode
from ..audit_core.events import Event, EventType
from . import forms
from .isolation import Stage, StageAction

#: Segundos por defecto en cada etapa, para que los recursos carguen y los
#: sensores tengan algo que observar.
DEFAULT_DWELL = 3.0
#: Segundos en la etapa de firma: lo que tarde el sitio en descifrar y firmar,
#: y en intentar -- si lo hace -- sacar algo por la red.
DEFAULT_OFFLINE_DWELL = 4.0


class AutopilotRefused(ValueError):
    """El piloto no puede funcionar con esta configuracion."""


def check_allowed(credential_mode: CredentialMode) -> None:
    """Lanza :class:`AutopilotRefused` si la credencial no es sintetica."""
    if credential_mode is not CredentialMode.SYNTHETIC:
        raise AutopilotRefused(
            "el piloto automatico solo funciona con la credencial sintetica de "
            "laboratorio. Con una credencial propia o real, FirmaScope no rellena "
            "el formulario: lo hace usted, viendo a que sitio se la entrega.")


class Autopilot:
    """Hace el trabajo de cada etapa y devuelve el control.

    Funciona en los dos modos de la maquina de etapas: como controlador de
    empuje (``__call__``, para la CLI) y como accion al entrar en una etapa
    (:meth:`act`, para la interfaz grafica, donde quien avanza es el operador).
    """

    def __init__(self, session: Any, dwell: float = DEFAULT_DWELL,
                 offline_dwell: float = DEFAULT_OFFLINE_DWELL):
        check_allowed(session.config.credential_mode)
        self.session = session
        self.dwell = max(0.0, float(dwell))
        self.offline_dwell = max(0.0, float(offline_dwell))
        self.signed = False
        self.sent = False
        self.notes: list[str] = []

    # -- controlador de empuje -------------------------------------------
    def __call__(self, stage: Stage, index: int, test: Any) -> StageAction:
        self.act(stage)
        return StageAction.CONTINUE

    # -- trabajo de cada etapa -----------------------------------------
    def act(self, stage: Stage, wait: bool = True) -> None:
        """Hace lo que la etapa pide. ``wait`` controla las esperas."""
        if stage.name == "sign":
            self._sign()
            if wait:
                self._wait(self.offline_dwell)
            return
        if stage.name == "submit":
            self._send()
        if wait:
            self._wait(self.dwell)

    def _sign(self) -> None:
        controller = self.session.controller
        credential = self.session.credential
        if credential is None or controller is None or controller.page is None:
            self._checkpoint("credenciales-no-entregadas",
                             "no hay credencial ni pagina a la que entregarla")
            return
        form = forms.detect(controller.page)
        if not form.usable:
            note = "; ".join(form.notes) or "formulario no reconocido"
            self.notes.append(note)
            self._checkpoint(
                "credenciales-no-entregadas",
                f"no se reconocio el formulario de firma: {note}. Conduzca la "
                "sesion a mano para este portal.", form=form.describe())
            return
        forms.provide(controller.page, credential, form)
        self._checkpoint("credenciales-entregadas",
                         "clave sintetica y contrasena introducidas en el formulario",
                         form=form.describe())
        self.signed = forms.submit(controller.page, form)
        self._checkpoint(
            "firma-solicitada" if self.signed else "firma-no-disparada",
            "se pulso el boton de firma" if self.signed
            else "no se encontro un boton de firma que pulsar")

    def _send(self) -> None:
        controller = self.session.controller
        if controller is None or controller.page is None:
            return
        self.sent = forms.send(controller.page)
        self._checkpoint(
            "firma-enviada" if self.sent else "envio-no-separado",
            "se pulso el boton de envio de la firma" if self.sent
            else "el sitio no separa firmar de enviar, o ya lo hizo al firmar")

    def _wait(self, seconds: float) -> None:
        controller = self.session.controller
        if seconds <= 0 or controller is None:
            return
        deadline = time.time() + seconds
        while time.time() < deadline:
            controller.drain_agent()
            controller.pump()
            try:
                controller.page.wait_for_timeout(250)
            except Exception:
                time.sleep(0.25)

    def _checkpoint(self, name: str, detail: str, **extra: Any) -> None:
        self.session.emit(Event(EventType.CHECKPOINT, self.session.session_id,
                                sensor="autopilot",
                                data={"name": name, "detail": detail, **extra}))
