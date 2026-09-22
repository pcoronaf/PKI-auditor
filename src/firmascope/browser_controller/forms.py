"""Entrega de credenciales sinteticas al sitio auditado.

En modo ``synthetic`` FirmaScope genera un par .key/.cer de laboratorio, lo
registra en el vault — de modo que cada representacion buscable del material
queda disponible como canario — y lo entrega al formulario del sitio.

Esa entrega es lo que hace observable el resto de la auditoria. Sin ella la
sesion nunca llega a manejar material privado y todas las reglas devuelven
``INCONCLUSIVE``, que es honesto pero inutil.

La deteccion del formulario es heuristica y deliberadamente conservadora: si
no encuentra los campos, lo dice y deja que el operador conduzca la sesion a
mano (``--headed``). Rellenar el formulario equivocado seria peor que no
rellenar ninguno.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: Selectores de campo de archivo para la clave privada, del mas al menos especifico.
KEY_FILE_SELECTORS = (
    'input[type=file][accept*=".key"]',
    'input[type=file][id*="key" i]',
    'input[type=file][name*="key" i]',
    'input[type=file][id*="llave" i]',
    'input[type=file][name*="llave" i]',
)

#: Selectores del campo de archivo para el certificado.
CERT_FILE_SELECTORS = (
    'input[type=file][accept*=".cer"]',
    'input[type=file][accept*=".crt"]',
    'input[type=file][id*="cer" i]',
    'input[type=file][name*="cer" i]',
    'input[type=file][id*="cert" i]',
    'input[type=file][name*="cert" i]',
)

PASSWORD_SELECTORS = (
    "input[type=password]",
    'input[id*="pass" i]',
    'input[id*="contrase" i]',
    'input[name*="pass" i]',
)

#: Textos habituales del boton que dispara la firma.
SUBMIT_TEXTS = ("firmar", "firma", "sign", "continuar", "aceptar", "enviar")

SUBMIT_SELECTORS = (
    "#sign",
    "button[type=submit]",
    "input[type=submit]",
)


@dataclass
class DetectedForm:
    """Campos encontrados en la pagina."""

    key_input: Any | None = None
    cert_input: Any | None = None
    password_input: Any | None = None
    submit: Any | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        """Con la clave y la contrasena basta para ejercitar el flujo."""
        return self.key_input is not None and self.password_input is not None

    def describe(self) -> dict[str, Any]:
        return {
            "key_input": self.key_input is not None,
            "cert_input": self.cert_input is not None,
            "password_input": self.password_input is not None,
            "submit": self.submit is not None,
            "usable": self.usable,
            "notes": list(self.notes),
        }


def _first_visible(page: Any, selectors: tuple[str, ...]) -> Any | None:
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if locator.count() > 0:
                return locator
        except Exception:
            continue
    return None


def _submit_button(page: Any) -> Any | None:
    button = _first_visible(page, SUBMIT_SELECTORS)
    if button is not None:
        return button
    for text in SUBMIT_TEXTS:
        try:
            locator = page.get_by_role("button", name=text, exact=False).first
            if locator.count() > 0:
                return locator
        except Exception:
            continue
    return None


def detect(page: Any) -> DetectedForm:
    """Localiza los campos del formulario de firma."""
    form = DetectedForm()
    form.key_input = _first_visible(page, KEY_FILE_SELECTORS)
    form.cert_input = _first_visible(page, CERT_FILE_SELECTORS)
    form.password_input = _first_visible(page, PASSWORD_SELECTORS)
    form.submit = _submit_button(page)

    if form.key_input is None:
        # Ultimo recurso: un unico input[type=file] en la pagina es, casi con
        # seguridad, el de la clave. Con dos o mas no se adivina.
        try:
            files = page.locator("input[type=file]")
            if files.count() == 1:
                form.key_input = files.first
                form.notes.append("campo de clave deducido: unico input[type=file]")
        except Exception:
            pass

    if form.key_input is None:
        form.notes.append("no se encontro un campo de archivo para la clave privada")
    if form.password_input is None:
        form.notes.append("no se encontro un campo de contrasena")
    if form.submit is None:
        form.notes.append("no se encontro el boton de firma")
    return form


def provide(page: Any, credential: Any, form: DetectedForm | None = None) -> DetectedForm:
    """Rellena el formulario con la credencial sintetica.

    No pulsa el boton: enviar es un acto distinto de rellenar, y el orquestador
    quiere registrar un hito entre ambos.
    """
    form = form or detect(page)
    if form.key_input is not None and credential.key_path is not None:
        form.key_input.set_input_files(str(credential.key_path))
    if form.cert_input is not None and credential.cert_path is not None:
        form.cert_input.set_input_files(str(credential.cert_path))
    if form.password_input is not None:
        form.password_input.fill(credential.password)
    return form


def submit(page: Any, form: DetectedForm) -> bool:
    """Dispara la firma. Devuelve si llego a pulsarse algo."""
    if form.submit is None:
        return False
    try:
        form.submit.click(timeout=5_000)
        return True
    except Exception:
        return False
