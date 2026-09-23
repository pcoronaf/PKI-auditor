# FirmaScope

**Auditor defensivo de custodia de claves privadas en aplicaciones web de firma
electrónica**, con énfasis en la e.firma del SAT.

FirmaScope no emite una calificación genérica de “sitio seguro”. Responde, con
evidencia reproducible, preguntas verificables:

- ¿Dónde se procesa la clave privada?
- ¿La firma se genera localmente?
- ¿Se transmite la clave, la contraseña, o datos derivados de ellas?
- ¿Qué comunicaciones ocurren después de que el navegador accede a la clave?

Y distingue rigurosamente entre **“no observé transmisión de la clave”** y
**“la clave no puede transmitirse”**. Los reportes son conservadores,
reproducibles y basados en evidencia.

> **Estado: alfa funcional.** Los cuatro niveles, con sus cuatro sensores, se
> ejecutan de extremo a extremo sobre las aplicaciones de laboratorio. Ver [Estado de implementación](#estado-de-implementación).

Licencia: Apache-2.0.

---

## Modelo de auditoría por niveles

| Nivel | Nombre | Qué responde |
|---|---|---|
| 1 | Network Observer | DevTools Network automatizado y reproducible |
| 2 | Front-End Code Analyzer | ¿qué *podría* hacer el código aunque no haya ocurrido? |
| 3 | Local Signing Test | ¿la firma se completa con la red aislada? |
| 4 | Full Correlated Audit | instrumentación + CDP + estático + proxy + correlación |

## Estados de conclusión

| Estado | Significado |
|---|---|
| `CONFIRMED` | demostrado experimentalmente bajo las condiciones registradas |
| `OBSERVED` | ocurrió durante esta ejecución |
| `POTENTIAL` | el código contiene una ruta viable, no ejecutada |
| `NOT_OBSERVED` | no se observó en esta ejecución — **no** equivale a imposible |
| `INCONCLUSIVE` | no hay evidencia suficiente |

## Etiquetas de procedencia

```text
S1 KEY_FILE      bytes del .key
S2 KEY_PASSWORD  contraseña de la clave
S3 PRIVATE_KEY   clave privada descifrada / CryptoKey privada
S4 CERTIFICATE   certificado .cer (material público)
S5 DOCUMENT      documento a firmar
S6 SIGNATURE     firma resultante
   DERIVED       marca de transformación (p. ej. cifrado del material)
```

Una transformación legítima es `S1 + S2 --decrypt--> S3` y `S3 + S5 --sign--> S6`.
Un caso sospechoso es `S3 --encrypt--> S7 [derived-from PRIVATE_KEY] --fetch()-->`:
el sistema no necesita interpretar el contenido de `S7`, le basta con establecer
que el dato enviado deriva de material privado.

La firma (`S6`) es el producto legítimo de la operación y **no** arrastra la
procedencia privada: si lo hiciera, el envío de la firma — que todo sitio
correcto debe hacer — se reportaría como exfiltración.

---

## Protección de secretos

- Los secretos observados **no se escriben a disco**.
- La correlación usa `HMAC(clave-de-sesión aleatoria, secreto)`; la clave vive
  sólo en memoria y se destruye al terminar la sesión.
- La captura completa de cuerpos HTTP está **deshabilitada por defecto**.
- FirmaScope no envía información de auditoría a ningún servicio externo.
- Las credenciales sintéticas declaran en su sujeto que **no** son certificados
  del SAT. La herramienta no promueve el uso de credenciales de producción.

---

## Arquitectura

```text
                       CLI / UI
                          |
                  Audit Orchestrator
      Session Manager  Correlation Engine  Rule Engine
      Evidence Store   Report Generator
         |                |                 |
  Browser Controller  Static JS Analyzer  Network Observation
  (Playwright/CDP)    (AST + taint)       (CDP + proxy)
         |                                  |
  Chromium instrumentado  <-------------> mitmproxy (opcional)
```

### Mapa especificación → repositorio

La especificación describe un monorepo con `packages/<componente>`. Aquí cada
componente es un subpaquete de una única distribución instalable, lo que evita
un *workspace* multi-paquete sin ganar acoplamiento:

| Componente de la especificación | Módulo |
|---|---|
| `packages/audit-core` | `firmascope.audit_core` |
| `packages/browser-controller` | `firmascope.browser_controller` |
| `packages/instrumentation-agent` | `firmascope.instrumentation_agent` |
| `packages/static-analyzer` | `firmascope.static_analyzer` |
| `packages/network-analyzer` | `firmascope.network_analyzer` |
| `packages/proxy-addon` | `firmascope.proxy_addon` |
| `packages/correlation-engine` | `firmascope.correlation_engine` |
| `packages/rule-engine` | `firmascope.rule_engine` |
| `packages/evidence-store` | `firmascope.evidence_store` |
| `packages/report-engine` | `firmascope.report_engine` |
| `apps/cli` | `firmascope.cli` |

Otras desviaciones deliberadas respecto de la especificación:

- **El agente de instrumentación es JavaScript, no TypeScript.** Se inyecta tal
  cual, sin paso de compilación: en una herramienta de seguridad, que el código
  ejecutado en el navegador sea byte a byte el del repositorio es más valioso
  que el tipado estático. Su SHA-256 se registra en `manifest.json`.
- **Python 3.10+** en lugar de 3.12+, para ampliar la base de ejecución.
- **El catálogo de reglas añade la categoría `code`** a las cuatro de la
  especificación (`crypto`, `network`, `storage`, `efirma`), para las reglas que
  provienen del análisis estático y no de un canal concreto.

---

## Estado de implementación

| Componente | Estado |
|---|---|
| Modelo de eventos y etiquetas de procedencia | implementado, con pruebas |
| Estados de conclusión | implementado, con pruebas |
| Vault de secretos, canarios y redacción | implementado, con pruebas |
| Configuración por niveles | implementado, con pruebas |
| Expediente SQLite + cadena de hashes | implementado, con pruebas |
| Agente de instrumentación (sources, WebCrypto, sinks, storage, workers) | implementado, con pruebas e2e |
| Observación de red por CDP y clasificación de terceros | implementado, con pruebas e2e |
| Controlador de navegador (perfil efímero, aislamiento de red, inventario de scripts) | implementado, con pruebas e2e |
| Credenciales sintéticas | implementado, con pruebas |
| Analizador estático (AST, taint interprocedural, source maps) | implementado, con pruebas |
| Motor de reglas y catálogo `FS-*` (12 reglas) | implementado, con pruebas |
| Motor de correlación | implementado, con pruebas |
| Motor de reportes (HTML + JSON) | implementado, con pruebas |
| CLI (`firmascope audit ...`) | implementado, con pruebas |
| Aplicaciones de laboratorio | implementadas, con pruebas e2e |
| Addon de mitmproxy (nivel 4, CA efímera) | implementado, con pruebas e2e |
| Pruebas TC-001..TC-006 | **verdes** |

La suíte son 224 pruebas unitarias más 23 extremo a extremo que lanzan un
Chromium real contra las nueve aplicaciones de laboratorio (dos de ellas en
nivel 4, con el proxy interpuesto):

```bash
pytest -m "not e2e"    # rápido, sin navegador
pytest -m e2e          # TC-001..TC-006 sobre el laboratorio
```

### Comportamiento de referencia

Lo que la herramienta concluye hoy sobre cada aplicación de laboratorio:

| Aplicación | Conclusión |
|---|---|
| `demo-safe` | sin hallazgos — firma local, sólo sale la firma |
| `demo-key-exfiltration` | `FS-KEY-001` y `FS-PWD-001` OBSERVED |
| `demo-encrypted-exfiltration` | `FS-NET-002` OBSERVED, `FS-KEY-002` POTENTIAL |
| `demo-server-sign` | `FS-KEY-001` y `FS-PWD-001` OBSERVED |
| `demo-static-only` | sólo `FS-CODE-001` POTENTIAL |
| `demo-worker` | `FS-KEY-001` OBSERVED — la fuga ocurre dentro de un Web Worker |
| `demo-side-channels` | `FS-KEY-001`, `FS-PWD-001` y `FS-NET-001` OBSERVED — beacon y píxel hacia un tercero |
| `demo-minified` | `FS-KEY-001` y `FS-PWD-001` OBSERVED, `FS-CODE-001` POTENTIAL — código empaquetado con terser |
| `demo-login` | sin hallazgos con `--session`; con `--manual`, `FS-LOCAL-001` CONFIRMADO |

Las dos filas que más dicen son la primera y la última. Que `demo-safe` no
produzca ningún hallazgo es lo que hace utilizable al resto del catálogo: una
herramienta que marca a las aplicaciones correctas no sirve para auditar
ninguna. Y que `demo-static-only` produzca `POTENTIAL` sin producir
`OBSERVED` es la separación entre los niveles 1 y 2: nada salió — eso es
cierto — pero el código cargado puede hacerlo.

Los tres últimos laboratorios existen para poner a prueba los supuestos de la
herramienta, y cada uno encontró algo:

- `demo-worker` mostró que la instrumentación **rompía** los workers del sitio:
  los cargaba desde un `blob:`, donde toda ruta relativa falla. Ahora el
  worker conserva su URL real y el agente se antepone a su script al
  descargarlo. La procedencia además cruza `postMessage`, así que la fuga
  desde el worker se ve en nivel 3 sin necesidad del proxy.
- `demo-side-channels` mostró que un `.key` enviado en la query de un píxel
  era invisible para CDP y el proxy, que solo miraban el cuerpo — y, peor,
  que esa URL **se guardaba sin redactar en el expediente**. Ahora se buscan
  canarios también en la URL (en su forma decodificada) y las peticiones se
  redactan igual que los eventos.
- `demo-minified` mostró que el análisis estático dependía de los nombres de
  variable. Sin ellos no encontraba nada; y al corregirlo aparecieron dos
  falsos positivos sobre la entrega de la firma (retornos que no distinguían
  el punto de llamada, y nombres reutilizados en bloques). Ahora la ruta se
  encuentra por las APIs y por los ids del HTML, que la minificación no toca.

`demo-encrypted-exfiltration` merece una nota. El seguimiento de procedencia
no atraviesa un bucle que construye una cadena carácter a carácter, así que
FirmaScope **no** afirma haber seguido el dato hasta la salida. Afirma lo que
sí sostiene: que salió un cuerpo opaco después del acceso a la clave, y que
el código contiene la ruta. Esa es la respuesta honesta, y es deliberado que
no sea la más contundente.

## Uso

```bash
pip install -e .

firmascope credentials new -o creds     # credenciales sintéticas de laboratorio
firmascope labs serve                   # http://127.0.0.1:8000
firmascope audit http://127.0.0.1:8000/demo-key-exfiltration/ --level 3
firmascope rules                        # catálogo de reglas
firmascope verify audits/FS-XXXX-XXXX   # cadena de integridad del expediente
```

En modo `synthetic` (el de por defecto) FirmaScope genera un par .key/.cer de
laboratorio, lo registra en el vault —de modo que cada representación
buscable queda disponible como canario— y lo entrega al formulario del sitio.
Si no reconoce el formulario lo dice y sugiere `--headed`, para que el
operador conduzca la sesión a mano: rellenar el formulario equivocado sería
peor que no rellenar ninguno.


### Plataformas con inicio de sesión

Si la plataforma exige iniciar sesión antes de llegar al formulario de firma,
el inicio de sesión se separa de la auditoría. **FirmaScope nunca ve la
contraseña de la plataforma**: la escribe el operador en un navegador visible.

Instalación en **Windows (PowerShell)** — la vía más sencilla para una
auditoría con navegador visible:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1      # si PowerShell lo bloquea: Set-ExecutionPolicy -Scope Process Bypass
pip install -e ".[proxy]"
playwright install chromium
```

En **WSL** hacen falta además las bibliotecas del sistema de Chromium
(`sudo .venv/bin/playwright install-deps chromium`) y WSLg (Windows 11) para
ver el navegador. Clona el repositorio dentro del sistema de ficheros de Linux
(`~/`), no en `/mnt/c/...`: ahí los permisos `0600` no se aplican, y si la
carpeta está en OneDrive el expediente se sincronizaría a la nube.

```bash
# 1. Inicia sesión a mano con la cuenta de PRUEBA; se guardan solo las cookies.
firmascope login https://plataforma.example/login --save ~/firmascope/sesion.json

# 2. Audita ya dentro de la sesión.
firmascope audit https://plataforma.example/firmar --session ~/firmascope/sesion.json

# 2b. Si el formulario de firma no se reconoce solo, condúcelo tú:
firmascope audit https://plataforma.example/firmar --session ~/firmascope/sesion.json --manual
```

En modo `--manual` FirmaScope abre el navegador, te da las credenciales
sintéticas que debes usar y espera a que firmes. En nivel 3 o superior te
pide después **repetir la firma con la red aislada**: si la aplicación firma
sin red, `FS-LOCAL-001` queda CONFIRMADO, que es la evidencia más fuerte que la
herramienta puede dar a favor de un sitio.

El fichero de sesión es una credencial: permite entrar en la cuenta mientras la
sesión siga activa. Se escribe con permisos `0600`, sus valores se protegen en
el vault para que no lleguen nunca al expediente y el manifiesto solo registra
que la sesión estaba autenticada. Guárdalo fuera de cualquier repositorio y, al
terminar, cierra la sesión en la plataforma y borra el fichero.

El navegador se lanza **con** el sandbox de Chromium. Playwright lo desactiva
por defecto, así que FirmaScope lo pide de forma explícita; solo se desactiva
al ejecutar como root (lo típico de un contenedor) o si el operador lo decide
con `--no-sandbox`.

### El proxy (nivel 4)

La instrumentación ve lo que el JavaScript *pide* enviar; CDP, lo que el
navegador *dice* que envía. El proxy ve lo que efectivamente sale por el
cable, ya codificado: el multipart con sus fronteras, el cuerpo tras la
compresión, los frames de WebSocket. Es el único sensor que no depende de la
cooperación del navegador, y por eso su coincidencia con los otros dos es la
corroboración más valiosa del expediente. En `demo-server-sign` las tres
vistas de la subida se funden en **una** cadena, sostenida por agente, CDP,
proxy y el canario del `.key` encontrado en bruto dentro del multipart.

```bash
pip install -e ".[proxy]"
firmascope audit <url> --level 4              # proxy activo si está instalado
firmascope audit <url> --level 4 --no-proxy   # tres sensores
```

- **CA efímera.** La autoridad certificadora de mitmproxy se genera en un
  directorio temporal por sesión y se borra al terminar. Nunca se instala en
  el almacén del sistema: sólo la acepta el contexto del navegador de
  auditoría, que muere con la sesión.
- **Degradación explícita.** Sin mitmproxy instalado, el nivel 4 sigue con
  tres sensores y el manifiesto lo dice. Nunca se finge un sensor que no
  corrió.
- **Sin cuerpos por defecto.** El proxy busca canarios en memoria y registra
  tamaños y digests. `Authorization` y `Cookie` se omiten del expediente.

## Documentación

- [`docs/evidence-model.md`](docs/evidence-model.md) — expediente, cadena de
  integridad y protección de secretos.
- [`docs/rule-development.md`](docs/rule-development.md) — catálogo de reglas,
  cómo escribir una nueva y cómo elegir el estado de conclusión.

---

## Dependencias

```text
Python >= 3.10
playwright      control del navegador y CDP
cryptography    credenciales sintéticas
PyYAML          paquetes de reglas
tree-sitter     análisis estático de JavaScript
mitmproxy       opcional, nivel 4
```

FirmaScope busca un Chromium ya instalado (variable `FIRMASCOPE_CHROMIUM_PATH`,
`PLAYWRIGHT_BROWSERS_PATH` o `/opt/pw-browsers`) antes de recurrir al de
Playwright.

---

## Advertencia de uso

FirmaScope es una herramienta **defensiva**. Está pensada para auditar sitios
propios o sitios sobre los que se tiene autorización de prueba, usando
credenciales sintéticas de laboratorio. No la uses con tu e.firma real.
