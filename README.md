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

> **Estado: completo y verificado contra el laboratorio.** Las pruebas
> TC-001..TC-011 se ejecutan con un Chromium real y comparan cada hallazgo con
> la verdad conocida del laboratorio; la interfaz gráfica se prueba contra el
> núcleo de verdad. Ver
> [Estado de implementación](#estado-de-implementación).

Licencia: Apache-2.0.

---

## Uso

```bash
pip install -e .
playwright install chromium     # o use --browser-path con un Chromium propio
firmascope audit                # el asistente pregunta todo lo necesario
```

`firmascope audit` no exige ningún argumento. Si hay terminal, abre un asistente
que pregunta el sitio, el nivel, el tipo de credencial y el aislamiento de red, y
permite revisarlo y corregirlo antes de arrancar. **La URL puede omitirse**: se
proporciona después con `url <dirección>`, o navegando en la ventana del
navegador.

```text
firmascope audit [URL]        auditar un sitio
firmascope audit URL --auto   auditar sin operador (sólo credencial sintética)
firmascope login URL          iniciar sesión en el portal y guardarla (--session)
firmascope panel [URL]        la interfaz en el navegador (abre un puerto local)
firmascope options            listar las opciones configurables (--json para una GUI)
firmascope credentials new    generar una credencial sintética de laboratorio
firmascope rules [--json]     listar el catálogo (--rules DIR añade paquetes propios)
firmascope labs list|serve    aplicaciones de laboratorio
firmascope verify DIR         verificar la cadena de evidencias de un expediente
```

### Auditoría desatendida

```bash
firmascope audit https://portal.ejemplo.mx --auto --headless
```

El piloto automático recorre las mismas etapas que un operador: espera a que
carguen los recursos, detecta el formulario de firma, lo rellena con la
credencial sintética **con la red cortada**, y envía la firma con la red
restablecida. Sirve para auditar un portal cada noche o tras cada despliegue, y
ver si su comportamiento cambió.

**Sólo funciona con credencial sintética**, y la CLI se niega en lugar de
degradar. Rellenar automáticamente una e.firma real en un portal sin
caracterizar sería entregar la clave sin que nadie vea a quién. Si el
formulario no se reconoce, el piloto lo dice y la auditoría queda
`INCONCLUSIVE` en lugar de afirmar nada.

Los argumentos de línea de comandos siguen funcionando, pero **precargan** las
respuestas del asistente en lugar de ser la única vía; `--no-interactive` no
pregunta nada, para guiones. El esquema de opciones vive en un solo sitio
(`firmascope.audit_core.options`) y lo renderizan tanto la CLI como, en su
momento, la interfaz gráfica: añadir una opción no obliga a tocar cada interfaz.

### Portales con inicio de sesión

Si el portal pide iniciar sesión antes de llegar al formulario de firma, la
sesión se inicia **aparte**, en un navegador sin instrumentar:

```bash
firmascope login https://portal.ejemplo.mx/login      # inicie sesión a mano, pulse Enter
firmascope audit https://portal.ejemplo.mx/firma --session ~/.firmascope/sesiones/portal.ejemplo.mx.json
```

En la interfaz gráfica es el botón «Iniciar sesión en el portal…» junto al
campo «Sesión iniciada en el portal».

Hacerlo dentro de la auditoría tendría dos problemas: la contraseña de la
cuenta pasaría por la instrumentación, y las cookies resultantes —que dan acceso
a la cuenta— podrían acabar en el expediente. Con `--session`:

- FirmaScope nunca ve la contraseña de la cuenta: sólo guarda cookies y
  almacenamiento local, en un fichero con permisos `0600`, por defecto en
  `~/.firmascope/sesiones/` y no en el directorio de trabajo.
- Antes de arrancar el navegador, cada valor de la sesión se registra en el
  vault como **protegido**: se redacta en URLs, cabeceras, eventos, código de
  scripts y cuerpos capturados, y la barrera final impide escribirlo. No es un
  canario: viaja en cada petición legítima, y tratarlo como fuga acusaría al
  portal de lo que es su funcionamiento normal.
- El manifiesto sólo registra que la sesión estaba autenticada, nunca la ruta
  ni el contenido del fichero.

El fichero permite entrar en la cuenta mientras la sesión siga activa: al
terminar, cierre la sesión en el portal y bórrelo.

### Control durante la auditoría

La auditoría avanza por etapas, y en cada una el operador decide:

```text
next / n     continuar          back / b    regresar de etapa
retry / r    repetir            cancel / q  cancelar y cerrar el expediente
url <URL>    abrir una página   offline / online   forzar el estado de red
config       cambiar opciones modificables en marcha (aislamiento, permitidos)
status       estado de la sesión    stages   lista de etapas
```

`next`, `back` y `cancel` son las tres acciones que una interfaz gráfica mapea a
sus botones. Cancelar **no** descarta el expediente: una auditoría interrumpida
sigue siendo evidencia de lo observado hasta ese punto, y se cierra como tal.

El estado de red se **reconcilia desde la etapa**, no se aplica como un cambio
incremental. Retroceder desde una etapa aislada restablece la red sin
contabilidad adicional, y la sesión nunca termina dejando el navegador aislado.

### Interfaz gráfica

```bash
cd gui/src-tauri && cargo build --release
FIRMASCOPE_PYTHONPATH=../../src ./target/release/firmascope-gui
```

La ventana es un **panel de control** junto al navegador auditado: dice en qué
etapa está, qué se ha observado y qué se concluye. El operador carga su `.key` y
firma en el Chromium instrumentado, no en la interfaz — si la interfaz rellenara
el formulario, estaría auditando un flujo que no es el que seguirá un usuario.

La interfaz no decide nada: pinta el mismo esquema de opciones que el asistente
de la CLI, y el núcleo valida. Habla con él por **JSON por línea sobre stdio**,
no por un puerto local: FirmaScope maneja la e.firma del operador, y un puerto
abierto es alcanzable por cualquier página que el usuario tenga abierta en
cualquier navegador. Detalles en [`gui/README.md`](gui/README.md).

En la etapa de firma, la tarjeta de la credencial sintética tiene botones para
copiar cada ruta y la contraseña. En los eventos en vivo, una salida por la que
viaja material privado (la clave o su contraseña) se resalta en rojo, también
si el aislamiento la bloqueó: el sitio lo intentó. Qué cuenta como tal lo decide
el núcleo (`is_private_egress`), con el mismo criterio que las reglas.

### Panel en el navegador (`firmascope panel`)

```bash
firmascope panel                                # o: firmascope audit https://portal.ejemplo.mx --panel
```

Es **la misma interfaz**, servida por el núcleo en `127.0.0.1` para abrirla en el
navegador habitual, sin compilar nada. Los argumentos de `audit ... --panel`
precargan el formulario.

> **Riesgo:** el panel abre un puerto local. Cualquier página web abierta y
> cualquier programa del equipo pueden intentar conectarse a él, y lo que viaja
> por él —incluida la contraseña de una e.firma propia— va sin cifrar dentro del
> equipo. Lo protegen un código de un solo uso en la URL, un token por sesión en
> una cabecera propia, la comprobación de `Host` y de origen, y una CSP que solo
> permite los ficheros de la interfaz. No lo use en un equipo compartido;
> la aplicación de escritorio no abre ningún puerto. El aviso se muestra al
> arrancar y en la propia página.

Cerrar o recargar la pestaña no aborta la auditoría; el panel se cierra con
Ctrl-C en la terminal, que cierra también el expediente.

### Credencial de prueba o credencial real

Por defecto FirmaScope genera una credencial sintética de laboratorio, cuyo
sujeto declara que **no** es un certificado del SAT. Para auditar un portal con
la e.firma real del operador existe el modo `real`, que exige confirmación
escrita y aplica un endurecimiento no negociable (sin cuerpos HTTP persistidos,
con redacción de nombres de archivo e identificadores fiscales). El
procedimiento y sus riesgos están en
[`docs/real-credentials.md`](docs/real-credentials.md).

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

## Los cuatro sensores

Ninguno ve el cuadro completo, y por eso son cuatro:

| Sensor | Qué aporta | Qué no puede ver |
|---|---|---|
| Instrumentación en la página | la **procedencia**: etiqueta el dato al leer el archivo y lo sigue por las APIs | la construcción de cadenas carácter a carácter |
| CDP (DevTools) | la petición del navegador, con initiator y pila de llamadas | cuerpos que Chromium no materializa (multipart, flujos) |
| Aislamiento de red | si la petición **llegó a salir**, porque es quien la aborta | nada de lo que ocurre dentro de la página |
| Proxy (mitmproxy) | el **contenido exacto** que viajó, tras terminar el TLS | lo que no pasa por HTTP(S) |

El caso que obliga a tener los cuatro es la subida del `.key` por
`multipart/form-data`, el patrón más común de todos: CDP entrega el cuerpo
vacío, así que sin proxy la afirmación «el `.key` salió» descansa sólo en la
procedencia que el agente infiere. Con proxy se encuentra la representación del
canario **dentro del cuerpo que viajó**, y la inferencia se convierte en prueba
de contenido.

El reverso también importa: una petición que el agente vio y el aislamiento
abortó no salió, aunque tres sensores la hayan observado. El
[motor de correlación](src/firmascope/correlation_engine/sensors.py) agrupa las
observaciones de una misma petición y deja una sola conclusión, con una regla
que no es estadística: *si un sensor con autoridad para negarla la negó, no
salió*.

Cada reporte declara qué sensores hubo. Un sensor ausente no produce hallazgos
vacíos: produce preguntas sin responder, y el reporte lo dice.

### Sobre la CA del proxy

La CA es **efímera**: vive en un directorio temporal que se borra al cerrar la
sesión, y el navegador la acepta sólo porque el contexto de Playwright se abre
con `ignore_https_errors`. FirmaScope **no instala certificados en el almacén
del sistema**, porque una CA de auditoría que sobrevive a la auditoría es una
puerta abierta: quien obtenga su clave privada puede suplantar cualquier sitio
para ese usuario.

El addon se ejecuta **dentro del proceso** de FirmaScope, no como un
`mitmdump -s` aparte. Para buscar los canarios hay que conocerlos, y los
canarios son el material de la credencial: pasárselos a otro proceso por
archivo, variable de entorno o socket sería sacar de la memoria exactamente lo
que la herramienta promete no sacar. Cargado con `mitmdump -s` también
funciona, pero sin vault — registra metadatos y digests, y no puede afirmar nada
sobre el contenido.

---

## Protección de secretos

- Los secretos observados **no se escriben a disco**, tampoco las cookies y
  tokens de la sesión del operador en el portal (`--session`).
- La correlación usa `HMAC(clave-de-sesión aleatoria, secreto)`; la clave vive
  sólo en memoria y se destruye al terminar la sesión.
- La captura completa de cuerpos HTTP está **deshabilitada por defecto**.
- FirmaScope no envía información de auditoría a ningún servicio externo.
- Las credenciales sintéticas declaran en su sujeto que **no** son certificados
  del SAT. La herramienta no promueve el uso de credenciales de producción.

---

## Arquitectura

```text
            CLI (asistente)   GUI (Tauri)
                    \            /
                     \  JSON/stdio
                      \        /
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
| `apps/gui` | `gui/` (Tauri) + `firmascope.gui_bridge` |

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
| Modelo de eventos y etiquetas de procedencia | implementado |
| Estados de conclusión | implementado |
| Vault de secretos, canarios y redacción | implementado |
| Configuración por niveles y esquema de opciones | implementado |
| Expediente SQLite + cadena de hashes | implementado |
| Agente de instrumentación (sources, WebCrypto, sinks, storage, workers) | implementado |
| Observación de red por CDP y clasificación de terceros | implementado |
| Controlador de navegador (perfil efímero, aislamiento de red, inventario de scripts) | implementado |
| Credenciales sintéticas y carga de la e.firma del operador | implementado |
| Analizador estático (AST, taint interprocedural, source maps) | implementado |
| Motor de reglas y catálogo `FS-*` (12 reglas) | implementado |
| Motor de correlación de sensores | implementado |
| Motor de reportes (HTML + JSON) | implementado |
| CLI con asistente interactivo y piloto automático | implementado |
| Addon de mitmproxy (interceptación TLS, nivel 4) | implementado |
| Aplicaciones de laboratorio (9) | implementado |
| Auditoría dentro de una sesión iniciada (`login`, `--session`) | implementado |
| Interfaz gráfica (Tauri) | implementado |
| Panel en el navegador (`firmascope panel`, misma interfaz) | implementado |
| Pruebas TC-001..TC-011, GUI y unitarias, con CI | implementado |

```bash
pip install -e ".[proxy,dev]"
PYTHONPATH=src python3 -m pytest tests/ -q
PYTHONPATH=src python3 -m pytest tests/ -q -m "not e2e"   # sin navegador
```

La CI (`.github/workflows/ci.yml`) ejecuta las dos suites en cada PR y en cada
push a `main`, y compila la interfaz de Tauri con `--locked`. El flujo
«Frescura de PRs» etiqueta los PR que se quedan atrás de `main` o entran en
conflicto, el mismo día en que ocurre. [`CLAUDE.md`](CLAUDE.md) recoge cómo
trabajar en el repositorio sin volver a abrir líneas paralelas.

### Cómo se verifica

Las pruebas de extremo a extremo no comprueban que la herramienta diga algo:
comprueban que diga **lo correcto**. El laboratorio levanta el portal y un
recolector de terceros en el mismo proceso, y registra lo que recibe. Un informe
que dice «la clave salió» es correcto sólo si el recolector la tiene; uno que
dice «se impidió» es correcto sólo si no la tiene. Esa comparación con la verdad
conocida es lo que separa una prueba de una ilusión.

Ejecutar la herramienta encontró cuatro defectos que el diseño no revelaba, y
los cuatro están cubiertos por pruebas de regresión:

1. **Un intento bloqueado se reportaba como clave enviada.** Una misma petición
   la ven varios sensores y sólo el aislamiento sabe que la abortó. Con una
   e.firma real, el error llevaba a revocar un certificado sin motivo.
2. **El patrón canónico de exfiltración no producía ninguna ruta estática**,
   porque la fuente se descartaba cuando su tipo no podía deducirse del nombre
   de la expresión — y `input.files[0] -> FileReader -> btoa -> fetch` no nombra
   la clave en ninguna parte.
3. **La subida del `.key` por `multipart/form-data` no se detectaba.**
   `FormData.append` no guarda el objeto etiquetado sino un `File` nuevo con los
   mismos bytes, así que la procedencia se perdía justo antes del envío; y como
   CDP entrega ese cuerpo vacío, tampoco había forma de probarlo por contenido.
   Lo primero se corrigió en la instrumentación y el análisis estático; lo
   segundo es lo que resuelve el proxy.

4. **La interfaz no pintaba el reporte al terminar.** Una acción de etapa que
   cierra el recorrido llama a `finish` dentro de sí misma, y el bloqueo de
   botones usaba una bandera en lugar de contar anidamientos: la llamada
   interior se descartaba en silencio. La auditoría terminaba bien y el
   expediente quedaba escrito, pero el operador no veía nada.

### Límites conocidos

- El seguimiento de procedencia en página no puede atravesar la construcción de
  cadenas carácter a carácter (`binary += String.fromCharCode(bytes[i])`): un
  número no transporta procedencia. Cuando ocurre, la salida se reporta como
  binario sin clasificar y la ruta estática sigue estando.
- El código minificado, el despacho dinámico, `eval` y WebAssembly pueden
  ocultar flujos que existen. **Ausencia de rutas no es ausencia de capacidad.**
- El análisis estático no sigue el flujo a través de propiedades de objetos
  (`state.key = archivo` en una función, `leer(state.key)` en otra). En código
  minificado, donde tampoco quedan nombres, esa ruta se encuentra pero queda
  como material *sin clasificar*: se afirma que algo leído de un archivo sale
  por la red, no que sea la clave.
- El aislamiento intercepta peticiones HTTP; un WebSocket abierto antes del
  corte no se aborta por esa vía.
- El proxy ve lo que pasa por HTTP(S). Un sitio con *certificate pinning*
  rechazará la CA efímera, y ese destino queda sin observar: el reporte lo
  registra como fallo de TLS en lugar de presentarlo como ausencia de tráfico.

---

## Documentación

- [`docs/evidence-model.md`](docs/evidence-model.md) — expediente, cadena de
  integridad y protección de secretos.
- [`docs/rule-development.md`](docs/rule-development.md) — catálogo de reglas,
  cómo escribir una nueva y cómo elegir el estado de conclusión.
- [`docs/real-credentials.md`](docs/real-credentials.md) — procedimiento, riesgos
  residuales y qué hacer si el hallazgo confirma la fuga.
- [`gui/README.md`](gui/README.md) — interfaz gráfica, el protocolo del puente y
  por qué el canal es stdio y no un puerto.

### Laboratorio

Aplicaciones que reproducen las arquitecturas que importan:

| Aplicación | Qué pone a prueba |
|---|---|
| `demo-safe` | la arquitectura correcta: nada debe acusarse |
| `demo-key-exfiltration` | firma bien *y* se lleva la clave |
| `demo-encrypted-exfiltration` | la clave sale cifrada: sólo la procedencia la delata |
| `demo-server-sign` | el servidor recibe la clave y firma con ella cuando quiere |
| `demo-static-only` | código capaz de exfiltrar que no se ejecuta |
| `demo-side-channels` | la clave en la URL de un píxel, la contraseña en un beacon |
| `demo-worker` | la clave cruza a un Web Worker y sale desde dentro |
| `demo-minified` | `demo-key-exfiltration` minificado: sin nombres de variable |
| `demo-login` | firma correcta tras iniciar sesión; el token viaja en cookie, cabecera y URL |

Las cuatro últimas llegaron con el PR #2. Cada una encontró al menos un fallo.
La cuenta de `demo-login` es `operador` / `laboratorio-firmascope`.

```bash
PYTHONPATH=src python3 -m firmascope.labs.server    # portal 8765, recolector 8766
firmascope credentials new --output /tmp/efirma
firmascope audit http://127.0.0.1:8765/demo-key-exfiltration/
```

El recolector es un **origen distinto** a propósito: es lo que da algo que
clasificar al detector de terceros y algo que bloquear al aislamiento.

---

## Dependencias

```text
Python >= 3.10
playwright      control del navegador y CDP
cryptography    credenciales sintéticas
PyYAML          paquetes de reglas
tree-sitter     análisis estático de JavaScript
mitmproxy       opcional, interceptación TLS del nivel 4
```

Sin mitmproxy, el nivel 4 funciona con tres sensores y el reporte declara que
falta el cuarto. Para exigirlo en lugar de degradar, elija «Siempre» en la
opción *Interceptación TLS con proxy*: la auditoría no arranca si no está.

FirmaScope busca un Chromium ya instalado (variable `FIRMASCOPE_CHROMIUM_PATH`,
`PLAYWRIGHT_BROWSERS_PATH` o `/opt/pw-browsers`) antes de recurrir al de
Playwright.

---

## Advertencia de uso

FirmaScope es una herramienta **defensiva**. Está pensada para auditar sitios
propios o sitios sobre los que se tiene autorización de prueba.

Use credenciales sintéticas de laboratorio siempre que pueda: caracterizan el
portal sin exponer nada. El modo `real` existe porque hay un caso legítimo en
que eso no basta — el operador tiene que firmar en ese portal de todas formas y
necesita saber qué hace con su clave — y está sujeto a confirmación escrita y a
restricciones que no se pueden desactivar.

Lo que ese modo **no** puede hacer es proteger la credencial: FirmaScope observa,
no bloquea. Si el sitio transmite la clave, el hallazgo llega después de que haya
salido. Audite primero con la credencial sintética, firme dentro de la etapa
aislada, y lea [`docs/real-credentials.md`](docs/real-credentials.md) antes de
decidir.
