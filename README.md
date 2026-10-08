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

> **Estado: funcional, verificado contra el laboratorio.** Las seis pruebas
> TC-001..TC-006 se ejecutan con un Chromium real y comparan cada hallazgo con
> la verdad conocida del laboratorio. Ver
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
firmascope options            listar las opciones configurables (--json para una GUI)
firmascope credentials new    generar una credencial sintética de laboratorio
firmascope rules              listar el catálogo de reglas
firmascope verify DIR         verificar la cadena de evidencias de un expediente
```

Los argumentos de línea de comandos siguen funcionando, pero **precargan** las
respuestas del asistente en lugar de ser la única vía; `--no-interactive` no
pregunta nada, para guiones. El esquema de opciones vive en un solo sitio
(`firmascope.audit_core.options`) y lo renderizan tanto la CLI como, en su
momento, la interfaz gráfica: añadir una opción no obliga a tocar cada interfaz.

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
| CLI con asistente interactivo | implementado |
| Aplicaciones de laboratorio (5, con lógica) | implementado |
| Pruebas TC-001..TC-006 + unitarias (35) | implementado |
| Addon de mitmproxy (nivel 4 con proxy) | **pendiente** |
| Interfaz gráfica (Tauri) | **pendiente** |

```bash
PYTHONPATH=src python3 -m pytest tests/ -q     # 35 pruebas
PYTHONPATH=src python3 -m pytest tests/ -q -m "not e2e"   # sin navegador
```

### Cómo se verifica

Las pruebas de extremo a extremo no comprueban que la herramienta diga algo:
comprueban que diga **lo correcto**. El laboratorio levanta el portal y un
recolector de terceros en el mismo proceso, y registra lo que recibe. Un informe
que dice «la clave salió» es correcto sólo si el recolector la tiene; uno que
dice «se impidió» es correcto sólo si no la tiene. Esa comparación con la verdad
conocida es lo que separa una prueba de una ilusión.

Ejecutar la herramienta por primera vez encontró tres defectos que el diseño no
revelaba, y los tres están cubiertos por pruebas de regresión:

1. **Un intento bloqueado se reportaba como clave enviada.** Una misma petición
   la ven varios sensores y sólo el aislamiento sabe que la abortó. Con una
   e.firma real, el error llevaba a revocar un certificado sin motivo.
2. **El patrón canónico de exfiltración no producía ninguna ruta estática**,
   porque la fuente se descartaba cuando su tipo no podía deducirse del nombre
   de la expresión — y `input.files[0] -> FileReader -> btoa -> fetch` no nombra
   la clave en ninguna parte.
3. **La subida del `.key` por `multipart/form-data` no se detectaba**, porque
   `FormData.append` no guarda el objeto etiquetado sino un `File` nuevo con los
   mismos bytes, y la procedencia se perdía justo antes del envío.

### Límites conocidos

- El seguimiento de procedencia en página no puede atravesar la construcción de
  cadenas carácter a carácter (`binary += String.fromCharCode(bytes[i])`): un
  número no transporta procedencia. Cuando ocurre, la salida se reporta como
  binario sin clasificar y la ruta estática sigue estando.
- El código minificado, el despacho dinámico, `eval` y WebAssembly pueden
  ocultar flujos que existen. **Ausencia de rutas no es ausencia de capacidad.**
- El aislamiento intercepta peticiones HTTP; un WebSocket abierto antes del
  corte no se aborta por esa vía.

---

## Documentación

- [`docs/evidence-model.md`](docs/evidence-model.md) — expediente, cadena de
  integridad y protección de secretos.
- [`docs/rule-development.md`](docs/rule-development.md) — catálogo de reglas,
  cómo escribir una nueva y cómo elegir el estado de conclusión.
- [`docs/real-credentials.md`](docs/real-credentials.md) — procedimiento, riesgos
  residuales y qué hacer si el hallazgo confirma la fuga.

### Laboratorio

Cinco aplicaciones que reproducen las arquitecturas que importan: firma local
correcta, exfiltración de la clave, exfiltración cifrada, firma en el servidor y
código capaz de exfiltrar que no se ejecuta.

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
mitmproxy       opcional, nivel 4
```

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
