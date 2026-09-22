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

> **Estado: en construcción.** Ver [Estado de implementación](#estado-de-implementación).

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
| Modelo de eventos y etiquetas de procedencia | implementado |
| Estados de conclusión | implementado |
| Vault de secretos, canarios y redacción | implementado |
| Configuración por niveles | implementado |
| Expediente SQLite + cadena de hashes | implementado |
| Agente de instrumentación (sources, WebCrypto, sinks, storage, workers) | implementado |
| Observación de red por CDP y clasificación de terceros | implementado |
| Controlador de navegador (perfil efímero, aislamiento de red, inventario de scripts) | implementado |
| Credenciales sintéticas | implementado |
| Analizador estático (AST, taint interprocedural, source maps) | implementado, **sin verificar** |
| Motor de reglas y catálogo `FS-*` (12 reglas) | implementado, **sin verificar** |
| Motor de correlación | **pendiente** |
| Motor de reportes (HTML + JSON) | **pendiente** |
| Addon de mitmproxy | **pendiente** |
| CLI (`firmascope audit ...`) | **pendiente** |
| Aplicaciones de laboratorio (lógica) | **pendiente** |
| Pruebas TC-001..TC-006 | **pendiente** |

### Sobre “sin verificar”

Ningún módulo ha pasado todavía por una suíte de pruebas automatizada.

- Los módulos del núcleo (eventos, vault, expediente, credenciales, dominios) se
  validaron con pruebas manuales durante el desarrollo: cadena de hashes,
  detección de manipulación, redacción, coincidencia de canarios en base64 y
  clasificación de dominios registrables.
- El analizador estático y el motor de reglas se escribieron **sin poder
  ejecutarlos**, por lo que deben tratarse como código sin verificar hasta que
  exista la suíte de pruebas. El diseño se razonó contra el código real de las
  aplicaciones de laboratorio, pero razonar no es ejecutar.

La suíte mínima que cerrará esa brecha son los casos TC-001..TC-006 de la
especificación, sobre las cinco aplicaciones de laboratorio.

---

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
