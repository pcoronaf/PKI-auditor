# Desarrollo de reglas

El motor de reglas separa **qué se declara** de **cómo se evalúa**:

- los metadatos viven en YAML, bajo `src/firmascope/rule_engine/rules/<categoría>/`;
- la lógica vive en Python, registrada por identificador.

Así el catálogo puede leerse y revisarse sin leer código, y un operador puede
añadir reglas propias sin tocar FirmaScope (NFR-004).

## Catálogo actual

| Regla | Categoría | Severidad | Pregunta que responde |
|---|---|---|---|
| `FS-KEY-001` | efirma | CRITICAL | ¿salió el .key o la clave privada sin transformar? |
| `FS-KEY-002` | efirma | CRITICAL | ¿salieron datos derivados de la clave privada? |
| `FS-PWD-001` | efirma | CRITICAL | ¿salió la contraseña de la clave? |
| `FS-PWD-002` | efirma | HIGH | ¿se persistió la contraseña en el navegador? |
| `FS-LOCAL-001` | efirma | INFO | ¿se firmó con la red aislada? |
| `FS-CRYPTO-001` | crypto | HIGH | ¿se exportó una clave privada? |
| `FS-CRYPTO-002` | crypto | MEDIUM | ¿se creó una clave privada extraíble? |
| `FS-NET-001` | network | MEDIUM | ¿qué terceros recibieron tráfico tras el acceso a la clave? |
| `FS-NET-002` | network | MEDIUM | ¿hubo salidas binarias sin clasificar en ese momento? |
| `FS-STORAGE-001` | storage | HIGH | ¿se escribió material privado en IndexedDB? |
| `FS-STORAGE-002` | storage | HIGH | ¿se escribió material privado en localStorage? |
| `FS-CODE-001` | code | HIGH | ¿existe una ruta de código capaz de exfiltrar? |

## Anatomía de una regla

### 1. Metadatos (YAML)

```yaml
id: FS-KEY-001
title: Clave privada transmitida directamente
category: efirma
severity: CRITICAL          # INFO | LOW | MEDIUM | HIGH | CRITICAL
summary: Resumen de una línea.
description: |
  Qué observa exactamente la regla y con qué sensores.
rationale: |
  Por qué importa. Aparece en el reporte como "Por qué importa:".
references:
  - FR-002
  - TC-002
enabled: true               # opcional
```

### 2. Evaluador (Python)

```python
from firmascope.audit_core.conclusions import Confidence, Severity, Status
from firmascope.audit_core.events import Tag
from firmascope.rule_engine.registry import RuleResult, rule


@rule("FS-KEY-001")
def key_file_transmitted(context, meta) -> RuleResult:
    hits = context.direct_egress(Tag.KEY_FILE, Tag.PRIVATE_KEY)
    if hits:
        return RuleResult(
            status=Status.OBSERVED,
            summary="...",
            evidence=[context.event_evidence(e) for e in hits],
            confidence=Confidence.HIGH,
        )
    if not context.observed_key_material():
        return RuleResult.inconclusive("La sesión no procesó material de clave.")
    return RuleResult.not_observed("No se observó transmisión directa.")
```

Cargue paquetes externos con `RuleEngine(extra_dirs=[Path("mis-reglas")])`.
Una regla externa con el mismo `id` que una integrada la sustituye.

## Reglas de estilo para autores

**Toda regla habilitada emite un hallazgo, incluso cuando no observa nada.** Un
reporte que dice explícitamente `NOT OBSERVED` es más útil que uno que calla.

**Distinga `NOT_OBSERVED` de `INCONCLUSIVE`.** Es la distinción central de la
herramienta:

- `NOT_OBSERVED`: la sesión ejercitó la condición y no ocurrió.
- `INCONCLUSIVE`: la sesión ni siquiera ejercitó la condición. Evaluar "¿se
  transmitió la clave?" en una sesión donde nunca se cargó una clave no es un
  aprobado, es una pregunta sin responder.

**Reserve `CONFIRMED` para experimentos.** Sólo `FS-LOCAL-001` lo emite, porque
descansa en una intervención (aislar la red) y no en una observación pasiva.

**`POTENTIAL` es para capacidad, no para conducta.** Las reglas alimentadas por
el análisis estático describen lo que el código *puede* hacer.

**Acompañe todo `NOT_OBSERVED` de su salvedad.** Use la constante
`NOT_OBSERVED_CAVEAT`: no observado no equivale a imposible.

**Nunca ponga secretos en la evidencia.** Use los constructores
`context.event_evidence()`, `context.request_evidence()` y
`context.code_evidence()`. El almacén redacta por si acaso, pero la regla no
debe depender de ello.

**Sea proporcionado en el lenguaje.** `FS-NET-001` se dispara con tráfico
perfectamente legítimo: su redacción es descriptiva, no acusatoria. Una
herramienta que grita ante cada CDN enseña a ignorarla.

## Consultas disponibles en el contexto

| Consulta | Devuelve |
|---|---|
| `events_of(*tipos)` | eventos de esos tipos |
| `events_with_tag(*etiquetas)` | eventos con alguna etiqueta de procedencia |
| `egress_events()` | eventos de canales de salida |
| `first_key_access()` | primer acceso a material privado |
| `observed_key_material()` / `observed_password()` | si la sesión llegó a ejercitar la condición |
| `after_key_access(eventos)` | filtra los posteriores al acceso a la clave |
| `within_window(eventos, ms)` | los que caen en la ventana de correlación |
| `offline_windows()` / `offline_at(ts)` / `offline_test_ran()` | estado de aislamiento de red |
| `events_while_offline(eventos)` | los ocurridos con la red aislada |
| `direct_egress(*etiquetas)` | salida del material sin transformar |
| `derived_egress(*etiquetas)` | salida de datos derivados |
| `any_egress(*etiquetas)` | ambas |
| `unclassified_binary_egress()` | salidas binarias opacas |
| `storage_writes(store, labels)` | escrituras a almacenamiento |
| `third_parties_after_key_access()` | terceros agrupados por dominio registrable |
| `static` | `StaticReport` del análisis de nivel 2 |
| `correlation` | motor de correlación, si se ejecutó |

## Cómo obtiene FirmaScope las etiquetas

Dos sensores independientes, y una regla puede exigir cualquiera de los dos:

1. **Canarios.** El vault conoce las representaciones de la credencial
   sintética (raw, base64, base64url, hex, URL-encoding, UTF-16, SHA-256) y las
   busca dentro de los cuerpos salientes. Encontrar una de ellas **prueba** que
   los bytes estaban ahí: es la evidencia más fuerte, y la que sostiene
   `direct_egress()`.
2. **Instrumentación.** El agente etiqueta el dato al leerlo y propaga la
   procedencia a través de las APIs que envuelve. Detecta lo que el canario no
   puede: material transformado, cifrado o troceado antes de salir. Es lo que
   sostiene `derived_egress()`.

El análisis estático aporta una tercera vía, que nunca produce `OBSERVED`
porque no observa ejecución alguna: sólo `POTENTIAL`.
