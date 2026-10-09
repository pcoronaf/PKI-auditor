# Modelo de evidencias

Cada sesión de FirmaScope produce un expediente autocontenido y verificable.

## Estructura del expediente

```text
audit/
 ├── manifest.json        metadatos de reproducibilidad + cabeza de la cadena de hashes
 ├── timeline.json        eventos normalizados en orden temporal
 ├── requests.json        peticiones salientes observadas (CDP y proxy)
 ├── scripts/             código JavaScript tal y como lo parseó el motor
 ├── script-hashes.json   inventario SHA-256 de los scripts
 ├── findings.json        hallazgos del motor de reglas
 ├── screenshots/         capturas en los hitos de la sesión
 ├── evidence/            artefactos adicionales (cuerpos HTTP si se habilitan)
 ├── report.html          reporte autocontenido, sin recursos externos
 └── report.json          reporte estructurado
```

## Cadena de integridad (NFR-003)

Cada evento persistido se encadena con el anterior:

```text
hash_n = SHA256(hash_{n-1} || canonical_json(evento_n))
```

`manifest.json` publica el hash final (`chain_head`). Modificar, insertar o
borrar un evento posterior rompe la cadena de forma detectable con:

```bash
firmascope verify audits/FS-XXXX-XXXX
```

## Protección de secretos

- Los secretos observados **no se escriben a disco**.
- La correlación usa `HMAC(clave-de-sesión, secreto)`; la clave de sesión es
  aleatoria, vive sólo en memoria y se destruye al terminar la sesión.
- La captura completa de cuerpos HTTP está deshabilitada por defecto. Cuando se
  habilita explícitamente, los cuerpos se analizan siempre en memoria pero sólo
  se persisten bajo `evidence/`.
- `Event.data` pasa por una función de redacción que elimina claves sensibles,
  trunca cadenas largas y sustituye cualquier aparición de un canario por un
  marcador `<canary:ETIQUETA>`.

## Reproducibilidad (NFR-002)

`manifest.json` registra objetivo, fecha/hora, versión de FirmaScope, versión y
ruta del navegador, sistema operativo, configuración de auditoría, modo de red,
hash del agente de instrumentación, hashes SHA-256 de todos los scripts y
configuración del proxy.

---

## Los sensores y lo que cada uno puede afirmar

Una misma petición HTTP la pueden ver cuatro sensores distintos, y ninguno ve el
cuadro completo:

| Sensor | Posición | Afirma |
|---|---|---|
| `agent` | dentro de la página, antes de que la petición salga | la **procedencia** del dato (etiquetas S1–S6) |
| `cdp` | en el navegador | que la petición **se emitió**, con initiator y pila |
| `isolation` | en la ruta de salida | si **llegó a salir**, porque es quien la aborta |
| `proxy` | terminando el TLS | el **contenido exacto** que viajó |

Cada uno responde una pregunta distinta y sólo esa. El agente sabe de dónde
venían los bytes pero no cómo acabó la petición. El aislamiento sabe que la
abortó pero no de dónde venían los bytes. CDP ve la petición pero no siempre su
cuerpo. El proxy ve el cuerpo pero no el código que lo construyó.

### Por qué hay que correlacionarlos

Contarlos por separado produce dos errores en direcciones opuestas:

- **Multiplicación.** Una exfiltración vista por tres sensores aparecería como
  tres salidas, y el mismo destino nombrado de dos formas (`host:puerto` según
  el agente, `host` según CDP).
- **Falsa afirmación.** Un intento que el aislamiento abortó se reportaría como
  material enviado, porque el sensor que lo negó no es el que lo vio. Con una
  e.firma real, eso lleva a revocar un certificado que nunca salió del equipo.

El motor de correlación agrupa las observaciones de una misma petición —por
digest del cuerpo, o por URL y tamaño dentro de una ventana— y deja **una sola
conclusión**. La regla de decisión no es estadística:

> Si un sensor con autoridad para negarla la negó, no salió.

El aislamiento tiene esa autoridad porque aborta la petición en el navegador: si
abortó, los bytes no llegaron a la red. Los demás observan la *intención* de
enviar, que es anterior al resultado.

### El expediente no se reescribe

La correlación es una **capa de interpretación** sobre las observaciones, no una
corrección de ellas. Los eventos crudos siguen encadenados tal como se
registraron, cada uno con su sensor, y `report.json` publica la agrupación
aparte. Si el operador discute la conclusión, puede recomputarla desde
`timeline.json` sin confiar en la nuestra.

Esto también fija quién escribe: los sensores producen en hilos y callbacks
distintos, pero sólo el hilo principal escribe en el expediente, de modo que la
cadena de hashes conserva un orden único y verificable.

### Cuando falta un sensor

`report.json` incluye `sensors`, con qué sensores estuvieron activos y qué no se
pudo observar sin ellos. Sin proxy, los cuerpos que el navegador no entrega al
depurador —subidas multipart, flujos— no se examinaron por contenido: la
procedencia que aporta la instrumentación sigue siendo válida, pero no hay
prueba de contenido para esas peticiones.

Un sensor ausente no produce hallazgos vacíos. Produce preguntas sin responder,
y el reporte las nombra en lugar de dejar un silencio que se leería como
tranquilidad.
