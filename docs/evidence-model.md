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
