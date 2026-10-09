# Auditar con una e.firma real

FirmaScope está pensado para usarse con credenciales sintéticas. Hay un caso
legítimo en el que eso no basta: **necesitas firmar en ese portal de todas
formas**, y quieres saber qué hace con tu clave. Para eso existe
`--credentials real`.

Este documento es el procedimiento para hacerlo con el menor riesgo posible, y
lo que FirmaScope puede y no puede hacer por ti.

## Lo que esta herramienta no puede hacer

**FirmaScope observa; no bloquea.** Si el portal transmite tu clave en el
momento en que la cargas, el hallazgo aparece *después* de que haya salido. No
hay ninguna configuración que cambie eso.

La única excepción es el aislamiento de red: con la red cortada, un intento de
transmisión se aborta antes de salir. Es la razón por la que el procedimiento
recomendado firma dentro de la ventana de aislamiento.

## Procedimiento recomendado

Todo lo que sigue puede hacerse **sin escribir un solo argumento**: `firmascope
audit` abre un asistente que pregunta el sitio, el nivel, el tipo de credencial
y el aislamiento, y permite revisarlo antes de arrancar. Los argumentos que
aparecen abajo son el equivalente no interactivo, útil para repetir una prueba
exactamente igual; cuando se indican, el asistente los toma como respuesta
precargada y no vuelve a preguntarlos.

```bash
firmascope options        # qué se puede configurar, y qué puede cambiarse en marcha
```

### 1. Caracteriza el portal con una credencial sintética

```bash
firmascope credentials new
firmascope audit https://portal.ejemplo.mx --credentials synthetic --level 4
```

La credencial sintética tiene la misma forma que una e.firma (PKCS#8 cifrado +
X.509 DER) pero no es tuya. Si el portal la exfiltra, no has perdido nada y ya
tienes la respuesta.

Un portal que falla aquí no necesita una segunda prueba: no le entregues tu
e.firma real.

> Si el portal valida el certificado contra el SAT, la credencial sintética será
> rechazada antes de llegar a la firma. En ese caso la prueba sintética sólo
> caracteriza el flujo hasta ese punto, y el paso 2 es el que da la respuesta.

### 2. Repite la prueba con tu e.firma, firmando con la red cortada

Con el asistente, elige «Mi e.firma real» en *Credencial a usar*: aparece
marcada como peligrosa, el asistente muestra los riesgos residuales y exige que
escribas `ACEPTO`. Después pide las rutas del `.key` y del `.cer`, que comprueba
que existan, y la contraseña por `getpass`.

El equivalente no interactivo:

```bash
firmascope audit https://portal.ejemplo.mx \
  --credentials real \
  --key ~/efirma/mi.key --cert ~/efirma/mi.cer \
  --i-accept-real-credential-risk \
  --isolation full --level 4
```

La contraseña nunca se pasa por argumento: los argumentos quedan en el historial
del shell y son visibles en la lista de procesos. Se pide siempre por `getpass`.

El flujo por etapas hace el trabajo:

| Etapa | Red | Qué haces |
|---|---|---|
| 1. Cargar el sitio | ONLINE | nada; se descargan los recursos |
| 2. Preparar | ONLINE | inicias sesión y llegas a la pantalla de firma |
| 3. Aislar | OFFLINE | FirmaScope corta la salida de red |
| 4. **Firmar** | OFFLINE | cargas `.cer`, `.key` y contraseña, y firmas |
| 5. Restablecer | ONLINE | vuelve la conectividad |
| 6. Enviar | ONLINE | envías la firma |

Tu clave sólo se usa en la etapa 4, con la red cortada. Si el portal intenta
enviarla, la petición se aborta y queda registrada como intento bloqueado —
evidencia de primer orden sobre lo que habría hecho con red.

### 3. Lee el resultado

```text
Localidad del procesamiento
  Private key access        OFFLINE
  Password access           OFFLINE
  Private key decryption    OFFLINE
  Signature generation      OFFLINE
  Signature submission      ONLINE
```

Eso es firma local demostrada: la clave se usó en tu equipo.

Si en cambio aparece

```text
[OBSERVADO   ] FS-KEY-001  Clave privada transmitida directamente
```

mira si el detalle dice `[ENVIADO]` o `[BLOQUEADO]`:

- **BLOQUEADO** — el aislamiento lo impidió. Tu clave no salió, pero el portal
  lo intentó: no vuelvas a firmar ahí sin aislamiento.
- **ENVIADO** — tu clave salió. **Revoca y renueva tu e.firma.** Un hallazgo así
  con credencial real es un incidente, no un informe.

## Controles durante la sesión

En cada etapa la interfaz acepta:

| Orden | Efecto |
|---|---|
| `next` / `n` | continuar a la siguiente etapa |
| `back` / `b` | **regresar a la etapa anterior** (restablece la red si hace falta) |
| `retry` / `r` | repetir la etapa actual |
| `cancel` / `q` | **cancelar**: restablece la red, cierra el expediente y conserva lo observado |
| `url <dirección>` | abrir una página (si arrancaste sin URL, o para navegar) |
| `offline` / `online` | forzar el estado de red sin cambiar de etapa |
| `config` | cambiar lo que puede cambiarse en marcha (aislamiento, hosts permitidos) |
| `status`, `stages`, `help` | consultar estado |

Lo que **no** aparece en `config` es deliberado: cambiar el nivel de auditoría o
el tipo de credencial a mitad de sesión cambiaría el significado de lo ya
registrado, así que exige una sesión nueva.

El estado de red se deriva de la etapa destino, no se aplica como un cambio
incremental. Por eso retroceder de la etapa 4 a la 2 restablece la red sola, y
cancelar nunca te deja con el navegador aislado.

`Ctrl-C` equivale a `cancel`: el expediente se cierra correctamente.

### Arrancar sin URL

El asistente deja vacío el campo *Sitio a auditar* si se pulsa Enter. También:

```bash
firmascope audit --credentials real --key ... --cert ...
```

Se abre el navegador vacío y la primera orden `url https://portal.ejemplo.mx`
fija el objetivo de la sesión. También puedes escribir la dirección en la barra
del propio navegador: FirmaScope lo detecta.

El primer objetivo es el que define qué cuenta como «tercero» durante el resto
de la sesión.

## La interceptación TLS con su e.firma real

El nivel 4 añade un proxy que termina el TLS para poder examinar los cuerpos que
el depurador del navegador no entrega — entre ellos, una subida
`multipart/form-data` con el `.key` dentro. Con credencial real conviene
entender exactamente qué implica:

**Lo que gana.** Si el portal transmite su clave, el hallazgo pasa de *inferido*
a *probado*: no se deduce de la procedencia que la instrumentación sigue, se
encuentra la representación del canario dentro del cuerpo que viajó. Para una
decisión tan costosa como revocar una e.firma, esa diferencia importa.

**Lo que cuesta.** El cuerpo descifrado pasa por la memoria del proceso de
FirmaScope. No se escribe en disco: con credencial real, `capture_bodies` se
fuerza a falso y no se puede reactivar. Pero durante unos milisegundos esos
bytes están en memoria, igual que ya lo está su clave descifrada para poder
generar los canarios.

**Lo que no ocurre.** La CA es efímera, vive en un directorio temporal y se
borra al cerrar la sesión. FirmaScope no instala certificados en el almacén del
sistema: el navegador de la auditoría acepta esa CA y nada más en su equipo lo
hace. Si el portal usa *certificate pinning*, rechazará la CA y ese destino
quedará sin observar; el reporte lo registra como fallo de TLS en lugar de
presentarlo como ausencia de tráfico.

Si prefiere no interceptar, elija «Nunca» en *Interceptación TLS con proxy*, o
audite en nivel 3. Pierde la prueba de contenido, no la de procedencia.

---

## Qué se endurece automáticamente en modo real

Estas restricciones **no son configurables**, porque el daño no sería
reversible:

| Restricción | Motivo |
|---|---|
| `capture_bodies` forzado a falso | un cuerpo HTTP persistido podría contener tu clave |
| Nombres de archivo redactados | el nombre de archivo de una e.firma del SAT **contiene tu RFC** |
| RFC y CURP redactados en todo texto | aparecen en formularios de firma |
| Digests globales → fingerprints de sesión | el SHA-256 de tu `.key` es un identificador estable tuyo |
| Sujeto y número de serie del certificado redactados | identifican al titular |
| La credencial nunca se copia a disco | se lee de su ubicación original |

Lo que el expediente **sí** contiene: que se usó una credencial real, su ventana
de validez, y fingerprints HMAC derivados de una clave de sesión aleatoria que
se destruye al terminar el proceso. Nada de eso te identifica ni sirve fuera de
la sesión.

Aun así, **revisa el expediente antes de compartirlo**.

## Por qué la clave descifrada entra en memoria del proceso

Para detectar la exfiltración de la clave *ya descifrada* —el caso en que el
portal la cifra con su propia clave pública antes de subirla, que a una
inspección de red le parece ruido— FirmaScope necesita conocer esa forma del
material. La descifra en memoria al cargar la credencial y registra sus
representaciones en el vault.

Ese vault es memoria y nada más: clave HMAC aleatoria por sesión, destruida al
terminar, nunca serializada. Sin ese paso, FS-KEY-002 no podría detectar nada.

## Si algo falla

**La página no carga.** Casi siempre es una etapa `OFFLINE` alcanzada antes de
cargar el sitio. FirmaScope lo avisa explícitamente
(`navigation-while-isolated`) y se niega a aislar antes de la primera carga.
Usa `back` para volver a una etapa en línea, o `online`.

**El portal se niega a firmar sin conexión.** Algunos verifican
`navigator.onLine`. Prueba `--no-offline-flag`: el aislamiento sigue activo,
pero el sitio ve la conexión como disponible.

**El portal necesita un recurso que no precargó.** Usa
`--isolation allowlist --allow-host portal.ejemplo.mx`: se bloquean los terceros
y se permite el propio portal. Menos concluyente que `full`, pero suficiente
para descartar exfiltración a terceros.

**La contraseña no abre el `.key`.** FirmaScope falla antes de empezar, en lugar
de auditar sin poder detectar nada. Verifica que el `.cer` y el `.key` son de la
misma e.firma: también se comprueba que sus claves públicas coincidan.
