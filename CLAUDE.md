# FirmaScope — instrucciones para trabajar en este repositorio

FirmaScope audita qué hace una aplicación web con la e.firma de una persona. Un
error aquí no es un fallo de estilo: es decirle a alguien que su clave está a
salvo cuando salió, o que salió cuando no.

## Antes de empezar: partir del `main` actual

Este repositorio ya tuvo dos ramas que partieron de un `main` viejo y
construyeron, en paralelo, implementaciones distintas de las mismas piezas
(orquestador, correlación, proxy, reportes). Nadie lo supo hasta intentar
fusionar, y para entonces cada una arreglaba fallos que la otra seguía teniendo.

1. **Ramifica desde el `main` remoto recién descargado**, nunca desde una rama
   local antigua:
   ```bash
   git fetch origin main && git checkout -b <rama> origin/main
   ```
2. **Mira los PR abiertos antes de construir algo.** Si alguno toca la misma
   pieza, amplía esa línea de trabajo o coordina; no abras una paralela.
3. **Antes de abrir o actualizar un PR, fusiona `main` en tu rama** y vuelve a
   pasar las pruebas. El flujo «Frescura de PRs» etiqueta los PR que se quedan
   atrás (`desactualizado`) o entran en conflicto (`conflicto con main`):
   trátalo como trabajo pendiente, no como ruido.
4. **Una pieza, una implementación.** Si existe un componente para algo,
   corrígelo o amplíalo. Dos caminos hacia la misma conclusión acaban
   discrepando.

## Pruebas

```bash
pip install -e ".[proxy,dev]"
PYTHONPATH=src python3 -m pytest tests/ -q                # todas
PYTHONPATH=src python3 -m pytest tests/ -q -m "not e2e"   # sin navegador
```

- Las pruebas `e2e` comparan cada hallazgo con la **verdad conocida** del
  laboratorio: «la clave salió» sólo es correcto si el recolector la recibió.
  Una prueba que sólo comprueba que la herramienta *dice algo* no prueba nada.
- **Todo arreglo lleva una prueba que falla sin él.** Compruébalo ejecutándola
  contra el código anterior; si pasa igual, la prueba no detecta el fallo.
- Un fallo nuevo se reproduce primero en el laboratorio
  (`src/firmascope/labs/apps/`), con el control de ejecutarlo sin FirmaScope
  cuando la duda sea si la herramienta altera el sitio.

## Invariantes que no se negocian

- **Ningún secreto llega a disco.** Los canarios viven en el vault, en memoria.
  Todo lo que se escribe en el expediente pasa por `redact()` y por
  `assert_no_secrets()`, incluidas URLs, cabeceras y peticiones. La sesión
  del operador en el portal (`--session`) se protege igual, como valor
  protegido y no como canario: viaja en cada petición legítima.
- **El aislamiento manda.** Una petición que el aislamiento abortó no salió,
  aunque otros sensores la vieran. La correlación respeta esa autoridad.
- **No observado no es imposible.** Ninguna regla convierte ausencia de
  evidencia en garantía, y ninguna etiqueta se inventa para dar un hallazgo más
  fuerte: material sin tipificar es `UNCLASSIFIED`, no la clave.
- **El sandbox de Chromium queda activado** salvo como root o con decisión
  explícita (`--no-sandbox`, `FIRMASCOPE_NO_SANDBOX=1`). Todo arranque pasa por
  `browser_controller/launch.py`.
- **La interfaz gráfica habla con el núcleo por stdio**, no por un puerto
  local: un puerto es alcanzable por cualquier página abierta y cualquier
  programa del equipo. **Excepción aceptada: el panel** (`firmascope panel`,
  `audit --panel`), que sirve la misma interfaz en el navegador para no exigir
  compilar Tauri. Es aceptable mientras conserve todas estas condiciones; quitar
  una no es un refactor, es reabrir la decisión:
  - es opcional y explícito: nada abre el panel por omisión;
  - escucha solo en `127.0.0.1`, en un puerto al azar salvo `--port`;
  - exige la cabecera `Host` propia (DNS rebinding), un token por sesión en
    `X-FS-Token`, cuerpo JSON y ningún `Origin`/`Sec-Fetch-Site` ajeno;
  - el token nunca va en la URL: la URL lleva un código de un solo uso;
  - sirve solo los ficheros de `firmascope/ui`, con CSP `'self'`;
  - **avisa del riesgo** (`PANEL_WARNING`) al arrancar en la terminal y en la
    propia página, y recomienda la aplicación de escritorio;
  - es otro transporte del mismo `Bridge` y la misma `app.js`, no una segunda
    interfaz.

  Cualquier otro puerto local sigue sin ser aceptable.
- **El piloto automático sólo funciona con credencial sintética.**
- La instrumentación **no puede alterar el sitio auditado**: si lo rompe, se
  audita un flujo que no existe.

## Convenciones

- Código, comentarios, documentación y mensajes de commit en español. Los
  comentarios explican *por qué*, sobre todo cuando la razón es un fallo que
  ya ocurrió.
- `Cargo.lock` se versiona: el árbol exacto de dependencias es parte de lo que
  un revisor debe poder reproducir.
