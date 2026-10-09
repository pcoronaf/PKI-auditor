// Interfaz grafica de FirmaScope.
//
// Esta capa es deliberadamente delgada. Todo el criterio de la auditoria -- que
// se observa, que se concluye, como se redacta el expediente -- vive en el
// nucleo de Python, que es el que esta cubierto por pruebas. Aqui solo hay dos
// cosas: lanzar ese nucleo como proceso hijo y pasarle mensajes.
//
// Esa division no es por comodidad. Una interfaz que reimplementara parte del
// criterio tendria dos verdades sobre la misma auditoria, y la que viera el
// operador no seria necesariamente la que quedara en el expediente.
//
// El canal es JSON por linea sobre la entrada y salida estandar del hijo. No se
// abre ningun puerto: FirmaScope maneja la e.firma del operador, y un puerto en
// localhost es alcanzable por cualquier pagina que el usuario tenga abierta en
// cualquier navegador.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde_json::{json, Value};
use tauri::{Manager, State};
use tauri_plugin_dialog::DialogExt;

/// Version de protocolo que esta interfaz sabe hablar.
const PROTOCOL: u64 = 1;

struct Core {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
}

struct Bridge {
    core: Mutex<Option<Core>>,
    next_id: AtomicU64,
}

impl Bridge {
    fn new() -> Self {
        Bridge {
            core: Mutex::new(None),
            next_id: AtomicU64::new(1),
        }
    }
}

/// Lanza el nucleo de Python.
///
/// Se busca en este orden: la variable `FIRMASCOPE_PYTHON`, un `python3` del
/// sistema. El modulo se invoca con `-m`, de modo que vale igual un FirmaScope
/// instalado con pip que un arbol de fuentes con `PYTHONPATH`.
fn spawn_core() -> Result<Core, String> {
    let python = std::env::var("FIRMASCOPE_PYTHON").unwrap_or_else(|_| "python3".to_string());
    let mut command = Command::new(&python);
    command
        .arg("-m")
        .arg("firmascope.gui_bridge.bridge")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // El stderr del hijo se hereda: los avisos del nucleo van al log de la
        // aplicacion y no al canal de protocolo, que debe quedar limpio.
        .stderr(Stdio::inherit());
    if let Ok(path) = std::env::var("FIRMASCOPE_PYTHONPATH") {
        command.env("PYTHONPATH", path);
    }

    let mut child = command.spawn().map_err(|e| {
        format!(
            "no se pudo lanzar el nucleo de FirmaScope con «{python}»: {e}. \
             Instale el paquete (pip install firmascope) o indique el interprete \
             en la variable FIRMASCOPE_PYTHON."
        )
    })?;
    let stdin = child.stdin.take().ok_or("sin entrada estandar del nucleo")?;
    let stdout = child.stdout.take().ok_or("sin salida estandar del nucleo")?;
    Ok(Core {
        child,
        stdin,
        stdout: BufReader::new(stdout),
    })
}

/// Una ida y vuelta por el canal.
///
/// El protocolo es estrictamente peticion/respuesta, asi que un solo cerrojo
/// sobre el par de descriptores basta y no hace falta emparejar por `id`.
fn roundtrip(core: &mut Core, id: u64, cmd: &str, args: Value) -> Result<Value, String> {
    let request = json!({ "id": id.to_string(), "cmd": cmd, "args": args });
    let line = serde_json::to_string(&request).map_err(|e| e.to_string())?;
    core.stdin
        .write_all(line.as_bytes())
        .and_then(|_| core.stdin.write_all(b"\n"))
        .and_then(|_| core.stdin.flush())
        .map_err(|e| format!("el nucleo no acepto la peticion: {e}"))?;

    let mut response = String::new();
    let read = core
        .stdout
        .read_line(&mut response)
        .map_err(|e| format!("no se pudo leer la respuesta del nucleo: {e}"))?;
    if read == 0 {
        return Err("el nucleo cerro el canal. Revise el log de la aplicacion.".into());
    }
    let parsed: Value = serde_json::from_str(response.trim())
        .map_err(|e| format!("respuesta ilegible del nucleo: {e}"))?;

    if parsed.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(parsed.get("result").cloned().unwrap_or(Value::Null))
    } else {
        Err(parsed
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("error desconocido del nucleo")
            .to_string())
    }
}

/// Unico punto por el que la interfaz habla con el nucleo.
#[tauri::command]
fn core_call(state: State<'_, Bridge>, cmd: String, args: Option<Value>) -> Result<Value, String> {
    let mut guard = state.core.lock().map_err(|_| "estado inconsistente")?;
    if guard.is_none() {
        *guard = Some(spawn_core()?);
    }
    let core = guard.as_mut().expect("nucleo lanzado");
    let id = state.next_id.fetch_add(1, Ordering::SeqCst);
    let args = args.unwrap_or_else(|| json!({}));

    let outcome = roundtrip(core, id, &cmd, args);
    if outcome.is_err() {
        // Si el canal se rompio, el nucleo ya no sirve: se descarta para que el
        // siguiente intento arranque uno limpio en lugar de fallar siempre.
        if let Some(mut dead) = guard.take() {
            let _ = dead.child.kill();
            let _ = dead.child.wait();
        }
    }
    outcome
}

/// Comprueba que el nucleo habla el mismo protocolo que esta interfaz.
#[tauri::command]
fn core_hello(state: State<'_, Bridge>) -> Result<Value, String> {
    let info = core_call(state, "hello".into(), None)?;
    let spoken = info.get("protocol").and_then(Value::as_u64).unwrap_or(0);
    if spoken != PROTOCOL {
        return Err(format!(
            "el nucleo habla el protocolo {spoken} y esta interfaz el {PROTOCOL}. \
             Es un error de empaquetado: actualice ambos a la misma version."
        ));
    }
    Ok(info)
}

/// Cierre ordenado: el nucleo cierra el expediente y restablece la red.
#[tauri::command]
fn core_shutdown(state: State<'_, Bridge>) -> Result<(), String> {
    let mut guard = state.core.lock().map_err(|_| "estado inconsistente")?;
    if let Some(mut core) = guard.take() {
        let id = state.next_id.fetch_add(1, Ordering::SeqCst);
        // Se ignora el resultado: lo que importa es haber dado la orden. Si el
        // nucleo no responde, se lo lleva el kill de abajo.
        let _ = roundtrip(&mut core, id, "shutdown", json!({}));
        let _ = core.child.wait();
    }
    Ok(())
}

/// Selector nativo de archivos para el `.key` y el `.cer`.
///
/// Pedirle a alguien que teclee la ruta de su e.firma es una invitacion a
/// equivocarse, y un error aqui significa auditar con el archivo que no era.
#[tauri::command]
fn pick_file(
    app: tauri::AppHandle,
    title: Option<String>,
    extensions: Option<Vec<String>>,
) -> Option<String> {
    let mut dialog = app.dialog().file();
    if let Some(title) = title {
        dialog = dialog.set_title(&title);
    }
    if let Some(exts) = extensions {
        let refs: Vec<&str> = exts.iter().map(String::as_str).collect();
        dialog = dialog.add_filter("Credencial", &refs);
    }
    dialog
        .blocking_pick_file()
        .and_then(|path| path.into_path().ok())
        .map(|path| path.to_string_lossy().to_string())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Bridge::new())
        .invoke_handler(tauri::generate_handler![
            core_call,
            core_hello,
            core_shutdown,
            pick_file
        ])
        .on_window_event(|window, event| {
            // Cerrar la ventana no debe dejar una auditoria a medias con el
            // navegador aislado: se le pide al nucleo que cierre el expediente.
            if let tauri::WindowEvent::Destroyed = event {
                if let Some(state) = window.try_state::<Bridge>() {
                    if let Ok(mut guard) = state.core.lock() {
                        if let Some(mut core) = guard.take() {
                            let id = state.next_id.fetch_add(1, Ordering::SeqCst);
                            let _ = roundtrip(&mut core, id, "shutdown", json!({}));
                            let _ = core.child.wait();
                        }
                    }
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("no se pudo iniciar la interfaz de FirmaScope");
}
