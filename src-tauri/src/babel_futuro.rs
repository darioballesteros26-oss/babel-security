// ============================================================
// BABEL — FUNCIONES CON POTENCIAL FUTURO
// ============================================================
//
// Este módulo contiene funciones que no están activas todavía
// pero tienen valor para versiones futuras de Babel.
//
// NO se incluye en main.rs ni se llama desde ningún sitio.
// Cuando llegue el momento, se activan desde main.rs con un
// comando Tauri nuevo.
//
// Funciones archivadas:
//
//   1. iniciar_watch() — Procesado automático en segundo plano
//      Vigilaba entrada_babel/ y procesaba archivos sin intervención.
//      Potencial: planes Pro/Egida — el abogado llega y los documentos
//      ya están traducidos y cifrados automáticamente.
//
//   2. detectar_archivo_arrastrado() — Drag al icono del dock
//      Detecta cuando el usuario arrastra un archivo encima del
//      ejecutable en el Finder de macOS.
//      Potencial: experiencia más fluida — arrastra PDF encima del
//      icono de Babel en el dock y se traduce sin abrir la app.

#![allow(dead_code, unused_imports)]

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::traductor;

const CARPETA_ENTRADA: &str = "../entrada_babel";
const CARPETA_SALIDA: &str = "../salida_babel";
const EXTENSIONES_VALIDAS: &[&str] = &["pdf", "docx", "txt"];

// ============================================================
// FUNCIÓN 1 — WATCH: Procesado automático en segundo plano
// ============================================================
//
// Cómo activarla en el futuro:
//
//   1. Añadir en main.rs un comando Tauri nuevo:
//
//      #[tauri::command]
//      fn iniciar_modo_watch(sesion: tauri::State<SesionActiva>) {
//          std::thread::spawn(move || {
//              let dict = /* cargar diccionario */;
//              let subclave = /* leer de sesión */;
//              babel_futuro::iniciar_watch(&dict, &subclave, 5);
//          });
//      }
//
//   2. En el frontend, un toggle en el sidebar que lo active.
//
//   3. Registrarlo en generate_handler![].
//
// Útil para: planes Pro y Egida — procesado nocturno automático.

/// Vigila `entrada_babel/` cada N segundos.
/// Cuando aparece un archivo PDF, DOCX o TXT nuevo, lo procesa
/// (traduce y cifra) y lo mueve a `salida_babel/`.
/// Diseñado para correr en un hilo separado en segundo plano.
pub fn iniciar_watch(dict: &HashMap<String, String>, subclave_hex: &str, intervalo_segundos: u64) {
    // Crear carpetas si no existen
    let _ = fs::create_dir_all(CARPETA_ENTRADA);
    let _ = fs::create_dir_all(CARPETA_SALIDA);

    // Registro de archivos ya procesados para no repetirlos
    // Clave: ruta del archivo | Valor: timestamp de última modificación
    let mut procesados: HashMap<PathBuf, SystemTime> = HashMap::new();

    loop {
        let entradas = match fs::read_dir(CARPETA_ENTRADA) {
            Ok(e) => e,
            Err(_) => {
                std::thread::sleep(Duration::from_secs(intervalo_segundos));
                continue;
            }
        };

        for entrada in entradas.flatten() {
            let path = entrada.path();

            if !path.is_file() {
                continue;
            }

            // Filtrar por extensión válida
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();

            if !EXTENSIONES_VALIDAS.contains(&ext.as_str()) {
                continue;
            }

            // Obtener timestamp de modificación
            let modificado = match entrada.metadata().and_then(|m| m.modified()) {
                Ok(t) => t,
                Err(_) => continue,
            };

            // Saltar si ya fue procesado con el mismo timestamp
            if procesados.get(&path) == Some(&modificado) {
                continue;
            }

            // Procesar el archivo
            traductor::procesar_archivo_inteligente(
                path.to_str().unwrap_or(""),
                dict,
                subclave_hex,
                "sistema",
            );

            // Mover a salida y registrar como procesado
            mover_a_salida(&path);
            procesados.insert(path, modificado);
        }

        std::thread::sleep(Duration::from_secs(intervalo_segundos));
    }
}

/// Mueve un archivo procesado de `entrada_babel/` a `salida_babel/`.
/// Si no puede moverlo (distintos volúmenes), copia y borra.
fn mover_a_salida(ruta: &Path) {
    let nombre = match ruta.file_name() {
        Some(n) => n,
        None => return,
    };

    let nombre_salida = format!("procesado_{}", nombre.to_string_lossy());
    let destino = PathBuf::from(CARPETA_SALIDA).join(&nombre_salida);

    if fs::rename(ruta, &destino).is_err() {
        if fs::copy(ruta, &destino).is_ok() {
            let _ = fs::remove_file(ruta);
        }
    }
}

// ============================================================
// FUNCIÓN 2 — DRAG AL ICONO: Procesar desde el dock de macOS
// ============================================================
//
// Cómo activarla en el futuro:
//
//   En main() de main.rs, antes de arrancar Tauri:
//
//      if let Some(ruta) = babel_futuro::detectar_archivo_arrastrado() {
//          // Necesitas sesión activa — mostrar login primero
//          // Luego llamar a procesar_archivo_arrastrado()
//      }
//
// Útil para: experiencia premium — arrastra un PDF encima del
// icono de Babel en el dock y se procesa automáticamente.

/// Detecta si el usuario arrastró un archivo encima del ejecutable.
/// Devuelve la ruta si el primer argumento es un archivo válido.
pub fn detectar_archivo_arrastrado() -> Option<PathBuf> {
    // args()[0] es el nombre del ejecutable — lo saltamos con nth(1)
    let ruta = std::env::args().nth(1)?;
    let path = PathBuf::from(&ruta);

    if !path.is_file() {
        return None;
    }

    let extension = path.extension()?.to_str()?.to_lowercase();
    if EXTENSIONES_VALIDAS.contains(&extension.as_str()) {
        Some(path)
    } else {
        None
    }
}

/// Procesa un archivo arrastrado al ejecutable.
/// Lo copia a `entrada_babel/` y usa el motor estándar.
pub fn procesar_archivo_arrastrado(
    ruta: &Path,
    dict: &HashMap<String, String>,
    subclave_hex: &str,
    id_usuario: &str,
) {
    let _ = fs::create_dir_all(CARPETA_ENTRADA);

    let nombre = ruta
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("archivo"));
    let destino = PathBuf::from(CARPETA_ENTRADA).join(nombre);

    if fs::copy(ruta, &destino).is_err() {
        return;
    }

    traductor::procesar_archivo_inteligente(
        destino.to_str().unwrap_or(""),
        dict,
        subclave_hex,
        id_usuario,
    );
}
