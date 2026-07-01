#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod babel_p2p;
mod bip39_words;
mod seguridad;
mod traductor;

use base64::Engine;
use chrono;
use hex;
use rand::RngCore;
use seguridad::{NivelAcceso, UsuarioBabel};
use serde;
use serde_json;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use tauri::{Emitter, Manager};
use zeroize::{Zeroize, Zeroizing};

const MAX_ARCHIVOS: usize = 1000;

// ============================================================
// HELPER — Borrado seguro de archivos temporales
// ============================================================
// Sobreescribe el archivo con ceros antes de borrarlo.
// Así los bytes no quedan recuperables en disco aunque el SO
// no haya sobreescrito el sector todavía.
// Úsalo siempre que el archivo haya existido en claro (sin cifrar).
pub fn borrar_seguro(ruta: &str) {
    if let Ok(meta) = fs::symlink_metadata(ruta) {
        if meta.file_type().is_symlink() {
            return;
        }
        let tamaño = meta.len() as usize;
        if tamaño > 0 {
            // sync_all() llama a fsync() tras cada pasada para forzar escritura
            // al dispositivo antes de la siguiente. En SSD el wear leveling sigue
            // siendo una limitación del hardware, pero al menos cada pasada se
            // compromete antes de continuar. El contenido ya va cifrado AES-256-GCM.
            for patron in &[vec![0x00u8; tamaño], vec![0xFFu8; tamaño], vec![0xAAu8; tamaño]] {
                // O_NOFOLLOW previene TOCTOU: si la ruta se convirtió en symlink
                // entre symlink_metadata y open, el kernel rechaza la apertura.
                #[cfg(unix)]
                let open_result = {
                    use std::os::unix::fs::OpenOptionsExt;
                    #[cfg(target_os = "macos")] const O_NOFOLLOW: i32 = 0x100;
                    #[cfg(not(target_os = "macos"))] const O_NOFOLLOW: i32 = 0x20000;
                    std::fs::OpenOptions::new().write(true).custom_flags(O_NOFOLLOW).open(ruta)
                };
                #[cfg(not(unix))]
                let open_result = std::fs::OpenOptions::new().write(true).open(ruta);
                if let Ok(mut f) = open_result {
                    use std::io::Write;
                    let _ = f.write_all(patron);
                    let _ = f.sync_all();
                }
            }
        }
    }
    let _ = fs::remove_file(ruta);
}

// ============================================================
// ESTADO GLOBAL — Sesión activa del usuario
// ============================================================

pub struct SesionActiva {
    pub subclave_hex: Mutex<Zeroizing<String>>,
    pub usuario: Mutex<String>,
    pub diccionario: Mutex<HashMap<String, String>>,
    pub idioma: Mutex<String>,
    pub buzon_activo: Mutex<String>,
    pub contador: Mutex<u32>,
}

impl SesionActiva {
    fn nueva() -> Self {
        Self {
            subclave_hex: Mutex::new(Zeroizing::new(String::new())),
            usuario: Mutex::new(String::new()),
            diccionario: Mutex::new(HashMap::new()),
            idioma: Mutex::new(String::from("es_en")),
            buzon_activo: Mutex::new(String::from("todos")),
            contador: Mutex::new(0),
        }
    }

    fn limpiar(&self) {
        use zeroize::Zeroize;
        if let Ok(mut s) = self.subclave_hex.lock() {
            seguridad::munlock_bytes(s.as_bytes()); // liberar antes de zeroizar
            s.zeroize();
        }
        if let Ok(mut u) = self.usuario.lock() {
            u.clear();
        }
        if let Ok(mut d) = self.diccionario.lock() {
            d.clear();
        }
        if let Ok(mut i) = self.idioma.lock() {
            i.clear();
        }
        if let Ok(mut b) = self.buzon_activo.lock() {
            b.clear();
        }
    }
}

// ============================================================
// HELPERS — Rutas absolutas de Babel
// ============================================================
// ~/Babel/          → archivos del sistema (salt, config, bloqueo...)
// ~/Babel/archivos/ → documentos cifrados del usuario
// ~/Babel/tmp/      → temporales durante traducción (se borran solos)
//
// Estas funciones siempre devuelven la misma ruta,
// independientemente de desde dónde se ejecute el .app.

pub fn babel_dir() -> std::path::PathBuf {
    // B1: si dirs::home_dir() falla (p. ej. usuario sin /etc/passwd), probar variables
    // de entorno antes de caer en el directorio de trabajo actual (inseguro en prod).
    let home = dirs::home_dir()
        .or_else(|| std::env::var("HOME").ok().map(std::path::PathBuf::from))
        .or_else(|| std::env::var("USERPROFILE").ok().map(std::path::PathBuf::from))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let dir = home.join("Babel");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn babel_path(nombre: &str) -> String {
    babel_dir().join(nombre).to_string_lossy().to_string()
}

/// ~/Babel/archivos/ — donde viven los documentos cifrados del usuario
fn archivos_dir() -> std::path::PathBuf {
    let dir = babel_dir().join("archivos");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn archivos_path(nombre: &str) -> String {
    archivos_dir().join(nombre).to_string_lossy().to_string()
}
/// ~/Babel/guardados/ — donde viven los documentos guardados sin traducir
fn guardados_dir() -> std::path::PathBuf {
    let dir = babel_dir().join("guardados");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn guardados_path(nombre: &str) -> String {
    guardados_dir().join(nombre).to_string_lossy().to_string()
}

/// ~/Babel/tmp/ — temporales de traducción. Se borran tras cada uso.
fn tmp_dir() -> std::path::PathBuf {
    let dir = babel_dir().join("tmp");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn tmp_path(nombre: &str) -> String {
    tmp_dir().join(nombre).to_string_lossy().to_string()
}
// Valida que una ruta pertenece a una carpeta autorizada usando paths canónicos
// Previene path traversal con ../../../etc/passwd
fn validar_ruta_en(ruta: &str, base: std::path::PathBuf) -> Result<(), String> {
    // Prevenir path traversal
    if ruta.contains("..") {
        return Err("Ruta no autorizada.".into());
    }
    // Verificar existencia
    if !std::path::Path::new(ruta).exists() {
        return Err("Archivo no encontrado.".into());
    }
    // Canonicalizar ambas rutas para resolver symlinks de macOS (/private/Users)
    let canonical_ruta = std::path::Path::new(ruta)
        .canonicalize()
        .map_err(|_| "Ruta inválida.".to_string())?;
    let canonical_base = base.canonicalize().map_err(|_| "Error base.".to_string())?;
    if !canonical_ruta.starts_with(&canonical_base) {
        return Err("Ruta no autorizada.".into());
    }
    Ok(())
}
// ============================================================
// COMANDO 1 — Verificación de entorno
// ============================================================

#[tauri::command]
fn verificar_entorno_seguro() -> Result<String, String> {
    let sandbox = seguridad::AntiSandbox::analizar_entorno();
    if !sandbox.seguro {
        // E-3: no filtrar nombres de procesos — solo el recuento
        return Err(format!(
            "Entorno comprometido: {} amenaza(s) detectada(s)",
            sandbox.amenazas.len()
        ));
    }

    if let Ok(keylogger) = seguridad::AntiKeylogger::blindaje_total(None) {
        if !keylogger.amenazas.is_empty() {
            return Err(format!(
                "Procesos sospechosos: {} proceso(s) detectado(s)",
                keylogger.amenazas.len()
            ));
        }
    }
    // Comprobar FileVault
    #[cfg(target_os = "macos")]
    {
        let fv = std::process::Command::new("fdesetup")
            .arg("status")
            .output();
        if let Ok(out) = fv {
            let status = String::from_utf8_lossy(&out.stdout);
            if !status.contains("On") {
                return Ok("BABEL SEGURO — FileVault desactivado. Recomendamos activarlo en Preferencias del Sistema.".into());
            }
        }
    }

    // Licencia por hardware — vincula Babel al número de serie del Mac.
    // Primera vez: crea licencia.babel con el hash del serial.
    // Siguientes veces: verifica que el serial coincide. Si no, acceso denegado.

    #[cfg(target_os = "macos")]
    let serial = std::process::Command::new("system_profiler")
        .args(["SPHardwareDataType"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| {
            s.lines()
                .find(|l| l.contains("Serial Number"))
                .map(|l| l.trim().to_string())
        })
        .unwrap_or_else(|| "UNKNOWN".to_string());

    #[cfg(not(target_os = "macos"))]
    let serial = "WINDOWS-NO-SERIAL".to_string();

    use sha2::Digest;
    let hash = format!("{:x}", sha2::Sha256::digest(serial.as_bytes()));
    let ruta_licencia = babel_path("licencia.babel");

    if std::path::Path::new(&ruta_licencia).exists() {
        let guardado = fs::read_to_string(&ruta_licencia)
            .unwrap_or_default()
            .trim()
            .to_string();
        if guardado != hash {
            return Err("Licencia inválida. Babel está vinculado a otro equipo.".into());
        }
    } else {
        let _ = fs::write(&ruta_licencia, &hash);
    };

    Ok("BABEL SEGURO — Todos los protocolos activos.".into())
}
// ============================================================
// COMANDO 2 — Comprobar si el búnker existe
// ============================================================

#[tauri::command]
fn comprobar_estado_bunker() -> bool {
    Path::new(&babel_path("usuarios.babel")).exists()
}

// ============================================================
// COMANDO 3 — Crear el búnker por primera vez
// ============================================================

#[tauri::command]
fn crear_acceso_bunker(maestra: String, usuario: String, pass: String) -> Result<String, String> {
    // Zeroizing garantiza borrado en cualquier salida, incluidos early returns
    let pass = Zeroizing::new(pass);
    let maestra = Zeroizing::new(maestra);

    if maestra.len() < 12 {
        return Err("La llave maestra debe tener al menos 12 caracteres.".into());
    }
    if pass.len() < 8 {
        return Err("La contraseña debe tener al menos 8 caracteres.".into());
    }
    let tiene_digito = pass.chars().any(|c| c.is_ascii_digit());
    let tiene_especial = pass.chars().any(|c| !c.is_alphanumeric());
    if !tiene_digito && !tiene_especial {
        return Err("La contraseña debe incluir al menos un número o un carácter especial.".into());
    }
    if usuario.trim().is_empty() {
        return Err("El nombre de usuario no puede estar vacío.".into());
    }
    if Path::new(&babel_path("usuarios.babel")).exists() {
        return Err("Ya existe un búnker. No se puede crear otro.".into());
    }

    let password_hash =
        seguridad::hash_password(pass.as_bytes()).map_err(|e| format!("Error Argon2id: {}", e))?;

    let nuevo_usuario = UsuarioBabel {
        nombre: usuario.trim().to_string(),
        password_hash,
        nivel: NivelAcceso::Luxury,
        id: format!(
            "{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        ),
        creditos: 9999,
    };

    let salt = traductor::cargar_o_crear_salt();
    let subclave = seguridad::derivar_subclave(maestra.as_bytes(), "babel-usuarios-v1", &salt)
        .map_err(|e| format!("Error derivando subclave: {}", e))?;

    let subclave_hex = Zeroizing::new(hex::encode(subclave.as_ref()));

    let mut json = Zeroizing::new(
        serde_json::to_string(&nuevo_usuario).map_err(|e| format!("Error serializando: {}", e))?,
    );

    let cifrado = seguridad::blindar_documento(&json, &subclave_hex)
        .map_err(|e| format!("Error cifrando: {}", e))?;
    json.zeroize();

    fs::write(&babel_path("usuarios.babel"), &cifrado)
        .map_err(|e| format!("Error guardando: {}", e))?;

    Ok(format!(
        "Búnker creado. Usuario '{}' blindado con AES-256-GCM.",
        nuevo_usuario.nombre
    ))
}

// ============================================================
// COMANDO 4 — Verificar login y guardar sesión
// ============================================================

fn incrementar_contador_y_bloquear(sesion: &tauri::State<SesionActiva>) -> Result<(), String> {
    // HMAC-SHA256 con master.salt: borrar intentos.dat no resetea el valor si hay sesión
    // activa en RAM, y el HMAC impide modificar el número sin conocer master.salt.
    let disco: u32 = seguridad::leer_contador_intentos();
    if let Ok(mut c) = sesion.contador.lock() {
        *c = (*c).max(disco) + 1;
        seguridad::escribir_contador_intentos(*c);
        if *c >= 3 {
            *c = 0;
            let _ = fs::remove_file(&babel_path("intentos.dat"));
            traductor::activar_bloqueo_disco()
                .map_err(|e| format!("Error crítico activando bloqueo: {}", e))?;
            return Err("Bloqueado 10 minutos por demasiados intentos fallidos.".into());
        }
    }
    Ok(())
}

#[tauri::command]
fn verificar_login(
    pass: String,
    pass_usuario: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<bool, String> {
    let pass = Zeroizing::new(pass);
    let pass_usuario = Zeroizing::new(pass_usuario);

    // Comprobar si hay bloqueo activo
    if let Some(ts) = seguridad::leer_bloqueo() {
        let restante = (ts + 600) - chrono::Local::now().timestamp();
        if restante > 0 {
            return Err(format!("Bloqueado. Espera {} segundos.", restante));
        } else {
            let _ = fs::remove_file(&babel_path("bloqueo.tmp"));
        }
    }

    let cifrado = fs::read(&babel_path("usuarios.babel"))
        .map_err(|_| "No se encontró el búnker.".to_string())?;

    let salt = traductor::cargar_o_crear_salt();
    let subclave = seguridad::derivar_subclave(pass.as_bytes(), "babel-usuarios-v1", &salt)
        .map_err(|e| format!("Error derivando subclave: {}", e))?;

    let subclave_hex = Zeroizing::new(hex::encode(subclave.as_ref()));

    let json = match seguridad::descifrar_documento(cifrado, &subclave_hex) {
        Ok(texto) => texto,
        Err(_) => {
            incrementar_contador_y_bloquear(&sesion)?;
            return Ok(false);
        }
    };

    let usuario_guardado: UsuarioBabel =
        serde_json::from_str(&json).map_err(|_| "Búnker corrupto.".to_string())?;

    let pass_ok = seguridad::verificar_password(&pass_usuario, &usuario_guardado.password_hash);
    if !pass_ok {
        incrementar_contador_y_bloquear(&sesion)?;
        return Ok(false);
    }

    if let Ok(mut s) = sesion.subclave_hex.lock() {
        *s = Zeroizing::new(subclave_hex.to_string());
        seguridad::mlock_bytes(s.as_bytes()); // evitar que el SO page la clave al swap
    }
    if let Ok(mut u) = sesion.usuario.lock() {
        *u = usuario_guardado.nombre.clone();
    }
    if let Ok(mut d) = sesion.diccionario.lock() {
        *d = traductor::cargar_diccionario("es_en", &subclave_hex, "todos");
    }

    // Login correcto — resetear contador (en RAM y en disco)
    if let Ok(mut c) = sesion.contador.lock() {
        *c = 0;
    }
    let _ = fs::remove_file(&babel_path("intentos.dat"));
    // Resetear amenazas conocidas para que el monitor periódico las reporte de nuevo
    seguridad::resetear_amenazas_conocidas();

    let mut json = Zeroizing::new(json);
    json.zeroize();

    Ok(true)
}

// ============================================================
// COMANDO 4b — Cambiar categoría del diccionario en caliente
// Recarga el diccionario filtrando por categoría (jurídico, médico, etc.)
// ============================================================
#[tauri::command]
fn cambiar_categoria_diccionario(
    categoria: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }

    let idioma = sesion
        .idioma
        .lock()
        .map_err(|_| "Error leyendo idioma.".to_string())?
        .clone();

    let nuevo_dict = traductor::cargar_diccionario(&idioma, &subclave_hex, &categoria);

    if let Ok(mut d) = sesion.diccionario.lock() {
        *d = nuevo_dict;
    }

    Ok(())
}

// ============================================================
// COMANDO 5 — Traducir documento vía selector de archivo
// ============================================================

#[tauri::command]
fn traducir_documento(
    nombre_archivo: String,
    contenido: Vec<u8>,
    sesion: tauri::State<SesionActiva>,
) -> Result<String, String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();

    if subclave_hex.is_empty() {
        return Err("No hay sesión activa. Inicia sesión primero.".into());
    }

    // Guardamos el temporal en ~/Babel/tmp/ — ruta absoluta, siempre funciona.
    // Extraemos solo el nombre base para evitar path traversal (../../etc/passwd).
    let nombre_solo = std::path::Path::new(&nombre_archivo)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Nombre de archivo inválido.")?
        .to_string();
    let ruta_temp = tmp_path(&nombre_solo);
    fs::write(&ruta_temp, &contenido).map_err(|e| format!("Error guardando temporal: {}", e))?;
    drop(Zeroizing::new(contenido));

    // Toda la lógica posterior se envuelve en closure para garantizar que
    // borrar_seguro se ejecute incluso si un mutex falla (early return).
    let resultado = (|| -> Result<String, String> {
        let id_usuario = sesion
            .usuario
            .lock()
            .map_err(|_| "Error".to_string())?
            .clone();

        let nombre_base = std::path::Path::new(&nombre_archivo)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(&nombre_archivo);

        // El resultado va a ~/Babel/archivos/ — carpeta visible en Finder
        let nombre_resultado = archivos_path(&format!("{}_{}.babel", id_usuario, nombre_base));

        let dict = sesion
            .diccionario
            .lock()
            .map_err(|_| "Error leyendo diccionario.".to_string())?
            .clone();

        let idioma_doc = sesion
            .idioma
            .lock()
            .map_err(|_| "Error leyendo idioma.".to_string())?
            .clone();

        let par_doc = idioma_a_par(&idioma_doc);

        traductor::procesar_archivo_inteligente(
            &ruta_temp,
            &dict,
            &subclave_hex,
            &id_usuario,
            par_doc,
        )?;

        Ok(nombre_resultado)
    })();

    // Borrado seguro: sobreescribe con ceros antes de eliminar.
    // Se ejecuta siempre, tanto en éxito como en error.
    borrar_seguro(&ruta_temp);

    resultado
}
// ============================================================
// COMANDO 5b — Traducir texto plano (chat de traducción)
// Traduce una cadena de texto usando el diccionario en RAM + NLLB.
// Devuelve (texto_traducido, palabras_sin_traducir).
// ============================================================
#[tauri::command]
fn traducir_texto(
    texto: String,
    idioma: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<(String, usize), String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }

    let dict = sesion
        .diccionario
        .lock()
        .map_err(|_| "Error leyendo diccionario.".to_string())?
        .clone();

    let par = idioma_a_par(&idioma);

    let (resultado, sin_traducir) =
        traductor::traducir_inteligente(&texto, &dict, &subclave_hex, par);
    Ok((resultado, sin_traducir))
}

// ============================================================
// COMANDO — Guardar documento sin traducir (vía ruta en disco)
// Cifra y guarda un archivo en ~/Babel/guardados/ sin traducirlo.
// El contenido se convierte a base64 antes de cifrar con AES-256-GCM.
// ============================================================

#[tauri::command]
fn guardar_documento_sin_traducir(
    nombre_archivo: String,
    ruta_completa: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<String, String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }

    let nombre_seguro = std::path::Path::new(&nombre_archivo)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Nombre de archivo inválido")?
        .to_string();
    let ext = std::path::Path::new(&nombre_seguro)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();
    if !["pdf", "docx", "txt", "png", "jpg", "jpeg"].contains(&ext.as_str()) {
        return Err(format!("Tipo de archivo no permitido: .{}", ext));
    }

    let id_usuario = sesion
        .usuario
        .lock()
        .map_err(|_| "Error".to_string())?
        .clone();

    // Canonicalizar para resolver symlinks — la autorización la gestiona el App Sandbox
    // a nivel OS mediante user-selected.read-write. El check starts_with(home) se elimina
    // porque en sandbox dirs::home_dir() apunta al contenedor, no al home real,
    // y rechazaría archivos legítimos seleccionados por el usuario con un file dialog.
    let ruta_canon = std::fs::canonicalize(&ruta_completa)
        .map_err(|_| "Ruta no accesible o inválida.".to_string())?;

    // S-1: límite de tamaño antes de leer en memoria
    let meta = std::fs::metadata(&ruta_canon).map_err(|e| format!("Error accediendo archivo: {}", e))?;
    if meta.len() > 100 * 1024 * 1024 {
        return Err("El archivo supera el límite de 100 MB.".into());
    }

    let contenido =
        fs::read(&ruta_canon).map_err(|e| format!("Error leyendo archivo: {}", e))?;

    let ts: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let nombre_base = std::path::Path::new(&nombre_archivo)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(&nombre_archivo);

    let nombre_cifrado = format!("{}_{}_{}.babel", id_usuario, nombre_base, ts);
    let ruta_cifrada = guardados_path(&nombre_cifrado);

    let contenido_b64 = traductor::comprimir_b64(&contenido);
    let cifrado = seguridad::blindar_documento(&contenido_b64, &subclave_hex)
        .map_err(|e| format!("Error cifrando: {}", e))?;

    fs::write(&ruta_cifrada, cifrado).map_err(|e| format!("Error guardando: {}", e))?;

    Ok(ruta_cifrada)
}

// ============================================================
// COMANDO — Listar archivos guardados (sin traducir)
// ============================================================

#[tauri::command]
fn listar_archivos_guardados(
    buzon: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<Vec<MetadatosArchivo>, String> {
    let id_usuario = sesion
        .usuario
        .lock()
        .map_err(|_| "Error".to_string())?
        .clone();
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error".to_string())?
        .clone();

    let mut archivos = Vec::new();

    // — ARCHIVOS GUARDADOS —
    let carpeta_g = guardados_dir();
    let ruta_index_g = guardados_path(".buzon_index_guardados.babel");
    let index_g: HashMap<String, String> = fs::read(&ruta_index_g)
        .ok()
        .and_then(|b| seguridad::descifrar_documento(b, &subclave_hex).ok())
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default();
    let nodos_g = cargar_nodos(
        std::path::Path::new(&guardados_path(".buzones_guardados.babel")),
        &subclave_hex,
    );

    if let Ok(entries) = fs::read_dir(&carpeta_g) {
        for entry in entries.flatten() {
            if archivos.len() >= MAX_ARCHIVOS {
                break;
            }
            let nombre = entry.file_name().to_string_lossy().to_string();
            if !nombre.starts_with(&format!("{}_", id_usuario)) || nombre.starts_with('.') {
                continue;
            }

            let buzon_archivo = index_g
                .get(&nombre)
                .cloned()
                .unwrap_or_else(|| "todos".to_string());
            if buzon != "todos" && buzon_archivo != buzon {
                continue;
            }

            let nombre_limpio = nombre
                .trim_start_matches(&format!("{}_", id_usuario))
                .to_string();
            let nombre_buzon = if buzon_archivo == "todos" || buzon_archivo.is_empty() {
                "todos".to_string()
            } else {
                nodos_g
                    .iter()
                    .find(|n| n.id == buzon_archivo)
                    .map(|n| n.nombre.clone())
                    .unwrap_or_else(|| "todos".to_string())
            };

            let fecha_g = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .map(|t| {
                    let ahora = std::time::SystemTime::now();
                    let dias = ahora.duration_since(t).unwrap_or_default().as_secs() / 86400;
                    if dias == 0 { "hoy".to_string() }
                    else if dias == 1 { "ayer".to_string() }
                    else if dias < 30 { format!("hace {} días", dias) }
                    else { format!("hace {} meses", dias / 30) }
                })
                .unwrap_or_else(|| "—".to_string());
            archivos.push(MetadatosArchivo {
                nombre: nombre_limpio,
                ruta: entry.path().to_string_lossy().to_string(),
                tamaño: entry.metadata().map(|m| m.len()).unwrap_or(0),
                fecha: fecha_g,
                idioma: "guardado".to_string(),
                buzon: nombre_buzon,
                es_traduccion: false,
            });
        }
    }

    // — ARCHIVOS TRADUCIDOS —
    let carpeta_a = archivos_dir();
    let ruta_index_a = archivos_path(".buzon_index.babel");
    let index_a: HashMap<String, String> = fs::read(&ruta_index_a)
        .ok()
        .and_then(|b| seguridad::descifrar_documento(b, &subclave_hex).ok())
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default();
    let nodos_a = cargar_nodos(
        std::path::Path::new(&archivos_path(".buzones.babel")),
        &subclave_hex,
    );

    if let Ok(entries) = fs::read_dir(&carpeta_a) {
        for entry in entries.flatten() {
            if archivos.len() >= MAX_ARCHIVOS {
                break;
            }
            let nombre = entry.file_name().to_string_lossy().to_string();
            if !nombre.starts_with(&format!("{}_", id_usuario)) || nombre.starts_with('.') {
                continue;
            }

            let buzon_archivo = index_a
                .get(&nombre)
                .cloned()
                .unwrap_or_else(|| "todos".to_string());
            if buzon != "todos" && buzon_archivo != buzon {
                continue;
            }

            let nombre_limpio = nombre
                .trim_start_matches(&format!("{}_", id_usuario))
                .replace("__orig", "")
                .to_string();

            let idioma = if nombre.contains("__orig") {
                "original".to_string()
            } else {
                nombre.split('_').nth(1).unwrap_or("").to_string()
            };

            let nombre_buzon = if buzon_archivo == "todos" || buzon_archivo.is_empty() {
                "todos".to_string()
            } else {
                nodos_a
                    .iter()
                    .find(|n| n.id == buzon_archivo)
                    .map(|n| n.nombre.clone())
                    .unwrap_or_else(|| "todos".to_string())
            };

            archivos.push(MetadatosArchivo {
                nombre: nombre_limpio,
                ruta: entry.path().to_string_lossy().to_string(),
                tamaño: entry.metadata().map(|m| m.len()).unwrap_or(0),
                fecha: "".to_string(),
                idioma,
                buzon: nombre_buzon,
                es_traduccion: true,
            });
        }
    }

    Ok(archivos)
}
// ============================================================
// COMANDO — Mover archivo guardado entre buzones
// Actualiza el índice cifrado .buzon_index_guardados.babel con el nuevo buzón destino.
// ============================================================
#[tauri::command]
fn mover_archivo_guardado(
    ruta: String,
    buzon_destino: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    validar_ruta_en(&ruta, guardados_dir())?;

    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();
    if subclave_hex.is_empty() { return Err("No hay sesión activa.".into()); }

    let ruta_index = guardados_path(".buzon_index_guardados.babel");

    let mut index: HashMap<String, String> = fs::read(&ruta_index)
        .ok()
        .and_then(|blob| seguridad::descifrar_documento(blob, &subclave_hex).ok())
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default();

    let nombre_clave = std::path::Path::new(&ruta)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    index.insert(nombre_clave, buzon_destino);

    let json = serde_json::to_string(&index).map_err(|e| format!("Error: {}", e))?;
    let cifrado =
        seguridad::blindar_documento(&json, &subclave_hex).map_err(|e| format!("Error: {}", e))?;
    fs::write(&ruta_index, cifrado).map_err(|e| format!("Error: {}", e))?;

    Ok(())
}
// ============================================================
// COMANDO 6 — Cerrar sesión (limpia la RAM)
// ============================================================
#[tauri::command]
fn cerrar_sesion_rust(sesion: tauri::State<SesionActiva>) {
    // Señalizar al hilo del servidor P2P para que salga y libere su copia de la subclave
    babel_p2p::detener_servidor_p2p();
    sesion.limpiar();
    // Borrar temporales en claro con 3 pasadas (0x00, 0xFF, 0xAA) + fsync antes de eliminar
    let tmp = babel_dir().join("tmp");
    if let Ok(entradas) = fs::read_dir(&tmp) {
        for entrada in entradas.flatten() {
            borrar_seguro(&entrada.path().to_string_lossy());
        }
    }
    // Matar Flask
}

// ============================================================
// COMANDO 7 — Traducir documento vía drag & drop nativo
// ============================================================

#[tauri::command]
fn traducir_documento_ruta(
    ruta: String,
    nombre_archivo: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<String, String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();

    if subclave_hex.is_empty() {
        return Err("No hay sesión activa. Inicia sesión primero.".into());
    }

    let path = Path::new(&ruta);
    if !path.is_file() {
        return Err(format!("Archivo no encontrado: {}", ruta));
    }

    // Restringir a los tipos de documento que Babel procesa realmente.
    // Evita que esta ruta abierta se use para leer ficheros arbitrarios del sistema.
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();
    if !["pdf", "docx", "txt"].contains(&ext.as_str()) {
        return Err(format!("Tipo de archivo no permitido: .{}", ext));
    }

    // Restringir al directorio home del usuario — evita path traversal desde XSS
    if let Some(home) = dirs::home_dir() {
        validar_ruta_en(&ruta, home)?;
    }

    // R-2: límite de tamaño antes de procesar
    let meta = std::fs::metadata(&ruta).map_err(|e| format!("Error accediendo archivo: {}", e))?;
    if meta.len() > 100 * 1024 * 1024 {
        return Err("El archivo supera el límite de 100 MB.".into());
    }

    let id_usuario = sesion
        .usuario
        .lock()
        .map_err(|_| "Error".to_string())?
        .clone();

    let _ts: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let nombre_base = std::path::Path::new(&nombre_archivo)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(&nombre_archivo);

    let dict = sesion
        .diccionario
        .lock()
        .map_err(|_| "Error leyendo diccionario.".to_string())?
        .clone();

    let idioma = sesion
        .idioma
        .lock()
        .map_err(|_| "Error leyendo idioma.".to_string())?
        .clone();

    let par = idioma_a_par(&idioma);

    let ruta_str = path.to_str()
        .ok_or_else(|| "Ruta contiene caracteres no permitidos (no-UTF8).".to_string())?;

    // Procesamos desde la ruta original — sin crear ningún temporal
    traductor::procesar_archivo_inteligente(
        ruta_str,
        &dict,
        &subclave_hex,
        &id_usuario,
        par,
    )?;

    let ruta_real = archivos_path(&format!("{}_{}.babel", id_usuario, nombre_base));
    Ok(ruta_real)
}

// ============================================================
// COMANDO 8 — Leer resultado para descarga
// ============================================================

#[tauri::command]
fn leer_resultado(ruta: String, sesion: tauri::State<SesionActiva>) -> Result<Vec<u8>, String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    // Seguridad: solo permitimos leer desde ~/Babel/archivos/
    validar_ruta_en(&ruta, archivos_dir())?;

    // R-3: comprobar tamaño antes de leer en memoria
    let meta = fs::metadata(&ruta).map_err(|e| format!("Error accediendo archivo: {}", e))?;
    if meta.len() > 100 * 1024 * 1024 {
        return Err("Archivo supera el límite de 100 MB.".into());
    }

    fs::read(&ruta).map_err(|e| format!("Error leyendo resultado: {}", e))
}

// ============================================================
// COMANDO 9 — Cambiar idioma y recargar diccionario
// ============================================================

#[tauri::command]
fn cambiar_idioma(idioma: String, sesion: tauri::State<SesionActiva>) -> Result<(), String> {
    if idioma.len() < 4
        || idioma.len() > 10
        || !idioma.chars().all(|c| c.is_ascii_lowercase() || c == '_')
        || !idioma.contains('_')
        || idioma.starts_with('_')
        || idioma.ends_with('_')
    {
        return Err("Idioma no válido.".into());
    }

    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }

    if let Ok(mut i) = sesion.idioma.lock() {
        *i = idioma.clone();
    }

    let nuevo_dict = traductor::cargar_diccionario(&idioma, &subclave_hex, "todos");
    if let Ok(mut d) = sesion.diccionario.lock() {
        *d = nuevo_dict;
    }

    Ok(())
}

// ============================================================
// COMANDO 10 — Listar archivos guardados
// ============================================================

#[derive(serde::Serialize)]
struct MetadatosArchivo {
    nombre: String,
    ruta: String,
    tamaño: u64,
    fecha: String,
    idioma: String,
    buzon: String,
    es_traduccion: bool,
}

#[tauri::command]
fn listar_archivos(
    _buzon: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<Vec<MetadatosArchivo>, String> {
    let id_usuario = sesion
        .usuario
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();

    let subclave_hex = Zeroizing::new(
        sesion
            .subclave_hex
            .lock()
            .map_err(|_| "Error leyendo sesión.".to_string())?
            .clone(),
    );

    // Carpeta absoluta — siempre ~/Babel/archivos/
    let carpeta = archivos_dir();
    let ruta_index = archivos_path(".buzon_index.babel");

    let index: HashMap<String, String> = fs::read(&ruta_index)
        .ok()
        .and_then(|blob| seguridad::descifrar_documento(blob, &subclave_hex).ok())
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default();

    let mut archivos = Vec::new();
    // Cargar nodos de buzones para resolver ID → nombre en los metadatos
    let nodos_buzon = cargar_nodos(
        std::path::Path::new(&archivos_path(".buzones.babel")),
        &subclave_hex,
    );
    let entradas = fs::read_dir(&carpeta).map_err(|e| format!("Error leyendo archivos: {}", e))?;

    for entrada in entradas.flatten() {
        if archivos.len() >= MAX_ARCHIVOS {
            break;
        }
        let path = entrada.path();
        if !path.is_file() {
            continue;
        }

        let nombre = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        if !nombre.ends_with(".babel") {
            continue;
        }
        if nombre == ".buzones.babel" || nombre == ".buzon_index.babel" {
            continue;
        }

        // Solo mostrar archivos del usuario activo
        if !nombre.starts_with(&format!("{}_", id_usuario)) {
            continue;
        }

        let ruta_completa = path.to_string_lossy().to_string();
        let buzon_archivo = index
            .get(&nombre)
            .cloned()
            .unwrap_or_else(|| "todos".to_string());

        if _buzon != "todos" && buzon_archivo != _buzon {
            continue;
        }

        let meta = entrada
            .metadata()
            .or_else(|_| fs::metadata(&path))
            .map_err(|e| format!("Error metadata: {}", e))?;

        let tamaño = meta.len();

        let fecha = meta
            .modified()
            .map(|t| {
                let ahora = std::time::SystemTime::now();
                let antiguedad = ahora.duration_since(t).unwrap_or_default();
                let dias = antiguedad.as_secs() / 86400;
                if dias == 0 {
                    "hoy".to_string()
                } else if dias == 1 {
                    "ayer".to_string()
                } else if dias < 30 {
                    format!("hace {} días", dias)
                } else {
                    let semanas = dias / 7;
                    if semanas < 8 {
                        format!("hace {} sem.", semanas)
                    } else {
                        format!("hace {} meses", dias / 30)
                    }
                }
            })
            .unwrap_or_else(|_| "—".to_string());

        archivos.push(MetadatosArchivo {
            nombre: nombre
                .trim_start_matches(&format!("{}_", id_usuario))
                .to_string(),
            ruta: ruta_completa,
            tamaño,
            fecha,
            idioma: if nombre.contains("__orig") {
                "original".to_string()
            } else {
                sesion
                    .idioma
                    .lock()
                    .map(|i| i.clone())
                    .unwrap_or_else(|_| "es_en".to_string())
            },
            buzon: if buzon_archivo == "todos" || buzon_archivo.is_empty() {
                "todos".to_string()
            } else {
                nodos_buzon
                    .iter()
                    .find(|n| n.id == buzon_archivo)
                    .map(|n| n.nombre.clone())
                    .unwrap_or_else(|| "todos".to_string())
            },
            es_traduccion: true,
        });
    }

    Ok(archivos)
}

// ============================================================
// ÁRBOL DE BUZONES — Struct + helpers compartidos
// Buzones jerárquicos: cada nodo tiene un ID permanente y un parent opcional.
// El ID es lo que se guarda en el índice de archivos, así renombrar nunca rompe nada.
// ============================================================

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
struct BuzonNodo {
    id: String,
    nombre: String,
    parent: Option<String>,
}

fn nuevo_id() -> String {
    use rand::rngs::OsRng;
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn cargar_nodos(ruta: &std::path::Path, subclave_hex: &str) -> Vec<BuzonNodo> {
    let blob = match fs::read(ruta) {
        Ok(b) => b,
        Err(_) => return vec![],
    };
    let json = match seguridad::descifrar_documento(blob, subclave_hex) {
        Ok(j) => j,
        Err(_) => return vec![],
    };
    // Formato nuevo: Vec<BuzonNodo>
    if let Ok(nodos) = serde_json::from_str::<Vec<BuzonNodo>>(&json) {
        return nodos;
    }
    // Migración automática desde formato viejo Vec<String> plano
    if let Ok(nombres) = serde_json::from_str::<Vec<String>>(&json) {
        return nombres
            .into_iter()
            .map(|n| BuzonNodo {
                id: nuevo_id(),
                nombre: n,
                parent: None,
            })
            .collect();
    }
    vec![]
}

fn guardar_nodos(
    nodos: &[BuzonNodo],
    ruta: &std::path::Path,
    subclave_hex: &str,
) -> Result<(), String> {
    let json = serde_json::to_string(nodos).map_err(|e| format!("Error: {}", e))?;
    let cifrado =
        seguridad::blindar_documento(&json, subclave_hex).map_err(|e| format!("Error: {}", e))?;
    fs::write(ruta, cifrado).map_err(|e| format!("Error: {}", e))?;
    Ok(())
}

fn recopilar_ids(nodos: &[BuzonNodo], id: &str) -> Vec<String> {
    let mut visitados = std::collections::HashSet::new();
    recopilar_ids_rec(nodos, id, &mut visitados)
}

fn recopilar_ids_rec(
    nodos: &[BuzonNodo],
    id: &str,
    visitados: &mut std::collections::HashSet<String>,
) -> Vec<String> {
    if !visitados.insert(id.to_string()) {
        return vec![];
    }
    let mut lista = vec![id.to_string()];
    for n in nodos {
        if n.parent.as_deref() == Some(id) {
            lista.extend(recopilar_ids_rec(nodos, &n.id, visitados));
        }
    }
    lista
}

// ============================================================
// COMANDO 11 — Crear buzón (traducciones)
// ============================================================

#[tauri::command]
fn crear_buzon(
    nombre: String,
    parent: Option<String>,
    sesion: tauri::State<SesionActiva>,
) -> Result<String, String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();
    if subclave_hex.is_empty() { return Err("No hay sesión activa.".into()); }

    let ruta = archivos_path(".buzones.babel");
    let mut nodos = cargar_nodos(std::path::Path::new(&ruta), &subclave_hex);
    let id = nuevo_id();
    nodos.push(BuzonNodo {
        id: id.clone(),
        nombre,
        parent,
    });
    guardar_nodos(&nodos, std::path::Path::new(&ruta), &subclave_hex)?;
    Ok(id)
}

// ============================================================
// COMANDO 12 — Listar buzones
// ============================================================

#[tauri::command]
fn listar_buzones(sesion: tauri::State<SesionActiva>) -> Result<Vec<BuzonNodo>, String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();

    let ruta = archivos_path(".buzones.babel");
    Ok(cargar_nodos(std::path::Path::new(&ruta), &subclave_hex))
}
// ============================================================
// COMANDOS — Buzones de archivos guardados (separados)
// ============================================================

#[tauri::command]
fn crear_buzon_guardado(
    nombre: String,
    parent: Option<String>,
    sesion: tauri::State<SesionActiva>,
) -> Result<String, String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();
    if subclave_hex.is_empty() { return Err("No hay sesión activa.".into()); }

    let ruta = guardados_path(".buzones_guardados.babel");
    let mut nodos = cargar_nodos(std::path::Path::new(&ruta), &subclave_hex);
    let id = nuevo_id();
    nodos.push(BuzonNodo {
        id: id.clone(),
        nombre,
        parent,
    });
    guardar_nodos(&nodos, std::path::Path::new(&ruta), &subclave_hex)?;
    Ok(id)
}

// Lista todos los buzones del sistema de archivos guardados (sin traducir)
#[tauri::command]
fn listar_buzones_guardados(sesion: tauri::State<SesionActiva>) -> Result<Vec<BuzonNodo>, String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();

    let ruta = guardados_path(".buzones_guardados.babel");
    Ok(cargar_nodos(std::path::Path::new(&ruta), &subclave_hex))
}
// ============================================================
// COMANDO 13 — Exportar archivo al Finder (save panel nativo)
// ============================================================

#[tauri::command]
fn exportar_archivo(
    ruta: String,
    app: tauri::AppHandle,
    sesion: tauri::State<SesionActiva>,
) -> Result<String, String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    // Seguridad: solo permitimos exportar desde ~/Babel/archivos/ o ~/Babel/guardados/
    validar_ruta_en(&ruta, archivos_dir()).or_else(|_| validar_ruta_en(&ruta, guardados_dir()))?;

    if !Path::new(&ruta).exists() {
        return Err(format!("Archivo no encontrado: {}", ruta));
    }

    let nombre = Path::new(&ruta)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    if nombre.is_empty() {
        return Err("No se pudo extraer el nombre del archivo.".into());
    }

    // Muestra el save panel nativo del Finder — el usuario elige dónde guardar.
    // user-selected.read-write concede acceso al destino elegido dentro del sandbox.
    use tauri_plugin_dialog::DialogExt;
    let destino_opt = app
        .dialog()
        .file()
        .set_file_name(&nombre)
        .blocking_save_file();

    let destino_path = match destino_opt {
        Some(fp) => fp.into_path().map_err(|e| format!("Error procesando ruta de destino: {}", e))?,
        None => return Err("Exportación cancelada.".into()),
    };

    std::fs::copy(&ruta, &destino_path)
        .map_err(|e| format!("Error al copiar: {}", e))?;

    Ok(destino_path.to_string_lossy().to_string())
}

// ============================================================
// COMANDO 13b — Exportar múltiples archivos a una carpeta
// Muestra UN folder picker nativo; copia todos los archivos ahí.
// ============================================================
#[tauri::command]
fn exportar_archivos_a_carpeta(
    rutas: Vec<String>,
    app: tauri::AppHandle,
    sesion: tauri::State<SesionActiva>,
) -> Result<u32, String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }

    use tauri_plugin_dialog::DialogExt;
    let carpeta_opt = app.dialog().file().blocking_pick_folder();
    let carpeta = match carpeta_opt {
        Some(fp) => fp.into_path().map_err(|e| format!("Error procesando carpeta: {}", e))?,
        None => return Err("Exportación cancelada.".into()),
    };

    let mut copiados: u32 = 0;
    for ruta in &rutas {
        if validar_ruta_en(ruta, archivos_dir())
            .or_else(|_| validar_ruta_en(ruta, guardados_dir()))
            .is_err()
        {
            continue;
        }
        let nombre = match Path::new(ruta).file_name() {
            Some(n) => n.to_string_lossy().to_string(),
            None => continue,
        };
        let destino = carpeta.join(&nombre);
        if std::fs::copy(ruta, &destino).is_ok() {
            copiados += 1;
        }
    }

    Ok(copiados)
}

// ============================================================
// COMANDO 14 — Mover archivos entre buzones
// ============================================================

#[tauri::command]
fn mover_archivo(
    ruta: String,
    buzon_destino: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    validar_ruta_en(&ruta, archivos_dir())?;

    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();
    if subclave_hex.is_empty() { return Err("No hay sesión activa.".into()); }

    let ruta_index = archivos_path(".buzon_index.babel");

    let mut index: HashMap<String, String> = fs::read(&ruta_index)
        .ok()
        .and_then(|blob| seguridad::descifrar_documento(blob, &subclave_hex).ok())
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default();

    let nombre_clave = std::path::Path::new(&ruta)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let nombre_orig = format!("{}__orig.babel", nombre_clave.trim_end_matches(".babel"));
    index.insert(nombre_clave, buzon_destino.clone());
    index.insert(nombre_orig, buzon_destino);

    let json = serde_json::to_string(&index).map_err(|e| format!("Error: {}", e))?;
    let cifrado =
        seguridad::blindar_documento(&json, &subclave_hex).map_err(|e| format!("Error: {}", e))?;
    fs::write(&ruta_index, cifrado).map_err(|e| format!("Error: {}", e))?;

    Ok(())
}

// ============================================================
// COMANDO 15 — Eliminar buzón
// ============================================================

#[tauri::command]
fn eliminar_buzon(id: String, sesion: tauri::State<SesionActiva>) -> Result<(), String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();
    if subclave_hex.is_empty() { return Err("No hay sesión activa.".into()); }

    let ruta = archivos_path(".buzones.babel");
    let mut nodos = cargar_nodos(std::path::Path::new(&ruta), &subclave_hex);
    let a_eliminar = recopilar_ids(&nodos, &id);
    nodos.retain(|n| !a_eliminar.contains(&n.id));
    guardar_nodos(&nodos, std::path::Path::new(&ruta), &subclave_hex)
}
// ============================================================
// COMANDO 15b — Renombrar buzón de traducciones (por ID)
// Solo cambia el nombre visible. El índice de archivos nunca se toca
// porque referencia el ID, que es permanente.
// ============================================================
#[tauri::command]
fn renombrar_buzon(
    id: String,
    nombre_nuevo: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();
    if subclave_hex.is_empty() { return Err("No hay sesión activa.".into()); }

    let ruta = archivos_path(".buzones.babel");
    let mut nodos = cargar_nodos(std::path::Path::new(&ruta), &subclave_hex);
    if let Some(n) = nodos.iter_mut().find(|n| n.id == id) {
        n.nombre = nombre_nuevo;
    }
    guardar_nodos(&nodos, std::path::Path::new(&ruta), &subclave_hex)
}
// ============================================================
// COMANDO 16 — Eliminar archivo con zeroize
// ============================================================
#[tauri::command]
fn renombrar_archivo(
    ruta: String,
    nombre_nuevo: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<String, String> {
    validar_ruta_en(&ruta, archivos_dir()).or_else(|_| validar_ruta_en(&ruta, guardados_dir()))?;

    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error sesión.".to_string())?
        .clone();
    let id_usuario = sesion
        .usuario
        .lock()
        .map_err(|_| "Error sesión.".to_string())?
        .clone();

    let guardados_canon = guardados_dir().canonicalize().unwrap_or_else(|_| guardados_dir());
    let ruta_canon_local = std::path::Path::new(&ruta)
        .canonicalize()
        .unwrap_or_else(|_| std::path::PathBuf::from(&ruta));
    let es_guardado = ruta_canon_local.starts_with(&guardados_canon);
    let dir = if es_guardado {
        guardados_dir()
    } else {
        archivos_dir()
    };

    let nombre_viejo = std::path::Path::new(&ruta)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    // Nuevo nombre manteniendo prefijo de usuario y extensión
    let nombre_limpio = nombre_nuevo
        .trim()
        .replace(['\0', '/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
    if nombre_limpio.is_empty() {
        return Err("El nombre no puede estar vacío.".to_string());
    }
    let nuevo_nombre_archivo = format!("{}_{}.babel", id_usuario, nombre_limpio);
    let nueva_ruta = dir.join(&nuevo_nombre_archivo);

    fs::rename(&ruta, &nueva_ruta).map_err(|e| format!("Error renombrando: {}", e))?;

    // Renombrar también el archivo __orig.babel compañero (traducciones)
    let nombre_viejo_orig = format!("{}__orig.babel", nombre_viejo.trim_end_matches(".babel"));
    let nuevo_nombre_orig = format!("{}__orig.babel", nuevo_nombre_archivo.trim_end_matches(".babel"));
    let ruta_orig_vieja = dir.join(&nombre_viejo_orig);
    if ruta_orig_vieja.exists() {
        let _ = fs::rename(&ruta_orig_vieja, dir.join(&nuevo_nombre_orig));
    }

    // Actualizar índice de buzones
    let ruta_index = if es_guardado {
        guardados_path(".buzon_index_guardados.babel")
    } else {
        archivos_path(".buzon_index.babel")
    };
    let mut index: HashMap<String, String> = fs::read(&ruta_index)
        .ok()
        .and_then(|b| seguridad::descifrar_documento(b, &subclave_hex).ok())
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default();
    if let Some(buzon) = index.remove(&nombre_viejo) {
        let buzon_orig = index.remove(&nombre_viejo_orig).unwrap_or(buzon.clone());
        index.insert(nuevo_nombre_archivo, buzon);
        index.insert(nuevo_nombre_orig, buzon_orig);
        let json = serde_json::to_string(&index).map_err(|e| format!("Error: {}", e))?;
        let cifrado = seguridad::blindar_documento(&json, &subclave_hex)
            .map_err(|e| format!("Error: {}", e))?;
        let _ = fs::write(&ruta_index, cifrado);
    }

    Ok(nueva_ruta.to_string_lossy().to_string())
}

#[tauri::command]
fn eliminar_archivo(ruta: String, sesion: tauri::State<SesionActiva>) -> Result<(), String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    validar_ruta_en(&ruta, archivos_dir()).or_else(|_| validar_ruta_en(&ruta, guardados_dir()))?;

    let meta_sym = fs::symlink_metadata(&ruta)
        .map_err(|e| format!("Error leyendo metadata: {}", e))?;
    if meta_sym.file_type().is_symlink() {
        return Err("No se puede eliminar un enlace simbólico.".into());
    }

    // 3 pasadas (0x00, 0xFF, 0xAA) + fsync + O_NOFOLLOW (igual que temporales)
    borrar_seguro(&ruta);

    Ok(())
}

// ============================================================
// COMANDO — Eliminar buzón del sistema de guardados
// ============================================================
#[tauri::command]
fn eliminar_buzon_guardado(id: String, sesion: tauri::State<SesionActiva>) -> Result<(), String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();
    if subclave_hex.is_empty() { return Err("No hay sesión activa.".into()); }

    let ruta = guardados_path(".buzones_guardados.babel");
    let mut nodos = cargar_nodos(std::path::Path::new(&ruta), &subclave_hex);
    let a_eliminar = recopilar_ids(&nodos, &id);
    nodos.retain(|n| !a_eliminar.contains(&n.id));
    guardar_nodos(&nodos, std::path::Path::new(&ruta), &subclave_hex)
}
// Abre la carpeta ~/Babel/guardados/ en Finder
#[tauri::command]
fn abrir_carpeta_guardados(sesion: tauri::State<SesionActiva>) -> Result<(), String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    tauri_plugin_opener::open_path(&*guardados_dir().to_string_lossy(), None::<&str>)
        .map_err(|e| format!("Error abriendo Finder: {}", e))
}

// Renombra un buzón del sistema de guardados (por ID)
#[tauri::command]
fn renombrar_buzon_guardado(
    id: String,
    nombre_nuevo: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();
    if subclave_hex.is_empty() { return Err("No hay sesión activa.".into()); }

    let ruta = guardados_path(".buzones_guardados.babel");
    let mut nodos = cargar_nodos(std::path::Path::new(&ruta), &subclave_hex);
    if let Some(n) = nodos.iter_mut().find(|n| n.id == id) {
        n.nombre = nombre_nuevo;
    }
    guardar_nodos(&nodos, std::path::Path::new(&ruta), &subclave_hex)
}

// ============================================================
// COMANDO — Guardar archivo sin traducir (vía bytes desde el explorador)
// Variante de guardar_documento_sin_traducir que recibe los bytes
// directamente desde TypeScript (para archivos seleccionados con input file).
// ============================================================
#[tauri::command]
fn guardar_bytes_sin_traducir(
    nombre_archivo: String,
    contenido: Vec<u8>,
    sesion: tauri::State<SesionActiva>,
) -> Result<String, String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();
    let id_usuario = sesion
        .usuario
        .lock()
        .map_err(|_| "Error".to_string())?
        .clone();

    if nombre_archivo.ends_with(".babel") {
        return Err("Los archivos .babel ya están cifrados.".into());
    }

    let ext_bytes = std::path::Path::new(&nombre_archivo)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();
    if !["pdf", "docx", "txt", "png", "jpg", "jpeg"].contains(&ext_bytes.as_str()) {
        return Err(format!("Tipo de archivo no permitido: .{}", ext_bytes));
    }

    if contenido.len() > 100 * 1024 * 1024 {
        return Err("El archivo supera el límite de 100 MB.".to_string());
    }

    let ts: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let nombre_base = std::path::Path::new(&nombre_archivo)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(&nombre_archivo);

    let nombre_cifrado = format!("{}_{}_{}.babel", id_usuario, nombre_base, ts);
    let ruta_cifrada = guardados_path(&nombre_cifrado);

    let contenido_b64 = traductor::comprimir_b64(&contenido);
    let cifrado = seguridad::blindar_documento(&contenido_b64, &subclave_hex)
        .map_err(|e| format!("Error cifrando: {}", e))?;

    fs::write(&ruta_cifrada, cifrado).map_err(|e| format!("Error guardando: {}", e))?;

    Ok(ruta_cifrada)
}
// ============================================================
// COMANDO 17 — Ver archivo descifrado
// ============================================================
fn extraer_texto_xml(xml: &str) -> String {
    let mut texto = String::new();
    let mut resto = xml;
    while let Some(i) = resto.find("<w:t") {
        let despues = &resto[i + 4..];
        if !despues.starts_with('>') && !despues.starts_with(' ') {
            resto = &resto[i + 4..];
            continue;
        }
        let desde = &resto[i..];
        if let Some(j) = desde.find('>') {
            let contenido = &desde[j + 1..];
            if let Some(k) = contenido.find("</w:t>") {
                let t = &contenido[..k];
                if !t.trim().is_empty() {
                    texto.push_str(t);
                }
            }
            resto = &desde[j + 1..];
        } else {
            break;
        }
    }
    texto
}

fn extraer_zip_html(raw_bytes: &[u8]) -> (String, String, String) {
    use std::io::Read;
    let cursor = std::io::Cursor::new(raw_bytes);
    let mut zip = match zip::ZipArchive::new(cursor) {
        Ok(z) => z,
        Err(_) => return (String::new(), String::new(), String::new()),
    };

    let mut header_html = String::new();
    let mut footer_html = String::new();
    let mut imagenes_html = String::new();

    // Encabezados y pies
    for nombre in &[
        "word/header1.xml",
        "word/header2.xml",
        "word/footer1.xml",
        "word/footer2.xml",
    ] {
        if let Ok(mut file) = zip.by_name(nombre) {
            let mut xml = String::new();
            if file.read_to_string(&mut xml).is_ok() {
                let texto = extraer_texto_xml(&xml);
                if !texto.trim().is_empty() {
                    let es_footer = nombre.contains("footer");
                    if es_footer && footer_html.is_empty() {
                        footer_html = formato_header_footer(&texto, false);
                    } else if !es_footer && header_html.is_empty() {
                        header_html = formato_header_footer(&texto, true);
                    }
                }
            }
        }
    }

    // Imágenes embebidas
    let n = zip.len();
    for i in 0..n {
        if let Ok(mut file) = zip.by_index(i) {
            let name = file.name().to_string();
            if name.starts_with("word/media/") {
                let mime = if name.ends_with(".png") {
                    "image/png"
                } else if name.ends_with(".jpg") || name.ends_with(".jpeg") {
                    "image/jpeg"
                } else if name.ends_with(".gif") {
                    "image/gif"
                } else if name.ends_with(".webp") {
                    "image/webp"
                } else {
                    continue;
                };
                let mut buf = Vec::new();
                if file.read_to_end(&mut buf).is_ok() {
                    let b64 = base64::engine::general_purpose::STANDARD.encode(&buf);
                    imagenes_html.push_str(&format!(
                        "<img src='data:{};base64,{}' style='max-width:100%;margin:10px 0;display:block;border-radius:4px;'>",
                        mime, b64
                    ));
                }
            }
        }
    }

    (header_html, footer_html, imagenes_html)
}

fn formato_header_footer(texto: &str, es_header: bool) -> String {
    let escaped = texto
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let borde = if es_header {
        "border-bottom:1px solid rgba(197,160,89,0.2);margin-bottom:16px;padding-bottom:10px;"
    } else {
        "border-top:1px solid rgba(197,160,89,0.2);margin-top:16px;padding-top:10px;"
    };
    format!(
        "<div style='font-size:0.8em;opacity:0.6;text-align:center;{}'>{}</div>",
        borde, escaped
    )
}

fn docx_a_html(raw_bytes: &[u8]) -> Result<String, String> {
    let mut imagenes: Vec<String> = Vec::new();
    if let Ok(mut zip) = zip::ZipArchive::new(std::io::Cursor::new(raw_bytes)) {
        let mut nombres: Vec<String> = (0..zip.len())
            .filter_map(|i| zip.by_index(i).ok().map(|f| f.name().to_string()))
            .filter(|n| n.starts_with("word/media/"))
            .collect();
        nombres.sort();
        for nombre in &nombres {
            if let Ok(mut f) = zip.by_name(nombre) {
                let ext = nombre.split('.').last().unwrap_or("png").to_lowercase();
                let mime = match ext.as_str() {
                    "jpg" | "jpeg" => "image/jpeg",
                    "gif" => "image/gif",
                    _ => "image/png",
                };
                let mut buf = Vec::new();
                if std::io::Read::read_to_end(&mut f, &mut buf).is_ok() {
                    let b64 = base64::engine::general_purpose::STANDARD.encode(&buf);
                    imagenes.push(format!("data:{};base64,{}", mime, b64));
                }
            }
        }
    }
    let img_idx = std::cell::Cell::new(0usize);

    let docx = match docx_rs::read_docx(raw_bytes) {
        Ok(d) => d,
        Err(_) => {
            if let Ok(xml_str) = std::str::from_utf8(raw_bytes) {
                let texto = extraer_texto_xml(xml_str);
                if !texto.trim().is_empty() {
                    return Ok(format!(
                        "html:<div style='font-family:Georgia,serif;line-height:1.7;color:inherit;white-space:pre-wrap;'>{}</div>",
                        texto.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
                    ));
                }
            }
            return Err("No se pudo leer el archivo.".into());
        }
    };

    let (header_html, footer_html, imagenes_html) = extraer_zip_html(raw_bytes);
    let mut html = String::from(
        "<div style='font-family:Georgia,serif;line-height:1.7;color:inherit;max-width:100%;'>",
    );
    if !header_html.is_empty() {
        html.push_str(&header_html);
    }

    let texto_run = |run: &docx_rs::Run| -> String {
        let bold = run.run_property.bold.is_some();
        let italic = run.run_property.italic.is_some();
        let mut out = String::new();
        for rc in &run.children {
            match rc {
                docx_rs::RunChild::Text(t) => {
                    let escaped = t
                        .text
                        .replace('&', "&amp;")
                        .replace('<', "&lt;")
                        .replace('>', "&gt;");
                    let s = if bold && italic {
                        format!("<strong><em>{}</em></strong>", escaped)
                    } else if bold {
                        format!("<strong>{}</strong>", escaped)
                    } else if italic {
                        format!("<em>{}</em>", escaped)
                    } else {
                        escaped
                    };
                    out.push_str(&s);
                }
                docx_rs::RunChild::Drawing(_) => {
                    let i = img_idx.get();
                    if i < imagenes.len() {
                        out.push_str(&format!(
                            "<img src='{}' style='max-width:100%;height:auto;display:block;margin:4px 0;'>",
                            imagenes[i]
                        ));
                        img_idx.set(i + 1);
                    }
                }
                docx_rs::RunChild::Tab(_) => out.push_str("&nbsp;&nbsp;&nbsp;&nbsp;"),
                _ => {}
            }
        }
        out
    };

    let parrafo_a_html = |para: &docx_rs::Paragraph| -> String {
        let mut p = String::from("<p style='margin:0 0 6px;'>");
        for cp in &para.children {
            if let docx_rs::ParagraphChild::Run(run) = cp {
                p.push_str(&texto_run(run));
            }
        }
        p.push_str("</p>");
        p
    };

    for child in &docx.document.children {
        match child {
            docx_rs::DocumentChild::Paragraph(para) => {
                html.push_str(&parrafo_a_html(para));
            }
            docx_rs::DocumentChild::Table(table) => {
                html.push_str("<table style='border-collapse:collapse;width:100%;margin:10px 0;'>");
                for row in &table.rows {
                    let docx_rs::TableChild::TableRow(tr) = row;
                    html.push_str("<tr>");
                    for cell in &tr.cells {
                        let docx_rs::TableRowChild::TableCell(tc) = cell;
                        html.push_str(
                            "<td style='border:1px solid rgba(197,160,89,0.3);padding:6px 10px;vertical-align:top;'>",
                        );
                        for cc in &tc.children {
                            if let docx_rs::TableCellContent::Paragraph(p) = cc {
                                html.push_str(&parrafo_a_html(p));
                            }
                        }
                        html.push_str("</td>");
                    }
                    html.push_str("</tr>");
                }
                html.push_str("</table>");
            }
            _ => {}
        }
    }

    if !imagenes_html.is_empty() {
        html.push_str(&format!(
            "<div style='margin-top:16px;'>{}</div>",
            imagenes_html
        ));
    }
    if !footer_html.is_empty() {
        html.push_str(&footer_html);
    }
    html.push_str("</div>");
    Ok(format!("html:{}", html))
}

#[tauri::command]
fn ver_archivo(ruta: String, sesion: tauri::State<SesionActiva>) -> Result<String, String> {
    validar_ruta_en(&ruta, archivos_dir()).or_else(|_| validar_ruta_en(&ruta, guardados_dir()))?;

    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();

    let bytes = fs::read(&ruta).map_err(|e| format!("Error leyendo archivo: {}", e))?;
    let contenido = seguridad::descifrar_documento(bytes, &subclave_hex)
        .map_err(|e| format!("Error descifrando: {}", e))?;

    if let Ok(raw_bytes) = traductor::descomprimir_b64(&contenido) {
        // DOCX — magic bytes PK
        if raw_bytes.starts_with(b"PK") {
            return docx_a_html(&raw_bytes);
        }
        // PDF — magic bytes %PDF
        if raw_bytes.starts_with(b"%PDF") {
            let b64 = base64::engine::general_purpose::STANDARD.encode(&raw_bytes);
            return Ok(format!("pdf:{}", b64));
        }

        // Imágenes: PNG, JPEG, GIF, WEBP
        let mime = if raw_bytes.starts_with(b"\x89PNG") {
            Some("image/png")
        } else if raw_bytes.starts_with(b"\xFF\xD8\xFF") {
            Some("image/jpeg")
        } else if raw_bytes.starts_with(b"GIF8") {
            Some("image/gif")
        } else if raw_bytes.len() > 12
            && &raw_bytes[0..4] == b"RIFF"
            && &raw_bytes[8..12] == b"WEBP"
        {
            Some("image/webp")
        } else {
            None
        };
        if let Some(mime) = mime {
            let b64 = base64::engine::general_purpose::STANDARD.encode(&raw_bytes);
            return Ok(format!("data:{};base64,{}", mime, b64));
        }

        // TXT — texto plano UTF-8
        if let Ok(texto_plano) = String::from_utf8(raw_bytes) {
            return Ok(texto_plano);
        }

        // Binario no reconocido
        return Err("Formato no previsualizable. Usa EXPORTAR.".into());
    }

    Ok(contenido)
}

// ============================================================
// COMANDO 18 — Guardar y cargar ajustes
// ============================================================

fn default_timeout() -> u32 { 15 }

#[derive(serde::Serialize, serde::Deserialize)]
pub struct AppSettings {
    borrar_al_salir: bool,
    diccionario: bool,
    idioma_origen: String,
    idioma_destino: String,
    categoria: String,
    #[serde(default = "default_timeout")]
    timeout_sesion_minutos: u32,
}

#[tauri::command]
fn save_settings(settings: AppSettings, sesion: tauri::State<SesionActiva>) -> Result<(), String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();

    let data = serde_json::to_string(&settings).map_err(|e| e.to_string())?;

    if subclave_hex.is_empty() {
        return Err("No hay sesión activa para cifrar los ajustes.".to_string());
    } else {
        let cifrado = seguridad::blindar_documento(&data, &subclave_hex)
            .map_err(|e| format!("Error cifrando ajustes: {}", e))?;
        fs::write(&babel_path("settings.babel"), cifrado).map_err(|e| e.to_string())?;
    }
    Ok(())
}

// Carga los ajustes — primero intenta settings.babel (cifrado), luego settings.json (plano)
#[tauri::command]
fn load_settings(sesion: tauri::State<SesionActiva>) -> Result<AppSettings, String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();

    let default = AppSettings {
        borrar_al_salir: false,
        diccionario: true,
        idioma_origen: "es".to_string(),
        idioma_destino: "en".to_string(),
        categoria: "todos".to_string(),
        timeout_sesion_minutos: 15,
    };

    if let Ok(cifrado) = fs::read(&babel_path("settings.babel")) {
        if let Ok(json) = seguridad::descifrar_documento(cifrado, &subclave_hex) {
            return serde_json::from_str(&json).map_err(|e| e.to_string());
        }
    }

    if let Ok(data) = fs::read_to_string(&babel_path("settings.json")) {
        if let Ok(settings) = serde_json::from_str::<AppSettings>(&data) {
            if !subclave_hex.is_empty() {
                if let Ok(json) = serde_json::to_string(&settings) {
                    if let Ok(cifrado) = seguridad::blindar_documento(&json, &subclave_hex) {
                        if fs::write(babel_path("settings.babel"), cifrado).is_ok() {
                            let _ = fs::remove_file(babel_path("settings.json"));
                            traductor::registrar_evento(
                                "settings.json migrado a settings.babel cifrado",
                                &subclave_hex,
                            );
                        } else {
                            traductor::registrar_evento(
                                "AVISO: migración settings.json fallida — no se pudo escribir settings.babel",
                                &subclave_hex,
                            );
                        }
                    }
                }
            }
            return Ok(settings);
        }
    }

    Ok(default)
}

// ============================================================
// HELPER — Genera 12 palabras aleatorias del diccionario BIP39
// ============================================================

fn generar_palabras_recuperacion() -> Vec<String> {
    use rand::rngs::OsRng;
    use rand::RngCore;
    let lista = bip39_words::WORDLIST;
    let n = lista.len() as u64;
    (0..12)
        .map(|_| {
            // Rechazo uniforme: evita sesgo al truncar módulo sobre rango no potencia-de-2
            let tope = (u64::MAX / n) * n;
            let idx = loop {
                let mut buf = [0u8; 8];
                OsRng.fill_bytes(&mut buf);
                let v = u64::from_le_bytes(buf);
                if v < tope { break (v % n) as usize; }
            };
            lista[idx].to_string()
        })
        .collect()
}

// ============================================================
// COMANDO 19 — Generar frase de recuperación BIP39
// ============================================================

#[tauri::command]
fn generar_frase_recuperacion(
    maestra: String,
    pass_usuario: String,
    _sesion: tauri::State<SesionActiva>,
) -> Result<Vec<String>, String> {
    // Zeroizing desde el primer momento para que serde_json nunca tenga copias no-zeroized
    let maestra = Zeroizing::new(maestra);
    let pass_usuario = Zeroizing::new(pass_usuario);

    // No se exige sesión: este comando se llama justo después de crear el búnker,
    // antes de que haya login. La seguridad viene de requerir la maestra válida.
    let palabras = generar_palabras_recuperacion();

    let salt_maestra = traductor::cargar_o_crear_salt();
    let recovery_salt = seguridad::derivar_recovery_salt_v2(&salt_maestra);
    // v3: Argon2id 131072/4/4 — mismos parámetros que el login
    let recovery_key = seguridad::derivar_clave_recuperacion_v3(&palabras, &recovery_salt)?;
    let recovery_key_hex = Zeroizing::new(hex::encode(recovery_key.as_ref()));
    // Construir JSON con format! para evitar copias de strings dentro de serde_json::Value
    let m_escaped = maestra.replace('\\', "\\\\").replace('"', "\\\"");
    let p_escaped = pass_usuario.replace('\\', "\\\\").replace('"', "\\\"");
    let mut datos_recovery = Zeroizing::new(format!("{{\"m\":\"{}\",\"p\":\"{}\"}}", m_escaped, p_escaped));
    let cifrado_recuperacion = seguridad::blindar_documento(&datos_recovery, &recovery_key_hex)
        .map_err(|e| format!("Error cifrando recovery.babel: {}", e))?;
    datos_recovery.zeroize();
    fs::write(&babel_path("recovery.babel"), &cifrado_recuperacion)
        .map_err(|e| format!("Error guardando recovery.babel: {}", e))?;

    let salt = traductor::cargar_o_crear_salt();
    let subclave = seguridad::derivar_subclave(maestra.as_bytes(), "babel-usuarios-v1", &salt)
        .map_err(|e| format!("Error derivando subclave: {}", e))?;
    let subclave_hex = Zeroizing::new(hex::encode(subclave.as_ref()));
    let cifrado_mnemonic = seguridad::blindar_documento(&palabras.join(" "), &subclave_hex)
        .map_err(|e| format!("Error cifrando mnemonic.babel: {}", e))?;
    fs::write(&babel_path("mnemonic.babel"), &cifrado_mnemonic)
        .map_err(|e| format!("Error guardando mnemonic.babel: {}", e))?;
    // maestra y pass_usuario se zeroizan automáticamente al salir del scope (Zeroizing<String>)
    Ok(palabras)
}

// ============================================================
// COMANDO 20 — Recuperar búnker con las 12 palabras
// ============================================================

#[tauri::command]
fn recuperar_con_frase(
    palabras: Vec<String>,
    sesion: tauri::State<SesionActiva>,
) -> Result<(String, String, String), String> {
    // Comprobar bloqueo activo
    if let Some(ts) = seguridad::leer_bloqueo() {
        let restante = (ts + 600) - chrono::Local::now().timestamp();
        if restante > 0 {
            return Err(format!("Bloqueado. Espera {} segundos.", restante));
        } else {
            let _ = fs::remove_file(&babel_path("bloqueo.tmp"));
        }
    }

    if palabras.len() != 12 {
        return Err("La frase debe tener exactamente 12 palabras.".into());
    }

    // B-1: validar todas las palabras sin early-return para evitar timing attack
    let todas_validas = palabras.iter().all(|p| bip39_words::WORDLIST.contains(&p.as_str()));
    if !todas_validas {
        return Err("Una o más palabras no pertenecen al diccionario BIP39.".into());
    }

    let salt_maestra = traductor::cargar_o_crear_salt();
    let recovery_salt = seguridad::derivar_recovery_salt_v2(&salt_maestra);
    // v3 (actual): Argon2id 131072/4/4 — mismos parámetros que el login
    let key_v3 = seguridad::derivar_clave_recuperacion_v3(&palabras, &recovery_salt)?;
    let key_v3_hex = Zeroizing::new(hex::encode(key_v3.as_ref()));
    // v2: Argon2id 65536/3/1 con salt por instalación
    let key_v2 = seguridad::derivar_clave_recuperacion_v2(&palabras, &recovery_salt)?;
    let key_v2_hex = Zeroizing::new(hex::encode(key_v2.as_ref()));

    let cifrado = fs::read(&babel_path("recovery.babel")).map_err(|_| {
        "No se encontró archivo de recuperación. ¿Generaste la frase al crear el búnker?"
            .to_string()
    })?;

    let mut usado_v0 = false;
    let mut datos =
        match seguridad::descifrar_documento(cifrado.clone(), &key_v3_hex) {
            Ok(d) => d,
            Err(_) => match seguridad::descifrar_documento(cifrado.clone(), &key_v2_hex) {
                Ok(d) => {
                    // Migración automática a v3
                    if let Ok(nuevo) = seguridad::blindar_documento(&d, &key_v3_hex) {
                        let _ = fs::write(babel_path("recovery.babel"), nuevo);
                    }
                    d
                }
                Err(_) => {
                    // Fallback v1: salt estática global
                    let key_v1 = seguridad::derivar_clave_recuperacion(&palabras)
                        .unwrap_or_else(|_| Zeroizing::new([0u8; 32]));
                    let key_v1_hex = Zeroizing::new(hex::encode(key_v1.as_ref()));
                    match seguridad::descifrar_documento(cifrado.clone(), &key_v1_hex) {
                        Ok(d) => {
                            if let Ok(nuevo) = seguridad::blindar_documento(&d, &key_v3_hex) {
                                let _ = fs::write(babel_path("recovery.babel"), nuevo);
                            }
                            d
                        }
                        Err(_) => {
                            // Fallback v0: HKDF sin Argon2id (muy antiguos)
                            let key_v0 = seguridad::derivar_clave_recuperacion_v0(&palabras)
                                .unwrap_or_else(|_| Zeroizing::new([0u8; 32]));
                            let key_v0_hex = Zeroizing::new(hex::encode(key_v0.as_ref()));
                            match seguridad::descifrar_documento(cifrado, &key_v0_hex) {
                                Ok(d) => {
                                    usado_v0 = true;
                                    if let Ok(nuevo) = seguridad::blindar_documento(&d, &key_v3_hex) {
                                        let _ = fs::write(babel_path("recovery.babel"), nuevo);
                                    }
                                    d
                                }
                                Err(_) => {
                                    incrementar_contador_y_bloquear(&sesion)?;
                                    return Err("Frase incorrecta - no corresponde a este bunker.".to_string());
                                }
                            }
                        }
                    }
                }
            }
        };

    // Frase correcta — resetear contador (en RAM y en disco)
    if let Ok(mut c) = sesion.contador.lock() {
        *c = 0;
    }
    let _ = fs::remove_file(&babel_path("intentos.dat"));

    let json: serde_json::Value =
        serde_json::from_str(&datos).map_err(|_| "Formato de recovery invalido.".to_string())?;
    let maestra = json["m"]
        .as_str()
        .ok_or("Falta maestra".to_string())?
        .to_string();
    let pass = json["p"]
        .as_str()
        .ok_or("Falta pass".to_string())?
        .to_string();

    datos.zeroize();
    let aviso = if usado_v0 {
        "ADVERTENCIA: búnker creado con esquema BIP39 v0 (HKDF sin Argon2id). \
         Se ha migrado automáticamente a v3 — vuelve a generar tu frase de recuperación.".to_string()
    } else {
        String::new()
    };
    Ok((maestra, pass, aviso))
}
// ============================================================
// COMANDO 21 — Ver frase de recuperación (dentro de la app)
// ============================================================

#[tauri::command]
fn ver_frase_recuperacion(sesion: tauri::State<SesionActiva>) -> Result<Vec<String>, String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();

    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }

    let cifrado = fs::read(&babel_path("mnemonic.babel")).map_err(|_| {
        "No se encontró la frase de recuperación. Genérala desde Configuración.".to_string()
    })?;

    let frase = seguridad::descifrar_documento(cifrado, &subclave_hex)
        .map_err(|e| format!("Error descifrando frase: {}", e))?;

    Ok(frase.split(' ').map(String::from).collect())
}

// COMANDO — Obtener nombre de usuario con llave maestra recuperada
#[tauri::command]
fn obtener_usuario_con_maestra(
    maestra: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<String, String> {
    // Comprobar bloqueo activo antes de intentar cualquier descifrado
    if let Some(ts) = seguridad::leer_bloqueo() {
        let restante = (ts + 600) - chrono::Local::now().timestamp();
        if restante > 0 {
            return Err(format!("Bloqueado. Espera {} segundos.", restante));
        } else {
            let _ = fs::remove_file(&babel_path("bloqueo.tmp"));
        }
    }

    let salt = traductor::cargar_o_crear_salt();
    let subclave = seguridad::derivar_subclave(maestra.as_bytes(), "babel-usuarios-v1", &salt)
        .map_err(|e| format!("Error derivando subclave: {}", e))?;
    let subclave_hex = Zeroizing::new(hex::encode(subclave.as_ref()));
    let cifrado = fs::read(&babel_path("usuarios.babel"))
        .map_err(|_| "No se encontro el bunker.".to_string())?;
    let json = match seguridad::descifrar_documento(cifrado, &subclave_hex) {
        Ok(j) => j,
        Err(_) => {
            incrementar_contador_y_bloquear(&sesion)?;
            return Err("Llave maestra incorrecta.".to_string());
        }
    };
    // Llave correcta — resetear contador (en RAM y en disco)
    if let Ok(mut c) = sesion.contador.lock() {
        *c = 0;
    }
    let _ = fs::remove_file(&babel_path("intentos.dat"));
    let usuario: seguridad::UsuarioBabel =
        serde_json::from_str(&json).map_err(|e| format!("Error leyendo usuario: {}", e))?;
    Ok(usuario.nombre)
}

// ============================================================
// COMANDO 22 — Términos de uso
// ============================================================

#[tauri::command]
fn comprobar_terminos_aceptados() -> bool {
    Path::new(&babel_path("terminos.babel")).exists()
}

#[tauri::command]
fn aceptar_terminos() -> Result<(), String> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string();
    fs::write(&babel_path("terminos.babel"), ts).map_err(|e| format!("Error: {}", e))
}

// ============================================================
// COMANDO 23 — Guardar configuración del email
// ============================================================

#[tauri::command]
fn guardar_config_email_tauri(
    smtp_servidor: String,
    imap_dominio: String,
    usuario: String,
    password: String,
    remitentes: String,
    firma: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();

    let remitentes_autorizados: Vec<String> = remitentes
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    let creds = traductor::CredencialesEmail {
        smtp_servidor,
        imap_dominio,
        usuario,
        password,
        remitentes_autorizados,
        firma,
    };

    traductor::guardar_config_email(&creds, &subclave_hex)?;
    Ok(())
}

// ============================================================
// COMANDO 24 — Enviar archivo cifrado por email
// ============================================================

#[tauri::command]
fn enviar_archivo_cifrado_tauri(
    ruta: String,
    destinatario: String,
    cc: String,
    cco: String,
    asunto: String,
    cuerpo: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    validar_ruta_en(&ruta, archivos_dir()).or_else(|_| validar_ruta_en(&ruta, guardados_dir()))?;

    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();

    let creds = traductor::cargar_config_email(&subclave_hex).ok_or_else(|| {
        "No hay configuración de email guardada. Configura SMTP primero.".to_string()
    })?;

    let resultado = traductor::enviar_archivo_descifrado(
        &ruta,
        &destinatario,
        &asunto,
        &cuerpo,
        &cc,
        &cco,
        &creds.smtp_servidor,
        &creds.usuario,
        &creds.password,
        &subclave_hex,
    )
    .map_err(|e| format!("Error enviando email: {}", e));

    if resultado.is_ok() {
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let evento = format!(
            "[{}] AVISO: documento descifrado enviado por email a {}",
            ts, destinatario
        );
        traductor::registrar_evento(&evento, &subclave_hex);
    }
    resultado
}

// ============================================================
// COMANDO 25 — Enviar bytes por email
// ============================================================

#[tauri::command]
fn enviar_bytes_cifrados_tauri(
    nombre_archivo: String,
    bytes: Vec<u8>,
    destinatario: String,
    cc: String,
    cco: String,
    asunto: String,
    cuerpo: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();

    let nombre_solo = std::path::Path::new(&nombre_archivo)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Nombre de archivo inválido.")?
        .to_string();
    let ruta_temp = tmp_path(&format!("email_{}", nombre_solo));
    fs::write(&ruta_temp, &bytes).map_err(|e| format!("Error guardando temporal: {}", e))?;

    // Closure garantiza borrar_seguro incluso si cargar_config_email devuelve None
    let resultado = (|| -> Result<(), String> {
        let creds = traductor::cargar_config_email(&subclave_hex).ok_or_else(|| {
            "No hay configuración de email guardada. Configura SMTP primero.".to_string()
        })?;

        traductor::enviar_archivo_descifrado(
            &ruta_temp,
            &destinatario,
            &asunto,
            &cuerpo,
            &cc,
            &cco,
            &creds.smtp_servidor,
            &creds.usuario,
            &creds.password,
            &subclave_hex,
        )
        .map_err(|e| format!("Error enviando email: {}", e))?;

        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let evento = format!(
            "[{}] AVISO: documento descifrado enviado por email a {}",
            ts, destinatario
        );
        traductor::registrar_evento(&evento, &subclave_hex);
        Ok(())
    })();

    borrar_seguro(&ruta_temp);
    resultado
}

// ============================================================
// COMANDO 26 — Obtener emails de la bandeja de entrada
// ============================================================

#[tauri::command]
fn obtener_emails_tauri(
    sesion: tauri::State<SesionActiva>,
) -> Result<Vec<traductor::EmailResumen>, String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();

    let creds = traductor::cargar_config_email(&subclave_hex).ok_or_else(|| {
        "No hay configuración de email guardada. Configura SMTP primero.".to_string()
    })?;

    let mut emails =
        traductor::obtener_emails(&creds.imap_dominio, &creds.usuario, &creds.password)
            .map_err(|e| format!("Error obteniendo emails: {}", e))?;

    if !creds.remitentes_autorizados.is_empty() {
        emails.retain(|e| {
            creds
                .remitentes_autorizados
                .iter()
                .any(|r| e.remitente.to_lowercase().contains(&r.to_lowercase()))
        });
    }

    Ok(emails)
}

// ============================================================
// COMANDO 27 — Obtener cuerpo completo de un email por ID
// ============================================================

#[derive(serde::Serialize)]
struct EmailCompleto {
    id: u32,
    remitente: String,
    asunto: String,
    fecha: String,
    cuerpo: String,
    adjuntos: Vec<String>,
}

#[tauri::command]
fn obtener_email_completo_tauri(
    id: u32,
    sesion: tauri::State<SesionActiva>,
) -> Result<EmailCompleto, String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();

    let creds = traductor::cargar_config_email(&subclave_hex)
        .ok_or_else(|| "No hay configuración de email guardada.".to_string())?;

    let email =
        traductor::obtener_email_completo(&creds.imap_dominio, &creds.usuario, &creds.password, id)
            .map_err(|e| format!("Error obteniendo email: {}", e))?;

    if !creds.remitentes_autorizados.is_empty() {
        let autorizado = creds
            .remitentes_autorizados
            .iter()
            .any(|r| email.remitente.to_lowercase().contains(r.as_str()));
        if !autorizado {
            return Err(format!(
                "Email bloqueado: remitente '{}' no está en la lista de autorizados.",
                email.remitente
            ));
        }
    }

    Ok(EmailCompleto {
        id: email.id,
        remitente: email.remitente,
        asunto: email.asunto,
        fecha: email.fecha,
        cuerpo: email.cuerpo,
        adjuntos: email.adjuntos,
    })
}

// ============================================================
// COMANDO — Obtener firma del email configurado
// ============================================================

#[tauri::command]
fn obtener_firma_email(sesion: tauri::State<SesionActiva>) -> String {
    let subclave_hex = match sesion.subclave_hex.lock() {
        Ok(s) => s.clone(),
        Err(_) => return String::new(),
    };
    if subclave_hex.is_empty() {
        return String::new();
    }
    traductor::cargar_config_email(&subclave_hex)
        .map(|c| c.firma.clone())
        .unwrap_or_default()
}

// ============================================================
// COMANDO — Eliminar email por UID via IMAP (\Deleted + EXPUNGE)
// ============================================================

#[tauri::command]
fn eliminar_email_tauri(
    id: u32,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();

    let creds = traductor::cargar_config_email(&subclave_hex)
        .ok_or_else(|| "No hay configuración de email guardada.".to_string())?;

    traductor::eliminar_email(&creds.imap_dominio, &creds.usuario, &creds.password, id)
        .map_err(|e| format!("Error eliminando email: {}", e))
}

// ============================================================
// COMANDO — Marcar email como no leído (IMAP -\Seen)
// ============================================================

#[tauri::command]
fn marcar_no_leido_tauri(
    id: u32,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();
    let creds = traductor::cargar_config_email(&subclave_hex)
        .ok_or_else(|| "No hay configuración de email guardada.".to_string())?;
    traductor::marcar_no_leido(&creds.imap_dominio, &creds.usuario, &creds.password, id)
        .map_err(|e| format!("Error marcando no leído: {}", e))
}

// ============================================================
// COMANDO — Comprobar si el email está configurado
// ============================================================

#[tauri::command]
fn tiene_config_email(sesion: tauri::State<SesionActiva>) -> bool {
    let subclave_hex = match sesion.subclave_hex.lock() {
        Ok(s) => s.clone(),
        Err(_) => return false,
    };
    if subclave_hex.is_empty() {
        return false;
    }
    traductor::cargar_config_email(&subclave_hex).is_some()
}

// ============================================================
// COMANDO 28 — Abrir carpeta Babel en Finder
// ============================================================

#[tauri::command]
fn abrir_carpeta_babel(sesion: tauri::State<SesionActiva>) -> Result<(), String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    let carpeta_babel = archivos_dir();
    tauri_plugin_opener::open_path(&*carpeta_babel.to_string_lossy(), None::<&str>)
        .map_err(|e| format!("Error abriendo Finder: {}", e))
}
// ============================================================
// COMANDOS P2P
// ============================================================

#[tauri::command]
fn iniciar_servidor_p2p(sesion: tauri::State<SesionActiva>) -> Result<String, String> {
    // Resetear señal de apagado antes de arrancar un nuevo servidor
    babel_p2p::reiniciar_servidor_p2p();

    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();
    let id_usuario = sesion
        .usuario
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();

    let hostname = hostname::get()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let nombre = format!("Babel-{}", hostname);
    babel_p2p::DescubrimientoRed::iniciar_servidor(nombre.clone());

    let clave = Zeroizing::new(subclave_hex.to_string());
    std::thread::spawn(move || {
        let servidor = babel_p2p::ServidorP2P::nuevo(clave.as_str(), &id_usuario);
        if let Err(e) = servidor.iniciar() {
            log::error!("[P2P] Error servidor: {}", e);
        }
    });

    Ok(nombre)
}
// Obtiene la IP local de la máquina usando un socket UDP sin enviar datos
#[tauri::command]
fn obtener_ip_local() -> Result<String, String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Error: {}", e))?;
    socket
        .connect("8.8.8.8:80")
        .map_err(|e| format!("Error: {}", e))?;
    let ip = socket
        .local_addr()
        .map_err(|e| format!("Error: {}", e))?
        .ip()
        .to_string();
    Ok(ip)
}

// Escanea la red local durante 2 segundos buscando otros Babel activos via mDNS
#[tauri::command]
fn buscar_peers_p2p() -> Result<Vec<babel_p2p::PeerDescubierto>, String> {
    babel_p2p::DescubrimientoRed::buscar_peers(2000)
}

// Envía un archivo cifrado a otro Babel en la red local via P2P
#[tauri::command]
fn enviar_archivo_p2p(
    ip: String,
    ruta: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    validar_ruta_en(&ruta, archivos_dir()).or_else(|_| validar_ruta_en(&ruta, guardados_dir()))?;

    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();

    // P-1: validar que la IP sea una IPv4 bien formada antes de conectar
    ip.parse::<std::net::Ipv4Addr>().map_err(|_| "IP de destino inválida".to_string())?;
    let peer = babel_p2p::DescubrimientoRed::peer_manual(&ip, "Babel-Remoto");
    let cliente = babel_p2p::ClienteP2P::nuevo(&subclave_hex);
    cliente.enviar(&peer, &ruta)
}
//=============================================================
// enviar mensajes de texto como archivos .txt para aprovechar la infraestructura de envío de archivos cifrados
//=============================================================
#[tauri::command]
fn enviar_mensaje_p2p(
    ip: String,
    mensaje: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    let subclave_hex = sesion
        .subclave_hex
        .lock()
        .map_err(|_| "Error leyendo sesión.".to_string())?
        .clone();

    // P-1: validar que la IP sea una IPv4 bien formada antes de conectar
    ip.parse::<std::net::Ipv4Addr>().map_err(|_| "IP de destino inválida".to_string())?;
    // Convertimos el mensaje a bytes y lo enviamos como si fuera un archivo
    let datos = mensaje.as_bytes().to_vec();
    let peer = babel_p2p::DescubrimientoRed::peer_manual(&ip, "Babel-Remoto");
    let cliente = babel_p2p::ClienteP2P::nuevo(&subclave_hex);
    cliente.enviar_bytes(&peer, "mensaje.txt", &datos)
}
//=============================================================
// Obtener mensajes de texto recibidos por P2P
//=============================================================
#[tauri::command]
fn listar_peers_pendientes_cmd(_sesion: tauri::State<SesionActiva>) -> Vec<String> {
    crate::babel_p2p::listar_peers_pendientes()
}

#[tauri::command]
fn aprobar_peer_pendiente_cmd(
    fingerprint: String,
    _sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    crate::babel_p2p::aprobar_peer_pendiente(&fingerprint)
}

#[tauri::command]
fn obtener_mensajes_p2p(sesion: tauri::State<SesionActiva>) -> Result<Vec<String>, String> {
    // C-2: verificar sesión activa
    let subclave = sesion.subclave_hex.lock().map_err(|_| "Error sesión".to_string())?.clone();
    if subclave.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    let mensajes = crate::babel_p2p::MENSAJES_ENTRANTES
        .lock()
        .map_err(|_| "Error leyendo mensajes".to_string())?
        .drain(..)
        .map(|z| (*z).clone())
        .collect();
    Ok(mensajes)
}
// ============================================================
// HELPER — Convierte código de idioma al par MarianMT
// ============================================================
// Centralizado aquí para no duplicar el match en cada comando.

fn idioma_a_par(idioma: &str) -> &'static str {
    match idioma {
        "es_en" => "es-en",
        "en_es" => "en-es",
        "es_fr" => "es-fr",
        "fr_es" => "fr-es",
        "es_ar" => "es-ar",
        "ar_es" => "ar-es",
        "fr_en" => "fr-en",
        "en_fr" => "en-fr",
        "en_ar" => "en-ar",
        "ar_en" => "ar-en",
        "fr_ar" => "fr-ar",
        "ar_fr" => "ar-fr",
        "es_de" => "es-de",
        "de_es" => "de-es",
        "fr_de" => "fr-de",
        "de_fr" => "de-fr",
        "ar_de" => "ar-de",
        "de_ar" => "de-ar",
        "es_ru" => "es-ru",
        "ru_es" => "ru-es",
        "fr_ru" => "fr-ru",
        "ru_fr" => "ru-fr",
        "ar_ru" => "ar-ru",
        "ru_ar" => "ru-ar",
        "es_zh" => "es-zh",
        "zh_es" => "zh-es",
        "fr_zh" => "fr-zh",
        "zh_fr" => "zh-fr",
        "ar_zh" => "ar-zh",
        "zh_ar" => "zh-ar",
        "de_ru" => "de-ru",
        "ru_de" => "ru-de",
        "de_zh" => "de-zh",
        "zh_de" => "zh-de",
        "ru_zh" => "ru-zh",
        "zh_ru" => "zh-ru",
        "en_de" => "en-de",
        "de_en" => "de-en",
        "en_ru" => "en-ru",
        "ru_en" => "ru-en",
        "en_zh" => "en-zh",
        "zh_en" => "zh-en",
        _ => "es-en",
    }
}

// ============================================================
// COMANDO — Guardar HTML de frase BIP39 en tmp para imprimir
// ============================================================

#[tauri::command]
fn guardar_html_frase(html: String) -> Result<String, String> {
    // X-3: rechazar HTML con scripts o tamaño excesivo
    if html.len() > 1_048_576 {
        return Err("HTML de frase demasiado grande.".into());
    }
    let lower = html.to_lowercase();
    let etiquetas_peligrosas = [
        "<script", "<iframe", "<embed", "<object", "<form",
        "<link", "<meta", "<base", "<svg", "<math",
    ];
    let protocolos_peligrosos = ["javascript:", "vbscript:", "data:text/html"];
    let eventos_inline = [
        "onerror", "onload", "onclick", "onmouseover", "onmouseout",
        "onfocus", "onblur", "onchange", "onsubmit", "onkeydown", "onkeyup",
        "onkeypress", "oninput", "onmouseenter", "onmouseleave", "ondrag",
        "ondrop", "onpaste", "oncopy", "oncontextmenu",
    ];
    let tiene_contenido_peligroso =
        etiquetas_peligrosas.iter().any(|t| lower.contains(t))
        || protocolos_peligrosos.iter().any(|p| lower.contains(p))
        || eventos_inline.iter().any(|e| lower.contains(e));
    if tiene_contenido_peligroso {
        return Err("HTML de frase contiene contenido no permitido.".into());
    }
    let ruta = tmp_path("frase_recuperacion.html");
    std::fs::write(&ruta, html.as_bytes())
        .map_err(|e| format!("Error al guardar HTML: {}", e))?;
    Ok(ruta)
}

// Borra el HTML de frase BIP39 de forma segura tras imprimir.
// El frontend lo llama 5 segundos después de openPath para dar tiempo a Safari.
#[tauri::command]
fn borrar_html_frase() {
    borrar_seguro(&tmp_path("frase_recuperacion.html"));
}

// ============================================================
// PUNTO DE ENTRADA — Arranca Tauri, registra todos los comandos
// y gestiona el estado global de sesión (SesionActiva).
// ============================================================

fn main() {
    // Impedir que debuggers externos se adjunten al proceso en producción.
    // En release, cualquier intento de ptrace/lldb cierra la app inmediatamente.
    seguridad::denegar_depuracion();

    env_logger::init();

    // Handle del servidor Python del USB — Mutex para poder matar en panic/exit
    static USB_CHILD: std::sync::Mutex<Option<std::process::Child>> =
        std::sync::Mutex::new(None);

    // Mata el proceso Python si la app peta antes del evento Destroyed
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Ok(mut guard) = USB_CHILD.lock() {
            if let Some(mut c) = guard.take() {
                let _ = c.kill();
            }
        }
        prev_hook(info);
    }));

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            // Modo USB: si Resources/ contiene python + servidor, arrancarlo
            if let Ok(res) = app.path().resource_dir() {
                let py_bin   = res.join("python").join("bin").join("python3");
                let servidor = res.join("servidor").join("nllb_server_usb.py");
                if py_bin.exists() && servidor.exists() {
                    let mut rng_bytes = [0u8; 16];
                    rand::rngs::OsRng.fill_bytes(&mut rng_bytes);
                    let token = format!("babel_{}", hex::encode(rng_bytes));

                    // B7/B8: token en OnceLock (no en env), resto vía Command::env()
                    // — evita set_var() UB y evita que el token aparezca en `ps aux`
                    traductor::inicializar_nllb_token(token.clone());

                    if let Ok(child) = std::process::Command::new(&py_bin)
                        .arg(&servidor)
                        .env("BABEL_NLLB_TOKEN", &token)
                        .env("TESSDATA_PREFIX", res.join("tessdata"))
                        .env("TRANSFORMERS_OFFLINE", "1")
                        .env("HF_DATASETS_OFFLINE", "1")
                        .env("TOKENIZERS_PARALLELISM", "false")
                        .spawn()
                    {
                        *USB_CHILD.lock().unwrap_or_else(|p| p.into_inner()) = Some(child);
                    }

                    // Hilo en background: cuando el servidor acepte conexiones,
                    // emite el evento "servidor-usb-listo" al frontend
                    let handle = app.handle().clone();
                    std::thread::spawn(move || {
                        let addr: std::net::SocketAddr =
                            "127.0.0.1:5002".parse().unwrap();
                        let timeout = std::time::Duration::from_secs(1);
                        for _ in 0..90 {
                            std::thread::sleep(std::time::Duration::from_secs(2));
                            if std::net::TcpStream::connect_timeout(&addr, timeout).is_ok() {
                                let _ = handle.emit("servidor-usb-listo", ());
                                break;
                            }
                        }
                    });
                }
            }
            // Monitor periódico de amenazas — escanea cada 5 minutos en background.
            // Solo emite el evento "amenaza-detectada" si hay amenazas NUEVAS respecto
            // a la última vez, y solo cuando hay sesión activa (subclave no vacía).
            let handle_monitor = app.handle().clone();
            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(300));
                    let sesion = handle_monitor.state::<SesionActiva>();
                    let subclave = match sesion.subclave_hex.lock() {
                        Ok(s) => s.clone(),
                        Err(_) => continue,
                    };
                    if subclave.is_empty() { continue; }
                    let nuevas = seguridad::analizar_amenazas_nuevas(&subclave);
                    if !nuevas.is_empty() {
                        let _ = handle_monitor.emit("amenaza-detectada", &nuevas);
                    }
                }
            });

            Ok(())
        })
        .on_window_event(|_window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                if let Ok(mut guard) = USB_CHILD.lock() {
                    if let Some(mut c) = guard.take() {
                        let _ = c.kill();
                        let _ = c.wait();
                    }
                }
            }
        })
        .manage(SesionActiva::nueva())
        .invoke_handler(tauri::generate_handler![
            verificar_entorno_seguro,
            comprobar_estado_bunker,
            crear_acceso_bunker,
            verificar_login,
            traducir_documento,
            cerrar_sesion_rust,
            traducir_documento_ruta,
            leer_resultado,
            traducir_texto,
            cambiar_categoria_diccionario,
            cambiar_idioma,
            listar_archivos,
            crear_buzon,
            listar_buzones,
            exportar_archivo,
            exportar_archivos_a_carpeta,
            eliminar_archivo,
            eliminar_buzon,
            ver_archivo,
            mover_archivo,
            generar_frase_recuperacion,
            recuperar_con_frase,
            ver_frase_recuperacion,
            comprobar_terminos_aceptados,
            aceptar_terminos,
            guardar_config_email_tauri,
            enviar_archivo_cifrado_tauri,
            enviar_bytes_cifrados_tauri,
            obtener_emails_tauri,
            obtener_email_completo_tauri,
            abrir_carpeta_babel,
            save_settings,
            load_settings,
            iniciar_servidor_p2p,
            obtener_ip_local,
            buscar_peers_p2p,
            enviar_archivo_p2p,
            enviar_mensaje_p2p,
            obtener_mensajes_p2p,
            listar_peers_pendientes_cmd,
            aprobar_peer_pendiente_cmd,
            renombrar_buzon,
            guardar_documento_sin_traducir,
            listar_archivos_guardados,
            crear_buzon_guardado,
            listar_buzones_guardados,
            eliminar_buzon_guardado,
            renombrar_buzon_guardado,
            abrir_carpeta_guardados,
            mover_archivo_guardado,
            guardar_bytes_sin_traducir,
            obtener_usuario_con_maestra,
            renombrar_archivo,
            tiene_config_email,
            obtener_firma_email,
            eliminar_email_tauri,
            marcar_no_leido_tauri,
            guardar_html_frase,
            borrar_html_frase,
        ]);
    if let Err(e) = app.run(tauri::generate_context!()) {
        eprintln!("[!] Error crítico al iniciar Babel: {}", e);
        std::process::exit(1);
    }
}
