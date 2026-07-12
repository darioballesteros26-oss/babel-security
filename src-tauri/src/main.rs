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

// M7: serializa el ciclo leer-descifrar-modificar-recifrar de los índices de buzones
// (.buzon_index*.babel). Sin esto, dos operaciones de mover/renombrar concurrentes
// pueden perder actualizaciones (last-write-wins sobre estado obsoleto).
static BUZON_INDEX_MUTEX: Mutex<()> = Mutex::new(());

// Rutas de archivos originales pendientes de borrado tras un import.
// Clave: token opaco generado por nuevo_id(); valor: ruta canónica.
// Cada import tiene su propio token — evita que imports concurrentes se sobreescriban.
static PENDING_BORRAR_ORIGINAL: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

// HELPER — Borrado seguro de archivos temporales
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

// ESTADO GLOBAL — Sesión activa del usuario

pub struct SesionActiva {
    // Parche 4: la subclave residente se guarda como 32 bytes crudos (mlock'd), NO como hex.
    // El hex duplicaba la huella en RAM y su alfabeto [0-9a-f] era un patrón trivial de tallar
    // en un volcado de memoria. Ahora sólo se codifica a hex transitoriamente, bajo demanda,
    // vía subclave_hex(); ese String se zeroiza al terminar cada comando. None = sin sesión.
    pub subclave: Mutex<Option<Zeroizing<[u8; 32]>>>,
    pub usuario: Mutex<String>,
    pub diccionario: Mutex<HashMap<String, String>>,
    pub idioma: Mutex<String>,
    pub buzon_activo: Mutex<String>,
    pub contador: Mutex<u32>,
}

impl SesionActiva {
    fn nueva() -> Self {
        Self {
            subclave: Mutex::new(None),
            usuario: Mutex::new(String::new()),
            diccionario: Mutex::new(HashMap::new()),
            idioma: Mutex::new(String::from("es_en")),
            buzon_activo: Mutex::new(String::from("todos")),
            contador: Mutex::new(0),
        }
    }

    /// Codifica la subclave residente a hex bajo demanda para las funciones cripto que
    /// esperan `&str`. Devuelve un `Zeroizing<String>` (se borra al final del comando) y
    /// cadena vacía cuando no hay sesión — así los checks `is_empty()` siguen funcionando.
    fn subclave_hex(&self) -> Result<Zeroizing<String>, String> {
        let guard = self
            .subclave
            .lock()
            .map_err(|_| "Error leyendo sesión.".to_string())?;
        Ok(match guard.as_ref() {
            Some(k) => Zeroizing::new(hex::encode(&k[..])),
            None => Zeroizing::new(String::new()),
        })
    }

    fn limpiar(&self) {
        if let Ok(mut s) = self.subclave.lock() {
            if let Some(k) = s.as_ref() {
                seguridad::munlock_bytes(&k[..]); // liberar el mlock antes de descartar
            }
            *s = None; // drop del Zeroizing<[u8;32]> → zeroiza los bytes
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

// HELPERS — Rutas absolutas de Babel
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
    // Prevenir path traversal — solo ".." como componente de ruta, no como subcadena
    // de nombre de archivo (ej: "fichero..babel" es válido y no debe bloquearse).
    if std::path::Path::new(ruta)
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        return Err("Ruta no autorizada.".into());
    }
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
// COMANDO 1 — Verificación de entorno

fn verificar_licencia_hardware() -> Result<(), String> {
    use hmac::{Hmac, Mac};
    use sha2::Digest;
    #[cfg(target_os = "macos")]
    let serial = std::process::Command::new("system_profiler")
        .args(["SPHardwareDataType"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.lines().find(|l| l.contains("Serial Number")).map(|l| l.trim().to_string()))
        .unwrap_or_else(|| "UNKNOWN".to_string());
    #[cfg(not(target_os = "macos"))]
    let serial = "WINDOWS-NO-SERIAL".to_string();

    const LICENCIA_KEY: &[u8] = b"babel-license-bind-v1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let hmac_serial = |bytes: &[u8]| -> String {
        let mut mac = <Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(LICENCIA_KEY)
            .expect("LICENCIA_KEY is a compile-time constant with valid length");
        mac.update(bytes);
        hex::encode(mac.finalize().into_bytes())
    };
    let firma = hmac_serial(serial.as_bytes());
    let ruta = babel_path("licencia.babel");
    if std::path::Path::new(&ruta).exists() {
        let guardado = fs::read_to_string(&ruta).unwrap_or_default().trim().to_string();
        let hash_legacy = format!("{:x}", sha2::Sha256::digest(serial.as_bytes()));
        if guardado != firma && guardado == hash_legacy {
            let _ = fs::write(&ruta, &firma); // migrar legado a HMAC
        } else if guardado != firma {
            return Err("Licencia inválida. Babel está vinculado a otro equipo.".into());
        }
    } else {
        let _ = fs::write(&ruta, &firma);
    }
    Ok(())
}

#[tauri::command]
fn verificar_entorno_seguro() -> Result<String, String> {
    let sandbox = seguridad::AntiSandbox::analizar_entorno();
    if !sandbox.seguro {
        return Err(format!("Entorno comprometido: {} amenaza(s) detectada(s)", sandbox.amenazas.len()));
    }
    if let Ok(keylogger) = seguridad::AntiKeylogger::blindaje_total(None) {
        if !keylogger.amenazas.is_empty() {
            return Err(format!("Procesos sospechosos: {} proceso(s) detectado(s)", keylogger.amenazas.len()));
        }
    }

    // FileVault: solo aviso, nunca bloquea (desactivarlo no debe permitir bypasear la licencia)
    #[allow(unused_mut)]
    let mut aviso_filevault = String::new();
    #[cfg(target_os = "macos")]
    if let Ok(out) = std::process::Command::new("fdesetup").arg("status").output() {
        if !String::from_utf8_lossy(&out.stdout).contains("On") {
            aviso_filevault = " — FileVault desactivado. Recomendamos activarlo en Preferencias del Sistema.".to_string();
        }
    }

    verificar_licencia_hardware()?;
    Ok(format!("BABEL SEGURO — Todos los protocolos activos.{}", aviso_filevault))
}
// COMANDO 2 — Comprobar si el búnker existe

#[tauri::command]
fn comprobar_estado_bunker() -> bool {
    Path::new(&babel_path("usuarios.babel")).exists()
}

// COMANDO 3 — Crear el búnker por primera vez

#[tauri::command]
fn crear_acceso_bunker(maestra: String, usuario: String, pass: String) -> Result<String, String> {
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

// COMANDO 4 — Verificar login y guardar sesión

fn incrementar_contador_y_bloquear(sesion: &tauri::State<SesionActiva>) -> Result<(), String> {
    // HMAC-SHA256 con master.salt: borrar intentos.dat no resetea el valor si hay sesión
    // activa en RAM, y el HMAC impide modificar el número sin conocer master.salt.
    let disco: u32 = seguridad::leer_contador_intentos();
    if let Ok(mut c) = sesion.contador.lock() {
        *c = (*c).max(disco) + 1;
        seguridad::escribir_contador_intentos(*c);
        if *c >= 5 {
            *c = 0;
            seguridad::borrar_contador_intentos();
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

    if let Ok(mut s) = sesion.subclave.lock() {
        // Guardamos los 32 bytes crudos (Copy) en un buffer mlock'd; el hex local se descarta.
        let z = Zeroizing::new(*subclave);
        seguridad::mlock_bytes(&z[..]); // evitar que el SO page la clave al swap
        *s = Some(z);
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
    seguridad::borrar_contador_intentos();
    // Resetear amenazas conocidas para que el monitor periódico las reporte de nuevo
    seguridad::resetear_amenazas_conocidas();

    let mut json = Zeroizing::new(json);
    json.zeroize();

    Ok(true)
}

// COMANDO 4b — Cambiar categoría del diccionario en caliente — Recarga el diccionario filtrando por categoría (jurídico, médico, etc.)
#[tauri::command]
fn cambiar_categoria_diccionario(
    categoria: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    let subclave_hex = sesion.subclave_hex()?;
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

// COMANDO 5 — Traducir documento vía selector de archivo

#[tauri::command]
fn traducir_documento(
    app: tauri::AppHandle,
    nombre_archivo: String,
    contenido: Vec<u8>,
    sesion: tauri::State<SesionActiva>,
) -> Result<String, String> {
    let subclave_hex = sesion.subclave_hex()?;

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

    let ext_doc = std::path::Path::new(&nombre_solo)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();
    if !["pdf", "docx", "txt"].contains(&ext_doc.as_str()) {
        return Err(format!("Tipo de archivo no permitido: .{}", ext_doc));
    }

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

        let progreso = |pct: u8, msg: &str| {
            let _ = app.emit("progreso-traduccion", serde_json::json!({"pct": pct, "msg": msg}));
        };
        traductor::procesar_archivo_inteligente(
            &ruta_temp,
            &dict,
            &subclave_hex,
            &id_usuario,
            par_doc,
            &progreso,
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
    let subclave_hex = sesion.subclave_hex()?;
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

// Núcleo compartido: lee un archivo en claro desde una ruta del sistema, lo cifra
// con AES-256-GCM y lo guarda en ~/Babel/guardados/. Lo usan tanto la importación
// por drag-and-drop (guardar_documento_sin_traducir) como la importación por diálogo
// de selección nativo (importar_archivo_dialogo). Devuelve la ruta del .babel creado.
fn cifrar_y_guardar_desde_ruta(
    nombre_archivo: &str,
    ruta_completa: &str,
    subclave_hex: &str,
    id_usuario: &str,
) -> Result<String, String> {
    let nombre_seguro = std::path::Path::new(nombre_archivo)
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

    // Canonicalizar para resolver symlinks — la autorización la gestiona el App Sandbox
    // a nivel OS mediante user-selected.read-write. El check starts_with(home) se elimina
    // porque en sandbox dirs::home_dir() apunta al contenedor, no al home real,
    // y rechazaría archivos legítimos seleccionados por el usuario con un file dialog.
    let ruta_canon = std::fs::canonicalize(ruta_completa)
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

    let nombre_base = std::path::Path::new(nombre_archivo)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(nombre_archivo);

    let nombre_cifrado = format!("{}_{}_{}.babel", id_usuario, nombre_base, ts);
    let ruta_cifrada = guardados_path(&nombre_cifrado);

    let contenido_b64 = traductor::comprimir_b64(&contenido);
    let cifrado = seguridad::blindar_documento(&contenido_b64, subclave_hex)
        .map_err(|e| format!("Error cifrando: {}", e))?;

    fs::write(&ruta_cifrada, cifrado).map_err(|e| format!("Error guardando: {}", e))?;

    Ok(ruta_cifrada)
}

#[tauri::command]
fn guardar_documento_sin_traducir(
    nombre_archivo: String,
    ruta_completa: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<String, String> {
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }

    let id_usuario = sesion
        .usuario
        .lock()
        .map_err(|_| "Error".to_string())?
        .clone();

    cifrar_y_guardar_desde_ruta(&nombre_archivo, &ruta_completa, &subclave_hex, &id_usuario)
}

// ============================================================
// COMANDO — Importar por diálogo de selección nativo + borrado seguro
// del original. El NSOpenPanel es el único punto donde el App Sandbox concede
// acceso read-write a un archivo fuera del contenedor; por eso podemos borrar
// de forma segura SOLO el archivo que el usuario acaba de elegir aquí.
// ============================================================

#[derive(serde::Serialize)]
struct ImportarDialogoResultado {
    ruta_cifrada: String,
    nombre: String,
    original_borrado: bool,
    tiene_original: bool,
    token_borrado: Option<String>,
}

#[tauri::command]
async fn importar_archivo_dialogo(
    app: tauri::AppHandle,
    sesion: tauri::State<'_, SesionActiva>,
) -> Result<Option<ImportarDialogoResultado>, String> {
    // Extraemos los datos de sesión ANTES de cruzar a otro hilo: tauri::State no es
    // Send y no puede sostenerse a través de un .await. subclave_hex es Zeroizing<String>,
    // así que sigue borrándose de memoria al soltarse dentro del closure.
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    let id_usuario = sesion
        .usuario
        .lock()
        .map_err(|_| "Error".to_string())?
        .clone();

    // Los diálogos nativos blocking_* hacen run_on_main_thread(closure) y luego esperan
    // el resultado en un canal. Si se invocaran desde el hilo principal —que es donde Tauri
    // ejecuta los comandos SÍNCRONOS— se produce un DEADLOCK: el main se bloquea esperando
    // el canal y nunca llega a ejecutar el closure del diálogo, congelando la UI ("cargando").
    // Por eso el comando es async y todo el bloque bloqueante corre en spawn_blocking, en un
    // hilo dedicado, dejando el hilo principal libre para dibujar los diálogos.
    tauri::async_runtime::spawn_blocking(move || {
        use tauri_plugin_dialog::DialogExt;

        // Diálogo de selección nativo del sistema. El App Sandbox concede acceso
        // read-write EXCLUSIVAMENTE al archivo que el usuario elija aquí.
        let seleccion = app
            .dialog()
            .file()
            .add_filter("Documentos", &["pdf", "docx", "txt"])
            .blocking_pick_file();

        let ruta_fp = match seleccion {
            Some(fp) => fp,
            None => return Ok(None), // usuario canceló el diálogo — sin error
        };
        let ruta_original = ruta_fp
            .into_path()
            .map_err(|e| format!("Ruta de origen inválida: {}", e))?;
        let ruta_original_str = ruta_original.to_string_lossy().to_string();
        let nombre = ruta_original
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("Nombre de archivo inválido")?
            .to_string();

        let ruta_cifrada =
            cifrar_y_guardar_desde_ruta(&nombre, &ruta_original_str, &subclave_hex, &id_usuario)?;

        // Generar token único por operación — cada import tiene su propia ranura en el mapa.
        // El frontend solo recibe el token opaco; la ruta real nunca cruza el IPC.
        let token = nuevo_id();
        if let Ok(mut guard) = PENDING_BORRAR_ORIGINAL.lock() {
            guard.get_or_insert_with(HashMap::new).insert(token.clone(), ruta_original_str);
        }

        Ok(Some(ImportarDialogoResultado {
            ruta_cifrada,
            nombre,
            original_borrado: false,
            tiene_original: true,
            token_borrado: Some(token),
        }))
    })
    .await
    .map_err(|e| format!("Error interno al importar: {}", e))?
}

// ============================================================
// COMANDO — Borrar de forma segura el archivo original tras importar.
// Recibe el token opaco devuelto por importar_archivo_dialogo.
// La ruta real se resuelve en Rust usando ese token — nunca cruza el IPC.
// AVISO (B2): en SSD con wear-leveling el contenido puede persistir en sectores
// históricos aunque se sobrescriba. El cifrado AES-256-GCM ya protege el contenido.
// ============================================================
#[tauri::command]
fn borrar_archivo_original(token: String) -> Result<bool, String> {
    let ruta = PENDING_BORRAR_ORIGINAL
        .lock()
        .map_err(|_| "Error interno.".to_string())?
        .as_mut()
        .and_then(|m| m.remove(&token))
        .ok_or_else(|| "No hay archivo pendiente de borrado.".to_string())?;

    let path = std::fs::canonicalize(&ruta)
        .map_err(|_| "Archivo no accesible.".to_string())?;
    let ruta_canon = path.to_str().unwrap_or(&ruta).to_string();
    borrar_seguro(&ruta_canon);
    Ok(!path.exists())
}

// ============================================================
// COMANDO — Borrar un archivo externo (fuera de ~/Babel/) de forma segura.
// Usado cuando el toggle "BORRAR ORIG." está ON en flujos de drag-and-drop/traducción.
// Rechaza rutas dentro del directorio Babel para evitar borrado accidental de datos propios.
// ============================================================
#[tauri::command]
fn borrar_archivo_fuente(ruta: String, sesion: tauri::State<SesionActiva>) -> Result<(), String> {
    sesion.subclave_hex()?; // requiere sesión activa
    let path = std::fs::canonicalize(&ruta)
        .map_err(|_| "Archivo no accesible.".to_string())?;
    let babel = babel_dir();
    if path.starts_with(&babel) {
        return Err("No se puede borrar archivos internos de Babel.".into());
    }
    borrar_seguro(path.to_str().unwrap_or(&ruta));
    Ok(())
}

// ============================================================
// COMANDO — Comprobar si ya existe un archivo guardado con ese nombre base
// Verifica contra el sistema de archivos real, no contra el DOM del frontend.
// Evita que archivos en buzones no visibles pasen inadvertidos (B5).
// ============================================================
#[tauri::command]
fn archivo_guardado_existe(nombre_base: String, sesion: tauri::State<SesionActiva>) -> bool {
    let _ = sesion; // requiere sesión activa — si no hay sesión, devuelve false
    let nombre_base_lower = nombre_base.to_lowercase();
    let carpetas = [guardados_dir(), archivos_dir()];
    for carpeta in &carpetas {
        if let Ok(entradas) = fs::read_dir(carpeta) {
            for entrada in entradas.flatten() {
                let fname = entrada.file_name();
                let fname_str = fname.to_string_lossy();
                if fname_str.ends_with(".babel") {
                    // Extraer el nombre base del archivo siguiendo limpiarNombre del frontend:
                    // formato: {id_usuario}_{nombre_base}_{timestamp}.babel
                    // → quitar prefijo usuario (hasta primer _), quitar sufijo _timestamp, quitar .babel
                    let sin_ext = &fname_str[..fname_str.len() - 6];
                    let sin_prefix = sin_ext.splitn(2, '_').nth(1).unwrap_or(sin_ext);
                    let sin_ts = sin_prefix.rsplit_once('_').map(|(s, _)| s).unwrap_or(sin_prefix);
                    // Quitar prefijo de idioma si existe (ej: es-en_)
                    let sin_idioma = sin_ts.splitn(2, '_')
                        .collect::<Vec<_>>();
                    let base = if sin_idioma.len() == 2 && sin_idioma[0].len() == 5 && sin_idioma[0].chars().nth(2) == Some('-') {
                        sin_idioma[1]
                    } else {
                        sin_ts
                    };
                    if base.to_lowercase() == nombre_base_lower {
                        return true;
                    }
                }
            }
        }
    }
    false
}

// COMANDO — Verificar herramientas opcionales para PDF
#[derive(serde::Serialize)]
struct HerramientasPdf {
    pdf2docx: bool,
    libreoffice: bool,
}

#[tauri::command]
fn verificar_herramientas_pdf() -> HerramientasPdf {
    let pdf2docx = std::process::Command::new("python3")
        .args(["-c", "import pdf2docx"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let libreoffice = [
        "/opt/homebrew/bin/soffice",
        "/usr/local/bin/soffice",
        "/Applications/LibreOffice.app/Contents/MacOS/soffice",
    ]
    .iter()
    .any(|&p| std::path::Path::new(p).exists());

    HerramientasPdf { pdf2docx, libreoffice }
}

// COMANDO — Listar archivos guardados (sin traducir)

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
    let subclave_hex = sesion.subclave_hex()?;

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
                buzon_id: buzon_archivo.clone(),
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
                // Formato nuevo: {usuario}_{par}_{nombre}.babel — par en posición [1]
                // Formato antiguo (sin par): se muestra vacío en UI
                let seg = nombre.split('_').nth(1).unwrap_or("");
                if seg.len() == 5 && seg.as_bytes().get(2) == Some(&b'-') {
                    seg.to_string()
                } else {
                    String::new()
                }
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
                buzon_id: buzon_archivo.clone(),
                es_traduccion: true,
            });
        }
    }

    Ok(archivos)
}
// COMANDO — Mover archivo guardado entre buzones — Actualiza el índice cifrado .buzon_index_guardados.babel con el nuevo buzón destino.
#[tauri::command]
fn mover_archivo_guardado(
    ruta: String,
    buzon_destino: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    validar_ruta_en(&ruta, guardados_dir())?;

    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() { return Err("No hay sesión activa.".into()); }

    // M7: serializar RMW del índice de buzones.
    let _idx_guard = BUZON_INDEX_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

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
// COMANDO 6 — Cerrar sesión (limpia la RAM)
#[tauri::command]
fn cerrar_sesion_rust(sesion: tauri::State<SesionActiva>) {
    babel_p2p::detener_servidor_p2p();
    sesion.limpiar();
    // Limpiar todas las rutas pendientes de borrado al cerrar sesión
    if let Ok(mut guard) = PENDING_BORRAR_ORIGINAL.lock() { *guard = None; }
    // Borrar temporales en claro con 3 pasadas (0x00, 0xFF, 0xAA) + fsync antes de eliminar
    let tmp = babel_dir().join("tmp");
    if let Ok(entradas) = fs::read_dir(&tmp) {
        for entrada in entradas.flatten() {
            borrar_seguro(&entrada.path().to_string_lossy());
        }
    }
    // Matar Flask
}

// COMANDO 7 — Traducir documento vía drag & drop nativo

#[tauri::command]
async fn traducir_documento_ruta(
    app: tauri::AppHandle,
    ruta: String,
    nombre_archivo: String,
    sesion: tauri::State<'_, SesionActiva>,
) -> Result<String, String> {
    // Extraer datos de sesión ANTES de spawn_blocking — State no es Send.
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa. Inicia sesión primero.".into());
    }
    let id_usuario = sesion.usuario.lock().map_err(|_| "Error".to_string())?.clone();
    let dict = sesion.diccionario.lock().map_err(|_| "Error leyendo diccionario.".to_string())?.clone();
    let idioma = sesion.idioma.lock().map_err(|_| "Error leyendo idioma.".to_string())?.clone();
    let par = idioma_a_par(&idioma);

    // La traducción de un documento puede tardar decenas de segundos.  Ejecutar en el
    // hilo principal bloquea el event-loop → la ventana deja de responder → macOS detecta
    // pérdida de foco → el timer de 20s dispara bloquearPantalla().  spawn_blocking mueve
    // todo el trabajo a un hilo dedicado y deja el hilo principal libre.
    tauri::async_runtime::spawn_blocking(move || {
        traductor::resetear_cancelacion();
        // Anti path-traversal
        if Path::new(&ruta).components().any(|c| c == std::path::Component::ParentDir) {
            return Err("Ruta no autorizada.".into());
        }

        // Extensión antes de canonicalize para dar un error claro si el tipo no es válido.
        let ext = Path::new(&ruta)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
            .unwrap_or_default();
        if !["pdf", "docx", "txt"].contains(&ext.as_str()) {
            return Err(format!("Tipo de archivo no permitido: .{}", ext));
        }

        // En sandbox, is_file() devuelve false para archivos arrastrados hasta que el OS
        // resuelve el acceso user-selected.  Canonicalize abre el acceso y falla si la ruta
        // no existe — igual que hace cifrar_y_guardar_desde_ruta para drag & drop.
        let path_canon = std::fs::canonicalize(&ruta)
            .map_err(|_| format!("Archivo no accesible: {}", ruta))?;

        let meta = std::fs::metadata(&path_canon)
            .map_err(|e| format!("Error accediendo archivo: {}", e))?;
        if meta.len() > 100 * 1024 * 1024 {
            return Err("El archivo supera el límite de 100 MB.".into());
        }

        let nombre_base = std::path::Path::new(&nombre_archivo)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(&nombre_archivo)
            .to_string();

        let ruta_str = path_canon.to_str()
            .ok_or_else(|| "Ruta contiene caracteres no permitidos (no-UTF8).".to_string())?;

        let progreso = |pct: u8, msg: &str| {
            let _ = app.emit("progreso-traduccion", serde_json::json!({"pct": pct, "msg": msg}));
        };
        traductor::procesar_archivo_inteligente(
            ruta_str,
            &dict,
            &subclave_hex,
            &id_usuario,
            par,
            &progreso,
        )?;

        let ruta_real = archivos_path(&format!("{}_{}_{}.babel", id_usuario, par, nombre_base));
        Ok(ruta_real)
    })
    .await
    .map_err(|e| format!("Error interno al traducir: {}", e))?
}

// ============================================================
// COMANDO — Traducir archivo .babel guardado (sin traducir)
// Descifra el .babel, escribe bytes a tmp/, llama al pipeline normal de
// traducción y devuelve la ruta del .babel resultante en archivos/.
// ============================================================
#[tauri::command]
async fn traducir_archivo_guardado(
    app: tauri::AppHandle,
    ruta: String,
    sesion: tauri::State<'_, SesionActiva>,
) -> Result<String, String> {
    validar_ruta_en(&ruta, archivos_dir())
        .or_else(|_| validar_ruta_en(&ruta, guardados_dir()))?;

    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    let id_usuario = sesion.usuario.lock().map_err(|_| "Error".to_string())?.clone();
    let dict = sesion.diccionario.lock().map_err(|_| "Error leyendo diccionario.".to_string())?.clone();
    let idioma = sesion.idioma.lock().map_err(|_| "Error leyendo idioma.".to_string())?.clone();
    let par = idioma_a_par(&idioma);

    tauri::async_runtime::spawn_blocking(move || {
        traductor::resetear_cancelacion();
        let bytes = descifrar_a_bytes(&ruta, &subclave_hex)?;

        if bytes.len() > 100 * 1024 * 1024 {
            return Err("El archivo supera el límite de 100 MB.".into());
        }

        let ext = detectar_ext(&bytes);
        if !["pdf", "docx", "txt"].contains(&ext) {
            return Err(format!("Tipo de archivo no soportado para traducción: .{}", ext));
        }

        // Nombre base desde la ruta .babel interna
        let nombre_base = nombre_exportacion(&ruta, ext);
        let nombre_sin_ext = Path::new(&nombre_base)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("archivo")
            .to_string();

        // Escribir a tmp/ y traducir
        let tmp_path = tmp_dir().join(&nombre_base);
        fs::write(&tmp_path, &bytes).map_err(|e| format!("Error escribiendo temporal: {}", e))?;

        let progreso = |pct: u8, msg: &str| {
            let _ = app.emit("progreso-traduccion", serde_json::json!({"pct": pct, "msg": msg}));
        };
        let tmp_str = tmp_path.to_str()
            .ok_or_else(|| "Ruta temporal con caracteres inválidos".to_string())?;

        let resultado = traductor::procesar_archivo_inteligente(
            tmp_str,
            &dict,
            &subclave_hex,
            &id_usuario,
            par,
            &progreso,
        );

        // Limpiar temporal con 3 pasadas (igual que borrar_seguro) — el archivo
        // contiene bytes descifrados de un documento confidencial.
        if let Some(s) = tmp_path.to_str() { borrar_seguro(s); }

        resultado?;

        // El traductor siempre guarda un __orig.babel propio, pero aquí el original
        // ya está preservado en GUARDADO — eliminar la copia redundante.
        let orig_redundante = archivos_path(&format!("{}_{}_{}__orig.babel", id_usuario, par, nombre_sin_ext));
        if std::path::Path::new(&orig_redundante).exists() {
            borrar_seguro(&orig_redundante);
        }

        let ruta_resultado = archivos_path(&format!("{}_{}_{}.babel", id_usuario, par, nombre_sin_ext));
        Ok(ruta_resultado)
    })
    .await
    .map_err(|e| format!("Error interno al traducir: {}", e))?
}

// ============================================================
// COMANDO — Traducir documento vía diálogo de selección nativo
// El <input type=file> del webview no abre el selector en la app sandbox (mismo
// motivo que importar_archivo_dialogo); este comando usa el NSOpenPanel nativo,
// única vía por la que el sandbox concede lectura de archivos fuera del contenedor.
// async + spawn_blocking para no deadlockear el hilo principal con el diálogo.
// ============================================================
#[tauri::command]
async fn traducir_documento_dialogo(
    app: tauri::AppHandle,
    sesion: tauri::State<'_, SesionActiva>,
) -> Result<Option<String>, String> {
    // Extraer datos de sesión ANTES de cruzar a spawn_blocking (State no es Send).
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa. Inicia sesión primero.".into());
    }
    let id_usuario = sesion.usuario.lock().map_err(|_| "Error".to_string())?.clone();
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

    tauri::async_runtime::spawn_blocking(move || {
        use tauri_plugin_dialog::DialogExt;
        let seleccion = app
            .dialog()
            .file()
            .add_filter("Documentos", &["pdf", "docx", "txt"])
            .blocking_pick_file();

        let ruta_fp = match seleccion {
            Some(fp) => fp,
            None => return Ok(None), // usuario canceló — sin error
        };
        traductor::resetear_cancelacion();
        let ruta = ruta_fp
            .into_path()
            .map_err(|e| format!("Ruta de origen inválida: {}", e))?;

        let ext = ruta
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
            .unwrap_or_default();
        if !["pdf", "docx", "txt"].contains(&ext.as_str()) {
            return Err(format!("Tipo de archivo no permitido: .{}", ext));
        }

        let meta = std::fs::metadata(&ruta)
            .map_err(|e| format!("Error accediendo al archivo: {}", e))?;
        if meta.len() > 100 * 1024 * 1024 {
            return Err("El archivo supera el límite de 100 MB.".into());
        }

        let nombre = ruta
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("Nombre de archivo inválido")?
            .to_string();
        let nombre_base = std::path::Path::new(&nombre)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(&nombre);
        let ruta_str = ruta
            .to_str()
            .ok_or_else(|| "Ruta contiene caracteres no permitidos (no-UTF8).".to_string())?;

        // Notificar al frontend: el usuario eligió el archivo, empieza la traducción.
        // El frontend usa este evento para mostrar la burbuja "TÚ" y activar la barra de
        // progreso sin necesidad de partir el comando en dos llamadas (lo que rompería el
        // security-scoped access del sandbox).
        let _ = app.emit("archivo-seleccionado", serde_json::json!({
            "nombre": nombre,
            "ext": ext.to_uppercase()
        }));

        let progreso = |pct: u8, msg: &str| {
            let _ = app.emit("progreso-traduccion", serde_json::json!({"pct": pct, "msg": msg}));
        };
        traductor::procesar_archivo_inteligente(
            ruta_str,
            &dict,
            &subclave_hex,
            &id_usuario,
            par,
            &progreso,
        )?;

        let ruta_real = archivos_path(&format!("{}_{}_{}.babel", id_usuario, par, nombre_base));
        Ok(Some(ruta_real))
    })
    .await
    .map_err(|e| format!("Error interno al traducir: {}", e))?
}

// ============================================================
// COMANDO — Solo diálogo de selección (sin traducir).
// El frontend lo usa para mostrar la burbuja "TÚ" antes de llamar
// a traducir_documento_ruta, replicando el flujo del drag & drop.
// ============================================================
#[tauri::command]
async fn seleccionar_ruta_dialogo(app: tauri::AppHandle) -> Result<Option<String>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        use tauri_plugin_dialog::DialogExt;
        let seleccion = app
            .dialog()
            .file()
            .add_filter("Documentos", &["pdf", "docx", "txt"])
            .blocking_pick_file();
        let ruta_fp = match seleccion {
            Some(fp) => fp,
            None => return Ok(None),
        };
        let ruta = ruta_fp
            .into_path()
            .map_err(|e| format!("Ruta inválida: {}", e))?;
        let ruta_str = ruta
            .to_str()
            .ok_or_else(|| "Ruta contiene caracteres no permitidos (no-UTF8).".to_string())?
            .to_string();
        Ok(Some(ruta_str))
    })
    .await
    .map_err(|e| format!("Error en diálogo: {}", e))?
}

// COMANDO 8 — Leer resultado para descarga

// Descifra un .babel y devuelve los bytes originales del documento.
// Maneja dos casos: contenido comprimido en b64 (PDF, DOCX, binarios) y
// texto plano directo (TXT translations guardados sin comprimir).
fn descifrar_a_bytes(ruta: &str, subclave_hex: &str) -> Result<Vec<u8>, String> {
    let cifrado = fs::read(ruta).map_err(|e| format!("Error leyendo: {}", e))?;
    let contenido = seguridad::descifrar_documento(cifrado, subclave_hex)
        .map_err(|e| format!("Error descifrando: {}", e))?;
    if let Ok(raw) = traductor::descomprimir_b64(&contenido) {
        return Ok(raw);
    }
    // Archivos html: (fallback PDF traducido): quitar prefijo antes de exportar
    if let Some(sin_prefijo) = contenido.strip_prefix("html:") {
        return Ok(sin_prefijo.as_bytes().to_vec());
    }
    // Fallback: el contenido descifrado ya es el texto (TXT sin comprimir)
    Ok(contenido.into_bytes())
}

// Detecta la extensión real de un archivo por sus magic bytes.
fn detectar_ext(bytes: &[u8]) -> &'static str {
    if bytes.len() >= 4 && &bytes[..4] == b"%PDF" { return "pdf"; }
    if bytes.len() >= 2 && &bytes[..2] == b"PK" { return "docx"; }
    if bytes.len() >= 4 && &bytes[..4] == b"\x89PNG" { return "png"; }
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xD8 { return "jpg"; }
    if bytes.len() >= 6 && &bytes[..6] == b"GIF89a" { return "gif"; }
    if bytes.len() >= 6 && &bytes[..6] == b"GIF87a" { return "gif"; }
    if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" { return "webp"; }
    "txt"
}

// Reconstruye un nombre de archivo limpio a partir de la ruta .babel interna.
// Formato interno: "{usuario}_{nombre_base}.babel" o "{usuario}_{nombre}_{ts}.babel"
fn nombre_exportacion(ruta: &str, ext: &str) -> String {
    let stem = Path::new(ruta).file_stem()
        .map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "archivo".into());
    // Strip user prefix (numeric first segment)
    let s = stem.splitn(2, '_').nth(1).unwrap_or(&stem).to_string();
    // Strip language-pair prefix "xx-xx_"
    let b = s.as_bytes();
    let s = if b.len() > 6 && b[2] == b'-' && b[5] == b'_'
        && b[0].is_ascii_lowercase() && b[1].is_ascii_lowercase()
        && b[3].is_ascii_lowercase() && b[4].is_ascii_lowercase()
    { s[6..].to_string() } else { s };
    // Strip __orig suffix
    let s = if s.ends_with("__orig") { s[..s.len()-6].to_string() } else { s };
    // Strip timestamp suffix (≥8 digits)
    let s = s.rfind('_').filter(|&p| s[p+1..].len() >= 8 && s[p+1..].chars().all(|c| c.is_ascii_digit()))
        .map(|p| s[..p].to_string()).unwrap_or(s);
    format!("{}.{}", s, ext)
}

#[tauri::command]
fn cancelar_traduccion_activa() {
    traductor::cancelar_traduccion();
}

#[tauri::command]
fn leer_resultado(ruta: String, sesion: tauri::State<SesionActiva>) -> Result<Vec<u8>, String> {
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    validar_ruta_en(&ruta, archivos_dir())?;

    let meta = fs::metadata(&ruta).map_err(|e| format!("Error accediendo archivo: {}", e))?;
    if meta.len() > 100 * 1024 * 1024 {
        return Err("Archivo supera el límite de 100 MB.".into());
    }

    descifrar_a_bytes(&ruta, &subclave_hex)
}

// COMANDO 9 — Cambiar idioma y recargar diccionario

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

    let subclave_hex = sesion.subclave_hex()?;
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

// COMANDO 10 — Listar archivos guardados

#[derive(serde::Serialize)]
struct MetadatosArchivo {
    nombre: String,
    ruta: String,
    tamaño: u64,
    fecha: String,
    idioma: String,
    buzon: String,
    buzon_id: String,
    es_traduccion: bool,
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

// Valida formato mínimo de dirección email: debe contener @ y un punto después de @.
fn validar_email(email: &str) -> Result<(), String> {
    let e = email.trim();
    if e.is_empty() { return Ok(()); } // CC/CCO son opcionales
    let at = e.find('@').ok_or_else(|| format!("Email inválido (falta @): {}", e))?;
    let dominio = &e[at + 1..];
    if !dominio.contains('.') {
        return Err(format!("Email inválido (dominio sin punto): {}", e));
    }
    if e.len() > 254 {
        return Err(format!("Email demasiado largo: {}", e));
    }
    Ok(())
}

fn validar_email_requerido(email: &str) -> Result<(), String> {
    let e = email.trim();
    if e.is_empty() {
        return Err("El campo destinatario no puede estar vacío.".into());
    }
    validar_email(e)
}

// Valida que un nombre de buzón sea aceptable (S7).
// Rechaza nombres vacíos, muy largos o con caracteres de control.
fn validar_nombre_buzon(nombre: &str) -> Result<String, String> {
    let nombre = nombre.trim().to_string();
    if nombre.is_empty() {
        return Err("El nombre no puede estar vacío.".into());
    }
    if nombre.len() > 64 {
        return Err("El nombre no puede superar los 64 caracteres.".into());
    }
    if nombre.chars().any(|c| c.is_control()) {
        return Err("El nombre contiene caracteres no permitidos.".into());
    }
    Ok(nombre)
}

// COMANDO 11 — Crear buzón (traducciones)

#[tauri::command]
fn crear_buzon(
    nombre: String,
    parent: Option<String>,
    sesion: tauri::State<SesionActiva>,
) -> Result<String, String> {
    let nombre = validar_nombre_buzon(&nombre)?;
    let subclave_hex = sesion.subclave_hex()?;
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

// COMANDO 12 — Listar buzones

#[tauri::command]
fn listar_buzones(sesion: tauri::State<SesionActiva>) -> Result<Vec<BuzonNodo>, String> {
    let subclave_hex = sesion.subclave_hex()?;

    let ruta = archivos_path(".buzones.babel");
    Ok(cargar_nodos(std::path::Path::new(&ruta), &subclave_hex))
}
// COMANDOS — Buzones de archivos guardados (separados)

#[tauri::command]
fn crear_buzon_guardado(
    nombre: String,
    parent: Option<String>,
    sesion: tauri::State<SesionActiva>,
) -> Result<String, String> {
    let nombre = validar_nombre_buzon(&nombre)?;
    let subclave_hex = sesion.subclave_hex()?;
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
    let subclave_hex = sesion.subclave_hex()?;

    let ruta = guardados_path(".buzones_guardados.babel");
    Ok(cargar_nodos(std::path::Path::new(&ruta), &subclave_hex))
}
// COMANDO 13 — Exportar archivo al Finder (save panel nativo)

#[tauri::command]
async fn exportar_archivo(
    ruta: String,
    app: tauri::AppHandle,
    sesion: tauri::State<'_, SesionActiva>,
) -> Result<String, String> {
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }

    tauri::async_runtime::spawn_blocking(move || {
        validar_ruta_en(&ruta, archivos_dir()).or_else(|_| validar_ruta_en(&ruta, guardados_dir()))?;

        // Descifrar y reconstruir el documento original
        let raw = descifrar_a_bytes(&ruta, &subclave_hex)?;
        let ext = detectar_ext(&raw);
        let nombre = nombre_exportacion(&ruta, ext);

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

        fs::write(&destino_path, &raw)
            .map_err(|e| format!("Error al escribir: {}", e))?;

        Ok(destino_path.to_string_lossy().to_string())
    })
    .await
    .map_err(|e| format!("Error interno al exportar: {}", e))?
}

// COMANDO 13b — Exportar múltiples archivos a una carpeta — Muestra UN folder picker nativo; copia todos los archivos ahí.
#[tauri::command]
async fn exportar_archivos_a_carpeta(
    rutas: Vec<String>,
    app: tauri::AppHandle,
    sesion: tauri::State<'_, SesionActiva>,
) -> Result<u32, String> {
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }

    tauri::async_runtime::spawn_blocking(move || {
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
            let raw = match descifrar_a_bytes(ruta, &subclave_hex) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let ext = detectar_ext(&raw);
            let nombre = nombre_exportacion(ruta, ext);
            let destino = carpeta.join(&nombre);
            if fs::write(&destino, &raw).is_ok() {
                copiados += 1;
            }
        }

        Ok(copiados)
    })
    .await
    .map_err(|e| format!("Error interno al exportar: {}", e))?
}

// COMANDO 14 — Mover archivos entre buzones

#[tauri::command]
fn mover_archivo(
    ruta: String,
    buzon_destino: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    validar_ruta_en(&ruta, archivos_dir())?;

    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() { return Err("No hay sesión activa.".into()); }

    // M7: serializar RMW del índice de buzones.
    let _idx_guard = BUZON_INDEX_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

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

// COMANDO 15 — Eliminar buzón

#[tauri::command]
fn eliminar_buzon(id: String, sesion: tauri::State<SesionActiva>) -> Result<(), String> {
    let subclave_hex = sesion.subclave_hex()?;
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
    let nombre_nuevo = validar_nombre_buzon(&nombre_nuevo)?;
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() { return Err("No hay sesión activa.".into()); }

    let ruta = archivos_path(".buzones.babel");
    let mut nodos = cargar_nodos(std::path::Path::new(&ruta), &subclave_hex);
    if let Some(n) = nodos.iter_mut().find(|n| n.id == id) {
        n.nombre = nombre_nuevo;
    }
    guardar_nodos(&nodos, std::path::Path::new(&ruta), &subclave_hex)
}
// COMANDO 16 — Eliminar archivo con zeroize
#[tauri::command]
fn renombrar_archivo(
    ruta: String,
    nombre_nuevo: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<String, String> {
    validar_ruta_en(&ruta, archivos_dir()).or_else(|_| validar_ruta_en(&ruta, guardados_dir()))?;

    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    let id_usuario = sesion
        .usuario
        .lock()
        .map_err(|_| "Error sesión.".to_string())?
        .clone();

    // M7: serializar toda la operación (rename + actualización de índice) contra otras
    // mutaciones de buzones concurrentes.
    let _idx_guard = BUZON_INDEX_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

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
        .replace(['\0', '\n', '\r', '/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
    if nombre_limpio.is_empty() {
        return Err("El nombre no puede estar vacío.".to_string());
    }
    let nuevo_nombre_archivo = format!("{}_{}.babel", id_usuario, nombre_limpio);
    let nueva_ruta = dir.join(&nuevo_nombre_archivo);

    // M5: no sobrescribir un archivo existente al renombrar (evita pérdida de datos silenciosa).
    // Comparamos rutas canónicas para permitir renombrar al mismo archivo (no-op) sin error.
    let es_mismo = std::path::Path::new(&ruta).canonicalize().ok()
        == nueva_ruta.canonicalize().ok().filter(|_| nueva_ruta.exists());
    if nueva_ruta.exists() && !es_mismo {
        return Err("Ya existe un archivo con ese nombre.".into());
    }

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
    let subclave_hex = sesion.subclave_hex()?;
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

// COMANDO — Eliminar buzón del sistema de guardados
#[tauri::command]
fn eliminar_buzon_guardado(id: String, sesion: tauri::State<SesionActiva>) -> Result<(), String> {
    let subclave_hex = sesion.subclave_hex()?;
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
    let subclave_hex = sesion.subclave_hex()?;
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
    let nombre_nuevo = validar_nombre_buzon(&nombre_nuevo)?;
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() { return Err("No hay sesión activa.".into()); }

    let ruta = guardados_path(".buzones_guardados.babel");
    let mut nodos = cargar_nodos(std::path::Path::new(&ruta), &subclave_hex);
    if let Some(n) = nodos.iter_mut().find(|n| n.id == id) {
        n.nombre = nombre_nuevo;
    }
    guardar_nodos(&nodos, std::path::Path::new(&ruta), &subclave_hex)
}

// COMANDO 17 — Ver archivo descifrado
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

    for nombre in &["word/header1.xml","word/header2.xml","word/footer1.xml","word/footer2.xml"] {
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
    for i in 0..zip.len() {
        if let Ok(mut file) = zip.by_index(i) {
            let name = file.name().to_string();
            if !name.starts_with("word/media/") { continue; }
            let mime = match name.rsplit('.').next().unwrap_or("") {
                "png" => "image/png", "jpg" | "jpeg" => "image/jpeg",
                "gif" => "image/gif", "webp" => "image/webp", _ => continue,
            };
            let mut buf = Vec::new();
            if file.read_to_end(&mut buf).is_ok() {
                imagenes_html.push_str(&format!(
                    "<img src='data:{};base64,{}' style='max-width:100%;margin:10px 0;display:block;border-radius:4px;'>",
                    mime, base64::engine::general_purpose::STANDARD.encode(&buf)
                ));
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
        let (bold, italic) = (run.run_property.bold.is_some(), run.run_property.italic.is_some());
        let mut out = String::new();
        for rc in &run.children {
            match rc {
                docx_rs::RunChild::Text(t) => {
                    let e = t.text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
                    out.push_str(&match (bold, italic) {
                        (true, true)  => format!("<strong><em>{}</em></strong>", e),
                        (true, false) => format!("<strong>{}</strong>", e),
                        (false, true) => format!("<em>{}</em>", e),
                        _             => e,
                    });
                }
                docx_rs::RunChild::Drawing(_) => {
                    let i = img_idx.get();
                    if i < imagenes.len() {
                        out.push_str(&format!("<img src='{}' style='max-width:100%;height:auto;display:block;margin:4px 0;'>", imagenes[i]));
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

    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }

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
        let mime = if raw_bytes.starts_with(b"\x89PNG") { Some("image/png") }
            else if raw_bytes.starts_with(b"\xFF\xD8\xFF") { Some("image/jpeg") }
            else if raw_bytes.starts_with(b"GIF8") { Some("image/gif") }
            else if raw_bytes.len() > 12 && &raw_bytes[..4] == b"RIFF" && &raw_bytes[8..12] == b"WEBP" { Some("image/webp") }
            else { None };
        if let Some(mime) = mime {
            return Ok(format!("data:{};base64,{}", mime, base64::engine::general_purpose::STANDARD.encode(&raw_bytes)));
        }

        // TXT — texto plano UTF-8
        if let Ok(texto_plano) = String::from_utf8(raw_bytes) {
            return Ok(texto_plano);
        }

        // Binario no reconocido
        return Err("Formato no previsualizable. Usa EXPORTAR.".into());
    }

    // Contenido guardado como html: (nueva ruta fallback PDF)
    if contenido.starts_with("html:") {
        return Ok(contenido);
    }

    // Retrocompatibilidad: archivos antiguos guardados como Markdown plano
    // (antes de introducir html: prefix) — convertir al vuelo para el visor
    let parece_markdown = contenido.lines().take(20).any(|l| {
        let t = l.trim();
        t.starts_with("# ") || t.starts_with("## ") || t.starts_with("### ")
            || (t.starts_with('|') && t.ends_with('|'))
    });
    if parece_markdown {
        return Ok(format!("html:{}", traductor::markdown_a_html(&contenido)));
    }

    Ok(contenido)
}

// COMANDO 18 — Guardar y cargar ajustes

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
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa para cifrar los ajustes.".to_string());
    }
    let data = serde_json::to_string(&settings).map_err(|e| e.to_string())?;
    let cifrado = seguridad::blindar_documento(&data, &subclave_hex)
        .map_err(|e| format!("Error cifrando ajustes: {}", e))?;
    fs::write(&babel_path("settings.babel"), cifrado).map_err(|e| e.to_string())?;
    Ok(())
}

// Carga los ajustes — primero intenta settings.babel (cifrado), luego settings.json (plano)
#[tauri::command]
fn load_settings(sesion: tauri::State<SesionActiva>) -> Result<AppSettings, String> {
    let subclave_hex = sesion.subclave_hex()?;

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
            // migrate plaintext settings to encrypted
            if !subclave_hex.is_empty() {
                if let Ok(json) = serde_json::to_string(&settings) {
                    if let Ok(cifrado) = seguridad::blindar_documento(&json, &subclave_hex) {
                        let ok = fs::write(babel_path("settings.babel"), cifrado).is_ok();
                        if ok { let _ = fs::remove_file(babel_path("settings.json")); }
                        traductor::registrar_evento(
                            if ok { "settings.json migrado a settings.babel cifrado" }
                            else { "AVISO: migración settings.json fallida — no se pudo escribir settings.babel" },
                            &subclave_hex,
                        );
                    }
                }
            }
            return Ok(settings);
        }
    }

    Ok(default)
}

// HELPER — Genera 12 palabras aleatorias del diccionario BIP39

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

// COMANDO 19 — Generar frase de recuperación BIP39

#[tauri::command]
fn generar_frase_recuperacion(
    maestra: String,
    pass_usuario: String,
    _sesion: tauri::State<SesionActiva>,
) -> Result<Vec<String>, String> {
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
    Ok(palabras)
}

// recuperar_con_frase era el comando IPC original (devolvía credenciales al frontend).
// Sustituido por recuperar_y_autenticar — ya no se registra como comando Tauri.
// ============================================================
// COMANDO — Recuperar Y autenticar en un solo paso (B7/S2)
// Las credenciales (maestra, pass) se derivan y verifican íntegramente en Rust.
// El frontend solo recibe un aviso opcional — ningún secreto cruza el IPC.
// ============================================================
#[tauri::command]
fn recuperar_y_autenticar(
    palabras: Vec<String>,
    sesion: tauri::State<SesionActiva>,
) -> Result<String, String> {
    // Reutilizar la misma lógica de recuperación para obtener las credenciales
    let (maestra, pass, aviso) = recuperar_con_frase_interno(&palabras, &sesion)?;
    let maestra = Zeroizing::new(maestra);
    let pass = Zeroizing::new(pass);

    // Ahora ejecutar el login internamente (igual que verificar_login)
    let salt = traductor::cargar_o_crear_salt();
    let subclave = seguridad::derivar_subclave(maestra.as_bytes(), "babel-usuarios-v1", &salt)
        .map_err(|e| format!("Error derivando subclave: {}", e))?;
    let subclave_hex = Zeroizing::new(hex::encode(subclave.as_ref()));

    let cifrado = fs::read(&babel_path("usuarios.babel"))
        .map_err(|_| "No se encontró el búnker.".to_string())?;
    let json = seguridad::descifrar_documento(cifrado, &subclave_hex)
        .map_err(|_| "Llave maestra incorrecta.".to_string())?;
    let usuario_guardado: UsuarioBabel =
        serde_json::from_str(&json).map_err(|_| "Búnker corrupto.".to_string())?;

    if !seguridad::verificar_password(&pass, &usuario_guardado.password_hash) {
        return Err("Contraseña de usuario incorrecta.".to_string());
    }

    // Establecer sesión
    if let Ok(mut s) = sesion.subclave.lock() {
        let z = Zeroizing::new(*subclave);
        seguridad::mlock_bytes(&z[..]);
        *s = Some(z);
    }
    if let Ok(mut u) = sesion.usuario.lock() {
        *u = usuario_guardado.nombre.clone();
    }
    if let Ok(mut d) = sesion.diccionario.lock() {
        *d = traductor::cargar_diccionario("es_en", &subclave_hex, "todos");
    }
    if let Ok(mut c) = sesion.contador.lock() { *c = 0; }
    seguridad::borrar_contador_intentos();
    seguridad::resetear_amenazas_conocidas();

    Ok(aviso)
}

// Lógica interna de recuperación compartida por recuperar_con_frase y recuperar_y_autenticar.
fn recuperar_con_frase_interno(
    palabras: &[String],
    sesion: &tauri::State<SesionActiva>,
) -> Result<(String, String, String), String> {
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
    let todas_validas = palabras.iter().all(|p| bip39_words::WORDLIST.contains(&p.as_str()));
    if !todas_validas {
        return Err("Una o más palabras no pertenecen al diccionario BIP39.".into());
    }

    let salt_maestra = traductor::cargar_o_crear_salt();
    let recovery_salt = seguridad::derivar_recovery_salt_v2(&salt_maestra);
    let key_v3 = seguridad::derivar_clave_recuperacion_v3(palabras, &recovery_salt)?;
    let key_v3_hex = Zeroizing::new(hex::encode(key_v3.as_ref()));
    let key_v2 = seguridad::derivar_clave_recuperacion_v2(palabras, &recovery_salt)?;
    let key_v2_hex = Zeroizing::new(hex::encode(key_v2.as_ref()));

    let cifrado = fs::read(&babel_path("recovery.babel")).map_err(|_| {
        "No se encontró archivo de recuperación.".to_string()
    })?;

    let mut usado_v0 = false;
    let mut datos = match seguridad::descifrar_documento(cifrado.clone(), &key_v3_hex) {
        Ok(d) => d,
        Err(_) => match seguridad::descifrar_documento(cifrado.clone(), &key_v2_hex) {
            Ok(d) => {
                if let Ok(nuevo) = seguridad::blindar_documento(&d, &key_v3_hex) {
                    let _ = fs::write(babel_path("recovery.babel"), nuevo);
                }
                d
            }
            Err(_) => {
                let key_v1 = seguridad::derivar_clave_recuperacion(palabras)
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
                        let key_v0 = seguridad::derivar_clave_recuperacion_v0(palabras)
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
                                incrementar_contador_y_bloquear(sesion)?;
                                return Err("Frase incorrecta - no corresponde a este bunker.".to_string());
                            }
                        }
                    }
                }
            }
        }
    };

    if let Ok(mut c) = sesion.contador.lock() { *c = 0; }
    seguridad::borrar_contador_intentos();

    let json: serde_json::Value =
        serde_json::from_str(&datos).map_err(|_| "Formato de recovery invalido.".to_string())?;
    let maestra = json["m"].as_str().ok_or("Falta maestra".to_string())?.to_string();
    let pass = json["p"].as_str().ok_or("Falta pass".to_string())?.to_string();
    datos.zeroize();

    let aviso = if usado_v0 {
        "ADVERTENCIA: búnker creado con esquema BIP39 v0 (HKDF sin Argon2id). \
         Se ha migrado automáticamente a v3 — vuelve a generar tu frase de recuperación.".to_string()
    } else {
        String::new()
    };
    Ok((maestra, pass, aviso))
}

// COMANDO 21 — Ver frase de recuperación (dentro de la app)

#[tauri::command]
fn ver_frase_recuperacion(sesion: tauri::State<SesionActiva>) -> Result<Vec<String>, String> {
    let subclave_hex = sesion.subclave_hex()?;

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
    seguridad::borrar_contador_intentos();
    let usuario: seguridad::UsuarioBabel =
        serde_json::from_str(&json).map_err(|e| format!("Error leyendo usuario: {}", e))?;
    Ok(usuario.nombre)
}

// COMANDO 22 — Términos de uso

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

// Extrae la parte <email@dominio> del remitente para comparar sin display name.
// Evita bypass de whitelist tipo: "empresa.com <evil@evil.com>"
fn addr_de_remitente(remitente: &str) -> String {
    if let Some(start) = remitente.find('<') {
        remitente[start + 1..].trim_end_matches('>').trim().to_lowercase()
    } else {
        remitente.trim().to_lowercase()
    }
}

fn es_remitente_valido(s: &str) -> bool {
    if s.contains('@') {
        let mut partes = s.splitn(2, '@');
        let local = partes.next().unwrap_or("");
        let dominio = partes.next().unwrap_or("");
        !local.is_empty() && !dominio.is_empty() && dominio.contains('.')
    } else {
        !s.is_empty()
            && s.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-')
            && !s.starts_with('.')
            && !s.ends_with('.')
    }
}

// COMANDO 23 — Guardar configuración del email

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
    let subclave_hex = sesion.subclave_hex()?;

    let remitentes_autorizados: Vec<String> = remitentes
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty() && es_remitente_valido(s))
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

// COMANDO 24 — Enviar archivo cifrado por email

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
    validar_email_requerido(&destinatario)?;
    validar_email(&cc)?;
    validar_email(&cco)?;
    validar_ruta_en(&ruta, archivos_dir()).or_else(|_| validar_ruta_en(&ruta, guardados_dir()))?;

    let subclave_hex = sesion.subclave_hex()?;

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

// COMANDO 25 — Enviar bytes por email

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
    validar_email_requerido(&destinatario)?;
    validar_email(&cc)?;
    validar_email(&cco)?;
    let subclave_hex = sesion.subclave_hex()?;

    let nombre_solo = std::path::Path::new(&nombre_archivo)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Nombre de archivo inválido.")?
        .to_string();
    // Sufijo aleatorio evita colisiones y ataques de predicción de nombre (B10)
    let ruta_temp = tmp_path(&format!("email_{}_{}", nombre_solo, nuevo_id()));
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

// COMANDO 26 — Obtener emails de la bandeja de entrada

#[tauri::command]
fn obtener_emails_tauri(
    sesion: tauri::State<SesionActiva>,
) -> Result<Vec<traductor::EmailResumen>, String> {
    let subclave_hex = sesion.subclave_hex()?;

    let creds = traductor::cargar_config_email(&subclave_hex).ok_or_else(|| {
        "No hay configuración de email guardada. Configura SMTP primero.".to_string()
    })?;

    let mut emails =
        traductor::obtener_emails(&creds.imap_dominio, &creds.usuario, &creds.password)
            .map_err(|e| format!("Error obteniendo emails: {}", e))?;

    if !creds.remitentes_autorizados.is_empty() {
        emails.retain(|e| {
            let addr = addr_de_remitente(&e.remitente);
            creds.remitentes_autorizados.iter().any(|r| {
                if r.contains('@') {
                    addr == r.as_str()
                } else {
                    addr.ends_with(&format!("@{}", r))
                }
            })
        });
    }

    Ok(emails)
}

// COMANDO 27 — Obtener cuerpo completo de un email por ID

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
    let subclave_hex = sesion.subclave_hex()?;

    let creds = traductor::cargar_config_email(&subclave_hex)
        .ok_or_else(|| "No hay configuración de email guardada.".to_string())?;

    let email =
        traductor::obtener_email_completo(&creds.imap_dominio, &creds.usuario, &creds.password, id)
            .map_err(|e| format!("Error obteniendo email: {}", e))?;

    if !creds.remitentes_autorizados.is_empty() {
        let addr = addr_de_remitente(&email.remitente);
        let autorizado = creds.remitentes_autorizados.iter().any(|r| {
            if r.contains('@') {
                addr == r.as_str()
            } else {
                addr.ends_with(&format!("@{}", r))
            }
        });
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

// COMANDO — Obtener firma del email configurado

#[tauri::command]
fn obtener_firma_email(sesion: tauri::State<SesionActiva>) -> String {
    let subclave_hex = match sesion.subclave_hex() {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    if subclave_hex.is_empty() {
        return String::new();
    }
    traductor::cargar_config_email(&subclave_hex)
        .map(|c| c.firma.clone())
        .unwrap_or_default()
}

// COMANDO — Eliminar email por UID via IMAP (\Deleted + EXPUNGE)

#[tauri::command]
fn eliminar_email_tauri(
    id: u32,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    let subclave_hex = sesion.subclave_hex()?;

    let creds = traductor::cargar_config_email(&subclave_hex)
        .ok_or_else(|| "No hay configuración de email guardada.".to_string())?;

    traductor::eliminar_email(&creds.imap_dominio, &creds.usuario, &creds.password, id)
        .map_err(|e| format!("Error eliminando email: {}", e))
}

// COMANDO — Marcar email como no leído (IMAP -\Seen)

#[tauri::command]
fn marcar_no_leido_tauri(
    id: u32,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    let subclave_hex = sesion.subclave_hex()?;
    let creds = traductor::cargar_config_email(&subclave_hex)
        .ok_or_else(|| "No hay configuración de email guardada.".to_string())?;
    traductor::marcar_no_leido(&creds.imap_dominio, &creds.usuario, &creds.password, id)
        .map_err(|e| format!("Error marcando no leído: {}", e))
}

// COMANDO — Comprobar si el email está configurado

#[tauri::command]
fn tiene_config_email(sesion: tauri::State<SesionActiva>) -> bool {
    let subclave_hex = match sesion.subclave_hex() {
        Ok(s) => s,
        Err(_) => return false,
    };
    if subclave_hex.is_empty() {
        return false;
    }
    traductor::cargar_config_email(&subclave_hex).is_some()
}

// COMANDO 28 — Abrir carpeta Babel en Finder

#[tauri::command]
fn abrir_carpeta_babel(sesion: tauri::State<SesionActiva>) -> Result<(), String> {
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    let carpeta_babel = archivos_dir();
    tauri_plugin_opener::open_path(&*carpeta_babel.to_string_lossy(), None::<&str>)
        .map_err(|e| format!("Error abriendo Finder: {}", e))
}
// COMANDOS P2P

#[tauri::command]
fn iniciar_servidor_p2p(sesion: tauri::State<SesionActiva>) -> Result<String, String> {
    // Resetear señal de apagado antes de arrancar un nuevo servidor
    babel_p2p::reiniciar_servidor_p2p();

    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
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

    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }

    // P-1: validar que la IP sea una IPv4 bien formada antes de conectar
    ip.parse::<std::net::Ipv4Addr>().map_err(|_| "IP de destino inválida".to_string())?;
    let peer = babel_p2p::DescubrimientoRed::peer_manual(&ip, "Babel-Remoto");
    let cliente = babel_p2p::ClienteP2P::nuevo(&subclave_hex);
    cliente.enviar(&peer, &ruta)
}
// enviar mensajes de texto como archivos .txt para aprovechar la infraestructura de envío de archivos cifrados
#[tauri::command]
fn enviar_mensaje_p2p(
    ip: String,
    mensaje: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }

    // P-1: validar que la IP sea una IPv4 bien formada antes de conectar
    ip.parse::<std::net::Ipv4Addr>().map_err(|_| "IP de destino inválida".to_string())?;
    // Convertimos el mensaje a bytes y lo enviamos como si fuera un archivo
    let datos = mensaje.as_bytes().to_vec();
    let peer = babel_p2p::DescubrimientoRed::peer_manual(&ip, "Babel-Remoto");
    let cliente = babel_p2p::ClienteP2P::nuevo(&subclave_hex);
    cliente.enviar_bytes(&peer, "mensaje.txt", &datos)
}
// Obtener mensajes de texto recibidos por P2P
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
    let subclave = sesion.subclave_hex()?;
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
// HELPER — Convierte código de idioma al par MarianMT
// Centralizado aquí para no duplicar el match en cada comando.

fn idioma_a_par(idioma: &str) -> &'static str {
    match idioma {
        "es_en"=>"es-en","en_es"=>"en-es","es_fr"=>"es-fr","fr_es"=>"fr-es",
        "es_ar"=>"es-ar","ar_es"=>"ar-es","fr_en"=>"fr-en","en_fr"=>"en-fr",
        "en_ar"=>"en-ar","ar_en"=>"ar-en","fr_ar"=>"fr-ar","ar_fr"=>"ar-fr",
        "es_de"=>"es-de","de_es"=>"de-es","fr_de"=>"fr-de","de_fr"=>"de-fr",
        "ar_de"=>"ar-de","de_ar"=>"de-ar","es_ru"=>"es-ru","ru_es"=>"ru-es",
        "fr_ru"=>"fr-ru","ru_fr"=>"ru-fr","ar_ru"=>"ar-ru","ru_ar"=>"ru-ar",
        "es_zh"=>"es-zh","zh_es"=>"zh-es","fr_zh"=>"fr-zh","zh_fr"=>"zh-fr",
        "ar_zh"=>"ar-zh","zh_ar"=>"zh-ar","de_ru"=>"de-ru","ru_de"=>"ru-de",
        "de_zh"=>"de-zh","zh_de"=>"zh-de","ru_zh"=>"ru-zh","zh_ru"=>"zh-ru",
        "en_de"=>"en-de","de_en"=>"de-en","en_ru"=>"en-ru","ru_en"=>"ru-en",
        "en_zh"=>"en-zh","zh_en"=>"zh-en",_=>"es-en",
    }
}

// COMANDO — Guardar HTML de frase BIP39 en tmp para imprimir
// La plantilla de impresión la construye Rust a partir de las 12 palabras, NO se recibe
// HTML del frontend. Antes se recibía HTML arbitrario y se filtraba con un blocklist frágil
// que, además, rechazaba la propia plantilla (`<meta>`, `<style>`) y dejaba la impresión rota.
// Al aceptar solo palabras validadas contra el diccionario BIP39 (lista cerrada de a-z), no
// existe ninguna superficie de inyección: nada de lo que escribimos depende de input libre.

const FRASE_HTML_CABECERA: &str = r#"<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Babel Security — Frase de Recuperación</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: Georgia, 'Times New Roman', serif; background: #fff; color: #1a1a1a; padding: 48px 56px; }
  header { text-align: center; border-bottom: 2px solid #1a1a1a; padding-bottom: 20px; margin-bottom: 32px; }
  h1 { font-size: 22px; letter-spacing: 6px; font-weight: 400; margin-bottom: 6px; }
  .subtitle { font-size: 10px; letter-spacing: 3px; color: #555; text-transform: uppercase; }
  .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-bottom: 40px; }
  .palabra { display: flex; align-items: center; gap: 12px; border: 1px solid #ccc; padding: 12px 16px; }
  .num { font-size: 10px; color: #999; min-width: 16px; text-align: right; font-family: 'Courier New', monospace; }
  .txt { font-size: 15px; letter-spacing: 0.5px; }
  footer { border-top: 1px solid #ccc; padding-top: 16px; display: flex; justify-content: space-between; }
  .aviso { font-size: 9px; letter-spacing: 1.5px; color: #888; text-transform: uppercase; }
  @media print { body { padding: 32px 40px; } }
</style>
</head>
<body>
  <header>
    <h1>BABEL SECURITY</h1>
    <p class="subtitle">Frase de recuperación BIP39 &mdash; Documento confidencial</p>
  </header>
  <div class="grid">"#;

const FRASE_HTML_MEDIO: &str = r#"</div>
  <footer>
    <span class="aviso">⚠ Guarda este documento bajo llave &mdash; No compartas con nadie</span>
    <span class="aviso">"#;

const FRASE_HTML_PIE: &str = r#"</span>
  </footer>
</body>
</html>"#;

#[tauri::command]
fn guardar_html_frase(palabras: Vec<String>) -> Result<String, String> {
    if palabras.len() != 12 {
        return Err("La frase debe tener exactamente 12 palabras.".into());
    }
    // Cada palabra debe pertenecer al diccionario BIP39 (solo a-z). Esto elimina cualquier
    // posibilidad de inyección HTML/JS: no escribimos nada que no sea una palabra conocida.
    for p in &palabras {
        if !bip39_words::WORDLIST.contains(&p.as_str()) {
            return Err("Una o más palabras no pertenecen al diccionario BIP39.".into());
        }
    }

    let celdas: String = palabras
        .iter()
        .enumerate()
        .map(|(i, p)| {
            format!(
                "<div class=\"palabra\"><span class=\"num\">{}</span><span class=\"txt\">{}</span></div>",
                i + 1,
                p
            )
        })
        .collect();

    let fecha = chrono::Local::now().format("%d/%m/%Y").to_string();

    let html = format!(
        "{}{}{}{}{}",
        FRASE_HTML_CABECERA, celdas, FRASE_HTML_MEDIO, fecha, FRASE_HTML_PIE
    );

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

// PUNTO DE ENTRADA — Arranca Tauri, registra todos los comandos — y gestiona el estado global de sesión (SesionActiva).

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
            let exe_dir = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.to_path_buf()));
            let sidecar_path = exe_dir.as_ref().map(|d| d.join("servidor_babel"));
            let sidecar_exists = sidecar_path.as_ref().map(|p| p.exists()).unwrap_or(false);
            // Fallback legacy: python + script en Resources/ (USBs anteriores)
            let legacy_exists = app.path().resource_dir().ok().map(|res| {
                res.join("python").join("bin").join("python3").exists()
                    && res.join("servidor").join("marian_server_usb.py").exists()
            }).unwrap_or(false);
            // Puerto libre = no hay servidor externo arrancado en modo dev
            let puerto_libre = std::net::TcpStream::connect_timeout(
                &"127.0.0.1:5002".parse::<std::net::SocketAddr>().unwrap(),
                std::time::Duration::from_millis(300),
            ).is_err();

            if puerto_libre && (sidecar_exists || legacy_exists) {
                let mut rng_bytes = [0u8; 16];
                rand::rngs::OsRng.fill_bytes(&mut rng_bytes);
                let token = format!("babel_{}", hex::encode(rng_bytes));
                traductor::inicializar_nllb_token(token.clone());

                let child_result = if sidecar_exists {
                    let bin = sidecar_path.unwrap();
                    std::process::Command::new(&bin)
                        .env("BABEL_NLLB_TOKEN", &token)
                        .env("TRANSFORMERS_OFFLINE", "1")
                        .env("HF_DATASETS_OFFLINE", "1")
                        .env("TOKENIZERS_PARALLELISM", "false")
                        .spawn()
                } else {
                    let res = app.path().resource_dir().unwrap();
                    let py_bin = res.join("python").join("bin").join("python3");
                    let servidor = res.join("servidor").join("marian_server_usb.py");
                    std::process::Command::new(&py_bin)
                        .arg(&servidor)
                        .env("BABEL_NLLB_TOKEN", &token)
                        .env("TRANSFORMERS_OFFLINE", "1")
                        .env("HF_DATASETS_OFFLINE", "1")
                        .env("TOKENIZERS_PARALLELISM", "false")
                        .spawn()
                };

                if let Ok(child) = child_result {
                    *USB_CHILD.lock().unwrap_or_else(|p| p.into_inner()) = Some(child);
                }

                let handle = app.handle().clone();
                std::thread::spawn(move || {
                    let addr: std::net::SocketAddr = "127.0.0.1:5002".parse().unwrap();
                    let timeout = std::time::Duration::from_secs(1);
                    for _ in 0..120 {
                        std::thread::sleep(std::time::Duration::from_secs(2));
                        if std::net::TcpStream::connect_timeout(&addr, timeout).is_ok() {
                            let _ = handle.emit("servidor-usb-listo", ());
                            break;
                        }
                    }
                });
            }

            // Dev/externo: tomar token del entorno si el modo USB no lo fijó ya (idempotente)
            if let Ok(tok) = std::env::var("BABEL_NLLB_TOKEN") {
                if !tok.is_empty() {
                    traductor::inicializar_nllb_token(tok);
                }
            }

            // Monitor de amenazas cada 5 min — solo emite si hay amenazas nuevas y sesión activa
            let handle_monitor = app.handle().clone();
            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(300));
                    let sesion = handle_monitor.state::<SesionActiva>();
                    let subclave = match sesion.subclave_hex() {
                        Ok(s) => s,
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
            traducir_archivo_guardado,
            traducir_documento_dialogo,
            cancelar_traduccion_activa,
            seleccionar_ruta_dialogo,
            leer_resultado,
            traducir_texto,
            cambiar_categoria_diccionario,
            cambiar_idioma,
            crear_buzon,
            listar_buzones,
            exportar_archivo,
            exportar_archivos_a_carpeta,
            eliminar_archivo,
            eliminar_buzon,
            ver_archivo,
            mover_archivo,
            generar_frase_recuperacion,
            recuperar_y_autenticar,
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
            importar_archivo_dialogo,
            borrar_archivo_original,
            borrar_archivo_fuente,
            archivo_guardado_existe,
            verificar_herramientas_pdf,
            listar_archivos_guardados,
            crear_buzon_guardado,
            listar_buzones_guardados,
            eliminar_buzon_guardado,
            renombrar_buzon_guardado,
            abrir_carpeta_guardados,
            mover_archivo_guardado,
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
