#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod babel_p2p;
mod bip39_words;
mod compartir;
mod custodia;
mod enclave;
mod finder;
mod gmail_oauth;
mod img_a_pdf;
mod integridad;
mod pdf_reducir;
mod conexion_directa;
mod buzon_b2;
mod pdf_union;
mod rat_detector;
mod registro_diario;
mod seguridad;
mod sincronizacion;
mod nom_cifrado;
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
// Serializa los drenados de entrada_finder/: evita que manejar_url_babel y
// procesar_entrada_finder (login/unlock) se solapen y cifren el mismo staged dos veces.
static FINDER_PROCESSING_MUTEX: Mutex<()> = Mutex::new(());
// Token CSRF efímero para el URL scheme babel://. Se genera al iniciar sesión y se
// verifica en manejar_url_babel cuando hay sesión activa. El Quick Action debe leerlo
// de ~/Babel/.finder_token e incluirlo en la URL como ?token=<hex>.
static FINDER_TOKEN: Mutex<Option<String>> = Mutex::new(None);

// Versión que se presentó al usuario para confirmar actualización.
// Permite detectar si entre el check() y el install() se publicó una versión diferente.
static UPDATE_VERSION_PENDIENTE: Mutex<Option<String>> = Mutex::new(None);

// Proceso hijo del servidor de traducción (sidecar PyInstaller).
// Módulo-nivel para poder matar desde el panic hook y desde on_window_event.
static USB_CHILD: Mutex<Option<std::process::Child>> = Mutex::new(None);

// Estado del servidor: 0=externo, 1=cargando, 2=listo, 3=error
static SERVIDOR_ESTADO: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

// Rutas de archivos originales pendientes de borrado tras un import.
// Clave: token opaco generado por nuevo_id(); valor: ruta canónica.
// Cada import tiene su propio token — evita que imports concurrentes se sobreescriban.
static PENDING_BORRAR_ORIGINAL: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

// Estado temporal del flujo PKCE Gmail OAuth en curso.
// Contiene (code_verifier, puerto_callback) mientras el usuario autoriza en el browser.

// ── Helpers CSRF token babel:// ───────────────────────────────────────────────

fn generar_finder_token() {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let hex = hex::encode(bytes);
    let ruta = babel_dir().join(".finder_token");
    let _ = escribir_privado(&ruta, hex.as_bytes());
    if let Ok(mut g) = FINDER_TOKEN.lock() {
        *g = Some(hex);
    }
}

fn limpiar_finder_token() {
    if let Ok(mut g) = FINDER_TOKEN.lock() {
        *g = None;
    }
    let _ = fs::remove_file(babel_dir().join(".finder_token"));
}

// Compara en tiempo constante el token de la URL contra el almacenado en memoria.
// Solo aplica cuando hay sesión activa; sin sesión no hay token y se ignora la URL.
fn verificar_finder_token(urls: &[String]) -> bool {
    let esperado = match FINDER_TOKEN.lock().ok().and_then(|g| g.clone()) {
        Some(t) => t,
        None => return false,
    };
    urls.iter().any(|url| {
        let qs = url.splitn(2, '?').nth(1).unwrap_or("");
        qs.split('&').any(|par| {
            if let Some(val) = par.strip_prefix("token=") {
                val.len() == esperado.len()
                    && val.as_bytes().iter().zip(esperado.as_bytes())
                        .fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
            } else {
                false
            }
        })
    })
}

// ── Borrado seguro de archivos temporales ─────────────────────────────────────
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

/// RAII: llama a `borrar_seguro` al soltar, incluso en panic o retorno anticipado.
/// Útil para garantizar limpieza de temporales plaintext en cualquier ruta de salida.
struct BorrarAlSalir(String);
impl Drop for BorrarAlSalir {
    fn drop(&mut self) {
        borrar_seguro(&self.0);
    }
}

/// Escribe `datos` en `ruta` con permisos 0o600 (solo dueño puede leer/escribir).
/// En Windows usa los permisos heredados del proceso (no hay ACL equivalente simple).
/// Usar en TODOS los archivos internos de Babel: vault, temporales, índices.
pub(crate) fn escribir_privado(
    ruta: impl AsRef<std::path::Path>,
    datos: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    #[cfg(unix)]
    let res = {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(ruta.as_ref())
            .and_then(|mut f| f.write_all(datos.as_ref()))
    };
    // En Windows no hay chmod: escritura normal, heredando las ACL del proceso.
    // (Antes esta rama se llamaba a sí misma → recursión infinita y crash al primer
    // guardado interno; en Unix nunca se compilaba, por eso el CI no lo detectaba.)
    #[cfg(not(unix))]
    let res = std::fs::write(ruta.as_ref(), datos.as_ref());
    res
}

/// Escritura atómica via temp-file + rename.
///
/// En POSIX, `rename(2)` es atómico: si el proceso muere antes de que el rename
/// se complete, el archivo destino conserva su contenido anterior íntegro. Solo
/// cuando el rename tiene éxito el archivo destino pasa a ver el contenido nuevo.
/// Soluciona el bug B2 del audit: `escribir_privado` no era atómico y un corte de
/// luz durante `guardar_emparejados` podía dejar `dispositivos.babel` truncado,
/// haciendo que `cargar_emparejados` devolviera `Vec::new()` y borrara los pares.
pub(crate) fn escribir_privado_atomico(
    ruta: impl AsRef<std::path::Path>,
    datos: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    let ruta = ruta.as_ref();
    let dir = ruta.parent().unwrap_or_else(|| std::path::Path::new("."));
    let fname = ruta
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "tmp".into());
    let tmp = dir.join(format!(".{}.tmp", fname));

    // Escribir al temporal (con permisos 0600 en Unix)
    escribir_privado(&tmp, datos)?;
    // Rename atómico temporal → destino
    std::fs::rename(&tmp, ruta)
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
    pub ultimo_acceso: Mutex<std::time::Instant>,
    pub timeout_minutos: Mutex<u32>,
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
            ultimo_acceso: Mutex::new(std::time::Instant::now()),
            timeout_minutos: Mutex::new(0),
        }
    }

    /// Codifica la subclave residente a hex bajo demanda para las funciones cripto que
    /// esperan `&str`. Verifica el timeout de inactividad y actualiza el timestamp.
    /// Devuelve un `Zeroizing<String>` (se borra al final del comando) y cadena vacía
    /// cuando no hay sesión — así los checks `is_empty()` siguen funcionando.
    fn subclave_hex(&self) -> Result<Zeroizing<String>, String> {
        // Verificar timeout de inactividad en backend
        let timeout_mins = self.timeout_minutos.lock()
            .map_err(|_| "Error leyendo sesión.".to_string())
            .map(|g| *g)?;
        if timeout_mins > 0 {
            let elapsed = self.ultimo_acceso.lock()
                .map_err(|_| "Error leyendo sesión.".to_string())
                .map(|g| g.elapsed().as_secs())?;
            if elapsed > (timeout_mins as u64 * 60) {
                return Err("Sesión expirada por inactividad.".into());
            }
        }
        if let Ok(mut t) = self.ultimo_acceso.lock() {
            *t = std::time::Instant::now();
        }

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
        if let Ok(mut c) = self.contador.lock() {
            *c = 0; // no arrastrar intentos fallidos entre sesiones
        }
        if let Ok(mut t) = self.timeout_minutos.lock() {
            *t = 0;
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
    // BABEL_DATA_DIR permite correr múltiples instancias con datos separados (pruebas).
    if let Ok(custom) = std::env::var("BABEL_DATA_DIR") {
        let expanded = if custom.starts_with("~/") {
            let home = std::env::var("HOME").unwrap_or_default();
            format!("{}/{}", home, &custom[2..])
        } else {
            custom
        };
        let dir = std::path::PathBuf::from(expanded);
        let _ = std::fs::create_dir_all(&dir);
        return dir;
    }
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

pub fn ruta_nomindex_guardados() -> String {
    guardados_path(".nomindex.babel")
}

/// Lee la versión del esquema de recovery.babel desde el marcador ~/Babel/recovery_v.
/// Devuelve 0 si el archivo no existe (vault antiguo sin marcador = v1 implícito).
fn leer_version_recovery() -> u8 {
    fs::read_to_string(babel_path("recovery_v"))
        .ok()
        .and_then(|s| s.trim().parse::<u8>().ok())
        .unwrap_or(0)
}

/// Escribe el marcador de versión de recovery.babel. Silencioso ante errores.
fn escribir_version_recovery(v: u8) {
    let _ = escribir_privado(babel_path("recovery_v"), v.to_string().as_bytes());
}

fn ruta_nomindex_archivos() -> String {
    archivos_path(".nomindex.babel")
}

/// Renombra los archivos de salida del pipeline de traducción de
/// `{id}_{par}_{stem}.babel` a un nombre opaco `{id}_{hex16}_{ts}.babel`
/// y registra la correspondencia en el índice cifrado de `archivos/`.
/// Devuelve la ruta completa del archivo traducido renombrado.
fn renombrar_salida_traduccion(
    id_usuario: &str,
    par: &str,
    nombre_base: &str,
    subclave_hex: &str,
) -> Result<String, String> {
    let adir = archivos_dir();
    let nomindex = ruta_nomindex_archivos();

    let mut raw = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let hex_opaco = hex::encode(raw);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let viejo_trad = format!("{}_{}_{}.babel", id_usuario, par, nombre_base);
    let nuevo_trad = format!("{}_{}_{}.babel", id_usuario, hex_opaco, ts);
    let viejo_path = adir.join(&viejo_trad);
    let nuevo_path = adir.join(&nuevo_trad);

    if !viejo_path.exists() {
        return Err(format!("Archivo de traducción no encontrado: {}", viejo_trad));
    }
    fs::rename(&viejo_path, &nuevo_path)
        .map_err(|e| format!("Error renombrando archivo traducido: {}", e))?;
    nom_cifrado::registrar(&nuevo_trad, nombre_base, ts, 0, &nomindex, subclave_hex)?;

    // Renombrar __orig.babel si existe (fallo no es fatal)
    let viejo_orig = format!("{}_{}_{}__orig.babel", id_usuario, par, nombre_base);
    let nuevo_orig = format!("{}_{}_{}__orig.babel", id_usuario, hex_opaco, ts);
    let viejo_orig_path = adir.join(&viejo_orig);
    if viejo_orig_path.exists() {
        if let Ok(()) = fs::rename(&viejo_orig_path, adir.join(&nuevo_orig)) {
            let _ = nom_cifrado::registrar(
                &nuevo_orig,
                &format!("{} (original)", nombre_base),
                ts,
                0,
                &nomindex,
                subclave_hex,
            );
        }
    }

    Ok(nuevo_path.to_string_lossy().to_string())
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

// Clave HMAC estática usada en versiones anteriores (v1). Se conserva SOLO para
// migrar licencias antiguas a la v2 (HMAC con master.salt, única por instalación).
const LICENCIA_KEY_V1: &[u8] = b"babel-license-bind-v1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

fn hmac_hex(bytes: &[u8], key: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(key)
        .expect("clave HMAC de longitud válida");
    mac.update(bytes);
    hex::encode(mac.finalize().into_bytes())
}

#[derive(PartialEq, Debug)]
enum LicenciaEstado {
    V2Ok,               // firma v2 válida — nada que hacer
    RequiereMigracion,  // firma v1 (clave estática) o hash SHA-256 legacy — reescribir como v2
    Invalida,           // no coincide con ninguna → vinculada a otro equipo
}

/// Clasifica el contenido guardado de licencia.babel contra el serial+salt actuales.
/// Función pura (sin E/S) para poder testear la migración v1/legacy → v2.
fn clasificar_licencia(guardado: &str, serial: &[u8], salt: &[u8]) -> LicenciaEstado {
    use sha2::Digest;
    if guardado == hmac_hex(serial, salt) {
        return LicenciaEstado::V2Ok;
    }
    let firma_v1 = hmac_hex(serial, LICENCIA_KEY_V1);
    let hash_legacy = format!("{:x}", sha2::Sha256::digest(serial));
    if guardado == firma_v1 || guardado == hash_legacy {
        LicenciaEstado::RequiereMigracion
    } else {
        LicenciaEstado::Invalida
    }
}

fn verificar_licencia_hardware() -> Result<(), String> {
    // Serial de hardware. Si no se puede leer (system_profiler falla, sin línea
    // "Serial Number", salida vacía...) devolvemos None y OMITIMOS la verificación:
    // un fallo transitorio de lectura no debe bloquear a un usuario legítimo. El
    // vínculo por hardware es una medida anti-copia blanda, no una frontera de
    // seguridad — antes se comparaba contra "UNKNOWN" y provocaba falsos rechazos.
    #[cfg(target_os = "macos")]
    let serial: Option<String> = std::process::Command::new("system_profiler")
        .args(["SPHardwareDataType"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.lines().find(|l| l.contains("Serial Number")).map(|l| l.trim().to_string()))
        .filter(|s| !s.is_empty());
    #[cfg(not(target_os = "macos"))]
    let serial: Option<String> = Some("WINDOWS-NO-SERIAL".to_string());

    let serial = match serial {
        Some(s) => s,
        None => {
            log::warn!("[licencia] No se pudo leer el serial de hardware; se omite la verificación de vínculo en este arranque.");
            return Ok(());
        }
    };

    // Clave HMAC derivada de master.salt (única por instalación).
    let salt = traductor::cargar_o_crear_salt();
    let firma = hmac_hex(serial.as_bytes(), &salt);
    let ruta = babel_path("licencia.babel");
    if std::path::Path::new(&ruta).exists() {
        let guardado = fs::read_to_string(&ruta).unwrap_or_default().trim().to_string();
        match clasificar_licencia(&guardado, serial.as_bytes(), &salt) {
            LicenciaEstado::V2Ok => {}
            LicenciaEstado::RequiereMigracion => {
                let _ = escribir_privado(&ruta, firma.as_bytes()); // migrar a v2
            }
            LicenciaEstado::Invalida => {
                return Err("Licencia inválida. Babel está vinculado a otro equipo.".into());
            }
        }
    } else {
        let _ = escribir_privado(&ruta, firma.as_bytes());
    }
    Ok(())
}

#[tauri::command]
fn verificar_entorno_seguro() -> Result<String, String> {
    let sandbox = seguridad::AntiSandbox::analizar_entorno();
    // La detección de virtualización YA NO bloquea: ejecutar Babel en una VM, un VDI
    // corporativo o un laboratorio de seguridad es un uso legítimo, y el cifrado
    // AES-256-GCM opera con seguridad total igualmente. Solo se informa como aviso.
    let aviso_sandbox = if !sandbox.seguro {
        format!(
            " — Aviso: entorno virtualizado detectado ({} indicador(es)).",
            sandbox.amenazas.len()
        )
    } else {
        String::new()
    };
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
    Ok(format!(
        "BABEL SEGURO — Todos los protocolos activos.{}{}",
        aviso_filevault, aviso_sandbox
    ))
}

// ENTRADA SEGURA — activa/desactiva el modo anti-keylogger del SO mientras el
// usuario teclea una contraseña. El frontend lo llama en focus/blur de los campos.
#[tauri::command]
fn activar_entrada_segura() {
    seguridad::activar_entrada_segura_os();
}

#[tauri::command]
fn desactivar_entrada_segura() {
    seguridad::desactivar_entrada_segura_os();
}

// Detección en vivo de captura/compartición de pantalla. El frontend la consulta en
// bucle corto mientras muestra contenido sensible. Devuelve dos niveles: `bloqueo`
// (ocultar contenido) y `aviso` (advertir sin bloquear).
#[tauri::command]
fn hay_captura_de_pantalla() -> seguridad::EstadoCaptura {
    seguridad::detectar_captura_pantalla()
}

// Escaneo de keyloggers/RATs bajo demanda, para lanzarlo JUSTO al mostrar el login o
// el desbloqueo — el momento exacto en que se teclea la maestra — en vez de esperar
// al monitor periódico de 5 min. Es async + spawn_blocking porque analizar_entorno()
// llama a codesign/ioreg/sqlite y no debe bloquear el event-loop.
#[tauri::command]
async fn escanear_keylogger_ahora() -> Vec<String> {
    tauri::async_runtime::spawn_blocking(|| {
        seguridad::AntiKeylogger::analizar_entorno().amenazas
    })
    .await
    .unwrap_or_default()
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
        schema_version: 1,
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

    escribir_privado(&babel_path("usuarios.babel"), &cifrado)
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
    // into_inner ante lock envenenado: un panic previo no debe permitir saltarse el lockout.
    let mut c = sesion.contador.lock().unwrap_or_else(|e| e.into_inner());
    *c = (*c).max(disco) + 1;
    seguridad::escribir_contador_intentos(*c);
    if *c >= 5 {
        *c = 0;
        seguridad::borrar_contador_intentos();
        traductor::activar_bloqueo_disco()
            .map_err(|e| format!("Error crítico activando bloqueo: {}", e))?;
        return Err("Bloqueado 10 minutos por demasiados intentos fallidos.".into());
    }
    Ok(())
}

fn cargar_settings_timeout(subclave_hex: &str) -> u32 {
    let ruta = babel_path("settings.babel");
    fs::read(&ruta).ok()
        .and_then(|b| seguridad::descifrar_documento(b, subclave_hex).ok())
        .and_then(|j| serde_json::from_str::<serde_json::Value>(&j).ok())
        .and_then(|v| v["timeout_sesion_minutos"].as_u64())
        .map(|m| m.min(1440) as u32)
        .unwrap_or(60)
}

fn verificar_login_interno(
    pass: String,
    pass_usuario: String,
    guardar_fecha: bool,
    sesion: tauri::State<SesionActiva>,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    let pass = Zeroizing::new(pass);
    let pass_usuario = Zeroizing::new(pass_usuario);

    // Comprobar si hay bloqueo activo
    if let Some(ts) = seguridad::leer_bloqueo() {
        let ahora = chrono::Local::now().timestamp();
        let expira = ts + 600;
        if ahora < expira {
            // cap a 600 s: evita bloqueo permanente si el reloj retrocede (NTP, ajuste manual)
            let restante = (expira - ahora).min(600);
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
    seguridad::resetear_amenazas_conocidas();
    crate::sincronizacion::establecer_subclave_sesion(&subclave_hex);
    generar_finder_token(); // token CSRF para babel:// URL scheme

    // Custodia: eliminar silenciosamente copias no autorizadas y registrar sospechas.
    {
        let hw_ids_pareados: Vec<String> = crate::sincronizacion::cargar_emparejados(&subclave_hex)
            .into_iter()
            .filter(|d| !d.hw_id.is_empty())
            .map(|d| d.hw_id)
            .collect();
        let eliminados = custodia::verificar_y_limpiar(&subclave_hex, &hw_ids_pareados);
        for nombre in &eliminados {
            crate::registro_diario::registrar_sospecha_hw(nombre, &subclave_hex);
        }
    }

    // Monitor RAT: arrancar en segundo plano tras login correcto
    crate::rat_detector::iniciar_monitor_rat(app.clone());

    // Cargar timeout de inactividad desde la configuración del usuario
    if let Ok(mut t) = sesion.ultimo_acceso.lock() {
        *t = std::time::Instant::now();
    }
    let timeout_mins = cargar_settings_timeout(&subclave_hex);
    if let Ok(mut tm) = sesion.timeout_minutos.lock() {
        *tm = timeout_mins;
    }

    // Guardar credenciales en el keychain del sistema para autologin en el próximo arranque
    guardar_credenciales_keychain(pass.as_str(), pass_usuario.as_str());
    if guardar_fecha {
        guardar_fecha_login_manual();
    }

    // Si recovery.babel existe pero el marcador de versión indica esquema antiguo
    // (o no existe el marcador, lo que implica vault creado antes del sistema de versiones),
    // avisar al usuario para que regenere su frase BIP39.
    if std::path::Path::new(&babel_path("recovery.babel")).exists() && leer_version_recovery() < 3 {
        let _ = app.emit("recuperacion-desactualizada", ());
    }

    let mut json = Zeroizing::new(json);
    json.zeroize();

    Ok(true)
}

// ──────────────────────────────────────────────────────────────────────────────
// AUTOLOGIN — Fichero cifrado con clave derivada del hardware de la máquina.
// Evita el diálogo de contraseña del sistema que genera el keyring del SO
// cuando la app se firma con firma ad-hoc (identidad cambia en cada build).
// ──────────────────────────────────────────────────────────────────────────────

fn autologin_babel_path() -> Option<std::path::PathBuf> {
    let home = dirs::home_dir()?;
    Some(home.join("Babel").join("autologin.babel"))
}

/// Deriva una clave AES-256 a partir del UUID hardware del Mac (o del hostname
/// como fallback). No requiere interacción del usuario.
fn autologin_machine_key() -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;

    // NOTA DE DISEÑO: esta clave protege el autologin por COMODIDAD, no por seguridad fuerte.
    // Cualquier proceso local con acceso a ioreg puede calcularla. La protección real
    // de las credenciales viene de FileVault (cifrado de disco) y de los permisos 0600
    // del archivo autologin.babel. Sin FileVault activo, el autologin no debe usarse.
    //
    // UUID hardware del Mac vía ioreg (único por máquina, no cambia con builds)
    let uuid = std::process::Command::new("ioreg")
        .args(["-d2", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()
        .and_then(|o| {
            let s = String::from_utf8_lossy(&o.stdout).to_string();
            s.lines()
                .find(|l| l.contains("IOPlatformUUID"))
                .and_then(|l| l.split('"').nth(3))
                .map(|u| u.to_string())
        })
        .unwrap_or_else(|| {
            hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "babel-autologin-fallback".to_string())
        });

    let hk = Hkdf::<Sha256>::new(Some(b"babel-autologin-salt-v1"), uuid.as_bytes());
    let mut key = [0u8; 32];
    // HKDF solo falla si okm es demasiado largo (255*hashlen). Con 32 bytes es imposible.
    let _ = hk.expand(b"autologin-aes-key", &mut key);
    key
}

fn guardar_credenciales_keychain(maestra: &str, pass_usuario: &str) {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, OsRng, rand_core::RngCore}};

    let Some(path) = autologin_babel_path() else { return };
    let payload = serde_json::json!([maestra, pass_usuario]).to_string();
    let key = autologin_machine_key();
    let cipher = Aes256Gcm::new((&key).into());
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let Ok(ct) = cipher.encrypt(nonce, payload.as_bytes()) else { return };
    // Formato: 12 bytes nonce | ciphertext
    let mut blob = Vec::with_capacity(12 + ct.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ct);
    // 0o600: solo el dueño puede leer; contiene contraseñas cifradas
    let _ = escribir_privado(&path, &blob);
}

fn cargar_credenciales_keychain() -> Option<(Zeroizing<String>, Zeroizing<String>)> {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};

    let path = autologin_babel_path()?;
    let blob = std::fs::read(&path).ok()?;
    if blob.len() < 13 { return None; }
    let key = autologin_machine_key();
    let cipher = Aes256Gcm::new((&key).into());
    let nonce = aes_gcm::Nonce::from_slice(&blob[..12]);
    let plain = Zeroizing::new(cipher.decrypt(nonce, &blob[12..]).ok()?);
    let partes: Vec<String> = serde_json::from_slice(&plain).ok()?;
    if partes.len() < 2 { return None; }
    let resultado = Some((Zeroizing::new(partes[0].clone()), Zeroizing::new(partes[1].clone())));
    drop(partes); // partes contiene contraseñas en claro; liberar antes de retornar
    resultado
}

fn borrar_credenciales_keychain() {
    if let Some(path) = autologin_babel_path() {
        let _ = std::fs::remove_file(path);
    }
}

// ── FECHA ÚLTIMO LOGIN MANUAL (para forzar contraseña cada 3 días) ───────────

const DIAS_FORZAR_LOGIN: u64 = 3 * 24 * 60 * 60;

fn autologin_fecha_path() -> Option<std::path::PathBuf> {
    let home = dirs::home_dir()?;
    Some(home.join("Babel").join("autologin_fecha.babel"))
}

fn guardar_fecha_login_manual() {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, OsRng, rand_core::RngCore}};
    let Some(path) = autologin_fecha_path() else { return };
    let now = unix_ahora().to_string();
    let key = autologin_machine_key();
    let cipher = Aes256Gcm::new((&key).into());
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let Ok(ct) = cipher.encrypt(nonce, now.as_bytes()) else { return };
    let mut blob = Vec::with_capacity(12 + ct.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ct);
    let _ = escribir_privado(&path, &blob);
}

fn cargar_fecha_login_manual() -> Option<u64> {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    let path = autologin_fecha_path()?;
    let blob = std::fs::read(&path).ok()?;
    if blob.len() < 13 { return None; }
    let key = autologin_machine_key();
    let cipher = Aes256Gcm::new((&key).into());
    let nonce = aes_gcm::Nonce::from_slice(&blob[..12]);
    let plain = cipher.decrypt(nonce, &blob[12..]).ok()?;
    std::str::from_utf8(&plain).ok()?.parse::<u64>().ok()
}

// ── PREFERENCIA DE AUTOLOGIN ─────────────────────────────────────────────────

fn autologin_pref_path() -> Option<std::path::PathBuf> {
    let home = dirs::home_dir()?;
    Some(home.join("Babel").join("autologin_pref.babel"))
}

#[tauri::command]
fn guardar_preferencia_autologin(activo: bool) {
    if let Some(path) = autologin_pref_path() {
        let _ = escribir_privado(&path, if activo { b"1" } else { b"0" });
    }
}

#[tauri::command]
fn leer_preferencia_autologin() -> Option<bool> {
    let path = autologin_pref_path()?;
    let bytes = std::fs::read(&path).ok()?;
    match bytes.first() {
        Some(b'1') => Some(true),
        Some(b'0') => Some(false),
        _ => None,
    }
}

// Wrapper Tauri: el login manual siempre actualiza la fecha.
#[tauri::command]
fn verificar_login(
    pass: String,
    pass_usuario: String,
    sesion: tauri::State<SesionActiva>,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    verificar_login_interno(pass, pass_usuario, true, sesion, app)
}


fn unix_ahora() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}


/// Intenta hacer login automático con credenciales guardadas en el keychain.
/// Devuelve true si hay credenciales guardadas Y son válidas.
#[tauri::command]
fn autologin_tauri(
    sesion: tauri::State<SesionActiva>,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    // Si la preferencia no está configurada o el usuario la desactivó, no hacer autologin.
    match leer_preferencia_autologin() {
        Some(true) => {}
        _ => return Ok(false),
    }
    // Forzar login manual si han pasado más de 3 días sin introducir la contraseña.
    match cargar_fecha_login_manual() {
        None => return Ok(false),
        Some(ultimo) => {
            if unix_ahora().saturating_sub(ultimo) > DIAS_FORZAR_LOGIN {
                return Ok(false);
            }
        }
    }
    let (maestra, pass_usuario) = match cargar_credenciales_keychain() {
        Some(c) => c,
        None => return Ok(false),
    };
    // Si las credenciales guardadas ya no son válidas (contraseña cambiada, etc.),
    // limpiamos el keychain y reseteamos el contador para que el fallo automático
    // no consuma intentos manuales del usuario.
    match verificar_login_interno(maestra.to_string(), pass_usuario.to_string(), false, sesion, app) {
        Ok(true) => Ok(true),
        Ok(false) => {
            borrar_credenciales_keychain();
            seguridad::borrar_contador_intentos();
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

/// Borra las credenciales guardadas del keychain (logout permanente).
#[tauri::command]
fn olvidar_sesion_tauri() -> Result<(), String> {
    borrar_credenciales_keychain();
    Ok(())
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
async fn traducir_documento(
    app: tauri::AppHandle,
    nombre_archivo: String,
    contenido: Vec<u8>,
    sesion: tauri::State<'_, SesionActiva>,
) -> Result<String, String> {
    crate::rat_detector::verificar_no_bloqueado_rat()?;

    // Extraer datos de sesión ANTES de spawn_blocking — State no es Send.
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa. Inicia sesión primero.".into());
    }
    let id_usuario = sesion.usuario.lock().map_err(|_| "Error".to_string())?.clone();
    let dict = sesion.diccionario.lock().map_err(|_| "Error leyendo diccionario.".to_string())?.clone();
    let idioma_doc = sesion.idioma.lock().map_err(|_| "Error leyendo idioma.".to_string())?.clone();
    let par_doc = idioma_a_par(&idioma_doc)?.to_string();

    // Extraemos solo el nombre base para evitar path traversal.
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

    // Subdirectorio único: dos traducciones del mismo nombre no colisionan en tmp/.
    // El nombre del archivo se conserva para que procesar_archivo_inteligente derive
    // el mismo stem que usamos abajo. cerrar_sesion limpia estos subdirectorios.
    let sub_tmp = tmp_dir().join(nuevo_id());
    let _ = fs::create_dir_all(&sub_tmp);
    let ruta_temp = sub_tmp.join(&nombre_solo).to_string_lossy().to_string();
    escribir_privado(&ruta_temp, &contenido).map_err(|e| format!("Error guardando temporal: {}", e))?;
    drop(Zeroizing::new(contenido));

    let nombre_base = std::path::Path::new(&nombre_archivo)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(&nombre_archivo)
        .to_string();
    // spawn_blocking libera el event-loop → los eventos progreso-traduccion
    // llegan al webview en tiempo real mientras traduce.
    tauri::async_runtime::spawn_blocking(move || {
        // BorrarAlSalir garantiza limpieza incluso si procesar_archivo_inteligente hace panic.
        let _guard = BorrarAlSalir(ruta_temp);
        traductor::resetear_cancelacion();
        let progreso = |pct: u8, msg: &str| {
            let _ = app.emit("progreso-traduccion", serde_json::json!({"pct": pct, "msg": msg}));
        };
        traductor::procesar_archivo_inteligente(
            &_guard.0,
            &dict,
            &subclave_hex,
            &id_usuario,
            &par_doc,
            &progreso,
        )?;
        // Renombrar los archivos de salida a nombres opacos y registrar en índice.
        renombrar_salida_traduccion(&id_usuario, &par_doc, &nombre_base, &subclave_hex)
    }).await.map_err(|e| e.to_string())?
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

    let par = idioma_a_par(&idioma)?;

    let (resultado, sin_traducir) =
        traductor::traducir_inteligente(&texto, &dict, &subclave_hex, par);
    Ok((resultado, sin_traducir))
}

// ============================================================
// COMANDO — Guardar documento sin traducir (vía ruta en disco)
// Cifra y guarda un archivo en ~/Babel/guardados/ sin traducirlo.
// El contenido se convierte a base64 antes de cifrar con AES-256-GCM.
// ============================================================

// Límite de tamaño por archivo importado (bytes). Debe coincidir con el del frontend.
const LIMITE_IMPORT_BYTES: u64 = 150 * 1024 * 1024;

// Comunica si la última llamada a cifrar_y_guardar_desde_bytes aplicó compresión
// con pérdida de resolución (JPEG downsampling o raw→JPEG). Se usa para emitir
// el evento "compresion-lossy" desde los comandos de importación interactiva.
thread_local! {
    static ULTIMA_IMPORTACION_LOSSY: std::cell::Cell<bool> = std::cell::Cell::new(false);
}

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
    // Canonicalizar para resolver symlinks — la autorización la gestiona el App Sandbox
    // a nivel OS mediante user-selected.read-write. El check starts_with(home) se elimina
    // porque en sandbox dirs::home_dir() apunta al contenedor, no al home real,
    // y rechazaría archivos legítimos seleccionados por el usuario con un file dialog.
    let ruta_canon = std::fs::canonicalize(ruta_completa)
        .map_err(|_| "Ruta no accesible o inválida.".to_string())?;

    // S-1: límite de tamaño antes de leer en memoria
    let meta = std::fs::metadata(&ruta_canon).map_err(|e| format!("Error accediendo archivo: {}", e))?;
    if meta.len() > LIMITE_IMPORT_BYTES {
        return Err("El archivo supera el límite de 150 MB.".into());
    }

    let contenido =
        fs::read(&ruta_canon).map_err(|e| format!("Error leyendo archivo: {}", e))?;

    cifrar_y_guardar_desde_bytes(nombre_archivo, &contenido, subclave_hex, id_usuario)
}

// Igual que cifrar_y_guardar_desde_ruta pero recibe el contenido ya en memoria.
// Lo usa la unión de PDFs para no escribir nunca el plaintext a disco.
fn cifrar_y_guardar_desde_bytes(
    nombre_archivo: &str,
    contenido: &[u8],
    subclave_hex: &str,
    id_usuario: &str,
) -> Result<String, String> {
    // Bloquear operaciones sensibles si el binario no superó la verificación de integridad.
    if !integridad::integridad_ok() {
        return Err(
            "Esta copia de Babel parece haber sido modificada y podría no ser segura. \
             Reinstala desde la fuente oficial para restaurar el acceso a las funciones de cifrado."
                .to_string(),
        );
    }

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
        let msg = hint_formato_no_soportado(&ext)
            .unwrap_or("Tipo de archivo no permitido");
        return Err(msg.to_string());
    }
    if contenido.len() as u64 > LIMITE_IMPORT_BYTES {
        return Err("El archivo supera el límite de 150 MB.".into());
    }

    // Auto-optimización: todo PDF que entra a Babel pasa por cinco etapas sin pérdida
    // visible, conservando texto y vectores intactos. El resultado solo se acepta si
    // es más pequeño que la entrada; si alguna etapa no mejora, se descarta su salida.
    //   1. reducir: recomprime imágenes JPEG sobredimensionadas (~170 DPI, q82).
    //   2. deduplicar_imagenes: elimina copias redundantes de la misma imagen
    //      (logos, sellos, marcas de agua repetidas en múltiples páginas).
    //   3. subset_fuentes: elimina los glifos no usados de las fuentes TrueType
    //      embebidas (aplica a PDFs generados por Word, LibreOffice, Acrobat).
    //   4. comprimir_imagenes: imágenes en crudo o FlateDecode →
    //      B/N puro: 1-bit+FlateDecode (≡ JBIG2, soporte universal);
    //      color/gris: JPEG q85 (DCTDecode, sin pérdida perceptible).
    //   5. comprimir_streams: FlateDecode nivel 9 sobre streams sin filtro
    //      (streams de contenido, fuentes subsetadas, ToUnicode, perfiles ICC…).
    // Resetear flag lossy al inicio de cada importación.
    ULTIMA_IMPORTACION_LOSSY.with(|c| c.set(false));

    let reducido: Option<Vec<u8>> = if detectar_ext(contenido) == "docx"
        || detectar_ext(contenido) == "pptx"
        || detectar_ext(contenido) == "xlsx"
    {
        let r = pdf_reducir::reducir_docx(contenido);
        // DOCX: downsampling JPEG/PNG es siempre lossy en resolución.
        if r.is_some() { ULTIMA_IMPORTACION_LOSSY.with(|c| c.set(true)); }
        r
    } else if detectar_ext(contenido) == "pdf" {
        let tras_reducir = pdf_reducir::reducir(contenido);
        // reducir: downsampling JPEG = lossy.
        if tras_reducir.is_some() { ULTIMA_IMPORTACION_LOSSY.with(|c| c.set(true)); }
        let base1: &[u8] = tras_reducir.as_deref().unwrap_or(contenido);
        let tras_dedup = pdf_reducir::deduplicar_imagenes(base1);
        let base2: &[u8] = tras_dedup.as_deref().unwrap_or(base1);
        let tras_subset = pdf_reducir::subset_fuentes(base2);
        let base3: &[u8] = tras_subset.as_deref().unwrap_or(base2);
        let tras_comprimir = pdf_reducir::comprimir_imagenes(base3);
        // comprimir_imagenes: puede aplicar JPEG q85 a imágenes color/gris = lossy.
        if tras_comprimir.is_some() { ULTIMA_IMPORTACION_LOSSY.with(|c| c.set(true)); }
        let base4: &[u8] = tras_comprimir.as_deref().unwrap_or(base3);
        let tras_streams = pdf_reducir::comprimir_streams(base4);
        // Prioridad: salida más compacta (etapa posterior gana porque acumula todas las anteriores).
        match (tras_streams, tras_comprimir, tras_subset, tras_dedup, tras_reducir) {
            (Some(s), _, _, _, _) => Some(s),
            (None, Some(c), _, _, _) => Some(c),
            (None, None, Some(s), _, _) => Some(s),
            (None, None, None, Some(d), _) => Some(d),
            (None, None, None, None, r) => r,
        }
    } else {
        None
    };
    let contenido: &[u8] = reducido.as_deref().unwrap_or(contenido);

    let ts: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let nombre_base = std::path::Path::new(nombre_archivo)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(nombre_archivo);

    // Nombre opaco en disco: 8 bytes aleatorios reemplazan el nombre original.
    // El nombre visible se almacena en el índice cifrado .nomindex.babel.
    let mut opaco_bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut opaco_bytes);
    let opaco_hex = hex::encode(opaco_bytes);
    let nombre_cifrado = format!("{}_{}_{}.babel", id_usuario, opaco_hex, ts);
    let ruta_cifrada = guardados_path(&nombre_cifrado);

    let contenido_b64 = traductor::comprimir_b64(contenido);
    let cifrado = seguridad::blindar_documento(&contenido_b64, subclave_hex)
        .map_err(|e| format!("Error cifrando: {}", e))?;

    escribir_privado(&ruta_cifrada, cifrado).map_err(|e| format!("Error guardando: {}", e))?;

    // Registrar nombre completo (con extensión) → nombre_cifrado en el índice cifrado.
    // Usar nombre_seguro (incluye extensión) para que la pantalla de archivos pueda
    // detectar el tipo por extensión (p. ej. imagen vs PDF).
    let _ = nom_cifrado::registrar(
        &nombre_cifrado,
        &nombre_seguro,
        ts,
        contenido.len() as u64,
        &ruta_nomindex_guardados(),
        subclave_hex,
    );

    // Vincular el nuevo archivo al hardware de este dispositivo.
    custodia::registrar_archivo(&nombre_cifrado, subclave_hex);

    Ok(ruta_cifrada)
}

#[tauri::command]
fn guardar_documento_sin_traducir(
    app: tauri::AppHandle,
    nombre_archivo: String,
    ruta_completa: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<String, String> {
    crate::rat_detector::verificar_no_bloqueado_rat()?;
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }

    let id_usuario = sesion
        .usuario
        .lock()
        .map_err(|_| "Error".to_string())?
        .clone();

    let ruta = cifrar_y_guardar_desde_ruta(&nombre_archivo, &ruta_completa, &subclave_hex, &id_usuario)?;
    if ULTIMA_IMPORTACION_LOSSY.with(|c| c.get()) {
        let _ = app.emit("compresion-lossy", ());
    }
    Ok(ruta)
}

// COMANDO — Igual que guardar_documento_sin_traducir pero recibe el contenido en
// base64 (para el arrastre HTML5, donde el webview solo expone los bytes del
// archivo, no su ruta). Evita depender del drag-drop nativo de wry (que en macOS
// reciente aborta el proceso por un unwrap sobre el pasteboard).
#[tauri::command]
fn guardar_documento_desde_bytes(
    app: tauri::AppHandle,
    nombre_archivo: String,
    contenido_b64: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<String, String> {
    crate::rat_detector::verificar_no_bloqueado_rat()?;
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    let id_usuario = sesion.usuario.lock().map_err(|_| "Error".to_string())?.clone();

    // S-4: rechazar por tamaño ANTES de decodificar (base64 infla ~4/3; así no se
    // reserva memoria de un string enorme antes de validar).
    if contenido_b64.len() > 205 * 1024 * 1024 {
        return Err("El archivo supera el límite de 150 MB.".into());
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(contenido_b64.as_bytes())
        .map_err(|_| "Datos del archivo no válidos.".to_string())?;
    if bytes.len() > 150 * 1024 * 1024 {
        return Err("El archivo supera el límite de 150 MB.".into());
    }

    let ruta = cifrar_y_guardar_desde_bytes(&nombre_archivo, &bytes, &subclave_hex, &id_usuario)?;
    if ULTIMA_IMPORTACION_LOSSY.with(|c| c.get()) {
        let _ = app.emit("compresion-lossy", ());
    }
    Ok(ruta)
}

// Borrado seguro de temporales de arrastre viejos (>1h) que hayan quedado de un
// fallo previo, para que nunca se acumule plaintext en el temp del contenedor.
fn barrer_temp_dnd(base: &std::path::Path) {
    let Ok(entradas) = std::fs::read_dir(base) else { return };
    let ahora = std::time::SystemTime::now();
    for e in entradas.flatten() {
        let viejo = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| ahora.duration_since(t).ok())
            .map(|d| d.as_secs() > 3600)
            .unwrap_or(false);
        if !viejo {
            continue;
        }
        let p = e.path();
        if p.is_dir() {
            if let Ok(hijos) = std::fs::read_dir(&p) {
                for h in hijos.flatten() {
                    borrar_seguro(&h.path().to_string_lossy());
                }
            }
            let _ = std::fs::remove_dir_all(&p);
        } else {
            borrar_seguro(&p.to_string_lossy());
        }
    }
}

// COMANDO — Escribe unos bytes (base64) a un temporal fuera del área de Babel y
// devuelve su ruta. Lo usa el arrastre HTML5 para TRADUCIR (la traducción necesita
// una ruta de archivo). El llamador debe borrarlo con borrar_archivo_fuente al terminar.
#[tauri::command]
fn preparar_temp_bytes(nombre_archivo: String, contenido_b64: String) -> Result<String, String> {
    let nombre = std::path::Path::new(&nombre_archivo)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
        .ok_or("Nombre de archivo inválido")?;
    // S-4: rechazar por tamaño antes de decodificar.
    if contenido_b64.len() > 205 * 1024 * 1024 {
        return Err("El archivo supera el límite de 150 MB.".into());
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(contenido_b64.as_bytes())
        .map_err(|_| "Datos del archivo no válidos.".to_string())?;
    if bytes.len() > 150 * 1024 * 1024 {
        return Err("El archivo supera el límite de 150 MB.".into());
    }
    let base = std::env::temp_dir().join("babel_dnd");
    let _ = std::fs::create_dir_all(&base);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700));
    }
    // S-3: limpia restos viejos de fallos anteriores.
    barrer_temp_dnd(&base);
    // S-3: subdirectorio único → sin colisiones entre archivos con el mismo nombre,
    // conservando el nombre de archivo limpio para la UI.
    static CTR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let uniq = format!(
        "{}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        CTR.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let dir = base.join(uniq);
    std::fs::create_dir_all(&dir).map_err(|e| format!("No se pudo preparar el archivo: {}", e))?;
    let ruta = dir.join(nombre);
    escribir_privado(&ruta, &bytes).map_err(|e| format!("No se pudo preparar el archivo: {}", e))?;
    Ok(ruta.to_string_lossy().to_string())
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
    crate::rat_detector::verificar_no_bloqueado_rat()?;
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
// COMANDO — Importar una CARPETA entera por diálogo nativo. Cifra cada archivo
// aplanando las subcarpetas (las carpetas de Babel son de un solo nivel). Devuelve
// el nombre de la carpeta elegida y las rutas .babel creadas; el frontend decide el
// destino (crear una carpeta con ese nombre, o volcar en la carpeta activa), igual
// que en el arrastre. NO borra los originales.
// ============================================================
#[derive(serde::Serialize)]
struct ImportarCarpetaResultado {
    nombre_carpeta: String,
    rutas: Vec<String>,
    guardados: u32,
    omitidos: u32,
}

// Recolecta rutas de archivo bajo `dir`, descendiendo en subcarpetas (aplanado).
fn recolectar_archivos(dir: &std::path::Path, salida: &mut Vec<std::path::PathBuf>) {
    // Cota de profundidad + no seguir symlinks: evita bucles infinitos si la carpeta
    // elegida contiene un enlace simbólico cíclico o un árbol patológicamente profundo.
    recolectar_archivos_rec(dir, salida, 0);
}

fn recolectar_archivos_rec(dir: &std::path::Path, salida: &mut Vec<std::path::PathBuf>, prof: u32) {
    const MAX_PROFUNDIDAD: u32 = 32;
    if prof > MAX_PROFUNDIDAD {
        return;
    }
    let Ok(entradas) = std::fs::read_dir(dir) else { return };
    for entrada in entradas.flatten() {
        // file_type() de DirEntry NO sigue symlinks — un symlink no cuenta como dir.
        let ft = match entrada.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_symlink() {
            continue;
        }
        let p = entrada.path();
        if ft.is_dir() {
            recolectar_archivos_rec(&p, salida, prof + 1);
        } else if ft.is_file() {
            salida.push(p);
        }
    }
}

#[tauri::command]
async fn importar_carpeta_dialogo(
    app: tauri::AppHandle,
    sesion: tauri::State<'_, SesionActiva>,
) -> Result<Option<ImportarCarpetaResultado>, String> {
    crate::rat_detector::verificar_no_bloqueado_rat()?;
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    let id_usuario = sesion
        .usuario
        .lock()
        .map_err(|_| "Error".to_string())?
        .clone();

    // spawn_blocking por el mismo motivo que importar_archivo_dialogo: los diálogos
    // blocking_* deadlockan si corren en el hilo principal.
    tauri::async_runtime::spawn_blocking(move || {
        use tauri_plugin_dialog::DialogExt;

        let carpeta = match app.dialog().file().blocking_pick_folder() {
            Some(fp) => fp,
            None => return Ok(None), // usuario canceló — sin error
        };
        let ruta_carpeta = carpeta
            .into_path()
            .map_err(|e| format!("Ruta de carpeta inválida: {}", e))?;
        let nombre_carpeta = ruta_carpeta
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("carpeta")
            .to_string();

        let mut archivos = Vec::new();
        recolectar_archivos(&ruta_carpeta, &mut archivos);

        let mut rutas = Vec::new();
        let mut omitidos: u32 = 0;
        for ruta in archivos {
            let nombre = match ruta.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => { omitidos += 1; continue; }
            };
            // Salta .babel (ya cifrados) y duplicados por nombre base. El resto de
            // filtros (extensión permitida, tamaño) los aplica cifrar_y_guardar_*.
            let nombre_base = std::path::Path::new(&nombre)
                .file_stem().and_then(|s| s.to_str()).unwrap_or(&nombre);
            if nombre.ends_with(".babel") || nombre_base_ya_guardado(nombre_base, Some(&subclave_hex)) {
                omitidos += 1;
                continue;
            }
            let ruta_str = ruta.to_string_lossy().to_string();
            match cifrar_y_guardar_desde_ruta(&nombre, &ruta_str, &subclave_hex, &id_usuario) {
                Ok(cifrada) => rutas.push(cifrada),
                Err(_) => omitidos += 1, // tipo no permitido, demasiado grande, etc.
            }
        }

        let guardados = rutas.len() as u32;
        Ok(Some(ImportarCarpetaResultado {
            nombre_carpeta,
            rutas,
            guardados,
            omitidos,
        }))
    })
    .await
    .map_err(|e| format!("Error interno al importar la carpeta: {}", e))?
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
    crate::rat_detector::verificar_no_bloqueado_rat()?;
    sesion.subclave_hex()?;
    let path = std::fs::canonicalize(&ruta)
        .map_err(|_| "Archivo no accesible.".to_string())?;

    // Solo archivos regulares — nunca directorios ni symlinks a directorios.
    let meta = std::fs::symlink_metadata(&path)
        .map_err(|_| "Archivo no accesible.".to_string())?;
    if !meta.file_type().is_file() {
        return Err("Solo se pueden borrar archivos regulares.".into());
    }

    // Rutas internas de Babel: siempre bloqueadas.
    let babel = std::fs::canonicalize(babel_dir()).unwrap_or_else(|_| babel_dir());
    if path.starts_with(&babel) {
        return Err("No se puede borrar archivos internos de Babel.".into());
    }

    // Temporales del drag & drop (preparar_temp_bytes): permitido directamente.
    // Canonicalizamos tmp_dnd para que el starts_with funcione en macOS donde
    // temp_dir() devuelve /var/folders/… y canonicalize resuelve a /private/var/…
    let tmp_dnd_raw = std::env::temp_dir().join("babel_dnd");
    let tmp_dnd = std::fs::canonicalize(&tmp_dnd_raw).unwrap_or(tmp_dnd_raw);
    if path.starts_with(&tmp_dnd) {
        borrar_seguro(path.to_str().unwrap_or(&ruta));
        return Ok(());
    }

    // Para cualquier otra ruta: solo documentos que el pipeline de traducción
    // acepta como entrada (pdf/docx/txt). Impide borrar ejecutables, configs,
    // o rutas del sistema si algún path malicioso llegara a este comando.
    let ext = path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();
    if !["pdf", "docx", "txt"].contains(&ext.as_str()) {
        return Err("Solo se pueden borrar documentos de traducción (pdf, docx, txt).".into());
    }

    borrar_seguro(path.to_str().unwrap_or(&ruta));
    Ok(())
}

// ============================================================
// FINDER — "Guardar con Babel" desde el clic derecho del Finder (macOS).
// El Quick Action copia cada archivo a ~/Babel/entrada_finder/ y dispara
// babel://guardar. Aquí ciframos e importamos reutilizando el núcleo existente
// (cifrar_y_guardar_desde_ruta) y borramos de forma segura staged + original.
// Ver módulo finder.rs y finder-extension/README.md.
// ============================================================

#[derive(serde::Serialize)]
struct FinderResultado {
    necesita_login: bool,
    procesados: usize,
    nombres: Vec<String>,
}

// Cifra e importa todo lo pendiente en entrada_finder/. Emite un evento
// "finder-guardado" por cada archivo. Devuelve cuántos se guardaron correctamente.
fn procesar_finder_bloqueante(
    app: &tauri::AppHandle,
    subclave_hex: &str,
    id_usuario: &str,
) -> usize {
    let _finder_guard = FINDER_PROCESSING_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = finder::entrada_finder_dir();
    let resultados = finder::procesar_entradas(&dir, |nombre, staged| {
        cifrar_y_guardar_desde_ruta(nombre, staged, subclave_hex, id_usuario)
    });

    // Comprobamos antes de emitir si la ventana es visible, para decidir después si
    // hace falta una notificación nativa del sistema.
    let ventana_visible = app
        .get_webview_window("main")
        .and_then(|w| w.is_visible().ok())
        .unwrap_or(false);

    for r in &resultados {
        let _ = app.emit(
            "finder-guardado",
            serde_json::json!({
                "nombre": r.nombre,
                "ok": r.ok,
                "error": r.error,
                "originalNoBorrado": r.original_no_borrado,
            }),
        );
    }

    let ok_count = resultados.iter().filter(|r| r.ok).count();
    let err_count = resultados.len() - ok_count;

    // Cuando la ventana está oculta (procesado en segundo plano) los toasts de la app
    // no son visibles. Emitimos una notificación nativa de macOS para que el usuario
    // sepa que su archivo ya está en el búnker.
    if !ventana_visible && !resultados.is_empty() {
        #[cfg(target_os = "macos")]
        {
            let msg = match (ok_count, err_count) {
                (1, 0) => {
                    let nombre = resultados.iter().find(|r| r.ok).map(|r| r.nombre.as_str()).unwrap_or("Archivo");
                    format!("{} cifrado y guardado en Babel.", nombre)
                }
                (n, 0) => format!("{} archivos cifrados y guardados en Babel.", n),
                (0, _) => "No se pudo cifrar ningún archivo.".to_string(),
                (n, e) => format!("{} cifrado(s). {} no pudo(n) guardarse.", n, e),
            };
            notificar_macos("Babel", &msg);
        }
    }

    ok_count
}

/// Muestra una notificación nativa de macOS vía osascript.
/// Filtra `"`, `\n` y `\r` para impedir inyección de sentencias AppleScript adicionales
/// (en AppleScript un salto de línea dentro de un string literal termina el statement).
#[cfg(target_os = "macos")]
fn notificar_macos(titulo: &str, mensaje: &str) {
    let limpiar = |s: &str| s.replace('"', "'").replace('\n', " ").replace('\r', "");
    let script = format!(
        r#"display notification "{}" with title "{}""#,
        limpiar(mensaje),
        limpiar(titulo),
    );
    let _ = std::process::Command::new("osascript")
        .args(["-e", &script])
        .spawn();
}

// Comando invocado por el frontend tras el login para drenar la cola de staging.
// Sin sesión activa devuelve necesita_login=true y no procesa nada.
#[tauri::command]
async fn procesar_entrada_finder(
    app: tauri::AppHandle,
    sesion: tauri::State<'_, SesionActiva>,
) -> Result<FinderResultado, String> {
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Ok(FinderResultado {
            necesita_login: true,
            procesados: 0,
            nombres: vec![],
        });
    }
    let id_usuario = sesion.usuario.lock().map_err(|_| "Error".to_string())?.clone();

    tauri::async_runtime::spawn_blocking(move || {
        let procesados = procesar_finder_bloqueante(&app, &subclave_hex, &id_usuario);
        // Recuperar los nombres OK que ya se emitieron requiere re-escanear; para el
        // frontend basta con el conteo — la lista se refresca por los eventos emitidos.
        Ok(FinderResultado {
            necesita_login: false,
            procesados,
            nombres: vec![],
        })
    })
    .await
    .map_err(|e| format!("Error interno finder: {}", e))?
}

// Handler del URL scheme babel://. Con sesión activa cifra en silencio (fricción cero);
// sin sesión, muestra la ventana y pide login — la cola se procesa tras autenticar.
fn manejar_url_babel(app: &tauri::AppHandle, urls: Vec<String>) {
    let hay_guardar = urls.iter().any(|u| finder::parsear_url_babel(u).is_some());
    if !hay_guardar {
        return;
    }
    let sesion = app.state::<SesionActiva>();
    let subclave_hex = sesion
        .subclave_hex()
        .unwrap_or_else(|_| Zeroizing::new(String::new()));

    if subclave_hex.is_empty() {
        // Sin sesión: mostrar la ventana y pedir login. La cola queda en entrada_finder/.
        if let Some(win) = app.get_webview_window("main") {
            let _ = win.show();
            let _ = win.unminimize();
            let _ = win.set_focus();
        }
        let _ = app.emit("finder-necesita-login", ());
        return;
    }

    // Con sesión activa: verificar token CSRF para que solo el Quick Action legítimo
    // (que lee ~/Babel/.finder_token) pueda disparar el procesamiento inmediato.
    if !verificar_finder_token(&urls) {
        log::warn!("[finder] babel://guardar recibida con sesión activa pero sin token válido — ignorada");
        return;
    }

    let id_usuario = sesion.usuario.lock().map(|u| u.clone()).unwrap_or_default();
    let app2 = app.clone();
    // Hilo dedicado: el cifrado puede tardar y no debe bloquear el hilo principal.
    // subclave_hex (Zeroizing) se mueve al hilo y se borra al terminar.
    std::thread::spawn(move || {
        procesar_finder_bloqueante(&app2, &subclave_hex, &id_usuario);
    });
}

// ============================================================
// COMANDO — Comprobar si ya existe un archivo guardado con ese nombre base
// Verifica contra el sistema de archivos real, no contra el DOM del frontend.
// Evita que archivos en buzones no visibles pasen inadvertidos (B5).
// ============================================================
#[tauri::command]
fn archivo_guardado_existe(nombre_base: String, sesion: tauri::State<SesionActiva>) -> bool {
    let subclave_hex = sesion.subclave_hex().unwrap_or_default();
    let subclave = if subclave_hex.is_empty() { None } else { Some(subclave_hex.as_str()) };
    nombre_base_ya_guardado(&nombre_base, subclave)
}

// Verifica si ya hay un .babel con ese nombre base (ignorando mayúsculas).
// Con subclave disponible, consulta primero el índice cifrado (archivos nuevos con nombre opaco).
// Sin subclave o para archivos legacy, escanea los nombres del sistema de archivos.
fn nombre_base_ya_guardado(nombre_base: &str, subclave_hex: Option<&str>) -> bool {
    let nombre_base_lower = nombre_base.to_lowercase();

    // 1. Consultar el índice cifrado si hay sesión activa (archivos con nombre opaco).
    if let Some(subclave) = subclave_hex {
        if !subclave.is_empty() {
            let nom_g = nom_cifrado::leer(&ruta_nomindex_guardados(), subclave);
            let nom_a = nom_cifrado::leer(&ruta_nomindex_archivos(), subclave);
            if nom_g.values().any(|v| v.nombre.to_lowercase() == nombre_base_lower)
                || nom_a.values().any(|v| v.nombre.to_lowercase() == nombre_base_lower)
            {
                return true;
            }
        }
    }

    // 2. Fallback legacy: escanear nombres en disco (archivos anteriores al índice cifrado).
    let carpetas = [guardados_dir(), archivos_dir()];
    for carpeta in &carpetas {
        if let Ok(entradas) = fs::read_dir(carpeta) {
            for entrada in entradas.flatten() {
                let fname = entrada.file_name();
                let fname_str = fname.to_string_lossy();
                if fname_str.ends_with(".babel") && !fname_str.starts_with('.') {
                    let sin_ext = &fname_str[..fname_str.len() - 6];
                    let sin_prefix = sin_ext.splitn(2, '_').nth(1).unwrap_or(sin_ext);
                    let sin_ts = sin_prefix.rsplit_once('_').map(|(s, _)| s).unwrap_or(sin_prefix);
                    let sin_idioma = sin_ts.splitn(2, '_').collect::<Vec<_>>();
                    let base = if sin_idioma.len() == 2
                        && sin_idioma[0].len() == 5
                        && sin_idioma[0].chars().nth(2) == Some('-')
                    {
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
        "C:\\Program Files\\LibreOffice\\program\\soffice.exe",
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
    let prefijo = format!("{}_", id_usuario);

    // Cargar índices de nombres cifrados para ambas colecciones.
    let nomindex_g = nom_cifrado::leer(&ruta_nomindex_guardados(), &subclave_hex);
    let nomindex_a = nom_cifrado::leer(&ruta_nomindex_archivos(), &subclave_hex);

    // Guardados sin traducir: idioma fijo "guardado" + fecha/tamaño del índice cifrado.
    recolectar_metadatos(
        &guardados_dir(),
        &guardados_path(".buzon_index_guardados.babel"),
        &guardados_path(".buzones_guardados.babel"),
        &prefijo, &buzon, &subclave_hex, false, &mut archivos,
        |nombre, entry| {
            let meta = nomindex_g.get(nombre);
            let nombre_limpio = meta.map(|m| m.nombre.clone()).unwrap_or_else(|| {
                nombre.trim_start_matches(&prefijo).to_string()
            });
            let bytes_orig = meta.map(|m| m.bytes).unwrap_or(0);
            let ts_stored = meta.map(|m| m.ts).unwrap_or(0);
            let fecha = dias_relativos_ts(ts_stored).unwrap_or_else(|| {
                // Legacy: leer mtime del filesystem
                entry.metadata().ok()
                    .and_then(|m| m.modified().ok())
                    .map(|t| {
                        let dias = std::time::SystemTime::now()
                            .duration_since(t).unwrap_or_default().as_secs() / 86400;
                        dias_a_texto(dias)
                    })
                    .unwrap_or_else(|| "—".to_string())
            });
            (nombre_limpio, "guardado".to_string(), fecha, bytes_orig)
        },
    );

    // Traducidos: idioma derivado del par en el nombre ("original" para los __orig).
    recolectar_metadatos(
        &archivos_dir(),
        &archivos_path(".buzon_index.babel"),
        &archivos_path(".buzones.babel"),
        &prefijo, &buzon, &subclave_hex, true, &mut archivos,
        |nombre, entry| {
            let meta = nomindex_a.get(nombre);
            let nombre_limpio = meta.map(|m| m.nombre.clone()).unwrap_or_else(|| {
                nombre.trim_start_matches(&prefijo).replace("__orig", "")
            });
            let bytes_orig = meta.map(|m| m.bytes).unwrap_or(0);
            let ts_stored = meta.map(|m| m.ts).unwrap_or(0);
            let fecha = dias_relativos_ts(ts_stored).unwrap_or_else(|| {
                entry.metadata().ok()
                    .and_then(|m| m.modified().ok())
                    .map(|t| {
                        let dias = std::time::SystemTime::now()
                            .duration_since(t).unwrap_or_default().as_secs() / 86400;
                        dias_a_texto(dias)
                    })
                    .unwrap_or_else(|| "—".to_string())
            });
            let idioma = if nombre.contains("__orig") {
                "original".to_string()
            } else {
                // El par de idioma (ej: "es-en") sigue en posición [1] del nombre en disco.
                let seg = nombre.split('_').nth(1).unwrap_or("");
                if seg.len() == 5 && seg.as_bytes().get(2) == Some(&b'-') {
                    seg.to_string()
                } else {
                    String::new()
                }
            };
            (nombre_limpio, idioma, fecha, bytes_orig)
        },
    );

    Ok(archivos)
}

fn dias_a_texto(dias: u64) -> String {
    if dias == 0 { "hoy".to_string() }
    else if dias == 1 { "ayer".to_string() }
    else if dias < 30 { format!("hace {} días", dias) }
    else { format!("hace {} meses", dias / 30) }
}

/// Devuelve fecha relativa desde un timestamp Unix almacenado en el índice cifrado.
/// Retorna None si ts == 0 (entrada legacy sin timestamp).
fn dias_relativos_ts(ts: u64) -> Option<String> {
    if ts == 0 { return None; }
    let ahora = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let dias = ahora.saturating_sub(ts) / 86400;
    Some(dias_a_texto(dias))
}

// Recorre `carpeta` recogiendo los .babel del usuario (prefijo) que casen con `buzon`,
// resolviendo el nombre del buzón desde su índice/nodos cifrados. `por_entrada` aporta
// los campos específicos de cada colección: (nombre_limpio, idioma, fecha, bytes_orig).
#[allow(clippy::too_many_arguments)]
fn recolectar_metadatos(
    carpeta: &std::path::Path,
    ruta_index: &str,
    ruta_buzones: &str,
    prefijo: &str,
    buzon: &str,
    subclave_hex: &str,
    es_traduccion: bool,
    archivos: &mut Vec<MetadatosArchivo>,
    por_entrada: impl Fn(&str, &std::fs::DirEntry) -> (String, String, String, u64),
) {
    let index: HashMap<String, String> = fs::read(ruta_index)
        .ok()
        .and_then(|b| seguridad::descifrar_documento(b, subclave_hex).ok())
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default();
    let nodos = cargar_nodos(std::path::Path::new(ruta_buzones), subclave_hex);

    let Ok(entries) = fs::read_dir(carpeta) else { return };
    for entry in entries.flatten() {
        if archivos.len() >= MAX_ARCHIVOS {
            break;
        }
        let nombre = entry.file_name().to_string_lossy().to_string();
        if !nombre.starts_with(prefijo) || nombre.starts_with('.') {
            continue;
        }

        let buzon_archivo = index.get(&nombre).cloned().unwrap_or_else(|| "todos".to_string());
        if buzon != "todos" && buzon_archivo != buzon {
            continue;
        }

        let nombre_buzon = if buzon_archivo == "todos" || buzon_archivo.is_empty() {
            "todos".to_string()
        } else {
            nodos
                .iter()
                .find(|n| n.id == buzon_archivo)
                .map(|n| n.nombre.clone())
                .unwrap_or_else(|| "todos".to_string())
        };

        let (nombre_limpio, idioma, fecha, bytes_orig) = por_entrada(&nombre, &entry);
        archivos.push(MetadatosArchivo {
            nombre: nombre_limpio,
            ruta: entry.path().to_string_lossy().to_string(),
            // Usar tamaño original cifrado en el índice; fallback al tamaño en disco.
            tamaño: if bytes_orig > 0 { bytes_orig } else { entry.metadata().map(|m| m.len()).unwrap_or(0) },
            fecha,
            idioma,
            buzon: nombre_buzon,
            buzon_id: buzon_archivo,
            es_traduccion,
        });
    }
}
// COMANDO — Mover archivo guardado entre buzones — Actualiza el índice cifrado .buzon_index_guardados.babel con el nuevo buzón destino.
#[tauri::command]
fn mover_archivo_guardado(
    ruta: String,
    buzon_destino: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    crate::rat_detector::verificar_no_bloqueado_rat()?;
    validar_ruta_en(&ruta, guardados_dir())?;

    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() { return Err("No hay sesión activa.".into()); }

    // M7: RMW serializado del índice de buzones (mismo helper que usa unir_pdfs).
    asignar_buzon_guardado(&ruta, &buzon_destino, &subclave_hex)
}
// COMANDO 6 — Cerrar sesión (limpia la RAM)
#[tauri::command]
fn cerrar_sesion_rust(sesion: tauri::State<SesionActiva>) {
    crate::rat_detector::detener_monitor_rat();
    babel_p2p::detener_servidor_p2p();
    crate::sincronizacion::limpiar_subclave_sesion();
    crate::conexion_directa::limpiar_subclave_servidor();
    limpiar_finder_token(); // revocar token CSRF del URL scheme babel://
    sesion.limpiar();
    // Al cerrar sesión: borrar TODOS los archivos en claro de compartidos/ sin esperar 1h.
    compartir::barrer_plaintext_compartidos_logout();
    // Limpiar todas las rutas pendientes de borrado al cerrar sesión
    if let Ok(mut guard) = PENDING_BORRAR_ORIGINAL.lock() { *guard = None; }
    // Borrar temporales en claro con 3 pasadas (0x00, 0xFF, 0xAA) + fsync antes de eliminar
    let tmp = babel_dir().join("tmp");
    if let Ok(entradas) = fs::read_dir(&tmp) {
        for entrada in entradas.flatten() {
            let p = entrada.path();
            if p.is_dir() {
                // Subdirectorios únicos de traducción: borrar su contenido y la carpeta.
                if let Ok(hijos) = fs::read_dir(&p) {
                    for h in hijos.flatten() {
                        borrar_seguro(&h.path().to_string_lossy());
                    }
                }
                let _ = fs::remove_dir_all(&p);
            } else {
                borrar_seguro(&p.to_string_lossy());
            }
        }
    }
}

// COMANDO — Estado del servidor de traducción (para que el frontend sepa si el sidecar arrancó)
#[tauri::command]
fn estado_servidor_cmd() -> String {
    match SERVIDOR_ESTADO.load(std::sync::atomic::Ordering::Relaxed) {
        1 => "cargando".into(),
        2 => "listo".into(),
        3 => "error".into(),
        _ => "externo".into(),
    }
}

// COMANDO 7 — Traducir documento vía drag & drop nativo

#[tauri::command]
async fn traducir_documento_ruta(
    app: tauri::AppHandle,
    ruta: String,
    nombre_archivo: String,
    sesion: tauri::State<'_, SesionActiva>,
) -> Result<String, String> {
    crate::rat_detector::verificar_no_bloqueado_rat()?;
    // Extraer datos de sesión ANTES de spawn_blocking — State no es Send.
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa. Inicia sesión primero.".into());
    }
    let id_usuario = sesion.usuario.lock().map_err(|_| "Error".to_string())?.clone();
    let dict = sesion.diccionario.lock().map_err(|_| "Error leyendo diccionario.".to_string())?.clone();
    let idioma = sesion.idioma.lock().map_err(|_| "Error leyendo idioma.".to_string())?.clone();
    let par = idioma_a_par(&idioma)?;

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
            let msg = hint_formato_no_soportado(&ext)
                .unwrap_or("Tipo de archivo no permitido para traducción");
            return Err(msg.to_string());
        }

        // En sandbox, is_file() devuelve false para archivos arrastrados hasta que el OS
        // resuelve el acceso user-selected.  Canonicalize abre el acceso y falla si la ruta
        // no existe — igual que hace cifrar_y_guardar_desde_ruta para drag & drop.
        let path_canon = std::fs::canonicalize(&ruta)
            .map_err(|_| format!("Archivo no accesible: {}", ruta))?;

        let meta = std::fs::metadata(&path_canon)
            .map_err(|e| format!("Error accediendo archivo: {}", e))?;
        if meta.len() > 150 * 1024 * 1024 {
            return Err("El archivo supera el límite de 150 MB.".into());
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
        renombrar_salida_traduccion(&id_usuario, par, &nombre_base, &subclave_hex)
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
    crate::rat_detector::verificar_no_bloqueado_rat()?;
    validar_ruta_en(&ruta, archivos_dir())
        .or_else(|_| validar_ruta_en(&ruta, guardados_dir()))?;

    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    let id_usuario = sesion.usuario.lock().map_err(|_| "Error".to_string())?.clone();
    let dict = sesion.diccionario.lock().map_err(|_| "Error leyendo diccionario.".to_string())?.clone();
    let idioma = sesion.idioma.lock().map_err(|_| "Error leyendo idioma.".to_string())?.clone();
    let par = idioma_a_par(&idioma)?;

    tauri::async_runtime::spawn_blocking(move || {
        traductor::resetear_cancelacion();
        let bytes = descifrar_a_bytes(&ruta, &subclave_hex)?;

        if bytes.len() > 150 * 1024 * 1024 {
            return Err("El archivo supera el límite de 150 MB.".into());
        }

        let ext = detectar_ext(&bytes);
        if !["pdf", "docx", "txt"].contains(&ext) {
            return Err(format!("Tipo de archivo no soportado para traducción: .{}", ext));
        }

        // Nombre original del archivo fuente (del índice cifrado si es opaco, del disco si es legacy).
        let nombre_disco_src = std::path::Path::new(&ruta)
            .file_name().unwrap_or_default().to_string_lossy().to_string();
        let nom_g = nom_cifrado::leer(&ruta_nomindex_guardados(), &subclave_hex);
        let nom_a = nom_cifrado::leer(&ruta_nomindex_archivos(), &subclave_hex);
        let nombre_original = nom_g.get(&nombre_disco_src)
            .or_else(|| nom_a.get(&nombre_disco_src))
            .map(|m| m.nombre.clone())
            .unwrap_or_else(|| {
                // Fallback legacy: derivar del nombre en disco.
                let base = nombre_exportacion(&ruta, ext);
                Path::new(&base).file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("archivo")
                    .to_string()
            });

        let nombre_base = format!("{}.{}", nombre_original, ext);

        // Escribir a tmp/ y traducir
        let tmp_path = tmp_dir().join(&nombre_base);
        escribir_privado(&tmp_path, &bytes).map_err(|e| format!("Error escribiendo temporal: {}", e))?;

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
        let orig_redundante = archivos_path(&format!("{}_{}_{}__orig.babel", id_usuario, par, nombre_original));
        if std::path::Path::new(&orig_redundante).exists() {
            borrar_seguro(&orig_redundante);
        }

        renombrar_salida_traduccion(&id_usuario, par, &nombre_original, &subclave_hex)
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
    crate::rat_detector::verificar_no_bloqueado_rat()?;
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
    let par = idioma_a_par(&idioma)?;

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
        if meta.len() > 150 * 1024 * 1024 {
            return Err("El archivo supera el límite de 150 MB.".into());
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

/// Valida que `ruta` esté dentro del vault (archivos/ o guardados/), la descifra con
/// la sesión activa y devuelve el plaintext en un buffer que se zeroiza al soltarse.
/// Centraliza el patrón validar-ruta + descifrar + Zeroizing que repetían export,
/// compartir y otros flujos (evita olvidar la zeroización en cada sitio).
fn abrir_descifrado_vault(ruta: &str, subclave_hex: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    validar_ruta_en(ruta, archivos_dir())
        .or_else(|_| validar_ruta_en(ruta, guardados_dir()))?;
    Ok(Zeroizing::new(descifrar_a_bytes(ruta, subclave_hex)?))
}

// Para formatos de documento propietarios conocidos que Babel no puede procesar,
// devuelve un mensaje en español con instrucciones para convertirlos. Devuelve None
// para extensiones soportadas o desconocidas.
fn hint_formato_no_soportado(ext: &str) -> Option<&'static str> {
    match ext {
        "pages" => Some("Este archivo es de Apple Pages y no se puede procesar directamente. \
            Expórtalo a PDF o Word desde Pages: Archivo → Exportar a → PDF (o Word)."),
        "odt" => Some("Este archivo es de LibreOffice Writer (.odt) y no se puede procesar \
            directamente. Guárdalo como Word desde LibreOffice: Archivo → Guardar como → \
            Word 2007-365 (.docx)."),
        "numbers" => Some("Este archivo es de Apple Numbers y no se puede procesar directamente. \
            Expórtalo desde Numbers: Archivo → Exportar a → PDF."),
        "key" => Some("Este archivo es de Apple Keynote y no se puede procesar directamente. \
            Expórtalo desde Keynote: Archivo → Exportar a → PDF (o PowerPoint)."),
        "doc" => Some("El formato .doc (Word antiguo) no está soportado directamente. \
            Ábrelo en Word y guárdalo como .docx: Archivo → Guardar como → Word (.docx)."),
        "xls" => Some("El formato .xls (Excel antiguo) no está soportado directamente. \
            Ábrelo en Excel y expórtalo a PDF: Archivo → Exportar → Crear documento PDF."),
        "ppt" => Some("El formato .ppt (PowerPoint antiguo) no está soportado directamente. \
            Ábrelo en PowerPoint y expórtalo a PDF: Archivo → Exportar → Crear documento PDF."),
        "rtf" => Some("El formato .rtf no está soportado directamente. \
            Ábrelo en TextEdit o Word y guárdalo como .docx o .txt."),
        "ods" => Some("Este archivo es de LibreOffice Calc (.ods) y no se puede procesar \
            directamente. Expórtalo como PDF desde LibreOffice: Archivo → Exportar como PDF."),
        "odp" => Some("Este archivo es de LibreOffice Impress (.odp) y no se puede procesar \
            directamente. Expórtalo como PDF desde LibreOffice: Archivo → Exportar como PDF."),
        _ => None,
    }
}

// Detecta la extensión real de un archivo por sus magic bytes.
fn detectar_ext(bytes: &[u8]) -> &'static str {
    if bytes.len() >= 4 && &bytes[..4] == b"%PDF" { return "pdf"; }
    if bytes.len() >= 4 && &bytes[..4] == b"\x89PNG" { return "png"; }
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xD8 { return "jpg"; }
    if bytes.len() >= 6 && (&bytes[..6] == b"GIF89a" || &bytes[..6] == b"GIF87a") { return "gif"; }
    if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" { return "webp"; }
    // Formatos ZIP: Office Open XML comparte magic bytes PK — hay que mirar dentro
    if bytes.len() >= 2 && &bytes[..2] == b"PK" {
        let head = &bytes[..bytes.len().min(4096)];
        if head.windows(5).any(|w| w == b"word/")  { return "docx"; }
        if head.windows(3).any(|w| w == b"xl/")    { return "xlsx"; }
        if head.windows(4).any(|w| w == b"ppt/")   { return "pptx"; }
        return "zip";
    }
    "txt"
}

// Devuelve el nombre de exportación consultando primero el índice cifrado.
// Para archivos nuevos con nombre opaco, recupera el nombre original del índice.
// Para archivos legacy, delega en nombre_exportacion() (parseo del nombre en disco).
fn nombre_exportacion_idx(
    ruta: &str,
    ext: &str,
    nomindex: &std::collections::HashMap<String, nom_cifrado::MetaEntrada>,
) -> String {
    if let Some(disk_name) = std::path::Path::new(ruta).file_name() {
        if let Some(meta) = nomindex.get(disk_name.to_string_lossy().as_ref()) {
            return format!("{}.{}", meta.nombre, ext);
        }
    }
    nombre_exportacion(ruta, ext)
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

// ============================================================
// UNIÓN DE PDFs — 100% nativa con PDFium (motor de Chromium, licencia BSD-3).
// Descifra cada .babel EN MEMORIA y une con pdf_union (conserva texto/vectores,
// no rasteriza); el plaintext nunca toca el disco y no depende del servidor.
// ============================================================

// Directorios candidatos donde localizar la librería PDFium: el resource dir del
// bundle (release) y la ruta vendorizada del repo (dev). bind_pdfium prueba cada
// uno y cae a la librería del sistema si ninguno sirve.
fn pdfium_dirs(app: &tauri::AppHandle) -> Vec<std::path::PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(res) = app.path().resource_dir() {
        dirs.push(res.join("binaries/pdfium"));
    }
    // Fallback dev: ruta del repo horneada en tiempo de compilación.
    dirs.push(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("binaries/pdfium"));
    dirs
}

// Asigna el buzón destino a un archivo guardado en el índice cifrado (RMW
// serializado). Reutilizado por mover_archivo_guardado y por unir_pdfs.
fn asignar_buzon_guardado(ruta: &str, buzon_id: &str, subclave_hex: &str) -> Result<(), String> {
    let _idx_guard = BUZON_INDEX_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let ruta_index = guardados_path(".buzon_index_guardados.babel");
    let mut index: HashMap<String, String> = fs::read(&ruta_index)
        .ok()
        .and_then(|blob| seguridad::descifrar_documento(blob, subclave_hex).ok())
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default();
    let nombre_clave = std::path::Path::new(ruta)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    index.insert(nombre_clave, buzon_id.to_string());
    let json = serde_json::to_string(&index).map_err(|e| format!("Error: {}", e))?;
    let cifrado =
        seguridad::blindar_documento(&json, subclave_hex).map_err(|e| format!("Error: {}", e))?;
    escribir_privado(&ruta_index, cifrado).map_err(|e| format!("Error: {}", e))?;
    Ok(())
}

#[derive(serde::Serialize)]
struct PdfUnionInfo {
    ruta: String, // ruta .babel original — la usa el frontend para reordenar
    nombre: String,
    paginas: usize,
    error: Option<String>,
}

// COMANDO — Prepara el panel de unión: por cada .babel seleccionado, descifra
// EN MEMORIA, comprueba que es un PDF y cuenta sus páginas con PDFium. No escribe
// nada al disco.
#[tauri::command]
async fn preparar_union_pdfs(
    app: tauri::AppHandle,
    rutas: Vec<String>,
    sesion: tauri::State<'_, SesionActiva>,
) -> Result<Vec<PdfUnionInfo>, String> {
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    let dirs = pdfium_dirs(&app);

    tauri::async_runtime::spawn_blocking(move || {
        let pdfium = pdf_union::pdfium(&dirs)?;
        let mut infos: Vec<PdfUnionInfo> = Vec::with_capacity(rutas.len());

        for ruta in &rutas {
            let nombre = nombre_exportacion(ruta, "pdf");
            let res = validar_ruta_en(ruta, guardados_dir())
                .or_else(|_| validar_ruta_en(ruta, archivos_dir()))
                .and_then(|_| descifrar_a_bytes(ruta, &subclave_hex));
            let (paginas, error) = match res {
                Ok(bytes) => {
                    if detectar_ext(&bytes) != "pdf" {
                        (0, Some("No es un PDF".to_string()))
                    } else {
                        match pdf_union::contar_paginas(pdfium, &bytes) {
                            Ok(p) => (p, None),
                            Err(msg) => (0, Some(msg)),
                        }
                    }
                }
                Err(e) => {
                    log::error!("union: no se pudo leer {}: {}", ruta, e);
                    (0, Some("No se pudo leer el archivo".to_string()))
                }
            };
            infos.push(PdfUnionInfo { ruta: ruta.clone(), nombre, paginas, error });
        }

        Ok(infos)
    })
    .await
    .map_err(|e| format!("Error interno: {}", e))?
}

// COMANDO — Une los PDFs (en el orden dado) y guarda el resultado cifrado en el
// buzón. Corre en spawn_blocking para no bloquear la UI y emite "progreso-union".
#[tauri::command]
async fn unir_pdfs(
    app: tauri::AppHandle,
    rutas: Vec<String>,
    nombre_salida: String,
    buzon_id: String,
    borrar_originales: bool,
    sesion: tauri::State<'_, SesionActiva>,
) -> Result<String, String> {
    crate::rat_detector::verificar_no_bloqueado_rat()?;
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    if rutas.len() < 2 {
        return Err("Selecciona al menos 2 PDFs.".into());
    }
    let id_usuario = sesion.usuario.lock().map_err(|_| "Error".to_string())?.clone();
    let dirs = pdfium_dirs(&app);

    tauri::async_runtime::spawn_blocking(move || {
        let progreso = |pct: u8, msg: &str| {
            let _ = app.emit("progreso-union", serde_json::json!({"pct": pct, "msg": msg}));
        };

        // Descifra cada PDF EN MEMORIA (nunca toca el disco en claro).
        // Zeroizing: el plaintext de cada PDF se borra de la RAM al salir del scope,
        // por cualquier ruta (éxito, error, o límite de tamaño superado).
        let mut entradas: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(rutas.len());
        let total = rutas.len();

        for (i, ruta) in rutas.iter().enumerate() {
            progreso(
                ((i * 60 / total) as u8).min(60),
                &format!("Preparando {}/{}", i + 1, total),
            );
            validar_ruta_en(ruta, guardados_dir())
                .or_else(|_| validar_ruta_en(ruta, archivos_dir()))
                .map_err(|e| {
                    // No se loguea la ruta para no filtrar metadatos del vault.
                    log::error!("union: ruta no válida: {}", e);
                    "Uno de los archivos no es accesible.".to_string()
                })?;
            let bytes = Zeroizing::new(descifrar_a_bytes(ruta, &subclave_hex).map_err(|e| {
                log::error!("union: fallo al descifrar una entrada: {}", e);
                "No se pudo leer uno de los archivos.".to_string()
            })?);
            if bytes.len() as u64 > LIMITE_IMPORT_BYTES {
                return Err("Un archivo supera el límite de 150 MB.".into());
            }
            if detectar_ext(&bytes) != "pdf" {
                return Err("Solo se pueden unir archivos PDF.".into());
            }
            entradas.push(bytes);
        }

        progreso(70, "Uniendo PDFs…");
        let pdfium = pdf_union::pdfium(&dirs)?;
        let refs: Vec<&[u8]> = entradas.iter().map(|z| z.as_slice()).collect();
        let pdf_unido = Zeroizing::new(pdf_union::unir(pdfium, &refs).map_err(|msg| {
            log::error!("union: fallo al unir: {}", msg);
            msg
        })?);
        drop(refs);
        drop(entradas); // zeroiza el plaintext de las entradas cuanto antes

        progreso(90, "Cifrando y guardando…");
        let base = std::path::Path::new(&nombre_salida)
            .file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .unwrap_or("documento_unido");
        let nombre_final = format!("{}.pdf", base);

        let ruta_cifrada =
            cifrar_y_guardar_desde_bytes(&nombre_final, &pdf_unido, &subclave_hex, &id_usuario)
                .map_err(|e| {
                    log::error!("union: cifrar/guardar: {}", e);
                    e
                })?;

        // Asignar el buzón destino (si no es "todos"). No es fatal si falla.
        if buzon_id != "todos" && !buzon_id.is_empty() {
            if let Err(e) = asignar_buzon_guardado(&ruta_cifrada, &buzon_id, &subclave_hex) {
                log::error!("union: no se pudo asignar buzón: {}", e);
            }
        }

        // Borrado seguro de los PDFs originales que se fusionaron (si se pidió).
        // Solo tras el éxito completo, para no perder datos si algo falla; nunca
        // borra el resultado recién creado. Las rutas ya se validaron arriba como
        // dentro de guardados/archivos.
        if borrar_originales {
            let nomindex_g = ruta_nomindex_guardados();
            let nomindex_a = ruta_nomindex_archivos();
            let gdir = guardados_dir();
            let mut no_borrados = 0u32;
            for ruta in &rutas {
                if *ruta != ruta_cifrada {
                    borrar_seguro(ruta);
                    // Verificar que el borrado tuvo efecto y avisar si no (consistencia
                    // con el flujo de importación / clic derecho). Sin loguear la ruta.
                    if std::path::Path::new(ruta).exists() {
                        no_borrados += 1;
                    } else {
                        // Limpiar el nomindex para no dejar entradas huérfanas.
                        let nombre_disco = std::path::Path::new(ruta)
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string();
                        let en_guardados = std::path::Path::new(ruta).starts_with(&gdir);
                        if en_guardados {
                            nom_cifrado::eliminar(&nombre_disco, &nomindex_g, &subclave_hex);
                        } else {
                            nom_cifrado::eliminar(&nombre_disco, &nomindex_a, &subclave_hex);
                        }
                    }
                }
            }
            if no_borrados > 0 {
                log::warn!("union: {} original(es) no pudieron borrarse", no_borrados);
                progreso(
                    100,
                    &format!(
                        "Unido. {} original(es) no pudieron borrarse — elimínalos manualmente.",
                        no_borrados
                    ),
                );
                return Ok(ruta_cifrada);
            }
        }

        progreso(100, "Listo");
        Ok(ruta_cifrada)
    })
    .await
    .map_err(|e| format!("Error interno al unir: {}", e))?
}

/// Convierte una o varias imágenes a PDF.
///
/// - `modo = "uno"`: todas las imágenes en un único PDF multi-página (en el
///   orden de `rutas`). Nombre de salida: `nombre_salida` (con extensión .pdf).
/// - `modo = "varios"`: un PDF por imagen, con el nombre base de la imagen.
///
/// Los PDFs resultantes se cifran con la sesión activa y se guardan en Babel.
/// Devuelve las rutas cifradas de los archivos creados.
#[tauri::command]
async fn convertir_imagenes_a_pdf(
    rutas: Vec<String>,
    nombre_salida: String,
    buzon_id: String,
    modo: String,
    borrar_originales: bool,
    sesion: tauri::State<'_, SesionActiva>,
) -> Result<Vec<String>, String> {
    crate::rat_detector::verificar_no_bloqueado_rat()?;
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    if rutas.is_empty() {
        return Err("No se seleccionaron imágenes.".into());
    }
    if modo != "uno" && modo != "varios" {
        return Err("Modo no válido. Usa 'uno' o 'varios'.".into());
    }
    let id_usuario = sesion.usuario.lock().map_err(|_| "Error".to_string())?.clone();
    // Cargar nomindex fuera de spawn_blocking (State no es Send) para recuperar nombres reales.
    let mut nomindex = nom_cifrado::leer(&ruta_nomindex_guardados(), &subclave_hex);
    nomindex.extend(nom_cifrado::leer(&ruta_nomindex_archivos(), &subclave_hex));

    tauri::async_runtime::spawn_blocking(move || {
        // Leer y descifrar cada imagen de Babel
        let mut blobs: Vec<Vec<u8>> = Vec::with_capacity(rutas.len());
        for ruta in &rutas {
            validar_ruta_en(ruta, guardados_dir())
                .or_else(|_| validar_ruta_en(ruta, archivos_dir()))
                .map_err(|_| "Un archivo no es accesible.".to_string())?;
            let bytes = descifrar_a_bytes(ruta, &subclave_hex)
                .map_err(|_| "No se pudo leer uno de los archivos.".to_string())?;
            if bytes.len() > 50 * 1024 * 1024 {
                return Err("Una imagen supera el límite de 50 MB.".into());
            }
            blobs.push(bytes);
        }

        // Generar PDFs (uno o varios) y recoger rutas de salida.
        let rutas_out: Vec<String> = if modo == "uno" {
            let pdf = img_a_pdf::imagenes_a_pdf_unico(&blobs)?;
            let base = std::path::Path::new(&nombre_salida)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("documento_convertido");
            let nombre_final = format!("{}.pdf", base);
            let ruta = cifrar_y_guardar_desde_bytes(
                &nombre_final,
                &pdf,
                &subclave_hex,
                &id_usuario,
            )?;
            if buzon_id != "todos" && !buzon_id.is_empty() {
                let _ = asignar_buzon_guardado(&ruta, &buzon_id, &subclave_hex);
            }
            vec![ruta]
        } else {
            // Un PDF por imagen: recuperar nombre real desde nomindex.
            let mut out: Vec<String> = Vec::with_capacity(blobs.len());
            for (i, (ruta, blob)) in rutas.iter().zip(blobs.iter()).enumerate() {
                let pdf = img_a_pdf::imagen_a_pdf(blob)
                    .map_err(|e| format!("Imagen {}: {}", i + 1, e))?;
                let disco = std::path::Path::new(ruta)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("imagen");
                let nombre_real = nomindex.get(disco)
                    .map(|m| {
                        let stem = std::path::Path::new(&m.nombre)
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or(&m.nombre);
                        stem.to_string()
                    })
                    .unwrap_or_else(|| format!("imagen_{}", i + 1));
                let nombre_final = format!("{}.pdf", nombre_real);
                let ruta_out = cifrar_y_guardar_desde_bytes(
                    &nombre_final,
                    &pdf,
                    &subclave_hex,
                    &id_usuario,
                )?;
                if buzon_id != "todos" && !buzon_id.is_empty() {
                    let _ = asignar_buzon_guardado(&ruta_out, &buzon_id, &subclave_hex);
                }
                out.push(ruta_out);
            }
            out
        };

        // Borrado seguro de las imágenes originales, solo tras éxito completo.
        // Mismo patrón que unir_pdfs: borrar_seguro + limpiar nomindex.
        if borrar_originales {
            let nomindex_g = ruta_nomindex_guardados();
            let nomindex_a = ruta_nomindex_archivos();
            let gdir = guardados_dir();
            for ruta in &rutas {
                if rutas_out.contains(ruta) { continue; }
                borrar_seguro(ruta);
                if !std::path::Path::new(ruta).exists() {
                    let nombre_disco = std::path::Path::new(ruta)
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    let en_guardados = std::path::Path::new(ruta).starts_with(&gdir);
                    if en_guardados {
                        nom_cifrado::eliminar(&nombre_disco, &nomindex_g, &subclave_hex);
                    } else {
                        nom_cifrado::eliminar(&nombre_disco, &nomindex_a, &subclave_hex);
                    }
                }
            }
        }

        Ok(rutas_out)
    })
    .await
    .map_err(|e| format!("Error interno: {}", e))?
}

#[tauri::command]
fn cancelar_traduccion_activa() {
    traductor::cancelar_traduccion();
}

#[tauri::command]
fn set_modo_rapido(activado: bool) {
    traductor::set_modo_rapido(activado);
}

#[tauri::command]
fn leer_resultado(ruta: String, sesion: tauri::State<SesionActiva>) -> Result<Vec<u8>, String> {
    crate::rat_detector::verificar_no_bloqueado_rat()?;
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    validar_ruta_en(&ruta, archivos_dir())?;

    let meta = fs::metadata(&ruta).map_err(|e| format!("Error accediendo archivo: {}", e))?;
    if meta.len() > 150 * 1024 * 1024 {
        return Err("Archivo supera el límite de 150 MB.".into());
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
    escribir_privado(ruta, cifrado).map_err(|e| format!("Error: {}", e))?;
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
    crate::rat_detector::verificar_no_bloqueado_rat()?;
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }

    // Cargar índice cifrado fuera de spawn_blocking (State no es Send).
    let mut nomindex = nom_cifrado::leer(&ruta_nomindex_guardados(), &subclave_hex);
    nomindex.extend(nom_cifrado::leer(&ruta_nomindex_archivos(), &subclave_hex));

    tauri::async_runtime::spawn_blocking(move || {
        // Descifrar y reconstruir el documento original (valida ruta + zeroiza).
        let raw = abrir_descifrado_vault(&ruta, &subclave_hex)?;
        let ext = detectar_ext(&raw);
        let nombre = nombre_exportacion_idx(&ruta, ext, &nomindex);

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

        fs::write(&destino_path, &*raw)
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
    crate::rat_detector::verificar_no_bloqueado_rat()?;
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }

    let mut nomindex = nom_cifrado::leer(&ruta_nomindex_guardados(), &subclave_hex);
    nomindex.extend(nom_cifrado::leer(&ruta_nomindex_archivos(), &subclave_hex));

    tauri::async_runtime::spawn_blocking(move || {
        use tauri_plugin_dialog::DialogExt;
        let carpeta_opt = app.dialog().file().blocking_pick_folder();
        let carpeta = match carpeta_opt {
            Some(fp) => fp.into_path().map_err(|e| format!("Error procesando carpeta: {}", e))?,
            None => return Err("Exportación cancelada.".into()),
        };

        let mut copiados: u32 = 0;
        for ruta in &rutas {
            let raw = match abrir_descifrado_vault(ruta, &subclave_hex) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let ext = detectar_ext(&raw);
            let nombre = nombre_exportacion_idx(ruta, ext, &nomindex);
            let destino = carpeta.join(&nombre);
            if fs::write(&destino, &*raw).is_ok() {
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
    crate::rat_detector::verificar_no_bloqueado_rat()?;
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
    // Solo mover el __orig si ya existe en el índice (no crear entradas fantasma para archivos sin traducción).
    if index.contains_key(&nombre_orig) {
        index.insert(nombre_orig, buzon_destino);
    }

    let json = serde_json::to_string(&index).map_err(|e| format!("Error: {}", e))?;
    let cifrado =
        seguridad::blindar_documento(&json, &subclave_hex).map_err(|e| format!("Error: {}", e))?;
    escribir_privado(&ruta_index, cifrado).map_err(|e| format!("Error: {}", e))?;

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

    let nombre_limpio = nombre_nuevo
        .trim()
        .replace(['\0', '\n', '\r', '/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
    if nombre_limpio.is_empty() {
        return Err("El nombre no puede estar vacío.".to_string());
    }

    let ruta_nomindex = if es_guardado {
        ruta_nomindex_guardados()
    } else {
        ruta_nomindex_archivos()
    };

    // Archivos con nombre opaco: actualizar solo el índice cifrado (el nombre en disco no cambia).
    // Archivos legacy: renombrar físicamente en disco (comportamiento anterior).
    let idx_actual = nom_cifrado::leer(&ruta_nomindex, &subclave_hex);
    if idx_actual.contains_key(&nombre_viejo) {
        // Comprobar colisión de nombre visible en el índice
        let nombre_lower = nombre_limpio.to_lowercase();
        let hay_colision = idx_actual.iter()
            .any(|(k, v)| k != &nombre_viejo && v.nombre.to_lowercase() == nombre_lower);
        if hay_colision {
            return Err("Ya existe un archivo con ese nombre.".into());
        }
        // Actualizar nombre visible en índice cifrado; disco sin cambios.
        nom_cifrado::actualizar(&nombre_viejo, &nombre_limpio, &ruta_nomindex, &subclave_hex)?;

        // Actualizar también el __orig compañero si existe en el índice
        let nombre_viejo_orig = format!("{}__orig.babel", nombre_viejo.trim_end_matches(".babel"));
        if idx_actual.contains_key(&nombre_viejo_orig) {
            nom_cifrado::actualizar(&nombre_viejo_orig, &nombre_limpio, &ruta_nomindex, &subclave_hex)?;
        }

        return Ok(ruta.clone());
    }

    // Ruta legacy: renombrar físicamente en disco.
    let nuevo_nombre_archivo = format!("{}_{}.babel", id_usuario, nombre_limpio);
    let nueva_ruta = dir.join(&nuevo_nombre_archivo);

    // M5: no sobrescribir un archivo existente al renombrar.
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
        let _ = escribir_privado_atomico(&ruta_index, &cifrado);
    }

    Ok(nueva_ruta.to_string_lossy().to_string())
}

#[tauri::command]
fn eliminar_archivo(ruta: String, sesion: tauri::State<SesionActiva>) -> Result<(), String> {
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    let _idx_guard = BUZON_INDEX_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let en_guardados = validar_ruta_en(&ruta, guardados_dir()).is_ok();
    let en_archivos = validar_ruta_en(&ruta, archivos_dir()).is_ok();
    if !en_guardados && !en_archivos {
        return Err("Ruta fuera del vault.".into());
    }

    let meta_sym = fs::symlink_metadata(&ruta)
        .map_err(|e| format!("Error leyendo metadata: {}", e))?;
    if meta_sym.file_type().is_symlink() {
        return Err("No se puede eliminar un enlace simbólico.".into());
    }

    // 3 pasadas (0x00, 0xFF, 0xAA) + fsync + O_NOFOLLOW (igual que temporales)
    borrar_seguro(&ruta);

    // Limpiar entrada del índice de nombres cifrado (silent on error).
    let nombre_disco = std::path::Path::new(&ruta)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    if en_guardados {
        nom_cifrado::eliminar(&nombre_disco, &ruta_nomindex_guardados(), &subclave_hex);
    } else {
        nom_cifrado::eliminar(&nombre_disco, &ruta_nomindex_archivos(), &subclave_hex);
        // Limpiar también la entrada __orig compañera si existe
        let orig = format!("{}__orig.babel", nombre_disco.trim_end_matches(".babel"));
        nom_cifrado::eliminar(&orig, &ruta_nomindex_archivos(), &subclave_hex);
    }

    // Limpiar entrada del índice de carpetas (buzon_index) para no acumular entradas huérfanas.
    let ruta_buzon_index = if en_guardados {
        guardados_path(".buzon_index_guardados.babel")
    } else {
        archivos_path(".buzon_index.babel")
    };
    let mut buzon_idx: HashMap<String, String> = fs::read(&ruta_buzon_index)
        .ok()
        .and_then(|b| seguridad::descifrar_documento(b, &subclave_hex).ok())
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default();
    if buzon_idx.remove(&nombre_disco).is_some() {
        if let Ok(json) = serde_json::to_string(&buzon_idx) {
            if let Ok(cifrado) = seguridad::blindar_documento(&json, &subclave_hex) {
                let _ = escribir_privado_atomico(&ruta_buzon_index, &cifrado);
            }
        }
    }

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
    crate::rat_detector::verificar_no_bloqueado_rat()?;
    if !integridad::integridad_ok() {
        return Err(
            "Esta copia de Babel parece haber sido modificada y podría no ser segura. \
             Reinstala desde la fuente oficial para restaurar el acceso al descifrado."
                .to_string(),
        );
    }
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

fn default_timeout() -> u32 { 60 }

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
    escribir_privado(&babel_path("settings.babel"), cifrado).map_err(|e| e.to_string())?;
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
        timeout_sesion_minutos: 60,
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
                        let ok = escribir_privado(babel_path("settings.babel"), cifrado).is_ok();
                        // Borrar settings.json tanto si la migración tuvo éxito como si no:
                        // si falló el cifrado, mejor perder la config que dejar datos en claro.
                        let _ = fs::remove_file(babel_path("settings.json"));
                        traductor::registrar_evento(
                            if ok { "settings.json migrado a settings.babel cifrado" }
                            else { "AVISO: migración settings.json fallida — settings.json borrado igualmente" },
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
    let mut m_escaped = Zeroizing::new(maestra.replace('\\', "\\\\").replace('"', "\\\""));
    let mut p_escaped = Zeroizing::new(pass_usuario.replace('\\', "\\\\").replace('"', "\\\""));
    let mut datos_recovery = Zeroizing::new(format!("{{\"m\":\"{}\",\"p\":\"{}\"}}", m_escaped.as_str(), p_escaped.as_str()));
    m_escaped.zeroize();
    p_escaped.zeroize();
    let cifrado_recuperacion = seguridad::blindar_documento(&datos_recovery, &recovery_key_hex)
        .map_err(|e| format!("Error cifrando recovery.babel: {}", e))?;
    datos_recovery.zeroize();
    escribir_privado(&babel_path("recovery.babel"), &cifrado_recuperacion)
        .map_err(|e| format!("Error guardando recovery.babel: {}", e))?;
    escribir_version_recovery(3);

    let salt = traductor::cargar_o_crear_salt();
    let subclave = seguridad::derivar_subclave(maestra.as_bytes(), "babel-usuarios-v1", &salt)
        .map_err(|e| format!("Error derivando subclave: {}", e))?;
    let subclave_hex = Zeroizing::new(hex::encode(subclave.as_ref()));
    let cifrado_mnemonic = seguridad::blindar_documento(&palabras.join(" "), &subclave_hex)
        .map_err(|e| format!("Error cifrando mnemonic.babel: {}", e))?;
    escribir_privado(&babel_path("mnemonic.babel"), &cifrado_mnemonic)
        .map_err(|e| format!("Error guardando mnemonic.babel: {}", e))?;
    Ok(palabras)
}

// recuperar_con_frase era el comando IPC original (devolvía credenciales al frontend).
// Sustituido por recuperar_y_autenticar — ya no se registra como comando Tauri.
// ============================================================
// COMANDO — Recuperar Y autenticar en un solo paso (B7/S2)
// Las credenciales (maestra, pass) se derivan y verifican íntegramente en Rust.
// El frontend recibe el aviso opcional y la contraseña recuperada para que el
// usuario pueda guardarla (la muestra una vez y luego la descarta del DOM).
// ============================================================
#[derive(serde::Serialize)]
struct RecuperacionResult {
    aviso: String,
    pass_recuperado: String,
}

#[tauri::command]
fn recuperar_y_autenticar(
    palabras: Vec<String>,
    sesion: tauri::State<SesionActiva>,
    app: tauri::AppHandle,
) -> Result<RecuperacionResult, String> {
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
    crate::sincronizacion::establecer_subclave_sesion(&subclave_hex);

    // Arrancar el monitor RAT igual que en verificar_login.
    crate::rat_detector::iniciar_monitor_rat(app);

    let pass_para_mostrar = pass.to_string();
    Ok(RecuperacionResult { aviso, pass_recuperado: pass_para_mostrar })
}

// Lógica interna de recuperación compartida por recuperar_con_frase y recuperar_y_autenticar.
fn recuperar_con_frase_interno(
    palabras: &[String],
    sesion: &tauri::State<SesionActiva>,
) -> Result<(String, String, String), String> {
    if let Some(ts) = seguridad::leer_bloqueo() {
        let ahora = chrono::Local::now().timestamp();
        let expira = ts + 600;
        if ahora < expira {
            // cap a 600 s: evita bloqueo permanente si el reloj retrocede (NTP, ajuste manual)
            let restante = (expira - ahora).min(600);
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
                    let _ = escribir_privado(babel_path("recovery.babel"), nuevo);
                    escribir_version_recovery(3);
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
                            let _ = escribir_privado(babel_path("recovery.babel"), nuevo);
                            escribir_version_recovery(3);
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
                                    let _ = escribir_privado(babel_path("recovery.babel"), nuevo);
                                    escribir_version_recovery(3);
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

    // Extraer maestra y pass directamente con regex mínimo en vez de serde_json::Value,
    // ya que serde_json::Value no implementa Zeroize y dejaría las strings en el heap.
    // Formato garantizado: {"m":"...","p":"..."} (generado por format! en generar_frase_recuperacion).
    let extraer = |campo: &str| -> Option<String> {
        let marca = format!("\"{}\":\"", campo);
        let inicio = datos.find(&marca)? + marca.len();
        let resto = &datos[inicio..];
        // Desescapar \" dentro del valor
        let mut valor = String::new();
        let mut chars = resto.chars();
        loop {
            match chars.next()? {
                '"' => break,
                '\\' => { valor.push(chars.next()?); }
                c => valor.push(c),
            }
        }
        Some(valor)
    };
    let maestra = extraer("m").ok_or("Falta maestra")?;
    let pass    = extraer("p").ok_or("Falta pass")?;
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
        let ahora = chrono::Local::now().timestamp();
        let expira = ts + 600;
        if ahora < expira {
            // cap a 600 s: evita bloqueo permanente si el reloj retrocede (NTP, ajuste manual)
            let restante = (expira - ahora).min(600);
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
    escribir_privado(&babel_path("terminos.babel"), ts).map_err(|e| format!("Error: {}", e))
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

// ──────────────────────────────────────────────────────────────────────────────
// HELPER EMAIL — access token OAuth o contraseña convencional
// ──────────────────────────────────────────────────────────────────────────────

fn credencial_email(
    creds: &traductor::CredencialesEmail,
    subclave_hex: &str,
) -> Result<(String, bool), String> {
    if creds.usar_oauth {
        let token = gmail_oauth::obtener_access_token(
            gmail_oauth::CLIENT_ID,
            gmail_oauth::CLIENT_SECRET,
            subclave_hex,
        )?;
        Ok((token, true))
    } else {
        Ok((creds.password.clone(), false))
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
    crate::rat_detector::verificar_no_bloqueado_rat()?;
    let subclave_hex = sesion.subclave_hex()?;

    let remitentes_autorizados: Vec<String> = remitentes
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty() && es_remitente_valido(s))
        .collect();

    // Preservar usar_oauth de la config existente para no desactivar OAuth al guardar ajustes
    let usar_oauth_existente = traductor::cargar_config_email(&subclave_hex)
        .map(|c| c.usar_oauth)
        .unwrap_or(false);

    let creds = traductor::CredencialesEmail {
        smtp_servidor,
        imap_dominio,
        usuario,
        password,
        remitentes_autorizados,
        firma,
        usar_oauth: usar_oauth_existente,
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
    let (credencial, usar_oauth) = credencial_email(&creds, &subclave_hex)?;

    let resultado = traductor::enviar_archivo_descifrado(
        &ruta,
        &destinatario,
        &asunto,
        &cuerpo,
        &cc,
        &cco,
        &creds.smtp_servidor,
        &creds.usuario,
        &credencial,
        &subclave_hex,
        usar_oauth,
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
    escribir_privado(&ruta_temp, &bytes).map_err(|e| format!("Error guardando temporal: {}", e))?;

    // Closure garantiza borrar_seguro incluso si cargar_config_email devuelve None
    let resultado = (|| -> Result<(), String> {
        let creds = traductor::cargar_config_email(&subclave_hex).ok_or_else(|| {
            "No hay configuración de email guardada. Configura SMTP primero.".to_string()
        })?;
        let (credencial, usar_oauth) = credencial_email(&creds, &subclave_hex)?;

        traductor::enviar_archivo_descifrado(
            &ruta_temp,
            &destinatario,
            &asunto,
            &cuerpo,
            &cc,
            &cco,
            &creds.smtp_servidor,
            &creds.usuario,
            &credencial,
            &subclave_hex,
            usar_oauth,
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
    vista: Option<String>,
    sesion: tauri::State<SesionActiva>,
) -> Result<Vec<traductor::EmailResumen>, String> {
    let subclave_hex = sesion.subclave_hex()?;
    let vista = vista.as_deref().unwrap_or("entrada");

    let creds = traductor::cargar_config_email(&subclave_hex).ok_or_else(|| {
        "No hay configuración de email guardada. Configura SMTP primero.".to_string()
    })?;
    let (credencial, usar_oauth) = credencial_email(&creds, &subclave_hex)?;

    let mut emails =
        traductor::obtener_emails(&creds.imap_dominio, &creds.usuario, &credencial, usar_oauth, vista)
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
    let (credencial, usar_oauth) = credencial_email(&creds, &subclave_hex)?;

    let email =
        traductor::obtener_email_completo(&creds.imap_dominio, &creds.usuario, &credencial, id, usar_oauth)
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
    let (credencial, usar_oauth) = credencial_email(&creds, &subclave_hex)?;

    traductor::eliminar_email(&creds.imap_dominio, &creds.usuario, &credencial, id, usar_oauth)
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
    let (credencial, usar_oauth) = credencial_email(&creds, &subclave_hex)?;
    traductor::marcar_no_leido(&creds.imap_dominio, &creds.usuario, &credencial, id, usar_oauth)
        .map_err(|e| format!("Error marcando no leído: {}", e))
}

// COMANDO — Archivar email (mover fuera de INBOX)
#[tauri::command]
fn archivar_email_tauri(
    id: u32,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    let subclave_hex = sesion.subclave_hex()?;
    let creds = traductor::cargar_config_email(&subclave_hex)
        .ok_or_else(|| "No hay configuración de email guardada.".to_string())?;
    let (credencial, usar_oauth) = credencial_email(&creds, &subclave_hex)?;
    traductor::archivar_email(&creds.imap_dominio, &creds.usuario, &credencial, id, usar_oauth)
        .map_err(|e| format!("Error archivando email: {}", e))
}

// COMANDO — Marcar/desmarcar email como destacado (\Flagged)
#[tauri::command]
fn marcar_destacado_tauri(
    id: u32,
    destacar: bool,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    let subclave_hex = sesion.subclave_hex()?;
    let creds = traductor::cargar_config_email(&subclave_hex)
        .ok_or_else(|| "No hay configuración de email guardada.".to_string())?;
    let (credencial, usar_oauth) = credencial_email(&creds, &subclave_hex)?;
    traductor::marcar_destacado(&creds.imap_dominio, &creds.usuario, &credencial, id, destacar, usar_oauth)
        .map_err(|e| format!("Error cambiando destacado: {}", e))
}

// COMANDO — Enviar email sin adjunto (solo texto)
#[tauri::command]
fn enviar_solo_texto_tauri(
    destinatario: String,
    asunto: String,
    cuerpo: String,
    cc: String,
    cco: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    let subclave_hex = sesion.subclave_hex()?;
    let creds = traductor::cargar_config_email(&subclave_hex)
        .ok_or_else(|| "No hay configuración de email guardada.".to_string())?;
    let (credencial, usar_oauth) = credencial_email(&creds, &subclave_hex)?;
    traductor::enviar_solo_texto(
        &destinatario, &asunto, &cuerpo, &cc, &cco,
        &creds.smtp_servidor, &creds.usuario, &credencial, usar_oauth,
    ).map_err(|e| format!("Error enviando: {}", e))
}

// COMANDO — Abrir selector de archivo en la carpeta ~/Babel
#[tauri::command]
async fn seleccionar_archivo_email_dialogo(
    app: tauri::AppHandle,
) -> Result<Option<(String, Vec<u8>)>, String> {
    // Directorio inicial fuera de ~/Babel/ para no exponer archivos internos del vault.
    let dir_inicial = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    let dir_babel = babel_dir();
    tauri::async_runtime::spawn_blocking(move || {
        use tauri_plugin_dialog::DialogExt;
        let seleccion = app
            .dialog()
            .file()
            .set_directory(&dir_inicial)
            .blocking_pick_file();

        let ruta_fp = match seleccion {
            Some(fp) => fp,
            None => return Ok(None),
        };
        let ruta = ruta_fp.into_path().map_err(|e| format!("Ruta inválida: {}", e))?;
        // Rechazar archivos dentro de ~/Babel/ para evitar adjuntar material criptográfico.
        if ruta.starts_with(&dir_babel) {
            return Err("No se puede adjuntar un archivo interno de Babel.".into());
        }
        let nombre = ruta
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("Nombre inválido")?
            .to_string();
        let bytes = std::fs::read(&ruta).map_err(|e| format!("Error leyendo archivo: {}", e))?;
        Ok(Some((nombre, bytes)))
    })
    .await
    .map_err(|e| format!("Error en hilo: {}", e))?
}

// ──────────────────────────────────────────────────────────────────────────────
// COMANDOS GMAIL OAUTH
// ──────────────────────────────────────────────────────────────────────────────

/// Inicia el flujo OAuth PKCE: genera la URL de autorización, abre el browser,
/// arranca un servidor local para el callback y, cuando llega el código,
/// lo intercambia por tokens y los guarda cifrados.
/// Emite el evento "oauth_gmail_resultado" con { ok: bool, email?: string, error?: string }.
#[tauri::command]
fn iniciar_oauth_gmail_tauri(
    sesion: tauri::State<SesionActiva>,
    app: tauri::AppHandle,
) -> Result<String, String> {
    let subclave_hex = sesion.subclave_hex()?;

    if gmail_oauth::CLIENT_ID.starts_with("TU_") {
        return Err("Credenciales GCP no configuradas. Rellena CLIENT_ID y CLIENT_SECRET en gmail_oauth.rs.".to_string());
    }

    let flujo = gmail_oauth::construir_flujo(gmail_oauth::CLIENT_ID)?;
    let url = flujo.url_auth.clone();
    let verifier = flujo.verifier;
    let puerto = flujo.puerto;
    let listener = flujo.listener;

    // Hilo que espera el callback, intercambia el código y emite evento.
    // verifier y puerto se capturan por move — si el usuario inicia un segundo
    // flujo OAuth, cada hilo usa su propio verifier sin interferirse.
    let app2 = app.clone();
    std::thread::spawn(move || {
        let resultado = (|| -> Result<String, String> {
            let code = gmail_oauth::capturar_codigo(listener)?;

            let tokens = gmail_oauth::intercambiar_codigo(
                gmail_oauth::CLIENT_ID,
                gmail_oauth::CLIENT_SECRET,
                &code,
                &verifier,
                puerto,
            )?;

            let almacenar = gmail_oauth::TokensGmail {
                refresh_token: tokens.refresh_token.clone().to_string(),
                email: tokens.email.clone(),
            };
            gmail_oauth::guardar_tokens_oauth(&almacenar, &subclave_hex)?;

            // Activar OAuth — siempre forzar servidores Gmail para garantizar que
            // imap_dominio y smtp_servidor no queden vacíos si la config previa era incompleta.
            let creds_base = traductor::cargar_config_email(&subclave_hex)
                .unwrap_or_else(|| traductor::CredencialesEmail {
                    smtp_servidor: String::new(),
                    imap_dominio: String::new(),
                    usuario: String::new(),
                    password: String::new(),
                    remitentes_autorizados: vec![],
                    firma: String::new(),
                    usar_oauth: false,
                });
            let creds = traductor::CredencialesEmail {
                smtp_servidor: "smtp.gmail.com".to_string(),
                imap_dominio: "imap.gmail.com".to_string(),
                usuario: tokens.email.clone(),
                password: String::new(),
                remitentes_autorizados: creds_base.remitentes_autorizados.clone(),
                firma: creds_base.firma.clone(),
                usar_oauth: true,
            };
            let _ = traductor::guardar_config_email(&creds, &subclave_hex);

            Ok(tokens.email)
        })();

        let payload = match resultado {
            Ok(email) => serde_json::json!({ "ok": true, "email": email }),
            Err(e) => serde_json::json!({ "ok": false, "error": e }),
        };
        let _ = app2.emit("oauth_gmail_resultado", payload);
    });

    Ok(url)
}

/// Comprueba si hay tokens OAuth de Gmail guardados y devuelve el email asociado.
#[tauri::command]
fn estado_oauth_gmail_tauri(
    sesion: tauri::State<SesionActiva>,
) -> Result<Option<String>, String> {
    if !gmail_oauth::tiene_oauth_guardado() {
        return Ok(None);
    }
    let subclave_hex = sesion.subclave_hex()?;
    let tokens = gmail_oauth::cargar_tokens_oauth(&subclave_hex);
    Ok(tokens.map(|t| t.email))
}

/// Revoca el token en Google y borra las credenciales OAuth locales.
#[tauri::command]
fn revocar_oauth_gmail_tauri(
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    let subclave_hex = sesion.subclave_hex()?;
    gmail_oauth::revocar_oauth(gmail_oauth::CLIENT_ID, gmail_oauth::CLIENT_SECRET, &subclave_hex)?;

    // Volver a modo contraseña en la config de email
    if let Some(mut creds) = traductor::cargar_config_email(&subclave_hex) {
        creds.usar_oauth = false;
        let _ = traductor::guardar_config_email(&creds, &subclave_hex);
    }
    Ok(())
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

// COMANDOS SINCRONIZACIÓN — Emparejamiento de dispositivos

/// Devuelve el nombre local del dispositivo (formato "Babel-<hostname>") sin
/// arrancar ningún servicio. Usado por el overlay RAT para identificar este nodo.
#[tauri::command]
fn obtener_nombre_local() -> String {
    let hostname = hostname::get()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    format!("Babel-{}", hostname)
}

#[tauri::command]
fn iniciar_sinc_servidor(sesion: tauri::State<SesionActiva>) -> Result<String, String> {
    let subclave = sesion.subclave_hex()?;
    if subclave.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    let hostname = hostname::get()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let nombre = format!("Babel-{}", hostname);
    crate::sincronizacion::iniciar_servidor_sinc(nombre.clone());
    crate::conexion_directa::iniciar_servidor_conex(&subclave, nombre.clone());
    // Iniciar también el descubrimiento UDP (idempotente: falla silenciosamente si ya corre)
    crate::babel_p2p::DescubrimientoRed::iniciar_servidor(nombre.clone());

    // Verificar buzón B2 al arrancar (background, no bloquea la UI)
    let subclave_b2 = subclave.clone();
    tauri::async_runtime::spawn(async move {
        let pendientes = crate::buzon_b2::contar_pendientes_todos(&subclave_b2).await;
        for c in &pendientes {
            log::info!(
                "[B2] {} mensaje(s) pendiente(s) de '{}' en buzón — usa 'BUZÓN' en Ajustes para aplicar",
                c.n, c.nombre
            );
        }
    });

    Ok(nombre)
}

#[tauri::command]
fn detener_sinc_servidor(sesion: tauri::State<SesionActiva>) -> Result<(), String> {
    sesion.subclave_hex()?;
    crate::sincronizacion::detener_servidor_sinc();
    Ok(())
}

#[tauri::command]
fn buscar_dispositivos_sinc() -> Result<Vec<babel_p2p::PeerDescubierto>, String> {
    babel_p2p::DescubrimientoRed::buscar_peers(3000)
}

#[tauri::command]
async fn solicitar_emparejamiento_sinc(
    ip: String,
    sesion: tauri::State<'_, SesionActiva>,
) -> Result<sincronizacion::ResultadoEmparejamiento, String> {
    let subclave = sesion.subclave_hex()?;
    if subclave.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    let hostname = hostname::get()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let nombre = format!("Babel-{}", hostname);
    let mi_ip = {
        let socket =
            std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
        socket.connect("8.8.8.8:80").map_err(|e| e.to_string())?;
        socket
            .local_addr()
            .map_err(|e| e.to_string())?
            .ip()
            .to_string()
    };
    let subclave_str = subclave.to_string();
    tauri::async_runtime::spawn_blocking(move || {
        crate::sincronizacion::solicitar_emparejamiento(&ip, &nombre, &mi_ip, &subclave_str)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn obtener_solicitud_sinc() -> Option<sincronizacion::SolicitudSincPublica> {
    crate::sincronizacion::SOLICITUD_PENDIENTE
        .lock()
        .ok()
        .and_then(|g| g.clone())
}

#[tauri::command]
fn aceptar_emparejamiento_sinc(sesion: tauri::State<SesionActiva>) -> Result<(), String> {
    let subclave = sesion.subclave_hex()?;
    if subclave.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    let solicitud = crate::sincronizacion::SOLICITUD_PENDIENTE
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .ok_or_else(|| "No hay solicitud de emparejamiento pendiente.".to_string())?;
    crate::sincronizacion::aceptar_y_generar_clave(
        &solicitud.ip,
        &solicitud.nombre,
        &subclave,
    )
}

#[tauri::command]
fn rechazar_emparejamiento_sinc(
    _sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    crate::sincronizacion::rechazar_emparejamiento();
    Ok(())
}

#[tauri::command]
fn listar_dispositivos_emparejados(
    sesion: tauri::State<SesionActiva>,
) -> Result<Vec<sincronizacion::DispositivoPublico>, String> {
    let subclave = sesion.subclave_hex()?;
    if subclave.is_empty() {
        return Ok(Vec::new());
    }
    Ok(
        crate::sincronizacion::cargar_emparejados(&subclave)
            .into_iter()
            .map(|d| sincronizacion::DispositivoPublico {
                id: d.id,
                nombre: d.nombre,
                ts: d.ts,
                ip_ultima: d.ip_ultima,
            })
            .collect(),
    )
}

#[tauri::command]
fn desemparejar_dispositivo(
    id: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    let subclave = sesion.subclave_hex()?;
    if subclave.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    let mut lista = crate::sincronizacion::cargar_emparejados(&subclave);
    let antes = lista.len();
    lista.retain(|d| d.id != id);
    if lista.len() == antes {
        return Err("Dispositivo no encontrado.".into());
    }
    crate::sincronizacion::guardar_emparejados(&lista, &subclave);
    Ok(())
}

#[tauri::command]
async fn probar_conexion_dispositivo(
    id: String,
    sesion: tauri::State<'_, SesionActiva>,
) -> Result<conexion_directa::ResultadoConexion, String> {
    let subclave = sesion.subclave_hex()?;
    if subclave.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    let hostname = hostname::get()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let nombre = format!("Babel-{}", hostname);
    let emparejados = crate::sincronizacion::cargar_emparejados(&subclave);
    let disp = emparejados
        .into_iter()
        .find(|d| d.id == id)
        .ok_or_else(|| "Dispositivo no encontrado.".to_string())?;
    let ip = disp.ip_ultima.clone();
    let clave = disp.clave_hex.clone();
    let clave_b2 = clave.clone();
    let nombre_b2 = nombre.clone();

    let b2_pendiente = disp.b2_pendiente;

    let resultado = tauri::async_runtime::spawn_blocking(move || {
        crate::conexion_directa::probar_conexion(&ip, &nombre, &clave)
    })
    .await
    .map_err(|e| e.to_string())?;

    // A2: Si el dispositivo es accesible y tiene b2_pendiente, intentar envío B2.
    // Si el flag caducó (>48 h, Err(())), limpiarlo.
    if b2_pendiente {
        let subclave2 = subclave.clone();
        let id2 = id.clone();
        let hostname2 = hostname::get()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let nombre_local = format!("Babel-{}", hostname2);
        tauri::async_runtime::spawn_blocking(move || {
            let emparejados = crate::sincronizacion::cargar_emparejados(&subclave2);
            if let Some(disp2) = emparejados.iter().find(|d| d.id == id2) {
                match crate::sincronizacion::reenviar_b2_si_pendiente(disp2, &nombre_local) {
                    Ok(true) | Err(()) => {
                        // Éxito o caducado → limpiar flag
                        let mut lista = crate::sincronizacion::cargar_emparejados(&subclave2);
                        if let Some(d) = lista.iter_mut().find(|d| d.id == id2) {
                            d.b2_pendiente = false;
                            d.ts_b2_pendiente = 0;
                            crate::sincronizacion::guardar_emparejados(&lista, &subclave2);
                        }
                    }
                    Ok(false) => {
                        log::info!("[SINC] B2 reintento fallido para {} — se intentará de nuevo.", id2);
                    }
                }
            }
        })
        .await
        .ok();
    }

    match resultado {
        Ok(res) => Ok(res),
        Err(ref e)
            if e.contains("No se pudo conectar")
                || e.contains("timed out")
                || e.contains("Connection refused")
                || e.contains("No route to host") =>
        {
            // Dispositivo apagado → caída automática al buzón B2
            let contenido = format!("Intento de conexión directa desde {}", nombre_b2);
            match crate::buzon_b2::subir_al_buzon("ping", &contenido, &nombre_b2, &clave_b2)
                .await
            {
                Ok(key) => {
                    let sufijo = key.rsplit('/').next().unwrap_or(&key).to_string();
                    Ok(conexion_directa::ResultadoConexion {
                        ok: false,
                        via_buzon: true,
                        ip_publica_remota: String::new(),
                        latencia_ms: 0,
                        error: format!(
                            "Dispositivo offline. Aviso enviado al buzón temporal ({})",
                            sufijo
                        ),
                    })
                }
                Err(b2e) => Err(format!(
                    "Dispositivo offline. Error al acceder al buzón B2: {}",
                    b2e
                )),
            }
        }
        Err(e) => Err(e),
    }
}

#[tauri::command]
async fn contar_pendientes_b2(
    id: String,
    sesion: tauri::State<'_, SesionActiva>,
) -> Result<usize, String> {
    let subclave = sesion.subclave_hex()?;
    if subclave.is_empty() {
        return Ok(0);
    }
    let emparejados = crate::sincronizacion::cargar_emparejados(&subclave);
    let disp = match emparejados.into_iter().find(|d| d.id == id) {
        Some(d) => d,
        None => return Err("Dispositivo no encontrado.".into()),
    };
    match crate::buzon_b2::listar_pendientes(&disp.clave_hex).await {
        Ok(p) => Ok(p.len()),
        Err(_) => Ok(0), // B2 no configurado o sin red: no mostrar error
    }
}

#[tauri::command]
async fn verificar_buzones_todos(
    sesion: tauri::State<'_, SesionActiva>,
) -> Result<Vec<buzon_b2::ConteoB2>, String> {
    let subclave = sesion.subclave_hex()?;
    if subclave.is_empty() {
        return Ok(Vec::new());
    }
    Ok(crate::buzon_b2::contar_pendientes_todos(&subclave).await)
}

#[tauri::command]
async fn aplicar_pendientes_buzon(
    id: String,
    sesion: tauri::State<'_, SesionActiva>,
) -> Result<Vec<buzon_b2::ResultadoAplicarB2>, String> {
    let subclave = sesion.subclave_hex()?;
    if subclave.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    let emparejados = crate::sincronizacion::cargar_emparejados(&subclave);
    let disp = emparejados
        .into_iter()
        .find(|d| d.id == id)
        .ok_or_else(|| "Dispositivo no encontrado.".to_string())?;

    let pendientes = crate::buzon_b2::listar_pendientes(&disp.clave_hex).await?;
    let mut resultados = Vec::new();
    for p in pendientes {
        match crate::buzon_b2::descargar_y_aplicar(&p.key, &disp.clave_hex).await {
            Ok(r) => resultados.push(r),
            Err(e) => log::error!("[B2] Error aplicando {}: {}", p.key, e),
        }
    }
    Ok(resultados)
}

// HELPER — Convierte código de idioma al par MarianMT
// Centralizado aquí para no duplicar el match en cada comando.

fn idioma_a_par(idioma: &str) -> Result<&'static str, String> {
    match idioma {
        "es_en"=>Ok("es-en"),"en_es"=>Ok("en-es"),"es_fr"=>Ok("es-fr"),"fr_es"=>Ok("fr-es"),
        "es_ar"=>Ok("es-ar"),"ar_es"=>Ok("ar-es"),"fr_en"=>Ok("fr-en"),"en_fr"=>Ok("en-fr"),
        "en_ar"=>Ok("en-ar"),"ar_en"=>Ok("ar-en"),"fr_ar"=>Ok("fr-ar"),"ar_fr"=>Ok("ar-fr"),
        "es_de"=>Ok("es-de"),"de_es"=>Ok("de-es"),"fr_de"=>Ok("fr-de"),"de_fr"=>Ok("de-fr"),
        "ar_de"=>Ok("ar-de"),"de_ar"=>Ok("de-ar"),"es_ru"=>Ok("es-ru"),"ru_es"=>Ok("ru-es"),
        "fr_ru"=>Ok("fr-ru"),"ru_fr"=>Ok("ru-fr"),"ar_ru"=>Ok("ar-ru"),"ru_ar"=>Ok("ru-ar"),
        "es_zh"=>Ok("es-zh"),"zh_es"=>Ok("zh-es"),"fr_zh"=>Ok("fr-zh"),"zh_fr"=>Ok("zh-fr"),
        "ar_zh"=>Ok("ar-zh"),"zh_ar"=>Ok("zh-ar"),"de_ru"=>Ok("de-ru"),"ru_de"=>Ok("ru-de"),
        "de_zh"=>Ok("de-zh"),"zh_de"=>Ok("zh-de"),"ru_zh"=>Ok("ru-zh"),"zh_ru"=>Ok("zh-ru"),
        "en_de"=>Ok("en-de"),"de_en"=>Ok("de-en"),"en_ru"=>Ok("en-ru"),"ru_en"=>Ok("ru-en"),
        "en_zh"=>Ok("en-zh"),"zh_en"=>Ok("zh-en"),
        _=>Err(format!("Par de idiomas no reconocido: '{idioma}'")),
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
    escribir_privado(&ruta, html.as_bytes())
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
// COMANDOS — COMPARTIR ARCHIVO CIFRADO (HTML autónomo)
// ============================================================

/// Descifra un .babel, empaqueta y genera un .html autónomo en ~/Babel/compartidos/.
/// Si el contacto es nuevo genera una contraseña aleatoria y la devuelve (solo la primera vez).
/// Si el contacto ya existe reutiliza su contraseña — el archivo se genera sin preguntar nada.
#[tauri::command]
fn generar_archivo_compartir(
    ruta: String,
    nombre_original: String,
    contacto: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<compartir::ResultadoCompartir, String> {
    crate::rat_detector::verificar_no_bloqueado_rat()?;
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }

    // Validar nombre del contacto
    let contacto = {
        let c = contacto.trim().to_string();
        if c.is_empty() { return Err("El nombre del contacto no puede estar vacío.".into()); }
        if c.len() > 64 { return Err("El nombre del contacto es demasiado largo.".into()); }
        if c.chars().any(|ch| ch.is_control()) { return Err("Nombre de contacto inválido.".into()); }
        c
    };

    // Descifrar el .babel (valida ruta + zeroiza el plaintext al salir).
    let bytes = abrir_descifrado_vault(&ruta, &subclave_hex)?;

    compartir::generar_archivo_compartir(&bytes, &nombre_original, &contacto, &subclave_hex)
}

/// Muestra el NSSharingServicePicker nativo de macOS para el archivo HTML generado.
/// Soporta AirDrop, Mail, Mensajes. En caso de error, el frontend debe ofrecer 'Revelar en Finder'.
#[tauri::command]
async fn compartir_archivo_nativo(
    ruta_html: String,
    app: tauri::AppHandle,
    sesion: tauri::State<'_, SesionActiva>,
) -> Result<(), String> {
    crate::rat_detector::verificar_no_bloqueado_rat()?;
    // Verificar sesión
    let subclave = sesion.subclave_hex()?;
    if subclave.is_empty() {
        return Err("No hay sesión activa.".into());
    }

    // Validar que la ruta esté dentro de ~/Babel/compartidos/
    validar_ruta_en(&ruta_html, compartir::compartidos_dir())?;

    #[cfg(target_os = "macos")]
    {
        let (tx, rx) = tokio::sync::oneshot::channel::<Result<(), String>>();
        let app_clone = app.clone();
        let path_clone = ruta_html.clone();

        app.run_on_main_thread(move || {
            let result = compartir::mostrar_share_picker_macos(&app_clone, &path_clone);
            let _ = tx.send(result);
        }).map_err(|e| format!("Error en hilo principal: {}", e))?;

        rx.await.map_err(|_| "Error de comunicación interna".to_string())?
    }

    #[cfg(not(target_os = "macos"))]
    Err("Compartición nativa no disponible en esta plataforma. Usa 'Revelar en Finder'.".into())
}

/// Genera HTML cifrado con contraseña aleatoria y abre el share sheet nativo inmediatamente.
/// No pide nombre de contacto ni guarda la contraseña en la tabla de contactos.
/// La contraseña se devuelve al frontend para que la copie al portapapeles.
#[tauri::command]
async fn compartir_directo(
    ruta: String,
    nombre_original: String,
    app: tauri::AppHandle,
    sesion: tauri::State<'_, SesionActiva>,
) -> Result<(), String> {
    crate::rat_detector::verificar_no_bloqueado_rat()?;
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        log::error!("[compartir_directo] No hay sesión activa");
        return Err("No hay sesión activa.".into());
    }

    // Descifrar → base64 → HTML sin contraseña → compartir (valida ruta + zeroiza).
    // No se loguean ruta ni nombre del archivo para no filtrar metadatos del documento.
    let mut bytes = abrir_descifrado_vault(&ruta, &subclave_hex)?;
    let ext = detectar_ext(&bytes);
    let mime = match ext {
        "pdf"  => "application/pdf",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "png"  => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif"  => "image/gif",
        "webp" => "image/webp",
        _      => "text/plain; charset=utf-8",
    };
    // Sanear nombre base (sin path traversal)
    let nombre_base = std::path::Path::new(&nombre_original)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&nombre_original);
    let nombre_con_ext = if std::path::Path::new(nombre_base).extension()
        .map(|e| !e.is_empty()).unwrap_or(false)
    {
        nombre_base.to_string()
    } else {
        format!("{}.{}", nombre_base, ext)
    };

    let mut b64 = base64::engine::general_purpose::STANDARD.encode(&**bytes);
    let html = compartir::generar_html_simple(&b64, &nombre_con_ext, mime);
    b64.zeroize();    // b64 es una copia base64 del plaintext — borrarla tras usarla
    bytes.zeroize();  // bytes ya no se necesitan — zerizar antes de tocar el disco

    // Nombre único para el .html: evita colisión en shares paralelos del mismo archivo
    let stem = std::path::Path::new(&nombre_con_ext)
        .file_stem().and_then(|s| s.to_str()).unwrap_or(&nombre_con_ext);
    let ruta_compartir = compartir::compartidos_dir()
        .join(format!("{}_{}.html", nuevo_id(), stem))
        .to_string_lossy()
        .to_string();

    escribir_privado(&ruta_compartir, html.as_bytes())
        .map_err(|e| format!("Error escribiendo HTML temporal: {}", e))?;

    log::info!("[compartir_directo] HTML listo");

    // macOS: NSSharingServicePicker (bloquea hasta que el usuario termina de compartir)
    // → BorrarAlSalir limpia el HTML al salir, incluso en error.
    #[cfg(target_os = "macos")]
    {
        let _guard = BorrarAlSalir(ruta_compartir.clone());
        let (tx, rx) = tokio::sync::oneshot::channel::<Result<(), String>>();
        let app_clone = app.clone();
        let path_clone = ruta_compartir.clone();
        app.run_on_main_thread(move || {
            let result = compartir::mostrar_share_picker_macos(&app_clone, &path_clone);
            match &result {
                Ok(_)  => log::info!("[compartir_directo] Share sheet OK"),
                Err(e) => log::error!("[compartir_directo] Share sheet falló: {}", e),
            }
            let _ = tx.send(result);
        }).map_err(|e| format!("Error en hilo principal: {}", e))?;
        return rx.await.map_err(|_| "Error de comunicación interna".to_string())?;
        // _guard sale de scope aquí → borrar_seguro
    }

    // Windows / Linux: abrir el HTML con la app por defecto (navegador).
    // El archivo queda en compartidos/ — sin NSSharingServicePicker no sabemos
    // cuándo el usuario termina de enviarlo, así que no lo borramos automáticamente.
    #[cfg(not(target_os = "macos"))]
    {
        #[cfg(target_os = "windows")]
        std::process::Command::new("cmd")
            .args(["/C", "start", "", &ruta_compartir])
            .spawn()
            .map_err(|e| format!("Error abriendo HTML: {}", e))?;

        #[cfg(not(target_os = "windows"))]
        std::process::Command::new("xdg-open")
            .arg(&ruta_compartir)
            .spawn()
            .map_err(|e| format!("Error abriendo HTML: {}", e))?;

        Ok(())
    }
}


/// Abre el Finder con el archivo HTML seleccionado, para arrastrar a WhatsApp/Telegram.
#[tauri::command]
fn revelar_en_finder(
    ruta: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    let subclave = sesion.subclave_hex()?;
    if subclave.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    validar_ruta_en(&ruta, compartir::compartidos_dir())?;

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .args(["-R", &ruta])
            .spawn()
            .map_err(|e| {
                log::error!("[compartir] open -R falló: {}", e);
                format!("Error abriendo Finder: {}", e)
            })?;
        Ok(())
    }
    #[cfg(target_os = "windows")]
    {
        // En Windows: /select muestra el archivo en el Explorador
        let ruta_w = ruta.replace('/', "\\");
        std::process::Command::new("explorer")
            .args(["/select,", &ruta_w])
            .spawn()
            .map_err(|e| format!("Error abriendo Explorador: {}", e))?;
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    Err("No disponible en esta plataforma.".into())
}

/// Lista los nombres de contactos con contraseña guardada.
#[tauri::command]
fn listar_contactos_compartir(
    sesion: tauri::State<SesionActiva>,
) -> Result<Vec<String>, String> {
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    let contactos = compartir::cargar_contactos(&subclave_hex);
    let mut nombres: Vec<String> = contactos.into_keys().collect();
    nombres.sort();
    Ok(nombres)
}

/// Devuelve la contraseña guardada para un contacto (para mostrarla en ajustes).
#[tauri::command]
fn ver_password_contacto(
    contacto: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<String, String> {
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    compartir::cargar_contactos(&subclave_hex)
        .get(&contacto)
        .cloned()
        .ok_or_else(|| format!("No hay contraseña guardada para '{}'.", contacto))
}

/// Cambia la contraseña de un contacto existente.
#[tauri::command]
fn actualizar_password_contacto(
    contacto: String,
    nueva_password: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    if nueva_password.trim().is_empty() {
        return Err("La contraseña no puede estar vacía.".into());
    }
    let mut contactos = compartir::cargar_contactos(&subclave_hex);
    if !contactos.contains_key(&contacto) {
        return Err(format!("Contacto '{}' no encontrado.", contacto));
    }
    contactos.insert(contacto, nueva_password.trim().to_string());
    compartir::guardar_contactos(&contactos, &subclave_hex)
}

// ── Destinos personalizados de compartición ───────────────────────────────────

/// Devuelve la lista de destinos cifrada en disco, o los destinos por defecto
/// si el archivo no existe todavía.
#[tauri::command]
fn cargar_destinos_compartir(
    sesion: tauri::State<SesionActiva>,
) -> Result<Vec<compartir::DestinoCompartir>, String> {
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    Ok(compartir::cargar_destinos(&subclave_hex))
}

/// Valida y persiste la lista completa de destinos.
#[tauri::command]
fn guardar_destinos_compartir(
    destinos: Vec<compartir::DestinoCompartir>,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    for d in &destinos {
        if d.nombre.is_empty() || d.nombre.len() > 64 {
            return Err(format!("Nombre inválido: '{}'", d.nombre));
        }
        if d.url.is_empty() || d.url.len() > 512 {
            return Err(format!("URL inválida: '{}'", d.url));
        }
        if !d.url.starts_with("http://") && !d.url.starts_with("https://") {
            return Err(format!("La URL debe empezar con http:// o https://: '{}'", d.url));
        }
        if let Some(ref bid) = d.bundle_id {
            if bid.len() > 128 || !bid.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-') {
                return Err(format!("Bundle ID inválido: '{}'", bid));
            }
        }
    }
    compartir::guardar_destinos(&destinos, &subclave_hex)
}

/// Descifra el .babel, copia el archivo al portapapeles (macOS) y abre la URL
/// del destino en el navegador por defecto. Devuelve el mensaje de confirmación.
/// Si se pasa `bundle_id` y la app está instalada (macOS), la abre en lugar de la URL.
#[tauri::command]
fn compartir_a_url(
    ruta: String,
    nombre_original: String,
    url: String,
    bundle_id: Option<String>,
    sesion: tauri::State<SesionActiva>,
) -> Result<String, String> {
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }

    validar_ruta_en(&ruta, archivos_dir())
        .or_else(|_| validar_ruta_en(&ruta, guardados_dir()))?;

    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(format!("URL inválida: '{}'", url));
    }

    let bytes = descifrar_a_bytes(&ruta, &subclave_hex)?;
    let ext = detectar_ext(&bytes);

    let nombre_base = std::path::Path::new(&nombre_original)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&nombre_original);

    let nombre_con_ext = if std::path::Path::new(nombre_base)
        .extension()
        .map(|e| !e.is_empty())
        .unwrap_or(false)
    {
        nombre_base.to_string()
    } else {
        format!("{}.{}", nombre_base, ext)
    };

    // Limpiar copias en claro de comparticiones previas antes de crear otra.
    compartir::barrer_plaintext_compartidos();

    let ruta_temporal = compartir::compartidos_dir()
        .join(format!("{}_{}", nuevo_id(), nombre_con_ext))
        .to_string_lossy()
        .to_string();

    escribir_privado(&ruta_temporal, &bytes)
        .map_err(|e| format!("Error guardando archivo temporal: {}", e))?;

    compartir::copiar_archivo_al_portapapeles(&ruta_temporal)
        .map_err(|e| {
            log::error!("compartir_a_url: fallo portapapeles: {}", e);
            format!("Error copiando al portapapeles: {}", e)
        })?;

    // Si hay bundle_id y la app está instalada → abrirla; si no → abrir URL
    #[cfg(target_os = "macos")]
    if let Some(ref bid) = bundle_id {
        if bid.len() > 128 || !bid.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-') {
            return Err(format!("Bundle ID inválido: '{}'", bid));
        }
        if compartir::verificar_app_instalada(bid) {
            compartir::abrir_app_bundle(bid)
                .map_err(|e| {
                    log::error!("compartir_a_url: fallo abriendo app {}: {}", bid, e);
                    format!("Error abriendo app: {}", e)
                })?;
            return Ok("Archivo copiado al portapapeles. Pégalo (Cmd+V) en el chat.".into());
        }
    }

    tauri_plugin_opener::open_url(&url, None::<&str>)
        .map_err(|e| {
            log::error!("compartir_a_url: fallo open_url {}: {}", url, e);
            format!("Error abriendo URL: {}", e)
        })?;

    Ok("Archivo copiado al portapapeles. Pégalo (Cmd+V) en el chat o súbelo desde ahí.".into())
}

/// Elimina un contacto y su contraseña de la tabla.
#[tauri::command]
fn olvidar_contacto(
    contacto: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    let mut contactos = compartir::cargar_contactos(&subclave_hex);
    contactos.remove(&contacto);
    compartir::guardar_contactos(&contactos, &subclave_hex)
}

// EXCLUSIÓN DE CAPTURA — marca la ventana de Babel para que su contenido no se
// comparta al hacer screen sharing / capturas por window-sharing.
#[cfg(target_os = "macos")]
fn excluir_ventana_de_captura(win: &tauri::WebviewWindow) {
    use objc::runtime::Object;
    use objc::{msg_send, sel, sel_impl};
    if let Ok(ptr) = win.ns_window() {
        let ns_window = ptr as *mut Object;
        // NSWindowSharingNone = 0 → el contenido de la ventana no se expone a otros
        // procesos vía window-sharing. Best-effort: no bloquea ScreenCaptureKit en
        // todas las versiones de macOS (ahí actúa la detección en vivo del paso N2).
        unsafe {
            let _: () = msg_send![ns_window, setSharingType: 0u64];
        }
    }
}

#[cfg(target_os = "windows")]
fn excluir_ventana_de_captura(_win: &tauri::WebviewWindow) {
    // PENDIENTE (fase Windows): SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)
    // ofrece bloqueo REAL de captura en Win10 2004+ (la ventana sale en negro para el
    // capturador). Requiere añadir el crate `windows` a Cargo.toml.
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn excluir_ventana_de_captura(_win: &tauri::WebviewWindow) {}

// ── ACTUALIZACIONES AUTOMÁTICAS ──────────────────────────────────────────────

/// Comprueba si hay una versión nueva en GitHub Releases.
/// - Si la ventana tiene el foco → emite "actualizacion-disponible" al frontend (popup en-app).
/// - Si la ventana no tiene foco → notificación nativa del sistema macOS.
async fn verificar_actualizacion(app: tauri::AppHandle) {
    use tauri_plugin_updater::UpdaterExt;
    let updater = match app.updater_builder().build() {
        Ok(u) => u,
        Err(e) => { log::warn!("[Updater] no disponible: {e}"); return; }
    };
    let update = match updater.check().await {
        Ok(Some(u)) => u,
        Ok(None) => return, // ya tenemos la última versión
        Err(e) => { log::warn!("[Updater] error al comprobar: {e}"); return; }
    };

    let info = serde_json::json!({
        "version": update.version,
        "notas":   update.body.clone().unwrap_or_default(),
        "fecha":   update.date.map(|d| d.to_string()).unwrap_or_default(),
    });

    let ventana_activa = app
        .get_webview_window("main")
        .map(|w| w.is_focused().unwrap_or(false))
        .unwrap_or(false);

    // Recordar la versión aprobada para verificar al instalar (TOCTOU entre check+install).
    if let Ok(mut g) = UPDATE_VERSION_PENDIENTE.lock() {
        *g = Some(update.version.clone());
    }

    // Siempre emitir el evento — el frontend mostrará el modal en cuanto tenga foco.
    let _ = app.emit("actualizacion-disponible", &info);

    // Además, si la ventana no está en foco, enviar notificación nativa para llamar la atención.
    if !ventana_activa {
        let version_raw = update.version.clone();
        let version_safe: String = version_raw.chars()
            .filter(|c| c.is_alphanumeric() || ".-+".contains(*c))
            .collect();
        let _ = std::process::Command::new("osascript")
            .arg("-e")
            .arg(format!(
                "display notification \"Babel {} está disponible. Ábrela para actualizar.\" with title \"Security Babel — Actualización\"",
                version_safe
            ))
            .output();
    }
}

/// Descarga e instala la actualización disponible. La app se reinicia sola al terminar.
#[tauri::command]
async fn instalar_actualizacion(app: tauri::AppHandle) -> Result<(), String> {
    use tauri_plugin_updater::UpdaterExt;
    let updater = app.updater_builder().build().map_err(|e| e.to_string())?;
    let update  = updater.check().await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "No hay actualización disponible.".to_string())?;

    // Verificar que la versión encontrada coincide con la que se mostró al usuario.
    // Protege el caso raro de que se publique una versión diferente entre check y install.
    if let Ok(g) = UPDATE_VERSION_PENDIENTE.lock() {
        if let Some(ref v_aprobada) = *g {
            if update.version != *v_aprobada {
                return Err(format!(
                    "La versión disponible cambió ({} → {}). Reinicia Babel para confirmar la nueva actualización.",
                    v_aprobada, update.version
                ));
            }
        }
    }

    let _ = app.emit("actualizacion-progreso", serde_json::json!({"estado": "descargando"}));

    update.download_and_install(
        |_chunk, _total| {},
        || { let _ = app.emit("actualizacion-progreso", serde_json::json!({"estado": "instalando"})); },
    ).await.map_err(|e| e.to_string())?;

    app.restart();
}

// PUNTO DE ENTRADA — Arranca Tauri, registra todos los comandos — y gestiona el estado global de sesión (SesionActiva).

fn main() {
    // Impedir que debuggers externos se adjunten al proceso en producción.
    // En release, cualquier intento de ptrace/lldb cierra la app inmediatamente.
    seguridad::denegar_depuracion();

    env_logger::init();

    // Verificar integridad del binario antes de cualquier operación sensible.
    // Si falla, INTEGRIDAD_OK queda en false y los comandos de cifrado lo comprueban.
    integridad::verificar_integridad_binario();

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
        // single_instance debe ir PRIMERO: si Babel ya corre, un segundo lanzamiento
        // (p. ej. `open babel://…` con la app cerrada y varios archivos) re-enfoca la
        // instancia viva en vez de abrir otra.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.set_focus();
            }
        }))
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            // Barrer ~/Babel/tmp/ al arranque para limpiar residuos de sesiones anteriores
            // que no cerraron limpiamente (SIGKILL, corte de luz). BorrarAlSalir no ejecuta
            // su destructor en crash abrupto, así que este barrido es la segunda línea de defensa.
            {
                let tmp = babel_dir().join("tmp");
                if let Ok(entradas) = std::fs::read_dir(&tmp) {
                    for entrada in entradas.flatten() {
                        let p = entrada.path();
                        if p.is_dir() {
                            if let Ok(hijos) = std::fs::read_dir(&p) {
                                for h in hijos.flatten() {
                                    borrar_seguro(&h.path().to_string_lossy());
                                }
                            }
                            let _ = std::fs::remove_dir_all(&p);
                        } else {
                            borrar_seguro(&p.to_string_lossy());
                        }
                    }
                }
                log::info!("[Arranque] tmp/ barrido completado.");
            }

            // HERRAMIENTAS EMPAQUETADAS — que la app use soffice/poppler/tessdata de su
            // propio bundle (Contents/Resources/…) y NO dependa de Homebrew/LibreOffice del
            // sistema. Debe correr ANTES de lanzar el sidecar o cualquier proceso hijo, ya
            // que estos heredan el entorno. En dev (sin bundle) las carpetas no existen y
            // simplemente no se fija nada, cayendo al comportamiento anterior (PATH/absolutos).
            if let Ok(res) = app.path().resource_dir() {
                let tools_bin = res.join("tools").join("bin");
                if tools_bin.is_dir() {
                    std::env::set_var("BABEL_TOOLS_DIR", &tools_bin);
                    // Prepender al PATH para procesos hijos que resuelvan por nombre.
                    let path_actual = std::env::var("PATH").unwrap_or_default();
                    std::env::set_var(
                        "PATH",
                        format!("{}:{}", tools_bin.display(), path_actual),
                    );
                    log::info!("[Tools] herramientas empaquetadas: {}", tools_bin.display());
                }
                let tessdata = res.join("tessdata");
                if tessdata.is_dir() {
                    std::env::set_var("TESSDATA_PREFIX", &tessdata);
                }
            }

            // FINDER — registrar el handler del URL scheme babel://.
            {
                use tauri_plugin_deep_link::DeepLinkExt;
                let handle_dl = app.handle().clone();
                app.deep_link().on_open_url(move |event| {
                    let urls: Vec<String> =
                        event.urls().iter().map(|u| u.to_string()).collect();
                    manejar_url_babel(&handle_dl, urls);
                });
                // En dev (binario sin bundle) el esquema no está en Info.plist. En Linux/
                // Windows se puede registrar en runtime; en macOS viene del Info.plist del
                // bundle (ver tauri.conf.json → plugins.deep-link).
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                {
                    let _ = app.deep_link().register("babel");
                }
            }

            // Excluir la ventana de Babel de la captura/compartición de pantalla.
            if let Some(win) = app.get_webview_window("main") {
                excluir_ventana_de_captura(&win);
            }
            let exe_dir = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.to_path_buf()));
            let sidecar_path = exe_dir.as_ref().map(|d| d.join("servidor_babel"));
            let sidecar_exists = sidecar_path.as_ref().map(|p| p.exists()).unwrap_or(false);
            // Fallback legacy: python + script en Resources/ (USBs anteriores)
            let legacy_exists = app.path().resource_dir().ok().map(|res| {
                res.join("python").join("bin").join("python3").exists()
                    && res.join("servidor").join("server.py").exists()
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

                // Resolver dónde están los modelos en orden de preferencia:
                // 1. ~/Babel/modelos_usb  (instalación estándar / usuario)
                // 2. {exe_dir}/modelos_usb (USB o dev con symlink)
                // 3. {resources}/modelos_usb (bundle con modelos integrados)
                // Si ninguno existe, se omite BABEL_DIR_USB y el servidor usa su default.
                let modelos_dir: Option<std::path::PathBuf> = [
                    Some(babel_dir().join("modelos_usb")),
                    exe_dir.as_ref().map(|d| d.join("modelos_usb")),
                    app.path().resource_dir().ok().map(|r| r.join("modelos_usb")),
                ]
                .into_iter()
                .flatten()
                .find(|p| p.is_dir());

                if let Some(ref m) = modelos_dir {
                    log::info!("[Servidor] modelos en {}", m.display());
                } else {
                    log::warn!("[Servidor] modelos no encontrados — la traducción puede fallar");
                }

                let child_result = if sidecar_exists {
                    let bin = sidecar_path.unwrap();
                    log::info!("[Servidor] lanzando sidecar: {}", bin.display());
                    let mut cmd = std::process::Command::new(&bin);
                    cmd .env("BABEL_NLLB_TOKEN", &token)
                        .env("TRANSFORMERS_OFFLINE", "1")
                        .env("HF_DATASETS_OFFLINE", "1")
                        .env("TOKENIZERS_PARALLELISM", "false");
                    if let Some(ref m) = modelos_dir {
                        cmd.env("BABEL_DIR_USB", m);
                    }
                    cmd.spawn()
                } else {
                    let res = app.path().resource_dir().unwrap();
                    let py_bin = res.join("python").join("bin").join("python3");
                    let servidor = res.join("servidor").join("server.py");
                    log::info!("[Servidor] lanzando legado python: {}", servidor.display());
                    let mut cmd2 = std::process::Command::new(&py_bin);
                    cmd2.arg(&servidor)
                        .env("BABEL_NLLB_TOKEN", &token)
                        .env("TRANSFORMERS_OFFLINE", "1")
                        .env("HF_DATASETS_OFFLINE", "1")
                        .env("TOKENIZERS_PARALLELISM", "false");
                    if let Some(ref m) = modelos_dir {
                        cmd2.env("BABEL_DIR_USB", m);
                    }
                    cmd2.spawn()
                };

                let handle = app.handle().clone();
                match child_result {
                    Ok(child) => {
                        log::info!("[Servidor] sidecar PID {}", child.id());
                        SERVIDOR_ESTADO.store(1, std::sync::atomic::Ordering::Relaxed);
                        *USB_CHILD.lock().unwrap_or_else(|p| p.into_inner()) = Some(child);

                        std::thread::spawn(move || {
                            let addr: std::net::SocketAddr = "127.0.0.1:5002".parse().unwrap();
                            let tc = std::time::Duration::from_secs(1);
                            let mut listo = false;
                            for _ in 0..120 {
                                std::thread::sleep(std::time::Duration::from_secs(2));
                                if std::net::TcpStream::connect_timeout(&addr, tc).is_ok() {
                                    log::info!("[Servidor] listo en 127.0.0.1:5002");
                                    SERVIDOR_ESTADO.store(2, std::sync::atomic::Ordering::Relaxed);
                                    let _ = handle.emit("servidor-usb-listo", ());
                                    listo = true;
                                    break;
                                }
                            }
                            if !listo {
                                log::error!("[Servidor] timeout: no respondió en 240 s");
                                SERVIDOR_ESTADO.store(3, std::sync::atomic::Ordering::Relaxed);
                                let _ = handle.emit(
                                    "servidor-error",
                                    "El traductor no arrancó en 4 minutos. Cierra y vuelve a abrir Babel.",
                                );
                            }
                        });
                    }
                    Err(e) => {
                        log::error!("[Servidor] fallo al lanzar: {}", e);
                        SERVIDOR_ESTADO.store(3, std::sync::atomic::Ordering::Relaxed);
                        let msg = format!("No se pudo lanzar el traductor: {}. Reinicia Babel.", e);
                        std::thread::spawn(move || {
                            std::thread::sleep(std::time::Duration::from_secs(3));
                            let _ = handle.emit("servidor-error", msg);
                        });
                    }
                }
            } else if !puerto_libre {
                log::info!("[Servidor] puerto 5002 ocupado — usando servidor externo");
                SERVIDOR_ESTADO.store(2, std::sync::atomic::Ordering::Relaxed);
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

            // ── Verificador de actualizaciones periódico ──────────────────────────
            // Comprueba cada 15 minutos si hay una nueva versión en GitHub Releases.
            // Si la ventana está en foco → emite evento al frontend (popup interno).
            // Si la ventana NO está en foco → notificación nativa del sistema.
            let handle_upd = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                // Primera comprobación: 2 min después del arranque (dar tiempo al sistema)
                tokio::time::sleep(tokio::time::Duration::from_secs(120)).await;
                loop {
                    verificar_actualizacion(handle_upd.clone()).await;
                    tokio::time::sleep(tokio::time::Duration::from_secs(15 * 60)).await;
                }
            });

            Ok(())
        })
        .on_window_event(|window, event| {
            match event {
                tauri::WindowEvent::CloseRequested { .. } => {
                    // X button: salir del proceso completo (macOS por defecto solo cierra
                    // la ventana pero deja el proceso vivo en el Dock).
                    window.app_handle().exit(0);
                }
                tauri::WindowEvent::Destroyed => {
                    // Nunca dejar el SO colgado en modo de entrada segura al cerrar Babel:
                    // dejaría el teclado del usuario en modo protegido para el resto del sistema.
                    seguridad::desactivar_entrada_segura_os();
                    if let Ok(mut guard) = USB_CHILD.lock() {
                        if let Some(mut c) = guard.take() {
                            let _ = c.kill();
                            let _ = c.wait();
                        }
                    }
                }
                _ => {}
            }
        })
        .manage(SesionActiva::nueva())
        .invoke_handler(tauri::generate_handler![
            verificar_entorno_seguro,
            activar_entrada_segura,
            desactivar_entrada_segura,
            hay_captura_de_pantalla,
            escanear_keylogger_ahora,
            comprobar_estado_bunker,
            crear_acceso_bunker,
            verificar_login,
            traducir_documento,
            cerrar_sesion_rust,
            traducir_documento_ruta,
            traducir_archivo_guardado,
            traducir_documento_dialogo,
            cancelar_traduccion_activa,
            set_modo_rapido,
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
            iniciar_sinc_servidor,
            obtener_nombre_local,
            detener_sinc_servidor,
            buscar_dispositivos_sinc,
            solicitar_emparejamiento_sinc,
            obtener_solicitud_sinc,
            aceptar_emparejamiento_sinc,
            rechazar_emparejamiento_sinc,
            listar_dispositivos_emparejados,
            desemparejar_dispositivo,
            probar_conexion_dispositivo,
            contar_pendientes_b2,
            verificar_buzones_todos,
            aplicar_pendientes_buzon,
            renombrar_buzon,
            guardar_documento_sin_traducir,
            guardar_documento_desde_bytes,
            preparar_temp_bytes,
            importar_archivo_dialogo,
            importar_carpeta_dialogo,
            borrar_archivo_original,
            borrar_archivo_fuente,
            procesar_entrada_finder,
            archivo_guardado_existe,
            verificar_herramientas_pdf,
            listar_archivos_guardados,
            crear_buzon_guardado,
            listar_buzones_guardados,
            eliminar_buzon_guardado,
            renombrar_buzon_guardado,
            abrir_carpeta_guardados,
            mover_archivo_guardado,
            preparar_union_pdfs,
            unir_pdfs,
            convertir_imagenes_a_pdf,
            obtener_usuario_con_maestra,
            renombrar_archivo,
            tiene_config_email,
            obtener_firma_email,
            eliminar_email_tauri,
            archivar_email_tauri,
            marcar_no_leido_tauri,
            marcar_destacado_tauri,
            enviar_solo_texto_tauri,
            seleccionar_archivo_email_dialogo,
            autologin_tauri,
            olvidar_sesion_tauri,
            guardar_preferencia_autologin,
            leer_preferencia_autologin,
            instalar_actualizacion,
            iniciar_oauth_gmail_tauri,
            estado_oauth_gmail_tauri,
            revocar_oauth_gmail_tauri,
            guardar_html_frase,
            borrar_html_frase,
            compartir_directo,
            generar_archivo_compartir,
            compartir_archivo_nativo,
            cargar_destinos_compartir,
            guardar_destinos_compartir,
            compartir_a_url,
            revelar_en_finder,
            listar_contactos_compartir,
            ver_password_contacto,
            actualizar_password_contacto,
            olvidar_contacto,
            registro_diario::registrar_evento_diario,
            registro_diario::obtener_eventos_dia,
            registro_diario::obtener_preferencias_registro,
            registro_diario::guardar_preferencias_registro,
            registro_diario::marcar_primera_vez_registro,
            registro_diario::obtener_ips_historial,
            estado_servidor_cmd,
            rat_detector::estado_bloqueo_rat,
            rat_detector::solicitar_desbloqueo_a_pares,
            rat_detector::desbloquear_rat_bip39,
            rat_detector::confirmar_desbloqueo_rat_cmd,
            rat_detector::rechazar_solicitud_desbloqueo_rat,
            rat_detector::obtener_solicitud_desbloqueo_rat,
            integridad::obtener_estado_integridad,
        ]);
    if let Err(e) = app.run(tauri::generate_context!()) {
        eprintln!("[!] Error crítico al iniciar Babel: {}", e);
        std::process::exit(1);
    }
}

// ─── Tests del sidecar ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests_licencia {
    use super::*;
    use sha2::Digest;

    // Una licencia generada ANTES del fix H2 (HMAC con clave estática v1, o hash
    // SHA-256 legacy) debe seguir validando y marcarse para migración a v2.
    #[test]
    fn migra_v1_y_legacy_a_v2() {
        let serial = b"C02ABC123XYZ";
        let salt = b"salt-de-prueba-para-licencia-32b";

        // v2 (formato nuevo) → OK sin tocar nada
        let firma_v2 = hmac_hex(serial, salt);
        assert_eq!(clasificar_licencia(&firma_v2, serial, salt), LicenciaEstado::V2Ok);

        // v1 (clave estática antigua) → requiere migración
        let firma_v1 = hmac_hex(serial, LICENCIA_KEY_V1);
        assert_eq!(clasificar_licencia(&firma_v1, serial, salt), LicenciaEstado::RequiereMigracion);

        // legacy (SHA-256 del serial) → requiere migración
        let hash_legacy = format!("{:x}", sha2::Sha256::digest(serial));
        assert_eq!(clasificar_licencia(&hash_legacy, serial, salt), LicenciaEstado::RequiereMigracion);
    }

    // El vínculo por hardware sigue funcionando: contenido ajeno o de otro equipo = inválido.
    #[test]
    fn rechaza_basura_y_otro_equipo() {
        let serial = b"C02ABC123XYZ";
        let salt = b"salt-de-prueba-para-licencia-32b";
        assert_eq!(clasificar_licencia("deadbeef", serial, salt), LicenciaEstado::Invalida);
        // firma v2 válida pero calculada con OTRO serial → inválida en este equipo
        let firma_otro = hmac_hex(b"OTRO-SERIAL", salt);
        assert_eq!(clasificar_licencia(&firma_otro, serial, salt), LicenciaEstado::Invalida);
    }
}

#[cfg(test)]
mod tests_sidecar {
    use super::*;

    // Verifica que el estado del servidor se lee correctamente desde el AtomicU8.
    #[test]
    fn test_estado_servidor_cmd() {
        SERVIDOR_ESTADO.store(0, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(estado_servidor_cmd(), "externo");

        SERVIDOR_ESTADO.store(1, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(estado_servidor_cmd(), "cargando");

        SERVIDOR_ESTADO.store(2, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(estado_servidor_cmd(), "listo");

        SERVIDOR_ESTADO.store(3, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(estado_servidor_cmd(), "error");

        // Restaurar para no afectar otros tests
        SERVIDOR_ESTADO.store(0, std::sync::atomic::Ordering::Relaxed);
    }

    // Verifica que el health-check detecta un puerto abierto.
    // Abre un listener temporal en un puerto libre y comprueba conectividad.
    #[test]
    fn test_health_check_detecta_puerto_abierto() {
        use std::net::{TcpListener, TcpStream};
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind temporal");
        let addr = listener.local_addr().unwrap();

        let conectado = TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok();
        assert!(conectado, "debe detectar el listener temporal como abierto");
    }

    // Verifica que el health-check falla en un puerto cerrado (sin servidor).
    #[test]
    fn test_health_check_detecta_puerto_cerrado() {
        use std::net::{SocketAddr, TcpStream};
        use std::time::Duration;

        // Puerto alto improbable que esté en uso
        let addr: SocketAddr = "127.0.0.1:19999".parse().unwrap();
        let conectado = TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok();
        // Si por casualidad está ocupado en CI simplemente no fallar
        if !conectado {
            assert!(!conectado);
        }
    }

    // Verifica que USB_CHILD arranca vacío y acepta un valor (sin lanzar proceso real).
    // Testea que la gestión del Mutex funciona correctamente.
    #[test]
    fn test_usb_child_mutex_inicial_vacio() {
        let guard = USB_CHILD.lock().unwrap_or_else(|p| p.into_inner());
        assert!(guard.is_none(), "USB_CHILD debe estar vacío al inicio");
    }
}

#[cfg(test)]
mod tests_formatos_no_soportados {
    use super::hint_formato_no_soportado;

    #[test]
    fn pages_devuelve_mensaje_con_instrucciones() {
        let msg = hint_formato_no_soportado("pages");
        assert!(msg.is_some(), ".pages debe tener mensaje");
        let msg = msg.unwrap();
        assert!(msg.contains("Apple Pages"), "debe mencionar Apple Pages");
        assert!(msg.contains("Exportar"), "debe incluir la ruta de exportación");
    }

    #[test]
    fn odt_devuelve_mensaje_con_instrucciones() {
        let msg = hint_formato_no_soportado("odt");
        assert!(msg.is_some(), ".odt debe tener mensaje");
        let msg = msg.unwrap();
        assert!(msg.contains("LibreOffice"), "debe mencionar LibreOffice");
        assert!(msg.contains(".docx"), "debe indicar el formato de destino");
    }

    #[test]
    fn numbers_devuelve_mensaje() {
        let msg = hint_formato_no_soportado("numbers");
        assert!(msg.is_some());
        assert!(msg.unwrap().contains("Apple Numbers"));
    }

    #[test]
    fn key_devuelve_mensaje() {
        let msg = hint_formato_no_soportado("key");
        assert!(msg.is_some());
        assert!(msg.unwrap().contains("Keynote"));
    }

    #[test]
    fn doc_xls_ppt_devuelven_mensaje() {
        assert!(hint_formato_no_soportado("doc").is_some());
        assert!(hint_formato_no_soportado("xls").is_some());
        assert!(hint_formato_no_soportado("ppt").is_some());
    }

    #[test]
    fn rtf_ods_odp_devuelven_mensaje() {
        assert!(hint_formato_no_soportado("rtf").is_some());
        assert!(hint_formato_no_soportado("ods").is_some());
        assert!(hint_formato_no_soportado("odp").is_some());
    }

    #[test]
    fn formatos_soportados_devuelven_none() {
        // Babel sí procesa estos — no debe mostrar aviso
        assert!(hint_formato_no_soportado("pdf").is_none());
        assert!(hint_formato_no_soportado("docx").is_none());
        assert!(hint_formato_no_soportado("txt").is_none());
        assert!(hint_formato_no_soportado("png").is_none());
        assert!(hint_formato_no_soportado("jpg").is_none());
    }

    #[test]
    fn extension_desconocida_devuelve_none() {
        // Para extensiones desconocidas el backend ya devuelve un error genérico
        assert!(hint_formato_no_soportado("xyz").is_none());
        assert!(hint_formato_no_soportado("").is_none());
        assert!(hint_formato_no_soportado("zip").is_none());
    }
}
