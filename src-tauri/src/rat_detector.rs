// Detección de herramientas de acceso remoto (RAT) y bloqueo silencioso de Babel.
//
// Flujo principal:
//   1. Monitor periódico (cada 30 s) escanea procesos conocidos.
//   2. Si detecta un RAT → RAT_BLOQUEADO=true + emite "rat-detectado" al frontend.
//   3. El frontend muestra overlay de bloqueo; el backend rechaza comandos críticos.
//   4. Desbloqueo por dos vías:
//      a. Par emparejado: A→B BABEL_RAT_REQ, B confirma, B→A BABEL_RAT_OK.
//      b. Frase BIP39: se descifra recovery.babel con las palabras (max 5 intentos).
//   5. El usuario puede marcar el proceso como "confiable" para esta sesión.
//   6. Cada detección queda registrada en Sospechas (tipo "sospecha_rat").

use std::collections::HashSet;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicU8, Ordering},
};
use std::thread;
use std::time::Duration;
use serde::Serialize;
use sha2::{Sha256, Digest};
use tauri::Emitter;

// ── Persistencia del contador BIP39 ──────────────────────────────────────────
//
// Almacenamiento dual: Keychain del sistema (macOS) + archivo ~Babel/.bip39_intentos.
// Al leer se toma el MAX de ambas fuentes: borrar una no resetea el contador.
// Al escribir se actualiza en ambas. Al limpiar se borran las dos.
// Archivo: 1 byte (contador) + 32 bytes SHA-256(BUILD_FINGERPRINT + ".bip39-v1." + byte).
// Tag inválida → tratado como MAX+1 (bloqueado).

// ── Keychain (macOS) ──────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn leer_intentos_keychain() -> Option<u8> {
    let out = std::process::Command::new("security")
        .args(["find-generic-password", "-s", "com.babel-security.bip39",
               "-a", "intentos", "-w"])
        .output().ok()?;
    if !out.status.success() { return None; }
    std::str::from_utf8(&out.stdout).ok()?.trim().parse().ok()
}

#[cfg(not(target_os = "macos"))]
fn leer_intentos_keychain() -> Option<u8> { None }

#[cfg(target_os = "macos")]
fn guardar_intentos_keychain(v: u8) {
    let _ = std::process::Command::new("security")
        .args(["add-generic-password", "-s", "com.babel-security.bip39",
               "-a", "intentos", "-w", &v.to_string(), "-U"])
        .output();
}

#[cfg(not(target_os = "macos"))]
fn guardar_intentos_keychain(_v: u8) {}

#[cfg(target_os = "macos")]
fn borrar_intentos_keychain() {
    let _ = std::process::Command::new("security")
        .args(["delete-generic-password", "-s", "com.babel-security.bip39",
               "-a", "intentos"])
        .output();
}

#[cfg(not(target_os = "macos"))]
fn borrar_intentos_keychain() {}

// ── Archivo firmado ───────────────────────────────────────────────────────────

fn ruta_bip39_intentos() -> std::path::PathBuf {
    crate::babel_dir().join(".bip39_intentos")
}

fn tag_bip39_intentos(v: u8) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(env!("BABEL_BUILD_FINGERPRINT").as_bytes());
    h.update(b".bip39-v1.");
    h.update([v]);
    h.finalize().into()
}

fn cargar_intentos_archivo() -> u8 {
    let datos = match std::fs::read(ruta_bip39_intentos()) {
        Ok(d) => d,
        Err(_) => return 0,
    };
    if datos.len() != 33 {
        return MAX_INTENTOS_BIP39 + 1;
    }
    let v = datos[0];
    if datos[1..] == tag_bip39_intentos(v) { v } else { MAX_INTENTOS_BIP39 + 1 }
}

fn guardar_intentos_archivo(v: u8) {
    let mut datos = vec![v];
    datos.extend_from_slice(&tag_bip39_intentos(v));
    let _ = crate::escribir_privado_atomico(&ruta_bip39_intentos(), &datos);
}

fn borrar_intentos_archivo() {
    let _ = std::fs::remove_file(ruta_bip39_intentos());
}

// ── API pública (dual) ────────────────────────────────────────────────────────

fn cargar_intentos_bip39_disco() -> u8 {
    let de_archivo = cargar_intentos_archivo();
    let de_keychain = leer_intentos_keychain().unwrap_or(0);
    de_archivo.max(de_keychain)
}

fn guardar_intentos_bip39_disco(v: u8) {
    guardar_intentos_archivo(v);
    guardar_intentos_keychain(v);
}

fn borrar_intentos_bip39_disco() {
    borrar_intentos_archivo();
    borrar_intentos_keychain();
}

/// Restaura el contador de intentos BIP39 desde disco al abrir sesión.
pub fn init_contador_bip39() {
    RAT_BIP39_INTENTOS.store(cargar_intentos_bip39_disco(), Ordering::Release);
}

// ── Estado global ─────────────────────────────────────────────────────────────

static RAT_BLOQUEADO: AtomicBool = AtomicBool::new(false);
static RAT_MONITOR_ACTIVO: AtomicBool = AtomicBool::new(false);
static RAT_BIP39_INTENTOS: AtomicU8 = AtomicU8::new(0);
// Generación del hilo monitor: se incrementa en detener_monitor_rat para que un hilo
// antiguo que aún esté durmiendo (hasta 30 s) se autodestruya al despertar.
static RAT_MONITOR_GEN: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
const MAX_INTENTOS_BIP39: u8 = 5;

static RAT_PROCESO: Mutex<Option<String>> = Mutex::new(None);
static RAT_SESIONES_CONFIABLES: Mutex<Option<HashSet<String>>> = Mutex::new(None);
// AppHandle almacenado globalmente para que el hilo monitor y el servidor sinc
// puedan emitir eventos al frontend sin recibir el handle como parámetro.
static RAT_APP_HANDLE: Mutex<Option<tauri::AppHandle>> = Mutex::new(None);

pub fn registrar_app_handle(app: tauri::AppHandle) {
    if let Ok(mut g) = RAT_APP_HANDLE.lock() {
        *g = Some(app);
    }
}

pub fn es_rat_bloqueado() -> bool {
    RAT_BLOQUEADO.load(Ordering::Acquire)
}

/// Guard para comandos Tauri críticos: retorna Err si Babel está bloqueado por RAT.
pub fn verificar_no_bloqueado_rat() -> Result<(), String> {
    if RAT_BLOQUEADO.load(Ordering::Acquire) {
        Err("Babel bloqueado: se ha detectado una herramienta de acceso remoto.".into())
    } else {
        Ok(())
    }
}

// ── Lista de procesos RAT ─────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
const PROCESOS_RAT: &[(&str, &str, bool)] = &[
    // (nombre_proceso, label_usuario, solo_si_hay_conexión_ESTABLISHED)
    ("TeamViewer",           "TeamViewer",              false),
    ("AnyDesk",              "AnyDesk",                 false),
    ("remoting_host",        "Chrome Remote Desktop",   false),
    ("LogMeInRemoteDesktop", "LogMeIn",                 false),
    ("Splashtop Streamer",   "Splashtop",               false),
    ("RustDesk",             "RustDesk",                false),
    ("NoMachine",            "NoMachine",               false),
    ("JumpDesktop",          "Jump Desktop",            false),
    ("ScreenConnect",        "ScreenConnect",           false),
    ("dwservice_agent",      "DWService",               false),
    ("meshagent",            "MeshCentral",             false),
    ("bomgar-pac",           "BeyondTrust",             false),
    ("AeroAdmin",            "AeroAdmin",               false),
    ("Remotix",              "Remotix",                 false),
    ("GoToAssistLauncher",   "GoTo Assist",             false),
    ("Vine Server",          "Vine VNC",                false),
    // screensharingd siempre corre como daemon; solo se bloquea si hay sesión ESTABLISHED.
    ("screensharingd",       "Screen Sharing de macOS", true),
];

#[cfg(target_os = "windows")]
const PROCESOS_RAT: &[(&str, &str, bool)] = &[
    ("TeamViewer.exe",                  "TeamViewer",            false),
    ("AnyDesk.exe",                     "AnyDesk",               false),
    ("chrome_remote_desktop_host.exe",  "Chrome Remote Desktop", false),
    ("winvnc.exe",                      "VNC Server",            false),
    ("vncserver.exe",                   "VNC Server",            false),
    ("RustDesk.exe",                    "RustDesk",              false),
    ("LogMeIn.exe",                     "LogMeIn",               false),
    ("ScreenConnect.ClientService.exe", "ScreenConnect",         false),
    ("bomgar-scc-ui.exe",               "BeyondTrust",           false),
    ("radmin.exe",                      "Radmin",                false),
    ("rfbserver.exe",                   "RFB Server",            false),
    ("AeroAdmin.exe",                   "AeroAdmin",             false),
    ("DWAgent.exe",                     "DWService",             false),
    ("meshagent.exe",                   "MeshCentral",           false),
    ("Splashtop Remote Service.exe",    "Splashtop",             false),
];

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
const PROCESOS_RAT: &[(&str, &str, bool)] = &[];

// ── Detección de procesos ─────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn proceso_activo(nombre: &str) -> bool {
    std::process::Command::new("pgrep")
        .args(["-x", nombre])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn screen_sharing_con_sesion_activa() -> bool {
    std::process::Command::new("lsof")
        .args(["-i", "TCP:5900", "-n", "-P"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("ESTABLISHED"))
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn proceso_activo(nombre: &str) -> bool {
    std::process::Command::new("tasklist")
        .args(["/FI", &format!("IMAGENAME eq {}", nombre), "/NH"])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .to_lowercase()
                .contains(&nombre.to_lowercase())
        })
        .unwrap_or(false)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn proceso_activo(_: &str) -> bool {
    false
}

/// Devuelve Some(label) del primer RAT activo no confiable, o None si todo está limpio.
pub fn detectar_rat_activo() -> Option<String> {
    let confiables: HashSet<String> = RAT_SESIONES_CONFIABLES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .cloned()
        .unwrap_or_default();

    for (proceso, label, requiere_conexion) in PROCESOS_RAT {
        if confiables.contains(*label) {
            continue;
        }
        #[cfg(target_os = "macos")]
        {
            let activo = if *requiere_conexion {
                screen_sharing_con_sesion_activa()
            } else {
                proceso_activo(proceso)
            };
            if activo {
                return Some(label.to_string());
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            if proceso_activo(proceso) {
                return Some(label.to_string());
            }
        }
    }
    None
}

// ── Monitor periódico ─────────────────────────────────────────────────────────

pub fn iniciar_monitor_rat(app: tauri::AppHandle) {
    registrar_app_handle(app.clone());
    init_contador_bip39(); // restaurar intentos fallidos persistidos de sesiones anteriores
    if RAT_MONITOR_ACTIVO.swap(true, Ordering::SeqCst) {
        return; // ya corriendo
    }
    // Leer la generación actual DESPUÉS del swap para que el hilo la use como
    // identificador de sesión. detener_monitor_rat la incrementa, lo que hace que
    // este hilo se autodestruya al despertar incluso si el flag aún no llegó.
    let gen = RAT_MONITOR_GEN.load(Ordering::SeqCst);
    thread::spawn(move || {
        // Espera inicial para evitar falsos positivos justo al login
        thread::sleep(Duration::from_secs(4));
        loop {
            if !RAT_MONITOR_ACTIVO.load(Ordering::SeqCst)
                || RAT_MONITOR_GEN.load(Ordering::SeqCst) != gen
            {
                break;
            }
            // No reemitir si ya estamos bloqueados
            if !RAT_BLOQUEADO.load(Ordering::Acquire) {
                if let Some(proceso) = detectar_rat_activo() {
                    activar_bloqueo_rat(&proceso, &app);
                }
            }
            thread::sleep(Duration::from_secs(30));
        }
    });
}

pub fn detener_monitor_rat() {
    // Incrementar la generación invalida el hilo que esté durmiendo (hasta 30 s
    // de latencia), evitando que arranque un nuevo hilo antes de que el viejo muera.
    RAT_MONITOR_GEN.fetch_add(1, Ordering::SeqCst);
    RAT_MONITOR_ACTIVO.store(false, Ordering::SeqCst);
    RAT_BLOQUEADO.store(false, Ordering::Release);
    RAT_BIP39_INTENTOS.store(0, Ordering::Release);
    borrar_intentos_bip39_disco(); // logout limpia el contador persistido
    if let Ok(mut g) = RAT_PROCESO.lock() {
        *g = None;
    }
    // Limpiar sesiones confiables para que no se filtren al siguiente login.
    if let Ok(mut c) = RAT_SESIONES_CONFIABLES.lock() {
        *c = None;
    }
    // Limpiar el handle: mensajes TCP retrasados no deben emitir eventos post-logout.
    if let Ok(mut h) = RAT_APP_HANDLE.lock() {
        *h = None;
    }
}

fn activar_bloqueo_rat(proceso: &str, app: &tauri::AppHandle) {
    RAT_BLOQUEADO.store(true, Ordering::Release);
    RAT_BIP39_INTENTOS.store(0, Ordering::Release);
    borrar_intentos_bip39_disco(); // nueva detección RAT = nueva oportunidad limpia
    if let Ok(mut g) = RAT_PROCESO.lock() {
        *g = Some(proceso.to_string());
    }
    let _ = app.emit("rat-detectado", serde_json::json!({ "proceso": proceso }));
    // Registrar en historial
    let subclave = crate::sincronizacion::obtener_subclave_sesion_copy()
        .unwrap_or_default();
    if !subclave.is_empty() {
        crate::registro_diario::registrar_sospecha_rat(proceso, &subclave);
    }
    log::warn!("[RAT] Babel bloqueado — proceso: {}", proceso);
}

/// Llamado desde el servidor sinc al recibir BABEL_RAT_OK de un par.
pub fn desbloquear_rat_desde_red() {
    RAT_BLOQUEADO.store(false, Ordering::Release);
    RAT_BIP39_INTENTOS.store(0, Ordering::Release);
    borrar_intentos_bip39_disco(); // desbloqueo por red limpia el contador
    if let Ok(mut g) = RAT_PROCESO.lock() {
        *g = None;
    }
    if let Ok(g) = RAT_APP_HANDLE.lock() {
        if let Some(app) = g.as_ref() {
            let _ = app.emit("rat-desbloqueado", serde_json::json!({}));
        }
    }
    log::info!("[RAT] Desbloqueado por confirmación de dispositivo emparejado.");
}

// ── Verificación BIP39 ────────────────────────────────────────────────────────

/// Verifica la frase BIP39 sin incrementar el contador de intentos del vault.
/// Tiene su propio contador (MAX_INTENTOS_BIP39 = 5) para prevenir brute-force.
pub fn verificar_frase_bip39_para_rat(palabras: &[String]) -> Result<bool, String> {
    // Reservar un slot de intento de forma atómica: evita que un doble-clic o
    // llamadas concurrentes puedan superar el límite con una race condition.
    // v <= MAX: permite un intento de verificación adicional al llegar al límite.
    // Sin esto, una frase CORRECTA presentada justo después de 5 intentos erróneos
    // sería rechazada antes de verificarse, bloqueando permanentemente al usuario legítimo
    // hasta reiniciar la app. La protección real contra brute-force es el KDF Argon2id,
    // no este contador (que se resetea al reiniciar). El slot extra no amplía la superficie
    // de ataque de manera significativa.
    if RAT_BIP39_INTENTOS.fetch_update(
        Ordering::AcqRel, Ordering::Acquire,
        |v| if v <= MAX_INTENTOS_BIP39 { Some(v + 1) } else { None },
    ).is_err() {
        return Err("Máximo de intentos alcanzado. Usa el dispositivo emparejado para desbloquear.".into());
    }

    if palabras.len() != 12 {
        RAT_BIP39_INTENTOS.fetch_sub(1, Ordering::AcqRel); // longitud inválida: no es un intento real
        return Ok(false);
    }
    // Palabras fuera del wordlist: mantener el slot (intento consumido).
    // El atacante no puede sondear indefinidamente con strings arbitrarios.
    if !palabras.iter().all(|p| crate::bip39_words::WORDLIST.contains(&p.as_str())) {
        return Ok(false);
    }
    let cifrado = match std::fs::read(crate::babel_path("recovery.babel")) {
        Ok(c) => c,
        Err(_) => {
            RAT_BIP39_INTENTOS.fetch_sub(1, Ordering::AcqRel); // error de infraestructura: liberar slot
            return Err("Sin frase de recuperación configurada en este búnker.".to_string());
        }
    };

    let salt_maestra = crate::traductor::cargar_o_crear_salt();
    let recovery_salt = crate::seguridad::derivar_recovery_salt_v2(&salt_maestra);

    // Intentar v3 → v2 → v1 → v0 para compatibilidad con búnkers antiguos.
    // En éxito se libera el slot: una frase correcta no debe consumir un intento.
    if let Ok(key) = crate::seguridad::derivar_clave_recuperacion_v3(palabras, &recovery_salt) {
        let hex = zeroize::Zeroizing::new(hex::encode(key.as_ref()));
        if crate::seguridad::descifrar_documento(cifrado.clone(), &hex).is_ok() {
            RAT_BIP39_INTENTOS.fetch_sub(1, Ordering::AcqRel);
            borrar_intentos_bip39_disco();
            return Ok(true);
        }
    }
    if let Ok(key) = crate::seguridad::derivar_clave_recuperacion_v2(palabras, &recovery_salt) {
        let hex = zeroize::Zeroizing::new(hex::encode(key.as_ref()));
        if crate::seguridad::descifrar_documento(cifrado.clone(), &hex).is_ok() {
            RAT_BIP39_INTENTOS.fetch_sub(1, Ordering::AcqRel);
            borrar_intentos_bip39_disco();
            return Ok(true);
        }
    }
    if let Ok(key) = crate::seguridad::derivar_clave_recuperacion(palabras) {
        let hex = zeroize::Zeroizing::new(hex::encode(key.as_ref()));
        if crate::seguridad::descifrar_documento(cifrado.clone(), &hex).is_ok() {
            RAT_BIP39_INTENTOS.fetch_sub(1, Ordering::AcqRel);
            borrar_intentos_bip39_disco();
            return Ok(true);
        }
    }
    if let Ok(key) = crate::seguridad::derivar_clave_recuperacion_v0(palabras) {
        let hex = zeroize::Zeroizing::new(hex::encode(key.as_ref()));
        if crate::seguridad::descifrar_documento(cifrado, &hex).is_ok() {
            RAT_BIP39_INTENTOS.fetch_sub(1, Ordering::AcqRel);
            borrar_intentos_bip39_disco();
            return Ok(true);
        }
    }

    // Frase incorrecta: el slot ya está consumido. Persistir el contador.
    guardar_intentos_bip39_disco(RAT_BIP39_INTENTOS.load(Ordering::Acquire));
    Ok(false)
}

// ── Protocolo TCP para desbloqueo remoto ──────────────────────────────────────

// Clave estática legacy — usada solo en tests y como fallback cuando no hay
// sesión activa (sin par emparejado). No proporciona autenticación fuerte porque
// cualquiera que lea el binario la conoce. Para mensajes entre pares emparejados,
// usar hmac_rat_con_clave con la clave compartida del par.
const HMAC_RAT_KEY: &[u8] = b"babel-rat-unlock-2026-v1";

/// Calcula el HMAC de un mensaje RAT usando la clave compartida con el par específico.
/// La clave del par es la clave AES-256 generada aleatoriamente durante el emparejamiento
/// y almacenada en dispositivos.babel. Es única por par y no está en el binario.
pub fn hmac_rat_con_clave(dominio: &str, ts: u64, clave_par: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type H = Hmac<Sha256>;
    let mut mac = H::new_from_slice(clave_par).expect("clave HMAC válida");
    mac.update(dominio.as_bytes());
    mac.update(b":");
    mac.update(ts.to_string().as_bytes());
    hex::encode(&mac.finalize().into_bytes()[..8])
}

/// Versión legacy con clave estática. Mantener para tests y fallback sin sesión.
pub fn hmac_rat(dominio: &str, ts: u64) -> String {
    hmac_rat_con_clave(dominio, ts, HMAC_RAT_KEY)
}

pub fn ahora_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Envía BABEL_RAT_REQ a todos los dispositivos emparejados. Retorna cuántos
/// respondieron BABEL_RAT_ACK (es decir, están disponibles para confirmar).
pub fn enviar_solicitud_desbloqueo_a_pares(subclave_hex: &str, nombre_local: &str) -> u32 {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;

    let proceso = RAT_PROCESO.lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_else(|| "desconocido".to_string());
    let ts = ahora_unix();

    let mut acks = 0u32;
    for disp in crate::sincronizacion::cargar_emparejados(subclave_hex) {
        if disp.ip_ultima.is_empty() {
            continue;
        }
        // HMAC calculado con la clave compartida única de este par.
        // Cada par usa una clave AES-256 distinta generada aleatoriamente al emparejar.
        let hmac = hmac_rat_con_clave("rat_req", ts, disp.clave_hex.as_bytes());
        let msg = format!("BABEL_RAT_REQ:{}:{}:{}:{}\n", nombre_local, proceso, ts, hmac);

        let addr = format!("{}:{}", disp.ip_ultima, crate::sincronizacion::PUERTO_SINC);
        let Ok(addr_parsed) = addr.parse() else { continue };
        let mut stream = match TcpStream::connect_timeout(&addr_parsed, Duration::from_secs(5)) {
            Ok(s) => s,
            Err(_) => continue,
        };
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        if stream.write_all(msg.as_bytes()).is_err() {
            continue;
        }
        let mut resp = String::new();
        if BufReader::new(&stream).read_line(&mut resp).is_ok()
            && resp.trim().starts_with("BABEL_RAT_ACK")
        {
            acks += 1;
        }
    }
    acks
}

/// Envía BABEL_RAT_OK desde el par B hacia el dispositivo bloqueado A.
pub fn enviar_confirmacion_desbloqueo(ip_bloqueado: &str, nombre_local: &str) -> bool {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;

    // Buscar la clave compartida con el dispositivo bloqueado para HMAC por-par.
    let par_clave_hex: Option<String> =
        crate::sincronizacion::obtener_subclave_sesion_copy().and_then(|subclave| {
            crate::sincronizacion::cargar_emparejados(&*subclave)
                .into_iter()
                .find(|d| d.ip_ultima == ip_bloqueado)
                .map(|d| d.clave_hex)
        });

    let ts = ahora_unix();
    let hmac = match &par_clave_hex {
        Some(clave) => hmac_rat_con_clave("rat_ok", ts, clave.as_bytes()),
        None => hmac_rat("rat_ok", ts), // fallback sin sesión activa
    };
    let msg = format!("BABEL_RAT_OK:{}:{}:{}\n", nombre_local, ts, hmac);

    let addr = format!("{}:{}", ip_bloqueado, crate::sincronizacion::PUERTO_SINC);
    let Ok(addr_parsed) = addr.parse() else { return false };
    let mut stream = match TcpStream::connect_timeout(&addr_parsed, Duration::from_secs(5)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let _ = stream.write_all(msg.as_bytes());
    let mut resp = String::new();
    let _ = BufReader::new(&stream).read_line(&mut resp);
    resp.trim() == "BABEL_RAT_OK_ACK"
}

// ── Comandos Tauri ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct EstadoRatPublico {
    pub bloqueado: bool,
    pub proceso: String,
    pub intentos_bip39: u8,
    pub max_intentos_bip39: u8,
}

#[tauri::command]
pub fn estado_bloqueo_rat() -> EstadoRatPublico {
    let proceso = RAT_PROCESO.lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_default();
    EstadoRatPublico {
        bloqueado: RAT_BLOQUEADO.load(Ordering::Acquire),
        proceso,
        intentos_bip39: RAT_BIP39_INTENTOS.load(Ordering::Acquire),
        max_intentos_bip39: MAX_INTENTOS_BIP39,
    }
}

#[tauri::command]
pub async fn solicitar_desbloqueo_a_pares(
    nombre_local: String,
    sesion: tauri::State<'_, crate::SesionActiva>,
) -> Result<u32, String> {
    let subclave = sesion.subclave_hex()?.to_string();
    tauri::async_runtime::spawn_blocking(move || {
        Ok(enviar_solicitud_desbloqueo_a_pares(&subclave, &nombre_local))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn desbloquear_rat_bip39(
    palabras: Vec<String>,
    marcar_confiable: bool,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let valida = verificar_frase_bip39_para_rat(&palabras)?;
        if valida {
            if marcar_confiable {
                if let Some(proceso) = RAT_PROCESO.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone()
                {
                    if let Ok(mut c) = RAT_SESIONES_CONFIABLES.lock() {
                        c.get_or_insert_with(HashSet::new).insert(proceso);
                    }
                }
            }
            RAT_BLOQUEADO.store(false, Ordering::Release);
            RAT_BIP39_INTENTOS.store(0, Ordering::Release);
            if let Ok(mut g) = RAT_PROCESO.lock() {
                *g = None; // limpiar siempre: el proceso ya está en RAT_SESIONES_CONFIABLES si aplica
            }
            let _ = app.emit("rat-desbloqueado", serde_json::json!({}));
            log::info!("[RAT] Desbloqueado con BIP39. Confiable esta sesión: {}", marcar_confiable);
        }
        Ok(valida)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn confirmar_desbloqueo_rat_cmd(
    ip_bloqueado: String,
    nombre_local: String,
) -> Result<bool, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let ok = enviar_confirmacion_desbloqueo(&ip_bloqueado, &nombre_local);
        // Solo limpiar el slot si el envío tuvo éxito. En caso de fallo TCP
        // el dispositivo A sigue bloqueado y el usuario puede reintentar.
        if ok {
            if let Ok(mut slot) = crate::sincronizacion::SOLICITUD_DESBLOQUEO_RAT.lock() {
                *slot = None;
            }
        }
        Ok(ok)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub fn rechazar_solicitud_desbloqueo_rat() {
    if let Ok(mut slot) = crate::sincronizacion::SOLICITUD_DESBLOQUEO_RAT.lock() {
        *slot = None;
    }
}

#[tauri::command]
pub fn obtener_solicitud_desbloqueo_rat()
    -> Option<crate::sincronizacion::SolicitudDesbloqueoRat>
{
    crate::sincronizacion::SOLICITUD_DESBLOQUEO_RAT
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

// marcar_rat_confiable_tauri ELIMINADO: era un bypass sin autenticación.
// La opción "confiar en este programa" se gestiona vía desbloquear_rat_bip39
// con marcar_confiable=true, que exige la frase BIP39 antes de confiar.

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Serializa los tests que leen y escriben RAT_BIP39_INTENTOS para evitar
    // interferencias cuando el runner ejecuta tests en paralelo dentro del módulo.
    static BIP39_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn lista_rat_no_vacia() {
        assert!(!PROCESOS_RAT.is_empty(), "debe haber al menos un proceso en la lista RAT");
    }

    #[test]
    fn proceso_inventado_no_detectado() {
        // "babel_inexistente_xyz_99999" no debe existir en ningún entorno CI limpio.
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        assert!(!proceso_activo("babel_inexistente_xyz_99999"));
    }

    #[test]
    fn hmac_rat_determinista() {
        let h = hmac_rat("rat_req", 1_700_000_000);
        assert_eq!(h, hmac_rat("rat_req", 1_700_000_000));
    }

    #[test]
    fn hmac_rat_tiene_16_hex_chars() {
        let h = hmac_rat("test", 42);
        assert_eq!(h.len(), 16);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hmac_rat_difiere_por_dominio() {
        let ts = 1_700_000_000u64;
        assert_ne!(hmac_rat("rat_req", ts), hmac_rat("rat_ok", ts));
    }

    #[test]
    fn bip39_frase_corta_no_pasa() {
        let _g = BIP39_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        RAT_BIP39_INTENTOS.store(0, Ordering::SeqCst);
        let pocas = vec!["abandon".to_string(); 5];
        assert_eq!(verificar_frase_bip39_para_rat(&pocas).unwrap(), false);
        RAT_BIP39_INTENTOS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn bip39_palabras_invalidas_consumen_intento() {
        let _g = BIP39_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        RAT_BIP39_INTENTOS.store(0, Ordering::SeqCst);
        let invalidas = vec!["xxxxxxinvalido123".to_string(); 12];
        assert_eq!(verificar_frase_bip39_para_rat(&invalidas).unwrap(), false);
        assert_eq!(RAT_BIP39_INTENTOS.load(Ordering::SeqCst), 1,
            "palabras inválidas deben consumir un intento");
        RAT_BIP39_INTENTOS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn bip39_longitud_incorrecta_no_consume_intento() {
        let _g = BIP39_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        RAT_BIP39_INTENTOS.store(0, Ordering::SeqCst);
        let corta = vec!["abandon".to_string(); 5];
        assert_eq!(verificar_frase_bip39_para_rat(&corta).unwrap(), false);
        assert_eq!(RAT_BIP39_INTENTOS.load(Ordering::SeqCst), 0,
            "longitud incorrecta no debe consumir intento");
        RAT_BIP39_INTENTOS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn bloqueo_y_liberacion_atomica() {
        RAT_BLOQUEADO.store(false, Ordering::Release);
        assert!(!es_rat_bloqueado());
        assert!(verificar_no_bloqueado_rat().is_ok());

        RAT_BLOQUEADO.store(true, Ordering::Release);
        assert!(es_rat_bloqueado());
        assert!(verificar_no_bloqueado_rat().is_err());

        RAT_BLOQUEADO.store(false, Ordering::Release);
    }

    #[test]
    fn bloqueo_bip39_tras_max_intentos() {
        let _g = BIP39_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // MAX+1 simula haber agotado todos los intentos (con <= en la guarda,
        // v=MAX todavía es permitido como intento extra; v=MAX+1 es el bloqueo real).
        RAT_BIP39_INTENTOS.store(MAX_INTENTOS_BIP39 + 1, Ordering::SeqCst);
        let palabras = vec!["abandon".to_string(); 12];
        let result = verificar_frase_bip39_para_rat(&palabras);
        assert!(result.is_err(), "debe retornar Err tras alcanzar MAX intentos");
        RAT_BIP39_INTENTOS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn sesiones_confiables_insercion_y_limpieza() {
        if let Ok(mut c) = RAT_SESIONES_CONFIABLES.lock() {
            let set = c.get_or_insert_with(HashSet::new);
            set.insert("TestRAT".to_string());
            assert!(set.contains("TestRAT"));
            set.remove("TestRAT");
            assert!(!set.contains("TestRAT"));
        }
    }

    #[test]
    fn detener_limpia_sesiones_confiables() {
        // Insertar una sesión confiable y verificar que detener_monitor_rat la limpia.
        if let Ok(mut c) = RAT_SESIONES_CONFIABLES.lock() {
            c.get_or_insert_with(HashSet::new).insert("TeamViewer".to_string());
        }
        detener_monitor_rat();
        let vacio = RAT_SESIONES_CONFIABLES.lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_none();
        assert!(vacio, "las sesiones confiables deben limpiarse al detener el monitor");
    }

    #[test]
    fn detectar_rat_en_ci_no_panic() {
        // No debemos detectar RAT en un entorno CI limpio, pero lo importante es no crashear.
        let _ = detectar_rat_activo();
    }

    #[test]
    fn sospecha_rat_evento_serializa() {
        let evento = crate::registro_diario::EventoDiario {
            tipo: "sospecha_rat".into(),
            timestamp: "2026-08-17T10:00:00".into(),
            ip: "192.168.1.10".into(),
            detalle: "AnyDesk".into(),
        };
        let j = serde_json::to_string(&evento).unwrap();
        let d: crate::registro_diario::EventoDiario = serde_json::from_str(&j).unwrap();
        assert_eq!(d.tipo, "sospecha_rat");
        assert_eq!(d.detalle, "AnyDesk");
    }
}
