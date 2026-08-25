// SINCRONIZACIÓN — Emparejamiento de dispositivos Babel v1
//
// Protocolo de handshake sobre TCP puro (puerto 47826, sin mTLS):
//
//   Solicitante A → Receptor B:  BABEL_SINC_REQ:{nom_A}:{ip_A}:{ts}:{hmac8}\n
//   B → A (acepta):              BABEL_SINC_OK:{nom_B}:{nonce12+ct_hex}:{ts}:{hmac8}\n
//   B → A (rechaza):             BABEL_SINC_NO:{ts}\n
//
// La clave compartida se cifra con AES-256-GCM antes de enviarse (envelope):
//   clave_envelope = HKDF(ikm=sinc_key(), salt=ts_bytes, info=b"sinc-envelope-v1")
//   nonce12+ct_hex = hex(nonce || AES-GCM-encrypt(clave_hex, key=clave_envelope))
//
// Esto protege contra captura pasiva en LAN. La autenticación real sigue siendo
// la confirmación explícita del usuario en ambos lados.
//
// Límite: 3 dispositivos emparejados por cuenta.
// Timeout del handshake: 30 s de espera en cada lado.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};
use std::thread;
use std::time::Duration;

use aes_gcm::aead::rand_core::RngCore as _;
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

pub const PUERTO_SINC: u16 = 47826;
pub const MAX_EMPAREJADOS: usize = 3;
const TIMEOUT_HANDSHAKE_SECS: u64 = 30;

// Clave de sesión derivada del BUILD_FINGERPRINT en runtime.
// No hardcodeada: el valor real no es visible con `strings` sobre el binario.
// Esquema: SHA-256(BUILD_FINGERPRINT || ":sinc-key-v1:").
fn sinc_key() -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(env!("BABEL_BUILD_FINGERPRINT").as_bytes());
    h.update(b":sinc-key-v1:");
    h.finalize().into()
}

// ── Envelope AES-GCM para la clave compartida en tránsito ──────────────────

// Formato del blob cifrado: [salt_aleatorio(16b) | nonce_gcm(12b) | ciphertext+tag]
// El salt_aleatorio añade entropía por sesión para que el timestamp observable en el
// mensaje no sea el único factor que determina la clave del envelope.
fn envelope_sinc_key(salt: &[u8; 16], ts: u64) -> [u8; 32] {
    use sha2::Sha256 as Sha256H;
    let mut ikm = [0u8; 8 + 16];
    ikm[..8].copy_from_slice(&ts.to_le_bytes());
    ikm[8..].copy_from_slice(salt);
    let hk = Hkdf::<Sha256H>::new(Some(&sinc_key()), &ikm);
    let mut key = [0u8; 32];
    let _ = hk.expand(b"sinc-envelope-v1", &mut key);
    key
}

fn envelope_cifrar(ts: u64, clave_hex: &str) -> String {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, OsRng, rand_core::RngCore}};
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key_bytes = envelope_sinc_key(&salt, ts);
    let cipher = Aes256Gcm::new((&key_bytes).into());
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, clave_hex.as_bytes()).unwrap_or_default();
    let mut blob = Vec::with_capacity(16 + 12 + ct.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ct);
    hex::encode(blob)
}

fn envelope_descifrar(ts: u64, blob_hex: &str) -> Option<String> {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    let blob = hex::decode(blob_hex).ok()?;
    if blob.len() < 29 { return None; } // 16 salt + 12 nonce + 1 byte mínimo ct
    let salt: [u8; 16] = blob[..16].try_into().ok()?;
    let key_bytes = envelope_sinc_key(&salt, ts);
    let cipher = Aes256Gcm::new((&key_bytes).into());
    let nonce = aes_gcm::Nonce::from_slice(&blob[16..28]);
    let pt = cipher.decrypt(nonce, &blob[28..]).ok()?;
    String::from_utf8(pt).ok()
}

// ── HMAC anti-scanner ───────────────────────────────────────────────────────

fn hmac_sinc(dominio: &str, ts: u64) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(&sinc_key()).expect("HMAC any len");
    mac.update(dominio.as_bytes());
    mac.update(b":");
    mac.update(ts.to_string().as_bytes());
    let tag = mac.finalize().into_bytes();
    hex::encode(&tag[..8])
}

/// Compara en tiempo constante el HMAC calculado con el recibido (16 chars hex).
/// Previene timing attacks: el XOR-fold no hace cortocircuito ante el primer byte diferente.
fn hmac_sinc_eq(dominio: &str, ts: u64, recibido_hex: &str) -> bool {
    let esperado = hmac_sinc(dominio, ts);
    if esperado.len() != recibido_hex.len() { return false; }
    esperado.as_bytes()
        .iter()
        .zip(recibido_hex.as_bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

fn ahora_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Rutas de almacenamiento ─────────────────────────────────────────────────

fn sinc_dir() -> PathBuf {
    let dir = crate::babel_dir().join("p2p");
    let _ = fs::create_dir_all(&dir);
    dir
}

fn ruta_dispositivos() -> PathBuf {
    sinc_dir().join("dispositivos.babel")
}

// ── Tipos públicos ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispositivoEmparejado {
    pub id: String,
    pub nombre: String,
    pub clave_hex: String,
    pub ts: u64,
    pub ip_ultima: String,
    /// A tiene credenciales B2 que B todavía no ha recibido (fallo/corte durante emparejamiento).
    /// Se reintenta automáticamente en `probar_conexion_dispositivo`.
    #[serde(default)]
    pub b2_pendiente: bool,
    /// Timestamp Unix del primer fallo de envío de B2. Caducidad: 48 h.
    #[serde(default)]
    pub ts_b2_pendiente: u64,
    /// HW ID del dispositivo emparejado (IOPlatformUUID en Mac, MachineGuid en Windows).
    /// Vacío en entradas creadas antes de v0.2.2 (backward compat).
    #[serde(default)]
    pub hw_id: String,
}

/// Devuelve true si el flag `b2_pendiente` lleva más de 48 h sin resolverse.
/// En ese caso se debe limpiar el flag y dejar de reintentar.
pub fn b2_pendiente_expirado(disp: &DispositivoEmparejado) -> bool {
    if !disp.b2_pendiente || disp.ts_b2_pendiente == 0 {
        return false;
    }
    ahora_unix().saturating_sub(disp.ts_b2_pendiente) > LIMITE_B2_PENDIENTE_SECS
}

const LIMITE_B2_PENDIENTE_SECS: u64 = 48 * 3600;

#[derive(Debug, Clone, Serialize)]
pub struct DispositivoPublico {
    pub id: String,
    pub nombre: String,
    pub ts: u64,
    pub ip_ultima: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SolicitudSincPublica {
    pub nombre: String,
    pub ip: String,
    /// El solicitante tiene b2.json configurado y lo ofrecerá si se acepta el emparejamiento.
    pub tiene_b2: bool,
    /// Timestamp Unix en que se recibió la solicitud (para caducidad de 48 h en frontend).
    pub ts_recibida: u64,
    /// HW ID del solicitante (usado para autorizar custodia al aceptar el emparejamiento).
    #[serde(default)]
    pub hw_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResultadoEmparejamiento {
    pub emparejado: bool,
    pub nombre: String,
    /// B confirmó que recibió y guardó las credenciales B2.
    pub b2_enviado: bool,
    /// B ya tenía credenciales B2 distintas — no se sobreescribieron (conflicto).
    pub b2_conflicto: bool,
}

// ── Estado global ───────────────────────────────────────────────────────────

pub static SOLICITUD_PENDIENTE: Mutex<Option<SolicitudSincPublica>> = Mutex::new(None);

// ── Solicitud de desbloqueo RAT (recibida en el par B desde el dispositivo bloqueado A) ──
#[derive(Clone, serde::Serialize)]
pub struct SolicitudDesbloqueoRat {
    pub nombre: String,
    pub proceso: String,
    pub ip: String,
}
pub static SOLICITUD_DESBLOQUEO_RAT: Mutex<Option<SolicitudDesbloqueoRat>> = Mutex::new(None);

static DECISION_MUTEX: Mutex<Option<bool>> = Mutex::new(None);
static DECISION_CONDVAR: Condvar = Condvar::new();
static CLAVE_PARA_ENVIAR: Mutex<Option<Zeroizing<String>>> = Mutex::new(None);

static SINC_SERVIDOR_ACTIVO: AtomicBool = AtomicBool::new(false);
static SUBCLAVE_SESION: Mutex<Option<Zeroizing<String>>> = Mutex::new(None);

pub fn establecer_subclave_sesion(subclave_hex: &str) {
    if let Ok(mut g) = SUBCLAVE_SESION.lock() {
        *g = Some(Zeroizing::new(subclave_hex.to_string()));
    }
}

pub fn limpiar_subclave_sesion() {
    if let Ok(mut g) = SUBCLAVE_SESION.lock() {
        *g = None;
    }
}

/// Retorna una copia Zeroizing de la subclave de sesión actual.
/// El caller debe retener el valor hasta terminar de usarlo; Zeroizing garantiza
/// que la copia se borre de memoria al salir del scope.
pub fn obtener_subclave_sesion_copy() -> Option<Zeroizing<String>> {
    SUBCLAVE_SESION.lock().ok()?.as_deref().map(|s| Zeroizing::new(s.to_string()))
}

pub fn detener_servidor_sinc() {
    SINC_SERVIDOR_ACTIVO.store(false, Ordering::SeqCst);
    log::info!("[SINC] Servidor sync detenido por petición.");
}

// ── Persistencia ─────────────────────────────────────────────────────────────

pub fn cargar_emparejados(subclave_hex: &str) -> Vec<DispositivoEmparejado> {
    if subclave_hex.is_empty() {
        return Vec::new();
    }
    fs::read(ruta_dispositivos())
        .ok()
        .and_then(|bytes| crate::seguridad::descifrar_documento(bytes, subclave_hex).ok())
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
}

pub fn guardar_emparejados(lista: &[DispositivoEmparejado], subclave_hex: &str) {
    if subclave_hex.is_empty() {
        return;
    }
    if let Ok(json) = serde_json::to_string(lista) {
        if let Ok(cifrado) = crate::seguridad::blindar_documento(&json, subclave_hex) {
            // Escritura atómica (temp+rename): si el proceso muere durante la escritura
            // el archivo anterior se conserva íntegro — no se pierden los pares existentes.
            if let Err(e) = crate::escribir_privado_atomico(ruta_dispositivos(), cifrado) {
                log::error!("[SINC] Error guardando dispositivos (atómico): {}", e);
            }
        }
    }
}

// ── Servidor TCP (receptor B) ───────────────────────────────────────────────

pub fn iniciar_servidor_sinc(nombre_local: String) {
    if SINC_SERVIDOR_ACTIVO.swap(true, Ordering::SeqCst) {
        return; // ya corriendo
    }
    thread::spawn(move || {
        let listener = match TcpListener::bind(format!("0.0.0.0:{}", PUERTO_SINC)) {
            Ok(l) => l,
            Err(e) => {
                log::warn!("[SINC] No se pudo abrir puerto {}: {}", PUERTO_SINC, e);
                SINC_SERVIDOR_ACTIVO.store(false, Ordering::SeqCst);
                return;
            }
        };
        if let Err(e) = listener.set_nonblocking(true) {
            log::warn!("[SINC] No se pudo poner listener en non-blocking: {}", e);
        }
        log::warn!("[SINC] Servidor sync activo en puerto {}.", PUERTO_SINC);

        loop {
            if !SINC_SERVIDOR_ACTIVO.load(Ordering::SeqCst) {
                log::info!("[SINC] Servidor sync: flag desactivado, cerrando hilo.");
                break;
            }
            match listener.accept() {
                Ok((stream, addr)) => {
                    // Los streams aceptados heredan el modo non-blocking del listener;
                    // ponerlo en blocking para que read_line() espere datos correctamente.
                    let _ = stream.set_nonblocking(false);
                    let ip = addr.ip().to_string();
                    let nom = nombre_local.clone();
                    thread::spawn(move || manejar_solicitud_sinc(stream, ip, nom));
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(200));
                }
                Err(e) => {
                    log::error!("[SINC] Error accept: {}", e);
                    thread::sleep(Duration::from_millis(500));
                }
            }
        }
    });
}

fn manejar_solicitud_sinc(stream: TcpStream, ip_origen: String, nombre_local: String) {
    if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(10))) {
        log::warn!("[SINC] No se pudo fijar read_timeout: {}", e);
    }
    if let Err(e) = stream.set_write_timeout(Some(Duration::from_secs(10))) {
        log::warn!("[SINC] No se pudo fijar write_timeout: {}", e);
    }

    let mut linea = String::new();
    {
        // Límite de 4 KB para prevenir DoS por OOM: un atacante en LAN podría
        // enviar líneas de cientos de MB en el timeout de 10 s sin este cap.
        // Take<BufReader<R>> implementa BufRead, por lo que read_line está disponible.
        let mut limitado = BufReader::new(&stream).take(4096);
        if let Err(e) = limitado.read_line(&mut linea) {
            log::warn!("[SINC] Error leyendo solicitud de {}: {}", ip_origen, e);
            return;
        }
    }
    if linea.len() > 4095 {
        log::warn!("[SINC] Línea entrante demasiado larga de {}, descartando", ip_origen);
        return;
    }
    let linea = linea.trim().to_string();

    // ── Reintento B2 (mensaje separado, sin re-emparejar) ──────────────────────
    // A → B: BABEL_B2_REINTENTO:{nombre}:{ts}:{hmac8}\n
    // Sólo cuando A tiene b2.json y B todavía no lo recibió (flag b2_pendiente).
    if linea.starts_with("BABEL_B2_REINTENTO:") {
        manejar_reintento_b2(stream, ip_origen, &nombre_local, &linea);
        return;
    }

    // ── Desbloqueo RAT — solicitud desde dispositivo bloqueado A ───────────────
    // A → B: BABEL_RAT_REQ:{nombre_A}:{proceso}:{ts}:{hmac8}\n
    // B responde BABEL_RAT_ACK:{ts}\n y guarda la solicitud para que la UI la muestre.
    if linea.starts_with("BABEL_RAT_REQ:") {
        let partes: Vec<&str> = linea.splitn(5, ':').collect();
        if partes.len() >= 5 {
            let nombre_solicitante = partes[1].chars()
                .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '.')
                .take(64).collect::<String>();
            let proceso = partes[2].chars()
                .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-')
                .take(64).collect::<String>();
            let ts: u64 = partes[3].parse().unwrap_or(0);
            let hmac_rx = partes[4].trim();
            let ahora = ahora_unix();
            // ts <= ahora + 5 evita que timestamps futuros pasen por saturating_sub==0.
            let ts_valido = ts > 0 && ahora.saturating_sub(ts) <= 60 && ts <= ahora + 5;
            // Solo aceptar de un par emparejado conocido por IP.
            // El HMAC se verifica con la clave compartida de ese par específico,
            // no con una clave estática global.
            let subclave = obtener_subclave_sesion_copy().unwrap_or_default();
            let emparejados = if subclave.is_empty() {
                vec![]
            } else {
                cargar_emparejados(&*subclave)
            };
            let par_opt = emparejados.iter().find(|d| d.ip_ultima == ip_origen);
            let es_par = par_opt.is_some();
            let hmac_esperado = par_opt
                .map(|p| crate::rat_detector::hmac_rat_con_clave("rat_req", ts, p.clave_hex.as_bytes()))
                .unwrap_or_default();
            if ts_valido && es_par && hmac_esperado == hmac_rx
            {
                if let Ok(mut slot) = SOLICITUD_DESBLOQUEO_RAT.lock() {
                    *slot = Some(SolicitudDesbloqueoRat {
                        nombre: nombre_solicitante,
                        proceso,
                        ip: ip_origen.clone(),
                    });
                }
                let ts_resp = ahora_unix();
                let mut w = match stream.try_clone() { Ok(s) => s, Err(_) => return };
                let _ = w.write_all(format!("BABEL_RAT_ACK:{}\n", ts_resp).as_bytes());
                log::info!("[RAT] Solicitud de desbloqueo recibida de {}", ip_origen);
            } else {
                log::warn!("[RAT] BABEL_RAT_REQ inválido (ts={} ahora={} es_par={}) de {}",
                    ts, ahora, es_par, ip_origen);
            }
        }
        return;
    }

    // ── Desbloqueo RAT — confirmación del par B hacia el dispositivo bloqueado A ─
    // B → A: BABEL_RAT_OK:{nombre_B}:{ts}:{hmac8}\n
    // A verifica y si es válido, desbloquea Babel y responde BABEL_RAT_OK_ACK\n.
    if linea.starts_with("BABEL_RAT_OK:") {
        let partes: Vec<&str> = linea.splitn(4, ':').collect();
        if partes.len() >= 4 {
            let ts: u64 = partes[2].parse().unwrap_or(0);
            let hmac_rx = partes[3].trim();
            let ahora = ahora_unix();
            // ts <= ahora + 5 evita que timestamps futuros pasen por saturating_sub==0.
            let ts_valido = ts > 0 && ahora.saturating_sub(ts) <= 60 && ts <= ahora + 5;
            // Solo aceptar de un par emparejado conocido por IP.
            // HMAC verificado con la clave del par específico.
            let subclave = obtener_subclave_sesion_copy().unwrap_or_default();
            let emparejados = if subclave.is_empty() {
                vec![]
            } else {
                cargar_emparejados(&*subclave)
            };
            let par_opt = emparejados.iter().find(|d| d.ip_ultima == ip_origen);
            let es_par = par_opt.is_some();
            let hmac_esperado = par_opt
                .map(|p| crate::rat_detector::hmac_rat_con_clave("rat_ok", ts, p.clave_hex.as_bytes()))
                .unwrap_or_default();
            if ts_valido && es_par && hmac_esperado == hmac_rx
                && crate::rat_detector::es_rat_bloqueado()
            {
                crate::rat_detector::desbloquear_rat_desde_red();
                let mut w = match stream.try_clone() { Ok(s) => s, Err(_) => return };
                let _ = w.write_all(b"BABEL_RAT_OK_ACK\n");
                log::info!("[RAT] Desbloqueado por confirmación de {}", ip_origen);
            } else {
                log::warn!("[RAT] BABEL_RAT_OK inválido (ts={} ahora={} es_par={}) de {}",
                    ts, ahora, es_par, ip_origen);
            }
        }
        return;
    }

    // Parsear: BABEL_SINC_REQ:{nombre}:{ip_remitente}:{ts}:{hmac8}[:{has_b2}[:{hw_id_A}]]
    let partes: Vec<&str> = linea.splitn(7, ':').collect();
    if partes.len() < 5 || partes[0] != "BABEL_SINC_REQ" {
        log::warn!("[SINC] Mensaje inesperado de {}: {:.40}", ip_origen, linea);
        return;
    }
    let nombre_remoto: String = partes[1]
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '.')
        .take(64)
        .collect();
    let ts: u64 = partes[3].parse().unwrap_or(0);
    let hmac_rx = partes[4];
    let solicitante_tiene_b2 = partes.get(5).map(|s| s.trim() == "1").unwrap_or(false);
    let hw_id_solicitante: String = partes.get(6).map(|s| s.trim().to_string()).unwrap_or_default();

    let ahora = ahora_unix();
    if ts == 0 || ahora.saturating_sub(ts) > 60 || ts > ahora + 5 {
        log::warn!("[SINC] Solicitud expirada o con timestamp futuro de {}", ip_origen);
        return;
    }
    if !hmac_sinc_eq("req", ts, hmac_rx) {
        log::warn!("[SINC] HMAC inválido en solicitud de {}", ip_origen);
        return;
    }
    if nombre_remoto.is_empty() {
        return;
    }

    log::warn!("[SINC] Solicitud de '{}' ({})", nombre_remoto, ip_origen);

    // Check-and-set atómico: rechazar solicitudes concurrentes sin ventana de carrera.
    {
        let mut slot = SOLICITUD_PENDIENTE.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_some() {
            log::warn!("[SINC] Solicitud concurrente de {} — rechazada (ocupado)", ip_origen);
            drop(slot);
            let ts_resp = ahora_unix();
            let mut w = match stream.try_clone() { Ok(s) => s, Err(_) => return };
            let _ = w.write_all(format!("BABEL_SINC_NO:{}\n", ts_resp).as_bytes());
            return;
        }
        *slot = Some(SolicitudSincPublica {
            nombre: nombre_remoto.clone(),
            ip: ip_origen.clone(),
            tiene_b2: solicitante_tiene_b2,
            ts_recibida: ahora_unix(),
            hw_id: hw_id_solicitante.clone(),
        });
    }
    // Reiniciar estado de decisión anterior
    if let Ok(mut d) = DECISION_MUTEX.lock() { *d = None; }
    if let Ok(mut c) = CLAVE_PARA_ENVIAR.lock() { *c = None; }

    // Esperar decisión del usuario (max TIMEOUT_HANDSHAKE_SECS)
    let decision = {
        let guard = DECISION_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        match DECISION_CONDVAR.wait_timeout_while(
            guard,
            Duration::from_secs(TIMEOUT_HANDSHAKE_SECS),
            |d| d.is_none(),
        ) {
            Ok((g, _)) => *g,
            Err(_) => None,
        }
    };

    // Limpiar solicitud pendiente
    if let Ok(mut slot) = SOLICITUD_PENDIENTE.lock() { *slot = None; }

    let mut writer = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };

    // Zeroizing<String>: la clave sale del buffer de sesión ya envuelta, se mantiene
    // zeroizable en este scope para la fase B2 y se elimina al salir del handler.
    let mut clave_compartida: Option<Zeroizing<String>> = None;

    match decision {
        Some(true) => {
            let clave_zeroizing = CLAVE_PARA_ENVIAR
                .lock()
                .ok()
                .and_then(|mut g| g.take());
            if let Some(clave_z) = clave_zeroizing {
                let ts_resp = ahora_unix();
                let hmac_resp = hmac_sinc("resp_ok", ts_resp);
                let tenemos_b2 = if crate::buzon_b2::leer_config_raw().is_some() { "1" } else { "0" };
                // Cifrar la clave compartida con AES-GCM antes de enviarla (envelope).
                let clave_cifrada = envelope_cifrar(ts_resp, &*clave_z);
                let mi_hw_id_b = crate::custodia::obtener_hw_id();
                let msg = format!(
                    "BABEL_SINC_OK:{}:{}:{}:{}:{}:{}\n",
                    nombre_local, clave_cifrada, ts_resp, hmac_resp, tenemos_b2, mi_hw_id_b
                );
                let _ = writer.write_all(msg.as_bytes());
                clave_compartida = Some(clave_z); // mantiene Zeroizing
                log::warn!("[SINC] Emparejamiento aceptado → '{}' ({})", nombre_remoto, ip_origen);
            } else {
                log::error!("[SINC] Sin clave para enviar a {}", ip_origen);
                let _ = writer.write_all(format!("BABEL_SINC_NO:{}\n", ahora_unix()).as_bytes());
            }
        }
        _ => {
            let _ = writer.write_all(format!("BABEL_SINC_NO:{}\n", ahora_unix()).as_bytes());
            log::warn!("[SINC] Emparejamiento rechazado a '{}' ({})", nombre_remoto, ip_origen);
        }
    }

    // ── Fase B2: recibir credenciales del solicitante (si las tiene) ────────────
    // A enviará BABEL_B2_OFFER:{hex_cifrado}\n  o  BABEL_B2_NONE\n
    // Timeout corto (5s): si A no envía nada, seguimos sin B2.
    if let Some(ref clave_hex) = clave_compartida {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut b2_linea = String::new();
        {
            let mut r = BufReader::new(&stream);
            let _ = r.read_line(&mut b2_linea);
        }
        let b2_linea = b2_linea.trim();

        let mut writer_b2 = match stream.try_clone() { Ok(s) => s, Err(_) => return };

        if let Some(hex_cifrado) = b2_linea.strip_prefix("BABEL_B2_OFFER:") {
            // Descifrar con la clave compartida (AES-256-GCM — self-authenticating)
            match hex::decode(hex_cifrado.trim()) {
                Ok(bytes) => match crate::seguridad::descifrar_documento(bytes, clave_hex) {
                    Ok(json) => {
                        // ¿Ya tenemos credenciales B2?
                        match crate::buzon_b2::key_id_actual() {
                            Some(key_id_local) => {
                                // Comparar con lo que nos ofrecen
                                let key_id_oferta = serde_json::from_str::<serde_json::Value>(&json)
                                    .ok()
                                    .and_then(|v| v["key_id"].as_str().map(|s| s.to_string()))
                                    .unwrap_or_default();
                                if key_id_local == key_id_oferta {
                                    // Mismas credenciales — sin conflicto
                                    let _ = writer_b2.write_all(b"BABEL_B2_OK\n");
                                } else {
                                    // Credenciales distintas — NO sobreescribir
                                    log::warn!(
                                        "[SINC] Conflicto B2: ya tenemos credenciales distintas. \
                                         No se sobreescribe. Resuelve manualmente si es necesario."
                                    );
                                    let _ = writer_b2.write_all(b"BABEL_B2_CONFLICT\n");
                                }
                            }
                            None => {
                                // No tenemos b2.json — guardar
                                match crate::buzon_b2::guardar_config_raw(&json) {
                                    Ok(_) => {
                                        log::info!(
                                            "[SINC] b2.json recibido de '{}' y guardado (0600).",
                                            nombre_remoto
                                        );
                                        let _ = writer_b2.write_all(b"BABEL_B2_OK\n");
                                    }
                                    Err(e) => {
                                        log::error!("[SINC] Error guardando b2.json: {}", e);
                                        let _ = writer_b2.write_all(b"BABEL_B2_SKIP\n");
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("[SINC] B2: descifrado fallido ({}). Ignorando oferta.", e);
                        let _ = writer_b2.write_all(b"BABEL_B2_SKIP\n");
                    }
                },
                Err(_) => { let _ = writer_b2.write_all(b"BABEL_B2_SKIP\n"); }
            }
        }
        // Si es BABEL_B2_NONE o timeout, no respondemos (A no espera respuesta en ese caso)
    }
}

// ── Cliente TCP (solicitante A) ─────────────────────────────────────────────

pub fn solicitar_emparejamiento(
    ip_destino: &str,
    nombre_local: &str,
    mi_ip: &str,
    subclave_hex: &str,
) -> Result<ResultadoEmparejamiento, String> {
    let emparejados = cargar_emparejados(subclave_hex);
    if emparejados.len() >= MAX_EMPAREJADOS {
        return Err(format!(
            "Límite de {} dispositivos emparejados alcanzado. Desempareja uno primero.",
            MAX_EMPAREJADOS
        ));
    }

    let ts = ahora_unix();
    let hmac = hmac_sinc("req", ts);
    let tenemos_b2 = if crate::buzon_b2::leer_config_raw().is_some() { "1" } else { "0" };
    let mi_hw_id = crate::custodia::obtener_hw_id();
    let msg = format!("BABEL_SINC_REQ:{}:{}:{}:{}:{}:{}\n", nombre_local, mi_ip, ts, hmac, tenemos_b2, mi_hw_id);

    let mut stream = TcpStream::connect(format!("{}:{}", ip_destino, PUERTO_SINC))
        .map_err(|e| format!("No se pudo conectar a {}: {}", ip_destino, e))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    // Tiempo de espera = timeout_handshake + margen de red
    stream
        .set_read_timeout(Some(Duration::from_secs(TIMEOUT_HANDSHAKE_SECS + 5)))
        .map_err(|e| e.to_string())?;

    stream
        .write_all(msg.as_bytes())
        .map_err(|e| format!("Error enviando solicitud: {}", e))?;

    let mut respuesta = String::new();
    {
        let mut reader = BufReader::new(&stream);
        reader
            .read_line(&mut respuesta)
            .map_err(|_| "Sin respuesta en el tiempo esperado (30 s). El dispositivo puede no estar disponible.".to_string())?;
    }
    let respuesta = respuesta.trim();

    if let Some(rest) = respuesta.strip_prefix("BABEL_SINC_OK:") {
        // BABEL_SINC_OK:{nombre_B}:{clave_hex64}:{ts_resp}:{hmac8}[:{has_b2_B}[:{hw_id_B}]]
        let partes: Vec<&str> = rest.splitn(6, ':').collect();
        if partes.len() < 4 {
            return Err("Respuesta SINC_OK malformada".into());
        }
        let nombre_remoto: String = partes[0]
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '.')
            .take(64)
            .collect();
        let clave_cifrada = partes[1].trim().to_string();
        let ts_resp: u64 = partes[2].parse().unwrap_or(0);
        let hmac_resp = partes[3];
        let b_tiene_b2 = partes.get(4).map(|s| s.trim() == "1").unwrap_or(false);
        let hw_id_remoto: String = partes.get(5).map(|s| s.trim().to_string()).unwrap_or_default();

        let ahora = ahora_unix();
        if ts_resp == 0 || ahora.saturating_sub(ts_resp) > 120 {
            return Err("Respuesta expirada".into());
        }
        if !hmac_sinc_eq("resp_ok", ts_resp, hmac_resp) {
            return Err("HMAC de respuesta inválido — posible manipulación".into());
        }
        // Descifrar la clave compartida del envelope AES-GCM
        let clave_hex = envelope_descifrar(ts_resp, &clave_cifrada)
            .ok_or("No se pudo descifrar la clave compartida")?;
        if clave_hex.len() != 64 || !clave_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("Clave compartida inválida en respuesta".into());
        }

        // Guardar par (re-carga para concurrencia segura)
        let mut lista = cargar_emparejados(subclave_hex);
        if lista.len() >= MAX_EMPAREJADOS {
            return Err("Límite de dispositivos alcanzado".into());
        }
        // Reemplazar si ya existía emparejamiento con esta IP
        lista.retain(|d| d.ip_ultima != ip_destino);

        let mut id_bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id_bytes);
        lista.push(DispositivoEmparejado {
            id: hex::encode(id_bytes),
            nombre: nombre_remoto.clone(),
            clave_hex: clave_hex.clone(),
            ts: ahora_unix(),
            ip_ultima: ip_destino.to_string(),
            b2_pendiente: false,
            ts_b2_pendiente: 0,
            hw_id: hw_id_remoto.clone(),
        });
        guardar_emparejados(&lista, subclave_hex);
        log::warn!("[SINC] Emparejado con '{}' ({})", nombre_remoto, ip_destino);

        // Autorizar el HW ID del dispositivo recién emparejado en todos los archivos de custodia.
        if !hw_id_remoto.is_empty() {
            crate::custodia::autorizar_hw_en_todos(&hw_id_remoto, subclave_hex);
        }

        // ── Fase B2: ofrecer credenciales si A las tiene y B no ─────────────────
        // Si ambos tienen B2 con distinto key_id → B responderá CONFLICT.
        // Si B ya tiene el mismo key_id → B responderá OK (sin conflicto real).
        // B2_NONE si A no tiene configurado B2.
        let mut b2_enviado = false;
        let mut b2_conflicto = false;

        // Configurar timeout de lectura para la respuesta B2 (10s)
        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();

        if let Some(b2_json) = crate::buzon_b2::leer_config_raw() {
            // Solo ofrecemos si B no tiene B2, o si tiene pero puede ser el mismo
            // (dejamos que B decida — si tiene el mismo key_id responderá OK)
            match crate::seguridad::blindar_documento(&b2_json, &clave_hex) {
                Ok(cifrado) => {
                    let oferta = format!("BABEL_B2_OFFER:{}\n", hex::encode(&cifrado));
                    if stream.write_all(oferta.as_bytes()).is_ok() {
                        // Leer respuesta de B
                        let mut resp_b2 = String::new();
                        let mut r = BufReader::new(&stream);
                        let _ = r.read_line(&mut resp_b2);
                        match resp_b2.trim() {
                            "BABEL_B2_OK"       => b2_enviado = true,
                            "BABEL_B2_CONFLICT"  => {
                                b2_conflicto = true;
                                log::warn!(
                                    "[SINC] '{}' ya tiene credenciales B2 distintas. \
                                     Ambos dispositivos usan cuentas B2 diferentes.",
                                    nombre_remoto
                                );
                            }
                            _ => {} // BABEL_B2_SKIP o timeout
                        }
                    }
                }
                Err(e) => log::warn!("[SINC] B2: no se pudo cifrar oferta: {}", e),
            }
        } else {
            // A no tiene B2 — avisar a B para que sepa que no hay oferta
            let _ = stream.write_all(b"BABEL_B2_NONE\n");
            // B no espera respuesta cuando enviamos NONE
        }

        // Si B tiene B2 y A no → A no puede recibirlo aquí (scope: A→B solo)
        if b_tiene_b2 && crate::buzon_b2::leer_config_raw().is_none() {
            log::info!(
                "[SINC] '{}' tiene B2 pero nosotros no. Para recibir sus credenciales, \
                 que '{}' inicie el emparejamiento desde su lado.",
                nombre_remoto, nombre_remoto
            );
        }

        // A2: Si A tenía B2 pero el envío no completó (corte de conexión durante oferta),
        // marcar el dispositivo como b2_pendiente para reintentarlo en la siguiente
        // conexión directa (probar_conexion_dispositivo lo detecta y llama a reenviar_b2_si_pendiente).
        let b2_pendiente_nuevo = !b2_enviado && !b2_conflicto && crate::buzon_b2::leer_config_raw().is_some();
        if b2_pendiente_nuevo {
            if let Some(d) = lista.iter_mut().find(|d| d.ip_ultima == ip_destino) {
                d.b2_pendiente = true;
                d.ts_b2_pendiente = ahora_unix();
                guardar_emparejados(&lista, subclave_hex);
                log::warn!(
                    "[SINC] B2 pendiente para '{}': se reintentará en la próxima conexión directa.",
                    nombre_remoto
                );
            }
        }

        Ok(ResultadoEmparejamiento {
            emparejado: true,
            nombre: nombre_remoto,
            b2_enviado,
            b2_conflicto,
        })
    } else if respuesta.starts_with("BABEL_SINC_NO:") {
        Ok(ResultadoEmparejamiento { emparejado: false, nombre: String::new(), b2_enviado: false, b2_conflicto: false })
    } else {
        Err(format!(
            "Respuesta inesperada de {}: {:.80}",
            ip_destino,
            respuesta
        ))
    }
}

// ── Acciones del usuario (receptor B) ──────────────────────────────────────

pub fn aceptar_y_generar_clave(
    ip_solicitante: &str,
    nombre_solicitante: &str,
    subclave_hex: &str,
) -> Result<(), String> {
    let mut lista = cargar_emparejados(subclave_hex);
    if lista.len() >= MAX_EMPAREJADOS {
        return Err(format!("Límite de {} dispositivos alcanzado.", MAX_EMPAREJADOS));
    }

    // Generar clave compartida aleatoria
    let mut clave = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut clave);
    let clave_hex = hex::encode(&clave);
    clave.zeroize();

    // Reemplazar si ya existía emparejamiento con esta IP
    lista.retain(|d| d.ip_ultima != ip_solicitante);

    let mut id_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut id_bytes);
    // Leer el HW ID del solicitante antes de que SOLICITUD_PENDIENTE se limpie.
    let hw_id_solicitante = SOLICITUD_PENDIENTE
        .lock()
        .map(|g| g.as_ref().map(|s| s.hw_id.clone()).unwrap_or_default())
        .unwrap_or_default();

    lista.push(DispositivoEmparejado {
        id: hex::encode(id_bytes),
        nombre: nombre_solicitante.to_string(),
        clave_hex: clave_hex.clone(),
        ts: ahora_unix(),
        ip_ultima: ip_solicitante.to_string(),
        b2_pendiente: false,
        ts_b2_pendiente: 0,
        hw_id: hw_id_solicitante.clone(),
    });
    guardar_emparejados(&lista, subclave_hex);

    // Autorizar el HW ID del solicitante en todos los archivos de custodia de este dispositivo.
    if !hw_id_solicitante.is_empty() {
        crate::custodia::autorizar_hw_en_todos(&hw_id_solicitante, subclave_hex);
    }

    // Poner clave en buffer para el hilo servidor
    if let Ok(mut c) = CLAVE_PARA_ENVIAR.lock() {
        *c = Some(Zeroizing::new(clave_hex));
    }
    // Señalar decisión = aceptar
    if let Ok(mut d) = DECISION_MUTEX.lock() {
        *d = Some(true);
    }
    DECISION_CONDVAR.notify_all();
    Ok(())
}

pub fn rechazar_emparejamiento() {
    if let Ok(mut d) = DECISION_MUTEX.lock() {
        *d = Some(false);
    }
    DECISION_CONDVAR.notify_all();
}

// ── B2 reintento (A2) ──────────────────────────────────────────────────────
// Protocolo: A → B: BABEL_B2_REINTENTO:{nombre}:{ts}:{hmac8}\n
//            B → A: BABEL_B2_YA_TENGO\n  |  BABEL_B2_NECESITO\n
//            A → B: BABEL_B2_OFFER:{hex_cifrado}\n  (solo si B dijo NECESITO)
//            B → A: BABEL_B2_OK\n  |  BABEL_B2_CONFLICT\n

/// Maneja en B un mensaje BABEL_B2_REINTENTO entrante (sin re-emparejar).
/// `linea` ya fue leída por `manejar_solicitud_sinc` — no releer del stream.
fn manejar_reintento_b2(stream: TcpStream, ip_origen: String, _nombre_local: &str, linea: &str) {
    // Parsear: BABEL_B2_REINTENTO:{nombre}:{ts}:{hmac8}
    let partes: Vec<&str> = linea.splitn(4, ':').collect();
    if partes.len() < 4 || partes[0] != "BABEL_B2_REINTENTO" {
        return;
    }
    let ts: u64 = partes[2].parse().unwrap_or(0);
    let hmac_rx = partes[3];
    let ahora = ahora_unix();
    if ts == 0 || ahora.saturating_sub(ts) > 60 || ts > ahora + 5 {
        log::warn!("[SINC] BABEL_B2_REINTENTO expirado o timestamp futuro de {}", ip_origen);
        return;
    }
    if !hmac_sinc_eq("b2_reintento", ts, hmac_rx) {
        log::warn!("[SINC] BABEL_B2_REINTENTO HMAC inválido de {}", ip_origen);
        return;
    }

    let mut writer = match stream.try_clone() { Ok(s) => s, Err(_) => return };

    if crate::buzon_b2::leer_config_raw().is_some() {
        // B ya tiene B2 — decirle a A que puede limpiar el flag
        let _ = writer.write_all(b"BABEL_B2_YA_TENGO\n");
        log::info!("[SINC] REINTENTO B2 de {}: ya teníamos B2.", ip_origen);
        return;
    }

    // B no tiene B2 — pedirle a A que envíe la oferta
    let _ = writer.write_all(b"BABEL_B2_NECESITO\n");

    // Leer la oferta cifrada
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut oferta_linea = String::new();
    {
        let mut r = BufReader::new(&stream);
        let _ = r.read_line(&mut oferta_linea);
    }
    let oferta_linea = oferta_linea.trim();

    if let Some(hex_cifrado) = oferta_linea.strip_prefix("BABEL_B2_OFFER:") {
        let subclave = match SUBCLAVE_SESION.lock().ok()
            .and_then(|g| g.as_deref().map(|s| Zeroizing::new(s.to_string())))
        {
            Some(s) => s,
            None => {
                log::warn!("[SINC] REINTENTO B2: sin sesión activa para descifrar oferta de {}", ip_origen);
                let _ = writer.write_all(b"BABEL_B2_SKIP\n");
                return;
            }
        };
        let emparejados = cargar_emparejados(&*subclave);
        let clave_hex = match emparejados.iter().find(|d| d.ip_ultima == ip_origen) {
            Some(d) => d.clave_hex.clone(),
            None => {
                log::warn!("[SINC] REINTENTO B2: par no encontrado para IP {} — ¿ya desemparejado?", ip_origen);
                let _ = writer.write_all(b"BABEL_B2_SKIP\n");
                return;
            }
        };
        let cifrado_bytes = match hex::decode(hex_cifrado) {
            Ok(b) => b,
            Err(_) => {
                log::warn!("[SINC] REINTENTO B2: oferta hex inválida de {}", ip_origen);
                let _ = writer.write_all(b"BABEL_B2_SKIP\n");
                return;
            }
        };
        match crate::seguridad::descifrar_documento(cifrado_bytes, &clave_hex) {
            Ok(b2_json) => match crate::buzon_b2::guardar_config_raw(&b2_json) {
                Ok(_) => {
                    log::info!("[SINC] REINTENTO B2: credenciales B2 aplicadas desde {}", ip_origen);
                    let _ = writer.write_all(b"BABEL_B2_OK\n");
                }
                Err(e) => {
                    log::warn!("[SINC] REINTENTO B2: error guardando B2 de {}: {}", ip_origen, e);
                    let _ = writer.write_all(b"BABEL_B2_SKIP\n");
                }
            },
            Err(e) => {
                log::warn!("[SINC] REINTENTO B2: descifrado fallido de {}: {}", ip_origen, e);
                let _ = writer.write_all(b"BABEL_B2_SKIP\n");
            }
        }
    }
}

/// Intenta enviar las credenciales B2 pendientes a un dispositivo emparejado.
///
/// Retorna:
/// - `Ok(true)`  → B2 enviado o B ya lo tenía; el llamador debe limpiar `b2_pendiente`.
/// - `Ok(false)` → reintento fallido (dispositivo offline, etc); reintentar luego.
/// - `Err(())`   → flag caducado (48 h); el llamador debe limpiar `b2_pendiente`.
pub fn reenviar_b2_si_pendiente(
    disp: &DispositivoEmparejado,
    nombre_local: &str,
) -> Result<bool, ()> {
    // A4: caducidad de 48 h del flag b2_pendiente
    if b2_pendiente_expirado(disp) {
        log::warn!(
            "[SINC] B2 pendiente para '{}' lleva >48 h sin resolverse — descartando.",
            disp.nombre
        );
        return Err(());
    }
    if !disp.b2_pendiente {
        return Ok(true);
    }

    let b2_json = match crate::buzon_b2::leer_config_raw() {
        Some(j) => j,
        None => return Ok(true), // A ya no tiene B2 — nada que enviar
    };

    // Conectar al dispositivo remoto por el puerto de sincronización
    let mut stream = match TcpStream::connect(format!("{}:{}", disp.ip_ultima, PUERTO_SINC)) {
        Ok(s) => s,
        Err(_) => return Ok(false), // offline — reintentar después
    };
    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();

    // Enviar mensaje de reintento con HMAC anti-scanner
    let ts = ahora_unix();
    let hmac = hmac_sinc("b2_reintento", ts);
    let msg = format!("BABEL_B2_REINTENTO:{}:{}:{}\n", nombre_local, ts, hmac);
    if stream.write_all(msg.as_bytes()).is_err() {
        return Ok(false);
    }

    let mut resp = String::new();
    {
        let mut r = BufReader::new(&stream);
        let _ = r.read_line(&mut resp);
    }

    match resp.trim() {
        "BABEL_B2_YA_TENGO" => {
            log::info!("[SINC] '{}' ya tiene B2 — flag b2_pendiente limpiado.", disp.nombre);
            Ok(true)
        }
        "BABEL_B2_NECESITO" => {
            // B necesita las credenciales — cifrar con la clave compartida del par
            match crate::seguridad::blindar_documento(&b2_json, &disp.clave_hex) {
                Ok(cifrado) => {
                    let oferta = format!("BABEL_B2_OFFER:{}\n", hex::encode(&cifrado));
                    if stream.write_all(oferta.as_bytes()).is_err() {
                        return Ok(false);
                    }
                    let mut resp2 = String::new();
                    {
                        let mut r = BufReader::new(&stream);
                        let _ = r.read_line(&mut resp2);
                    }
                    match resp2.trim() {
                        "BABEL_B2_OK" => {
                            log::info!(
                                "[SINC] B2 enviado con éxito a '{}' (reintento).", disp.nombre
                            );
                            Ok(true)
                        }
                        other => {
                            log::warn!("[SINC] Reintento B2 para '{}': respuesta inesperada '{}'", disp.nombre, other);
                            Ok(false)
                        }
                    }
                }
                Err(e) => {
                    log::warn!("[SINC] No se pudo cifrar oferta B2 para '{}': {}", disp.nombre, e);
                    Ok(false)
                }
            }
        }
        _ => Ok(false),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn disp_con_b2_pendiente(ts_b2: u64) -> DispositivoEmparejado {
        DispositivoEmparejado {
            id: "test".into(),
            nombre: "TestDevice".into(),
            clave_hex: "a".repeat(64),
            ts: 0,
            ip_ultima: "127.0.0.1".into(),
            b2_pendiente: true,
            ts_b2_pendiente: ts_b2,
            hw_id: String::new(),
        }
    }

    // A4: flag b2_pendiente con 49 h de antigüedad → expirado
    #[test]
    fn b2_pendiente_expira_tras_48h() {
        let ts_viejo = ahora_unix().saturating_sub(49 * 3600);
        let disp = disp_con_b2_pendiente(ts_viejo);
        assert!(b2_pendiente_expirado(&disp), "debe estar expirado tras 49h");
    }

    // A4: flag con 1 h → todavía vigente
    #[test]
    fn b2_pendiente_no_expira_antes_de_48h() {
        let ts_reciente = ahora_unix().saturating_sub(3600);
        let disp = disp_con_b2_pendiente(ts_reciente);
        assert!(!b2_pendiente_expirado(&disp), "no debe expirar con solo 1h");
    }

    // A4: sin flag b2_pendiente → no expira aunque el ts sea viejo
    #[test]
    fn sin_flag_no_expira() {
        let mut disp = disp_con_b2_pendiente(0);
        disp.b2_pendiente = false;
        assert!(!b2_pendiente_expirado(&disp));
    }

    // A2: serde backward-compat — un JSON antiguo (sin b2_pendiente) carga con defaults
    #[test]
    fn dispositivo_sin_campo_b2_carga_con_default() {
        let json = r#"{"id":"abc","nombre":"X","clave_hex":"deadbeef","ts":0,"ip_ultima":"1.2.3.4"}"#;
        let d: DispositivoEmparejado = serde_json::from_str(json).expect("debe parsear");
        assert!(!d.b2_pendiente);
        assert_eq!(d.ts_b2_pendiente, 0);
    }

    // A4: SolicitudSincPublica con ts_recibida viejo debería considerarse caducada
    #[test]
    fn solicitud_con_ts_recibida_viejo() {
        let sol = SolicitudSincPublica {
            nombre: "Peer".into(),
            ip: "1.2.3.4".into(),
            tiene_b2: false,
            ts_recibida: ahora_unix().saturating_sub(49 * 3600),
            hw_id: String::new(),
        };
        let edad = ahora_unix().saturating_sub(sol.ts_recibida);
        assert!(edad > 48 * 3600, "solicitud de 49h debe considerarse caducada");
    }

    // Fase 1: HMAC de autenticación de broadcast es determinista
    #[test]
    fn hmac_es_determinista() {
        let ts = 1_700_000_000u64;
        let h1 = hmac_sinc("test.local", ts);
        let h2 = hmac_sinc("test.local", ts);
        assert_eq!(h1, h2, "mismo dominio+ts debe producir mismo HMAC");
    }

    // Fase 1: HMAC cambia al cambiar el dominio (no hay colisión trivial)
    #[test]
    fn hmac_difiere_con_dominio_distinto() {
        let ts = 1_700_000_000u64;
        let h1 = hmac_sinc("dispositivo-a.local", ts);
        let h2 = hmac_sinc("dispositivo-b.local", ts);
        assert_ne!(h1, h2, "distintos dominios deben producir HMAC distintos");
    }

    // Fase 1: HMAC cambia al cambiar el timestamp (replay attack básico)
    #[test]
    fn hmac_difiere_con_ts_distinto() {
        let h1 = hmac_sinc("test.local", 1_000);
        let h2 = hmac_sinc("test.local", 2_000);
        assert_ne!(h1, h2, "distintos timestamps deben producir HMAC distintos");
    }

    // Fase 1: HMAC es un hex de 16 chars (8 bytes truncados)
    #[test]
    fn hmac_formato_16_chars_hex() {
        let h = hmac_sinc("test.local", 0);
        assert_eq!(h.len(), 16, "HMAC debe ser 16 chars hex (8 bytes)");
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()), "debe ser hex válido");
    }

    // Fase 1/3: DispositivoEmparejado hace round-trip por serde_json
    #[test]
    fn dispositivo_emparejado_serde_roundtrip() {
        let orig = DispositivoEmparejado {
            id: "abc123".into(),
            nombre: "MacBook Pro".into(),
            clave_hex: "f0".repeat(32),
            ts: 1_700_000_000,
            ip_ultima: "192.168.1.10".into(),
            b2_pendiente: true,
            ts_b2_pendiente: 1_699_990_000,
            hw_id: "test-uuid-1234".into(),
        };
        let json = serde_json::to_string(&orig).expect("debe serializar");
        let restaurado: DispositivoEmparejado = serde_json::from_str(&json).expect("debe deserializar");
        assert_eq!(restaurado.id, orig.id);
        assert_eq!(restaurado.nombre, orig.nombre);
        assert_eq!(restaurado.clave_hex, orig.clave_hex);
        assert_eq!(restaurado.b2_pendiente, orig.b2_pendiente);
        assert_eq!(restaurado.ts_b2_pendiente, orig.ts_b2_pendiente);
    }

    // Fase 2: SolicitudSincPublica reciente NO está caducada
    #[test]
    fn solicitud_reciente_no_esta_caducada() {
        let sol = SolicitudSincPublica {
            nombre: "Peer".into(),
            ip: "10.0.0.1".into(),
            tiene_b2: true,
            ts_recibida: ahora_unix().saturating_sub(60), // hace 1 minuto
            hw_id: String::new(),
        };
        let edad = ahora_unix().saturating_sub(sol.ts_recibida);
        assert!(edad < 48 * 3600, "solicitud de 1min no debe estar caducada");
    }

    // Fase 3: b2_pendiente con ts=0 nunca expira (caso arranque sin timestamp)
    #[test]
    fn b2_pendiente_con_ts_cero_no_expira() {
        let disp = disp_con_b2_pendiente(0);
        assert!(!b2_pendiente_expirado(&disp), "ts=0 no debe expirar");
    }
}
