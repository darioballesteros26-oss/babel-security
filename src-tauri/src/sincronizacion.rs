// SINCRONIZACIÓN — Emparejamiento de dispositivos Babel v1
//
// Protocolo de handshake sobre TCP puro (puerto 47826, sin mTLS):
//
//   Solicitante A → Receptor B:  BABEL_SINC_REQ:{nom_A}:{ip_A}:{ts}:{hmac8}\n
//   B → A (acepta):              BABEL_SINC_OK:{nom_B}:{clave_hex64}:{ts}:{hmac8}\n
//   B → A (rechaza):             BABEL_SINC_NO:{ts}\n
//
// La autenticación real es la confirmación explícita del usuario en ambos lados.
// El HMAC protege contra escáneres de red genéricos. La clave compartida (32 bytes
// aleatorios de OsRng) se transmite dentro del canal TCP local y se almacena
// cifrada con AES-256-GCM en ~/Babel/p2p/dispositivos.babel.
//
// Límite: 3 dispositivos emparejados por cuenta.
// Timeout del handshake: 30 s de espera en cada lado.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};
use std::thread;
use std::time::Duration;

use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

pub const PUERTO_SINC: u16 = 47826;
pub const MAX_EMPAREJADOS: usize = 3;
const TIMEOUT_HANDSHAKE_SECS: u64 = 30;
const APP_SINC_KEY: &[u8] = b"babel-sinc-handshake-2026-v1";

// ── HMAC anti-scanner ───────────────────────────────────────────────────────

fn hmac_sinc(dominio: &str, ts: u64) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(APP_SINC_KEY).expect("HMAC any len");
    mac.update(dominio.as_bytes());
    mac.update(b":");
    mac.update(ts.to_string().as_bytes());
    let tag = mac.finalize().into_bytes();
    hex::encode(&tag[..8])
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
}

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

static DECISION_MUTEX: Mutex<Option<bool>> = Mutex::new(None);
static DECISION_CONDVAR: Condvar = Condvar::new();
static CLAVE_PARA_ENVIAR: Mutex<Option<Zeroizing<String>>> = Mutex::new(None);

static SINC_SERVIDOR_ACTIVO: AtomicBool = AtomicBool::new(false);

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
            let _ = crate::escribir_privado(ruta_dispositivos(), cifrado);
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
        let mut reader = BufReader::new(&stream);
        if let Err(e) = reader.read_line(&mut linea) {
            log::warn!("[SINC] Error leyendo solicitud de {}: {}", ip_origen, e);
            return;
        }
    }
    let linea = linea.trim().to_string();

    // Parsear: BABEL_SINC_REQ:{nombre}:{ip_remitente}:{ts}:{hmac8}[:{has_b2}]
    let partes: Vec<&str> = linea.splitn(6, ':').collect();
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

    let ahora = ahora_unix();
    if ts == 0 || ahora.saturating_sub(ts) > 60 {
        log::warn!("[SINC] Solicitud expirada de {}", ip_origen);
        return;
    }
    if hmac_sinc("req", ts) != hmac_rx {
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

    let mut clave_compartida: Option<String> = None;

    match decision {
        Some(true) => {
            let clave_zeroizing = CLAVE_PARA_ENVIAR
                .lock()
                .ok()
                .and_then(|mut g| g.take());
            if let Some(clave_z) = clave_zeroizing {
                let ts_resp = ahora_unix();
                let hmac_resp = hmac_sinc("resp_ok", ts_resp);
                // Indicamos si nosotros (B) tenemos b2.json para que A lo sepa
                let tenemos_b2 = if crate::buzon_b2::leer_config_raw().is_some() { "1" } else { "0" };
                let msg = format!(
                    "BABEL_SINC_OK:{}:{}:{}:{}:{}\n",
                    nombre_local, *clave_z, ts_resp, hmac_resp, tenemos_b2
                );
                let _ = writer.write_all(msg.as_bytes());
                clave_compartida = Some((*clave_z).clone());
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
    let msg = format!("BABEL_SINC_REQ:{}:{}:{}:{}:{}\n", nombre_local, mi_ip, ts, hmac, tenemos_b2);

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
        // BABEL_SINC_OK:{nombre_B}:{clave_hex64}:{ts_resp}:{hmac8}[:{has_b2_B}]
        let partes: Vec<&str> = rest.splitn(5, ':').collect();
        if partes.len() < 4 {
            return Err("Respuesta SINC_OK malformada".into());
        }
        let nombre_remoto: String = partes[0]
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '.')
            .take(64)
            .collect();
        let clave_hex = partes[1].trim().to_string();
        let ts_resp: u64 = partes[2].parse().unwrap_or(0);
        let hmac_resp = partes[3];
        let b_tiene_b2 = partes.get(4).map(|s| s.trim() == "1").unwrap_or(false);

        let ahora = ahora_unix();
        if ts_resp == 0 || ahora.saturating_sub(ts_resp) > 120 {
            return Err("Respuesta expirada".into());
        }
        if hmac_sinc("resp_ok", ts_resp) != hmac_resp {
            return Err("HMAC de respuesta inválido — posible manipulación".into());
        }
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

        let mut id_bytes = [0u8; 6];
        rand::rngs::OsRng.fill_bytes(&mut id_bytes);
        lista.push(DispositivoEmparejado {
            id: hex::encode(id_bytes),
            nombre: nombre_remoto.clone(),
            clave_hex: clave_hex.clone(),
            ts: ahora_unix(),
            ip_ultima: ip_destino.to_string(),
        });
        guardar_emparejados(&lista, subclave_hex);
        log::warn!("[SINC] Emparejado con '{}' ({})", nombre_remoto, ip_destino);

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

    let mut id_bytes = [0u8; 6];
    rand::rngs::OsRng.fill_bytes(&mut id_bytes);
    lista.push(DispositivoEmparejado {
        id: hex::encode(id_bytes),
        nombre: nombre_solicitante.to_string(),
        clave_hex: clave_hex.clone(),
        ts: ahora_unix(),
        ip_ultima: ip_solicitante.to_string(),
    });
    guardar_emparejados(&lista, subclave_hex);

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
