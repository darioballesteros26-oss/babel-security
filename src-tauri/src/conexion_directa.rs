// Fase 2: conexión directa entre dispositivos emparejados (hole punching UDP)
//
// Arquitectura de intercambio de direcciones:
// - Puerto TCP 47827 para negociación (uno por dispositivo, paralelo al 47826 de pairing)
// - Iniciador (A) conecta a B usando ip_ultima almacenada del emparejamiento
// - Ambos obtienen su IP:puerto público vía STUN (stun.l.google.com:19302, implementado
//   manualmente — ~40 líneas, sin crate adicional, evita dependencias pesadas de webrtc)
// - Intercambian tanto STUN addr como local port UDP en el canal TCP
// - A y B envían HP ("BHP") a la STUN addr del otro Y a la IP LAN directa del otro
//   → cubre hairpin NAT (mismo router) y NAT simétrico/cono
// - Si ningún paquete llega en HOLE_PUNCH_DURACION_MS → mensaje claro de fallo
// - Si llega → A envía test cifrado AES-256-GCM con la clave de Fase 1, B responde ACK
//
// Limitación conocida: NAT simétrico puro sin TURN relay falla. Se informa al usuario.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::Serialize;
use sha2::Sha256;

pub const PUERTO_CONEX: u16 = 47827;
const APP_CONEX_KEY: &[u8] = b"babel-conex-2026-v1";
const TIMEOUT_NEGOC_SECS: u64 = 10;
const HOLE_PUNCH_DURACION_MS: u64 = 4000;
const UDP_RECV_TIMEOUT_MS: u64 = 150;
const TEST_ACK_TIMEOUT_SECS: u64 = 8;

#[derive(Debug, Clone, Serialize)]
pub struct ResultadoConexion {
    pub ok: bool,
    pub via_buzon: bool,   // true cuando Fase 2 falló y se cayó al buzón B2
    pub ip_publica_remota: String,
    pub latencia_ms: u64,
    pub error: String,
}

static CONEX_SERVIDOR_ACTIVO: AtomicBool = AtomicBool::new(false);
pub static SUBCLAVE_SERVIDOR: Mutex<String> = Mutex::new(String::new());

// ── STUN minimal — RFC 5389 Binding Request, solo IPv4 ──────────────────────

fn obtener_addr_stun(socket: &UdpSocket) -> Result<SocketAddr, String> {
    let stun_addr = "stun.l.google.com:19302"
        .to_socket_addrs()
        .map_err(|e| format!("DNS STUN: {}", e))?
        .next()
        .ok_or("DNS STUN sin resultados")?;

    let mut req = [0u8; 20];
    req[0] = 0x00; req[1] = 0x01;                          // Binding Request
    req[4] = 0x21; req[5] = 0x12; req[6] = 0xA4; req[7] = 0x42; // Magic Cookie
    rand::rngs::OsRng.fill_bytes(&mut req[8..20]);          // Transaction ID

    socket.set_read_timeout(Some(Duration::from_secs(5))).ok();
    socket.send_to(&req, stun_addr).map_err(|e| format!("STUN send: {}", e))?;

    let mut buf = [0u8; 512];
    let (n, _) = socket.recv_from(&mut buf)
        .map_err(|_| "Sin respuesta STUN (5 s). Sin acceso a internet o servidor no alcanzable.")?;

    if n < 20 || buf[0] != 0x01 || buf[1] != 0x01 {
        return Err("Respuesta STUN inválida".into());
    }

    let mut i = 20usize;
    while i + 4 <= n {
        let tipo = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let largo = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        i += 4;
        if i + largo > n { break; }
        if (tipo == 0x0020 || tipo == 0x0001) && largo >= 8 && buf[i + 1] == 0x01 {
            let (port, ip) = if tipo == 0x0020 {
                (
                    u16::from_be_bytes([buf[i+2], buf[i+3]]) ^ 0x2112u16,
                    [buf[i+4]^0x21, buf[i+5]^0x12, buf[i+6]^0xA4, buf[i+7]^0x42],
                )
            } else {
                (
                    u16::from_be_bytes([buf[i+2], buf[i+3]]),
                    [buf[i+4], buf[i+5], buf[i+6], buf[i+7]],
                )
            };
            return Ok(SocketAddr::from((std::net::Ipv4Addr::from(ip), port)));
        }
        i += largo + if largo % 4 != 0 { 4 - (largo % 4) } else { 0 };
    }
    Err("XOR-MAPPED-ADDRESS no encontrado en respuesta STUN".into())
}

// ── HMAC anti-scanner ───────────────────────────────────────────────────────

fn hmac_conex(dominio: &str, ts: u64) -> String {
    type H = Hmac<Sha256>;
    let mut mac = H::new_from_slice(APP_CONEX_KEY).expect("hmac");
    mac.update(dominio.as_bytes());
    mac.update(b":");
    mac.update(ts.to_string().as_bytes());
    hex::encode(&mac.finalize().into_bytes()[..8])
}

fn ahora_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Borra la clave de sesión de conexión directa de la memoria al cerrar sesión.
pub fn limpiar_subclave_servidor() {
    if let Ok(mut g) = SUBCLAVE_SERVIDOR.lock() {
        g.zeroize();
    }
}

// ── Servidor TCP de negociación (receptor B) ─────────────────────────────────

pub fn iniciar_servidor_conex(subclave_hex: &str, nombre_local: String) {
    if let Ok(mut g) = SUBCLAVE_SERVIDOR.lock() {
        g.zeroize(); // zeroiza el valor anterior antes de sobreescribir
        *g = subclave_hex.to_string();
    }
    if CONEX_SERVIDOR_ACTIVO.swap(true, Ordering::SeqCst) {
        return;
    }
    thread::spawn(move || {
        let listener = match TcpListener::bind(format!("0.0.0.0:{}", PUERTO_CONEX)) {
            Ok(l) => l,
            Err(e) => {
                log::warn!("[CONEX] Puerto {} no disponible: {}", PUERTO_CONEX, e);
                CONEX_SERVIDOR_ACTIVO.store(false, Ordering::SeqCst);
                return;
            }
        };
        listener.set_nonblocking(true).ok();
        log::warn!("[CONEX] Servidor conexión directa activo en :{}", PUERTO_CONEX);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).ok();
                    let nom = nombre_local.clone();
                    thread::spawn(move || manejar_negociacion_receptor(stream, nom));
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(200));
                }
                Err(e) => {
                    log::error!("[CONEX] accept: {}", e);
                    thread::sleep(Duration::from_millis(500));
                }
            }
        }
    });
}

fn manejar_negociacion_receptor(stream: TcpStream, nombre_local: String) {
    stream.set_read_timeout(Some(Duration::from_secs(TIMEOUT_NEGOC_SECS))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

    // Leer solicitud PRIMERO — A ya está esperando con timeout de 20s;
    // si hacemos STUN antes el reloj de A corre durante ~5s antes de que B
    // siquiera haya leído el request, reduciendo el margen disponible.
    let mut linea = String::new();
    {
        let mut r = BufReader::new(&stream);
        if let Err(e) = r.read_line(&mut linea) {
            log::warn!("[CONEX-R] read_line: {}", e); return;
        }
    }
    let linea = linea.trim().to_string();

    // BABEL_CONEX_REQ:{stun_ip}:{stun_port}:{local_port}:{key_fp8}:{ts}:{hmac8}
    let p: Vec<&str> = linea.splitn(7, ':').collect();
    if p.len() < 7 || p[0] != "BABEL_CONEX_REQ" {
        log::warn!("[CONEX-R] Mensaje inesperado: {:.40}", linea); return;
    }
    let a_stun_ip   = p[1];
    let a_stun_port: u16 = p[2].parse().unwrap_or(0);
    let a_local_port: u16 = p[3].parse().unwrap_or(0);
    let key_fp8     = p[4];
    let ts: u64     = p[5].parse().unwrap_or(0);
    let hmac_rx     = p[6];

    if ts == 0 || ahora_unix().saturating_sub(ts) > 60 || a_stun_port == 0 { return; }
    if hmac_conex("req", ts) != hmac_rx { log::warn!("[CONEX-R] HMAC inválido"); return; }

    // Buscar clave compartida por fingerprint (primeros 8 chars del clave_hex = 4 bytes)
    let subclave = SUBCLAVE_SERVIDOR.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if subclave.is_empty() { return; }
    let emparejados = crate::sincronizacion::cargar_emparejados(&subclave);
    let clave_hex = match emparejados.iter().find(|d| d.clave_hex.starts_with(key_fp8)) {
        Some(d) => d.clave_hex.clone(),
        None => { log::warn!("[CONEX-R] Fingerprint {} no reconocido", key_fp8); return; }
    };

    // Obtener IP LAN del iniciador (desde la conexión TCP)
    let a_lan_ip = match stream.peer_addr() {
        Ok(a) => a.ip().to_string(),
        Err(_) => return,
    };

    // Crear UDP socket y obtener addr STUN DESPUÉS de leer y validar el request.
    // El reloj de timeout de A (20s) empezó cuando A llamó read_line; B ya leyó el
    // request en <1ms, así que A tiene ~20s disponibles para que B complete STUN.
    let udp = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => { log::error!("[CONEX-R] UDP bind: {}", e); return; }
    };
    let mi_local_port = match udp.local_addr() {
        Ok(a) => a.port(),
        Err(_) => return,
    };
    let mi_stun = match obtener_addr_stun(&udp) {
        Ok(a) => a,
        Err(e) => { log::warn!("[CONEX-R] STUN: {}", e); return; }
    };
    udp.set_read_timeout(Some(Duration::from_millis(UDP_RECV_TIMEOUT_MS))).ok();

    // Enviar respuesta con nuestra addr STUN y puerto local UDP
    let ts_resp = ahora_unix();
    let resp = format!(
        "BABEL_CONEX_RESP:{}:{}:{}:{}:{}\n",
        mi_stun.ip(), mi_stun.port(), mi_local_port, ts_resp, hmac_conex("resp", ts_resp)
    );
    {
        let mut w = match stream.try_clone() { Ok(s) => s, Err(_) => return };
        if w.write_all(resp.as_bytes()).is_err() { return; }
    }
    drop(stream);

    // Direcciones de A a intentar (STUN y LAN directa)
    let mut destinos: Vec<SocketAddr> = Vec::new();
    if let Ok(a) = format!("{}:{}", a_stun_ip, a_stun_port).parse() {
        destinos.push(a);
    }
    if a_local_port > 0 {
        if let Ok(a) = format!("{}:{}", a_lan_ip, a_local_port).parse() {
            if !destinos.contains(&a) { destinos.push(a); }
        }
    }

    // Hole punching + esperar mensaje de test cifrado
    let deadline = Instant::now() + Duration::from_millis(HOLE_PUNCH_DURACION_MS + TEST_ACK_TIMEOUT_SECS * 1000);
    let mut ciphertext: Option<(Vec<u8>, SocketAddr)> = None;

    while Instant::now() < deadline {
        for &dest in &destinos {
            let _ = udp.send_to(b"BHP", dest);
        }
        let mut buf = [0u8; 4096];
        match udp.recv_from(&mut buf) {
            Ok((n, src)) if destinos.contains(&src) || destinos.iter().any(|d| d.ip() == src.ip()) => {
                if n == 3 && &buf[..3] == b"BHP" {
                    continue; // HP packet — canal se está abriendo
                }
                ciphertext = Some((buf[..n].to_vec(), src));
                break;
            }
            _ => {}
        }
        if ciphertext.is_some() { break; }
    }

    let (bytes, src) = match ciphertext {
        Some(b) => b,
        None => { log::warn!("[CONEX-R] No se recibió test (hole punch fallido)"); return; }
    };

    match crate::seguridad::descifrar_documento(bytes, &clave_hex) {
        Ok(txt) => {
            log::warn!("[CONEX-R] Test recibido de {}: {}", src, txt);
            let ack = format!("ACK:{}:{}", ahora_unix(), nombre_local);
            match crate::seguridad::blindar_documento(&ack, &clave_hex) {
                Ok(ack_bytes) => { let _ = udp.send_to(&ack_bytes, src); }
                Err(e) => { log::error!("[CONEX-R] Error cifrando ACK: {}", e); }
            }
        }
        Err(e) => { log::warn!("[CONEX-R] Error descifrando test: {}", e); }
    }
}

// ── Iniciador (dispositivo A) ─────────────────────────────────────────────────

pub fn probar_conexion(
    ip_destino: &str,
    nombre_local: &str,
    clave_hex: &str,
) -> Result<ResultadoConexion, String> {
    // Crear UDP socket (mismo para STUN y hole punch)
    let udp = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| format!("UDP bind: {}", e))?;
    let mi_local_port = udp.local_addr().map_err(|e| e.to_string())?.port();

    // Obtener IP pública vía STUN
    let mi_stun = obtener_addr_stun(&udp)
        .map_err(|e| format!("No se pudo obtener IP pública: {}", e))?;
    udp.set_read_timeout(Some(Duration::from_millis(UDP_RECV_TIMEOUT_MS))).ok();

    if clave_hex.len() < 8 {
        return Err("Clave de emparejamiento inválida (longitud < 8)".into());
    }
    let key_fp8 = &clave_hex[..8];
    let ts = ahora_unix();
    let req = format!(
        "BABEL_CONEX_REQ:{}:{}:{}:{}:{}:{}\n",
        mi_stun.ip(), mi_stun.port(), mi_local_port, key_fp8, ts, hmac_conex("req", ts)
    );

    // Conectar TCP al receptor
    let dest_tcp: SocketAddr = format!("{}:{}", ip_destino, PUERTO_CONEX)
        .parse()
        .map_err(|_| "IP de destino inválida".to_string())?;
    let mut tcp = TcpStream::connect_timeout(&dest_tcp, Duration::from_secs(5))
        .map_err(|e| format!("No se pudo conectar a {}:{}: {}", ip_destino, PUERTO_CONEX, e))?;
    tcp.set_write_timeout(Some(Duration::from_secs(5))).ok();
    // 20s: B necesita hasta ~5s para STUN tras leer el request; 10s era demasiado justo.
    tcp.set_read_timeout(Some(Duration::from_secs(20))).ok();

    tcp.write_all(req.as_bytes())
        .map_err(|e| format!("Error enviando solicitud: {}", e))?;

    // Leer respuesta
    let mut resp_linea = String::new();
    {
        let mut r = BufReader::new(&tcp);
        r.read_line(&mut resp_linea)
            .map_err(|_| "El dispositivo remoto no respondió a tiempo")?;
    }
    drop(tcp);

    let resp = resp_linea.trim();
    // BABEL_CONEX_RESP:{stun_ip}:{stun_port}:{local_port}:{ts}:{hmac}
    let p: Vec<&str> = resp.splitn(6, ':').collect();
    if p.len() < 6 || p[0] != "BABEL_CONEX_RESP" {
        return Err(format!("Respuesta inesperada: {:.60}", resp));
    }
    let b_stun_ip   = p[1];
    let b_stun_port: u16 = p[2].parse().unwrap_or(0);
    let b_local_port: u16 = p[3].parse().unwrap_or(0);
    let ts_resp: u64 = p[4].parse().unwrap_or(0);
    let hmac_resp   = p[5];

    if ts_resp == 0 || ahora_unix().saturating_sub(ts_resp) > 60 || b_stun_port == 0 {
        return Err("Respuesta de conexión inválida o expirada".into());
    }
    if hmac_conex("resp", ts_resp) != hmac_resp {
        return Err("HMAC de respuesta inválido".into());
    }

    // Construir lista de destinos UDP de B (STUN + LAN directa)
    let mut destinos: Vec<SocketAddr> = Vec::new();
    if let Ok(a) = format!("{}:{}", b_stun_ip, b_stun_port).parse() {
        destinos.push(a);
    }
    if b_local_port > 0 {
        if let Ok(a) = format!("{}:{}", ip_destino, b_local_port).parse::<SocketAddr>() {
            if !destinos.contains(&a) { destinos.push(a); }
        }
    }
    if destinos.is_empty() {
        return Err("No se pudo determinar la dirección del receptor".into());
    }

    // Hole punching: enviar BHP a todos los destinos, esperar BHP de vuelta
    let deadline_hp = Instant::now() + Duration::from_millis(HOLE_PUNCH_DURACION_MS);
    let mut canal_abierto: Option<SocketAddr> = None;
    while Instant::now() < deadline_hp {
        for &dest in &destinos {
            let _ = udp.send_to(b"BHP", dest);
        }
        let mut buf = [0u8; 16];
        if let Ok((n, src)) = udp.recv_from(&mut buf) {
            if (destinos.contains(&src) || destinos.iter().any(|d| d.ip() == src.ip()))
                && n == 3 && &buf[..3] == b"BHP"
            {
                canal_abierto = Some(src);
                break;
            }
        }
    }

    // Si no recibimos BHP, intentar igualmente (puede ser NAT que bloquea HP pero deja pasar datos)
    let destino_final = canal_abierto.unwrap_or(destinos[0]);

    // Cifrar y enviar mensaje de test
    let test_plain = format!("PING:{}:{}", ahora_unix(), nombre_local);
    let test_bytes = crate::seguridad::blindar_documento(&test_plain, clave_hex)
        .map_err(|e| format!("Error cifrando test: {}", e))?;

    udp.set_read_timeout(Some(Duration::from_secs(TEST_ACK_TIMEOUT_SECS))).ok();
    let t0 = Instant::now();
    udp.send_to(&test_bytes, destino_final)
        .map_err(|e| format!("Error enviando test: {}", e))?;

    // Esperar ACK cifrado
    let mut ack_buf = vec![0u8; 4096];
    loop {
        match udp.recv_from(&mut ack_buf) {
            Ok((n, src)) if destinos.contains(&src) || destinos.iter().any(|d| d.ip() == src.ip()) => {
                let latencia_ms = t0.elapsed().as_millis() as u64;
                return match crate::seguridad::descifrar_documento(ack_buf[..n].to_vec(), clave_hex) {
                    Ok(_) => Ok(ResultadoConexion {
                        ok: true,
                        via_buzon: false,
                        ip_publica_remota: b_stun_ip.to_string(),
                        latencia_ms,
                        error: String::new(),
                    }),
                    Err(e) => Err(format!("ACK recibido pero inválido (error de descifrado): {}", e)),
                };
            }
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut
                   || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                return Err(
                    "NAT_SIMETRICO: Conexión directa no fue posible en esta red. \
                     El NAT de una o ambas redes es simétrico y no permite hole punching. \
                     Ambos dispositivos deben estar en la misma red local, \
                     o en redes con NAT de cono (cone NAT). \
                     Soporte de relay (TURN) disponible en una fase futura."
                        .into(),
                );
            }
            Err(e) => return Err(format!("Error esperando ACK: {}", e)),
        }
    }
}
