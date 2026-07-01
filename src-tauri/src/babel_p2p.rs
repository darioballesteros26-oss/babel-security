// ============================================================
// BABEL P2P - COMUNICACIÓN DIRECTA ENTRE INSTANCIAS v5
// ============================================================
//
// Módulo único que incluye todo el sistema P2P:
//   - Certificados mTLS (generación y gestión)
//   - Descubrimiento en red local por UDP broadcast
//   - Protocolo de transferencia con cabecera fija
//   - Servidor TLS con mTLS (requiere cert del cliente)
//   - Cliente TLS (presenta su cert + verifica pinning)
//   - Cifrado/descifrado en tránsito: archivos se descifran
//     antes de enviar y se re-cifran con la clave del receptor
//
// TLS: rustls 0.22 con StreamOwned (síncrono, sin tokio)
// mTLS: cliente presenta certificado — servidor lo valida

use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ServerConfig};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use zeroize::Zeroizing;

// Buffer global de mensajes entrantes. Zeroizing<String> garantiza borrado al drenarlo.
pub static MENSAJES_ENTRANTES: Mutex<Vec<Zeroizing<String>>> = Mutex::new(Vec::new());
const MAX_MENSAJES: usize = 1000;

// Peers rechazados por fingerprint desconocido, pendientes de aprobación del usuario.
// Cada entrada: (fingerprint_completo, ip_redactada).
pub static PEERS_PENDIENTES: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

/// IP LAN local usando el truco de conectar UDP sin enviar tráfico real.
fn lan_ip() -> Option<std::net::IpAddr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:80").ok()?;
    s.local_addr().ok().map(|a| a.ip())
}

// Señal de apagado para el servidor P2P. Se activa en cerrar_sesion para que el
// hilo del servidor salga limpiamente y libere (zeroize) la subclave en RAM.
static P2P_SHUTDOWN: AtomicBool = AtomicBool::new(false);

pub fn detener_servidor_p2p() {
    P2P_SHUTDOWN.store(true, Ordering::SeqCst);
}

pub fn reiniciar_servidor_p2p() {
    P2P_SHUTDOWN.store(false, Ordering::SeqCst);
}

// ============================================================
// CONSTANTES
// ============================================================
fn p2p_dir() -> PathBuf {
    let dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Babel")
        .join("p2p");
    let _ = fs::create_dir_all(&dir);
    dir
}

fn peers_dir() -> PathBuf {
    let dir = p2p_dir().join("peers");
    let _ = fs::create_dir_all(&dir);
    dir
}

fn ruta_cert() -> PathBuf {
    p2p_dir().join("certificado.der")
}
fn ruta_clave() -> PathBuf {
    p2p_dir().join("clave_privada.der")
}

fn recibidos_dir() -> PathBuf {
    let dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Babel")
        .join("archivos");
    let _ = fs::create_dir_all(&dir);
    dir
}

fn ruta_peers_trusted() -> PathBuf {
    p2p_dir().join("peers_trusted.babel")
}

fn fingerprint_cert(cert_der: &CertificateDer) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert_der.as_ref());
    hex::encode(hasher.finalize())
}

/// Oculta los dos últimos octetos de una IPv4 en logs.
fn redactar_ip(ip: &str) -> String {
    let partes: Vec<&str> = ip.splitn(5, '.').collect();
    if partes.len() >= 2 {
        format!("{}.*.*", partes[0..2].join("."))
    } else {
        "?.?.*.*".to_string()
    }
}

// ============================================================
// peers_trusted — cifrado con AES-256-GCM
// ============================================================
// El archivo peers_trusted.babel contiene las IPs históricas y
// fingerprints de certificados. Cifrarlo evita revelar con quién
// se ha comunicado este Babel si alguien accede al disco.

fn cargar_peers_trusted(subclave_hex: &str) -> HashMap<String, String> {
    if subclave_hex.is_empty() {
        return HashMap::new();
    }
    fs::read(ruta_peers_trusted())
        .ok()
        .and_then(|bytes| crate::seguridad::descifrar_documento(bytes, subclave_hex).ok())
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
}

fn guardar_peers_trusted(peers: &HashMap<String, String>, subclave_hex: &str) {
    if subclave_hex.is_empty() {
        return;
    }
    if let Ok(json) = serde_json::to_string(peers) {
        if let Ok(cifrado) = crate::seguridad::blindar_documento(&json, subclave_hex) {
            let _ = fs::write(ruta_peers_trusted(), cifrado);
        }
    }
}

// ============================================================
// CONSTANTES DE PROTOCOLO
// ============================================================
pub const PUERTO_DESCUBRIMIENTO: u16 = 47823;
pub const PUERTO_TRANSFERENCIA: u16 = 47824;
pub const TAMAÑO_CABECERA: usize = 304;
pub const MAX_NOMBRE: usize = 256;
pub const MAX_TAMAÑO_ARCHIVO: u64 = 100 * 1024 * 1024; // 100MB
// V2: incluye timestamp Unix para invalidar replays > 60 s y fingerprint del cert.
// V1 se sigue parseando como fallback para compatibilidad con versiones antiguas.
const PREFIJO_ANUNCIO_V2: &str = "BABEL_P2P_ANNOUNCE_V2:";
const PREFIJO_RESPUESTA_V2: &str = "BABEL_P2P_RESPONSE_V2:";
const VERSION_PROTOCOLO: u32 = 1;

// ============================================================
// ESTRUCTURAS
// ============================================================

/// Babel encontrado en la red local
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerDescubierto {
    pub ip: String,
    pub puerto: u16,
    pub nombre: String,
}

// ============================================================
// CERTIFICADOS - Gestión de identidad mTLS
// ============================================================

pub struct GestorCertificados;

impl GestorCertificados {
    pub fn generar_o_cargar() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), String> {
        let _ = fs::create_dir_all(p2p_dir());
        let _ = fs::create_dir_all(peers_dir());

        if ruta_cert().exists() && ruta_clave().exists() {
            return Self::cargar();
        }

        log::warn!("[P2P] Generando certificado de identidad...");

        // Incluir el hostname real además de localhost para que SNI funcione
        // cuando el cliente conecta por nombre en vez de por IP.
        let mut sans = vec!["localhost".to_string()];
        if let Ok(h) = hostname::get() {
            let hn = h.to_string_lossy().to_string();
            if !hn.is_empty() && hn != "localhost" { sans.push(hn); }
        }
        let cert = generate_simple_self_signed(sans)
            .map_err(|e| format!("Error generando certificado: {}", e))?;

        let cert_der = cert
            .serialize_der()
            .map_err(|e| format!("Error serializando cert: {}", e))?;
        let clave_der = Zeroizing::new(cert.serialize_private_key_der());

        fs::write(ruta_cert(), &cert_der).map_err(|e| format!("Error guardando cert: {}", e))?;
        // Cifrar la clave privada antes de guardarla en disco
        if let Some(enc_key) = clave_privada_p2p_enc() {
            match crate::seguridad::blindar_documento(&hex::encode(clave_der.as_slice()), &enc_key) {
                Ok(cifrado) => {
                    fs::write(ruta_clave(), cifrado).map_err(|e| format!("Error guardando clave cifrada: {}", e))?;
                }
                Err(_) => {
                    fs::write(ruta_clave(), clave_der.as_slice()).map_err(|e| format!("Error guardando clave: {}", e))?;
                }
            }
        } else {
            fs::write(ruta_clave(), clave_der.as_slice()).map_err(|e| format!("Error guardando clave: {}", e))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(ruta_clave(), fs::Permissions::from_mode(0o600));
        }

        log::info!("[OK] Certificado generado en {:?}", ruta_cert());
        log::error!("[P2P]  NUNCA compartas {:?}.", ruta_clave());

        Ok((cert_der, clave_der))
    }

    fn cargar() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), String> {
        let cert = fs::read(ruta_cert()).map_err(|e| format!("Error leyendo cert: {}", e))?;
        let blob = fs::read(ruta_clave()).map_err(|e| format!("Error leyendo clave: {}", e))?;

        let clave = if let Some(enc_key) = clave_privada_p2p_enc() {
            // Intentar descifrar (formato nuevo cifrado)
            match crate::seguridad::descifrar_documento(blob.clone(), &enc_key)
                .and_then(|hex| hex::decode(hex.trim()).map_err(|e| e.to_string()))
            {
                Ok(bytes) => Zeroizing::new(bytes),
                Err(_) => {
                    // Migración: estaba en texto plano — re-cifrar y guardar
                    let raw = Zeroizing::new(blob);
                    if let Ok(cifrado) = crate::seguridad::blindar_documento(&hex::encode(&*raw), &enc_key) {
                        let _ = fs::write(ruta_clave(), cifrado);
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let _ = fs::set_permissions(ruta_clave(), fs::Permissions::from_mode(0o600));
                        }
                    }
                    raw
                }
            }
        } else {
            Zeroizing::new(blob)
        };
        Ok((cert, clave))
    }
}

// ============================================================
// DESCUBRIMIENTO - Búsqueda de peers en red local por UDP
// ============================================================

pub struct DescubrimientoRed;

impl DescubrimientoRed {
    pub fn iniciar_servidor(nombre: String) {
        thread::spawn(move || {
            // Preferir la IP LAN para no escuchar en todas las interfaces
            let bind_ip = lan_ip()
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "0.0.0.0".to_string());
            let socket = UdpSocket::bind(format!("{}:{}", bind_ip, PUERTO_DESCUBRIMIENTO))
                .or_else(|_| UdpSocket::bind(format!("0.0.0.0:{}", PUERTO_DESCUBRIMIENTO)))
                .unwrap_or_else(|e| {
                    log::warn!("[P2P] No se pudo iniciar descubrimiento: {}", e);
                    std::process::exit(0); // no debería llegar aquí
                });
            let _ = socket.set_broadcast(true);

            // Rate limiting: máx 10 peticiones por IP por ventana de 1 segundo
            let mut contadores: HashMap<std::net::IpAddr, (u32, std::time::Instant)> = HashMap::new();
            const MAX_POR_SEGUNDO: u32 = 10;

            // Fingerprint propio para incluir en la respuesta (permite pre-verificación TOFU)
            let fp_propio: String = fs::read(ruta_cert())
                .map(|b| fingerprint_cert(&CertificateDer::from(b)))
                .map(|fp| fp[..8.min(fp.len())].to_string())
                .unwrap_or_default();

            let mut buf = [0u8; 256];
            loop {
                let (n, origen) = match socket.recv_from(&mut buf) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let ip = origen.ip();
                let ahora_inst = std::time::Instant::now();
                let entrada = contadores.entry(ip).or_insert((0, ahora_inst));
                if ahora_inst.duration_since(entrada.1) >= Duration::from_secs(1) {
                    *entrada = (0, ahora_inst);
                }
                entrada.0 += 1;
                if entrada.0 > MAX_POR_SEGUNDO {
                    log::warn!("[P2P] Rate limit UDP: {} descartado.", redactar_ip(&ip.to_string()));
                    continue;
                }
                let msg = std::str::from_utf8(&buf[..n]).unwrap_or("");
                // Validar formato V2 (con timestamp) o aceptar V1 legado
                let valido = if let Some(rest) = msg.strip_prefix(PREFIJO_ANUNCIO_V2) {
                    let ts: u64 = rest.parse().unwrap_or(0);
                    let ahora_u = ahora_unix();
                    ts > 0 && ahora_u.saturating_sub(ts) < 60
                } else {
                    msg == "BABEL_P2P_ANNOUNCE_V1"
                };
                if valido {
                    let ts = ahora_unix();
                    let respuesta = format!("{}{}:{}:{}:{}", PREFIJO_RESPUESTA_V2, ts, nombre, PUERTO_TRANSFERENCIA, fp_propio);
                    let _ = socket.send_to(respuesta.as_bytes(), origen);
                }
            }
        });
    }

    pub fn buscar_peers(timeout_ms: u64) -> Result<Vec<PeerDescubierto>, String> {
        let socket =
            UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Error socket búsqueda: {}", e))?;
        socket
            .set_broadcast(true)
            .map_err(|e| format!("Error broadcast: {}", e))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(timeout_ms)))
            .map_err(|e| format!("Error timeout: {}", e))?;

        let destino = SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::BROADCAST),
            PUERTO_DESCUBRIMIENTO,
        );
        let anuncio = format!("{}{}", PREFIJO_ANUNCIO_V2, ahora_unix());
        socket
            .send_to(anuncio.as_bytes(), destino)
            .map_err(|e| format!("Error enviando broadcast: {}", e))?;

        log::warn!("[P2P] Buscando Babel en la red local...");
        let mut peers = Vec::new();
        let mut buf = [0u8; 512];

        loop {
            match socket.recv_from(&mut buf) {
                Ok((n, origen)) => {
                    let respuesta = String::from_utf8_lossy(&buf[..n]);
                    if let Some(peer) = Self::parsear_respuesta(&respuesta, &origen) {
                        log::warn!(
                            "[P2P] Encontrado: {} en {}:{}",
                            peer.nombre,
                            redactar_ip(&peer.ip),
                            peer.puerto
                        );
                        peers.push(peer);
                    }
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break
                }
                Err(_) => break,
            }
        }

        if peers.is_empty() {
            log::warn!("[P2P] No se encontró ningún Babel.");
        } else {
            log::warn!("[P2P] {} Babel encontrado(s).", peers.len());
        }
        Ok(peers)
    }

    fn parsear_respuesta(respuesta: &str, origen: &SocketAddr) -> Option<PeerDescubierto> {
        let (ts_str, nombre_raw, puerto_str) = if let Some(rest) = respuesta.strip_prefix(PREFIJO_RESPUESTA_V2) {
            // Formato V2: <ts>:<nombre>:<puerto>:<fp8_opcional>
            let p: Vec<&str> = rest.splitn(4, ':').collect();
            if p.len() < 3 { return None; }
            (p[0], p[1], p[2])
        } else if let Some(rest) = respuesta.strip_prefix("BABEL_P2P_RESPONSE_V1:") {
            // Legado V1: <nombre>:<puerto>
            let p: Vec<&str> = rest.splitn(2, ':').collect();
            if p.len() != 2 { return None; }
            ("0", p[0], p[1])
        } else {
            return None;
        };

        // Validar timestamp: rechazar respuestas > 60 s (anti-replay)
        let ts: u64 = ts_str.parse().unwrap_or(0);
        if ts > 0 && ahora_unix().saturating_sub(ts) > 60 {
            return None;
        }

        let nombre: String = nombre_raw
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '.')
            .take(64)
            .collect();
        if nombre.is_empty() { return None; }
        let puerto: u16 = puerto_str.trim().parse().ok()?;
        Some(PeerDescubierto { ip: origen.ip().to_string(), puerto, nombre })
    }

    pub fn peer_manual(ip: &str, nombre: &str) -> PeerDescubierto {
        PeerDescubierto {
            ip: ip.to_string(),
            puerto: PUERTO_TRANSFERENCIA,
            nombre: nombre.to_string(),
        }
    }
}

// ============================================================
// PROTOCOLO - Formato de paquetes (sin cambios)
// ============================================================

pub struct Cabecera {
    pub longitud_datos: u64,
    pub nombre_archivo: String,
    pub checksum: [u8; 32],
}

impl Cabecera {
    pub fn nueva(nombre: &str, datos: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(datos);
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&hasher.finalize());
        Self {
            longitud_datos: datos.len() as u64,
            nombre_archivo: nombre.to_string(),
            checksum,
        }
    }

    pub fn serializar(&self) -> Vec<u8> {
        let mut buf = vec![0u8; TAMAÑO_CABECERA];
        buf[0..8].copy_from_slice(&self.longitud_datos.to_le_bytes());
        let nb = self.nombre_archivo.as_bytes();
        // Truncar en límite de carácter UTF-8 válido para evitar secuencias parciales
        let len = if nb.len() <= MAX_NOMBRE {
            nb.len()
        } else {
            std::str::from_utf8(&nb[..MAX_NOMBRE])
                .map(|_| MAX_NOMBRE)
                .unwrap_or_else(|e| e.valid_up_to())
        };
        buf[8..8 + len].copy_from_slice(&nb[..len]);
        buf[264..268].copy_from_slice(&1u32.to_le_bytes());
        buf[268..300].copy_from_slice(&self.checksum);
        buf[300..304].copy_from_slice(&VERSION_PROTOCOLO.to_le_bytes());
        buf
    }

    pub fn deserializar(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < TAMAÑO_CABECERA {
            return Err(format!("Cabecera incompleta: {} bytes", buf.len()));
        }
        let longitud_datos = u64::from_le_bytes(
            buf[0..8].try_into().map_err(|_| "Error leyendo longitud")?,
        );
        let nombre_raw = &buf[8..264];
        let fin = nombre_raw.iter().position(|&b| b == 0).unwrap_or(256);
        let nombre_archivo = String::from_utf8_lossy(&nombre_raw[..fin]).to_string();
        let tipo = u32::from_le_bytes(
            buf[264..268].try_into().map_err(|_| "Error leyendo tipo")?,
        );
        if tipo != 1 {
            return Err(format!("Tipo de transferencia no soportado: {}", tipo));
        }
        let version = u32::from_le_bytes(
            buf[300..304].try_into().map_err(|_| "Error leyendo version")?,
        );
        if version != VERSION_PROTOCOLO {
            return Err(format!("Versión incompatible: {}", version));
        }
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&buf[268..300]);
        Ok(Self {
            longitud_datos,
            nombre_archivo,
            checksum,
        })
    }
}

pub fn enviar_archivo<S: Read + Write>(
    stream: &mut S,
    nombre: &str,
    datos: &[u8],
) -> Result<(), String> {
    let cabecera = Cabecera::nueva(nombre, datos);
    stream
        .write_all(&cabecera.serializar())
        .map_err(|e| format!("Error enviando cabecera: {}", e))?;
    stream
        .write_all(datos)
        .map_err(|e| format!("Error enviando datos: {}", e))?;
    stream.flush().map_err(|e| format!("Error flush: {}", e))?;
    log::warn!("[P2P] Enviado {} ({} bytes).", nombre, datos.len());
    Ok(())
}

pub fn recibir_archivo<S: Read + Write>(stream: &mut S) -> Result<(String, Vec<u8>), String> {
    let mut buf_cabecera = vec![0u8; TAMAÑO_CABECERA];
    stream
        .read_exact(&mut buf_cabecera)
        .map_err(|e| format!("Error leyendo cabecera: {}", e))?;

    let cabecera = Cabecera::deserializar(&buf_cabecera)?;

    if cabecera.longitud_datos > MAX_TAMAÑO_ARCHIVO {
        return Err(format!(
            "Archivo demasiado grande: {} bytes",
            cabecera.longitud_datos
        ));
    }

    let mut datos = vec![0u8; cabecera.longitud_datos as usize];
    stream
        .read_exact(&mut datos)
        .map_err(|e| format!("Error leyendo datos: {}", e))?;

    let mut hasher = Sha256::new();
    hasher.update(&datos);
    let checksum: [u8; 32] = hasher.finalize().into();
    if checksum != cabecera.checksum {
        return Err("Checksum inválido — datos corruptos en tránsito".to_string());
    }

    log::info!(
        "[P2P] Recibido {} ({} bytes) - íntegro.",
        cabecera.nombre_archivo,
        datos.len()
    );
    Ok((cabecera.nombre_archivo, datos))
}

// ============================================================
// VERIFICADOR SERVIDOR (cliente → servidor): TOFU con pinning
// ============================================================
// Primera conexión a un peer: acepta y guarda el fingerprint SHA-256.
// Siguientes: rechaza si cambió. Ahora también verifica la firma TLS.

#[derive(Debug)]
struct VerificadorPinning {
    peer_ip: String,
    subclave_hex: Zeroizing<String>,
}

impl rustls::client::danger::ServerCertVerifier for VerificadorPinning {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let fp = fingerprint_cert(end_entity);
        let _guard = TOFU_PINNING_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let mut peers = cargar_peers_trusted(&self.subclave_hex);
        match peers.get(&self.peer_ip) {
            Some(esperado) => {
                if *esperado != fp {
                    return Err(rustls::Error::General(format!(
                        "Certificado de {} no coincide con el registrado. Posible MITM.",
                        self.peer_ip
                    )));
                }
            }
            None => {
                peers.insert(self.peer_ip.clone(), fp);
                guardar_peers_trusted(&peers, &self.subclave_hex);
                log::warn!("[P2P] Peer {} registrado (TOFU).", redactar_ip(&self.peer_ip));
            }
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ============================================================
// VERIFICADOR CLIENTE (servidor → cliente): mTLS
// ============================================================
// El servidor requiere que el cliente presente un certificado.
// TOFU: acepta el primer peer que se conecta y registra su fingerprint.
// Conexiones posteriores se rechazan si el fingerprint no coincide.
// Thread-safe: CERTS_AUTORIZADOS_MUTEX serializa acceso al archivo.

static CERTS_AUTORIZADOS_MUTEX: Mutex<()> = Mutex::new(());

// IP del peer actual pasada al verificador vía thread-local (una conexión = un hilo).
thread_local! {
    static PEER_IP_ACTUAL: std::cell::RefCell<String> = std::cell::RefCell::new(String::new());
}

// Thread-safe: serializa el TOFU del cliente para evitar race condition
// donde dos conexiones simultáneas podrían registrar fingerprints distintos.
static TOFU_PINNING_MUTEX: Mutex<()> = Mutex::new(());

fn ruta_certs_autorizados() -> std::path::PathBuf {
    p2p_dir().join("certs_autorizados.dat")
}

const TOFU_TTL_SECS: u64 = 90 * 24 * 3600; // 90 días

fn ahora_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Deriva la clave de cifrado para la clave privada P2P desde master.salt.
/// SHA-256 con dominio propio — distinta de clave_certs_autorizados.
fn clave_privada_p2p_enc() -> Option<Zeroizing<String>> {
    let salt = fs::read(crate::babel_dir().join("master.salt")).ok()?;
    if salt.len() < 32 { return None; }
    let mut hasher = Sha256::new();
    hasher.update(b"babel-p2p-clave-privada-v1:");
    hasher.update(&salt[..32]);
    let derived: [u8; 32] = hasher.finalize().into();
    Some(Zeroizing::new(hex::encode(derived)))
}

// Deriva la clave para cifrar certs_autorizados.dat desde master.salt.
// Los fingerprints no son contraseñas, pero revelan con qué peers hemos
// comunicado — cifrarlos equipara la protección a peers_trusted.babel.
fn clave_certs_autorizados() -> Option<Zeroizing<String>> {
    let bytes = fs::read(crate::babel_dir().join("master.salt")).ok()?;
    if bytes.len() < 32 { return None; }
    Some(Zeroizing::new(hex::encode(&bytes[..32])))
}

// Formato de cada línea del texto plano interno: `fingerprint:unix_timestamp`
// El archivo en disco se cifra con AES-256-GCM. Migración automática desde texto plano.
fn cargar_certs_autorizados() -> std::collections::HashSet<String> {
    let ahora = ahora_unix();
    let ruta = ruta_certs_autorizados();

    // Intentar descifrar (formato nuevo); si falla, leer como texto plano (legado)
    let texto = clave_certs_autorizados()
        .and_then(|clave| fs::read(&ruta).ok()
            .and_then(|blob| crate::seguridad::descifrar_documento(blob, &clave).ok()))
        .unwrap_or_else(|| fs::read_to_string(&ruta).unwrap_or_default());

    texto.lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.is_empty() { return None; }
            let mut partes = l.splitn(2, ':');
            let fp = partes.next()?.to_string();
            let ts: u64 = partes.next().and_then(|t| t.parse().ok()).unwrap_or(ahora);
            if ahora.saturating_sub(ts) > TOFU_TTL_SECS { None } else { Some(fp) }
        })
        .collect()
}

fn guardar_certs_autorizados(certs: &std::collections::HashSet<String>) {
    let ahora = ahora_unix();
    let contenido: String = certs.iter()
        .map(|fp| format!("{}:{}", fp, ahora))
        .collect::<Vec<_>>()
        .join("\n");

    if let Some(clave) = clave_certs_autorizados() {
        if let Ok(cifrado) = crate::seguridad::blindar_documento(&contenido, &clave) {
            let _ = fs::write(ruta_certs_autorizados(), cifrado);
            return;
        }
    }
    // Fallback texto plano si master.salt no existe (primera ejecución)
    let _ = fs::write(ruta_certs_autorizados(), contenido);
}

#[derive(Debug)]
struct VerificadorClienteP2P;

impl rustls::server::danger::ClientCertVerifier for VerificadorClienteP2P {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        if end_entity.as_ref().is_empty() {
            return Err(rustls::Error::NoCertificatesPresented);
        }
        let fp = fingerprint_cert(end_entity);
        let _guard = CERTS_AUTORIZADOS_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let mut autorizados = cargar_certs_autorizados();

        if autorizados.contains(&fp) {
            // Fingerprint ya autorizado — aceptar sin re-guardar
            Ok(rustls::server::danger::ClientCertVerified::assertion())
        } else if autorizados.is_empty() {
            // TOFU bootstrap: primer peer ever — auto-aceptar
            autorizados.insert(fp);
            guardar_certs_autorizados(&autorizados);
            log::warn!("[P2P] Primer peer registrado por TOFU (bootstrap).");
            Ok(rustls::server::danger::ClientCertVerified::assertion())
        } else {
            // Peer desconocido — añadir a pendientes para que el usuario lo apruebe
            let ip_red = PEER_IP_ACTUAL.with(|c| redactar_ip(&c.borrow()));
            if let Ok(mut pending) = PEERS_PENDIENTES.lock() {
                if !pending.iter().any(|(f, _)| f == &fp) {
                    pending.push((fp.clone(), ip_red.clone()));
                    log::warn!("[P2P] Peer {} pendiente de aprobación.", ip_red);
                }
            }
            Err(rustls::Error::General("Certificado P2P no autorizado — aprobación pendiente".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ============================================================
// SERVIDOR - Babel que recibe archivos
// ============================================================

pub struct ServidorP2P {
    subclave_hex: Zeroizing<String>,
    id_usuario: String,
}

impl ServidorP2P {
    pub fn nuevo(subclave_hex: &str, id_usuario: &str) -> Self {
        Self {
            subclave_hex: Zeroizing::new(subclave_hex.to_string()),
            id_usuario: id_usuario.to_string(),
        }
    }

    pub fn iniciar(&self) -> Result<(), String> {
        let _ = fs::create_dir_all(recibidos_dir());

        let config_tls = self.construir_config_servidor()?;
        let config_arc = Arc::new(config_tls);
        let conexiones_activas = Arc::new(AtomicUsize::new(0));

        // Preferir LAN IP para no exponer el servidor en todas las interfaces
        let bind_addr = lan_ip()
            .map(|ip| format!("{}:{}", ip, PUERTO_TRANSFERENCIA))
            .unwrap_or_else(|| format!("0.0.0.0:{}", PUERTO_TRANSFERENCIA));
        let listener = TcpListener::bind(&bind_addr)
            .or_else(|_| TcpListener::bind(format!("0.0.0.0:{}", PUERTO_TRANSFERENCIA)))
            .map_err(|e| format!("No se pudo abrir puerto {}: {}", PUERTO_TRANSFERENCIA, e))?;

        // Non-blocking + poll loop permite comprobar P2P_SHUTDOWN sin bloquearse
        // indefinidamente en accept(). El sleep de 100ms entre reintentos WouldBlock
        // garantiza que el hilo salga en menos de 200ms tras cerrar sesión.
        listener.set_nonblocking(true)
            .map_err(|e| format!("No se pudo poner listener en non-blocking: {}", e))?;

        log::warn!("[P2P] Servidor mTLS activo en puerto {}.", PUERTO_TRANSFERENCIA);

        loop {
            if P2P_SHUTDOWN.load(Ordering::Relaxed) {
                log::warn!("[P2P] Señal de apagado recibida — cerrando servidor.");
                break;
            }

            let stream = match listener.accept() {
                Ok((s, _)) => {
                    // Restaurar modo bloqueante en el stream de conexión individual
                    let _ = s.set_nonblocking(false);
                    // Previene DoS por peers que abren conexión y no envían datos
                    if let Err(e) = s.set_read_timeout(Some(Duration::from_secs(30))) {
                        log::warn!("[P2P] No se pudo establecer read_timeout: {}", e);
                    }
                    // Previene peers lentos que consumen el hilo indefinidamente al escribir
                    if let Err(e) = s.set_write_timeout(Some(Duration::from_secs(30))) {
                        log::warn!("[P2P] No se pudo establecer write_timeout: {}", e);
                    }
                    s
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(e) => {
                    log::error!("[P2P] Error de red: {}", e);
                    continue;
                }
            };

            // Rechazar si ya hay demasiadas conexiones simultáneas
            if conexiones_activas.load(Ordering::Relaxed) >= 10 {
                log::warn!("[P2P] Límite de conexiones alcanzado, rechazando.");
                continue;
            }

            let ip = stream
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or("?".to_string());
            log::warn!("[P2P] Conexión desde {}", redactar_ip(&ip));

            let config_clone = config_arc.clone();
            let subclave = self.subclave_hex.clone();
            let usuario = self.id_usuario.clone();
            let contador = conexiones_activas.clone();

            // fetch_add dentro del closure — si spawn falla el contador no queda corrupto
            let ip_clone = ip.clone();
            thread::spawn(move || {
                // Inyectar la IP en el thread-local antes del handshake TLS
                PEER_IP_ACTUAL.with(|c| *c.borrow_mut() = ip_clone);
                contador.fetch_add(1, Ordering::Relaxed);
                let conn = match rustls::ServerConnection::new(config_clone) {
                    Ok(c) => c,
                    Err(e) => {
                        log::error!("[P2P] Error TLS: {}", e);
                        contador.fetch_sub(1, Ordering::Relaxed);
                        return;
                    }
                };
                let mut tls_stream = rustls::StreamOwned::new(conn, stream);
                let manejador = ServidorP2P { subclave_hex: subclave, id_usuario: usuario };
                match recibir_archivo(&mut tls_stream) {
                    Ok((nombre, datos)) => manejador.guardar_archivo(&nombre, &datos, &ip),
                    Err(e) => {
                        log::error!("[P2P] Error recibiendo de {}: {}", redactar_ip(&ip), e);
                        crate::seguridad::registrar_evento_seguridad(
                            &format!("Error P2P de {}: {}", redactar_ip(&ip), e),
                            &manejador.subclave_hex,
                        );
                    }
                }
                contador.fetch_sub(1, Ordering::Relaxed);
            });
        }
        Ok(())
    }

    /// Guarda el archivo recibido cifrándolo con la clave local.
    /// El nombre incluye el prefijo de usuario para que aparezca en listar_archivos.
    fn guardar_archivo(&self, nombre: &str, datos: &[u8], ip: &str) {
        let nombre_seguro = Path::new(nombre)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("archivo_recibido")
            .to_string();

        // Mensajes de texto — no se guardan en disco, van al buffer en RAM
        if nombre_seguro == "mensaje.txt" {
            // Límite de 64 KB por mensaje para evitar saturación de RAM
            if datos.len() > 64 * 1024 {
                log::warn!("[P2P] Mensaje demasiado grande ({} bytes), descartado.", datos.len());
                return;
            }
            if let Ok(texto) = String::from_utf8(datos.to_vec()) {
                if let Ok(mut msgs) = MENSAJES_ENTRANTES.lock() {
                    if msgs.len() < MAX_MENSAJES {
                        msgs.push(Zeroizing::new(texto));
                    } else {
                        log::warn!("[P2P] Buffer de mensajes lleno, mensaje descartado.");
                    }
                }
            }
            return;
        }

        if self.subclave_hex.is_empty() {
            log::error!("[P2P] Sin clave de sesión — no se puede cifrar el archivo recibido.");
            return;
        }

        // Cifrar con la clave local antes de guardar
        let contenido_b64 = crate::traductor::comprimir_b64(datos);
        let cifrado = match crate::seguridad::blindar_documento(&contenido_b64, &self.subclave_hex) {
            Ok(c) => c,
            Err(e) => {
                log::error!("[P2P] Error cifrando archivo recibido: {}", e);
                return;
            }
        };

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let nombre_sin_ext = Path::new(&nombre_seguro)
            .file_stem()
            .and_then(|n| n.to_str())
            .unwrap_or("p2p");
        // Prefijo de usuario para que listar_archivos lo muestre correctamente
        let nombre_babel = format!("{}_p2p_{}_{}.babel", self.id_usuario, nombre_sin_ext, ts);
        let ruta = recibidos_dir().join(&nombre_babel);

        match fs::write(&ruta, cifrado) {
            Ok(_) => {
                log::info!("[OK] P2P recibido y cifrado: {}", ruta.display());
                crate::seguridad::registrar_evento_seguridad(
                    &format!(
                        "P2P recibido de {}: {} ({} bytes)",
                        ip, nombre_seguro, datos.len()
                    ),
                    &self.subclave_hex,
                );
            }
            Err(e) => log::error!("[P2P] No se pudo guardar: {}", e),
        }
    }

    fn construir_config_servidor(&self) -> Result<ServerConfig, String> {
        let (cert_der, clave_der) = GestorCertificados::generar_o_cargar()?;
        let cert = CertificateDer::from(cert_der);
        let clave = PrivateKeyDer::Pkcs8(clave_der.to_vec().into());

        // mTLS: el servidor requiere que el cliente presente un certificado válido.
        let config = ServerConfig::builder()
            .with_client_cert_verifier(Arc::new(VerificadorClienteP2P))
            .with_single_cert(vec![cert], clave)
            .map_err(|e| format!("Error configurando servidor mTLS: {}", e))?;

        Ok(config)
    }
}

// ============================================================
// CLIENTE - Babel que envía archivos
// ============================================================

pub struct ClienteP2P {
    subclave_hex: Zeroizing<String>,
}

impl ClienteP2P {
    pub fn nuevo(subclave_hex: &str) -> Self {
        Self {
            subclave_hex: Zeroizing::new(subclave_hex.to_string()),
        }
    }

    /// Envía un archivo .babel descifrado para que el receptor pueda re-cifrarlo
    /// con su propia clave. El canal TLS garantiza confidencialidad en tránsito.
    pub fn enviar(&self, peer: &PeerDescubierto, ruta_archivo: &str) -> Result<(), String> {
        if self.subclave_hex.is_empty() {
            return Err("Sin clave de sesión para descifrar el archivo".into());
        }

        // Descifrar el .babel del emisor
        let bytes_cifrados = fs::read(ruta_archivo)
            .map_err(|e| format!("No se pudo leer {}: {}", ruta_archivo, e))?;
        let contenido = crate::seguridad::descifrar_documento(bytes_cifrados, &self.subclave_hex)
            .map_err(|e| format!("Error descifrando para envío P2P: {}", e))?;

        // Descomprimir/decodificar → bytes en bruto del documento original
        let datos = crate::traductor::descomprimir_b64(&contenido)
            .unwrap_or_else(|_| contenido.into_bytes());

        // Derivar nombre limpio (sin prefijo "babel_" ni extensión ".babel")
        let nombre_babel_file = Path::new(ruta_archivo)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("archivo.babel");
        let nombre_base = nombre_babel_file
            .trim_end_matches(".babel")
            .trim_start_matches("babel_");

        // Detectar extensión real por magic bytes
        let ext = if datos.starts_with(b"PK") {
            "docx"
        } else if datos.starts_with(b"%PDF") {
            "pdf"
        } else if datos.starts_with(b"\x89PNG") {
            "png"
        } else if datos.starts_with(b"\xFF\xD8\xFF") {
            "jpg"
        } else {
            "txt"
        };
        let nombre_envio = format!("{}.{}", nombre_base, ext);

        log::warn!("[P2P] Conectando a {} ({})...", peer.nombre, redactar_ip(&peer.ip));

        let mut tls_stream = self.conectar_tls(peer)?;
        enviar_archivo(&mut tls_stream, &nombre_envio, &datos)?;

        crate::seguridad::registrar_evento_seguridad(
            &format!(
                "P2P enviado a {} ({}): {} ({} bytes)",
                peer.nombre, peer.ip, nombre_envio, datos.len()
            ),
            &self.subclave_hex,
        );

        log::info!("[OK] {} enviado a {}.", nombre_envio, peer.nombre);
        Ok(())
    }

    /// Envía bytes arbitrarios (mensajes de texto) sin descifrar — no son .babel.
    pub fn enviar_bytes(
        &self,
        peer: &PeerDescubierto,
        nombre: &str,
        datos: &[u8],
    ) -> Result<(), String> {
        log::warn!("[P2P] Conectando a {} ({})...", peer.nombre, redactar_ip(&peer.ip));
        let mut tls_stream = self.conectar_tls(peer)?;
        enviar_archivo(&mut tls_stream, nombre, datos)?;
        log::info!("[OK] Mensaje enviado a {}.", peer.nombre);
        Ok(())
    }

    fn conectar_tls(
        &self,
        peer: &PeerDescubierto,
    ) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, String> {
        let config_tls = self.construir_config_cliente(&peer.ip)?;
        let config_arc = Arc::new(config_tls);

        let stream = TcpStream::connect(format!("{}:{}", peer.ip, peer.puerto))
            .map_err(|e| format!("No se pudo conectar a {}: {}", peer.ip, e))?;

        let server_name = ServerName::try_from(peer.nombre.clone())
            .or_else(|_| ServerName::try_from("localhost"))
            .map_err(|e| format!("ServerName inválido para '{}': {}", peer.nombre, e))?;

        let conn = rustls::ClientConnection::new(config_arc, server_name)
            .map_err(|e| format!("Error conexión TLS: {}", e))?;

        log::warn!("[P2P] Túnel mTLS establecido con {}.", peer.nombre);
        Ok(rustls::StreamOwned::new(conn, stream))
    }

    fn construir_config_cliente(&self, peer_ip: &str) -> Result<ClientConfig, String> {
        let (cert_der, clave_der) = GestorCertificados::generar_o_cargar()?;
        let cert = CertificateDer::from(cert_der);
        let clave = PrivateKeyDer::Pkcs8(clave_der.to_vec().into());

        // mTLS: el cliente presenta su certificado al servidor
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(VerificadorPinning {
                peer_ip: peer_ip.to_string(),
                subclave_hex: self.subclave_hex.clone(),
            }))
            .with_client_auth_cert(vec![cert], clave)
            .map_err(|e| format!("Error configurando cert cliente mTLS: {}", e))?;

        Ok(config)
    }
}

// ============================================================
// APROBACIÓN DE PEERS PENDIENTES (M9 TOFU)
// ============================================================

/// Devuelve los peers pendientes de aprobación como "fp8:ip_redactada".
pub fn listar_peers_pendientes() -> Vec<String> {
    PEERS_PENDIENTES
        .lock()
        .map(|g| g.iter().map(|(fp, ip)| format!("{}:{}", &fp[..8.min(fp.len())], ip)).collect())
        .unwrap_or_default()
}

/// Aprueba un peer pendiente por su fingerprint (completo o los 8 primeros chars).
pub fn aprobar_peer_pendiente(fp_input: &str) -> Result<(), String> {
    let _guard = CERTS_AUTORIZADOS_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let mut pendientes = PEERS_PENDIENTES.lock().map_err(|_| "Lock error".to_string())?;
    let pos = pendientes
        .iter()
        .position(|(fp, _)| fp == fp_input || fp.starts_with(fp_input))
        .ok_or("Peer no encontrado en pendientes")?;
    let (fp_completo, _) = pendientes.remove(pos);
    let mut autorizados = cargar_certs_autorizados();
    autorizados.insert(fp_completo);
    guardar_certs_autorizados(&autorizados);
    Ok(())
}
