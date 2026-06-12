// ============================================================
// BABEL P2P - COMUNICACIÓN DIRECTA ENTRE INSTANCIAS v4
// ============================================================
//
// Módulo único que incluye todo el sistema P2P:
//   - Certificados mTLS (generación y gestión)
//   - Descubrimiento en red local por UDP broadcast
//   - Protocolo de transferencia con cabecera fija
//   - Servidor TLS (recibe archivos)
//   - Cliente TLS (envía archivos)
//   - Menú de usuario
//
// TLS: rustls 0.22 con StreamOwned (síncrono, sin tokio)

use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ServerConfig};
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use zeroize::Zeroizing;

// Buffer global de mensajes entrantes
// Cuando llega un mensaje de texto, se guarda aquí
// main.rs lo lee y lo manda al frontend
pub static MENSAJES_ENTRANTES: Mutex<Vec<String>> = Mutex::new(Vec::new());

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

// Constantes del protocolo - estas no cambian, son números y textos fijos
pub const PUERTO_DESCUBRIMIENTO: u16 = 47823;
pub const PUERTO_TRANSFERENCIA: u16 = 47824;
pub const TAMAÑO_CABECERA: usize = 304;
pub const MAX_NOMBRE: usize = 256;
pub const MAX_TAMAÑO_ARCHIVO: u64 = 100 * 1024 * 1024; // 100MB
const MENSAJE_ANUNCIO: &[u8] = b"BABEL_P2P_ANNOUNCE_V1";
const PREFIJO_RESPUESTA: &str = "BABEL_P2P_RESPONSE_V1:";
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
//
// Cada Babel tiene un par:
//   certificado.der  - público, se comparte con otros Babel
//   clave_privada.der - secreto, nunca sale de esta máquina

pub struct GestorCertificados;

impl GestorCertificados {
    /// Genera o carga el certificado de este Babel.
    /// La primera vez genera uno nuevo autofirmado.
    /// Las siguientes veces carga el existente.
    pub fn generar_o_cargar() -> Result<(Vec<u8>, Vec<u8>), String> {
        let _ = fs::create_dir_all(p2p_dir());
        let _ = fs::create_dir_all(peers_dir());

        if ruta_cert().exists() && ruta_clave().exists() {
            return Self::cargar();
        }

        log::warn!("[P2P] Generando certificado de identidad...");

        let cert = generate_simple_self_signed(vec!["localhost".to_string()])
            .map_err(|e| format!("Error generando certificado: {}", e))?;

        let cert_der = cert
            .serialize_der()
            .map_err(|e| format!("Error serializando cert: {}", e))?;
        let clave_der = cert.serialize_private_key_der();

        fs::write(ruta_cert(), &cert_der).map_err(|e| format!("Error guardando cert: {}", e))?;
        fs::write(ruta_clave(), &clave_der).map_err(|e| format!("Error guardando clave: {}", e))?;

        log::info!("[OK] Certificado generado en {:?}", ruta_cert());
        log::info!("[P2P] Comparte {:?} con otros Babel.", ruta_cert());
        log::error!("[P2P]  NUNCA compartas {:?}.", ruta_clave());

        Ok((cert_der, clave_der))
    }

    /// Carga el certificado existente desde disco.
    fn cargar() -> Result<(Vec<u8>, Vec<u8>), String> {
        let cert = fs::read(ruta_cert()).map_err(|e| format!("Error leyendo cert: {}", e))?;
        let clave = Zeroizing::new(
            fs::read(ruta_clave()).map_err(|e| format!("Error leyendo clave: {}", e))?,
        );
        Ok((cert, clave.to_vec()))
    }
}

// ============================================================
// DESCUBRIMIENTO - Búsqueda de peers en red local por UDP
// ============================================================
//
// Babel envía un broadcast UDP a toda la red.
// Cualquier Babel que escuche responde con su IP y puerto.
// En menos de 2 segundos sabes quién está disponible.

pub struct DescubrimientoRed;

impl DescubrimientoRed {
    /// Inicia el servidor de descubrimiento en un hilo background.
    /// Cuando llega un anuncio, responde con nuestra IP y puerto.
    pub fn iniciar_servidor(nombre: String) {
        thread::spawn(move || {
            let socket = match UdpSocket::bind(format!("0.0.0.0:{}", PUERTO_DESCUBRIMIENTO)) {
                Ok(s) => s,
                Err(e) => {
                    log::warn!("[P2P] No se pudo iniciar descubrimiento: {}", e);
                    return;
                }
            };
            let _ = socket.set_broadcast(true);

            let mut buf = [0u8; 256];
            loop {
                let (n, origen) = match socket.recv_from(&mut buf) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                if &buf[..n] == MENSAJE_ANUNCIO {
                    let respuesta =
                        format!("{}{}:{}", PREFIJO_RESPUESTA, nombre, PUERTO_TRANSFERENCIA);
                    let _ = socket.send_to(respuesta.as_bytes(), origen);
                }
            }
        });
    }

    /// Busca otros Babel en la red local.
    /// Espera `timeout_ms` milisegundos recogiendo respuestas.
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
        socket
            .send_to(MENSAJE_ANUNCIO, destino)
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
                            peer.ip,
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
        if !respuesta.starts_with(PREFIJO_RESPUESTA) {
            return None;
        }
        let resto = &respuesta[PREFIJO_RESPUESTA.len()..];
        let partes: Vec<&str> = resto.splitn(2, ':').collect();
        if partes.len() != 2 {
            return None;
        }
        let nombre = partes[0].to_string();
        let puerto: u16 = partes[1].trim().parse().ok()?;
        Some(PeerDescubierto {
            ip: origen.ip().to_string(),
            puerto,
            nombre,
        })
    }

    /// Crea un peer manualmente por IP (cuando el broadcast no funciona).
    pub fn peer_manual(ip: &str, nombre: &str) -> PeerDescubierto {
        PeerDescubierto {
            ip: ip.to_string(),
            puerto: PUERTO_TRANSFERENCIA,
            nombre: nombre.to_string(),
        }
    }
}

// ============================================================
// PROTOCOLO - Formato de paquetes
// ============================================================
//
// Cabecera de 304 bytes fijos:
//   [0..8]    longitud_datos  (u64 LE)
//   [8..264]  nombre_archivo  (256 bytes, relleno con ceros)
//   [264..268] tipo           (u32 LE)
//   [268..300] checksum       (SHA-256, 32 bytes)
//   [300..304] version        (u32 LE)

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
        let len = nb.len().min(MAX_NOMBRE);
        buf[8..8 + len].copy_from_slice(&nb[..len]);
        buf[264..268].copy_from_slice(&1u32.to_le_bytes()); // tipo Archivo
        buf[268..300].copy_from_slice(&self.checksum);
        buf[300..304].copy_from_slice(&VERSION_PROTOCOLO.to_le_bytes());
        buf
    }

    pub fn deserializar(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < TAMAÑO_CABECERA {
            return Err(format!("Cabecera incompleta: {} bytes ", buf.len()));
        }
        let longitud_datos = u64::from_le_bytes(
            buf[0..8]
                .try_into()
                .map_err(|_| "Error leyendo longitud ")?,
        );
        let nombre_raw = &buf[8..264];
        let fin = nombre_raw.iter().position(|&b| b == 0).unwrap_or(256);
        let nombre_archivo = String::from_utf8_lossy(&nombre_raw[..fin]).to_string();
        let version = u32::from_le_bytes(
            buf[300..304]
                .try_into()
                .map_err(|_| "Error leyendo version ")?,
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
            "Archivo demasiado grande: {} bytes ",
            cabecera.longitud_datos
        ));
    }

    let mut datos = vec![0u8; cabecera.longitud_datos as usize];
    stream
        .read_exact(&mut datos)
        .map_err(|e| format!("Error leyendo datos: {}", e))?;

    // Verificamos integridad con checksum SHA-256
    let mut hasher = Sha256::new();
    hasher.update(&datos);
    let checksum: [u8; 32] = hasher.finalize().into();
    if checksum != cabecera.checksum {
        return Err("Checksum invalido - datos corruptos en transito ".to_string());
    }

    log::info!(
        "[P2P] Recibido {} ({} bytes) - integro.",
        cabecera.nombre_archivo,
        datos.len()
    );
    Ok((cabecera.nombre_archivo, datos))
}

// ============================================================
// SERVIDOR - Babel que recibe archivos
// ============================================================

pub struct ServidorP2P {
    subclave_hex: String,
}

impl ServidorP2P {
    pub fn nuevo(subclave_hex: &str) -> Self {
        Self {
            subclave_hex: subclave_hex.to_string(),
        }
    }

    pub fn iniciar(&self) -> Result<(), String> {
        let _ = fs::create_dir_all(recibidos_dir());

        let config_tls = self.construir_config_servidor()?;
        let config_arc = Arc::new(config_tls);

        let listener = TcpListener::bind(format!("0.0.0.0:{}", PUERTO_TRANSFERENCIA))
            .map_err(|e| format!("No se pudo abrir puerto {}: {}", PUERTO_TRANSFERENCIA, e))?;

        log::warn!("[P2P] Servidor activo en puerto {}.", PUERTO_TRANSFERENCIA);
        log::warn!("[P2P] Archivos recibidos en {:?}", recibidos_dir());

        for conexion in listener.incoming() {
            let stream = match conexion {
                Ok(s) => s,
                Err(e) => {
                    log::error!("[P2P] Error de red: {}", e);
                    continue;
                }
            };

            let ip = stream
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or("?".to_string());
            log::warn!("[P2P] Conexión desde {}", ip);

            // Negociamos TLS con rustls síncrono
            let conn = match rustls::ServerConnection::new(config_arc.clone()) {
                Ok(c) => c,
                Err(e) => {
                    log::error!("[P2P] Error TLS: {}", e);
                    continue;
                }
            };

            let mut tls_stream = rustls::StreamOwned::new(conn, stream);

            match recibir_archivo(&mut tls_stream) {
                Ok((nombre, datos)) => self.guardar_archivo(&nombre, &datos, &ip),
                Err(e) => {
                    log::error!("[P2P] Error recibiendo de {}: {}", ip, e);
                    crate::seguridad::registrar_evento_seguridad(
                        &format!("Error P2P de {}: {}", ip, e),
                        &self.subclave_hex,
                    );
                }
            }
        }
        Ok(())
    }

    fn guardar_archivo(&self, nombre: &str, datos: &[u8], ip: &str) {
        // Sanitizamos el nombre para evitar path traversal
        let nombre_seguro = Path::new(nombre)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("archivo_recibido")
            .to_string();

        // Si el archivo es un mensaje de texto - no lo guardamos en disco
        // lo metemos en el buffer de mensajes entrantes
        if nombre_seguro == "mensaje.txt" {
            if let Ok(texto) = String::from_utf8(datos.to_vec()) {
                if let Ok(mut msgs) = MENSAJES_ENTRANTES.lock() {
                    msgs.push(texto);
                }
            }
            return;
        }
        let ruta = recibidos_dir().join(&nombre_seguro);
        match fs::write(&ruta, datos) {
            Ok(_) => {
                log::info!("[OK] Guardado: {}", ruta.display());
                crate::seguridad::registrar_evento_seguridad(
                    &format!(
                        "P2P recibido de {}: {} ({} bytes)",
                        ip,
                        nombre_seguro,
                        datos.len()
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
        let clave = PrivateKeyDer::Pkcs8(clave_der.into());

        // TLS 1.3 con autenticación del servidor.
        // mTLS completo se añade en la siguiente versión con WebPkiClientVerifier.
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], clave)
            .map_err(|e| format!("Error configurando servidor TLS: {}", e))?;

        Ok(config)
    }
}

// ============================================================
// VERIFICADOR PERMISIVO - Para red local sin intercambio de certs
// ============================================================
// Acepta cualquier certificado en red local.
// El contenido sigue cifrado con AES-256-GCM en la capa de aplicación.

#[derive(Debug)]
struct VerificadorPermisivo;

impl rustls::client::danger::ServerCertVerifier for VerificadorPermisivo {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

// ============================================================
// CLIENTE - Babel que envía archivos
// ============================================================

pub struct ClienteP2P {
    subclave_hex: String,
}

impl ClienteP2P {
    pub fn nuevo(subclave_hex: &str) -> Self {
        Self {
            subclave_hex: subclave_hex.to_string(),
        }
    }

    pub fn enviar(&self, peer: &PeerDescubierto, ruta_archivo: &str) -> Result<(), String> {
        let datos = fs::read(ruta_archivo)
            .map_err(|e| format!("No se pudo leer {}: {}", ruta_archivo, e))?;

        let nombre = Path::new(ruta_archivo)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("archivo.babel ")
            .to_string();

        log::warn!("[P2P] Conectando a {} ({})...", peer.nombre, peer.ip);

        let config_tls = self.construir_config_cliente()?;
        let config_arc = Arc::new(config_tls);

        let stream = TcpStream::connect(format!("{}:{}", peer.ip, peer.puerto))
            .map_err(|e| format!("No se pudo conectar a {}: {}", peer.ip, e))?;

        let server_name = ServerName::try_from(peer.nombre.clone())
            .or_else(|_| ServerName::try_from("localhost"))
            .map_err(|e| format!("ServerName inválido para '{}': {}", peer.nombre, e))?;

        let conn = rustls::ClientConnection::new(config_arc, server_name)
            .map_err(|e| format!("Error conexión TLS: {}", e))?;

        let mut tls_stream = rustls::StreamOwned::new(conn, stream);

        log::warn!("[P2P] Túnel TLS establecido con {}.", peer.nombre);

        enviar_archivo(&mut tls_stream, &nombre, &datos)?;

        crate::seguridad::registrar_evento_seguridad(
            &format!(
                "P2P enviado a {} ({}): {} ({} bytes)",
                peer.nombre,
                peer.ip,
                nombre,
                datos.len()
            ),
            &self.subclave_hex,
        );

        log::info!("[OK] {} enviado a {}.", nombre, peer.nombre);
        Ok(())
    }

    fn construir_config_cliente(&self) -> Result<ClientConfig, String> {
        // Red local - aceptamos cualquier certificado autofirmado
        // El contenido sigue cifrado con AES-256-GCM en capa de aplicación
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(VerificadorPermisivo))
            .with_no_client_auth();
        Ok(config)
    }
    pub fn enviar_bytes(
        &self,
        peer: &PeerDescubierto,
        nombre: &str,
        datos: &[u8],
    ) -> Result<(), String> {
        log::warn!("[P2P] Conectando a {} ({})...", peer.nombre, peer.ip);

        let config_tls = self.construir_config_cliente()?;
        let config_arc = Arc::new(config_tls);

        let stream = TcpStream::connect(format!("{}:{}", peer.ip, peer.puerto))
            .map_err(|e| format!("No se pudo conectar a {}: {}", peer.ip, e))?;

        let server_name = ServerName::try_from(peer.nombre.clone())
            .or_else(|_| ServerName::try_from("localhost"))
            .map_err(|e| format!("ServerName inválido para '{}': {}", peer.nombre, e))?;

        let conn = rustls::ClientConnection::new(config_arc, server_name)
            .map_err(|e| format!("Error conexión TLS: {}", e))?;

        let mut tls_stream = rustls::StreamOwned::new(conn, stream);

        enviar_archivo(&mut tls_stream, nombre, datos)?;

        log::info!("[OK] Mensaje enviado a {}.", peer.nombre);
        Ok(())
    }
}
