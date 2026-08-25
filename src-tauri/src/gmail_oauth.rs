// OAuth 2.0 PKCE para Gmail — flujo Desktop App (RFC 7636)
//
// SETUP ANTES DE COMPILAR:
//   1. Crea un proyecto en https://console.cloud.google.com/
//   2. APIs & Services → Enable → "Gmail API"
//   3. APIs & Services → Credentials → Create → OAuth 2.0 Client ID
//      Tipo: "Desktop app" → descarga el JSON
//   4. Copia client_id y client_secret en las constantes de abajo.
//   5. OAuth consent screen → add test users (hasta 100 sin verificación).
//
// SCOPES: https://mail.google.com/
//   Clasificación Google: RESTRINGIDO
//   → Requiere verificación de seguridad para >100 usuarios.
//   → En "Testing" mode (consola GCP) funciona sin verificación hasta 100 cuentas.
//   → Es el único scope válido para IMAP/SMTP con XOAUTH2.

// ──────────────────────────────────────────────────────────────────────────────
// CREDENCIALES GCP — nunca hardcodear aquí.
// Definir en el entorno ANTES de compilar (o en .cargo/config.toml bajo [env],
// asegurándose de que ese archivo NO esté versionado):
//
//   export BABEL_GOOGLE_CLIENT_ID="673788....apps.googleusercontent.com"
//   export BABEL_GOOGLE_CLIENT_SECRET="GOCSPX-..."
//
// Si las variables no están definidas en tiempo de compilación, las constantes
// quedan vacías y las funciones que las usan devuelven error descriptivo.
// ──────────────────────────────────────────────────────────────────────────────
pub const CLIENT_ID: &str = match option_env!("BABEL_GOOGLE_CLIENT_ID") {
    Some(v) => v,
    None => "",
};
pub const CLIENT_SECRET: &str = match option_env!("BABEL_GOOGLE_CLIENT_SECRET") {
    Some(v) => v,
    None => "",
};
// ──────────────────────────────────────────────────────────────────────────────

const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const REVOKE_URL: &str = "https://oauth2.googleapis.com/revoke";
const USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v2/userinfo";
const OAUTH_FILE: &str = "oauth_gmail.babel";

// mail.google.com: acceso IMAP/SMTP. email: permite leer el email del usuario vía userinfo.
pub const SCOPE: &str = "https://mail.google.com/ email";

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use zeroize::{Zeroize, Zeroizing};

// ──────────────────────────────────────────────────────────────────────────────
// TIPOS
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct TokensGmail {
    pub refresh_token: String,
    pub email: String,
}

// Caché de access token en memoria: (token, unix_ts_obtenido, expires_in_secs)
// Zeroizing<String> garantiza que el token se borra de RAM al reemplazarlo o al salir.
// No se persiste en disco — solo dura lo que dura el proceso.
static TOKEN_CACHE: Mutex<Option<(Zeroizing<String>, u64, u64)>> = Mutex::new(None);

// ──────────────────────────────────────────────────────────────────────────────
// PKCE HELPERS
// ──────────────────────────────────────────────────────────────────────────────

fn generar_verifier() -> Zeroizing<String> {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    Zeroizing::new(B64URL.encode(bytes))
}

fn generar_challenge(verifier: &str) -> String {
    B64URL.encode(Sha256::digest(verifier.as_bytes()))
}

// Percent-encode para parámetros de URL (RFC 3986 §2.1).
fn pct(s: &str) -> String {
    s.bytes()
        .flat_map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![b as char]
            }
            other => format!("%{:02X}", other).chars().collect(),
        })
        .collect()
}

// ──────────────────────────────────────────────────────────────────────────────
// FLUJO PKCE — PASO 1: construir URL + estado
// ──────────────────────────────────────────────────────────────────────────────

pub struct FlujoPKCE {
    pub url_auth: String,
    pub verifier: Zeroizing<String>,
    pub puerto: u16,
    // El listener se crea aquí y se mantiene vivo hasta capturar_codigo,
    // evitando la race condition TOCTOU donde el OS reasigna el puerto
    // entre puerto_libre() y el bind del hilo.
    pub listener: TcpListener,
}

pub fn construir_flujo(client_id: &str) -> Result<FlujoPKCE, String> {
    if client_id.is_empty() {
        return Err(
            "Gmail OAuth no configurado. Define BABEL_GOOGLE_CLIENT_ID en el entorno \
             de compilación (ver gmail_oauth.rs para instrucciones)."
                .into(),
        );
    }
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("No se pudo abrir servidor OAuth: {}", e))?;
    let puerto = listener
        .local_addr()
        .map_err(|e| format!("No se pudo obtener puerto OAuth: {}", e))?
        .port();

    let verifier = generar_verifier();
    let challenge = generar_challenge(&verifier);
    let redirect = format!("http://127.0.0.1:{}/callback", puerto);

    let url_auth = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope={}\
         &code_challenge={}&code_challenge_method=S256&access_type=offline&prompt=consent",
        AUTH_URL,
        pct(client_id),
        pct(&redirect),
        pct(SCOPE),
        challenge,
    );

    Ok(FlujoPKCE { url_auth, verifier, puerto, listener })
}

// ──────────────────────────────────────────────────────────────────────────────
// FLUJO PKCE — PASO 2: escuchar callback en localhost
// ──────────────────────────────────────────────────────────────────────────────

// Escucha en el listener ya creado por construir_flujo.
// Itera conexiones hasta encontrar el callback real con ?code= o ?error=,
// descartando peticiones auxiliares del navegador (favicon, etc.).
// Timeout de 10 minutos para no colgar el hilo si el usuario cierra el browser.
pub fn capturar_codigo(listener: TcpListener) -> Result<String, String> {
    let html_ok = concat!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n",
        "<!DOCTYPE html><html><head><meta charset=utf-8>",
        "<style>body{font-family:sans-serif;background:#0a0a0a;color:#c8a96e;",
        "display:flex;align-items:center;justify-content:center;height:100vh;margin:0}",
        ".box{text-align:center;padding:2em}</style></head>",
        "<body><div class=box>",
        "<div style='font-size:3em;margin-bottom:.5em'>&#10003;</div>",
        "<h2>Babel \u{2014} Autenticaci\u{f3}n completada</h2>",
        "<p style='color:#888'>Puedes cerrar esta pesta\u{f1}a y volver a Babel.</p>",
        "</div></body></html>",
    );
    let html_ignore = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

    // Iterar hasta recibir la petición de callback (máx 20 intentos para ignorar
    // peticiones auxiliares del browser: favicon, prefetch, etc.)
    for _ in 0..20 {
        let (mut stream, _) = match listener.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                   || e.kind() == std::io::ErrorKind::TimedOut => {
                return Err("Tiempo de espera agotado: el usuario no completó el flujo OAuth".to_string());
            }
            Err(e) => return Err(format!("Error esperando callback OAuth: {}", e)),
        };

        let mut buf = vec![0u8; 8192];
        let n = match stream.read(&mut buf) {
            Ok(n) => n,
            Err(_) => continue,
        };
        if n == 0 { continue; }

        let peticion = String::from_utf8_lossy(&buf[..n]);
        let primera_linea = peticion.lines().next().unwrap_or("");
        // "GET /callback?code=XXXX&scope=... HTTP/1.1"
        let path = primera_linea.split_whitespace().nth(1).unwrap_or("");

        // Ignorar peticiones que no son el callback de OAuth
        if !path.starts_with("/callback") {
            let _ = stream.write_all(html_ignore.as_bytes());
            continue;
        }

        let qs = path.split('?').nth(1).unwrap_or("");

        if let Some(par) = qs.split('&').find(|p| p.starts_with("code=")) {
            let _ = stream.write_all(html_ok.as_bytes());
            return Ok(par[5..].to_string());
        }

        let error = qs
            .split('&')
            .find(|p| p.starts_with("error="))
            .map(|p| p[6..].to_string())
            .unwrap_or_else(|| "respuesta inesperada".to_string());
        let _ = stream.write_all(html_ignore.as_bytes());
        return Err(format!("Google denegó el acceso: {}", error));
    }

    Err("No se recibió el callback OAuth tras varios intentos".to_string())
}

// ──────────────────────────────────────────────────────────────────────────────
// HTTPS CON RUSTLS + WEBPKI-ROOTS (sin confiar en el store del sistema)
// ──────────────────────────────────────────────────────────────────────────────

fn crear_config_tls() -> Arc<rustls::ClientConfig> {
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

// POST HTTPS usando rustls directamente, ignorando el CA store del sistema.
// Previene MITM por CAs corporativas o comprometidas instaladas por el SO.
fn post_https(host: &str, path: &str, body: &str, content_type: &str) -> Result<String, String> {
    let config = crear_config_tls();
    let server_name: rustls::pki_types::ServerName<'static> = host.to_owned()
        .try_into()
        .map_err(|_| format!("Hostname TLS inválido: {}", host))?;
    let conn = rustls::ClientConnection::new(config, server_name)
        .map_err(|e| format!("TLS init: {}", e))?;
    let tcp = std::net::TcpStream::connect(format!("{}:443", host))
        .map_err(|e| format!("TCP: {}", e))?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(30))).ok();
    tcp.set_write_timeout(Some(std::time::Duration::from_secs(30))).ok();
    let mut tls = rustls::StreamOwned::new(conn, tcp);

    let peticion = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, host, content_type, body.len(), body
    );
    tls.write_all(peticion.as_bytes())
        .map_err(|e| format!("Error enviando: {}", e))?;

    let mut respuesta = Vec::new();
    tls.read_to_end(&mut respuesta)
        .map_err(|e| format!("Error leyendo respuesta: {}", e))?;

    let respuesta_str = String::from_utf8_lossy(&respuesta).to_string();
    let status: u16 = respuesta_str.split_whitespace().nth(1)
        .and_then(|s| s.parse().ok()).unwrap_or(0);
    let body_inicio = respuesta_str.find("\r\n\r\n")
        .ok_or_else(|| "Respuesta HTTP sin separador".to_string())? + 4;
    let body_resp = respuesta_str[body_inicio..].to_string();

    if (200..300).contains(&status) {
        Ok(body_resp)
    } else {
        Err(format!("HTTP {}: {}", status, body_resp))
    }
}

// GET HTTPS con Authorization Bearer usando rustls.
fn get_https_bearer(host: &str, path: &str, token: &str) -> Result<String, String> {
    let config = crear_config_tls();
    let server_name: rustls::pki_types::ServerName<'static> = host.to_owned()
        .try_into()
        .map_err(|_| format!("Hostname TLS inválido: {}", host))?;
    let conn = rustls::ClientConnection::new(config, server_name)
        .map_err(|e| format!("TLS init: {}", e))?;
    let tcp = std::net::TcpStream::connect(format!("{}:443", host))
        .map_err(|e| format!("TCP: {}", e))?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(30))).ok();
    let mut tls = rustls::StreamOwned::new(conn, tcp);

    let peticion = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
        path, host, token
    );
    tls.write_all(peticion.as_bytes())
        .map_err(|e| format!("Error enviando: {}", e))?;

    let mut respuesta = Vec::new();
    tls.read_to_end(&mut respuesta)
        .map_err(|e| format!("Error leyendo respuesta: {}", e))?;

    let respuesta_str = String::from_utf8_lossy(&respuesta).to_string();
    let status: u16 = respuesta_str.split_whitespace().nth(1)
        .and_then(|s| s.parse().ok()).unwrap_or(0);
    let body_inicio = respuesta_str.find("\r\n\r\n")
        .ok_or_else(|| "Respuesta HTTP sin separador".to_string())? + 4;
    let body_resp = respuesta_str[body_inicio..].to_string();

    if (200..300).contains(&status) {
        Ok(body_resp)
    } else {
        Err(format!("HTTP {}: {}", status, body_resp))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// FLUJO PKCE — PASO 3: intercambiar código por tokens
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RespToken {
    access_token: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
}

#[derive(Deserialize)]
struct UserInfo {
    email: Option<String>,
}

pub struct TokensNuevos {
    pub refresh_token: Zeroizing<String>,
    pub email: String,
}

pub fn intercambiar_codigo(
    client_id: &str,
    client_secret: &str,
    code: &str,
    verifier: &str,
    puerto: u16,
) -> Result<TokensNuevos, String> {
    let redirect = format!("http://127.0.0.1:{}/callback", puerto);
    let cuerpo = format!(
        "client_id={}&client_secret={}&code={}&code_verifier={}\
         &grant_type=authorization_code&redirect_uri={}",
        pct(client_id),
        pct(client_secret),
        pct(code),
        pct(verifier),
        pct(&redirect),
    );

    let body_str = post_https("oauth2.googleapis.com", "/token", &cuerpo,
        "application/x-www-form-urlencoded")
        .map_err(|e| format!("Google rechazó el código OAuth: {}", e))?;
    let tokens: RespToken = serde_json::from_str(&body_str)
        .map_err(|e| format!("Respuesta de token inválida: {}", e))?;

    let refresh = tokens.refresh_token.ok_or(
        "Google no devolvió refresh_token. \
         Asegúrate de que el scope es mail.google.com y prompt=consent."
            .to_string(),
    )?;

    let email = get_https_bearer("www.googleapis.com", "/oauth2/v2/userinfo",
        &tokens.access_token)
        .ok()
        .and_then(|b| serde_json::from_str::<UserInfo>(&b).ok())
        .and_then(|u| u.email)
        .unwrap_or_default();

    if email.is_empty() {
        return Err(
            "No se pudo obtener el email de la cuenta Google. \
             Comprueba la conexión y que el scope incluye 'email'."
                .to_string(),
        );
    }

    Ok(TokensNuevos {
        refresh_token: Zeroizing::new(refresh),
        email,
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// REFRESCO AUTOMÁTICO
// ──────────────────────────────────────────────────────────────────────────────

fn ahora_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn refrescar(
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> Result<(String, u64), String> {
    let cuerpo = format!(
        "client_id={}&client_secret={}&refresh_token={}&grant_type=refresh_token",
        pct(client_id),
        pct(client_secret),
        pct(refresh_token),
    );

    let body_str = post_https("oauth2.googleapis.com", "/token", &cuerpo,
        "application/x-www-form-urlencoded")
        .map_err(|e| format!("Error refrescando access token: {}", e))?;
    let tokens: RespToken = serde_json::from_str(&body_str)
        .map_err(|e| format!("Respuesta de refresco inválida: {}", e))?;

    Ok((tokens.access_token, tokens.expires_in.unwrap_or(3600)))
}

/// Devuelve un access token válido, refrescándolo si le quedan menos de 60 s.
pub fn obtener_access_token(
    client_id: &str,
    client_secret: &str,
    subclave_hex: &str,
) -> Result<String, String> {
    let ahora = ahora_secs();

    // Consultar caché en memoria
    {
        let cache = TOKEN_CACHE.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((ref token, obtenido, expires)) = *cache {
            if ahora < obtenido + expires.saturating_sub(60) {
                return Ok(token.as_str().to_string());
            }
        }
    }

    // Cargar refresh_token cifrado y pedir nuevo access_token
    let almacenados = cargar_tokens_oauth(subclave_hex)
        .ok_or("No hay credenciales Gmail OAuth. Conéctate primero.")?;

    let (nuevo_token, expires) = refrescar(client_id, client_secret, &almacenados.refresh_token)?;

    // Actualizar caché
    {
        let mut cache = TOKEN_CACHE.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((ref mut old, _, _)) = *cache {
            old.zeroize();
        }
        *cache = Some((Zeroizing::new(nuevo_token.clone()), ahora, expires));
    }

    Ok(nuevo_token)
}

/// Invalida la caché en memoria (llamar al revocar o cerrar sesión OAuth).
pub fn invalidar_cache() {
    let mut cache = TOKEN_CACHE.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((ref mut token, _, _)) = *cache {
        token.zeroize();
    }
    *cache = None;
}

// ──────────────────────────────────────────────────────────────────────────────
// ALMACENAMIENTO CIFRADO
// ──────────────────────────────────────────────────────────────────────────────

pub fn guardar_tokens_oauth(tokens: &TokensGmail, subclave_hex: &str) -> Result<(), String> {
    let json = serde_json::to_string(tokens)
        .map_err(|e| format!("Error serializando tokens OAuth: {}", e))?;
    let cifrado = crate::seguridad::blindar_documento(&json, subclave_hex)
        .map_err(|e| format!("Error cifrando tokens OAuth: {}", e))?;
    crate::escribir_privado(crate::babel_dir().join(OAUTH_FILE), cifrado)
        .map_err(|e| format!("Error guardando tokens OAuth: {}", e))
}

pub fn cargar_tokens_oauth(subclave_hex: &str) -> Option<TokensGmail> {
    let bytes = std::fs::read(crate::babel_dir().join(OAUTH_FILE)).ok()?;
    let json = Zeroizing::new(crate::seguridad::descifrar_documento(bytes, subclave_hex).ok()?);
    serde_json::from_str(json.as_str()).ok()
}

pub fn tiene_oauth_guardado() -> bool {
    crate::babel_dir().join(OAUTH_FILE).exists()
}

pub fn revocar_oauth(_client_id: &str, _client_secret: &str, subclave_hex: &str) -> Result<(), String> {
    // Revocar el refresh_token directamente (la API de Google acepta ambos;
    // usar el refresh_token es más robusto porque funciona aunque el access_token
    // haya expirado o no se pueda refrescar).
    if let Some(tokens) = cargar_tokens_oauth(subclave_hex) {
        post_https("oauth2.googleapis.com", "/revoke",
            &format!("token={}", pct(&tokens.refresh_token)),
            "application/x-www-form-urlencoded")
            .map_err(|e| format!("Error revocando token en Google: {}", e))?;
    }
    let _ = std::fs::remove_file(crate::babel_dir().join(OAUTH_FILE));
    invalidar_cache();
    Ok(())
}

