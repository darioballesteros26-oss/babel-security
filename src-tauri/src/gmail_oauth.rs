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
// CREDENCIALES GCP — RELLENA ANTES DE COMPILAR
// ──────────────────────────────────────────────────────────────────────────────
pub const CLIENT_ID: &str = "673788639619-18fp4qa704t8umn4ben55o0p4d37dq2m.apps.googleusercontent.com";
pub const CLIENT_SECRET: &str = "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";
// ──────────────────────────────────────────────────────────────────────────────

const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const REVOKE_URL: &str = "https://oauth2.googleapis.com/revoke";
const USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v2/userinfo";
const OAUTH_FILE: &str = "oauth_gmail.babel";

pub const SCOPE: &str = "https://mail.google.com/";

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Mutex;
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
// No se persiste en disco — solo dura lo que dura el proceso.
static TOKEN_CACHE: Mutex<Option<(String, u64, u64)>> = Mutex::new(None);

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

fn puerto_libre() -> Result<u16, String> {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .map_err(|e| format!("No se pudo reservar puerto local: {}", e))
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
}

pub fn construir_flujo(client_id: &str) -> Result<FlujoPKCE, String> {
    let verifier = generar_verifier();
    let challenge = generar_challenge(&verifier);
    let puerto = puerto_libre()?;
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

    Ok(FlujoPKCE { url_auth, verifier, puerto })
}

// ──────────────────────────────────────────────────────────────────────────────
// FLUJO PKCE — PASO 2: escuchar callback en localhost
// ──────────────────────────────────────────────────────────────────────────────

pub fn capturar_codigo(puerto: u16) -> Result<String, String> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", puerto))
        .map_err(|e| format!("No se pudo abrir puerto {}: {}", puerto, e))?;

    let (mut stream, _) = listener
        .accept()
        .map_err(|e| format!("Error esperando callback OAuth: {}", e))?;

    let mut buf = vec![0u8; 4096];
    let n = stream
        .read(&mut buf)
        .map_err(|e| format!("Error leyendo petición: {}", e))?;

    let html = concat!(
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
    let _ = stream.write_all(html.as_bytes());

    let peticion = String::from_utf8_lossy(&buf[..n]);
    let primera_linea = peticion.lines().next().unwrap_or("");
    // "GET /callback?code=XXXX&scope=... HTTP/1.1"
    let path = primera_linea.split_whitespace().nth(1).unwrap_or("");
    let qs = path.split('?').nth(1).unwrap_or("");

    if let Some(par) = qs.split('&').find(|p| p.starts_with("code=")) {
        return Ok(par[5..].to_string());
    }

    let error = qs
        .split('&')
        .find(|p| p.starts_with("error="))
        .map(|p| p[6..].to_string())
        .unwrap_or_else(|| "respuesta inesperada".to_string());
    Err(format!("Google denegó el acceso: {}", error))
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

    let resp = ureq::post(TOKEN_URL)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&cuerpo)
        .map_err(|e| format!("Error intercambiando código OAuth: {}", e))?;

    let tokens: RespToken = resp
        .into_json()
        .map_err(|e| format!("Respuesta de token inválida: {}", e))?;

    let refresh = tokens.refresh_token.ok_or(
        "Google no devolvió refresh_token. \
         Asegúrate de que el scope es mail.google.com y prompt=consent."
            .to_string(),
    )?;

    let email = ureq::get(USERINFO_URL)
        .set(
            "Authorization",
            &format!("Bearer {}", tokens.access_token),
        )
        .call()
        .ok()
        .and_then(|r| r.into_json::<UserInfo>().ok())
        .and_then(|u| u.email)
        .unwrap_or_default();

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

    let resp = ureq::post(TOKEN_URL)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&cuerpo)
        .map_err(|e| format!("Error refrescando access token: {}", e))?;

    let tokens: RespToken = resp
        .into_json()
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
                return Ok(token.clone());
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
        *cache = Some((nuevo_token.clone(), ahora, expires));
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

pub fn revocar_oauth(client_id: &str, client_secret: &str, subclave_hex: &str) {
    // Intentar revocar en Google (no fatal si falla)
    if let Some(tokens) = cargar_tokens_oauth(subclave_hex) {
        // Intentar obtener un access_token fresco para revocar
        if let Ok(at) = refrescar(client_id, client_secret, &tokens.refresh_token) {
            let _ = ureq::post(REVOKE_URL)
                .set("Content-Type", "application/x-www-form-urlencoded")
                .send_string(&format!("token={}", pct(&at.0)));
        }
    }
    let _ = std::fs::remove_file(crate::babel_dir().join(OAUTH_FILE));
    invalidar_cache();
}

