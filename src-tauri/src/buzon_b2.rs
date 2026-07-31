// Fase 3 sincronización: buzón temporal en Backblaze B2 (S3-compatible).
//
// Implementación sin dependencias nuevas: usa SigV4 (hmac+sha2+hex ya
// presentes) + ureq bloqueante envuelto en spawn_blocking.
// El intermediario nunca ve el contenido — solo bytes ya cifrados con la
// clave AES-256-GCM del par. La clave nunca sale del dispositivo.
//
// Configuración: ~/Babel/b2.json (añadido a .gitignore)
// Formato:
//   {
//     "key_id": "...",
//     "application_key": "...",
//     "bucket": "babel-sincronizacion-security",
//     "endpoint": "https://s3.us-west-004.backblazeb2.com",
//     "region": "us-west-004"
//   }

use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

// ── Configuración ─────────────────────────────────────────────────────────────

#[derive(Deserialize, Clone)]
struct ConfigB2 {
    key_id: String,
    application_key: String,
    bucket: String,
    endpoint: String,
    region: String,
}

pub fn ruta_config() -> std::path::PathBuf {
    crate::babel_dir().join("b2.json")
}

fn cargar_config() -> Result<ConfigB2, String> {
    let ruta = ruta_config();
    if !ruta.exists() {
        return Err(format!(
            "Configuración B2 no encontrada en {}. \
             Crea el archivo con las credenciales de Backblaze.",
            ruta.display()
        ));
    }
    let contenido = std::fs::read_to_string(&ruta)
        .map_err(|e| format!("Error al leer b2.json: {e}"))?;
    serde_json::from_str::<ConfigB2>(&contenido)
        .map_err(|e| format!("Error al parsear b2.json: {e}"))
}

fn host_de_endpoint(endpoint: &str) -> &str {
    endpoint
        .trim_start_matches("https://")
        .trim_start_matches("http://")
}

// ── SigV4 ─────────────────────────────────────────────────────────────────────

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    type H = Hmac<Sha256>;
    let mut mac = H::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

// Devuelve el valor del header Authorization para una petición S3 con
// UNSIGNED-PAYLOAD (B2 lo acepta; evita hashear el cuerpo dos veces).
fn sigv4_auth(
    method: &str,
    host: &str,
    path: &str,   // URI codificada, empieza con /
    query: &str,  // query string ya codificada y ordenada (sin "?")
    region: &str,
    key_id: &str,
    secret: &str,
    datetime: &str, // YYYYMMDDTHHmmSSZ
) -> String {
    let date = &datetime[..8];

    // canonical headers: ordenados, lowercase, terminan en \n
    let canonical_headers = format!(
        "host:{}\nx-amz-content-sha256:UNSIGNED-PAYLOAD\nx-amz-date:{}\n",
        host, datetime
    );
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\nUNSIGNED-PAYLOAD",
        method, path, query, canonical_headers, signed_headers
    );

    let scope = format!("{}/{}/s3/aws4_request", date, region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        datetime,
        scope,
        sha256_hex(canonical_request.as_bytes())
    );

    let k_date = hmac_sha256(format!("AWS4{}", secret).as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    format!(
        "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature={}",
        key_id, scope, signed_headers, signature
    )
}

// URL-encode RFC 3986 (para nombres de objeto en S3)
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b'/' => out.push('/'), // mantenemos "/" en paths de objeto
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

// URL-encode para valores de query string (sí codifica "/")
fn url_encode_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

// ── Operaciones S3 síncronas (llamadas desde spawn_blocking) ─────────────────

fn ahora_datetime() -> String {
    Utc::now().format("%Y%m%dT%H%M%SZ").to_string()
}

fn s3_put_sync(cfg: &ConfigB2, key: &str, data: &[u8]) -> Result<(), String> {
    let host = host_de_endpoint(&cfg.endpoint);
    let path = format!("/{}/{}", cfg.bucket, url_encode(key));
    let dt = ahora_datetime();
    let auth = sigv4_auth("PUT", host, &path, "", &cfg.region, &cfg.key_id, &cfg.application_key, &dt);
    let url = format!("{}{}", cfg.endpoint, path);

    ureq::put(&url)
        .set("Authorization", &auth)
        .set("x-amz-date", &dt)
        .set("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
        .set("Content-Type", "application/octet-stream")
        .send_bytes(data)
        .map_err(|e| format!("Error PUT B2: {e}"))?;
    Ok(())
}

fn s3_get_sync(cfg: &ConfigB2, key: &str) -> Result<Vec<u8>, String> {
    let host = host_de_endpoint(&cfg.endpoint);
    let path = format!("/{}/{}", cfg.bucket, url_encode(key));
    let dt = ahora_datetime();
    let auth = sigv4_auth("GET", host, &path, "", &cfg.region, &cfg.key_id, &cfg.application_key, &dt);
    let url = format!("{}{}", cfg.endpoint, path);

    let resp = ureq::get(&url)
        .set("Authorization", &auth)
        .set("x-amz-date", &dt)
        .set("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
        .call()
        .map_err(|e| format!("Error GET B2: {e}"))?;

    let mut bytes = Vec::new();
    resp.into_reader()
        .read_to_end(&mut bytes)
        .map_err(|e| format!("Error leyendo cuerpo B2: {e}"))?;
    Ok(bytes)
}

fn s3_list_sync(cfg: &ConfigB2, prefijo: &str) -> Result<Vec<String>, String> {
    let host = host_de_endpoint(&cfg.endpoint);
    let path = format!("/{}/", cfg.bucket);
    // query string ordenada y codificada
    let query = format!(
        "list-type=2&prefix={}",
        url_encode_query(prefijo)
    );
    let dt = ahora_datetime();
    let auth = sigv4_auth("GET", host, &path, &query, &cfg.region, &cfg.key_id, &cfg.application_key, &dt);
    let url = format!("{}{}?{}", cfg.endpoint, path, query);

    let resp = ureq::get(&url)
        .set("Authorization", &auth)
        .set("x-amz-date", &dt)
        .set("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
        .call()
        .map_err(|e| format!("Error LIST B2: {e}"))?;

    let xml = resp
        .into_string()
        .map_err(|e| format!("Error leyendo respuesta LIST: {e}"))?;

    // Extraer <Key>...</Key> sin crate XML (la respuesta es ASCII/UTF-8 predecible)
    let keys: Vec<String> = xml
        .split("<Key>")
        .skip(1)
        .filter_map(|s| s.split("</Key>").next())
        .map(|s| s.to_string())
        .collect();
    Ok(keys)
}

fn s3_delete_sync(cfg: &ConfigB2, key: &str) -> Result<(), String> {
    let host = host_de_endpoint(&cfg.endpoint);
    let path = format!("/{}/{}", cfg.bucket, url_encode(key));
    let dt = ahora_datetime();
    let auth = sigv4_auth(
        "DELETE", host, &path, "", &cfg.region, &cfg.key_id, &cfg.application_key, &dt,
    );
    let url = format!("{}{}", cfg.endpoint, path);

    ureq::delete(&url)
        .set("Authorization", &auth)
        .set("x-amz-date", &dt)
        .set("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
        .call()
        .map_err(|e| format!("Error DELETE B2: {e}"))?;
    Ok(())
}

// ── Tipos públicos ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendienteB2 {
    pub key: String,
    pub timestamp: u64,
    pub nombre_archivo: String,
    pub id_par: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConteoB2 {
    pub id_par: String,
    pub nombre: String,
    pub n: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResultadoAplicarB2 {
    pub key: String,
    pub tipo: String,
    pub contenido: String,
    pub nombre_origen: String,
    pub timestamp: u64,
}

// Payload cifrado almacenado en B2
#[derive(Serialize, Deserialize)]
struct PayloadB2 {
    tipo: String,
    contenido: String,
    timestamp: u64,
    nombre_origen: String,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn ahora() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// Identificador del par derivado de la clave compartida: sha256(clave_hex)[..8 bytes → 16 hex].
// Ambos dispositivos del par tienen la misma clave, luego el mismo prefijo S3.
// Sin esto, A usaría su propio ID local de B y B usaría su propio ID local de A
// → distintos prefijos → los mensajes nunca se encontrarían.
fn id_de_par(clave_hex: &str) -> String {
    hex::encode(&Sha256::digest(clave_hex.as_bytes())[..8])
}

fn prefijo_par(clave_hex: &str) -> String {
    format!("pares/{}/", id_de_par(clave_hex))
}

fn clave_objeto(clave_hex: &str, tipo: &str) -> String {
    format!("pares/{}/{}_{}.enc", id_de_par(clave_hex), ahora(), tipo)
}

// ── Subir al buzón ────────────────────────────────────────────────────────────

pub async fn subir_al_buzon(
    tipo: &str,
    contenido: &str,
    nombre_origen: &str,
    clave_hex: &str,
) -> Result<String, String> {
    let cfg = cargar_config()?;

    let payload = PayloadB2 {
        tipo: tipo.to_string(),
        contenido: contenido.to_string(),
        timestamp: ahora(),
        nombre_origen: nombre_origen.to_string(),
    };
    let json = serde_json::to_string(&payload)
        .map_err(|e| format!("Error serializando payload: {e}"))?;

    // Cifrar con la clave del par — el intermediario nunca ve el contenido
    let cifrado = crate::seguridad::blindar_documento(&json, clave_hex)
        .map_err(|e| format!("Error al cifrar payload B2: {e}"))?;

    // Prefijo derivado de la clave — mismo en ambos lados del par
    let key = clave_objeto(clave_hex, tipo);
    let key2 = key.clone();

    tokio::task::spawn_blocking(move || s3_put_sync(&cfg, &key2, &cifrado))
        .await
        .map_err(|e| format!("B2 thread error: {e}"))?
        .map_err(|e| format!("Error subiendo a B2: {e}"))?;

    log::info!("[buzon_b2] Subido: {}", key);
    Ok(key)
}

// ── Listar pendientes para un par ─────────────────────────────────────────────

// clave_hex: la clave compartida del par (misma en ambos dispositivos).
// El prefijo S3 se deriva de la clave, no del ID local, para que ambos lados coincidan.
pub async fn listar_pendientes(clave_hex: &str) -> Result<Vec<PendienteB2>, String> {
    let cfg = cargar_config()?;
    let prefijo = prefijo_par(clave_hex);
    let par_id = id_de_par(clave_hex);

    let keys = tokio::task::spawn_blocking(move || s3_list_sync(&cfg, &prefijo))
        .await
        .map_err(|e| format!("B2 thread error: {e}"))?
        .map_err(|e| format!("Error listando B2: {e}"))?;

    let pendientes = keys
        .into_iter()
        .filter_map(|key| {
            let nombre_parte = key.rsplit('/').next()?.to_string();
            let guion = nombre_parte.find('_')?;
            let ts: u64 = nombre_parte[..guion].parse().ok()?;
            let nombre_archivo = nombre_parte[guion + 1..]
                .trim_end_matches(".enc")
                .to_string();
            Some(PendienteB2 {
                key,
                timestamp: ts,
                nombre_archivo,
                id_par: par_id.clone(),
            })
        })
        .collect();

    Ok(pendientes)
}

// ── Descargar, descifrar y borrar (solo si todo va bien) ──────────────────────

pub async fn descargar_y_aplicar(
    key: &str,
    clave_hex: &str,
) -> Result<ResultadoAplicarB2, String> {
    let cfg = cargar_config()?;
    let cfg_del = cfg.clone(); // clonar antes de que cfg sea movido al GET
    let key2 = key.to_string();

    let cifrado = tokio::task::spawn_blocking(move || s3_get_sync(&cfg, &key2))
        .await
        .map_err(|e| format!("B2 thread error: {e}"))?
        .map_err(|e| format!("Error descargando de B2: {e}"))?;

    // Si el descifrado falla → conservar el objeto para reintento, NO borrar
    let json = crate::seguridad::descifrar_documento(cifrado, clave_hex).map_err(|e| {
        log::error!(
            "[buzon_b2] Fallo al descifrar '{}': {} — objeto conservado para reintento",
            key,
            e
        );
        format!("Error de descifrado: {e}")
    })?;

    let payload: PayloadB2 = serde_json::from_str(&json).map_err(|e| {
        log::error!(
            "[buzon_b2] Payload inválido en '{}': {} — objeto conservado para reintento",
            key,
            e
        );
        format!("Error al parsear payload: {e}")
    })?;

    // Borrar SOLO después de descifrar y parsear con éxito
    let key3 = key.to_string();
    match tokio::task::spawn_blocking(move || s3_delete_sync(&cfg_del, &key3)).await {
        Ok(Ok(_)) => log::info!("[buzon_b2] Borrado tras aplicar: {}", key),
        Ok(Err(e)) => log::warn!("[buzon_b2] No se pudo borrar '{}': {}", key, e),
        Err(e) => log::warn!("[buzon_b2] B2 delete thread error '{}': {}", key, e),
    }

    Ok(ResultadoAplicarB2 {
        key: key.to_string(),
        tipo: payload.tipo,
        contenido: payload.contenido,
        nombre_origen: payload.nombre_origen,
        timestamp: payload.timestamp,
    })
}

// ── Conteo de pendientes para todos los dispositivos emparejados ──────────────

pub async fn contar_pendientes_todos(subclave_hex: &str) -> Vec<ConteoB2> {
    // Si B2 no está configurado, salir silenciosamente
    if cargar_config().is_err() {
        return Vec::new();
    }
    let emparejados = crate::sincronizacion::cargar_emparejados(subclave_hex);
    let mut resultado = Vec::new();
    for disp in emparejados {
        match listar_pendientes(&disp.clave_hex).await {
            Ok(p) if !p.is_empty() => resultado.push(ConteoB2 {
                id_par: disp.id.clone(),
                nombre: disp.nombre,
                n: p.len(),
            }),
            Ok(_) => {}
            Err(e) => log::warn!("[buzon_b2] Error listando para {}: {}", disp.id, e),
        }
    }
    resultado
}
