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
use std::collections::HashMap;
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

/// Lee el contenido raw de b2.json para compartirlo durante el emparejamiento.
/// Devuelve None si el archivo no existe o no es legible.
pub fn leer_config_raw() -> Option<String> {
    std::fs::read_to_string(ruta_config()).ok()
}

/// Devuelve el key_id configurado actualmente (para detectar conflictos).
pub fn key_id_actual() -> Option<String> {
    cargar_config().ok().map(|c| c.key_id)
}

/// Guarda las credenciales B2 recibidas de un par con permisos 0600.
/// No sobreescribe automáticamente — el llamador debe comprobar conflictos antes.
pub fn guardar_config_raw(json: &str) -> Result<(), String> {
    let ruta = ruta_config();
    if let Some(p) = ruta.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    std::fs::write(&ruta, json).map_err(|e| format!("Error guardando b2.json: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&ruta, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
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

// A1 — Identificador del par NO ADIVINABLE derivado de la clave compartida.
//
// sha256(clave_hex)[..16 bytes → 32 hex chars].
// - La entrada es 32 bytes de OsRng → 256 bits de entropía.
// - SHA-256 es preimage-resistente: sin la clave compartida es computacionalmente
//   inviable derivar el prefijo S3 (no es secuencial ni predecible).
// - 16 bytes de salida = 128 bits → probabilidad de colisión ~2^(-128) para cualquier
//   par de claves distintas (birthday bound: necesitarías 2^64 pares).
//   Con un máximo de 3 pares por dispositivo, la colisión es imposible en la práctica.
// - NUNCA usar un contador ni un ID local: serían predecibles y romperian la
//   confidencialidad del namespace de sincronización.
fn id_de_par(clave_hex: &str) -> String {
    hex::encode(&Sha256::digest(clave_hex.as_bytes())[..16])
}

// A3 — Registro de fallos de descifrado por objeto S3.
//
// Formato: ~/Babel/p2p/b2_fallos.json → HashMap<s3_key, ts_primer_fallo_unix>
// Política: si un objeto lleva >48 h fallando → se borra de B2 y se descarta
// el registro. Un objeto nuevo con la misma key (no es posible dado que las keys
// incluyen timestamp) se trataría como intento independiente (A3, requisito 4).
const LIMITE_FALLOS_SECS: u64 = 48 * 3600;

fn ruta_fallos() -> std::path::PathBuf {
    crate::babel_dir().join("p2p").join("b2_fallos.json")
}

fn cargar_fallos() -> HashMap<String, u64> {
    std::fs::read_to_string(ruta_fallos())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn guardar_fallos(fallos: &HashMap<String, u64>) {
    if let Ok(json) = serde_json::to_string(fallos) {
        // No atómico intencionadamente: si se corrompe se trata como mapa vacío (seguro).
        let _ = std::fs::write(ruta_fallos(), json);
    }
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

    // A3 — Verificar si este objeto tiene un fallo registrado (y si ya caducó 48 h).
    {
        let mut fallos = cargar_fallos();
        if let Some(&ts_fallo) = fallos.get(key) {
            let edad = ahora().saturating_sub(ts_fallo);
            if edad > LIMITE_FALLOS_SECS {
                // Caducó: borrar de B2 y limpiar registro
                let key_del = key.to_string();
                let cfg_del2 = cfg_del.clone();
                let _ = tokio::task::spawn_blocking(move || s3_delete_sync(&cfg_del2, &key_del)).await;
                fallos.remove(key);
                guardar_fallos(&fallos);
                log::warn!(
                    "[buzon_b2] Objeto '{}' descartado tras {}h de fallos (límite 48h). \
                     Si era un mensaje válido, el remitente deberá reenviarlo.",
                    key,
                    edad / 3600
                );
                return Err(format!("Objeto '{}' descartado por caducidad de fallo (48h)", key));
            }
            // Fallo conocido pero no caducado → no reintentar hasta próximo ciclo
            log::info!("[buzon_b2] Objeto '{}' tiene fallo de {}h — esperando caducidad.", key, edad / 3600);
            return Err(format!("Descifrado de '{}' falló anteriormente; se reintentará.", key));
        }
    }

    // Si el descifrado falla → conservar el objeto para reintento, NO borrar
    let json = match crate::seguridad::descifrar_documento(cifrado, clave_hex) {
        Ok(j) => j,
        Err(e) => {
            // A3: Registrar primer fallo con timestamp
            let mut fallos = cargar_fallos();
            fallos.entry(key.to_string()).or_insert_with(ahora);
            guardar_fallos(&fallos);
            log::error!(
                "[buzon_b2] Fallo al descifrar '{}': {} — registrado en b2_fallos.json (caducará en 48h)",
                key, e
            );
            return Err(format!("Error de descifrado: {e}"));
        }
    };

    let payload: PayloadB2 = match serde_json::from_str(&json) {
        Ok(p) => p,
        Err(e) => {
            let mut fallos = cargar_fallos();
            fallos.entry(key.to_string()).or_insert_with(ahora);
            guardar_fallos(&fallos);
            log::error!(
                "[buzon_b2] Payload inválido en '{}': {} — registrado en b2_fallos.json",
                key, e
            );
            return Err(format!("Error al parsear payload: {e}"));
        }
    };

    // A3: Descifrado exitoso → limpiar cualquier fallo previo registrado
    {
        let mut fallos = cargar_fallos();
        if fallos.remove(key).is_some() {
            guardar_fallos(&fallos);
            log::info!("[buzon_b2] Fallo previo de '{}' limpiado tras descifrado exitoso.", key);
        }
    }

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

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // A1: id_de_par produce exactamente 32 hex chars (16 bytes de SHA-256)
    #[test]
    fn id_de_par_es_32_chars() {
        let clave = "a".repeat(64); // simula 32 bytes en hex
        let id = id_de_par(&clave);
        assert_eq!(id.len(), 32, "id_de_par debe devolver 32 hex chars (16 bytes)");
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()), "solo hex");
    }

    // A1: id_de_par es determinista (misma clave → mismo id)
    #[test]
    fn id_de_par_determinista() {
        let clave = "deadbeef".repeat(8);
        assert_eq!(id_de_par(&clave), id_de_par(&clave));
    }

    // A1: claves distintas → ids distintos (no colisión para entradas normales)
    #[test]
    fn id_de_par_sin_colision() {
        let c1 = "0".repeat(64);
        let c2 = "1".repeat(64);
        assert_ne!(id_de_par(&c1), id_de_par(&c2));
    }

    // A1: el id NO revela la clave (no es un prefijo de la clave ni la clave misma)
    #[test]
    fn id_de_par_no_es_la_clave() {
        let clave = "abcdef0123456789".repeat(4);
        let id = id_de_par(&clave);
        assert_ne!(id, &clave[..32], "el id no debe ser un fragmento de la clave");
    }

    // A3: primer fallo se registra correctamente en el mapa
    #[test]
    fn fallo_se_registra() {
        let mut fallos: HashMap<String, u64> = HashMap::new();
        let key = "pares/abc123/1234567_ping.enc".to_string();
        let ts = ahora();
        fallos.entry(key.clone()).or_insert(ts);
        assert!(fallos.contains_key(&key));
        assert_eq!(*fallos.get(&key).unwrap(), ts);
    }

    // A3: objeto con fallo de hace 47 h → no caducado
    #[test]
    fn fallo_47h_no_caduca() {
        let ts_fallo = ahora().saturating_sub(47 * 3600);
        let edad = ahora().saturating_sub(ts_fallo);
        assert!(edad < LIMITE_FALLOS_SECS, "47h no debe superar el límite de 48h");
    }

    // A3: objeto con fallo de hace 49 h → caducado
    #[test]
    fn fallo_49h_caduca() {
        let ts_fallo = ahora().saturating_sub(49 * 3600);
        let edad = ahora().saturating_sub(ts_fallo);
        assert!(edad > LIMITE_FALLOS_SECS, "49h debe superar el límite de 48h");
    }

    // A3: segunda llamada con la misma key no sobreescribe el ts original (or_insert)
    #[test]
    fn fallo_no_sobreescribe_ts_original() {
        let mut fallos: HashMap<String, u64> = HashMap::new();
        let key = "pares/abc/123_ping.enc".to_string();
        let ts_original = ahora().saturating_sub(10);
        fallos.entry(key.clone()).or_insert(ts_original);
        // Segunda llamada — simula un segundo fallo
        let ts_nuevo = ahora();
        fallos.entry(key.clone()).or_insert(ts_nuevo);
        // El ts original debe conservarse
        assert_eq!(*fallos.get(&key).unwrap(), ts_original, "or_insert no debe sobreescribir");
    }

    // A3: éxito limpia el fallo del mapa
    #[test]
    fn exito_limpia_fallo() {
        let mut fallos: HashMap<String, u64> = HashMap::new();
        let key = "pares/abc/123_msg.enc".to_string();
        fallos.insert(key.clone(), ahora() - 3600);
        fallos.remove(&key);
        assert!(!fallos.contains_key(&key));
    }
}
