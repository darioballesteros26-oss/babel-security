use base64;
use base64::Engine;
use std::sync::atomic::{AtomicBool, Ordering};
use tesseract::Tesseract;

// Flag global para cancelar la traducción en curso.
// El frontend lo activa via `cancelar_traduccion()`; los bucles de traducción
// lo comprueban entre párrafos/trozos y abortan devolviendo Err("cancelada").
pub static CANCELAR_TRADUCCION: AtomicBool = AtomicBool::new(false);

// Modo rápido: si está activo, la app pide beam=1 al servidor (más rápido, algo menos
// de calidad). Por defecto false = calidad (beam por defecto del modelo). Lo activa el
// toggle del sidebar vía el comando `set_modo_rapido`.
pub static MODO_RAPIDO: AtomicBool = AtomicBool::new(true);

pub fn set_modo_rapido(v: bool) {
    MODO_RAPIDO.store(v, Ordering::Relaxed);
}

pub fn cancelar_traduccion() {
    CANCELAR_TRADUCCION.store(true, Ordering::Relaxed);
}

pub fn resetear_cancelacion() {
    CANCELAR_TRADUCCION.store(false, Ordering::Relaxed);
}
pub const ZSTD_MAGIC: &[u8] = b"BZ1:";

pub fn comprimir_b64(data: &[u8]) -> String {
    let es_binario = data.starts_with(b"\x89PNG")
        || data.starts_with(b"\xff\xd8\xff")
        || data.starts_with(b"GIF")
        || data.starts_with(b"%PDF")
        || data.starts_with(b"PK");
    if es_binario {
        return base64::engine::general_purpose::STANDARD.encode(data);
    }
    if let Ok(c) = zstd::encode_all(data, 3) {
        let mut buf = ZSTD_MAGIC.to_vec();
        buf.extend_from_slice(&c);
        return base64::engine::general_purpose::STANDARD.encode(&buf);
    }
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn descomprimir_b64(b64: &str) -> Result<Vec<u8>, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| e.to_string())?;
    if bytes.starts_with(ZSTD_MAGIC) {
        zstd::decode_all(&bytes[ZSTD_MAGIC.len()..]).map_err(|e| e.to_string())
    } else {
        Ok(bytes)
    }
}

use chrono;
use hex;
use imap;
use mailparse;
use mailparse::MailHeaderMap;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
// (std::io::Write se importa localmente en clonar_y_traducir — ya no se usa a nivel de módulo)
use std::sync::OnceLock;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::seguridad;
use lettre::{Message, Transport};
pub fn enviar_archivo_descifrado(
    ruta: &str,
    destinatario: &str,
    asunto: &str,
    cuerpo: &str,
    cc: &str,
    cco: &str,
    smtp_servidor: &str,
    smtp_usuario: &str,
    smtp_password: &str,
    subclave_hex: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    validar_campo_imap(smtp_servidor, "smtp_servidor")?;
    validar_campo_imap(smtp_usuario, "smtp_usuario")?;
    validar_campo_imap(smtp_password, "smtp_password")?;
    // Descifrar el archivo
    let bytes_cifrados = fs::read(ruta)?;
    let contenido = seguridad::descifrar_documento(bytes_cifrados, subclave_hex)
        .map_err(|e| format!("Error descifrando: {}", e))?;

    let (bytes_adjunto, nombre_adjunto, content_type): (Vec<u8>, String, &str) =
        if let Ok(docx_bytes) = descomprimir_b64(&contenido) {
            if docx_bytes.starts_with(b"PK") {
                let nombre_base = std::path::Path::new(ruta)
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let nombre_limpio = nombre_base
                    .split('_')
                    .skip(1)
                    .collect::<Vec<&str>>()
                    .join("_")
                    .trim_end_matches("__orig")
                    .to_string();
                let nombre = (if nombre_limpio.is_empty() {
                    nombre_base
                } else {
                    nombre_limpio
                }) + ".docx";
                (
                    docx_bytes,
                    nombre,
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                )
            } else {
                // Base64 pero no DOCX - texto plano
                let nombre = std::path::Path::new(ruta)
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string()
                    + ".txt";
                (contenido.into_bytes(), nombre, "text/plain")
            }
        } else {
            // Texto plano directo
            let nombre = std::path::Path::new(ruta)
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
                + ".txt";
            (contenido.into_bytes(), nombre, "text/plain")
        };

    let cuerpo_escapado = if cuerpo.is_empty() {
        "Te envío el documento adjunto.".to_string()
    } else {
        cuerpo
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    };
    let cuerpo_html = format!(
        "<html><body style='font-family:Arial,sans-serif;color:#222;'>\
        <p>{}</p>\
        <hr style='border:1px solid #eee;margin:20px 0;'>\
        <p style='font-size:12px;color:#888;'>Enviado con Babel Security - traducción y cifrado 100% local.</p>\
        </body></html>",
        cuerpo_escapado
    );

    let mut builder = Message::builder()
        .from(smtp_usuario.parse()?)
        .to(destinatario.parse()?);

    for addr in cc.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        validar_campo_imap(addr, "cc")?;
        builder = builder.cc(addr.parse::<lettre::message::Mailbox>()?);
    }
    for addr in cco.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        validar_campo_imap(addr, "cco")?;
        builder = builder.bcc(addr.parse::<lettre::message::Mailbox>()?);
    }

    let email = builder
        .subject(if asunto.is_empty() {
            "Documento de Babel Security"
        } else {
            asunto
        })
        .multipart(
            lettre::message::MultiPart::mixed()
                .singlepart(
                    lettre::message::SinglePart::builder()
                        .header(lettre::message::header::ContentType::parse(
                            "text/html; charset=utf-8",
                        )?)
                        .body(cuerpo_html),
                )
                .singlepart(
                    lettre::message::SinglePart::builder()
                        .header(lettre::message::header::ContentType::parse(content_type)?)
                        .header(lettre::message::header::ContentDisposition::attachment(
                            nombre_adjunto.as_str(),
                        ))
                        .body(lettre::message::Body::new(bytes_adjunto)),
                ),
        )?;

    let creds = lettre::transport::smtp::authentication::Credentials::new(
        smtp_usuario.to_string(),
        smtp_password.to_string(),
    );

    let mailer = lettre::SmtpTransport::relay(smtp_servidor)?
        .credentials(creds)
        .timeout(Some(std::time::Duration::from_secs(30)))
        .build();

    mailer.send(&email)?;
    Ok(())
}

// --- ESTRUCTURAS SEGURAS ---
#[derive(Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct CredencialesEmail {
    pub usuario: String,
    pub password: String,
    pub smtp_servidor: String,
    pub imap_dominio: String,
    pub remitentes_autorizados: Vec<String>,
    #[serde(default)]
    pub firma: String,
}

// ============================================================
// GESTIÓN DE SALT MAESTRA
// ============================================================

static SALT_MAESTRA_CACHE: OnceLock<[u8; 32]> = OnceLock::new();

/// Carga la sal maestra desde ~/Babel/master.salt.
/// Si no existe, la genera y la guarda junto con un backup.
/// La sal NO es secreta: solo debe ser única e inmutable.
/// Si se pierde sin backup, todos los datos cifrados son irrecuperables.
/// Thread-safe: OnceLock garantiza una sola inicialización aunque haya concurrencia.
pub fn cargar_o_crear_salt() -> [u8; 32] {
    *SALT_MAESTRA_CACHE.get_or_init(|| {
    let dir = crate::babel_dir();
    let ruta_salt = dir.join("master.salt");
    let ruta_bck = dir.join("master.salt.bck");

    let salt_principal = leer_salt_abs(&ruta_salt);
    let salt_backup = leer_salt_abs(&ruta_bck);

    match (salt_principal, salt_backup) {
        (Some(s), _) => {
            let _ = crate::escribir_privado(&ruta_bck, s);
            salt_perms_600(&ruta_bck);
            return s;
        }
        (None, Some(s)) => {
            log::warn!("[Babel] master.salt no encontrada - recuperando desde backup...");
            if let Err(e) = crate::escribir_privado(&ruta_salt, s) {
                log::error!("[Babel] No se pudo restaurar master.salt: {}", e);
            } else {
                salt_perms_600(&ruta_salt);
                log::info!("[Babel] master.salt restaurada desde backup.");
            }
            return s;
        }
        (None, None) => {
            log::warn!(
                "[Babel] Primera ejecución - generando salt maestra en {:?}",
                ruta_salt
            );
        }
    }

    let nueva_salt = seguridad::generar_salt_maestra();
    if let Err(e) = crate::escribir_privado(&ruta_salt, nueva_salt) {
        log::error!(
            "[Babel] ERROR CRÍTICO: no se pudo guardar master.salt: {}",
            e
        );
    } else {
        salt_perms_600(&ruta_salt);
    }
    let _ = crate::escribir_privado(&ruta_bck, nueva_salt);
    salt_perms_600(&ruta_bck);
    log::info!("[Babel] master.salt generada correctamente.");
    nueva_salt
    })
}

#[cfg(unix)]
fn salt_perms_600(ruta: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(ruta, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn salt_perms_600(_ruta: &std::path::Path) {}

/// Lee y valida un archivo de salt desde una ruta absoluta (PathBuf).
fn leer_salt_abs(ruta: &PathBuf) -> Option<[u8; 32]> {
    let bytes = fs::read(ruta).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

// ============================================================
// 1. INICIO DE SESIÓN (LOGIN)
// ============================================================

/// Guarda timestamp + firma HMAC-SHA256(timestamp) en bloqueo.tmp.
/// Delega en seguridad::activar_bloqueo() para usar la misma clave que leer_bloqueo().
pub fn activar_bloqueo_disco() -> Result<(), String> {
    crate::seguridad::activar_bloqueo()
}

// detector de pdf y docx
pub fn procesar_archivo_inteligente(
    ruta: &str,
    dict: &HashMap<String, String>,
    subclave_hex: &str,
    id_usuario: &str,
    par: &str,
    progreso: &dyn Fn(u8, &str),
) -> Result<(), String> {
    let ruta_limpia = ruta.trim();
    progreso(3, "LEYENDO DOCUMENTO...");

    if ruta_limpia.ends_with(".docx") {
        log::warn!("Detectado documento Word. Iniciando Preservador...");
        clonar_y_traducir(ruta_limpia, dict, subclave_hex, id_usuario, par, progreso)
            .map_err(|e| format!("Error en Word: {}", e))?;

        // DOCX traducido → PDF con LibreOffice (layout fijo, sin reflujo de párrafos).
        // Si LibreOffice no está o falla, el babel DOCX queda intacto como fallback.
        let nombre = std::path::Path::new(ruta_limpia)
            .file_stem().unwrap_or_default().to_string_lossy();
        let archivos_dir = crate::babel_dir().join("archivos");
        let tmp_dir = crate::babel_dir().join("tmp");
        let _ = fs::create_dir_all(&tmp_dir);
        let salida = archivos_dir.join(format!("{}_{}_{}.babel", id_usuario, par, nombre));
        progreso(96, "GENERANDO PDF...");
        let soffice = [
            "/Applications/LibreOffice.app/Contents/MacOS/soffice",
            "/opt/homebrew/bin/soffice",
            "/usr/local/bin/soffice",
            "soffice",
        ].iter().copied()
         .find(|&p| p == "soffice" || std::path::Path::new(p).exists())
         .unwrap_or("soffice");
        if let Ok(cifrado_bytes) = fs::read(&salida) {
            if let Ok(b64_docx) = seguridad::descifrar_documento(cifrado_bytes, subclave_hex) {
                if let Ok(docx_bytes) = descomprimir_b64(&b64_docx) {
                    let docx_tmp = tmp_dir.join(format!("{}_docx_pdf.docx", nombre));
                    if crate::escribir_privado(&docx_tmp, &docx_bytes).is_ok() {
                        let mut child = std::process::Command::new(soffice)
                            .args(["--headless", "--convert-to", "pdf",
                                   "--outdir", &tmp_dir.to_string_lossy(),
                                   &docx_tmp.to_string_lossy()])
                            .spawn().ok();
                        let lo_ok = match child.as_mut() {
                            None => false,
                            Some(c) => {
                                let deadline = std::time::Instant::now()
                                    + std::time::Duration::from_secs(180);
                                loop {
                                    match c.try_wait() {
                                        Ok(Some(s)) => break s.success(),
                                        Ok(None) if std::time::Instant::now() < deadline => {
                                            std::thread::sleep(std::time::Duration::from_millis(300));
                                        }
                                        _ => { let _ = c.kill(); break false; }
                                    }
                                }
                            }
                        };
                        borrar_seguro_local(&docx_tmp.to_string_lossy());
                        if lo_ok {
                            let pdf_out = tmp_dir.join(format!("{}_docx_pdf.pdf", nombre));
                            if let Ok(pdf_bytes) = fs::read(&pdf_out) {
                                borrar_seguro_local(&pdf_out.to_string_lossy());
                                let b64_pdf = comprimir_b64(&pdf_bytes);
                                if let Ok(cifrado_pdf) =
                                    seguridad::blindar_documento(&b64_pdf, subclave_hex)
                                {
                                    let _ = crate::escribir_privado(&salida, cifrado_pdf);
                                }
                            }
                        }
                    }
                }
            }
        }
    } else if ruta_limpia.ends_with(".pdf") {
        log::warn!("Detectado archivo PDF. Iniciando Extractor...");
        procesar_pdf(ruta_limpia, dict, subclave_hex, id_usuario, par, progreso)
            .map_err(|e| format!("Error en PDF: {}", e))?;
    } else if ruta_limpia.ends_with(".txt") {
        let texto = fs::read_to_string(ruta_limpia)
            .map_err(|e| format!("Error leyendo TXT: {}", e))?;
        let nombre = std::path::Path::new(ruta_limpia)
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy();
        let archivos_dir = crate::babel_dir().join("archivos");
        let _ = fs::create_dir_all(&archivos_dir);

        // Guardar original cifrado
        if let Ok(cifrado_orig) = seguridad::blindar_documento(&texto, subclave_hex) {
            let salida_orig =
                archivos_dir.join(format!("{}_{}_{}__orig.babel", id_usuario, par, nombre));
            let _ = crate::escribir_privado(&salida_orig, cifrado_orig);
        }

        // Traducir párrafo a párrafo con contexto del anterior para coherencia
        let parrafos: Vec<&str> = texto.split('\n').collect();
        let total_p = parrafos.iter().filter(|p| !p.trim().is_empty()).count().max(1);
        let mut traducidos_p = 0usize;
        let mut traducido_final = String::new();
        for parrafo in &parrafos {
            if CANCELAR_TRADUCCION.load(Ordering::Relaxed) {
                return Err("Traducción cancelada.".into());
            }
            if parrafo.trim().is_empty() {
                traducido_final.push('\n');
                continue;
            }
            let pct = (10 + traducidos_p * 80 / total_p).min(90) as u8;
            progreso(pct, &format!("TRADUCIENDO... {}%", pct));
            traducidos_p += 1;
            let traducido = traducir_texto_largo(parrafo, par, dict, subclave_hex);
            traducido_final.push_str(&traducido);
            traducido_final.push('\n');
        }
        progreso(93, "CIFRANDO RESULTADO...");
        // Guardar traducción cifrada
        if let Ok(cifrado) = seguridad::blindar_documento(&traducido_final, subclave_hex) {
            let salida = archivos_dir.join(format!("{}_{}_{}.babel", id_usuario, par, nombre));
            let _ = crate::escribir_privado(&salida, cifrado);
        }
    } else {
        return Err(format!("Formato no soportado: {}", ruta_limpia));
    }

    Ok(())
}
// =============================================================
// 5. MOTOR Y UTILIDADES
// =============================================================

pub fn motor_atomico(
    texto: &str,
    dict: &HashMap<String, String>,
    subclave_hex: &str,
) -> (String, usize) {
    let mut palabras_traducidas: Vec<String> = Vec::new();
    // HashSet para deduplicar en O(1) — Vec::contains era O(n) por entrada
    let mut palabras_desconocidas: HashSet<String> = HashSet::new();

    for palabra in texto.split_whitespace() {
        let (raiz, _signo) = separar_signo(palabra);
        let clave = raiz.to_lowercase();
        if let Some(traduccion) = dict.get(&clave) {
            // Traducción palabra a palabra — evita replace() global que sustituye subcadenas
            palabras_traducidas.push(traduccion.clone());
        } else {
            palabras_traducidas.push(palabra.to_string());
            if clave.chars().all(|c| c.is_alphabetic()) && clave.len() > 3 {
                palabras_desconocidas.insert(clave);
            }
        }
    }

    let resultado = palabras_traducidas.join(" ");
    let n = palabras_desconocidas.len();

    for palabra in &palabras_desconocidas {
        registrar_pendiente(palabra, subclave_hex);
    }
    (resultado, n)
}
/// Traduce los tags <a:t> (DrawingML) de un XML — usado en charts de DOCX.
/// Números puros y textos vacíos se dejan intactos.
fn traducir_xml_at(
    xml: &str,
    dict: &HashMap<String, String>,
    subclave_hex: &str,
    par: &str,
) -> String {
    let mut resultado = String::with_capacity(xml.len() * 2);
    let mut resto = xml;
    loop {
        // Buscar <a:t> o <a:t con atributos
        let tag_pos = {
            let mut p = usize::MAX;
            let mut off = 0;
            while let Some(rel) = resto[off..].find("<a:t") {
                let abs = off + rel;
                let after = resto.get(abs + 4..abs + 5).unwrap_or("");
                if after == ">" || after == " " { p = abs; break; }
                off = abs + 4;
            }
            p
        };
        if tag_pos == usize::MAX {
            resultado.push_str(resto);
            break;
        }
        resultado.push_str(&resto[..tag_pos]);
        let desde_tag = &resto[tag_pos..];
        let Some(j) = desde_tag.find('>') else {
            resultado.push_str(desde_tag);
            break;
        };
        let tag = &desde_tag[..j + 1];
        let tras_tag = &desde_tag[j + 1..];
        let Some(k) = tras_tag.find("</a:t>") else {
            resultado.push_str(desde_tag);
            break;
        };
        let contenido = &tras_tag[..k];
        let dec = contenido
            .replace("&amp;", "&").replace("&lt;", "<")
            .replace("&gt;", ">").replace("&apos;", "'").replace("&quot;", "\"");

        let trad = if dec.trim().is_empty() || dec.trim().parse::<f64>().is_ok() {
            dec
        } else {
            match traducir_via_servidor(dec.trim(), par) {
                Ok(t) => t,
                Err(_) => {
                    let (fallback, _) = motor_atomico(dec.trim(), dict, subclave_hex);
                    fallback
                }
            }
        };
        let esc = trad.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
        resultado.push_str(tag);
        resultado.push_str(&esc);
        resultado.push_str("</a:t>");
        resto = &tras_tag[k + 6..];
    }
    resultado
}

/// Versión batch de la traducción XML: extrae todos los párrafos, los traduce en
/// lotes de 50 con MarianMT + Qwen selectivo, y reconstruye el XML en una pasada.
/// 4-5× más rápido que la versión secuencial para documentos con muchos párrafos.
fn traducir_xml_batch(
    xml: &str,
    dict: &HashMap<String, String>,
    subclave_hex: &str,
    par: &str,
    pct_inicio: u8,
    pct_fin: u8,
    progreso: &dyn Fn(u8, &str),
) -> String {
    // Fase 1: localizar todos los <w:p>…</w:p> (y auto-cerrados <w:p …/>)
    struct InfoP {
        start: usize, // byte donde empieza <w:p
        end: usize,   // byte exclusivo donde termina (después de > o </w:p>)
        texto: String,
    }

    let mut bloques: Vec<InfoP> = Vec::new();
    let mut pos = 0usize;

    while pos < xml.len() {
        let Some(rel) = xml[pos..].find("<w:p") else { break };
        let abs = pos + rel;
        let after = xml.get(abs + 4..abs + 5).unwrap_or("");
        if after != ">" && after != " " && after != "/" {
            pos = abs + 4;
            continue;
        }
        let Some(tag_rel) = xml[abs..].find('>') else { pos = abs + 4; continue };
        let tag_end = abs + tag_rel;
        // Auto-cerrado <w:p ... />
        if xml[abs..tag_end + 1].ends_with("/>") {
            bloques.push(InfoP { start: abs, end: tag_end + 1, texto: String::new() });
            pos = tag_end + 1;
            continue;
        }
        // Párrafo normal — buscar </w:p>
        let Some(cierre_rel) = xml[abs..].find("</w:p>") else { pos = abs + 4; continue };
        let fin = abs + cierre_rel + 6;
        let texto = extraer_texto_wt(&xml[abs..fin]);
        bloques.push(InfoP { start: abs, end: fin, texto });
        pos = fin;
    }

    // Fase 2: batch MarianMT para párrafos no vacíos
    let traducibles: Vec<usize> = bloques.iter()
        .enumerate()
        .filter(|(_, b)| !b.texto.trim().is_empty())
        .map(|(i, _)| i)
        .collect();

    let mut traducciones: Vec<String> = bloques.iter()
        .map(|b| b.texto.clone())  // default = original (no-ops para vacíos)
        .collect();

    let total = traducibles.len().max(1);
    let pct_marian = pct_fin.saturating_sub(2);
    let mut hechos = 0usize;

    let batch = batch_por_tier();
    for lote in traducibles.chunks(batch) {
        if CANCELAR_TRADUCCION.load(Ordering::Relaxed) { break; }
        let pct = (pct_inicio as usize
            + hechos * (pct_marian as usize).saturating_sub(pct_inicio as usize) / total)
            .min(pct_marian as usize) as u8;
        progreso(pct, &format!("TRADUCIENDO... {}%", pct));

        let mut batch_idxs: Vec<usize> = Vec::new();
        let mut batch_txts: Vec<&str> = Vec::new();
        let mut largos: Vec<usize> = Vec::new();

        for &bi in lote {
            let t = bloques[bi].texto.as_str();
            // 1400 chars ≈ 400 tokens — margen seguro bajo el límite de 512 del tokenizador
            if t.len() <= 1400 { batch_idxs.push(bi); batch_txts.push(t); }
            else { largos.push(bi); }
        }

        if !batch_txts.is_empty() {
            match traducir_batch_via_servidor(&batch_txts, par) {
                Ok(trs) if trs.len() == batch_txts.len() => {
                    for (&bi, t) in batch_idxs.iter().zip(trs) { traducciones[bi] = t; }
                }
                _ => {
                    for (&bi, &txt) in batch_idxs.iter().zip(batch_txts.iter()) {
                        traducciones[bi] = traducir_texto_largo(txt, par, dict, subclave_hex);
                    }
                }
            }
        }
        for bi in largos {
            traducciones[bi] = traducir_texto_largo(&bloques[bi].texto, par, dict, subclave_hex);
        }

        hechos += lote.len();
        let pct_post = (pct_inicio as usize
            + hechos * (pct_marian as usize).saturating_sub(pct_inicio as usize) / total)
            .min(pct_marian as usize) as u8;
        progreso(pct_post, &format!("TRADUCIENDO... {}%", pct_post));
    }
    // Fase 3: reconstruir XML
    let mut resultado = String::with_capacity(xml.len() + 512);
    let mut cursor = 0usize;
    for (i, bloque) in bloques.iter().enumerate() {
        resultado.push_str(&xml[cursor..bloque.start]);
        let parrafo_xml = &xml[bloque.start..bloque.end];
        if bloque.texto.trim().is_empty() {
            resultado.push_str(parrafo_xml);
        } else {
            resultado.push_str(&reconstruir_parrafo(parrafo_xml, &traducciones[i]));
        }
        cursor = bloque.end;
    }
    resultado.push_str(&xml[cursor..]);
    resultado
}

// Divide el texto en oraciones individuales separando en [.!?] seguido de espacio.
fn partir_en_oraciones(texto: &str) -> Vec<String> {
    let mut oraciones: Vec<String> = Vec::new();
    let mut actual = String::new();
    let chars: Vec<char> = texto.chars().collect();
    let n = chars.len();
    let mut i = 0;
    while i < n {
        actual.push(chars[i]);
        if matches!(chars[i], '.' | '!' | '?') {
            let sig = chars.get(i + 1).copied().unwrap_or('\0');
            if sig == ' ' || sig == '\0' {
                // No partir si la palabra antes del punto es una abreviatura:
                // ≤4 letras puras (Art., Sr., Dr., Núm., Fig., Ref., etc.)
                // o termina en dígito (ej. "5.") — en ambos casos MarianMT
                // necesita el contexto siguiente para traducir bien.
                let previa = actual
                    .trim_end_matches(|c: char| matches!(c, '.' | '!' | '?'))
                    .split_whitespace()
                    .last()
                    .unwrap_or("");
                // Abreviatura: ≤4 letras puras antes del punto (Art., Sr., Dr., Núm., Fig.)
                // Números como "5." SÍ cierran oración → no se protegen.
                let es_abrev = !previa.is_empty()
                    && previa.len() <= 4
                    && previa.chars().all(|c| c.is_alphabetic());
                if !es_abrev {
                    let s = actual.trim().to_string();
                    if !s.is_empty() { oraciones.push(s); }
                    actual = String::new();
                    if sig == ' ' { i += 1; }
                }
            }
        }
        i += 1;
    }
    let resto = actual.trim().to_string();
    if !resto.is_empty() { oraciones.push(resto); }
    oraciones
}

// Traduce texto potencialmente largo partiéndolo en trozos de máx. MAX_CHARS caracteres
// respetando límites de oración para no cortar MarianMT a mitad de frase.
fn traducir_texto_largo(
    texto: &str,
    par: &str,
    dict: &HashMap<String, String>,
    subclave_hex: &str,
) -> String {
    const MAX_CHARS: usize = 1800;
    if texto.len() <= MAX_CHARS {
        return match traducir_via_servidor(texto, par) {
            Ok(t) => t,
            Err(_) => motor_atomico(texto, dict, subclave_hex).0,
        };
    }

    let oraciones = partir_en_oraciones(texto);
    let mut trozos: Vec<String> = Vec::new();
    let mut trozo = String::new();

    for oracion in &oraciones {
        if trozo.len() + oracion.len() + 1 > MAX_CHARS && !trozo.is_empty() {
            trozos.push(trozo.clone());
            trozo = oracion.clone();
        } else {
            if !trozo.is_empty() { trozo.push(' '); }
            trozo.push_str(oracion);
        }
    }
    if !trozo.is_empty() { trozos.push(trozo); }

    let mut resultado_partes: Vec<String> = Vec::with_capacity(trozos.len());
    for trozo in &trozos {
        if CANCELAR_TRADUCCION.load(Ordering::Relaxed) {
            return "[[CANCELADA]]".to_string();
        }
        let t = match traducir_via_servidor(trozo, par) {
            Ok(t) => t,
            Err(_) => motor_atomico(trozo, dict, subclave_hex).0,
        };
        resultado_partes.push(t);
    }
    resultado_partes.join(" ")
}

/// Concatena el contenido de todos los <w:t> del fragmento XML dado.
fn extraer_texto_wt(xml: &str) -> String {
    let mut texto = String::new();
    let mut resto = xml;
    loop {
        // Buscar <w:br o <w:t — lo que llegue primero
        let br_pos = resto.find("<w:br").unwrap_or(usize::MAX);
        let wt_pos = {
            let mut p = usize::MAX;
            let mut off = 0;
            while let Some(rel) = resto[off..].find("<w:t") {
                let abs = off + rel;
                let after = resto.get(abs + 4..abs + 5).unwrap_or("");
                if after == ">" || after == " " { p = abs; break; }
                off = abs + 4;
            }
            p
        };

        if br_pos == usize::MAX && wt_pos == usize::MAX { break; }

        if br_pos < wt_pos {
            // Salto de línea dentro del párrafo — insertar espacio como límite de palabra
            if !texto.is_empty() && !texto.ends_with(' ') {
                texto.push(' ');
            }
            let end = resto[br_pos..].find('>').unwrap_or(0);
            resto = &resto[br_pos + end + 1..];
        } else {
            // <w:t> — extraer contenido
            let pos = wt_pos;
            let Some(j) = resto[pos..].find('>') else { break };
            let ini = pos + j + 1;
            let Some(k) = resto[ini..].find("</w:t>") else { break };
            let t = resto[ini..ini + k]
                .replace("&amp;", "&").replace("&lt;", "<")
                .replace("&gt;", ">").replace("&apos;", "'").replace("&quot;", "\"");
            texto.push_str(&t);
            resto = &resto[ini + k + 6..];
        }
    }
    texto
}

/// Reescribe el XML del párrafo: pone `traduccion` en el primer <w:t>
/// con texto y vacía los demás, conservando el formato/estilo intacto.
// Reparte las palabras de `trad` entre N runs proporcionalmente a la longitud original de cada uno.
fn distribuir_por_runs(trad: &str, orig_lens: &[usize]) -> Vec<String> {
    let n = orig_lens.len();
    if n == 0 { return vec![]; }
    if n == 1 { return vec![trad.to_string()]; }

    let total_orig: usize = orig_lens.iter().sum();
    let words: Vec<&str> = trad.split_whitespace().collect();
    let nw = words.len();

    if total_orig == 0 || nw == 0 {
        let mut v = vec![String::new(); n];
        if !trad.is_empty() { v[0] = trad.to_string(); }
        return v;
    }

    let mut counts: Vec<usize> = orig_lens
        .iter()
        .map(|&l| ((l as f64 / total_orig as f64) * nw as f64).round() as usize)
        .collect();

    // Garantizar ≥1 palabra por run que tenía texto original
    // (evita hipervínculos o palabras en negrita cortas que queden vacíos)
    for i in 0..n {
        if orig_lens[i] > 0 && counts[i] == 0 {
            if let Some(j) = (0..n).filter(|&j| counts[j] > 1).max_by_key(|&j| counts[j]) {
                counts[j] -= 1;
                counts[i] = 1;
            }
        }
    }

    let sum: usize = counts.iter().sum();
    if sum < nw {
        counts[n - 1] += nw - sum;
    } else if sum > nw {
        let mut excess = sum - nw;
        while excess > 0 {
            if let Some(i) = (0..n).filter(|&i| counts[i] > 1).max_by_key(|&i| counts[i]) {
                counts[i] -= 1;
                excess -= 1;
            } else { break; }
        }
    }

    let mut result = Vec::with_capacity(n);
    let mut cur = 0;
    for (i, &c) in counts.iter().enumerate() {
        let end = if i == n - 1 { nw } else { (cur + c).min(nw) };
        let chunk = words[cur..end].join(" ");
        // Espacio separador al final de cada run no-último con contenido:
        // sin él, dos runs adyacentes se mostrarían pegados ("Holamundo").
        let chunk = if i < n - 1 && !chunk.is_empty() {
            format!("{} ", chunk)
        } else {
            chunk
        };
        result.push(chunk);
        cur = end;
    }
    result
}

fn reconstruir_parrafo(parrafo: &str, traduccion: &str) -> String {
    // PASO 1 — recoger longitudes de runs no vacíos
    let mut orig_lens: Vec<usize> = Vec::new();
    {
        let mut scan = parrafo;
        loop {
            let Some(pos) = scan.find("<w:t") else { break };
            let after = scan.get(pos + 4..pos + 5).unwrap_or("");
            if after != ">" && after != " " { scan = &scan[pos + 4..]; continue; }
            let desde = &scan[pos..];
            let Some(j) = desde.find('>') else { break };
            let tras = &desde[j + 1..];
            let Some(k) = tras.find("</w:t>") else { break };
            let dec = tras[..k]
                .replace("&amp;", "&").replace("&lt;", "<")
                .replace("&gt;", ">").replace("&apos;", "'").replace("&quot;", "\"");
            if !dec.trim().is_empty() {
                // Runs sin letras (": ", ".", " ") → peso 0: no compiten por palabras.
                // La puntuación llega embebida en la traducción de los runs alfa adyacentes.
                let len = if dec.chars().any(|c| c.is_alphabetic()) { dec.trim().len() } else { 0 };
                orig_lens.push(len);
            }
            scan = &tras[k + 6..];
        }
    }

    // Si ningún run tiene letras (separadores, líneas de guiones…) → comportamiento original
    let any_alpha = orig_lens.iter().any(|&l| l > 0);
    let trad_parts = distribuir_por_runs(traduccion, &orig_lens);
    let mut run_idx = 0usize;

    // PASO 2 — reconstruir con el fragmento proporcional por run
    let mut resultado = String::with_capacity(parrafo.len() + traduccion.len());
    let mut resto = parrafo;
    loop {
        let Some(pos) = resto.find("<w:t") else {
            resultado.push_str(resto);
            break;
        };
        let after = resto.get(pos + 4..pos + 5).unwrap_or("");
        if after != ">" && after != " " {
            resultado.push_str(&resto[..pos + 4]);
            resto = &resto[pos + 4..];
            continue;
        }
        resultado.push_str(&resto[..pos]);
        let desde_tag = &resto[pos..];
        let Some(j) = desde_tag.find('>') else {
            resultado.push_str(desde_tag);
            break;
        };
        let tag = &desde_tag[..j + 1];
        let tras_tag = &desde_tag[j + 1..];
        let Some(k) = tras_tag.find("</w:t>") else {
            resultado.push_str(desde_tag);
            break;
        };
        let contenido = &tras_tag[..k];
        let dec = contenido
            .replace("&amp;", "&").replace("&lt;", "<")
            .replace("&gt;", ">").replace("&apos;", "'").replace("&quot;", "\"");

        if !dec.trim().is_empty() {
            let chunk = if run_idx < trad_parts.len() { &trad_parts[run_idx] } else { "" };
            run_idx += 1;
            let es_alfa = dec.chars().any(|c| c.is_alphabetic());
            if !any_alpha || es_alfa {
                // Run con letras (o párrafo 100% puntuación): usar chunk de traducción
                let esc = chunk.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
                if chunk.starts_with(' ') || chunk.ends_with(' ') || tag.contains("preserve") {
                    resultado.push_str("<w:t xml:space=\"preserve\">");
                } else {
                    resultado.push_str("<w:t>");
                }
                resultado.push_str(&esc);
                resultado.push_str("</w:t>");
            } else {
                // Run de puntuación en párrafo con contenido alfa: vaciar.
                // La puntuación queda embebida en el chunk del run alfa adyacente.
                resultado.push_str(tag);
                resultado.push_str("</w:t>");
            }
        } else {
            // Runs vacíos/espacios: conservar tal cual (pueden ser separadores tipográficos)
            resultado.push_str(tag);
            resultado.push_str(contenido);
            resultado.push_str("</w:t>");
        }
        resto = &tras_tag[k + 6..];
    }
    resultado
}

// PRESERVACIÓN DE FORMATO (DOCX):
// El DOCX es un ZIP con XML interno. Esta función abre el ZIP en memoria,
// traduce ÚNICAMENTE el texto de los nodos <w:t> en word/document.xml
// (y <a:t> en charts), y reempaqueta el ZIP byte a byte conservando:
//   - Imágenes, fuentes, estilos, temas, relaciones (.rels)
//   - Formato de párrafo: negrita, cursiva, tamaño, color, alineación
//   - Tablas, listas, encabezados, pies de página, secciones
//   - Hipervínculos, comentarios, marcadores
// El texto se redistribuye entre los runs originales del párrafo de forma
// proporcional a su longitud para no romper el estilo run a run.
// Limitación conocida: el texto traducido puede ser más largo/corto que el
// original; si desborda un cuadro de texto con tamaño fijo, Word lo recorta.
pub fn clonar_y_traducir(
    ruta: &str,
    dict: &HashMap<String, String>,
    subclave_hex: &str,
    id_usuario: &str,
    par: &str,
    progreso: &dyn Fn(u8, &str),
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};

    let raw_bytes = fs::read(ruta)?;
    let archivos_dir = crate::babel_dir().join("archivos");
    let _ = fs::create_dir_all(&archivos_dir);
    let nombre = std::path::Path::new(ruta)
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy();

    // Extraer texto plano del XML para guardar el original legible
    let cursor_text = std::io::Cursor::new(&raw_bytes);
    let mut zip_text = zip::ZipArchive::new(cursor_text)?;
    let mut xml_doc = String::new();
    {
        let mut f = zip_text.by_name("word/document.xml")?;
        f.read_to_string(&mut xml_doc)?;
    }

    // Texto plano original para el visor
    let b64_orig = comprimir_b64(&raw_bytes);
    if let Ok(cifrado_orig) = seguridad::blindar_documento(&b64_orig, subclave_hex) {
        let salida_orig = archivos_dir.join(format!("{}_{}_{}__orig.babel", id_usuario, par, nombre));
        let _ = crate::escribir_privado(&salida_orig, cifrado_orig);
    }

    progreso(15, "PROCESANDO WORD...");
    // Traducir document.xml (rango de progreso 20–88%) — batch de 50 párrafos por request
    let xml_traducido = traducir_xml_batch(&xml_doc, dict, subclave_hex, par, 20, 88, progreso);

    // Reempaquetar ZIP preservando TODO — imágenes, estilos, fuentes, relaciones
    let mut buf_out = std::io::Cursor::new(Vec::new());
    {
        let cursor_in = std::io::Cursor::new(&raw_bytes);
        let mut zip_in = zip::ZipArchive::new(cursor_in)?;
        let mut zip_out = zip::ZipWriter::new(&mut buf_out);
        let opts_deflate = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        let opts_store = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);

        for i in 0..zip_in.len() {
            let mut file = zip_in.by_index(i)?;
            let name = file.name().to_string();

            if name == "word/document.xml" {
                // Cuerpo principal — traducido
                zip_out.start_file(&name, opts_deflate)?;
                zip_out.write_all(xml_traducido.as_bytes())?;
            } else if name.starts_with("word/header")
                || name.starts_with("word/footer")
                || name == "word/footnotes.xml"
                || name == "word/endnotes.xml"
                || name == "word/comments.xml"
            {
                // Encabezados, pies, notas al pie/al final y comentarios — traducir
                let mut xml_sub = String::new();
                file.read_to_string(&mut xml_sub)?;
                let xml_sub_trad =
                    traducir_xml_batch(&xml_sub, dict, subclave_hex, par, 88, 95, progreso);
                zip_out.start_file(&name, opts_deflate)?;
                zip_out.write_all(xml_sub_trad.as_bytes())?;
            } else if name.starts_with("word/charts/") && name.ends_with(".xml") {
                // Gráficos — títulos, etiquetas de ejes y series (<a:t>)
                let mut xml_chart = String::new();
                file.read_to_string(&mut xml_chart)?;
                let xml_chart_trad = traducir_xml_at(&xml_chart, dict, subclave_hex, par);
                zip_out.start_file(&name, opts_deflate)?;
                zip_out.write_all(xml_chart_trad.as_bytes())?;
            } else {
                // Imágenes, estilos, fuentes, relaciones — copiar intacto
                let es_xml = name.ends_with(".xml") || name.ends_with(".rels");
                zip_out.start_file(&name, if es_xml { opts_deflate } else { opts_store })?;
                let mut content = Vec::new();
                file.read_to_end(&mut content)?;
                zip_out.write_all(&content)?;
            }
        }
        zip_out.finish()?;
    }
    let docx_bytes = buf_out.into_inner();

    // Cifrar y guardar
    let b64 = comprimir_b64(&docx_bytes);
    let cifrado = seguridad::blindar_documento(&b64, subclave_hex)?;
    let salida = archivos_dir.join(format!("{}_{}_{}.babel", id_usuario, par, nombre));
    crate::escribir_privado(&salida, &cifrado)?;

    registrar_evento(&format!("Word procesado: {}", ruta), subclave_hex);
    Ok(())
}

fn ocr_pagina_pdf(ruta_pdf: &str, pagina: u32) -> String {
    use rand::{rngs::OsRng, RngCore};
    let tmp_dir = crate::babel_dir().join("tmp");
    let _ = std::fs::create_dir_all(&tmp_dir);
    let mut rand_bytes = [0u8; 4];
    OsRng.fill_bytes(&mut rand_bytes);
    let tmp_base = tmp_dir.join(format!("ocr_{}_{}", pagina, hex::encode(rand_bytes)));
    let tmp_img = format!("{}.png", tmp_base.to_string_lossy());

    let pdftoppm = [
        "/opt/homebrew/bin/pdftoppm",
        "/usr/local/bin/pdftoppm",
        "/usr/bin/pdftoppm",
        "pdftoppm",
    ]
    .iter()
    .copied()
    .find(|&p| p == "pdftoppm" || std::path::Path::new(p).exists())
    .unwrap_or("pdftoppm");

    let ok = std::process::Command::new(pdftoppm)
        .args([
            "-r",
            "300",
            "-f",
            &pagina.to_string(),
            "-l",
            &pagina.to_string(),
            "-png",
            "-singlefile",
            ruta_pdf,
            &tmp_base.to_string_lossy(),
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !ok {
        if std::path::Path::new(&tmp_img).exists() {
            let tam = std::fs::metadata(&tmp_img).map(|m| m.len() as usize).unwrap_or(0);
            if tam > 0 { let _ = crate::escribir_privado(&tmp_img, vec![0u8; tam]); }
            let _ = fs::remove_file(&tmp_img);
        }
        return String::new();
    }

    let resultado = match Tesseract::new(None, Some("spa+eng+fra+deu+ara+rus+chi_sim")) {
        Ok(t) => match t.set_image(&tmp_img) {
            Ok(mut t2) => t2.get_text().unwrap_or_default(),
            Err(_) => String::new(),
        },
        Err(_) => String::new(),
    };

    let tam = std::fs::metadata(&tmp_img)
        .map(|m| m.len() as usize)
        .unwrap_or(0);
    let _ = crate::escribir_privado(&tmp_img, vec![0u8; tam]);
    let _ = fs::remove_file(&tmp_img);
    resultado
}

// M6: delega en crate::borrar_seguro, que aplica O_NOFOLLOW + symlink_metadata para evitar
// TOCTOU por symlink (los temporales viven en ~/Babel/tmp, potencialmente compartido) además
// de las 3 pasadas + fsync. Antes esta versión local abría con write() sin O_NOFOLLOW.
fn borrar_seguro_local(ruta: &str) {
    crate::borrar_seguro(ruta);
}

/// Localiza un script de servidor relativo al intérprete Python detectado.
/// En USB: python en Resources/python/bin/ → Resources/servidor/<script>
/// En dev: python en babel_env/bin/ → Babel/babel-interfaz/servidor_babel/<script>
fn encontrar_script_servidor(python3: &str, nombre_script: &str) -> Option<String> {
    let py = std::path::Path::new(python3);
    let base = py.parent()?.parent()?.parent()?;
    let candidatos = [
        base.join(format!("servidor/{}", nombre_script)),
        base.join(format!("babel-interfaz/servidor_babel/{}", nombre_script)),
    ];
    for c in &candidatos {
        if c.exists() {
            return Some(c.to_string_lossy().to_string());
        }
    }
    None
}


/// Une líneas partidas a mitad de frase en texto extraído de PDF.
/// Heurísticas:
///   - Si la línea termina en guión silábico → quita el guión, une sin espacio.
///   - Si la línea no termina en puntuación de cierre (.!?:;»") y tiene ≥10 chars
///     Y la siguiente empieza en minúscula → une con espacio (continuación de oración).
///   - Las líneas en blanco siempre son separadores de párrafo (no se cruzan).
///   - Encabezados (todo-mayúsculas cortos o markdown #) no se unen.
/// Extrae el prefijo Markdown de una línea (heading, lista) para protegerlo durante
/// la traducción. Devuelve (prefijo, texto_limpio); ambos son subslices de `s`.
fn separar_prefijo_md(s: &str) -> (&str, &str) {
    // Headings: ### ## #
    for n in [3usize, 2, 1] {
        if s.len() > n + 1
            && s.as_bytes()[..n].iter().all(|&b| b == b'#')
            && s.as_bytes()[n] == b' '
        {
            return (&s[..n + 1], &s[n + 1..]);
        }
    }
    // Unordered list
    if s.starts_with("- ") { return (&s[..2], &s[2..]); }
    if s.starts_with("* ") { return (&s[..2], &s[2..]); }
    // Ordered list: 1. 12. etc.
    let b = s.as_bytes();
    let mut n = 0;
    while n < b.len() && b[n].is_ascii_digit() { n += 1; }
    if n > 0 && b.get(n) == Some(&b'.') && b.get(n + 1) == Some(&b' ') {
        return (&s[..n + 2], &s[n + 2..]);
    }
    ("", s)
}

/// Convierte Markdown (salida de pymupdf4llm) a HTML para el visor integrado.
/// Maneja: encabezados, párrafos, listas, tablas, negrita/cursiva, separadores.
pub fn markdown_a_html(md: &str) -> String {
    fn escape_html(s: &str) -> String {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
    }

    fn inline_fmt(s: &str) -> String {
        let src = escape_html(s);
        let mut out = String::with_capacity(src.len() + 16);
        let mut rem = src.as_str();
        while !rem.is_empty() {
            // **bold**
            if rem.starts_with("**") {
                if let Some(end) = rem[2..].find("**") {
                    out.push_str("<strong>");
                    out.push_str(&rem[2..2 + end]);
                    out.push_str("</strong>");
                    rem = &rem[2 + end + 2..];
                    continue;
                }
            }
            // *italic* — solo si el contenido no cruza otra estrella doble
            if rem.starts_with('*') && !rem.starts_with("**") {
                if let Some(end) = rem[1..].find('*') {
                    if end > 0 && end < 50 && !rem[1..1 + end].contains("**") {
                        out.push_str("<em>");
                        out.push_str(&rem[1..1 + end]);
                        out.push_str("</em>");
                        rem = &rem[1 + end + 1..];
                        continue;
                    }
                }
            }
            let ch = rem.chars().next().unwrap();
            out.push(ch);
            rem = &rem[ch.len_utf8()..];
        }
        out
    }

    let mut html = String::with_capacity(md.len() * 2);
    let mut in_ul = false;
    let mut in_ol = false;
    let mut in_table = false;
    let mut in_table_header = true;
    let mut in_code = false;
    let mut para_buf = String::new();

    macro_rules! flush_para {
        () => {
            if !para_buf.is_empty() {
                html.push_str("<p>");
                html.push_str(&para_buf);
                html.push_str("</p>");
                para_buf.clear();
            }
        };
    }
    macro_rules! close_lists {
        () => {
            if in_ul { html.push_str("</ul>"); in_ul = false; }
            if in_ol { html.push_str("</ol>"); in_ol = false; }
        };
    }
    macro_rules! close_table {
        () => {
            if in_table { html.push_str("</table>"); in_table = false; in_table_header = true; }
        };
    }

    for line in md.lines() {
        let trimmed = line.trim();

        // Code fence
        if trimmed.starts_with("```") {
            if in_code {
                html.push_str("</code></pre>");
                in_code = false;
            } else {
                flush_para!(); close_lists!(); close_table!();
                html.push_str("<pre><code>");
                in_code = true;
            }
            continue;
        }
        if in_code {
            html.push_str(&escape_html(line));
            html.push('\n');
            continue;
        }

        // Empty line
        if trimmed.is_empty() {
            flush_para!(); close_lists!(); close_table!();
            continue;
        }

        // Horizontal rule / page separator: ≥3 chars todos guiones/iguales/guiones_bajos
        if trimmed.len() >= 3
            && trimmed.chars().all(|c| c == '-' || c == '=' || c == '_')
            && !trimmed.chars().any(|c| c.is_alphabetic())
        {
            flush_para!(); close_lists!(); close_table!();
            html.push_str("<hr>");
            continue;
        }

        // Headings
        if trimmed.starts_with("### ") {
            flush_para!(); close_lists!(); close_table!();
            html.push_str(&format!("<h3>{}</h3>", inline_fmt(&trimmed[4..])));
            continue;
        }
        if trimmed.starts_with("## ") {
            flush_para!(); close_lists!(); close_table!();
            html.push_str(&format!("<h2>{}</h2>", inline_fmt(&trimmed[3..])));
            continue;
        }
        if trimmed.starts_with("# ") {
            flush_para!(); close_lists!(); close_table!();
            html.push_str(&format!("<h1>{}</h1>", inline_fmt(&trimmed[2..])));
            continue;
        }

        // Table rows: | col | col |
        if trimmed.starts_with('|') && trimmed.ends_with('|') && trimmed.len() > 2 {
            flush_para!(); close_lists!();
            let inner = &trimmed[1..trimmed.len() - 1];
            // Separator row: | --- | --- |
            let is_sep = inner.split('|').all(|s| {
                let t = s.trim();
                !t.is_empty() && t.chars().all(|c| c == '-' || c == ':' || c == ' ')
            });
            if is_sep { in_table_header = false; continue; }
            if !in_table { html.push_str("<table>"); in_table = true; in_table_header = true; }
            let tag = if in_table_header { "th" } else { "td" };
            html.push_str("<tr>");
            for cell in inner.split('|') {
                html.push_str(&format!("<{0}>{1}</{0}>", tag, inline_fmt(cell.trim())));
            }
            html.push_str("</tr>");
            continue;
        }
        close_table!();

        // Unordered list
        if trimmed.starts_with("- ") || trimmed.starts_with("* ") {
            flush_para!();
            if in_ol { html.push_str("</ol>"); in_ol = false; }
            if !in_ul { html.push_str("<ul>"); in_ul = true; }
            html.push_str(&format!("<li>{}</li>", inline_fmt(&trimmed[2..])));
            continue;
        }

        // Ordered list
        {
            let b = trimmed.as_bytes();
            let mut n = 0;
            while n < b.len() && b[n].is_ascii_digit() { n += 1; }
            if n > 0 && b.get(n) == Some(&b'.') && b.get(n + 1) == Some(&b' ') {
                flush_para!();
                if in_ul { html.push_str("</ul>"); in_ul = false; }
                if !in_ol { html.push_str("<ol>"); in_ol = true; }
                html.push_str(&format!("<li>{}</li>", inline_fmt(&trimmed[n + 2..])));
                continue;
            }
        }

        // Regular paragraph
        close_lists!();
        if !para_buf.is_empty() { para_buf.push(' '); }
        para_buf.push_str(&inline_fmt(trimmed));
    }

    flush_para!();
    if in_ul { html.push_str("</ul>"); }
    if in_ol { html.push_str("</ol>"); }
    if in_table { html.push_str("</table>"); }
    if in_code { html.push_str("</code></pre>"); }
    html
}

fn unir_lineas_partidas(texto: &str) -> String {
    const MIN_LEN: usize = 10;

    let lineas: Vec<&str> = texto.lines().collect();
    if lineas.len() <= 1 {
        return texto.to_string();
    }

    let es_terminal = |s: &str| {
        s.chars().last()
            .map(|c| matches!(c, '.' | '!' | '?' | ':' | ';' | '»' | '"' | ')' | ']'))
            .unwrap_or(true)
    };

    // Encabezados: todo-mayúsculas corto (<60 chars con al menos una letra) o línea markdown
    let es_encabezado = |s: &str| -> bool {
        if s.starts_with('#') { return true; }
        let tiene_letras = s.chars().any(|c| c.is_alphabetic());
        let todo_mayus = s.chars().filter(|c| c.is_alphabetic()).all(|c| c.is_uppercase());
        tiene_letras && todo_mayus && s.len() < 60
    };

    let mut resultado: Vec<String> = Vec::with_capacity(lineas.len());
    let mut acum = String::new();

    for i in 0..lineas.len() {
        let trim = lineas[i].trim();

        if trim.is_empty() {
            if !acum.is_empty() {
                resultado.push(acum.trim_end().to_string());
                acum.clear();
            }
            resultado.push(String::new());
            continue;
        }

        acum.push_str(trim);

        let sig = lineas.get(i + 1).map(|s| s.trim()).unwrap_or("");
        let trim_acum = acum.trim_end();

        // Guión silábico al final: quitar guión, continuar sin espacio.
        // Excluir líneas que son SOLO guiones (separadores de página: ---, -----, etc.)
        if trim_acum.ends_with('-')
            && trim_acum.len() > 1
            && !sig.is_empty()
            && !trim_acum.chars().all(|c| c == '-')
        {
            let new_len = trim_acum.len() - 1;
            acum.truncate(new_len);
            continue;
        }

        // Continuación de oración: sin terminal, no es encabezado, ≥10 chars, siguiente en minúscula
        if !es_terminal(trim_acum)
            && !es_encabezado(trim_acum)
            && trim_acum.len() >= MIN_LEN
            && !sig.is_empty()
            && sig.chars().next().map(|c| c.is_lowercase()).unwrap_or(false)
        {
            acum = format!("{} ", trim_acum);
            continue;
        }

        resultado.push(trim_acum.to_string());
        acum.clear();
    }

    if !acum.trim().is_empty() {
        resultado.push(acum.trim_end().to_string());
    }

    resultado.join("\n")
}

pub fn procesar_pdf(
    ruta: &str,
    dict: &HashMap<String, String>,
    subclave_hex: &str,
    id_usuario: &str,
    par: &str,
    progreso: &dyn Fn(u8, &str),
) -> Result<(), Box<dyn std::error::Error>> {
    let nombre = std::path::Path::new(ruta)
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let archivos_dir = crate::babel_dir().join("archivos");
    let _ = fs::create_dir_all(&archivos_dir);
    let tmp_dir = crate::babel_dir().join("tmp");
    let _ = fs::create_dir_all(&tmp_dir);

    progreso(5, "CONVIRTIENDO PDF...");
    // PASO 1: PDF → DOCX con pdf2docx (timeout 120 s)
    let ruta_docx_tmp = tmp_dir.join(format!("{}_tmp.docx", nombre));
    // Buscar el python que tenga pdf2docx: babel_env primero, luego rutas estándar
    let python3 = [
        "/Users/georgina/Desktop/Babel/babel_env/bin/python3",
        "/opt/homebrew/bin/python3",
        "/usr/local/bin/python3",
        "/usr/bin/python3",
        "python3",
    ]
    .iter()
    .copied()
    .find(|&p| {
        if p == "python3" { return true; }
        std::process::Command::new(p)
            .args(["-c", "import pdf2docx"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
    .unwrap_or("python3");

    let ok = {
        let mut child = std::process::Command::new(python3)
            .args([
                "-c",
                "import fitz; fitz.Rect.get_area = lambda self: self.width * self.height; import sys; from pdf2docx import Converter; cv=Converter(sys.argv[1]); cv.convert(sys.argv[2]); cv.close()",
                ruta,
                &ruta_docx_tmp.to_string_lossy(),
            ])
            .spawn()
            .ok();
        match child.as_mut() {
            None => false,
            Some(c) => {
                let deadline = std::time::Instant::now()
                    + std::time::Duration::from_secs(120);
                let inicio = std::time::Instant::now();
                loop {
                    match c.try_wait() {
                        Ok(Some(s)) => break s.success(),
                        Ok(None) if std::time::Instant::now() < deadline => {
                            std::thread::sleep(std::time::Duration::from_millis(500));
                            // Avanzar de 5% a 14% durante la conversión (cada ~3s = 1%)
                            let elapsed = inicio.elapsed().as_secs();
                            let pct = (5 + (elapsed / 3).min(9)) as u8;
                            progreso(pct, "CONVIRTIENDO PDF...");
                        }
                        _ => {
                            let _ = c.kill();
                            break false;
                        }
                    }
                }
            }
        }
    };

    // PASO 1b: si pdf2docx falló, intentar con LibreOffice antes de caer a texto plano.
    // LibreOffice preserva tablas, columnas e índices mejor que cualquier extractor de texto.
    let ok = if !ok {
        progreso(6, "CONVIRTIENDO PDF (LibreOffice)...");
        let soffice = [
            "/Applications/LibreOffice.app/Contents/MacOS/soffice",
            "/opt/homebrew/bin/soffice",
            "/usr/local/bin/soffice",
            "soffice",
        ]
        .iter()
        .copied()
        .find(|&p| p == "soffice" || std::path::Path::new(p).exists())
        .unwrap_or("soffice");

        let lo_ok = {
            let mut child = std::process::Command::new(soffice)
                .args([
                    "--headless",
                    "--convert-to", "docx",
                    "--outdir", &tmp_dir.to_string_lossy(),
                    ruta,
                ])
                .spawn()
                .ok();
            match child.as_mut() {
                None => false,
                Some(c) => {
                    let deadline = std::time::Instant::now()
                        + std::time::Duration::from_secs(180);
                    let inicio = std::time::Instant::now();
                    loop {
                        match c.try_wait() {
                            Ok(Some(s)) => break s.success(),
                            Ok(None) if std::time::Instant::now() < deadline => {
                                std::thread::sleep(std::time::Duration::from_millis(500));
                                let elapsed = inicio.elapsed().as_secs();
                                let pct = (6 + (elapsed / 4).min(8)) as u8;
                                progreso(pct, "CONVIRTIENDO PDF (LibreOffice)...");
                            }
                            _ => { let _ = c.kill(); break false; }
                        }
                    }
                }
            }
        };

        if lo_ok {
            // LibreOffice genera el DOCX con el mismo nombre del PDF de entrada en tmp_dir
            let pdf_stem = std::path::Path::new(ruta)
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy();
            let lo_docx = tmp_dir.join(format!("{}.docx", pdf_stem));
            if lo_docx.exists() {
                let _ = fs::rename(&lo_docx, &ruta_docx_tmp);
                true
            } else {
                false
            }
        } else {
            false
        }
    } else {
        true
    };

    if !ok {
        // Ejecuta un script Python externo con la ruta del PDF y devuelve su stdout.
        let ejecutar_script = |script: &str| -> String {
            std::process::Command::new(python3)
                .args([script, ruta])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .unwrap_or_default()
        };

        // Seleccionar el mejor texto disponible en orden de calidad decreciente.
        let texto_extraido: String = 'extraccion: {
            // PASO 2: pymupdf4llm — Markdown estructurado (encabezados, tablas, listas).
            // Rápido, sin GPU, alta calidad para PDFs con texto nativo o digital.
            if let Some(s) = encontrar_script_servidor(python3, "pymupdf4llm_extract.py") {
                progreso(8, "ANALIZANDO PDF (PyMuPDF4LLM)...");
                let out = ejecutar_script(&s);
                if out.split_whitespace().count() >= 50 {
                    break 'extraccion out;
                }
            }

            // PASO 3: PaddleOCR-VL-1.5 — vía servidor (modelo warm en memoria).
            // Primera llamada: carga el modelo (~35s) + inferencia.
            // Llamadas siguientes: solo inferencia (~7s/pág), sin cold start.
            // Modelo Apache 2.0: PaddlePaddle/PaddleOCR-VL-1.5-GGUF vía llama-cpp-python.
            progreso(9, "OCR AVANZADO (PaddleOCR-VL)...");
            if let Some(out) = ocr_via_servidor(ruta) {
                if out.split_whitespace().count() >= 30 {
                    break 'extraccion out;
                }
            }

            // PASO 4: pdftotext — fallback ligero para PDFs con texto nativo sin estructura
            let pdftotext_bin = [
                "/opt/homebrew/bin/pdftotext",
                "/usr/local/bin/pdftotext",
                "/usr/bin/pdftotext",
                "pdftotext",
            ]
            .iter()
            .copied()
            .find(|&p| p == "pdftotext" || std::path::Path::new(p).exists())
            .unwrap_or("pdftotext");

            let texto_pdftotext = std::process::Command::new(pdftotext_bin)
                .args([ruta, "-"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();

            if texto_pdftotext.split_whitespace().count() > 20 {
                break 'extraccion texto_pdftotext;
            }

            // PASO 5: Tesseract OCR — último recurso para PDFs completamente escaneados
            progreso(13, "OCR PÁGINA A PÁGINA...");
            let mut ocr_total = String::new();
            for pag in 1u32..=50 {
                let pag_text = ocr_pagina_pdf(ruta, pag);
                if pag_text.trim().is_empty() {
                    break;
                }
                ocr_total.push_str(&pag_text);
                ocr_total.push('\n');
            }
            ocr_total
        };

        // Bucle de traducción por lotes (batch HTTP) para máxima velocidad
        progreso(15, "TRADUCIENDO...");
        let texto_unido = unir_lineas_partidas(&texto_extraido);
        let parrafos: Vec<String> = texto_unido.lines().map(String::from).collect();

        // Primera pasada: clasificar cada línea en vacía, artefacto o "pendiente de traducir"
        let mut salida: Vec<String> = Vec::with_capacity(parrafos.len());
        let mut pendientes: Vec<(usize, String)> = Vec::new(); // (índice en salida, texto)
        // Prefijos Markdown (# ## - * 1.) separados antes de traducir para protegerlos.
        let mut md_prefijos: HashMap<usize, String> = HashMap::new();

        for parrafo in &parrafos {
            let trim = parrafo.trim();
            if trim.is_empty() {
                salida.push("\n".to_string());
                continue;
            }
            // Líneas solo estructurales (guiones, pipes, iguales) sin texto alfabético
            let solo_estructura = !trim.chars().any(|c| c.is_alphabetic())
                && trim.chars().any(|c| c == '-' || c == '=' || c == '|' || c == '_');
            // Cabeceras/pies correntes del PDF: "Página Uno", "Page 1", "1 de 50", etc.
            // Son artefactos de extracción — cortan el flujo del texto y no deben traducirse.
            let trim_low = trim.to_lowercase();
            let es_cabecera_pagina = trim.len() < 50 && (
                (trim_low.starts_with("página ") || trim_low.starts_with("page ") || trim_low.starts_with("pág. ") || trim_low.starts_with("pag. "))
                    && trim.split_whitespace().count() <= 3
            );
            let es_artefacto = trim.len() < 2
                || trim.parse::<u64>().is_ok()
                || (trim.starts_with("http") && !trim.contains(' '))
                || (trim.starts_with("www.") && !trim.contains(' '))
                || solo_estructura
                || es_cabecera_pagina;
            if es_artefacto {
                salida.push(format!("{}\n", parrafo));
                continue;
            }
            // Separar prefijo Markdown antes de traducir
            let (pfx, texto) = separar_prefijo_md(trim);
            let idx = salida.len();
            if !pfx.is_empty() {
                md_prefijos.insert(idx, pfx.to_string());
                pendientes.push((idx, texto.to_string()));
            } else {
                pendientes.push((idx, parrafo.clone()));
            }
            salida.push(String::new()); // marcador de posición
        }

        // Segunda pasada: traducir en lotes (tamaño según tier de RAM) con un HTTP request por lote
        let batch_pdf = batch_por_tier();
        let total_trad = pendientes.len().max(1);
        let mut hechos = 0usize;

        for lote in pendientes.chunks(batch_pdf) {
            if CANCELAR_TRADUCCION.load(Ordering::Relaxed) {
                return Err("Traducción cancelada.".into());
            }
            // Progreso al inicio del lote (hechos) y al final (hechos + lote.len())
            // para que la barra avance al empezar cada lote, no al terminar.
            let pct_ini = (20 + hechos * 50 / total_trad).min(69) as u8;
            let pct_fin = (20 + (hechos + lote.len()) * 50 / total_trad).min(70) as u8;
            progreso(pct_ini, &format!("TRADUCIENDO... {}%", pct_ini));

            // Fase 1: batch MarianMT para todo el lote (sin Qwen)
            let mut batch_ids: Vec<usize> = Vec::new();
            let mut batch_txts: Vec<&str> = Vec::new();
            let mut largos: Vec<(usize, &str)> = Vec::new();

            for (out_idx, texto) in lote {
                if texto.len() <= 1400 {
                    batch_ids.push(*out_idx);
                    batch_txts.push(texto.as_str());
                } else {
                    largos.push((*out_idx, texto.as_str()));
                }
            }

            if !batch_txts.is_empty() {
                match traducir_batch_via_servidor(&batch_txts, par) {
                    Ok(traducciones) if traducciones.len() == batch_txts.len() => {
                        for (out_idx, t) in batch_ids.iter().zip(traducciones) {
                            salida[*out_idx] = format!("{}\n", t);
                        }
                    }
                    _ => {
                        for (out_idx, texto) in batch_ids.iter().zip(&batch_txts) {
                            let t = traducir_texto_largo(texto, par, dict, subclave_hex);
                            salida[*out_idx] = format!("{}\n", t);
                        }
                    }
                }
            }
            for (out_idx, texto) in largos {
                let t = traducir_texto_largo(texto, par, dict, subclave_hex);
                salida[out_idx] = format!("{}\n", t);
            }

            hechos += lote.len();
            progreso(pct_fin, &format!("TRADUCIENDO... {}%", pct_fin));
        }

        // Restaurar prefijos Markdown separados antes de traducir
        for (out_idx, _) in &pendientes {
            if let Some(pfx) = md_prefijos.get(out_idx) {
                let t = salida[*out_idx].trim_end_matches('\n').to_string();
                if !t.is_empty() {
                    salida[*out_idx] = format!("{}{}\n", pfx, t);
                }
            }
        }

        let traducido: String = salida.concat();
        progreso(91, "GENERANDO PDF...");

        let soffice_bin = [
            "/Applications/LibreOffice.app/Contents/MacOS/soffice",
            "/opt/homebrew/bin/soffice",
            "/usr/local/bin/soffice",
            "soffice",
        ]
        .iter().copied()
        .find(|&p| p == "soffice" || std::path::Path::new(p).exists())
        .unwrap_or("soffice");

        // Intento 1: LibreOffice HTML→PDF (layout y tipografía profesionales)
        let guardado_como_pdf = 'conv: {
            let html_content = format!(
                "<!DOCTYPE html><html><head><meta charset='utf-8'>\
                 <style>@page{{margin:2.5cm 2cm}}body{{font-family:Georgia,serif;\
                 font-size:11pt;line-height:1.6;color:#111}}h1{{font-size:18pt;\
                 margin-top:1em}}h2{{font-size:14pt}}h3{{font-size:12pt}}\
                 p{{margin:.4em 0 .8em}}table{{border-collapse:collapse;width:100%;\
                 margin:1em 0}}td,th{{border:1px solid #aaa;padding:4px 8px}}\
                 th{{background:#eee}}pre{{background:#f4f4f4;padding:8px;\
                 font-size:9pt}}</style></head><body>{}</body></html>",
                markdown_a_html(&traducido)
            );
            let html_tmp = tmp_dir.join(format!("{}_fallback.html", nombre));
            let pdf_lo  = tmp_dir.join(format!("{}_fallback.pdf", nombre));
            if crate::escribir_privado(&html_tmp, html_content.as_bytes()).is_ok() {
                let mut child = std::process::Command::new(soffice_bin)
                    .args(["--headless", "--convert-to", "pdf",
                           "--outdir", &tmp_dir.to_string_lossy(),
                           &html_tmp.to_string_lossy()])
                    .spawn().ok();
                let lo_ok = match child.as_mut() {
                    None => false,
                    Some(c) => {
                        let deadline = std::time::Instant::now()
                            + std::time::Duration::from_secs(120);
                        loop {
                            match c.try_wait() {
                                Ok(Some(s)) => break s.success(),
                                Ok(None) if std::time::Instant::now() < deadline => {
                                    std::thread::sleep(std::time::Duration::from_millis(300));
                                }
                                _ => { let _ = c.kill(); break false; }
                            }
                        }
                    }
                };
                borrar_seguro_local(&html_tmp.to_string_lossy());
                if lo_ok {
                    if let Ok(pdf_bytes) = fs::read(&pdf_lo) {
                        borrar_seguro_local(&pdf_lo.to_string_lossy());
                        let b64 = comprimir_b64(&pdf_bytes);
                        if let Ok(cifrado) = seguridad::blindar_documento(&b64, subclave_hex) {
                            let _ = crate::escribir_privado(
                                archivos_dir.join(format!("{}_{}_{}.babel", id_usuario, par, nombre)),
                                cifrado,
                            );
                            break 'conv true;
                        }
                    }
                }
            }

            // Intento 2: reportlab (md_to_pdf.py) — fallback si LibreOffice no está
            let Some(script) = encontrar_script_servidor(python3, "md_to_pdf.py") else {
                break 'conv false;
            };
            let md_tmp = tmp_dir.join(format!("{}_fallback.md", nombre));
            if crate::escribir_privado(&md_tmp, traducido.as_bytes()).is_err() { break 'conv false; }
            let pdf_out = tmp_dir.join(format!("{}_fallback.pdf", nombre));
            let ok = std::process::Command::new(python3)
                .args([script.as_str(), &md_tmp.to_string_lossy(), &pdf_out.to_string_lossy()])
                .status().map(|s| s.success()).unwrap_or(false);
            borrar_seguro_local(&md_tmp.to_string_lossy());
            if !ok { break 'conv false; }
            let pdf_bytes = match fs::read(&pdf_out) {
                Ok(b) => { borrar_seguro_local(&pdf_out.to_string_lossy()); b }
                Err(_) => break 'conv false,
            };
            let b64 = comprimir_b64(&pdf_bytes);
            match seguridad::blindar_documento(&b64, subclave_hex) {
                Ok(cifrado) => {
                    let _ = crate::escribir_privado(
                        archivos_dir.join(format!("{}_{}_{}.babel", id_usuario, par, nombre)),
                        cifrado,
                    );
                    true
                }
                Err(_) => false,
            }
        };

        if !guardado_como_pdf {
            // Fallback: HTML formateado en el visor integrado
            progreso(93, "CIFRANDO RESULTADO...");
            let contenido = format!("html:{}", markdown_a_html(&traducido));
            let cifrado = seguridad::blindar_documento(&contenido, subclave_hex)?;
            crate::escribir_privado(
                archivos_dir.join(format!("{}_{}_{}.babel", id_usuario, par, nombre)),
                cifrado,
            )?;
        }
        return Ok(());
    }

    progreso(10, "PROCESANDO PDF...");
    // PASO 2 & 3 — cleanup de ruta_docx_tmp garantizado aunque falle la traducción
    // (el original __orig lo guarda clonar_y_traducir internamente)
    let resultado = (|| -> Result<(), Box<dyn std::error::Error>> {
        // PASO 2: traducir DOCX con el pipeline ZIP (guarda también __orig)
        clonar_y_traducir(
            &ruta_docx_tmp.to_string_lossy(),
            dict,
            subclave_hex,
            id_usuario,
            par,
            progreso,
        )?;
        // Renombrar _tmp → nombre final (clonar_y_traducir usa el stem del DOCX temporal)
        let salida_tmp = archivos_dir.join(format!("{}_{}_{}_tmp.babel", id_usuario, par, nombre));
        let salida_final = archivos_dir.join(format!("{}_{}_{}.babel", id_usuario, par, nombre));
        if salida_tmp.exists() {
            let _ = fs::rename(&salida_tmp, &salida_final);
        }
        let orig_tmp =
            archivos_dir.join(format!("{}_{}_{}_tmp__orig.babel", id_usuario, par, nombre));
        let orig_final =
            archivos_dir.join(format!("{}_{}_{}__orig.babel", id_usuario, par, nombre));
        if orig_tmp.exists() {
            let _ = fs::rename(&orig_tmp, &orig_final);
        }

        // PASO 3: DOCX traducido → PDF con LibreOffice (PDF entra, PDF sale con layout real)
        // Descifrar el DOCX babel, convertir a PDF, reemplazar el babel con el PDF.
        // Si LibreOffice falla, el DOCX babel queda intacto como fallback.
        progreso(95, "GENERANDO PDF...");
        let soffice_pdf = [
            "/Applications/LibreOffice.app/Contents/MacOS/soffice",
            "/opt/homebrew/bin/soffice",
            "/usr/local/bin/soffice",
            "soffice",
        ]
        .iter().copied()
        .find(|&p| p == "soffice" || std::path::Path::new(p).exists())
        .unwrap_or("soffice");

        if let Ok(cifrado_bytes) = fs::read(&salida_final) {
            if let Ok(b64_docx) = seguridad::descifrar_documento(cifrado_bytes, subclave_hex) {
                if let Ok(docx_bytes) = descomprimir_b64(&b64_docx) {
                    let docx_conv = tmp_dir.join(format!("{}_conv.docx", nombre));
                    if crate::escribir_privado(&docx_conv, &docx_bytes).is_ok() {
                        let mut child = std::process::Command::new(soffice_pdf)
                            .args(["--headless", "--convert-to", "pdf",
                                   "--outdir", &tmp_dir.to_string_lossy(),
                                   &docx_conv.to_string_lossy()])
                            .spawn().ok();
                        let lo_ok = match child.as_mut() {
                            None => false,
                            Some(c) => {
                                let deadline = std::time::Instant::now()
                                    + std::time::Duration::from_secs(180);
                                loop {
                                    match c.try_wait() {
                                        Ok(Some(s)) => break s.success(),
                                        Ok(None) if std::time::Instant::now() < deadline => {
                                            std::thread::sleep(std::time::Duration::from_millis(300));
                                        }
                                        _ => { let _ = c.kill(); break false; }
                                    }
                                }
                            }
                        };
                        borrar_seguro_local(&docx_conv.to_string_lossy());
                        if lo_ok {
                            let pdf_out = tmp_dir.join(format!("{}_conv.pdf", nombre));
                            if let Ok(pdf_bytes) = fs::read(&pdf_out) {
                                borrar_seguro_local(&pdf_out.to_string_lossy());
                                let b64_pdf = comprimir_b64(&pdf_bytes);
                                if let Ok(cifrado_pdf) = seguridad::blindar_documento(&b64_pdf, subclave_hex) {
                                    let _ = crate::escribir_privado(&salida_final, cifrado_pdf);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    })();
    borrar_seguro_local(&ruta_docx_tmp.to_string_lossy());
    resultado?;
    registrar_evento(&format!("PDF procesado: {}", ruta), subclave_hex);
    Ok(())
}

pub fn separar_signo(palabra: &str) -> (&str, &str) {
    let signos = [',', '.', '!', '?', ';', ':'];
    if let Some((i, c)) = palabra.char_indices().last() {
        if signos.contains(&c) {
            return (&palabra[..i], &palabra[i..]);
        }
    }
    (palabra, "")
}

pub fn registrar_evento(evento: &str, subclave_hex: &str) {
    // A1: delegamos en seguridad::registrar_evento_seguridad para que TODAS las escrituras
    // a auditoria.babel pasen por AUDIT_MUTEX + hash-chaining. Antes este writer escribía
    // el mismo archivo sin serializar ni encadenar, lo que corrompía el log bajo concurrencia
    // (monitor de amenazas, threads P2P, email) y rompía la cadena forense.
    let fecha = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let mensaje = format!("[{}] {}", fecha, evento);
    seguridad::registrar_evento_seguridad(&mensaje, subclave_hex);
}

// ============================================================
// SISTEMA DE DICCIONARIO JSON - AUTOMÁTICO
// ============================================================
//
// Estructura de archivos:
//   diccionarios/es_en.json       ← JSON legible, editable a mano
//   diccionarios/es_en.babel      ← mismo contenido cifrado (fuente de verdad)
//   diccionarios/historial.json   ← cada traducción nueva se registra
//   diccionarios/pendientes.json  ← palabras vistas sin traducción aún
//
// Regla: el .babel siempre gana. El .json es solo para inspección/edición.
// Al arrancar: si existe .babel se carga cifrado.
//              si solo existe .json se importa y se cifra automáticamente.
fn ruta_dict(nombre: &str) -> PathBuf {
    crate::babel_dir().join("diccionarios").join(nombre)
}

fn init_dir_dict() {
    let _ = fs::create_dir_all(crate::babel_dir().join("diccionarios"));
}

fn aplanar_categorias(
    categorizado: HashMap<String, HashMap<String, String>>,
    categoria: &str,
) -> HashMap<String, String> {
    let mut resultado = HashMap::new();
    for (cat, terminos) in categorizado {
        if categoria == "todos" || categoria == cat {
            resultado.extend(terminos);
        }
    }
    resultado
}

pub fn cargar_diccionario(
    nombre: &str,
    subclave_hex: &str,
    categoria: &str,
) -> HashMap<String, String> {
    init_dir_dict();
    let ruta_cifrada = ruta_dict(&format!("{}.babel", nombre));
    let ruta_json = ruta_dict(&format!("{}.json", nombre));

    // 1. Intentamos cargar desde el .babel cifrado (fuente de verdad)
    if let Ok(blob) = fs::read(&ruta_cifrada) {
        match seguridad::descifrar_documento(blob, subclave_hex) {
            Ok(json) => {
                // Intentar con categorías primero
                if let Ok(dict) =
                    serde_json::from_str::<HashMap<String, HashMap<String, String>>>(&json)
                {
                    return aplanar_categorias(dict, categoria);
                }
                // Fallback: el .babel guardó un diccionario plano
                if let Ok(plano) = serde_json::from_str::<HashMap<String, String>>(&json) {
                    return plano;
                }
                log::warn!(" [!] Diccionario cifrado con formato no reconocido.");
            }
            Err(_) => log::error!(
                " [!] No se pudo descifrar {}. Clave incorrecta.",
                ruta_cifrada.display()
            ),
        }
    }

    // 2. Fallback: intentamos importar desde el .json (con categorías o plano)
    if let Ok(contenido) = fs::read_to_string(&ruta_json) {
        // Intentar formato categorizado primero
        if let Ok(dict) = serde_json::from_str::<HashMap<String, HashMap<String, String>>>(&contenido) {
            log::info!("[OK] Diccionario JSON categorizado importado. Cifrando...");
            let plano = aplanar_categorias(dict, categoria);
            guardar_diccionario(nombre, &plano, subclave_hex);
            return plano;
        }
        // Fallback: JSON plano (clave → traducción directa sin categorías)
        if let Ok(plano) = serde_json::from_str::<HashMap<String, String>>(&contenido) {
            log::info!("[OK] Diccionario JSON plano importado. Cifrando...");
            guardar_diccionario(nombre, &plano, subclave_hex);
            return plano;
        }
        log::error!("[!] JSON de diccionario con formato no reconocido.");
    }

    log::info!("[INIT] Diccionario '{}' nuevo - empezando vacio.", nombre);
    HashMap::new()
}

pub fn guardar_diccionario(nombre: &str, dict: &HashMap<String, String>, subclave_hex: &str) {
    init_dir_dict();
    let ruta_cifrada = ruta_dict(&format!("{}.babel", nombre));

    if let Ok(json) = serde_json::to_string_pretty(dict) {
        match seguridad::blindar_documento(&json, subclave_hex) {
            Ok(cifrado) => {
                if let Err(e) = crate::escribir_privado(&ruta_cifrada, cifrado) {
                    log::error!("[!] Error guardando diccionario cifrado: {}", e);
                }
            }
            Err(e) => log::warn!("[!] Error cifrando diccionario: {}", e),
        }
    }
}

static PENDIENTES_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Registra una palabra desconocida en pendientes.babel (cifrado) para traducción futura.
pub fn registrar_pendiente(palabra: &str, subclave_hex: &str) {
    let _guard = PENDIENTES_MUTEX.lock().unwrap_or_else(|e| {
        log::error!("[!] PENDIENTES_MUTEX poisoned — pendientes.babel puede estar corrupto");
        e.into_inner()
    });
    init_dir_dict();
    let ruta = ruta_dict("pendientes.babel");

    let mut pendientes: Vec<String> = fs::read(&ruta)
        .ok()
        .and_then(|blob| seguridad::descifrar_documento(blob, subclave_hex).ok())
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default();

    if !pendientes.contains(&palabra.to_string()) {
        pendientes.push(palabra.to_string());
        pendientes.sort();
        if let Ok(json) = serde_json::to_string_pretty(&pendientes) {
            match seguridad::blindar_documento(&json, subclave_hex) {
                Ok(cifrado) => {
                    let _ = crate::escribir_privado(&ruta, cifrado);
                }
                Err(e) => log::warn!("[!] Error cifrando pendientes: {}", e),
            }
        }
    }
}

/// Guarda las credenciales de email cifradas en ~/Babel/config.babel
pub fn guardar_config_email(creds: &CredencialesEmail, subclave_hex: &str) -> Result<(), String> {
    let json = serde_json::to_string(&creds)
        .map_err(|e| format!("Error serializando config de email: {}", e))?;
    let cifrado = seguridad::blindar_documento(&json, subclave_hex)
        .map_err(|e| format!("Error cifrando config de email: {}", e))?;
    crate::escribir_privado(crate::babel_dir().join("config.babel"), cifrado)
        .map_err(|e| format!("Error guardando config de email: {}", e))?;
    Ok(())
}

/// Carga y descifra las credenciales de email desde ~/Babel/config.babel
pub fn cargar_config_email(subclave_hex: &str) -> Option<CredencialesEmail> {
    let contenido = fs::read(crate::babel_dir().join("config.babel")).ok()?;
    let descifrado = Zeroizing::new(seguridad::descifrar_documento(contenido, subclave_hex).ok()?);
    serde_json::from_str(descifrado.as_str()).ok()
}

// ============================================================
// EMAIL - OBTENER LISTA DE EMAILS DE LA BANDEJA DE ENTRADA
// ============================================================

#[derive(serde::Serialize)]
pub struct EmailResumen {
    pub id: u32,
    pub remitente: String,
    pub asunto: String,
    pub fecha: String,
    pub tiene_adjunto: bool,
    pub leido: bool,
    pub snippet: String,
}

/// Rechaza campos IMAP con caracteres de control o demasiado largos.
fn validar_campo_imap(valor: &str, _campo: &str) -> Result<(), Box<dyn std::error::Error>> {
    if valor.len() > 320 {
        return Err("Parámetro de conexión demasiado largo.".into());
    }
    // Rechazar cualquier carácter de control ASCII (0x00-0x1F, 0x7F) incluyendo
    // \r \n \t y otros que podrían inyectarse en cabeceras IMAP/SMTP.
    if valor.chars().any(|c| c.is_ascii_control()) {
        return Err("Parámetro de conexión contiene caracteres no permitidos.".into());
    }
    Ok(())
}

/// Extrae un snippet de texto plano de los primeros bytes de un mensaje RFC822.
fn extraer_snippet(datos: &[u8]) -> String {
    let texto = String::from_utf8_lossy(datos);
    // Saltar cabeceras — buscar línea en blanco separadora
    let cuerpo = match texto.find("\r\n\r\n").map(|p| p + 4)
        .or_else(|| texto.find("\n\n").map(|p| p + 2))
    {
        Some(pos) => texto[pos..].trim_start(),
        None => return String::new(),
    };
    // Si empieza con boundary MIME o cabecera de parte, buscar otro separador
    let cuerpo = if cuerpo.starts_with("--") || cuerpo.starts_with("Content-") {
        match cuerpo.find("\r\n\r\n").map(|p| p + 4)
            .or_else(|| cuerpo.find("\n\n").map(|p| p + 2))
        {
            Some(pos) => cuerpo[pos..].trim_start(),
            None => return String::new(),
        }
    } else {
        cuerpo
    };
    // Descartar si parece base64 (líneas largas alfanuméricas)
    if cuerpo.lines().next()
        .map(|l| l.len() > 60 && l.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '='))
        .unwrap_or(false)
    {
        return String::new();
    }
    // Tomar hasta 300 chars y colapsar espacios
    cuerpo
        .chars()
        .take(300)
        .filter(|c| !c.is_control() || *c == ' ')
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(130)
        .collect()
}

/// Devuelve true si la estructura BODYSTRUCTURE indica adjuntos.
/// Usa la representación Debug del tipo opaco de imap-proto para evitar
/// depender de los tipos internos del crate alpha.
fn body_tiene_adjunto_str(bs_debug: &str) -> bool {
    let s = bs_debug.to_ascii_lowercase();
    s.contains("multipart") && (s.contains("mixed") || s.contains("related"))
        || s.contains("\"attachment\"")
        || s.contains("attachment\"")
}

fn obtener_emails_interno(
    imap_dominio: &str,
    usuario: &str,
    password: &str,
) -> Result<Vec<EmailResumen>, String> {
    let cliente = imap::ClientBuilder::new(imap_dominio, 993)
        .connect()
        .map_err(|e| format!("Error conexión IMAP: {}", e))?;

    let mut sesion = cliente.login(usuario, password).map_err(|_| "Error de autenticación IMAP.".to_string())?;

    sesion.select("INBOX").map_err(|e| e.to_string())?;

    // UIDs permanentes — no cambian al borrar emails (a diferencia de seq numbers)
    let todos: Vec<u32> = sesion.uid_search("ALL").map_err(|e| e.to_string())?.into_iter().collect();

    let mut ids: Vec<u32> = todos;
    ids.sort_unstable();
    ids.reverse();
    ids.truncate(20);
    if ids.is_empty() {
        let _ = sesion.logout();
        return Ok(vec![]);
    }

    let ids_str = ids
        .iter()
        .map(|id| id.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let fetch = sesion.uid_fetch(&ids_str, "(ENVELOPE FLAGS BODYSTRUCTURE RFC822<0.700>)").map_err(|e| e.to_string())?;

    let mut emails: Vec<EmailResumen> = Vec::new();

    for msg in fetch.iter() {
        let id = msg.uid.unwrap_or(msg.message);

        let envelope = match msg.envelope() {
            Some(e) => e,
            None => continue,
        };

        // Remitente
        let remitente = envelope
            .from
            .as_ref()
            .and_then(|f| f.first())
            .map(|addr| {
                let mailbox = addr
                    .mailbox
                    .as_ref()
                    .map(|m| std::str::from_utf8(m).unwrap_or("").to_string())
                    .unwrap_or_default();
                let host = addr
                    .host
                    .as_ref()
                    .map(|h| std::str::from_utf8(h).unwrap_or("").to_string())
                    .unwrap_or_default();
                let name = addr
                    .name
                    .as_ref()
                    .map(|n| std::str::from_utf8(n).unwrap_or("").to_string())
                    .unwrap_or_default();
                if name.is_empty() {
                    format!("{}@{}", mailbox, host)
                } else {
                    format!("{} <{}@{}>", name, mailbox, host)
                }
            })
            .unwrap_or_else(|| "Desconocido".to_string());

        // Asunto
        let asunto = envelope
            .subject
            .as_ref()
            .and_then(|s| std::str::from_utf8(s).ok())
            .unwrap_or("Sin asunto")
            .to_string();

        // Fecha
        let fecha = envelope
            .date
            .as_ref()
            .and_then(|d| std::str::from_utf8(d).ok())
            .unwrap_or("")
            .to_string();

        let tiene_adjunto = msg.bodystructure()
            .map(|bs| body_tiene_adjunto_str(&format!("{bs:?}")))
            .unwrap_or(false);

        let leido = msg.flags().iter().any(|f| format!("{f:?}").contains("Seen"));
        let snippet = msg.body().map(extraer_snippet).unwrap_or_default();

        emails.push(EmailResumen {
            id,
            remitente,
            asunto,
            fecha,
            tiene_adjunto,
            leido,
            snippet,
        });
    }

    let _ = sesion.logout();
    Ok(emails)
}

/// Wrapper con timeout de 30s para obtener_emails_interno.
pub fn obtener_emails(
    imap_dominio: &str,
    usuario: &str,
    password: &str,
) -> Result<Vec<EmailResumen>, Box<dyn std::error::Error>> {
    validar_campo_imap(imap_dominio, "imap_dominio")?;
    validar_campo_imap(usuario, "usuario")?;
    validar_campo_imap(password, "password")?;
    let (tx, rx) = std::sync::mpsc::channel::<Result<Vec<EmailResumen>, String>>();
    let dom = Zeroizing::new(imap_dominio.to_string());
    let usr = Zeroizing::new(usuario.to_string());
    let pwd = Zeroizing::new(password.to_string());
    std::thread::spawn(move || { let _ = tx.send(obtener_emails_interno(dom.as_str(), usr.as_str(), pwd.as_str())); });
    rx.recv_timeout(std::time::Duration::from_secs(30))
        .map_err(|_| "Timeout de conexión IMAP (30s)".to_string())?
        .map_err(|e| e.into())
}

// ============================================================
// EMAIL - OBTENER EMAIL COMPLETO POR ID
// ============================================================

fn extraer_mime_rec(parte: &mailparse::ParsedMail, cuerpo: &mut String, adjuntos: &mut Vec<String>) {
    let ct = parte.headers.get_first_header("Content-Type")
        .map(|h| h.get_value().to_lowercase())
        .unwrap_or_default();
    let cd = parte.headers.get_first_header("Content-Disposition")
        .map(|h| h.get_value().to_lowercase())
        .unwrap_or_default();
    if !parte.subparts.is_empty() {
        for sub in &parte.subparts {
            extraer_mime_rec(sub, cuerpo, adjuntos);
        }
    } else if cd.contains("attachment") {
        let nombre_raw = cd.split(';')
            .find(|p| p.trim().starts_with("filename"))
            .and_then(|p| p.split('=').nth(1))
            .map(|n| n.trim().trim_matches('"').to_string())
            .unwrap_or_else(|| "adjunto".to_string());
        let nombre = std::path::Path::new(&nombre_raw)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("adjunto")
            .to_string();
        adjuntos.push(nombre);
    } else if ct.contains("text/plain") && cuerpo.is_empty() {
        *cuerpo = parte.get_body().unwrap_or_default();
    } else if ct.contains("text/html") && cuerpo.is_empty() {
        *cuerpo = parte.get_body().unwrap_or_default();
    }
}

pub struct EmailCompletoRust {
    pub id: u32,
    pub remitente: String,
    pub asunto: String,
    pub fecha: String,
    pub cuerpo: String,
    pub adjuntos: Vec<String>,
}

fn obtener_email_completo_interno(
    imap_dominio: &str,
    usuario: &str,
    password: &str,
    id: u32,
) -> Result<EmailCompletoRust, String> {
    let cliente = imap::ClientBuilder::new(imap_dominio, 993)
        .connect()
        .map_err(|e| format!("Error conexión IMAP: {}", e))?;

    let mut sesion = cliente.login(usuario, password).map_err(|_| "Error de autenticación IMAP.".to_string())?;

    sesion.select("INBOX").map_err(|e| e.to_string())?;

    let fetch = sesion.uid_fetch(id.to_string(), "(RFC822)").map_err(|e| e.to_string())?;

    let msg = fetch.iter().next().ok_or("Email no encontrado")?;

    let cuerpo_raw = msg.body().unwrap_or(&[]);
    let email_parseado = mailparse::parse_mail(cuerpo_raw).map_err(|e| e.to_string())?;

    // Remitente
    let remitente = email_parseado
        .headers
        .get_first_header("From")
        .map(|h| h.get_value())
        .unwrap_or_else(|| "Desconocido".to_string());

    // Asunto
    let asunto = email_parseado
        .headers
        .get_first_header("Subject")
        .map(|h| h.get_value())
        .unwrap_or_else(|| "Sin asunto".to_string());

    // Fecha
    let fecha = email_parseado
        .headers
        .get_first_header("Date")
        .map(|h| h.get_value())
        .unwrap_or_default();

    // Cuerpo de texto — búsqueda recursiva para soportar MIME anidado
    // (ej: multipart/mixed → multipart/alternative → text/plain + text/html)
    let mut cuerpo = String::new();
    let mut adjuntos: Vec<String> = Vec::new();
    extraer_mime_rec(&email_parseado, &mut cuerpo, &mut adjuntos);

    let _ = sesion.logout();

    Ok(EmailCompletoRust {
        id,
        remitente,
        asunto,
        fecha,
        cuerpo,
        adjuntos,
    })
}

pub fn obtener_email_completo(
    imap_dominio: &str,
    usuario: &str,
    password: &str,
    id: u32,
) -> Result<EmailCompletoRust, Box<dyn std::error::Error>> {
    validar_campo_imap(imap_dominio, "imap_dominio")?;
    validar_campo_imap(usuario, "usuario")?;
    validar_campo_imap(password, "password")?;

    let dom = Zeroizing::new(imap_dominio.to_string());
    let usr = Zeroizing::new(usuario.to_string());
    let pwd = Zeroizing::new(password.to_string());

    let (tx, rx) = std::sync::mpsc::channel::<Result<EmailCompletoRust, String>>();
    std::thread::spawn(move || {
        let _ = tx.send(obtener_email_completo_interno(dom.as_str(), usr.as_str(), pwd.as_str(), id));
    });

    rx.recv_timeout(std::time::Duration::from_secs(30))
        .map_err(|_| "Timeout de conexión IMAP (30s)".to_string())?
        .map_err(|e| e.into())
}

// ============================================================
// EMAIL - ELIMINAR EMAIL POR UID (IMAP \Deleted + EXPUNGE)
// ============================================================

fn eliminar_email_interno(
    imap_dominio: &str,
    usuario: &str,
    password: &str,
    uid: u32,
) -> Result<(), String> {
    let cliente = imap::ClientBuilder::new(imap_dominio, 993)
        .connect()
        .map_err(|e| format!("Error conexión IMAP: {}", e))?;

    let mut sesion = cliente
        .login(usuario, password)
        .map_err(|_| "Error de autenticación IMAP.".to_string())?;

    sesion.select("INBOX").map_err(|e| e.to_string())?;

    sesion
        .uid_store(uid.to_string(), "+FLAGS (\\Deleted)")
        .map_err(|e| format!("Error marcando email: {}", e))?;

    sesion
        .expunge()
        .map_err(|e| format!("Error purgando email: {}", e))?;

    let _ = sesion.logout();
    Ok(())
}

pub fn eliminar_email(
    imap_dominio: &str,
    usuario: &str,
    password: &str,
    uid: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    validar_campo_imap(imap_dominio, "imap_dominio")?;
    validar_campo_imap(usuario, "usuario")?;
    validar_campo_imap(password, "password")?;

    let dom = Zeroizing::new(imap_dominio.to_string());
    let usr = Zeroizing::new(usuario.to_string());
    let pwd = Zeroizing::new(password.to_string());

    let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();
    std::thread::spawn(move || {
        let _ = tx.send(eliminar_email_interno(
            dom.as_str(),
            usr.as_str(),
            pwd.as_str(),
            uid,
        ));
    });

    rx.recv_timeout(std::time::Duration::from_secs(30))
        .map_err(|_| "Timeout de conexión IMAP (30s)".to_string())?
        .map_err(|e| e.into())
}

fn marcar_no_leido_interno(
    imap_dominio: &str,
    usuario: &str,
    password: &str,
    uid: u32,
) -> Result<(), String> {
    let cliente = imap::ClientBuilder::new(imap_dominio, 993)
        .connect()
        .map_err(|e| format!("Error conexión IMAP: {}", e))?;
    let mut sesion = cliente
        .login(usuario, password)
        .map_err(|_| "Error de autenticación IMAP.".to_string())?;
    sesion.select("INBOX").map_err(|e| e.to_string())?;
    sesion
        .uid_store(uid.to_string(), "-FLAGS (\\Seen)")
        .map_err(|e| format!("Error marcando no leído: {}", e))?;
    let _ = sesion.logout();
    Ok(())
}

pub fn marcar_no_leido(
    imap_dominio: &str,
    usuario: &str,
    password: &str,
    uid: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    validar_campo_imap(imap_dominio, "imap_dominio")?;
    validar_campo_imap(usuario, "usuario")?;
    validar_campo_imap(password, "password")?;
    let dom = Zeroizing::new(imap_dominio.to_string());
    let usr = Zeroizing::new(usuario.to_string());
    let pwd = Zeroizing::new(password.to_string());
    let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();
    std::thread::spawn(move || {
        let _ = tx.send(marcar_no_leido_interno(dom.as_str(), usr.as_str(), pwd.as_str(), uid));
    });
    rx.recv_timeout(std::time::Duration::from_secs(30))
        .map_err(|_| "Timeout IMAP (30s)".to_string())?
        .map_err(|e| e.into())
}

// ============================================================
// MARIAN - TRADUCCIÓN NEURONAL VÍA SERVIDOR PYTHON
// ============================================================

static UREQ_AGENT: OnceLock<ureq::Agent> = OnceLock::new();

// Token NLLB en OnceLock en lugar de variable de entorno:
// - Elimina set_var() (UB en contexto multihilo, B7)
// - El token ya no aparece en `ps aux` ni /proc/self/environ (B8)
static NLLB_TOKEN: OnceLock<String> = OnceLock::new();
static TOKEN_DESDE_ARCHIVO: OnceLock<String> = OnceLock::new();

// Token por defecto FIJO, idéntico al de server.py (_TOKEN_DEFECTO). Permite que la app
// se autentique con el servidor local aunque se abra con doble clic (sin BABEL_NLLB_TOKEN
// en el entorno) — antes ese caso caía al diccionario y traducía palabra por palabra.
// Es defensa en profundidad sobre un puerto solo-localhost; el modo USB lo sobrescribe
// con un token aleatorio vía inicializar_nllb_token.
const NLLB_TOKEN_DEFECTO: &str = "babel-local-default-token-2026-no-compartir";

pub fn inicializar_nllb_token(token: String) {
    let _ = NLLB_TOKEN.set(token);
}

/// Resuelve el token efectivo por prioridad: OnceLock (modo USB) > variable de entorno
/// (arrancar_babel.sh / npm run tauri dev) > constante por defecto compartida.
fn token_efectivo() -> String {
    if let Some(t) = NLLB_TOKEN.get() {
        if !t.is_empty() {
            return t.clone();
        }
    }
    if let Ok(t) = std::env::var("BABEL_NLLB_TOKEN") {
        if !t.is_empty() {
            return t;
        }
    }
    // Si server.py arrancó manualmente sin BABEL_NLLB_TOKEN, habrá persistido
    // el token en ~/Babel/servidor_token.txt. Lo leemos una sola vez.
    let desde_archivo = TOKEN_DESDE_ARCHIVO.get_or_init(|| {
        let path = crate::babel_dir().join("servidor_token.txt");
        std::fs::read_to_string(path)
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    });
    if desde_archivo.len() >= 32 {
        return desde_archivo.clone();
    }
    NLLB_TOKEN_DEFECTO.to_string()
}

fn agente_http() -> &'static ureq::Agent {
    UREQ_AGENT.get_or_init(|| {
        ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(3))
            .timeout(std::time::Duration::from_secs(60))
            .build()
    })
}

// Tamaño de lote de traducción según el tier de RAM de la máquina.
// El servidor elige el modelo por la RAM total (SMaLL-100 en <12 GB, MADLAD-3B en ≥12 GB);
// reutilizamos esa decisión como proxy del tier. SMaLL-100 (~0.6 GB, decoder de 3 capas)
// tiene una huella de memoria de activación mucho menor que el viejo M2M-100 (~2 GB), así
// que en el tier ligero cabe un lote bastante mayor sin disparar el swap; aun así lo
// mantenemos por debajo del de MADLAD por prudencia en máquinas de 8 GB muy cargadas.
// Se consulta /ping una sola vez y se cachea. Ante cualquier error → valor conservador.
static BATCH_TIER: OnceLock<usize> = OnceLock::new();

fn batch_por_tier() -> usize {
    *BATCH_TIER.get_or_init(|| {
        let modelo = agente_http()
            .get("http://127.0.0.1:5002/ping")
            .set("X-Babel-Token", &token_efectivo())
            .call()
            .ok()
            .and_then(|r| r.into_json::<serde_json::Value>().ok())
            .and_then(|j| j["modelo"].as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        if modelo.contains("madlad") { 150 } else { 80 }
    })
}

static UREQ_AGENTE_BATCH: OnceLock<ureq::Agent> = OnceLock::new();

fn agente_http_batch() -> &'static ureq::Agent {
    UREQ_AGENTE_BATCH.get_or_init(|| {
        ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(600))
            .build()
    })
}

// Timeout generoso para OCR: primer uso carga el modelo (~35s) + inferencia (~7s/pág × 60 pág)
static UREQ_AGENTE_OCR: OnceLock<ureq::Agent> = OnceLock::new();

fn agente_http_ocr() -> &'static ureq::Agent {
    UREQ_AGENTE_OCR.get_or_init(|| {
        ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(600))
            .build()
    })
}

/// Llama al endpoint /ocr_pdf del servidor para hacer OCR con PaddleOCR-VL.
/// El modelo queda en memoria entre llamadas → sin cold start a partir de la segunda vez.
/// Devuelve None si el servidor no tiene el modelo o hay cualquier error.
fn ocr_via_servidor(ruta_pdf: &str) -> Option<String> {
    let body = serde_json::json!({ "ruta": ruta_pdf });
    let resp = agente_http_ocr()
        .post("http://127.0.0.1:5002/ocr_pdf")
        .set("Content-Type", "application/json")
        .set("X-Babel-Token", &token_efectivo())
        .send_json(&body)
        .ok()?;
    let json: serde_json::Value = resp.into_json().ok()?;
    json["texto"].as_str().map(|s| s.to_string())
}


fn traducir_batch_via_servidor(textos: &[&str], par: &str) -> Result<Vec<String>, String> {
    let mut body = serde_json::json!({
        "textos": textos,
        "par": par,
    });
    if MODO_RAPIDO.load(Ordering::Relaxed) {
        body["beam"] = serde_json::json!(1);
    }
    let resp = agente_http_batch()
        .post("http://127.0.0.1:5002/traducir_batch")
        .set("Content-Type", "application/json")
        .set("X-Babel-Token", &token_efectivo())
        .send_json(&body)
        .map_err(|e| format!("Batch no disponible: {}", e))?;
    let json: serde_json::Value = resp
        .into_json()
        .map_err(|e| format!("Batch respuesta inválida: {}", e))?;
    json["traducciones"]
        .as_array()
        .ok_or_else(|| "Batch: campo traducciones ausente".to_string())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
}

/// Traduce un texto llamando al servidor Python local (127.0.0.1:5002/traducir).
pub fn traducir_via_servidor(texto: &str, par: &str) -> Result<String, String> {
    const MAX_BYTES: usize = 50_000;
    if texto.len() > MAX_BYTES {
        return Err(format!("Texto demasiado grande ({} bytes, máx {} KB)", texto.len(), MAX_BYTES / 1000));
    }
    let url = "http://127.0.0.1:5002/traducir";
    let token = token_efectivo();
    let body = if MODO_RAPIDO.load(Ordering::Relaxed) {
        serde_json::json!({ "texto": texto, "par": par, "beam": 1 })
    } else {
        serde_json::json!({ "texto": texto, "par": par })
    };

    let respuesta = agente_http()
        .post(url)
        .set("Content-Type", "application/json")
        .set("X-Babel-Token", &token)
        .send_json(&body)
        .map_err(|e| format!("Servidor de traducción no disponible: {}", e))?;

    let json: serde_json::Value = respuesta
        .into_json()
        .map_err(|e| format!("Error leyendo respuesta: {}", e))?;

    json["traduccion"]
        .as_str()
        .map(|s| {
            if s.len() > 50_000 {
                return Err("Respuesta excede el límite de 50 000 caracteres".to_string());
            }
            Ok(s.to_string())
        })
        .ok_or_else(|| "Respuesta inválida del servidor".to_string())
        .and_then(|r| r)
}

/// Traduce con MarianMT. Si no está disponible, usa el diccionario.
pub fn traducir_inteligente(
    texto: &str,
    dict: &std::collections::HashMap<String, String>,
    subclave_hex: &str,
    par: &str,
) -> (String, usize) {
    match traducir_via_servidor(texto, par) {
        Ok(traduccion) => (traduccion, 0),
        Err(_) => motor_atomico(texto, dict, subclave_hex),
    }
}
