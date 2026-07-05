use base64;
use base64::Engine;
use tesseract::Tesseract;
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
            let _ = fs::write(&ruta_bck, s);
            salt_perms_600(&ruta_bck);
            return s;
        }
        (None, Some(s)) => {
            log::warn!("[Babel] master.salt no encontrada - recuperando desde backup...");
            if let Err(e) = fs::write(&ruta_salt, s) {
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
    if let Err(e) = fs::write(&ruta_salt, nueva_salt) {
        log::error!(
            "[Babel] ERROR CRÍTICO: no se pudo guardar master.salt: {}",
            e
        );
    } else {
        salt_perms_600(&ruta_salt);
    }
    let _ = fs::write(&ruta_bck, nueva_salt);
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
                archivos_dir.join(format!("{}_{}__orig.babel", id_usuario, nombre));
            let _ = fs::write(&salida_orig, cifrado_orig);
        }

        // Traducir párrafo a párrafo para evitar bucles en NLLB
        let parrafos: Vec<&str> = texto.split('\n').collect();
        let total_p = parrafos.iter().filter(|p| !p.trim().is_empty()).count().max(1);
        let mut traducidos_p = 0usize;
        let mut traducido_final = String::new();
        for parrafo in &parrafos {
            if parrafo.trim().is_empty() {
                traducido_final.push('\n');
                continue;
            }
            let pct = (10 + traducidos_p * 80 / total_p).min(90) as u8;
            progreso(pct, &format!("TRADUCIENDO... {}%", pct));
            traducidos_p += 1;
            let traducido = match traducir_con_marian(parrafo, par) {
                Ok(t) => t,
                Err(_) => {
                    let (t, _) =
                        traducir_inteligente(parrafo, dict, subclave_hex, par);
                    t
                }
            };
            traducido_final.push_str(&traducido);
            traducido_final.push('\n');
        }
        progreso(93, "CIFRANDO RESULTADO...");
        // Guardar traducción cifrada
        if let Ok(cifrado) = seguridad::blindar_documento(&traducido_final, subclave_hex) {
            let salida = archivos_dir.join(format!("{}_{}.babel", id_usuario, nombre));
            let _ = fs::write(&salida, cifrado);
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
fn traducir_xml_directo(
    xml: &str,
    dict: &HashMap<String, String>,
    subclave_hex: &str,
    par: &str,
    pct_inicio: u8,
    pct_fin: u8,
    progreso: &dyn Fn(u8, &str),
) -> String {
    let xml_total = xml.len().max(1);
    let mut resultado = String::with_capacity(xml.len() * 2);
    let mut resto = xml;
    let mut ultimo_pct = pct_inicio;

    loop {
        // Progreso continuo basado en posición de caracteres procesados
        let pos_actual = xml_total - resto.len();
        let pct = (pct_inicio as usize
            + pos_actual * pct_fin.saturating_sub(pct_inicio) as usize / xml_total)
            .min(pct_fin as usize) as u8;
        if pct >= ultimo_pct + 3 {
            ultimo_pct = pct;
            progreso(pct, &format!("TRADUCIENDO... {}%", pct));
        }

        // Buscar el próximo <w:p> o <w:p ...> (no <w:pPr>, <w:pStyle>, etc.)
        let Some(pos) = encontrar_wp(resto) else {
            resultado.push_str(resto);
            break;
        };

        resultado.push_str(&resto[..pos]);
        let desde_p = &resto[pos..];

        // Detectar párrafo vacío auto-cerrado <w:p ... />
        let tag_end = match desde_p.find('>') {
            Some(j) => j,
            None => { resultado.push_str(desde_p); break; }
        };
        if desde_p[..tag_end + 1].ends_with("/>") {
            resultado.push_str(&desde_p[..tag_end + 1]);
            resto = &desde_p[tag_end + 1..];
            continue;
        }

        // Encontrar el cierre del párrafo
        let Some(fin_rel) = desde_p.find("</w:p>") else {
            resultado.push_str(desde_p);
            break;
        };
        let parrafo_xml = &desde_p[..fin_rel + 6];
        resultado.push_str(&traducir_parrafo_xml(parrafo_xml, dict, subclave_hex, par));
        resto = &desde_p[fin_rel + 6..];
    }

    resultado
}

/// Devuelve la posición del próximo <w:p> o <w:p ...> real (no <w:pPr> etc.)
fn encontrar_wp(xml: &str) -> Option<usize> {
    let mut desde = 0;
    loop {
        let rel = xml[desde..].find("<w:p")?;
        let pos = desde + rel;
        let after = xml.get(pos + 4..pos + 5).unwrap_or("");
        if after == ">" || after == " " || after == "/" {
            return Some(pos);
        }
        desde = pos + 4;
    }
}

/// Traduce un párrafo completo: extrae todo el texto, lo traduce como unidad
/// y pone el resultado en el primer <w:t>, vaciando los demás.
fn traducir_parrafo_xml(
    parrafo: &str,
    dict: &HashMap<String, String>,
    subclave_hex: &str,
    par: &str,
) -> String {
    let texto = extraer_texto_wt(parrafo);
    if texto.trim().is_empty() {
        return parrafo.to_string();
    }

    let traducido = match traducir_con_marian(&texto, par) {
        Ok(t) => t,
        Err(_) => motor_atomico(&texto, dict, subclave_hex).0,
    };

    reconstruir_parrafo(parrafo, &traducido)
}

/// Concatena el contenido de todos los <w:t> del fragmento XML dado.
fn extraer_texto_wt(xml: &str) -> String {
    let mut texto = String::new();
    let mut resto = xml;
    loop {
        let Some(pos) = resto.find("<w:t") else { break };
        let after = resto.get(pos + 4..pos + 5).unwrap_or("");
        if after != ">" && after != " " {
            resto = &resto[pos + 4..];
            continue;
        }
        let Some(j) = resto[pos..].find('>') else { break };
        let contenido_ini = pos + j + 1;
        let Some(k) = resto[contenido_ini..].find("</w:t>") else { break };
        let t = &resto[contenido_ini..contenido_ini + k];
        let t_dec = t.replace("&amp;", "&").replace("&lt;", "<")
                     .replace("&gt;", ">").replace("&apos;", "'").replace("&quot;", "\"");
        texto.push_str(&t_dec);
        resto = &resto[contenido_ini + k + 6..];
    }
    texto
}

/// Reescribe el XML del párrafo: pone `traduccion` en el primer <w:t>
/// con texto y vacía los demás, conservando el formato/estilo intacto.
fn reconstruir_parrafo(parrafo: &str, traduccion: &str) -> String {
    let esc = traduccion.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let mut resultado = String::with_capacity(parrafo.len() + esc.len());
    let mut resto = parrafo;
    let mut puesto = false;

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
        let contenido_dec = contenido.replace("&amp;", "&").replace("&lt;", "<")
                                     .replace("&gt;", ">").replace("&apos;", "'").replace("&quot;", "\"");

        if !contenido_dec.trim().is_empty() && !puesto {
            // Primer <w:t> con texto: escribir la traducción completa
            resultado.push_str("<w:t xml:space=\"preserve\">");
            resultado.push_str(&esc);
            resultado.push_str("</w:t>");
            puesto = true;
        } else if !contenido_dec.trim().is_empty() {
            // Resto de <w:t> con texto: vaciar (ya pusimos la traducción)
            resultado.push_str(tag);
            resultado.push_str("</w:t>");
        } else {
            // Espacios / vacíos: conservar tal cual
            resultado.push_str(tag);
            resultado.push_str(contenido);
            resultado.push_str("</w:t>");
        }

        resto = &tras_tag[k + 6..];
    }

    resultado
}

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
        let salida_orig = archivos_dir.join(format!("{}_{}__orig.babel", id_usuario, nombre));
        let _ = fs::write(&salida_orig, cifrado_orig);
    }

    progreso(15, "PROCESANDO WORD...");
    // Traducir document.xml (rango de progreso 20–88%)
    let xml_traducido = traducir_xml_directo(&xml_doc, dict, subclave_hex, par, 20, 88, progreso);

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
                    traducir_xml_directo(&xml_sub, dict, subclave_hex, par, 88, 95, progreso);
                zip_out.start_file(&name, opts_deflate)?;
                zip_out.write_all(xml_sub_trad.as_bytes())?;
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
    let salida = archivos_dir.join(format!("{}_{}.babel", id_usuario, nombre));
    fs::write(&salida, &cifrado)?;

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
            if tam > 0 { let _ = fs::write(&tmp_img, vec![0u8; tam]); }
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
    let _ = fs::write(&tmp_img, vec![0u8; tam]);
    let _ = fs::remove_file(&tmp_img);
    resultado
}

// M6: delega en crate::borrar_seguro, que aplica O_NOFOLLOW + symlink_metadata para evitar
// TOCTOU por symlink (los temporales viven en ~/Babel/tmp, potencialmente compartido) además
// de las 3 pasadas + fsync. Antes esta versión local abría con write() sin O_NOFOLLOW.
fn borrar_seguro_local(ruta: &str) {
    crate::borrar_seguro(ruta);
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
    let ok = {
        let mut child = std::process::Command::new("python3")
            .args([
                "-c",
                "import sys; from pdf2docx import Converter; cv=Converter(sys.argv[1]); cv.convert(sys.argv[2]); cv.close()",
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
                loop {
                    match c.try_wait() {
                        Ok(Some(s)) => break s.success(),
                        Ok(None) if std::time::Instant::now() < deadline => {
                            std::thread::sleep(std::time::Duration::from_millis(500));
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

    if !ok {
        // Fallback: pdftotext → si vacío, OCR página a página (máx. 50)
        let pdftotext = [
            "/opt/homebrew/bin/pdftotext",
            "/usr/local/bin/pdftotext",
            "/usr/bin/pdftotext",
            "pdftotext",
        ]
        .iter()
        .copied()
        .find(|&p| p == "pdftotext" || std::path::Path::new(p).exists())
        .unwrap_or("pdftotext");
        let mut texto = Zeroizing::new(
            std::process::Command::new(pdftotext)
                .args([ruta, "-"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default(),
        );
        if texto.trim().is_empty() {
            let mut ocr_total = String::new();
            for pag in 1u32..=50 {
                let pag_text = ocr_pagina_pdf(ruta, pag);
                if pag_text.trim().is_empty() {
                    break;
                }
                ocr_total.push_str(&pag_text);
                ocr_total.push('\n');
            }
            *texto = ocr_total;
        }
        progreso(15, "EXTRAYENDO TEXTO...");
        // Traducir párrafo a párrafo con NLLB (fallback a diccionario)
        let parrafos: Vec<String> = texto.lines().map(String::from).collect();
        let total_p = parrafos.iter().filter(|p| !p.trim().is_empty()).count().max(1);
        let mut traducidos_p = 0usize;
        let mut traducido = String::new();
        for parrafo in &parrafos {
            if parrafo.trim().is_empty() {
                traducido.push('\n');
                continue;
            }
            let pct = (20 + traducidos_p * 70 / total_p).min(90) as u8;
            progreso(pct, &format!("TRADUCIENDO... {}%", pct));
            traducidos_p += 1;
            let t = match traducir_con_marian(parrafo, par) {
                Ok(t) => t,
                Err(_) => {
                    let (t, _) = motor_atomico(parrafo, dict, subclave_hex);
                    t
                }
            };
            traducido.push_str(&t);
            traducido.push('\n');
        }
        progreso(93, "CIFRANDO RESULTADO...");
        let cifrado = seguridad::blindar_documento(&traducido, subclave_hex)?;
        fs::write(
            archivos_dir.join(format!("{}_{}.babel", id_usuario, nombre)),
            cifrado,
        )?;
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
        let salida_tmp = archivos_dir.join(format!("{}_{}_tmp.babel", id_usuario, nombre));
        let salida_final = archivos_dir.join(format!("{}_{}.babel", id_usuario, nombre));
        if salida_tmp.exists() {
            let _ = fs::rename(&salida_tmp, &salida_final);
        }
        let orig_tmp =
            archivos_dir.join(format!("{}_{}_tmp__orig.babel", id_usuario, nombre));
        let orig_final =
            archivos_dir.join(format!("{}_{}__orig.babel", id_usuario, nombre));
        if orig_tmp.exists() {
            let _ = fs::rename(&orig_tmp, &orig_final);
        }

        // PASO 3: DOCX traducido → PDF vía LibreOffice
        let ruta_docx_trad =
            archivos_dir.join(format!("{}_{}.babel", id_usuario, nombre));
        if let Ok(bytes_cifrados) = fs::read(&ruta_docx_trad) {
            if let Ok(b64) = seguridad::descifrar_documento(bytes_cifrados, subclave_hex) {
                if let Ok(docx_bytes) = descomprimir_b64(&b64) {
                    let docx_para_pdf = tmp_dir.join(format!("{}_trad.docx", nombre));
                    let _ = fs::write(&docx_para_pdf, &docx_bytes);
                    let soffice = [
                        "/opt/homebrew/bin/soffice",
                        "/usr/local/bin/soffice",
                        "/Applications/LibreOffice.app/Contents/MacOS/soffice",
                    ]
                    .iter()
                    .find(|&&p| std::path::Path::new(p).exists())
                    .copied()
                    .unwrap_or("soffice");
                    std::process::Command::new(soffice)
                        .args([
                            "--headless",
                            "--convert-to",
                            "pdf",
                            "--outdir",
                            &tmp_dir.to_string_lossy(),
                            &docx_para_pdf.to_string_lossy(),
                        ])
                        .status()
                        .ok();

                    let pdf_out = tmp_dir.join(format!("{}_trad.pdf", nombre));
                    if pdf_out.exists() {
                        if let Ok(pdf_bytes) = fs::read(&pdf_out) {
                            let b64_pdf = base64::engine::general_purpose::STANDARD
                                .encode(&pdf_bytes);
                            match seguridad::blindar_documento(&b64_pdf, subclave_hex) {
                                Ok(cifrado_pdf) => {
                                    let _ = fs::write(&ruta_docx_trad, cifrado_pdf);
                                }
                                Err(e) => {
                                    registrar_evento(
                                        &format!("AVISO: error cifrando PDF traducido: {}", e),
                                        subclave_hex,
                                    );
                                }
                            }
                        }
                        borrar_seguro_local(&pdf_out.to_string_lossy());
                    }
                    borrar_seguro_local(&docx_para_pdf.to_string_lossy());
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
                if let Err(e) = fs::write(&ruta_cifrada, cifrado) {
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
                    let _ = fs::write(&ruta, cifrado);
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
    fs::write(crate::babel_dir().join("config.babel"), cifrado)
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

/// Rechaza cualquier campo IMAP que contenga \r o \n — previene inyección de comandos.
fn validar_campo_imap(valor: &str, _campo: &str) -> Result<(), Box<dyn std::error::Error>> {
    if valor.len() > 320 {
        return Err("Parámetro de conexión demasiado largo.".into());
    }
    if valor.contains('\r') || valor.contains('\n') || valor.contains('\0') {
        return Err("Parámetro de conexión inválido.".into());
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

/// Llama al servidor Python MarianMT en localhost:5002.
/// Incluye token de seguridad — Flask rechaza sin él.
pub fn traducir_con_marian(texto: &str, par: &str) -> Result<String, String> {
    const MAX_BYTES: usize = 50_000;
    if texto.len() > MAX_BYTES {
        return Err(format!("Texto demasiado grande ({} bytes, máx {} KB)", texto.len(), MAX_BYTES / 1000));
    }
    let url = "http://127.0.0.1:5002/traducir";
    let token = token_efectivo();
    let body = serde_json::json!({
        "texto": texto,
        "par": par
    });

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
    match traducir_con_marian(texto, par) {
        Ok(traduccion) => (traduccion, 0),
        Err(_) => motor_atomico(texto, dict, subclave_hex),
    }
}
