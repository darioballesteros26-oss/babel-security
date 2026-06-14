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
use sha2;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::seguridad;
use lettre::{Message, Transport};
pub fn enviar_archivo_descifrado(
    ruta: &str,
    destinatario: &str,
    asunto: &str,
    cuerpo: &str, // ← añade
    smtp_servidor: &str,
    smtp_usuario: &str,
    smtp_password: &str,
    subclave_hex: &str,
) -> Result<(), Box<dyn std::error::Error>> {
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

    let cuerpo_html = format!(
    "<html><body style='font-family:Arial,sans-serif;color:#222;'>\
    <p>{}</p>\
    <hr style='border:1px solid #eee;margin:20px 0;'>\
    <p style='font-size:12px;color:#888;'>Enviado con Babel Security - traducción y cifrado 100% local.</p>\
    </body></html>",
    if cuerpo.is_empty() { "Te envío el documento adjunto.".to_string() } else { cuerpo.to_string() }
);

    let email = Message::builder()
        .from(smtp_usuario.parse()?)
        .to(destinatario.parse()?)
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
}

// ============================================================
// GESTIÓN DE SALT MAESTRA
// ============================================================

/// Carga la sal maestra desde ~/Babel/master.salt.
/// Si no existe, la genera y la guarda junto con un backup.
/// La sal NO es secreta: solo debe ser única e inmutable.
/// Si se pierde sin backup, todos los datos cifrados son irrecuperables.
pub fn cargar_o_crear_salt() -> [u8; 32] {
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

/// Guarda timestamp + firma SHA256(timestamp|salt) en bloqueo.tmp
pub fn activar_bloqueo_disco() {
    let ts = chrono::Local::now().timestamp();
    let salt = cargar_o_crear_salt();
    use sha2::Digest;
    let firma = format!(
        "{:x}",
        sha2::Sha256::digest(format!("{}:{}", ts, hex::encode(salt)).as_bytes())
    );
    let contenido = format!("{}:{}", ts, firma);
    let ruta = crate::babel_dir().join("bloqueo.tmp");
    let _ = fs::write(&ruta, contenido);
}

// detector de pdf y docx
pub fn procesar_archivo_inteligente(
    ruta: &str,
    dict: &HashMap<String, String>,
    subclave_hex: &str,
    id_usuario: &str,
    origen: &str,
    destino: &str,
) {
    let ruta_limpia = ruta.trim();

    if ruta_limpia.ends_with(".docx") {
        log::warn!("Detectado documento Word. Iniciando Preservador...");
        if let Err(e) =
            clonar_y_traducir(ruta_limpia, dict, subclave_hex, id_usuario, origen, destino)
        {
            log::warn!("Error en Word: {}", e);
        }
    } else if ruta_limpia.ends_with(".pdf") {
        log::warn!("Detectado archivo PDF. Iniciando Extractor...");
        if let Err(e) = procesar_pdf(ruta_limpia, dict, subclave_hex, id_usuario, origen, destino) {
            log::warn!("Error en PDF: {}", e);
        }
    } else if ruta_limpia.ends_with(".txt") {
        if let Ok(texto) = fs::read_to_string(ruta_limpia) {
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
            let mut traducido_final = String::new();
            for parrafo in &parrafos {
                if parrafo.trim().is_empty() {
                    traducido_final.push('\n');
                    continue;
                }
                let traducido = match traducir_con_nllb(parrafo, origen, destino) {
                    Ok(t) => t,
                    Err(_) => {
                        let (t, _) =
                            traducir_inteligente(parrafo, dict, subclave_hex, origen, destino);
                        t
                    }
                };
                traducido_final.push_str(&traducido);
                traducido_final.push('\n');
            }
            // Guardar traducción cifrada
            if let Ok(cifrado) = seguridad::blindar_documento(&traducido_final, subclave_hex) {
                let salida = archivos_dir.join(format!("{}_{}.babel", id_usuario, nombre));
                let _ = fs::write(&salida, cifrado);
            }
        } // cierra if let Ok(texto)
    } // cierra else if .txt
}
// =============================================================
// 5. MOTOR Y UTILIDADES
// =============================================================

pub fn motor_atomico(
    texto: &str,
    dict: &HashMap<String, String>,
    subclave_hex: &str,
) -> (String, usize) {
    let mut resultado = texto.to_string();
    let mut palabras_desconocidas: Vec<String> = Vec::new();

    for palabra in texto.split_whitespace() {
        let (raiz, _signo) = separar_signo(palabra);
        let clave = raiz.to_lowercase();
        if let Some(traduccion) = dict.get(&clave) {
            resultado = resultado.replace(raiz, traduccion);
        } else if clave.chars().all(|c| c.is_alphabetic()) && clave.len() > 3 {
            // Palabra alfabética de más de 3 letras sin traducción conocida
            if !palabras_desconocidas.contains(&clave) {
                palabras_desconocidas.push(clave);
            }
        }
    }

    // Registramos todas las palabras desconocidas en pendientes.babel sin interrumpir
    for palabra in &palabras_desconocidas {
        registrar_pendiente(palabra, subclave_hex);
    }
    (resultado, palabras_desconocidas.len())
}
fn traducir_xml_directo(
    xml: &str,
    dict: &HashMap<String, String>,
    subclave_hex: &str,
    origen: &str,
    destino: &str,
) -> String {
    let mut resultado = String::with_capacity(xml.len() * 2);
    let mut resto = xml;
    while !resto.is_empty() {
        if let Some(pos) = resto.find("<w:t") {
            let after = &resto[pos + 4..];
            if !after.starts_with('>') && !after.starts_with(' ') {
                resultado.push_str(&resto[..pos + 4]);
                resto = &resto[pos + 4..];
                continue;
            }
            resultado.push_str(&resto[..pos]);
            resto = &resto[pos..];
            if let Some(j) = resto.find('>') {
                resultado.push_str(&resto[..j + 1]);
                resto = &resto[j + 1..];
                if let Some(k) = resto.find("</w:t>") {
                    let texto = &resto[..k];
                    if texto.trim().is_empty() {
                        resultado.push_str(texto);
                    } else {
                        let traducido = match traducir_con_nllb(texto, origen, destino) {
                            Ok(t) => t,
                            Err(_) => {
                                let (t, _) = motor_atomico(texto, dict, subclave_hex);
                                t
                            }
                        };
                        let traducido_escaped = traducido
                            .replace('&', "&amp;")
                            .replace('<', "&lt;")
                            .replace('>', "&gt;");
                        if !resultado.ends_with(' ') && !traducido_escaped.starts_with(' ') {
                            resultado.push(' ');
                        }
                        resultado.push_str(&traducido_escaped);
                    }
                    resto = &resto[k..];
                }
            }
        } else {
            resultado.push_str(resto);
            break;
        }
    }
    resultado
}

pub fn clonar_y_traducir(
    ruta: &str,
    dict: &HashMap<String, String>,
    subclave_hex: &str,
    id_usuario: &str,
    origen: &str,
    destino: &str,
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

    // Traducir document.xml
    let xml_traducido = traducir_xml_directo(&xml_doc, dict, subclave_hex, origen, destino);

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
            } else if name.starts_with("word/header") || name.starts_with("word/footer") {
                // Encabezados y pies — también traducir
                let mut xml_hf = String::new();
                file.read_to_string(&mut xml_hf)?;
                let xml_hf_trad =
                    traducir_xml_directo(&xml_hf, dict, subclave_hex, origen, destino);
                zip_out.start_file(&name, opts_deflate)?;
                zip_out.write_all(xml_hf_trad.as_bytes())?;
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
    let tmp_dir = crate::babel_dir().join("tmp");
    let _ = std::fs::create_dir_all(&tmp_dir);
    let tmp_base = tmp_dir.join(format!("ocr_{}", pagina));
    let tmp_img = format!("{}.png", tmp_base.to_string_lossy());

    let ok = std::process::Command::new("/opt/homebrew/bin/pdftoppm")
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

fn borrar_seguro_local(ruta: &str) {
    if let Ok(meta) = fs::metadata(ruta) {
        let tam = meta.len() as usize;
        if tam > 0 {
            let _ = fs::write(ruta, vec![0u8; tam]);
            let _ = fs::write(ruta, vec![0xFFu8; tam]);
            let _ = fs::write(ruta, vec![0xAAu8; tam]);
        }
    }
    let _ = fs::remove_file(ruta);
}

pub fn procesar_pdf(
    ruta: &str,
    dict: &HashMap<String, String>,
    subclave_hex: &str,
    id_usuario: &str,
    origen: &str,
    destino: &str,
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

    // PASO 1: PDF → DOCX con pdf2docx
    let ruta_docx_tmp = tmp_dir.join(format!("{}_tmp.docx", nombre));
    let ok = std::process::Command::new("python3")
        .args([
            "-c",
            "import sys; from pdf2docx import Converter; cv=Converter(sys.argv[1]); cv.convert(sys.argv[2]); cv.close()",
            ruta,
            ruta_docx_tmp.to_str().unwrap_or(""),
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !ok {
        // Fallback: texto plano si falla la conversión
        let mut texto = Zeroizing::new(
            std::process::Command::new("/opt/homebrew/bin/pdftotext")
                .args([ruta, "-"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default(),
        );
        if texto.trim().is_empty() {
            *texto = ocr_pagina_pdf(ruta, 1);
        }
        let (traducido, _) = traducir_inteligente(&texto, dict, subclave_hex, origen, destino);
        let cifrado = seguridad::blindar_documento(&traducido, subclave_hex)?;
        fs::write(
            archivos_dir.join(format!("{}_{}.babel", id_usuario, nombre)),
            cifrado,
        )?;
        return Ok(());
    }

    // PASO 2: guardar original (DOCX original cifrado)
    if let Ok(bytes_orig) = fs::read(&ruta_docx_tmp) {
        let b64 = comprimir_b64(&bytes_orig);
        if let Ok(cifrado_orig) = seguridad::blindar_documento(&b64, subclave_hex) {
            let _ = fs::write(
                archivos_dir.join(format!("{}_{}__orig.babel", id_usuario, nombre)),
                cifrado_orig,
            );
        }
    }

    // PASO 3: traducir DOCX con el pipeline ZIP
    clonar_y_traducir(
        &ruta_docx_tmp.to_string_lossy(),
        dict,
        subclave_hex,
        id_usuario,
        origen,
        destino,
    )?;
    // Renombrar _tmp → nombre final
    let salida_tmp = archivos_dir.join(format!("{}_{}_tmp.babel", id_usuario, nombre));
    let salida_final = archivos_dir.join(format!("{}_{}.babel", id_usuario, nombre));
    if salida_tmp.exists() {
        let _ = fs::rename(&salida_tmp, &salida_final);
    }
    let orig_tmp = archivos_dir.join(format!("{}_{}_tmp__orig.babel", id_usuario, nombre));
    let orig_final = archivos_dir.join(format!("{}_{}__orig.babel", id_usuario, nombre));
    if orig_tmp.exists() {
        let _ = fs::rename(&orig_tmp, &orig_final);
    }

    // PASO 4: convertir DOCX traducido → PDF con LibreOffice
    let ruta_docx_trad = archivos_dir.join(format!("{}_{}.babel", id_usuario, nombre));
    // El DOCX traducido lo guarda clonar_y_traducir como babel — necesitamos descifrarlo
    if let Ok(bytes_cifrados) = fs::read(&ruta_docx_trad) {
        if let Ok(b64) = seguridad::descifrar_documento(bytes_cifrados, subclave_hex) {
            if let Ok(docx_bytes) = descomprimir_b64(&b64) {
                let docx_para_pdf = tmp_dir.join(format!("{}_trad.docx", nombre));
                fs::write(&docx_para_pdf, &docx_bytes)?;
                std::process::Command::new("/opt/homebrew/bin/soffice")
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
                        let b64_pdf = base64::engine::general_purpose::STANDARD.encode(&pdf_bytes);
                        let cifrado_pdf = seguridad::blindar_documento(&b64_pdf, subclave_hex)?;
                        fs::write(&ruta_docx_trad, cifrado_pdf)?;
                    }
                    borrar_seguro_local(&pdf_out.to_string_lossy());
                }
                borrar_seguro_local(&docx_para_pdf.to_string_lossy());
            }
        }
    }

    // Limpiar temporal
    borrar_seguro_local(&ruta_docx_tmp.to_string_lossy());
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
    let fecha = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let mensaje = format!("[{}] {}", fecha, evento);

    match seguridad::blindar_documento(&mensaje, subclave_hex) {
        Ok(cifrado) => {
            // Ruta absoluta para la auditoría - siempre en ~/Babel/
            let ruta_auditoria = crate::babel_dir().join("auditoria.babel");
            let ruta_backup = crate::babel_dir().join("auditoria_backup.babel");

            let escribir = |ruta: &PathBuf| -> bool {
                if let Ok(mut archivo) = fs::OpenOptions::new().append(true).create(true).open(ruta)
                {
                    let _ = archivo.write_all(&(cifrado.len() as u32).to_le_bytes());
                    let _ = archivo.write_all(&cifrado);
                    true
                } else {
                    false
                }
            };

            if !escribir(&ruta_auditoria) {
                log::warn!("[!] Auditoría principal inaccesible...");
                if !escribir(&ruta_backup) {
                    log::error!("[!] Error crítico: no se pudo registrar el evento.");
                }
            }
        }
        Err(e) => log::error!(" [!] Error de seguridad en auditoría: {}", e),
    }
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

    // 2. Fallback: intentamos importar desde el .json con categorías
    if let Ok(contenido) = fs::read_to_string(&ruta_json) {
        match serde_json::from_str::<HashMap<String, HashMap<String, String>>>(&contenido) {
            Ok(dict) => {
                log::info!("[OK] Diccionario importado desde JSON. Cifrando...");
                let plano = aplanar_categorias(dict, categoria);
                guardar_diccionario(nombre, &plano, subclave_hex);
                return plano;
            }
            Err(e) => log::error!("[!] JSON de diccionario invalido: {}", e),
        }
    }

    log::info!("[INIT] Diccionario '{}' nuevo - empezando vacio.", nombre);
    HashMap::new()
}

pub fn guardar_diccionario(nombre: &str, dict: &HashMap<String, String>, subclave_hex: &str) {
    init_dir_dict();
    let ruta_cifrada = ruta_dict(&format!("{}.babel", nombre));
    let ruta_json = ruta_dict(&format!("{}.json", nombre));

    if let Ok(json) = serde_json::to_string_pretty(dict) {
        // Guardamos versión cifrada (.babel)
        match seguridad::blindar_documento(&json, subclave_hex) {
            Ok(cifrado) => {
                if let Err(e) = fs::write(&ruta_cifrada, cifrado) {
                    log::error!("[!] Error guardando diccionario cifrado: {}", e);
                }
            }
            Err(e) => log::warn!("[!] Error cifrando diccionario: {}", e),
        }
        // Sincronizamos versión legible (.json)
        sincronizar_json_legible(&ruta_json, dict);
    }
}

/// Escribe el diccionario como JSON legible y ordenado alfabéticamente.
fn sincronizar_json_legible(ruta: &std::path::Path, dict: &HashMap<String, String>) {
    let mut entradas: Vec<(&String, &String)> = dict.iter().collect();
    entradas.sort_by_key(|(k, _)| k.as_str());

    let mapa_ordenado: serde_json::Map<String, serde_json::Value> = entradas
        .into_iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
        .collect();

    if let Ok(json) = serde_json::to_string_pretty(&mapa_ordenado) {
        let _ = fs::write(ruta, json);
    }
}

/// Registra una palabra desconocida en pendientes.babel (cifrado) para traducción futura.
pub fn registrar_pendiente(palabra: &str, subclave_hex: &str) {
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
pub fn guardar_config_email(creds: &CredencialesEmail, subclave_hex: &str) {
    if let Ok(json) = serde_json::to_string(&creds) {
        if let Ok(cifrado) = seguridad::blindar_documento(&json, subclave_hex) {
            let _ = fs::write(crate::babel_dir().join("config.babel"), cifrado);
        }
    }
}

/// Carga y descifra las credenciales de email desde ~/Babel/config.babel
pub fn cargar_config_email(subclave_hex: &str) -> Option<CredencialesEmail> {
    let contenido = fs::read(crate::babel_dir().join("config.babel")).ok()?;
    let descifrado = seguridad::descifrar_documento(contenido, subclave_hex).ok()?;
    serde_json::from_str(&descifrado).ok()
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
}

/// Conecta por IMAP y devuelve los últimos 20 emails de la bandeja.
/// Usa ENVELOPE para no descargar el cuerpo - solo metadatos.
pub fn obtener_emails(
    imap_dominio: &str,
    usuario: &str,
    password: &str,
) -> Result<Vec<EmailResumen>, Box<dyn std::error::Error>> {
    let cliente = imap::ClientBuilder::new(imap_dominio, 993)
        .connect()
        .map_err(|e| format!("Error conexión IMAP: {}", e))?;

    let mut sesion = cliente.login(usuario, password).map_err(|e| e.0)?;

    sesion.select("INBOX")?;

    // Buscamos todos los emails y cogemos los últimos 20
    let todos: Vec<u32> = sesion.search("ALL")?.into_iter().collect();

    let mut ids: Vec<u32> = todos;
    ids.sort_unstable();
    ids.reverse();
    ids.truncate(20);
    if ids.is_empty() {
        sesion.logout()?;
        return Ok(vec![]);
    }

    // Construimos el rango de IDs para el fetch
    let ids_str = ids
        .iter()
        .map(|id| id.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let fetch = sesion.fetch(&ids_str, "(ENVELOPE FLAGS)")?;

    let mut emails: Vec<EmailResumen> = Vec::new();

    for msg in fetch.iter() {
        let id = msg.message;

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

        let tiene_adjunto = false;

        emails.push(EmailResumen {
            id,
            remitente,
            asunto,
            fecha,
            tiene_adjunto,
        });
    }

    sesion.logout()?;
    Ok(emails)
}

// ============================================================
// EMAIL - OBTENER EMAIL COMPLETO POR ID
// ============================================================

pub struct EmailCompletoRust {
    pub id: u32,
    pub remitente: String,
    pub asunto: String,
    pub fecha: String,
    pub cuerpo: String,
    pub adjuntos: Vec<String>,
}

/// Descarga el cuerpo completo de un email por su ID IMAP.
/// Parsea remitente, asunto, fecha, cuerpo de texto y nombres de adjuntos.
pub fn obtener_email_completo(
    imap_dominio: &str,
    usuario: &str,
    password: &str,
    id: u32,
) -> Result<EmailCompletoRust, Box<dyn std::error::Error>> {
    let cliente = imap::ClientBuilder::new(imap_dominio, 993)
        .connect()
        .map_err(|e| format!("Error conexión IMAP: {}", e))?;

    let mut sesion = cliente.login(usuario, password).map_err(|e| e.0)?;

    sesion.select("INBOX")?;

    let fetch = sesion.fetch(id.to_string(), "(RFC822)")?;

    let msg = fetch.iter().next().ok_or("Email no encontrado")?;

    let cuerpo_raw = msg.body().unwrap_or(&[]);
    let email_parseado = mailparse::parse_mail(cuerpo_raw)?;

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

    // Cuerpo de texto
    let mut cuerpo = String::new();
    let mut adjuntos: Vec<String> = Vec::new();

    if email_parseado.subparts.is_empty() {
        cuerpo = email_parseado.get_body().unwrap_or_default();
    } else {
        for parte in &email_parseado.subparts {
            let content_type = parte
                .headers
                .get_first_header("Content-Type")
                .map(|h| h.get_value().to_lowercase())
                .unwrap_or_default();

            let content_disposition = parte
                .headers
                .get_first_header("Content-Disposition")
                .map(|h| h.get_value().to_lowercase())
                .unwrap_or_default();

            if content_disposition.contains("attachment") {
                let nombre = content_disposition
                    .split(';')
                    .find(|p| p.trim().starts_with("filename"))
                    .and_then(|p| p.split('=').nth(1))
                    .map(|n| n.trim().trim_matches('"').to_string())
                    .unwrap_or_else(|| "adjunto".to_string());
                adjuntos.push(nombre);
            } else if content_type.contains("text/plain") && cuerpo.is_empty() {
                cuerpo = parte.get_body().unwrap_or_default();
            } else if content_type.contains("text/html") && cuerpo.is_empty() {
                cuerpo = parte.get_body().unwrap_or_default();
            }
        }
    }

    sesion.logout()?;

    Ok(EmailCompletoRust {
        id,
        remitente,
        asunto,
        fecha,
        cuerpo,
        adjuntos,
    })
}

// ============================================================
// NLLB - TRADUCCIÓN NEURONAL VÍA SERVIDOR PYTHON
// ============================================================

/// Llama al servidor Python NLLB en localhost:5000.
/// Incluye token de seguridad - Flask rechaza sin él.
pub fn traducir_con_nllb(texto: &str, origen: &str, destino: &str) -> Result<String, String> {
    let url = "http://127.0.0.1:5002/traducir";
    let token = std::env::var("BABEL_NLLB_TOKEN")
        .map_err(|_| "BABEL_NLLB_TOKEN no configurado".to_string())?;
    let body = serde_json::json!({
        "texto": texto,
        "origen": origen,
        "destino": destino
    });

    let respuesta = ureq::post(url)
        .set("Content-Type", "application/json")
        .set("X-Babel-Token", &token)
        .send_json(&body)
        .map_err(|e| format!("Servidor NLLB no disponible: {}", e))?;

    let json: serde_json::Value = respuesta
        .into_json()
        .map_err(|e| format!("Error leyendo respuesta NLLB: {}", e))?;

    json["traduccion"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "Respuesta NLLB inválida".to_string())
}

/// Traduce usando NLLB. Si no está disponible, usa el diccionario.
pub fn traducir_inteligente(
    texto: &str,
    dict: &std::collections::HashMap<String, String>,
    subclave_hex: &str,
    origen: &str,
    destino: &str,
) -> (String, usize) {
    match traducir_con_nllb(texto, origen, destino) {
        Ok(traduccion) => (traduccion, 0),
        Err(_) => motor_atomico(texto, dict, subclave_hex),
    }
}
