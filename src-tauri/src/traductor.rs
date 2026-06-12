#![allow(dead_code, unused_imports, unused_variables, unused_mut)]

use base64;
use tesseract::Tesseract;
use base64::Engine;
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
use docx_rs;
use hex;
use imap;
use lopdf;
use mailparse;
use mailparse::MailHeaderMap;
use pdf_extract;
use rand::RngCore;
use rpassword;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use sha2;


use crate::seguridad;
use crate::seguridad::{SesionBunker, UsuarioBabel};
use lettre::{
    message::header::ContentType, message::Attachment,
    transport::smtp::authentication::Credentials, Message, SmtpTransport, Transport,
};
use crate::seguridad::escribir_bloqueo;

// ============================================================
// DRAG & DROP - DOS MODOS
// ============================================================
//
// Modo 1 - Argumento directo:
//   El usuario arrastra un archivo encima del .exe en Windows/macOS.
//   El SO pasa la ruta como argumento: babel.exe "C:\contrato.pdf"
//   Se llama desde main() antes de arrancar el login.
//
// Modo 2 - Carpeta de entrada (watch):
//   El usuario arrastra archivos a la carpeta "entrada_babel/".
//   Babel la vigila en bucle y procesa lo que aparezca.
//   Útil cuando Babel ya está corriendo en segundo plano.

/// Carpeta que Babel vigila para el modo watch.
/// Rutas absolutas - funcionan igual en dev y en el .app compilado.
fn carpeta_entrada() -> PathBuf {
    crate::babel_dir().join("tmp")
}
fn carpeta_salida() -> PathBuf {
    crate::babel_dir().join("archivos")
}

/// Extensiones que Babel acepta. Todo lo demás se ignora.
const EXTENSIONES_VALIDAS: &[&str] = &["pdf", "docx"];

// ============================================================
// MODO 1 - Procesar archivo pasado como argumento (drag al .exe)
// ============================================================

/// Comprueba si el usuario arrastró un archivo al ejecutable.
/// Devuelve la ruta si el primer argumento es un archivo válido.
pub fn detectar_archivo_arrastrado() -> Option<PathBuf> {
    // std::env::args() devuelve los argumentos de la línea de comandos.
    // El índice 0 es siempre el nombre del ejecutable - lo saltamos con skip(1).
    let ruta = std::env::args().nth(1)?;
    let path = PathBuf::from(&ruta);

    // Verificamos que el archivo existe y tiene extensión válida.
    if !path.is_file() {
        return None;
    }

    let extension = path.extension()?.to_str()?.to_lowercase();
    if EXTENSIONES_VALIDAS.contains(&extension.as_str()) {
        Some(path)
    } else {
        log::warn!(" [!] Archivo ignorado - extensión no soportada: .{}",
            extension
        );
        None
    }
}
/// Procesa un único archivo arrastrado al ejecutable.
/// Se llama desde main() cuando detectar_archivo_arrastrado() devuelve Some.
pub fn procesar_archivo_arrastrado(
    ruta: &Path,
    dict: &HashMap<String, String>,
    subclave_hex: &str,
    id_usuario: &str,
) {
    log::warn!("\n [BABEL] Archivo recibido.");

    // Copiamos el archivo a la carpeta de entrada para que el flujo
    // sea idéntico al del modo watch - un solo punto de procesado.
    let _ = fs::create_dir_all(carpeta_entrada());
    let nombre = ruta
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("archivo"));
    let destino = carpeta_entrada().join(nombre);

    if let Err(e) = fs::copy(ruta, &destino) {
        log::warn!("[!] No se pudo copiar a entrada_babel/: {}", e);
        return;
    }

    // Una vez en la carpeta de entrada, lo procesa el motor estándar.
    procesar_archivo_inteligente(
        destino.to_str().unwrap_or(""),
        dict,
        subclave_hex,
        id_usuario,
        "spa_Latn",
        "eng_Latn",
    );
}

// ============================================================
// MODO 2 - Watch: Babel vigila la carpeta de entrada en bucle
// ============================================================

/// Lanza el modo watch: vigila "entrada_babel/" cada N segundos.
/// Cuando aparece un archivo nuevo, lo procesa y lo mueve a "salida_babel/".
/// Pensado para correr en segundo plano mientras el usuario trabaja.
pub fn iniciar_watch(dict: &HashMap<String, String>, subclave_hex: &str, intervalo_segundos: u64) {
    // Creamos las carpetas si no existen todavía.
    if let Err(e) = fs::create_dir_all(carpeta_entrada()) {
        log::warn!("[!] No se pudo crear entrada_babel/: {}", e);
        return;
    }
    if let Err(e) = fs::create_dir_all(carpeta_salida()) {
        log::warn!("[!] No se pudo crear salida_babel/: {}", e);
        return;
    }

    log::warn!(" [WATCH] Vigilando {:?} arrastra aquí tus archivos.",
        carpeta_entrada()
    );
    log::warn!(" [WATCH] Intervalo de comprobación: {}s. Ctrl+C para salir.",
        intervalo_segundos
    );

    // Guardamos los archivos ya procesados para no repetirlos.
    // La clave es la ruta, el valor es el timestamp de modificación.
    let mut procesados: HashMap<PathBuf, SystemTime> = HashMap::new();

    loop {
        // Leemos el contenido actual de la carpeta de entrada.
        let entradas = match fs::read_dir(carpeta_entrada()) {
            Ok(e) => e,
            Err(e) => {
                log::warn!("[!] Error leyendo entrada_babel/: {}", e);
                std::thread::sleep(Duration::from_secs(intervalo_segundos));
                continue;
            }
        };

        for entrada in entradas.flatten() {
            let path = entrada.path();

            // Solo procesamos archivos, no subdirectorios.
            if !path.is_file() {
                continue;
            }

            // Filtramos por extensión válida.
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            if !EXTENSIONES_VALIDAS.contains(&ext.as_str()) {
                continue;
            }

            // Obtenemos el timestamp de última modificación del archivo.
            // Si no podemos leerlo, lo saltamos.
            let modificado = match entrada.metadata().and_then(|m| m.modified()) {
                Ok(t) => t,
                Err(_) => continue,
            };

            // Si ya procesamos este archivo con el mismo timestamp, lo saltamos.
            if procesados.get(&path) == Some(&modificado) {
                continue;
            }

            // Archivo nuevo o modificado - lo procesamos.
            log::info!("[WATCH] Archivo detectado.");
            procesar_archivo_inteligente(
                path.to_str().unwrap_or(""),
                dict,
                subclave_hex,
                "sistema",
                "spa_Latn",
                "eng_Latn",
            );

            // Movemos el resultado a salida_babel/ y borramos el original.
            mover_a_salida(&path);

            // Registramos como procesado.
            procesados.insert(path, modificado);
        }

        // Esperamos antes de la siguiente comprobación.
        std::thread::sleep(Duration::from_secs(intervalo_segundos));
    }
}

/// Mueve el archivo procesado de entrada_babel/ a salida_babel/.
/// Si no puede moverlo, lo deja donde está y avisa.
fn mover_a_salida(ruta: &Path) {
    let nombre = match ruta.file_name() {
        Some(n) => n,
        None => return,
    };

    // Construimos la ruta de destino con prefijo "procesado_" para que sea
    // fácil distinguir qué archivos ya han pasado por Babel.
    let nombre_salida = format!("procesado_{}", nombre.to_string_lossy());
    let destino = carpeta_salida().join(&nombre_salida);

    // Intentamos mover. Si falla (distintos volúmenes), copiamos y borramos.
    if fs::rename(ruta, &destino).is_err() {
        if let Ok(_) = fs::copy(ruta, &destino) {
            let _ = fs::remove_file(ruta);
        } else {
            log::error!("[!] No se pudo mover {} a salida_babel/", ruta.display());
        }
    } else {
        log::info!("[OK] Movido a salida_babel/{}", nombre_salida);
    }
}
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

pub struct EmailEntrante {
    pub cuerpo: String,
}

impl EmailEntrante {
    pub fn nuevo(remitente: &str, asunto: &str, cuerpo: &str) -> Self {
        Self {
            cuerpo: format!(
                "De: {} | Asunto: {} | Contenido: {}",
                remitente, asunto, cuerpo
            ),
        }
    }
}

// ============================================================
// GESTIÓN DE SALT MAESTRA
// ============================================================

/// Carga la sal maestra desde ~/Babel/master.salt.
/// Si no existe, la genera y la guarda junto con un backup.
/// La sal NO es secreta: solo debe ser única e inmutable.
/// Si se pierde sin backup, todos los datos cifrados son irrecuperables.
pub fn cargar_o_crear_salt() -> [u8; 32] {
    // Rutas absolutas - funcionan igual en dev y en el .app compilado
    let dir = crate::babel_dir();
    let ruta_salt = dir.join("master.salt");
    let ruta_bck = dir.join("master.salt.bck");

    let salt_principal = leer_salt_abs(&ruta_salt);
    let salt_backup = leer_salt_abs(&ruta_bck);

    match (salt_principal, salt_backup) {
        (Some(s), _) => {
            // Principal ok - sincronizamos el backup por si acaso
            let _ = fs::write(&ruta_bck, s);
            return s;
        }
        (None, Some(s)) => {
            // Principal perdida - recuperamos desde backup
            log::warn!("[Babel] master.salt no encontrada - recuperando desde backup...");
            if let Err(e) = fs::write(&ruta_salt, s) {
               log::error!("[Babel] No se pudo restaurar master.salt: {}", e);
            } else {
                log::info!("[Babel] master.salt restaurada desde backup.");
            }
            return s;
        }
        (None, None) => {
            // Primera ejecución o pérdida total
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
    }
    let _ = fs::write(&ruta_bck, nueva_salt);
   log::info!("[Babel] master.salt generada correctamente.");
    nueva_salt
}

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
    let firma = format!("{:x}", sha2::Sha256::digest(
        format!("{}:{}", ts, hex::encode(salt)).as_bytes()
    ));
    let contenido = format!("{}:{}", ts, firma);
    let ruta = crate::babel_dir().join("bloqueo.tmp");
    let _ = fs::write(&ruta, contenido);
}

/// Comprueba bloqueo verificando la firma. Sin firma válida, ignora el archivo.
pub fn comprobar_bloqueo() {
    let ruta_bloqueo = crate::babel_dir().join("bloqueo.tmp");
    if let Ok(contenido) = fs::read_to_string(&ruta_bloqueo) {
        let partes: Vec<&str> = contenido.trim().splitn(2, ':').collect();
        if partes.len() != 2 { return; }
        let ts_str = partes[0];
        let firma_guardada = partes[1];
        let salt = cargar_o_crear_salt();
        use sha2::Digest;
        let firma_esperada = format!("{:x}", sha2::Sha256::digest(
            format!("{}:{}", ts_str, hex::encode(salt)).as_bytes()
        ));
        if firma_guardada != firma_esperada {
            // Archivo manipulado o recreado sin el salt — ignorar
            let _ = fs::remove_file(&ruta_bloqueo);
            return;
        }
        if let Ok(timestamp) = ts_str.parse::<i64>() {
            let ahora = chrono::Local::now().timestamp();
            let restante = (timestamp + 600) - ahora;
            if restante > 0 {
                log::warn!("Sistema bloqueado. Espera {} segundos mas.", restante);
                std::thread::sleep(std::time::Duration::from_secs(restante as u64));
                std::process::exit(1);
            } else {
                let _ = fs::remove_file(&ruta_bloqueo);
            }
        }
    }
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
/// Extrae texto de un PDF desde bytes en memoria — para el visor de Babel
pub fn extraer_texto_pdf_bytes(bytes: &[u8]) -> Result<String, String> {
    let tmp = std::env::temp_dir()
        .join(format!("babel_prev_{}.pdf", std::process::id()));
    std::fs::write(&tmp, bytes)
        .map_err(|e| format!("Error temp: {}", e))?;
    let texto = std::process::Command::new("/opt/homebrew/bin/pdftotext")
        .args([tmp.to_str().unwrap_or(""), "-"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    let _ = std::fs::remove_file(&tmp);
    if texto.trim().is_empty() {
        return Err("PDF sin texto extraíble (puede ser escaneado). Usa EXPORTAR.".into());
    }
    Ok(texto)
}
// =============================================================
// 5. MOTOR Y UTILIDADES
// =============================================================

pub fn ejecutar_sistema(sesion: SesionBunker, _usuario: UsuarioBabel) {
    let salt_maestra = cargar_o_crear_salt();

    // derivar_subclave devuelve Result - si falla aquí es un error crítico,
    // no podemos continuar sin la subclave de traducción.
    let sub_trad_bytes = match seguridad::derivar_subclave(
        &sesion.clave_maestra_derivada,
        "traduccion-v1-salt-marbella",
        &salt_maestra,
    ) {
        Ok(s) => s,
        Err(e) => {
            log::warn!(
                " [CRÍTICO] No se pudo derivar subclave de traducción: {}",
                e
            );
            return;
        }
    };
    let sub_trad_hex = Zeroizing::new(hex::encode(sub_trad_bytes.as_ref()));

    // Diccionario cargado y descifrado con la subclave del búnker
    let mut babel_dict = cargar_diccionario("es_en", &sub_trad_hex, "todos");

    let creds_email = match cargar_config_email(&sub_trad_hex) {
        Some(c) => c,
        None => {
            log::warn!("[!] No hay config de email. Introduce datos para blindar:");
            let u = rpassword::prompt_password("Usuario Email: ").unwrap_or_else(|_| String::new());
            let p = rpassword::prompt_password("Password App: ").unwrap_or_else(|_| String::new());
            let d = {
                let mut buf = String::new();
                print!("Dominio IMAP (ej: imap.gmail.com): ");
                io::stdout().flush().ok();
                io::stdin().read_line(&mut buf).ok();
                buf.trim().to_string()
            };
            let r = {
                let mut buf = String::new();
                print!("Remitentes autorizados (separados por coma): ");
                io::stdout().flush().ok();
                io::stdin().read_line(&mut buf).ok();
                buf.trim()
                    .split(',')
                    .map(|s| s.trim().to_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect()
            };
            let nuevas_creds = CredencialesEmail {
                usuario: u,
                password: p,
                imap_dominio: d,
                remitentes_autorizados: r,
                smtp_servidor: String::new(),
            };
            guardar_config_email(&nuevas_creds, &sub_trad_hex);
            nuevas_creds
        }
    };

    if let Err(e) = activar_centinela(&creds_email, &babel_dict, &sub_trad_hex) {
        log::warn!("[!] Error de red: {}", e);
    }

    loop {
        print!("> ");
        io::stdout().flush().ok();
        let mut entrada = String::new();
        io::stdin().read_line(&mut entrada).ok();
        let cmd = entrada.trim();

        if cmd == "salir" {
            log::warn!("[!] Cerrando sesión segura...");
            break;
        }

        if cmd == "p2p" {
            // Abre el menú P2P - comunicación directa con otros Babel en la red
            crate::babel_p2p::menu_p2p(&sub_trad_hex);
            continue;
        }

        if cmd == "watch" {
            // Activa la carpeta de entrada - arrastra archivos y se procesan solos
            iniciar_watch(&babel_dict, &sub_trad_hex, 3);
            continue;
        }

        if cmd == "ayuda" {
            log::info!("  salir - cierra la sesion");
            log::info!("  procesar - procesa un archivo manualmente");
            log::info!("  watch - vigila entrada_babel/ y procesa automatico");
            log::info!("  p2p      - envía o recibe archivos con otro Babel en red local");
            log::info!("  [palabra] - traduce o aprende una palabra");
            continue;
        }

        if cmd == "procesar" {
            log::warn!("Introduce el archivo:");
            let mut r = String::new();
            io::stdin().read_line(&mut r).ok();
            procesar_archivo_inteligente(
                r.trim(),
                &babel_dict,
                &sub_trad_hex,
                "sistema",
                "spa_Latn",
                "eng_Latn",
            );
            if let Err(e) = activar_centinela(&creds_email, &babel_dict, &sub_trad_hex) {
                log::warn!("[!] Error del centinela tras procesar: {}", e);
            }
            continue;
        }

        if !cmd.is_empty() {
            if let Some(trad) = babel_dict.get(cmd) {
                log::warn!("Traducción: {}", trad);
            } else {
                log::warn!("Palabra desconocida. ¿Traducción para '{}'?", cmd);
                let mut nueva_t = String::new();
                io::stdin().read_line(&mut nueva_t).ok();
                let nueva_t = nueva_t.trim();

                if !nueva_t.is_empty() {
                    babel_dict.insert(cmd.to_string(), nueva_t.to_string());
                    guardar_diccionario("es_en", &babel_dict, &sub_trad_hex);
                    registrar_traduccion_nueva(cmd, nueva_t, &sub_trad_hex);
                    log::warn!("[!] Aprendido: {} -> {}", cmd, nueva_t);
                } else {
                    // Palabra vista pero sin traducción → va a pendientes.babel
                    registrar_pendiente(cmd, &sub_trad_hex);
                    log::warn!("[!] Anotado en pendientes para traducción futura.");
                }
            }
        }
    }
}

// Límites del centinela - protección contra bombardeo de emails (DoS)
const MAX_EMAILS_POR_CICLO: usize = 20; // máximo de emails procesados por llamada
const MAX_ADJUNTOS_POR_EMAIL: usize = 5; // máximo de adjuntos por email
const MAX_BYTES_ADJUNTO: usize = 25 * 1024 * 1024; // 25 MB por adjunto

pub fn activar_centinela(
    creds: &CredencialesEmail,
    dict: &HashMap<String, String>,
    subclave_hex: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    log::warn!("[SEGURIDAD] Iniciando túnel TLS 1.3...");

    let dominio = &creds.imap_dominio;

    // native-tls - más simple y compatible con macOS/Windows
    // imap alpha - connect() gestiona TLS internamente
    let cliente = imap::ClientBuilder::new(dominio.as_str(), 993)
        .connect()
        .map_err(|e| format!("Error conexión IMAP: {}", e))?;
    let mut sesion = cliente
        .login(&creds.usuario, &creds.password)
        .map_err(|e| e.0)?;
    sesion.select("INBOX")?;

    log::warn!("[CENTINELA] Vigilando bandeja de entrada...");
    let mensajes_pendientes = sesion.search("UNSEEN")?;

    let total = mensajes_pendientes.len();
    if total > MAX_EMAILS_POR_CICLO {
       log::warn!("[!] Centinela: {} emails pendientes - procesando solo los primeros {} (rate-limit).", total, MAX_EMAILS_POR_CICLO);
        registrar_evento(
            &format!(
                "Rate-limit activado: {} emails en cola, procesados {}",
                total, MAX_EMAILS_POR_CICLO
            ),
            subclave_hex,
        );
    }

    for id_msj in mensajes_pendientes.iter().take(MAX_EMAILS_POR_CICLO) {
        let fetch = sesion.fetch(id_msj.to_string(), "(RFC822)")?;

        if let Some(contenido) = fetch.iter().next() {
            let cuerpo_raw: &[u8] = contenido.body().map(|b| b as &[u8]).unwrap_or(&[]);

            let email_parseado = mailparse::parse_mail(cuerpo_raw)?;

            let remitente_raw = email_parseado
                .headers
                .get_first_header("From")
                .map(|h| h.get_value().to_lowercase())
                .unwrap_or_default();

            let autorizado = creds
                .remitentes_autorizados
                .iter()
                .any(|r| remitente_raw.contains(r.as_str()));

            if !autorizado {
                log::warn!("[CENTINELA] ID {} rechazado: remitente '{}' no autorizado.",
                    id_msj, remitente_raw
                );
                registrar_evento(
                    &format!("Correo rechazado ({}): ID {}", remitente_raw, id_msj),
                    subclave_hex,
                );
                continue;
            }

            log::warn!("[CENTINELA] ID {} autorizado ({}). Buscando adjuntos...",
                id_msj, remitente_raw
            );

            // --- Extracción de adjuntos con rate-limit ---
            let mut adjuntos_procesados = 0;
            for parte in &email_parseado.subparts {
                // Rate-limit: máximo MAX_ADJUNTOS_POR_EMAIL por email
                if adjuntos_procesados >= MAX_ADJUNTOS_POR_EMAIL {
                    log::warn!(" [!] Centinela: email ID {} tiene más de {} adjuntos - ignorando el resto.",
                        id_msj, MAX_ADJUNTOS_POR_EMAIL
                    );
                    registrar_evento(
                        &format!(
                            "Rate-limit adjuntos: email ID {} truncado a {}",
                            id_msj, MAX_ADJUNTOS_POR_EMAIL
                        ),
                        subclave_hex,
                    );
                    break;
                }

                let content_disposition = parte
                    .headers
                    .get_first_header("Content-Disposition")
                    .map(|h| h.get_value().to_lowercase())
                    .unwrap_or_default();

                let content_type = parte
                    .headers
                    .get_first_header("Content-Type")
                    .map(|h| h.get_value().to_lowercase())
                    .unwrap_or_default();

                let es_adjunto = content_disposition.contains("attachment");
                let es_pdf = content_type.contains("pdf") || content_disposition.contains(".pdf");
                let es_docx = content_type.contains("docx")
                    || content_disposition.contains(".docx")
                    || content_type.contains("openxmlformats");

                if !es_adjunto || (!es_pdf && !es_docx) {
                    continue;
                }

                let nombre_archivo = content_disposition
                    .split(';')
                    .find(|p: &&str| p.trim().starts_with("filename"))
                    .and_then(|p: &str| p.split('=').nth(1))
                    .map(|n: &str| n.trim().trim_matches('"').to_string())
                    .unwrap_or_else(|| {
                        format!("adjunto_{}.{}", id_msj, if es_pdf { "pdf" } else { "docx" })
                    });

                let mut bytes_adjunto = parte.get_body_raw()?;

                // Rate-limit: rechazar adjuntos que superen MAX_BYTES_ADJUNTO
                if bytes_adjunto.len() > MAX_BYTES_ADJUNTO {
                    log::warn!(" [!] Centinela: adjunto '{}' demasiado grande ({} MB) - ignorado.",
                        nombre_archivo,
                        bytes_adjunto.len() / 1024 / 1024
                    );
                    registrar_evento(
                        &format!(
                            "Adjunto rechazado por tamaño: {} ({} bytes)",
                            nombre_archivo,
                            bytes_adjunto.len()
                        ),
                        subclave_hex,
                    );
                    bytes_adjunto.zeroize();
                    continue;
                }

                let ruta_temp = format!("tmp_{}_{}.babel", id_msj, nombre_archivo);

                // Ciframos el adjunto con una clave efímera de sesión antes de
                // escribirlo a disco. Si el proceso se cuelga, el archivo temporal
                // queda en disco CIFRADO - ilegible sin la clave efímera que solo
                // existe en RAM durante esta sesión.
                let mut clave_efimera = Zeroizing::new([0u8; 32]);
                rand::thread_rng().fill_bytes(clave_efimera.as_mut());
                let clave_efimera_hex = Zeroizing::new(hex::encode(clave_efimera.as_ref()));

                // Convertimos los bytes a texto base64 para usar blindar_documento
                let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes_adjunto as &[u8]);
                let cifrado_temp = match seguridad::blindar_documento(&b64, &clave_efimera_hex) {
                    Ok(c) => c,
                    Err(e) => {
                        log::warn!("[!] No se pudo cifrar temporal: {}", e);
                        bytes_adjunto.zeroize();
                        continue;
                    }
                };

                // Ahora sí escribimos a disco - siempre cifrado
                if let Err(e) = fs::write(&ruta_temp, &cifrado_temp) {
                    log::warn!("[!] Error escribiendo temporal: {}", e);
                    bytes_adjunto.zeroize();
                    continue;
                }

                // Borramos bytes en RAM tras escribir
                bytes_adjunto.zeroize();

                log::warn!("[CENTINELA] Adjunto: {} - procesando...", ruta_temp);
                registrar_evento(
                    &format!("Adjunto recibido: {} (ID {})", nombre_archivo, id_msj),
                    subclave_hex,
                );

                procesar_archivo_inteligente(
                    &ruta_temp,
                    dict,
                    subclave_hex,
                    "sistema",
                    "spa_Latn",
                    "eng_Latn",
                );

                if let Err(e) = fs::remove_file(&ruta_temp) {
                    log::warn!("[!] No se pudo borrar el temporal {}: {}", ruta_temp, e);
                }

                adjuntos_procesados += 1;
            }

            if adjuntos_procesados == 0 {
                log::warn!("[CENTINELA] ID {} sin adjuntos .pdf/.docx. Saltando.",
                    id_msj
                );
            } else {
                registrar_evento(
                    &format!(
                        "Auto-procesados {} adjuntos (ID {})",
                        adjuntos_procesados, id_msj
                    ),
                    subclave_hex,
                );
            }
        }
    }

    log::warn!("[OK] Ciclo de vigilancia completado. Sistema en espera...");
    Ok(())
}
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
fn extraer_texto_parrafo(para: &docx_rs::Paragraph) -> String {
    let mut texto = String::new();
    for cp in &para.children {
        if let docx_rs::ParagraphChild::Run(run) = cp {
            for rc in &run.children {
                if let docx_rs::RunChild::Text(t) = rc {
                    texto.push_str(&t.text);
                }
            }
        }
    }
    texto
}

fn traducir_parrafo_mut(
    para: &mut docx_rs::Paragraph,
    texto_orig: &str,
    dict: &HashMap<String, String>,
    subclave_hex: &str,
    origen: &str,
    destino: &str,
) {
    if texto_orig.trim().is_empty() { return; }
    let linea = match traducir_con_nllb(texto_orig, origen, destino) {
        Ok(t) => t,
        Err(_) => { let (t, _) = motor_atomico(texto_orig, dict, subclave_hex); t }
    };
    let props = para.property.clone();
    for cp in para.children.iter_mut() {
        if let docx_rs::ParagraphChild::Run(ref mut run) = cp {
            run.children.retain(|c| !matches!(c, docx_rs::RunChild::Text(_)));
        }
    }
    if !linea.is_empty() {
        for cp in para.children.iter_mut() {
            if let docx_rs::ParagraphChild::Run(ref mut run) = cp {
                run.children.insert(0, docx_rs::RunChild::Text(docx_rs::Text::new(linea)));
                break;
            }
        }
    }
    para.property = props;
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
                            Err(_) => { let (t, _) = motor_atomico(texto, dict, subclave_hex); t }
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
    { let mut f = zip_text.by_name("word/document.xml")?; f.read_to_string(&mut xml_doc)?; }

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
                let xml_hf_trad = traducir_xml_directo(&xml_hf, dict, subclave_hex, origen, destino);
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
        .args(["-r", "300", "-f", &pagina.to_string(), "-l", &pagina.to_string(),
               "-png", "-singlefile", ruta_pdf, &tmp_base.to_string_lossy()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !ok { return String::new(); }

    let resultado = match Tesseract::new(None, Some("spa+eng+fra+deu+ara+rus+chi_sim")) {
        Ok(t) => match t.set_image(&tmp_img) {
            Ok(mut t2) => t2.get_text().unwrap_or_default(),
            Err(_) => String::new(),
        },
        Err(_) => String::new(),
    };

    let tam = std::fs::metadata(&tmp_img).map(|m| m.len() as usize).unwrap_or(0);
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
                .unwrap_or_default()
        );
        if texto.trim().is_empty() { *texto = ocr_pagina_pdf(ruta, 1); }
        let (traducido, _) = traducir_inteligente(&texto, dict, subclave_hex, origen, destino);
        let cifrado = seguridad::blindar_documento(&traducido, subclave_hex)?;
        fs::write(archivos_dir.join(format!("{}_{}.babel", id_usuario, nombre)), cifrado)?;
        return Ok(());
    }

    // PASO 2: guardar original (DOCX original cifrado)
    if let Ok(bytes_orig) = fs::read(&ruta_docx_tmp) {
        let b64 = comprimir_b64(&bytes_orig);
        if let Ok(cifrado_orig) = seguridad::blindar_documento(&b64, subclave_hex) {
            let _ = fs::write(
                archivos_dir.join(format!("{}_{}__orig.babel", id_usuario, nombre)),
                cifrado_orig
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
    if salida_tmp.exists() { let _ = fs::rename(&salida_tmp, &salida_final); }
    let orig_tmp = archivos_dir.join(format!("{}_{}_tmp__orig.babel", id_usuario, nombre));
    let orig_final = archivos_dir.join(format!("{}_{}__orig.babel", id_usuario, nombre));
    if orig_tmp.exists() { let _ = fs::rename(&orig_tmp, &orig_final); }

    // PASO 4: convertir DOCX traducido → PDF con LibreOffice
    let ruta_docx_trad = archivos_dir.join(format!("{}_{}.babel", id_usuario, nombre));
    // El DOCX traducido lo guarda clonar_y_traducir como babel — necesitamos descifrarlo
    if let Ok(bytes_cifrados) = fs::read(&ruta_docx_trad) {
        if let Ok(b64) = seguridad::descifrar_documento(bytes_cifrados, subclave_hex) {
            if let Ok(docx_bytes) = descomprimir_b64(&b64) {
                let docx_para_pdf = tmp_dir.join(format!("{}_trad.docx", nombre));
                fs::write(&docx_para_pdf, &docx_bytes)?;
                std::process::Command::new("/opt/homebrew/bin/soffice")
                    .args(["--headless", "--convert-to", "pdf",
                           "--outdir", &tmp_dir.to_string_lossy(),
                           &docx_para_pdf.to_string_lossy()])
                    .status().ok();

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
const DIR_DICT: &str = "../diccionarios";

fn ruta_dict(nombre: &str) -> String {
    format!("{}/{}", DIR_DICT, nombre)
}

/// Asegura que el directorio de diccionarios existe.
fn init_dir_dict() {
    let _ = fs::create_dir_all(DIR_DICT);
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
                ruta_cifrada
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
fn sincronizar_json_legible(ruta: &str, dict: &HashMap<String, String>) {
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

/// Registra una traducción nueva en historial.babel (cifrado).
pub fn registrar_traduccion_nueva(original: &str, traduccion: &str, subclave_hex: &str) {
    init_dir_dict();
    let ruta = ruta_dict("historial.babel");

    #[derive(Serialize, Deserialize)]
    struct EntradaHistorial {
        fecha: String,
        original: String,
        traduccion: String,
    }

    let mut historial: Vec<EntradaHistorial> = fs::read(&ruta)
        .ok()
        .and_then(|blob| seguridad::descifrar_documento(blob, subclave_hex).ok())
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default();

    historial.push(EntradaHistorial {
        fecha: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        original: original.to_string(),
        traduccion: traduccion.to_string(),
    });

    if let Ok(json) = serde_json::to_string_pretty(&historial) {
        match seguridad::blindar_documento(&json, subclave_hex) {
            Ok(cifrado) => {
                let _ = fs::write(&ruta, cifrado);
            }
            Err(e) => log::warn!("[!] Error cifrando historial: {}", e),
        }
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
    let token = String::new();
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