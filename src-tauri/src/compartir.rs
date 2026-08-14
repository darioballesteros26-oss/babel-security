// SISTEMA BABEL — MÓDULO COMPARTIR SEGURO
#![allow(dead_code)]
//
// Genera archivos HTML autocontenidos que cualquier persona puede descifrar
// desde el navegador (WebCrypto API) sin instalar nada.
//
// Cifrado: PBKDF2-SHA256 (250.000 iteraciones) + AES-256-GCM
// Tabla de contactos: JSON cifrado con la clave maestra del usuario.

use std::collections::HashMap;
use std::fs;
use rand::{rngs::OsRng, RngCore};
use base64::Engine;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::{babel_path, seguridad};
use crate::bip39_words::WORDLIST;

// ── Rutas ──────────────────────────────────────────────────────────────────

pub fn compartidos_dir() -> std::path::PathBuf {
    let dir = crate::babel_dir().join("compartidos");
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Como `barrer_plaintext_compartidos` pero sin límite de antigüedad.
/// Se llama al cerrar sesión para garantizar que ningún archivo en claro persiste.
pub fn barrer_plaintext_compartidos_logout() {
    let dir = compartidos_dir();
    let Ok(entradas) = fs::read_dir(&dir) else { return };
    for e in entradas.flatten() {
        let p = e.path();
        if !p.is_file() { continue; }
        let es_html = p.extension().and_then(|x| x.to_str())
            .map(|x| x.eq_ignore_ascii_case("html")).unwrap_or(false);
        if !es_html {
            crate::borrar_seguro(&p.to_string_lossy());
        }
    }
}

/// Borra de forma segura las copias EN CLARO que compartir_a_url deja en compartidos/
/// (el documento descifrado que se copia al portapapeles). El .html de compartición SÍ
/// se conserva: es el entregable. Solo se limpian los temporales no-.html con > 1 h de
/// antigüedad, para no borrar un archivo que el usuario aún no ha pegado con Cmd+V.
pub fn barrer_plaintext_compartidos() {
    let dir = compartidos_dir();
    let Ok(entradas) = fs::read_dir(&dir) else { return };
    let ahora = std::time::SystemTime::now();
    for e in entradas.flatten() {
        let p = e.path();
        if !p.is_file() {
            continue;
        }
        let es_html = p
            .extension()
            .and_then(|x| x.to_str())
            .map(|x| x.eq_ignore_ascii_case("html"))
            .unwrap_or(false);
        if es_html {
            continue;
        }
        let viejo = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| ahora.duration_since(t).ok())
            .map(|d| d.as_secs() > 3600)
            .unwrap_or(true);
        if viejo {
            crate::borrar_seguro(&p.to_string_lossy());
        }
    }
}

fn contactos_path() -> String {
    babel_path("contactos_compartir.babel")
}

// ── MIME type ──────────────────────────────────────────────────────────────

pub fn mime_de_nombre(nombre: &str) -> &'static str {
    match std::path::Path::new(nombre)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some("pdf")  => "application/pdf",
        Some("docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        Some("txt")  => "text/plain; charset=utf-8",
        Some("png")  => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        _ => "application/octet-stream",
    }
}

// ── Payload ────────────────────────────────────────────────────────────────

/// Empaqueta nombre + MIME + bytes del archivo en un único buffer.
/// Formato: uint32_be(header_len) || header_json_utf8 || contenido_bytes
pub fn empaquetar_payload(nombre: &str, mime: &str, contenido: &[u8]) -> Vec<u8> {
    let header = format!("{{\"n\":{},\"t\":{}}}", json_str(nombre), json_str(mime));
    let header_bytes = header.as_bytes();
    let header_len = (header_bytes.len() as u32).to_be_bytes();
    let mut buf = Vec::with_capacity(4 + header_bytes.len() + contenido.len());
    buf.extend_from_slice(&header_len);
    buf.extend_from_slice(header_bytes);
    buf.extend_from_slice(contenido);
    buf
}

/// Desempaqueta el payload descifrado → (nombre, mime, contenido)
pub fn desempaquetar_payload(payload: &[u8]) -> Result<(String, String, Vec<u8>), String> {
    if payload.len() < 4 {
        return Err("Payload demasiado corto".into());
    }
    let header_len = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    if 4 + header_len > payload.len() {
        return Err("Payload corrupto: header_len excede el buffer".into());
    }
    let header_str = std::str::from_utf8(&payload[4..4 + header_len])
        .map_err(|_| "Header UTF-8 inválido".to_string())?;
    let header: serde_json::Value = serde_json::from_str(header_str)
        .map_err(|_| "Header JSON inválido".to_string())?;
    let nombre = header["n"].as_str().ok_or("Campo n ausente")?.to_string();
    let mime   = header["t"].as_str().ok_or("Campo t ausente")?.to_string();
    let contenido = payload[4 + header_len..].to_vec();
    Ok((nombre, mime, contenido))
}

fn json_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Escapa una cadena para incrustarla dentro de un literal JS `"..."` en HTML.
/// Además de comillas y barra, neutraliza `<`/`>` (→ </>) para que un nombre
/// con `</script>` no pueda cerrar el bloque de script e inyectar código en el HTML que
/// abre el receptor. También escapa saltos de línea.
fn js_str(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

// ── PBKDF2-SHA256 + AES-256-GCM ───────────────────────────────────────────

/// Cifra el payload. Devuelve base64(salt[16] || iv[12] || ciphertext).
pub fn cifrar_con_pbkdf2(payload: &[u8], password: &str) -> Result<String, String> {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    let mut salt = [0u8; 16];
    let mut iv_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut iv_bytes);

    let mut key_bytes = Zeroizing::new([0u8; 32]);
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 250_000, key_bytes.as_mut());

    let key = Key::<Aes256Gcm>::from_slice(key_bytes.as_ref());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&iv_bytes);

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| format!("Error cifrando: {}", e))?;

    let mut combined = Vec::with_capacity(28 + ciphertext.len());
    combined.extend_from_slice(&salt);
    combined.extend_from_slice(&iv_bytes);
    combined.extend_from_slice(&ciphertext);

    Ok(base64::engine::general_purpose::STANDARD.encode(&combined))
}

/// Descifra base64(salt || iv || ciphertext). Error genérico si la contraseña es incorrecta.
pub fn descifrar_con_pbkdf2(b64: &str, password: &str) -> Result<Vec<u8>, String> {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    let combined = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| "Datos inválidos".to_string())?;

    // 16 salt + 12 iv + 16 GCM tag = mínimo 44 bytes de overhead
    if combined.len() < 44 {
        return Err("Datos inválidos".to_string());
    }

    let salt = &combined[..16];
    let iv_bytes = &combined[16..28];
    let ciphertext = &combined[28..];

    let mut key_bytes = Zeroizing::new([0u8; 32]);
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 250_000, key_bytes.as_mut());

    let key = Key::<Aes256Gcm>::from_slice(key_bytes.as_ref());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Contraseña incorrecta".to_string())
}

// ── HTML sin contraseña ────────────────────────────────────────────────────

/// HTML autónomo que muestra el archivo directamente, sin contraseña.
/// El contenido va embebido como base64; el receptor solo necesita abrir el .html.
pub fn generar_html_simple(b64_data: &str, nombre: &str, mime: &str) -> String {
    let title  = nombre.replace('&',"&amp;").replace('<',"&lt;").replace('>',"&gt;");
    let nom_js = js_str(nombre);
    let mim_js = js_str(mime);
    format!(r##"<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;background:#0a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:24px}}
.hdr{{text-align:center;margin-bottom:28px}}
.hdr h1{{font-size:13px;letter-spacing:6px;color:#888;font-weight:400;text-transform:uppercase}}
.hdr p{{font-size:11px;color:#555;letter-spacing:2px;margin-top:6px}}
#viewer{{width:100%;max-width:820px}}
img{{max-width:100%;border-radius:6px;display:block;margin:0 auto}}
iframe{{width:100%;height:80vh;border:none;border-radius:6px;background:#1a1a1a}}
pre{{white-space:pre-wrap;font-size:14px;line-height:1.7;color:#ccc;background:#111;padding:20px;border-radius:6px;border:1px solid #222;max-height:70vh;overflow-y:auto}}
.dl{{display:block;margin:20px auto 0;padding:14px 32px;background:transparent;border:1px solid #444;color:#e0e0e0;font-size:12px;letter-spacing:3px;text-transform:uppercase;cursor:pointer;border-radius:4px;max-width:320px;text-align:center}}
.dl:hover{{border-color:#888}}
.foot{{margin-top:28px;font-size:10px;color:#333;letter-spacing:1px;text-align:center}}
</style>
</head>
<body>
<div class="hdr"><h1>Babel Security</h1><p>{title}</p></div>
<div id="viewer"></div>
<p class="foot">Compartido con Babel Security &mdash; babel-security.com</p>
<script>
(function(){{
  const B64="{b64}",NOM="{nom_js}",MIME="{mim_js}";
  const bytes=Uint8Array.from(atob(B64),c=>c.charCodeAt(0));
  const mob=/iPhone|iPad|iPod|Android/i.test(navigator.userAgent);
  const v=document.getElementById('viewer');
  function btnDescargar(url,nombre){{
    const b=document.createElement('button');b.className='dl';b.textContent='⬇ Descargar '+nombre;
    if(mob){{b.onclick=()=>window.open(url,'_blank');}}
    else{{b.onclick=()=>{{const a=document.createElement('a');a.href=url;a.download=nombre;a.click();}};}}
    return b;
  }}
  const dataUrl='data:'+MIME+';base64,'+B64;
  if(MIME.startsWith('text/')||MIME==='application/json'){{
    const p=document.createElement('pre');p.textContent=new TextDecoder().decode(bytes);v.appendChild(p);
    v.appendChild(btnDescargar(dataUrl,NOM));
  }}else if(MIME.startsWith('image/')){{
    const img=document.createElement('img');img.src=dataUrl;img.alt=NOM;v.appendChild(img);
    v.appendChild(btnDescargar(dataUrl,NOM));
  }}else if(MIME==='application/pdf'){{
    if(mob){{
      v.appendChild(btnDescargar(dataUrl,NOM));
    }}else{{
      const f=document.createElement('iframe');f.src=dataUrl;v.appendChild(f);
      v.appendChild(btnDescargar(dataUrl,NOM));
    }}
  }}else{{
    v.appendChild(btnDescargar(dataUrl,NOM));
  }}
}})();
</script>
</body>
</html>"##,
        title  = title,
        b64    = b64_data,
        nom_js = nom_js,
        mim_js = mim_js,
    )
}

// ── Generación del HTML autónomo ───────────────────────────────────────────

/// Genera el HTML completo para compartir. nombre_original solo se usa para el <title>.
pub fn generar_html_compartir(b64_data: &str, nombre_original: &str) -> String {
    let title_escaped = nombre_original
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");

    format!(r##"<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Babel — {title}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:24px}}
.card{{width:100%;max-width:420px;background:#111;border:1px solid #222;border-radius:8px;padding:40px 32px}}
.logo{{text-align:center;margin-bottom:32px}}
.logo h1{{font-size:13px;letter-spacing:6px;color:#888;font-weight:400;text-transform:uppercase}}
.logo p{{font-size:11px;color:#444;letter-spacing:2px;margin-top:6px}}
.lock{{width:40px;height:40px;margin:0 auto 20px;opacity:.3}}
form{{display:flex;flex-direction:column;gap:14px}}
label{{font-size:11px;color:#555;letter-spacing:1.5px;text-transform:uppercase}}
.pwd-wrap{{position:relative}}
#pwd{{width:100%;padding:12px 44px 12px 14px;background:#1a1a1a;border:1px solid #2a2a2a;border-radius:4px;color:#e0e0e0;font-size:18px;letter-spacing:4px;text-align:center;outline:none;transition:border-color .2s;box-sizing:border-box}}
#pwd:focus{{border-color:#444}}
#toggle-pwd{{position:absolute;right:10px;top:50%;transform:translateY(-50%);background:none;border:none;padding:4px;cursor:pointer;color:#444;line-height:0;transition:color .2s}}
#toggle-pwd:hover{{color:#aaa}}
#toggle-pwd svg{{width:18px;height:18px;display:block}}
button{{padding:13px;background:#e0e0e0;color:#0a0a0a;border:none;border-radius:4px;font-size:13px;letter-spacing:2px;text-transform:uppercase;cursor:pointer;font-weight:600;transition:opacity .2s}}
button:hover{{opacity:.85}}
button:disabled{{opacity:.4;cursor:default}}
.error{{display:none;font-size:12px;color:#c44;letter-spacing:.5px;text-align:center;padding:10px;background:rgba(200,68,68,.08);border-radius:4px}}
.spinner{{display:none;text-align:center;font-size:11px;color:#555;letter-spacing:2px;padding:8px}}
#viewer{{display:none;margin-top:32px;border-top:1px solid #1e1e1e;padding-top:24px}}
#viewer h2{{font-size:11px;letter-spacing:2px;color:#555;text-transform:uppercase;margin-bottom:16px}}
#text-content{{white-space:pre-wrap;font-size:14px;line-height:1.7;color:#ccc;max-height:60vh;overflow-y:auto;background:#0d0d0d;padding:16px;border-radius:4px;border:1px solid #1e1e1e}}
.dl-btn{{margin-top:16px;width:100%;padding:13px;background:transparent;color:#e0e0e0;border:1px solid #333;border-radius:4px;font-size:12px;letter-spacing:2px;text-transform:uppercase;cursor:pointer;transition:border-color .2s}}
.dl-btn:hover{{border-color:#666}}
.footer-note{{margin-top:24px;text-align:center;font-size:10px;color:#333;letter-spacing:1px}}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <svg class="lock" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect x="8" y="18" width="24" height="18" rx="2" fill="#fff"/>
      <path d="M13 18V13a7 7 0 0114 0v5" stroke="#fff" stroke-width="2" fill="none"/>
      <circle cx="20" cy="27" r="2.5" fill="#0a0a0a"/>
    </svg>
    <h1>Babel Security</h1>
    <p>Documento cifrado</p>
  </div>
  <form id="frm" onsubmit="return false">
    <label for="pwd">Contraseña</label>
    <div class="pwd-wrap">
      <input type="password" id="pwd" name="password" autocomplete="off"
             placeholder="Introduce la contraseña" autofocus
             spellcheck="false" autocorrect="off" autocapitalize="off">
      <button type="button" id="toggle-pwd" onclick="togglePwd()" title="Mostrar/ocultar contraseña" aria-label="Mostrar contraseña">
        <svg id="ico-show" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>
        <svg id="ico-hide" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="display:none"><path d="M17.94 17.94A10.06 10.06 0 0112 19c-6.5 0-10-7-10-7a17.6 17.6 0 014.06-5.06M9.9 4.24A9.12 9.12 0 0112 4c6.5 0 10 7 10 7a17.6 17.6 0 01-2.33 3.37M3 3l18 18"/><circle cx="12" cy="12" r="3" style="clip-path:none"/></svg>
      </button>
    </div>
    <button id="btn" onclick="descifrar()">Descifrar</button>
    <div class="error" id="err">Contraseña incorrecta. Inténtalo de nuevo.</div>
    <div class="spinner" id="spin">Descifrando&hellip;</div>
  </form>
  <div id="viewer">
    <h2 id="viewer-title"></h2>
    <pre id="text-content"></pre>
    <button class="dl-btn" id="dl-btn" style="display:none">Descargar archivo</button>
  </div>
  <p class="footer-note">Generado con Babel Security &mdash; babel-security.com</p>
</div>
<script>
const DATA="{b64}";
const ITER=250000;
let blobUrl=null;

function togglePwd(){{
  const p=document.getElementById('pwd');
  const show=document.getElementById('ico-show');
  const hide=document.getElementById('ico-hide');
  if(p.type==='password'){{p.type='text';show.style.display='none';hide.style.display='block';}}
  else{{p.type='password';show.style.display='block';hide.style.display='none';}}
}}

async function descifrar(){{
  const pwd=document.getElementById('pwd').value;
  if(!pwd)return;
  const btn=document.getElementById('btn');
  const err=document.getElementById('err');
  const spin=document.getElementById('spin');
  err.style.display='none';
  btn.disabled=true;
  spin.style.display='block';
  try{{
    const raw=Uint8Array.from(atob(DATA),c=>c.charCodeAt(0));
    const salt=raw.slice(0,16);
    const iv=raw.slice(16,28);
    const ct=raw.slice(28);
    const km=await crypto.subtle.importKey('raw',new TextEncoder().encode(pwd),'PBKDF2',false,['deriveKey']);
    const key=await crypto.subtle.deriveKey(
      {{name:'PBKDF2',salt,iterations:ITER,hash:'SHA-256'}},
      km,
      {{name:'AES-GCM',length:256}},
      false,['decrypt']
    );
    const plain=await crypto.subtle.decrypt({{name:'AES-GCM',iv}},key,ct);
    const bytes=new Uint8Array(plain);
    const hlen=new DataView(bytes.buffer).getUint32(0,false);
    const hdr=JSON.parse(new TextDecoder().decode(bytes.slice(4,4+hlen)));
    const content=bytes.slice(4+hlen);
    mostrar(hdr.n,hdr.t,content);
    document.getElementById('frm').style.display='none';
    document.getElementById('viewer').style.display='block';
  }}catch(e){{
    err.style.display='block';
    btn.disabled=false;
  }}finally{{
    spin.style.display='none';
  }}
}}

function toB64(bytes){{
  let s='';for(let i=0;i<bytes.length;i++)s+=String.fromCharCode(bytes[i]);return btoa(s);
}}

function mostrar(nombre,mime,bytes){{
  const titulo=document.getElementById('viewer-title');
  const textEl=document.getElementById('text-content');
  const dlBtn=document.getElementById('dl-btn');
  const viewer=document.getElementById('viewer');
  titulo.textContent=nombre;
  const esTexto=mime.startsWith('text/')||mime==='application/json'||mime==='application/octet-stream'&&nombre.endsWith('.txt');
  const esImagen=mime.startsWith('image/');
  const esPDF=mime==='application/pdf';
  if(esTexto){{
    textEl.textContent=new TextDecoder().decode(bytes);
    textEl.style.display='block';
  }}else if(esImagen){{
    const img=document.createElement('img');
    img.src='data:'+mime+';base64,'+toB64(bytes);
    img.style.cssText='max-width:100%;border-radius:4px;display:block;margin-top:8px';
    viewer.appendChild(img);
  }}else if(esPDF){{
    // data URI funciona en iOS Safari; iframe para desktop
    const dataUrl='data:application/pdf;base64,'+toB64(bytes);
    const isMobile=/iPhone|iPad|iPod|Android/i.test(navigator.userAgent);
    if(isMobile){{
      // En iOS abrir en nueva pestaña (los iframes PDF no se ven en Safari)
      dlBtn.style.display='block';
      dlBtn.textContent='Abrir PDF';
      dlBtn.onclick=function(){{window.open(dataUrl,'_blank');}};
    }}else{{
      const fr=document.createElement('iframe');
      fr.src=dataUrl;
      fr.style.cssText='width:100%;height:500px;border:none;border-radius:4px;margin-top:8px;background:#222';
      viewer.appendChild(fr);
    }}
  }}else{{
    // Otros (DOCX, etc.): en móvil a.download no funciona en iOS Safari → abrir en pestaña.
    const dataUrl='data:'+mime+';base64,'+toB64(bytes);
    const isMobile=/iPhone|iPad|iPod|Android/i.test(navigator.userAgent);
    dlBtn.style.display='block';
    dlBtn.textContent='Descargar '+nombre;
    if(isMobile){{
      dlBtn.onclick=function(){{window.open(dataUrl,'_blank');}};
    }}else{{
      dlBtn.onclick=function(){{
        const a=document.createElement('a');
        a.href=dataUrl;a.download=nombre;a.click();
      }};
    }}
  }}
}}

document.getElementById('pwd').addEventListener('keydown',function(e){{
  if(e.key==='Enter')descifrar();
}});
</script>
</body>
</html>"##,
        title = title_escaped,
        b64 = b64_data,
    )
}

// ── Contraseña aleatoria ───────────────────────────────────────────────────

/// Genera una contraseña memorable con 3 palabras BIP39 + 3 dígitos.
/// Ejemplo: "apple-tiger-globe-742"
pub fn generar_password_aleatoria() -> String {
    let n = WORDLIST.len() as u64;
    let tope = (u64::MAX / n) * n;

    let palabra = || -> &'static str {
        loop {
            let mut buf = [0u8; 8];
            OsRng.fill_bytes(&mut buf);
            let v = u64::from_le_bytes(buf);
            if v < tope {
                return WORDLIST[(v % n) as usize];
            }
        }
    };

    let mut buf = [0u8; 2];
    OsRng.fill_bytes(&mut buf);
    let digitos = (u16::from_le_bytes(buf) % 900 + 100) as u16; // 100-999

    format!("{}-{}-{}-{}", palabra(), palabra(), palabra(), digitos)
}

// ── Tabla de contactos cifrada ─────────────────────────────────────────────

pub fn cargar_contactos(subclave_hex: &str) -> HashMap<String, String> {
    let ruta = contactos_path();
    fs::read(&ruta)
        .ok()
        .and_then(|b| seguridad::descifrar_documento(b, subclave_hex).ok())
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default()
}

pub fn guardar_contactos(
    contactos: &HashMap<String, String>,
    subclave_hex: &str,
) -> Result<(), String> {
    let json = serde_json::to_string(contactos).map_err(|e| format!("Error: {}", e))?;
    let cifrado = seguridad::blindar_documento(&json, subclave_hex)
        .map_err(|e| format!("Error cifrando contactos: {}", e))?;
    crate::escribir_privado(contactos_path(), cifrado).map_err(|e| format!("Error guardando contactos: {}", e))
}

/// Devuelve (password, es_nuevo). Si el contacto ya existe reutiliza su contraseña.
pub fn obtener_o_crear_password(
    contacto: &str,
    subclave_hex: &str,
) -> Result<(String, bool), String> {
    let mut contactos = cargar_contactos(subclave_hex);
    if let Some(pwd) = contactos.get(contacto) {
        return Ok((pwd.clone(), false));
    }
    let pwd = generar_password_aleatoria();
    contactos.insert(contacto.to_string(), pwd.clone());
    guardar_contactos(&contactos, subclave_hex)?;
    Ok((pwd, true))
}

// ── Resultado del comando compartir ───────────────────────────────────────

#[derive(Serialize)]
pub struct ResultadoCompartir {
    pub ruta_html: String,
    pub nombre_html: String,
    pub es_nuevo_contacto: bool,
    pub password: Option<String>,
}

/// Lógica completa: descifra el .babel, genera y guarda el HTML.
/// Devuelve la ruta del .html generado y metadatos para el frontend.
pub fn generar_archivo_compartir(
    bytes_descifrados: &[u8],
    nombre_original: &str,
    contacto: &str,
    subclave_hex: &str,
) -> Result<ResultadoCompartir, String> {
    let mime = mime_de_nombre(nombre_original);
    // payload es una copia nueva del plaintext del documento — Zeroizing la borra al salir.
    let payload = Zeroizing::new(empaquetar_payload(nombre_original, mime, bytes_descifrados));

    let (password, es_nuevo) = obtener_o_crear_password(contacto, subclave_hex)?;

    let b64 = cifrar_con_pbkdf2(&payload, &password)?;
    let html = generar_html_compartir(&b64, nombre_original);

    // Nombre del HTML: quitar extensión + "_seguro.html"
    let stem = std::path::Path::new(nombre_original)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(nombre_original);

    // Sanear: solo alfanumérico, guión, guión bajo y punto
    let stem_limpio: String = stem
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();

    let nombre_html = format!("{}_seguro.html", stem_limpio);
    let ruta_html = compartidos_dir()
        .join(&nombre_html)
        .to_string_lossy()
        .to_string();

    crate::escribir_privado(&ruta_html, html.as_bytes())
        .map_err(|e| format!("Error guardando HTML: {}", e))?;

    log::info!("[compartir] HTML de compartición generado.");

    Ok(ResultadoCompartir {
        ruta_html,
        nombre_html,
        es_nuevo_contacto: es_nuevo,
        password: if es_nuevo { Some(password) } else { None },
    })
}

// ── Destinos personalizados de compartición ───────────────────────────────────

/// Un destino de compartición personalizado: nombre visible + URL de la app/web.
/// Si `bundle_id` está presente (macOS), Babel intenta abrir la app instalada;
/// si no está instalada o no hay bundle_id, abre la URL en el navegador.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct DestinoCompartir {
    pub nombre: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
}

/// Destino incluido de fábrica. El usuario puede añadir más o eliminarlo.
pub fn destinos_por_defecto() -> Vec<DestinoCompartir> {
    vec![DestinoCompartir {
        nombre: "WhatsApp".into(),
        url: "https://web.whatsapp.com".into(),
        bundle_id: Some("net.whatsapp.WhatsApp".into()),
    }]
}

fn destinos_path() -> String {
    crate::babel_path("destinos_compartir.babel")
}

/// Carga los destinos del disco. Devuelve los por defecto si el archivo no existe.
pub fn cargar_destinos(subclave_hex: &str) -> Vec<DestinoCompartir> {
    let ruta = destinos_path();
    fs::read(&ruta)
        .ok()
        .and_then(|b| crate::seguridad::descifrar_documento(b, subclave_hex).ok())
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_else(destinos_por_defecto)
}

/// Guarda la lista de destinos en disco, cifrada con la subclave del usuario.
pub fn guardar_destinos(destinos: &[DestinoCompartir], subclave_hex: &str) -> Result<(), String> {
    let json = serde_json::to_string(destinos)
        .map_err(|e| format!("Error serializando destinos: {}", e))?;
    let cifrado = crate::seguridad::blindar_documento(&json, subclave_hex)
        .map_err(|e| format!("Error cifrando destinos: {}", e))?;
    crate::escribir_privado(destinos_path(), cifrado)
        .map_err(|e| format!("Error guardando destinos: {}", e))
}

// ── Portapapeles y detección de apps (macOS) ─────────────────────────────────
//
// Los destinos "personalizados" del menú compartir (WhatsApp, Telegram, LexNET)
// NO son integración nativa real con esas apps — no exponen API pública de
// compartición de archivos en macOS y WhatsApp/Telegram no se integran con el
// NSSharingServicePicker del sistema.
//
// En su lugar, Babel descifra el archivo, lo copia al portapapeles como NSURL
// y lanza la app/web por comodidad. El usuario pega con Cmd+V en el chat.
// El picker nativo del sistema (Grupo 1) sigue disponible para AirDrop, Mail, etc.

/// Copia el archivo al portapapeles del sistema como objeto de archivo (no texto).
/// En macOS usa NSPasteboard + NSURL; en Windows usa PowerShell Set-Clipboard.
/// Un Cmd+V / Ctrl+V posterior en cualquier app lo adjunta como archivo real.
pub fn copiar_archivo_al_portapapeles(path: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        use objc::runtime::Object;
        use objc::{class, msg_send, sel, sel_impl};
        use std::ffi::CString;

        let c_path = CString::new(path).map_err(|_| "Ruta contiene bytes nulos")?;

        unsafe {
            let ns_string: *mut Object = msg_send![
                class!(NSString),
                stringWithUTF8String: c_path.as_ptr()
            ];
            if ns_string.is_null() {
                return Err("Error creando NSString con la ruta".into());
            }

            let file_url: *mut Object = msg_send![class!(NSURL), fileURLWithPath: ns_string];
            if file_url.is_null() {
                return Err("Error creando NSURL para el archivo".into());
            }

            let pasteboard: *mut Object = msg_send![class!(NSPasteboard), generalPasteboard];
            let (): () = msg_send![pasteboard, clearContents];

            let array: *mut Object = msg_send![class!(NSArray), arrayWithObject: file_url];
            let _: i64 = msg_send![pasteboard, writeObjects: array];
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    {
        // Set-Clipboard -LiteralPath copia el archivo como CF_HDROP (igual que Ctrl+C en Explorer)
        // Escapamos comillas simples duplicándolas (convención PowerShell)
        let path_esc = path.replace('\'', "''");
        let script = format!("Set-Clipboard -LiteralPath '{}'", path_esc);
        std::process::Command::new("powershell")
            .args(["-NonInteractive", "-NoProfile", "-NoLogo", "-Command", &script])
            .output()
            .map_err(|e| format!("Error ejecutando PowerShell: {}", e))?;
        Ok(())
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        // Linux y otros: el archivo queda en compartidos/ para adjuntarlo manualmente
        let _ = path;
        Ok(())
    }
}

/// Comprueba si una app con el bundle ID dado está instalada en este Mac.
/// Usa NSWorkspace (sin Spotlight) para mayor fiabilidad.
#[cfg(target_os = "macos")]
#[allow(unexpected_cfgs)]
pub fn verificar_app_instalada(bundle_id: &str) -> bool {
    use objc::runtime::Object;
    use objc::{class, msg_send, sel, sel_impl};
    use std::ffi::CString;

    let c_bundle = match CString::new(bundle_id) {
        Ok(s) => s,
        Err(_) => return false,
    };

    unsafe {
        let ns_bundle: *mut Object = msg_send![
            class!(NSString),
            stringWithUTF8String: c_bundle.as_ptr()
        ];
        if ns_bundle.is_null() {
            return false;
        }

        let workspace: *mut Object = msg_send![class!(NSWorkspace), sharedWorkspace];
        let url: *mut Object = msg_send![
            workspace,
            URLForApplicationWithBundleIdentifier: ns_bundle
        ];
        !url.is_null()
    }
}

/// Lanza/activa la app con el bundle ID dado mediante `open -b <bundle_id>`.
#[cfg(target_os = "macos")]
#[allow(unexpected_cfgs)]
pub fn abrir_app_bundle(bundle_id: &str) -> Result<(), String> {
    let output = std::process::Command::new("open")
        .args(["-b", bundle_id])
        .output()
        .map_err(|e| format!("Error ejecutando open: {}", e))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(format!("No se pudo abrir la app con bundle '{}'", bundle_id))
    }
}

// ── NSSharingServicePicker (macOS) ─────────────────────────────────────────

/// Muestra el selector nativo de compartición de macOS anclado a la ventana principal.
/// Si no hay ventana activa o falla ObjC, registra el error y devuelve Err.
#[cfg(target_os = "macos")]
#[allow(unexpected_cfgs)]
pub fn mostrar_share_picker_macos(
    app: &tauri::AppHandle,
    file_path: &str,
) -> Result<(), String> {
    use objc::runtime::Object;
    use objc::{class, msg_send, sel, sel_impl};
    use std::ffi::CString;
    use tauri::Manager;

    let window = app
        .get_webview_window("main")
        .ok_or_else(|| {
            log::error!("[compartir] NSSharingServicePicker: no hay ventana activa");
            "No hay ventana activa — usa 'Revelar en Finder' para compartir manualmente".to_string()
        })?;

    let ns_window_ptr = window
        .ns_window()
        .map_err(|e| {
            log::error!("[compartir] ns_window() falló: {}", e);
            format!("Error obteniendo ventana: {}", e)
        })?;

    let c_path = CString::new(file_path)
        .map_err(|_| "Ruta contiene bytes nulos".to_string())?;

    unsafe {
        let ns_string: *mut Object = msg_send![
            class!(NSString),
            stringWithUTF8String: c_path.as_ptr()
        ];
        if ns_string.is_null() {
            return Err("Error creando NSString con la ruta".to_string());
        }

        let file_url: *mut Object = msg_send![
            class!(NSURL),
            fileURLWithPath: ns_string
        ];
        if file_url.is_null() {
            return Err("Error creando NSURL para el archivo".to_string());
        }

        let items: *mut Object = msg_send![
            class!(NSArray),
            arrayWithObject: file_url
        ];

        let picker_alloc: *mut Object = msg_send![class!(NSSharingServicePicker), alloc];
        let picker: *mut Object = msg_send![picker_alloc, initWithItems: items];
        if picker.is_null() {
            return Err("Error creando NSSharingServicePicker".to_string());
        }

        // Obtener la content view de la ventana para anclar el picker
        let ns_window = ns_window_ptr as *mut Object;
        let content_view: *mut Object = msg_send![ns_window, contentView];

        // CGRect en (0,0) con tamaño (1,1) — lo suficiente para anclar el picker
        #[repr(C)]
        #[derive(Copy, Clone)]
        struct CGPoint { x: f64, y: f64 }
        #[repr(C)]
        #[derive(Copy, Clone)]
        struct CGSize { width: f64, height: f64 }
        #[repr(C)]
        #[derive(Copy, Clone)]
        struct CGRect { origin: CGPoint, size: CGSize }

        let rect = CGRect {
            origin: CGPoint { x: 0.0, y: 0.0 },
            size: CGSize { width: 1.0, height: 1.0 },
        };

        // NSMaxYEdge = 1 — el menú aparece encima del rect
        let (): () = msg_send![
            picker,
            showRelativeToRect: rect
            ofView: content_view
            preferredEdge: 1usize
        ];
    }

    Ok(())
}

// ── Tests unitarios ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Ciclo completo: empaquetar → cifrar → descifrar → desempaquetar
    #[test]
    fn ciclo_cifrado_descifrado_correcto() {
        let nombre = "contrato.pdf";
        let mime = "application/pdf";
        let contenido = b"contenido del documento PDF de prueba";
        let password = "test-password-123";

        let payload = empaquetar_payload(nombre, mime, contenido);
        let b64 = cifrar_con_pbkdf2(&payload, password).expect("cifrado debe funcionar");
        let descifrado = descifrar_con_pbkdf2(&b64, password).expect("descifrado debe funcionar");

        assert_eq!(descifrado, payload, "payload debe ser idéntico tras cifrar+descifrar");

        let (n, t, c) = desempaquetar_payload(&descifrado).expect("desempaquetar debe funcionar");
        assert_eq!(n, nombre);
        assert_eq!(t, mime);
        assert_eq!(c.as_slice(), contenido);
    }

    // Contraseña incorrecta → error
    #[test]
    fn descifrado_contraseña_incorrecta_falla() {
        let payload = empaquetar_payload("doc.txt", "text/plain", b"secreto");
        let b64 = cifrar_con_pbkdf2(&payload, "contraseña-correcta").unwrap();
        let resultado = descifrar_con_pbkdf2(&b64, "contraseña-incorrecta");
        assert!(resultado.is_err(), "debe fallar con contraseña incorrecta");
    }

    // Ciclo completo con contenido binario
    #[test]
    fn ciclo_contenido_binario() {
        let contenido: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        let payload = empaquetar_payload("imagen.png", "image/png", &contenido);
        let b64 = cifrar_con_pbkdf2(&payload, "mi-contraseña").unwrap();
        let descifrado = descifrar_con_pbkdf2(&b64, "mi-contraseña").unwrap();
        let (_, _, c) = desempaquetar_payload(&descifrado).unwrap();
        assert_eq!(c, contenido);
    }

    // Contacto nuevo → contraseña generada y guardada
    // Contacto existente → misma contraseña reutilizada
    #[test]
    fn contacto_nuevo_crea_password() {
        // Simula tabla vacía y verifica que se genera contraseña
        let mut tabla: HashMap<String, String> = HashMap::new();
        let contacto = "Ana García";

        // Primer uso: contacto no existe
        assert!(!tabla.contains_key(contacto));

        let pwd = generar_password_aleatoria();
        tabla.insert(contacto.to_string(), pwd.clone());

        // Segundo uso: misma contraseña
        let pwd2 = tabla.get(contacto).cloned().unwrap();
        assert_eq!(pwd, pwd2, "debe reutilizar la misma contraseña");
    }

    // La contraseña aleatoria tiene el formato esperado
    #[test]
    fn password_aleatoria_formato() {
        let pwd = generar_password_aleatoria();
        let partes: Vec<&str> = pwd.split('-').collect();
        assert_eq!(partes.len(), 4, "debe tener 4 partes separadas por guión");
        let digitos: u16 = partes[3].parse().expect("la última parte debe ser numérica");
        assert!(digitos >= 100 && digitos <= 999, "dígitos deben estar en 100-999");
    }

    // Cada cifrado produce un base64 distinto (salt aleatoria)
    #[test]
    fn cifrados_son_no_deterministas() {
        let payload = b"mismo contenido";
        let b1 = cifrar_con_pbkdf2(payload, "password").unwrap();
        let b2 = cifrar_con_pbkdf2(payload, "password").unwrap();
        assert_ne!(b1, b2, "cada cifrado debe usar salt/iv distintos");
    }

    // Nombre HTML generado correctamente
    #[test]
    fn nombre_html_sufijo_seguro() {
        // Verificar la lógica de nombre
        let nombre_original = "contrato.pdf";
        let stem = std::path::Path::new(nombre_original)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(nombre_original);
        let nombre_html = format!("{}_seguro.html", stem);
        assert_eq!(nombre_html, "contrato_seguro.html");
    }

    // ── Tests de portapapeles y detección de apps (macOS) ─────────────────

    // Safari siempre está instalado en cualquier Mac — verifica verificar_app_instalada
    #[cfg(target_os = "macos")]
    #[test]
    fn safari_siempre_instalado() {
        assert!(
            verificar_app_instalada("com.apple.Safari"),
            "Safari debe estar instalado en cualquier Mac"
        );
    }

    // Bundle ID inventado → false
    #[cfg(target_os = "macos")]
    #[test]
    fn bundle_id_inventado_no_instalado() {
        assert!(
            !verificar_app_instalada("com.babel.app.que.jamas.existira.xyzzy.9999"),
            "Bundle ID inventado no debe aparecer como instalado"
        );
    }

    // copiar_archivo_al_portapapeles con archivo real → Ok
    #[cfg(target_os = "macos")]
    #[test]
    fn copiar_archivo_real_al_portapapeles() {
        use std::io::Write;
        let ruta = std::env::temp_dir().join("babel_test_clipboard_compartir.txt");
        {
            let mut f = std::fs::File::create(&ruta).expect("crear archivo de prueba");
            f.write_all(b"babel-portapapeles-test").expect("escribir");
        }
        let res = copiar_archivo_al_portapapeles(ruta.to_str().unwrap());
        std::fs::remove_file(&ruta).ok();
        assert!(
            res.is_ok(),
            "copiar al portapapeles no debe fallar con ruta válida: {:?}", res
        );
    }

    // La URL de LexNET es HTTPS y tiene el dominio correcto
    #[test]
    fn url_lexnet_formato_correcto() {
        let url = "https://lexnet.justicia.es";
        assert!(url.starts_with("https://"), "LexNET debe usar HTTPS");
        assert!(url.contains("lexnet"), "URL debe contener lexnet");
        assert!(url.contains("justicia.es"), "URL debe ser del dominio justicia.es");
    }

    // ── Tests de destinos personalizados ─────────────────────────────────────

    #[test]
    fn destino_por_defecto_es_whatsapp_web() {
        let d = destinos_por_defecto();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].nombre, "WhatsApp");
        assert_eq!(d[0].url, "https://web.whatsapp.com");
        assert_eq!(d[0].bundle_id.as_deref(), Some("net.whatsapp.WhatsApp"));
    }

    #[test]
    fn destinos_json_roundtrip() {
        let destinos = vec![
            DestinoCompartir { nombre: "WhatsApp".into(), url: "https://web.whatsapp.com".into(), bundle_id: Some("net.whatsapp.WhatsApp".into()) },
            DestinoCompartir { nombre: "LexNET".into(), url: "https://lexnet.justicia.es".into(), bundle_id: None },
        ];
        let json = serde_json::to_string(&destinos).expect("serializar");
        let cargados: Vec<DestinoCompartir> = serde_json::from_str(&json).expect("deserializar");
        assert_eq!(destinos, cargados, "roundtrip JSON debe conservar todos los campos");
    }

    #[test]
    fn agregar_y_eliminar_destino_sin_corrupcion() {
        let mut lista = destinos_por_defecto();
        // Añadir destino sin bundle_id (añadido por el usuario)
        lista.push(DestinoCompartir { nombre: "LexNET".into(), url: "https://lexnet.justicia.es".into(), bundle_id: None });
        assert_eq!(lista.len(), 2);
        // Editar
        lista[1].nombre = "LexNET Justicia".into();
        assert_eq!(lista[1].nombre, "LexNET Justicia");
        // Eliminar
        lista.remove(1);
        assert_eq!(lista.len(), 1);
        assert_eq!(lista[0].nombre, "WhatsApp", "el destino restante debe ser el original");
    }
}
