// Servidor de embeddings (opción B del RAG). Arranca EmbeddingGemma-300M vía el mismo
// binario llama-server que el chat, pero en modo --embedding, en un puerto propio. Sirve
// para la búsqueda SEMÁNTICA de la biblioteca jurídica: convierte texto en vectores de
// significado para encontrar la ley correcta aunque el usuario no use las palabras
// técnicas (p. ej. «echar a un inquilino» → desahucio). ~0,3 GB de RAM mientras corre.
//
// Todo es tolerante a fallos: si el modelo no está o el servidor no responde, las
// funciones devuelven None y la biblioteca cae a BM25 (cero regresión).

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use tauri::Manager;

const HOST: &str = "127.0.0.1";
const PUERTO: u16 = 8766; // distinto del chat (8765)
const NOMBRE_EMBEDDER: &str = "embeddinggemma-300M-Q8_0.gguf";

// EmbeddingGemma recomienda prefijos de tarea. Los documentos y la consulta se embeben
// con prefijos distintos; así están calibrados para recuperación (retrieval).
pub(crate) const PREFIJO_DOC: &str = "title: none | text: ";
const PREFIJO_QUERY: &str = "task: search result | query: ";

static EMB_PID: AtomicU32 = AtomicU32::new(0);
static APP: OnceLock<tauri::AppHandle> = OnceLock::new();

/// Guarda el AppHandle para poder localizar el modelo y el binario sin tener que
/// propagar `app` por toda la cadena de búsqueda de la biblioteca. Se llama en setup.
pub fn init(app: tauri::AppHandle) {
    let _ = APP.set(app);
}

fn ruta_embedder(app: &tauri::AppHandle) -> PathBuf {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Ok(res) = app.path().resource_dir() {
        dirs.push(res.join("modelos_ia"));
    }
    dirs.push(
        dirs::home_dir()
            .unwrap_or_default()
            .join("Babel")
            .join("modelos_ia"),
    );
    for d in &dirs {
        let r = d.join(NOMBRE_EMBEDDER);
        if r.exists() {
            return r;
        }
    }
    dirs.into_iter().next().unwrap_or_default().join(NOMBRE_EMBEDDER)
}

/// El modelo embedder está instalado en este equipo.
pub fn disponible() -> bool {
    APP.get().map(|a| ruta_embedder(a).exists()).unwrap_or(false)
}

fn ping() -> bool {
    ureq::get(&format!("http://{HOST}:{PUERTO}/health"))
        .timeout(Duration::from_millis(800))
        .call()
        .map(|r| r.status() == 200)
        .unwrap_or(false)
}

/// Limpia la cuarentena de macOS del binario y sus backends .so/.dylib (igual que el
/// chat: sin esto Gatekeeper mata el proceso o no carga Metal al instalar desde DMG).
#[cfg(target_os = "macos")]
fn limpiar_cuarentena(bin: &str) {
    use std::path::Path;
    let dir = Path::new(bin).parent().map(|p| p.to_path_buf()).unwrap_or_default();
    let frameworks = dir.join("..").join("..").join("Frameworks");
    for d in [&dir, &frameworks] {
        if d.exists() {
            let _ = std::process::Command::new("xattr")
                .args(["-r", "-d", "com.apple.quarantine"])
                .arg(d)
                .output();
        }
    }
}
#[cfg(not(target_os = "macos"))]
fn limpiar_cuarentena(_bin: &str) {}

/// Arranca el servidor de embeddings si no está ya activo. Devuelve true si responde.
/// Síncrono (se llama desde el contexto bloqueante de la biblioteca). Idempotente.
pub fn asegurar_embedder() -> bool {
    if EMB_PID.load(Ordering::Acquire) != 0 && ping() {
        return true;
    }
    let Some(app) = APP.get() else { return false };
    let modelo = ruta_embedder(app);
    if !modelo.exists() {
        return false;
    }
    // Si ya hay un servidor sano en el puerto (de un arranque anterior), reusarlo.
    if ping() {
        return true;
    }
    let bin = crate::ia_redaccion::ruta_llama_server(app);
    limpiar_cuarentena(&bin);

    let hijo = std::process::Command::new(&bin)
        .args([
            "--model", &modelo.to_string_lossy(),
            "--host", HOST,
            "--port", &PUERTO.to_string(),
            "--embedding",
            "--pooling", "mean",
            "--ctx-size", "2048",
            "--batch-size", "8192",
            "--ubatch-size", "8192",
            "--n-gpu-layers", "99",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    let hijo = match hijo {
        Ok(h) => h,
        Err(e) => {
            log::warn!("[EMB] no se pudo arrancar el embedder: {e}");
            return false;
        }
    };
    EMB_PID.store(hijo.id(), Ordering::Release);

    // Esperar a que cargue (hasta ~40 s; EmbeddingGemma es pequeño).
    for _ in 0..80 {
        std::thread::sleep(Duration::from_millis(500));
        if ping() {
            log::info!("[EMB] embedder listo en el puerto {PUERTO}");
            return true;
        }
    }
    log::warn!("[EMB] el embedder no respondió a tiempo");
    false
}

/// Detiene el embedder (al cerrar la app o por detección RAT). Libera su RAM.
pub fn detener_embedder() {
    let pid = EMB_PID.swap(0, Ordering::AcqRel);
    if pid == 0 {
        return;
    }
    #[cfg(unix)]
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .output();
    }
}

fn l2_normalizar(v: &mut [f32]) {
    let norma = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norma > 0.0 {
        for x in v.iter_mut() {
            *x /= norma;
        }
    }
}

/// Embebe una lista de textos (ya con el prefijo que corresponda). Devuelve vectores
/// L2-normalizados (para que el coseno sea un simple producto escalar). None si falla.
pub(crate) fn embed(textos: &[String]) -> Option<Vec<Vec<f32>>> {
    if textos.is_empty() {
        return Some(vec![]);
    }
    if !asegurar_embedder() {
        return None;
    }
    let body = serde_json::json!({ "input": textos }).to_string();
    let resp = ureq::post(&format!("http://{HOST}:{PUERTO}/v1/embeddings"))
        .set("Content-Type", "application/json")
        .timeout(Duration::from_secs(600))
        .send_string(&body)
        .ok()?;
    let v: serde_json::Value = resp.into_json().ok()?;
    let data = v["data"].as_array()?;
    let mut out = Vec::with_capacity(data.len());
    for row in data {
        let arr = row["embedding"].as_array()?;
        let mut vec: Vec<f32> = arr.iter().map(|x| x.as_f64().unwrap_or(0.0) as f32).collect();
        l2_normalizar(&mut vec);
        out.push(vec);
    }
    Some(out)
}

/// Embebe la CONSULTA del usuario (con el prefijo de query de EmbeddingGemma).
pub(crate) fn embed_query(query: &str) -> Option<Vec<f32>> {
    let entrada = vec![format!("{PREFIJO_QUERY}{query}")];
    embed(&entrada)?.into_iter().next()
}
