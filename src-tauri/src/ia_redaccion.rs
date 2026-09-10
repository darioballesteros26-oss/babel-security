use std::path::PathBuf;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

const PUERTO: u16 = 8765;
const HOST: &str = "127.0.0.1";

pub struct IaRedaccionState {
    proceso: Mutex<Option<Child>>,
    pub estado: Mutex<String>, // "inactivo" | "cargando" | "activo" | "error:..."
}

impl IaRedaccionState {
    pub fn nueva() -> Self {
        Self {
            proceso: Mutex::new(None),
            estado: Mutex::new("inactivo".into()),
        }
    }
}

fn ruta_modelo() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_default()
        .join("Babel")
        .join("modelos_ia")
        .join("Qwen3-4B-Q4_K_M.gguf")
}

fn base_url() -> String {
    format!("http://{}:{}", HOST, PUERTO)
}

async fn ping_servidor() -> bool {
    let url = format!("{}/health", base_url());
    tauri::async_runtime::spawn_blocking(move || {
        ureq::get(&url)
            .timeout(std::time::Duration::from_secs(3))
            .call()
            .map(|r| r.status() == 200)
            .unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

#[tauri::command]
pub async fn iniciar_ia_redaccion(
    state: tauri::State<'_, IaRedaccionState>,
) -> Result<String, String> {
    // Ya activo → no relanzar
    if *state.estado.lock().await == "activo" {
        return Ok("activo".into());
    }

    let modelo = ruta_modelo();
    if !modelo.exists() {
        let msg = format!(
            "Modelo no encontrado en {}. Descárgalo primero.",
            modelo.display()
        );
        *state.estado.lock().await = format!("error:{msg}");
        return Err(msg);
    }

    // Matar proceso anterior si existía
    if let Some(mut p) = state.proceso.lock().await.take() {
        let _ = p.kill().await;
        sleep(Duration::from_millis(500)).await;
    }

    *state.estado.lock().await = "cargando".into();

    let hilos = num_cpus::get().min(6).to_string();
    let modelo_str = modelo.to_string_lossy().to_string();

    // Apple Silicon: /opt/homebrew — Intel Mac: /usr/local
    let llama_bin = if std::path::Path::new("/opt/homebrew/bin/llama-server").exists() {
        "/opt/homebrew/bin/llama-server"
    } else {
        "/usr/local/bin/llama-server"
    };

    let child = Command::new(llama_bin)
        .args([
            "--model",        &modelo_str,
            "--host",         HOST,
            "--port",         &PUERTO.to_string(),
            "--ctx-size",     "4096",
            "--n-gpu-layers", "99",   // Metal GPU en macOS ARM
            "--threads",      &hilos,
            "--parallel",     "1",   // Un slot (un usuario a la vez)
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| {
            let msg = format!("No se pudo arrancar llama-server: {e}");
            // Si falla el spawn, actualizar estado para no quedar en "cargando"
            // (no podemos await aquí, usamos try_lock como mejor esfuerzo)
            if let Ok(mut est) = state.estado.try_lock() {
                *est = format!("error:{msg}");
            }
            msg
        })?;

    *state.proceso.lock().await = Some(child);

    // Esperar respuesta — hasta 2 minutos (carga inicial del modelo)
    for _ in 0..60u32 {
        sleep(Duration::from_millis(2000)).await;

        // Salir limpiamente si alguien llamó parar_ia_redaccion mientras cargaba
        if *state.estado.lock().await == "inactivo" {
            return Ok("parado".into());
        }

        if ping_servidor().await {
            *state.estado.lock().await = "activo".into();
            return Ok("activo".into());
        }
    }

    // Timeout — matar proceso y reportar error
    if let Some(mut p) = state.proceso.lock().await.take() {
        let _ = p.kill().await;
    }
    let msg = "El modelo no respondió en 2 minutos. Comprueba que ~/Babel/modelos_ia/Qwen3-4B-Q4_K_M.gguf existe y hay suficiente RAM.".to_string();
    *state.estado.lock().await = format!("error:{msg}");
    Err(msg)
}

#[tauri::command]
pub async fn parar_ia_redaccion(
    state: tauri::State<'_, IaRedaccionState>,
) -> Result<(), String> {
    if let Some(mut p) = state.proceso.lock().await.take() {
        p.kill().await.map_err(|e| e.to_string())?;
    }
    *state.estado.lock().await = "inactivo".into();
    Ok(())
}

#[tauri::command]
pub async fn estado_ia_redaccion(
    state: tauri::State<'_, IaRedaccionState>,
) -> Result<String, String> {
    Ok(state.estado.lock().await.clone())
}

#[tauri::command]
pub async fn enviar_mensaje_ia(
    mensaje: String,
    state: tauri::State<'_, IaRedaccionState>,
) -> Result<String, String> {
    if *state.estado.lock().await != "activo" {
        return Err("El asistente no está activo.".into());
    }

    // /no_think desactiva el modo razonamiento encadenado de Qwen3
    let body = serde_json::json!({
        "model": "qwen3",
        "messages": [
            {
                "role": "system",
                "content": "/no_think Eres Babel, un asistente de redacción de documentos en español. Respondes de forma clara, directa y concisa en español. Solo redactas y editas texto."
            },
            {
                "role": "user",
                "content": mensaje
            }
        ],
        "temperature": 0.7,
        "max_tokens": 2048,
        "stream": false
    });

    let url = format!("{}/v1/chat/completions", base_url());
    let body_str = body.to_string();

    let raw = tauri::async_runtime::spawn_blocking(move || {
        ureq::post(&url)
            .set("Content-Type", "application/json")
            .timeout(std::time::Duration::from_secs(120))
            .send_string(&body_str)
            .map_err(|e| format!("Error al contactar el asistente: {e}"))?
            .into_string()
            .map_err(|e| format!("Error leyendo respuesta: {e}"))
    })
    .await
    .map_err(|e| format!("Error de tarea interna: {e}"))??;

    let json: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("Respuesta inesperada del modelo: {e}"))?;

    let content = json["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("")
        .to_string();

    Ok(limpiar_thinking(&content))
}

// Qwen3 puede incluir <think>…</think> aunque /no_think esté activo
fn limpiar_thinking(texto: &str) -> String {
    if let (Some(i), Some(j)) = (texto.find("<think>"), texto.find("</think>")) {
        if i < j {
            return texto[j + "</think>".len()..]
                .trim_start_matches('\n')
                .trim()
                .to_string();
        }
    }
    texto.trim().to_string()
}
