use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use tauri::{Emitter, Manager};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

use crate::ia_biblioteca;

// PID del proceso llama-server activo. 0 = no corriendo.
// Permite que rat_detector lo mate de forma síncrona sin acceder al estado Tauri.
static LLAMA_PID: AtomicU32 = AtomicU32::new(0);

/// Mata llama-server inmediatamente si está corriendo. Llamado por rat_detector
/// al detectar acceso remoto, sin esperar a que el hilo async libere el Mutex del proceso.
pub fn matar_llama_si_activo() {
    let pid = LLAMA_PID.swap(0, Ordering::AcqRel);
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
    log::warn!("[IA] llama-server (PID {}) detenido por detección RAT.", pid);
}

fn detectar_fechas_imposibles(texto: &str) -> Vec<String> {
    let meses = [
        ("enero", 31u32), ("febrero", 29), ("marzo", 31),
        ("abril", 30), ("mayo", 31), ("junio", 30),
        ("julio", 31), ("agosto", 31), ("septiembre", 30),
        ("octubre", 31), ("noviembre", 30), ("diciembre", 31),
    ];
    let texto_lower = texto.to_lowercase();
    let mut alertas = Vec::new();
    for (mes, max_dias) in &meses {
        // Busca "NN de MES" con el día antes del nombre del mes
        let patron = format!(" de {}", mes);
        let mut pos = 0;
        while let Some(idx) = texto_lower[pos..].find(&patron) {
            let abs = pos + idx;
            // Extrae hasta 2 dígitos justo antes del " de mes"
            let antes = texto_lower[..abs].trim_end();
            let dia_str: String = antes.chars().rev().take_while(|c| c.is_ascii_digit()).collect::<String>().chars().rev().collect();
            if let Ok(dia) = dia_str.parse::<u32>() {
                if dia > *max_dias || dia == 0 {
                    // Captura el fragmento original (no lowercased) para la alerta
                    let frag_start = abs.saturating_sub(3);
                    let frag_end = (abs + patron.len() + 5).min(texto.len());
                    alertas.push(format!("\"{}\" ({} tiene máximo {} días)", texto[frag_start..frag_end].trim(), mes, max_dias));
                }
            }
            pos = abs + patron.len();
        }
    }
    alertas
}

fn es_bisiesto(anio: u32) -> bool {
    (anio.is_multiple_of(4) && !anio.is_multiple_of(100)) || anio.is_multiple_of(400)
}

fn max_dias_febrero(anio: Option<u32>) -> u32 {
    match anio {
        Some(a) => if es_bisiesto(a) { 29 } else { 28 },
        None => 29, // conservador: no alertar si no se conoce el año
    }
}

fn detectar_fechas_palabras_imposibles(texto: &str) -> Vec<String> {
    // Nombres de día en palabras — más largas primero para evitar coincidencias parciales
    const PALABRAS_DIA: &[(&str, u32)] = &[
        ("treinta y uno", 31), ("treinta", 30),
        ("veintinueve", 29), ("veintiocho", 28), ("veintisiete", 27),
        ("veintiseis", 26), ("veinticinco", 25), ("veinticuatro", 24),
        ("veintitres", 23), ("veintidos", 22), ("veintiuno", 21),
        ("veinte", 20), ("diecinueve", 19), ("dieciocho", 18),
        ("diecisiete", 17), ("dieciseis", 16), ("quince", 15),
        ("catorce", 14), ("trece", 13), ("doce", 12), ("once", 11),
        ("diez", 10), ("nueve", 9), ("ocho", 8), ("siete", 7),
        ("seis", 6), ("cinco", 5), ("cuatro", 4), ("tres", 3),
        ("dos", 2), ("primero", 1), ("uno", 1),
    ];
    const MESES: &[(&str, usize)] = &[
        ("enero", 0), ("febrero", 1), ("marzo", 2), ("abril", 3),
        ("mayo", 4), ("junio", 5), ("julio", 6), ("agosto", 7),
        ("septiembre", 8), ("octubre", 9), ("noviembre", 10), ("diciembre", 11),
    ];
    const MAX_POR_MES: [u32; 12] = [31, 0, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    // to_lowercase() no cambia longitudes en bytes para español (á→á, é→é…)
    // por lo que los índices en texto_lower coinciden con texto
    let texto_lower = texto.to_lowercase();
    let mut alertas = Vec::new();

    for (mes_nombre, mes_idx) in MESES {
        let patron = format!(" de {}", mes_nombre);
        let mut pos = 0;
        while let Some(idx) = texto_lower[pos..].find(&patron) {
            let abs = pos + idx;
            let antes_lower = &texto_lower[..abs];

            // Normalizar acentos solo para búsqueda de palabras (no para indexar texto original)
            let antes_norm: String = antes_lower
                .replace('á', "a").replace('é', "e").replace('í', "i")
                .replace('ó', "o").replace(['ú', 'ü'], "u");
            let antes_trim = antes_norm.trim_end();

            // Si ya termina en dígito → lo gestiona detectar_fechas_imposibles
            if antes_trim.chars().last().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                pos = abs + patron.len();
                continue;
            }

            // Buscar el nombre de día más largo que encaje al final de antes_trim
            let mut encontrado: Option<(u32, &str)> = None;
            for (palabra, dia) in PALABRAS_DIA {
                if antes_trim.ends_with(palabra) {
                    let boundary = antes_trim.len() - palabra.len();
                    let frontera_ok = boundary == 0
                        || antes_trim[..boundary]
                            .chars().last()
                            .map(|c| !c.is_alphabetic())
                            .unwrap_or(true);
                    if frontera_ok {
                        encontrado = Some((*dia, palabra));
                        break;
                    }
                }
            }

            if let Some((dia, palabra_dia)) = encontrado {
                // Intentar extraer año de 4 dígitos tras el nombre del mes
                let despues = abs + patron.len();
                let anio: Option<u32> = {
                    let r = texto_lower[despues..]
                        .trim_start_matches([' ', '\t'])
                        .trim_start_matches("de ")
                        .trim_start();
                    let s: String = r.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if s.len() == 4 { s.parse().ok() } else { None }
                };

                let max = if *mes_idx == 1 {
                    max_dias_febrero(anio)
                } else {
                    MAX_POR_MES[*mes_idx]
                };

                if dia > max {
                    alertas.push(format!(
                        "\"{}\" ({} tiene máximo {} días)",
                        format!("{} de {}", palabra_dia, mes_nombre),
                        mes_nombre, max
                    ));
                }
            }
            pos = abs + patron.len();
        }
    }
    alertas
}

fn detectar_referencia_sesion_anterior(texto: &str) -> bool {
    let t = texto.to_lowercase()
        .replace('á', "a").replace('é', "e").replace('í', "i")
        .replace('ó', "o").replace('ú', "u");
    let frases = [
        "sesion anterior", "caso anterior", "cliente anterior",
        "expediente anterior", "contrato anterior", "documento anterior",
        "como hicimos antes", "el contrato que hicimos",
        "trabajo anterior", "lo que hicimos",
    ];
    frases.iter().any(|f| t.contains(f))
}

// Tope de caracteres del mensaje del usuario (incluye el documento que la interfaz
// antepone). Con ctx=16384 y max_tokens=1536, tras restar system+prefijo+RAG (~6K
// tokens) y un margen, quedan ~8K tokens ≈ ~24 000 caracteres para el mensaje. Pasarse
// haría que llama.cpp rechace la petición con HTTP 400 (exceed_context_size_error).
const MAX_MENSAJE_CHARS: usize = 24_000;

/// Trunca en un límite de carácter UTF-8 válido, añadiendo un aviso visible si recorta.
fn acotar_mensaje(mensaje: &str) -> std::borrow::Cow<'_, str> {
    if mensaje.chars().count() <= MAX_MENSAJE_CHARS {
        return std::borrow::Cow::Borrowed(mensaje);
    }
    let recortado: String = mensaje.chars().take(MAX_MENSAJE_CHARS).collect();
    log::warn!(
        "[IA] mensaje/documento demasiado largo ({} chars) — truncado a {} para no exceder el contexto",
        mensaje.chars().count(),
        MAX_MENSAJE_CHARS
    );
    std::borrow::Cow::Owned(format!(
        "{recortado}\n\n[AVISO DEL SISTEMA: el documento era demasiado largo y se ha \
recortado para poder procesarlo. Trabaja solo con la parte incluida y advierte al \
usuario de que faltan páginas.]"
    ))
}

fn preparar_mensaje(mensaje_original: &str) -> String {
    let mensaje_acotado = acotar_mensaje(mensaje_original);
    let mensaje = mensaje_acotado.as_ref();

    let mut alertas = detectar_fechas_imposibles(mensaje);
    alertas.extend(detectar_fechas_palabras_imposibles(mensaje));
    if !alertas.is_empty() {
        let aviso = alertas.join("; ");
        // Cuando hay ALERTA no se incluye el PREFIJO_CONTROL completo:
        // sus ejemplos de importes confunden al modelo, que los procesa
        // como si fueran contenido del documento en vez de instrucciones.
        return format!(
            "[ALERTA PREVIA DEL SISTEMA — PARADA INMEDIATA]\n\
El texto del usuario contiene fechas de calendario imposibles: {aviso}\n\
Tu única respuesta debe ser señalar cada fecha imposible indicada arriba y preguntar \
al usuario cuál es la fecha correcta. No hagas ningún otro análisis. \
No uses esas fechas en la redacción.\n\
---\n\
TEXTO DEL USUARIO: {mensaje}"
        );
    }

    // RAG: recuperar artículos relevantes de la biblioteca jurídica local.
    // El bloque se inyecta DESPUÉS de la solicitud como contexto suplementario.
    // Presupuesto: ~6000 chars ≈ 1500 tokens (dentro del límite 8192 del contexto).
    let (normativa, _) = ia_biblioteca::buscar_normativa(mensaje, 6000);

    format!(
        "{}\n---\nSOLICITUD DEL USUARIO: {}\n\n{}",
        PREFIJO_CONTROL, mensaje, normativa
    )
}

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

// Modelos candidatos EN ORDEN DE PREFERENCIA. El Q4_K_M (~2.5 GB) es más ligero y
// mucho más rápido en CPU — clave para Macs sin GPU utilizable (p. ej. MacBook Neo,
// A18 Pro) y con 8 GB. Si no está, se cae al Q6_K (~3.1 GB, máxima calidad).
const MODELOS_CANDIDATOS: &[&str] = &[
    "Qwen3-4B-Q4_K_M.gguf",
    "Qwen3-4B-Q6_K.gguf",
];

// Nombre por defecto para el mensaje de error si no se encuentra ninguno.
const NOMBRE_MODELO: &str = MODELOS_CANDIDATOS[0];

// Busca el primer modelo candidato presente en: 1) Resources/modelos_ia/ (bundle),
// 2) ~/Babel/modelos_ia/. Devuelve la primera coincidencia según MODELOS_CANDIDATOS.
fn ruta_modelo(app: &tauri::AppHandle) -> PathBuf {
    let mut dirs_busqueda: Vec<PathBuf> = Vec::new();
    if let Ok(res) = app.path().resource_dir() {
        dirs_busqueda.push(res.join("modelos_ia"));
    }
    dirs_busqueda.push(
        dirs::home_dir()
            .unwrap_or_default()
            .join("Babel")
            .join("modelos_ia"),
    );

    for dir in &dirs_busqueda {
        for nombre in MODELOS_CANDIDATOS {
            let ruta = dir.join(nombre);
            if ruta.exists() {
                return ruta;
            }
        }
    }

    // Ninguno encontrado: devolver la ruta esperada del preferido para el mensaje de error.
    dirs_busqueda
        .into_iter()
        .next()
        .unwrap_or_default()
        .join(NOMBRE_MODELO)
}

// Busca llama-server en: 1) Resources/binaries/ (bundle USB), 2) Homebrew
fn ruta_llama_server(app: &tauri::AppHandle) -> String {
    if let Ok(res) = app.path().resource_dir() {
        let bundled = res.join("binaries").join("llama-server");
        if bundled.exists() {
            return bundled.to_string_lossy().into_owned();
        }
    }
    if std::path::Path::new("/opt/homebrew/bin/llama-server").exists() {
        return "/opt/homebrew/bin/llama-server".into();
    }
    "/usr/local/bin/llama-server".into()
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
    app: tauri::AppHandle,
    state: tauri::State<'_, IaRedaccionState>,
) -> Result<String, String> {
    crate::rat_detector::verificar_no_bloqueado_rat()?;

    // Ya activo → no relanzar
    if *state.estado.lock().await == "activo" {
        return Ok("activo".into());
    }

    // EXCLUSIÓN MUTUA: liberar la RAM del traductor Python (SMaLL-100, ~1-2 GB) antes
    // de cargar Qwen. En equipos de 8 GB ambos no caben a la vez y la coexistencia
    // provoca swap → la IA tarda minutos en responder. Al matarlo, SERVIDOR_ESTADO
    // vuelve a 0 y el traductor se relanzará solo cuando el usuario regrese a él.
    crate::matar_servidor_traduccion();

    let modelo = ruta_modelo(&app);
    if !modelo.exists() {
        let msg = format!(
            "Modelo no encontrado en {}. Descárgalo primero.",
            modelo.display()
        );
        *state.estado.lock().await = format!("error:{msg}");
        return Err(msg);
    }

    // Matar proceso anterior si existía en esta sesión
    if let Some(mut p) = state.proceso.lock().await.take() {
        let _ = p.kill().await;
        LLAMA_PID.store(0, Ordering::Release);
        sleep(Duration::from_millis(500)).await;
    }
    // Matar cualquier llama-server huérfano de sesiones anteriores que ocupe el puerto
    let puerto_ia_ocupado = std::net::TcpStream::connect_timeout(
        &format!("{}:{}", HOST, PUERTO).parse::<std::net::SocketAddr>().unwrap(),
        std::time::Duration::from_millis(300),
    ).is_ok();
    if puerto_ia_ocupado {
        let _ = std::process::Command::new("pkill").args(["-KILL", "-f", "llama-server"]).output();
        sleep(Duration::from_millis(1500)).await;
    }

    *state.estado.lock().await = "cargando".into();

    // Pre-warm the legal library BM25 index while the model loads (~200 ms once)
    tauri::async_runtime::spawn_blocking(ia_biblioteca::precalentar);

    // Hilos para llama-server: usar todos los núcleos MENOS uno. Dejar un núcleo libre
    // evita que la generación acapare la CPU y «congele» la interfaz. Antes se topaba a
    // 4 (conservador); en el A18 Pro del Neo (6 núcleos) esto sube a 5, acelerando
    // prefill y generación. Mínimo 4 para no quedarnos cortos en equipos de 2 núcleos.
    let hilos = num_cpus::get().saturating_sub(1).max(4).to_string();
    let modelo_str = modelo.to_string_lossy().to_string();
    let llama_bin = ruta_llama_server(&app);
    let puerto_str = PUERTO.to_string();

    // Al instalar desde DMG en otro Mac, macOS aplica com.apple.quarantine a todos
    // los archivos del bundle pero solo lo limpia del ejecutable principal al aprobar
    // la app. Los binarios en Resources/binaries/ retienen la quarantine y macOS
    // bloquea su ejecución (Gatekeeper mata el proceso con SIGKILL). Eliminarla
    // explícitamente antes de lanzar y registrar el resultado: si falla (bundle
    // read-only por App Translocation, permisos), el proceso morirá al arrancar y
    // el diagnóstico del log lo dejará claro.
    #[cfg(target_os = "macos")]
    {
        match std::process::Command::new("xattr")
            .args(["-d", "com.apple.quarantine", &llama_bin])
            .output()
        {
            Ok(o) if o.status.success() => {}
            Ok(_) => log::debug!("[IA] xattr quarantine ya limpio o no presente en llama-server"),
            Err(e) => log::warn!("[IA] no se pudo ejecutar xattr sobre llama-server: {e}"),
        }
    }

    let log_path = crate::babel_dir().join("llama-server.log");

    // Arranque con reintento GPU → CPU. Primero intentamos con Metal (--n-gpu-layers 99),
    // que es rápido en Macs con GPU utilizable. Si el proceso muere al cargar (p. ej.
    // "no usable GPU found" en chips A-series antiguos como el A18 Pro del MacBook Neo,
    // cuya GPU este build de llama.cpp no reconoce), reintentamos en CPU puro
    // (--n-gpu-layers 0): más lento pero funciona en cualquier Mac.
    // Recordar entre sesiones qué backend funcionó. En Macs sin GPU utilizable (p. ej.
    // el A18 Pro del MacBook Neo) el intento con Metal SIEMPRE falla y obliga a cargar
    // el modelo de 2,3 GB dos veces (GPU→CPU), duplicando el tiempo de arranque y la
    // sensación de «congelado». Si la última vez ganó CPU, arrancamos directo en CPU.
    let hint_path = crate::babel_dir().join("ia_backend.txt");
    let hint = std::fs::read_to_string(&hint_path).unwrap_or_default();
    let intentos: Vec<(&str, &str)> = if hint.trim() == "cpu" {
        log::info!("[IA] backend recordado: CPU — se omite el intento de GPU");
        vec![("0", "CPU")]
    } else {
        vec![("99", "GPU (Metal)"), ("0", "CPU")]
    };
    let mut ultimo_error = String::new();

    for (i, (gpu_layers, etiqueta)) in intentos.iter().enumerate() {
        *state.estado.lock().await = "cargando".into();
        log::info!("[IA] Arrancando llama-server en modo {etiqueta} (--n-gpu-layers {gpu_layers})");

        match arrancar_llama(
            &state, &llama_bin, &modelo_str, &puerto_str, &hilos, gpu_layers, &log_path,
        )
        .await
        {
            Arranque::Activo => {
                // Persistir el backend ganador para la próxima sesión.
                let _ = std::fs::write(&hint_path, if *gpu_layers == "0" { "cpu" } else { "gpu" });
                *state.estado.lock().await = "activo".into();
                return Ok("activo".into());
            }
            Arranque::Parado => return Ok("parado".into()),
            Arranque::Fallo(msg) => {
                ultimo_error = msg;
                if i + 1 < intentos.len() {
                    log::warn!(
                        "[IA] Arranque en {etiqueta} falló ({ultimo_error}). Reintentando en CPU…"
                    );
                    // Asegurar que el proceso muerto quedó recogido y el puerto libre
                    if let Some(mut p) = state.proceso.lock().await.take() {
                        let _ = p.kill().await;
                    }
                    LLAMA_PID.store(0, Ordering::Release);
                    sleep(Duration::from_millis(1000)).await;
                }
            }
        }
    }

    let msg = format!("El asistente de IA no pudo arrancar. {ultimo_error}");
    log::error!("[IA] {msg}");
    *state.estado.lock().await = format!("error:{msg}");
    Err(msg)
}

/// Resultado de un intento de arranque de llama-server.
enum Arranque {
    Activo,
    Parado,        // el usuario canceló mientras cargaba
    Fallo(String), // razón del fallo (incluye cola del log)
}

/// Lanza llama-server con el número de capas GPU indicado y espera hasta que
/// responda, muera, o el usuario cancele. Captura stdout+stderr en `log_path`.
#[allow(clippy::too_many_arguments)]
async fn arrancar_llama(
    state: &IaRedaccionState,
    llama_bin: &str,
    modelo_str: &str,
    puerto_str: &str,
    hilos: &str,
    gpu_layers: &str,
    log_path: &std::path::Path,
) -> Arranque {
    // Capturar stdout+stderr de llama-server en ~/Babel/llama-server.log. Antes se
    // descartaban (Stdio::null) y cualquier fallo de arranque (dylib ausente, RAM
    // insuficiente, quarantine, GPU no válida, modelo corrupto) era invisible: el
    // usuario esperaba 5 minutos hasta un timeout genérico. Con el log reportamos
    // la causa real y decidimos si reintentar en CPU.
    let log_stdout = std::fs::File::create(log_path).ok();
    let log_stderr = log_stdout.as_ref().and_then(|f| f.try_clone().ok());

    let mut cmd = Command::new(llama_bin);
    cmd.args([
        "--model",        modelo_str,
        "--host",         HOST,
        "--port",         puerto_str,
        // system(~2K)+prefijo(~2K)+RAG(~1.7K) ya gastan ~6K; con un documento cargado
        // el prompt supera fácilmente 8192 → llama.cpp devuelve HTTP 400
        // (exceed_context_size_error). 16384 da holgura para documentos medianos.
        // KV en q4_0 mantiene el coste de RAM bajo (~590 MB a 16K, cabe en 8 GB).
        "--ctx-size",     "16384",
        "--n-gpu-layers", gpu_layers,
        "--threads",      hilos,
        "--parallel",     "1",
        "--flash-attn",   "on",    // menos pico de memoria en atención
        "--cache-type-k", "q4_0",  // KV cache quantizado: −857 MB wired vs f16
        "--cache-type-v", "q4_0",
        // El SYSTEM_PROMPT (~2K tokens) es un prefijo CONSTANTE en cada petición.
        // --cache-reuse deja que el slot reaproveche el KV ya calculado de ese prefijo
        // común en vez de re-hacer el prefill entero cada mensaje. En CPU (Macs sin GPU
        // utilizable) eso ahorra varios segundos de latencia por turno, sin coste de RAM.
        "--cache-reuse",  "256",
    ]);
    // ggml carga sus backends (Metal, CPU por chip, BLAS) como plugins .so en runtime.
    // Van empaquetados JUNTO a llama-server (Resources/binaries/) y ggml escanea el
    // directorio del propio ejecutable, así que los encuentra sin Homebrew. Sin esos
    // .so no hay backend alguno → "no usable GPU found" + fallo de carga del modelo.
    // (No usamos GGML_BACKEND_PATH: espera la ruta a UN fichero .so, no una carpeta.)

    match (log_stdout, log_stderr) {
        (Some(out), Some(err)) => { cmd.stdout(out).stderr(err); }
        _ => { cmd.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()); }
    }

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return Arranque::Fallo(format!("No se pudo ejecutar llama-server: {e}")),
    };

    // Registrar PID antes de mover el child al Mutex para que rat_detector pueda
    // matarlo de forma síncrona sin necesitar acceso al estado Tauri.
    if let Some(pid) = child.id() {
        LLAMA_PID.store(pid, Ordering::Release);
    }
    *state.proceso.lock().await = Some(child);

    // Esperar respuesta — hasta 5 minutos (Qwen 3.1 GB en CPU puede tardar más)
    for _ in 0..150u32 {
        sleep(Duration::from_millis(2000)).await;

        // Salir limpiamente si alguien llamó parar_ia_redaccion mientras cargaba
        if *state.estado.lock().await == "inactivo" {
            return Arranque::Parado;
        }

        // Detectar muerte temprana del proceso: si llama-server salió, no tiene
        // sentido esperar 5 minutos. Devolvemos la causa real del log para que el
        // llamador decida si reintentar (p. ej. GPU → CPU).
        let salida = {
            let mut guard = state.proceso.lock().await;
            match guard.as_mut().and_then(|c| c.try_wait().ok().flatten()) {
                Some(status) => {
                    *guard = None;
                    Some(status)
                }
                None => None,
            }
        };
        if let Some(status) = salida {
            LLAMA_PID.store(0, Ordering::Release);
            let detalle = leer_cola_log(log_path);
            return Arranque::Fallo(format!("llama-server terminó ({status}). {detalle}"));
        }

        if ping_servidor().await {
            return Arranque::Activo;
        }
    }

    // Timeout — matar proceso y reportar
    if let Some(mut p) = state.proceso.lock().await.take() {
        let _ = p.kill().await;
        LLAMA_PID.store(0, Ordering::Release);
    }
    Arranque::Fallo(format!(
        "El modelo no respondió en 5 minutos. {}",
        leer_cola_log(log_path)
    ))
}

/// Lee las últimas líneas del log de llama-server para incluir la causa real del
/// fallo en el mensaje de error mostrado al usuario. Devuelve cadena vacía si no
/// hay log o no contiene nada útil.
fn leer_cola_log(log_path: &std::path::Path) -> String {
    let contenido = match std::fs::read_to_string(log_path) {
        Ok(c) => c,
        Err(_) => return String::new(),
    };
    let cola: Vec<&str> = contenido
        .lines()
        .filter(|l| !l.trim().is_empty())
        .rev()
        .take(3)
        .collect();
    if cola.is_empty() {
        return String::new();
    }
    let mut lineas: Vec<&str> = cola;
    lineas.reverse();
    format!("Detalle técnico: {}", lineas.join(" | "))
}

#[tauri::command]
pub async fn parar_ia_redaccion(
    state: tauri::State<'_, IaRedaccionState>,
) -> Result<(), String> {
    if let Some(mut p) = state.proceso.lock().await.take() {
        // Ignorar error: el proceso puede haber sido matado ya por matar_llama_si_activo
        // (detección RAT) antes de que llegue esta llamada desde el frontend.
        let _ = p.kill().await;
        LLAMA_PID.store(0, Ordering::Release);
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
    crate::rat_detector::verificar_no_bloqueado_rat()?;

    if *state.estado.lock().await != "activo" {
        return Err("El asistente no está activo.".into());
    }

    if detectar_referencia_sesion_anterior(&mensaje) {
        return Ok("No tengo acceso a sesiones o documentos anteriores. Cada sesión es completamente independiente. Proporciona los datos del documento actual.".into());
    }

    let mensaje_con_prefijo = preparar_mensaje(&mensaje);
    let body = serde_json::json!({
        "model": "qwen3",
        "messages": [
            { "role": "system", "content": SYSTEM_PROMPT },
            { "role": "user",   "content": mensaje_con_prefijo }
        ],
        "temperature": 0.3,
        "top_p": 0.9,
        "min_p": 0.05,
        "max_tokens": 1536,
        "repeat_penalty": 1.1,
        "stream": false
    });

    let url = format!("{}/v1/chat/completions", base_url());
    let body_str = body.to_string();

    let raw = tauri::async_runtime::spawn_blocking(move || {
        ureq::post(&url)
            .set("Content-Type", "application/json")
            .timeout(std::time::Duration::from_secs(600)) // amplio: en CPU (Macs sin GPU utilizable) la generación es lenta
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

    // Aplicar el mismo pipeline de limpieza que el modo streaming
    let limpio = limpiar_pasos_internos(&limpiar_thinking(&content));
    Ok(limpio.lines().map(limpiar_md).collect::<Vec<_>>().join("\n").trim().to_string())
}

const SYSTEM_PROMPT: &str = "/no_think Eres Babel, asistente de redacción documental y jurídica. \
Jerarquía de prioridades ESTRICTA:\n\
1. EXACTITUD: No inventes datos, fechas, cantidades, nombres ni hechos.\n\
2. FIDELIDAD: Usa únicamente la información del documento original proporcionado.\n\
3. ESTRUCTURA: Organiza el texto de forma clara y coherente.\n\
4. CALIDAD JURÍDICA: Lenguaje preciso y apropiado al contexto.\n\
5. ESTILO: Redacción cuidada y fluida.\n\
\n\
REGLAS OBLIGATORIAS DE COMPORTAMIENTO:\n\
\n\
REGLA 0 — PARADA OBLIGATORIA ANTE CONTRADICCIONES (PRIORIDAD MÁXIMA SOBRE TODAS LAS DEMÁS REGLAS): Si en cualquier momento de tu análisis detectas que dos datos del documento no pueden ser ciertos al mismo tiempo (un número que no coincide con su versión literal, una fecha que no existe en el calendario, un dato que contradice a otro del mismo documento), DETENTE INMEDIATAMENTE. No generes ningún texto de documento — ni un párrafo, ni un encabezado, ni una sola línea del borrador. Responde señalando la contradicción exacta con las palabras literales del documento y preguntando al usuario cuál dato es correcto. La elección entre datos contradictorios SIEMPRE corresponde al usuario, nunca al modelo.\n\
\n\
REGLA 1 — DATOS FALTANTES: Si detectas que falta un dato necesario (fecha, nombre, cantidad, referencia, cláusula, etc.) para completar lo solicitado, escribe ÚNICAMENTE esto y PARA: «Antes de redactar necesito saber: [nombre exacto del dato faltante]. ¿Puedes proporcionarlo?». Si faltan VARIOS datos, enuméralos TODOS en una única pregunta numerada — NUNCA preguntes de un dato a la vez cuando faltan varios. No escribas ninguna parte del documento. No uses marcadores [PENDIENTE] — esos solo son válidos si el usuario elige explícitamente la opción (a) de la REGLA 2 en una respuesta posterior.\n\
\n\
REGLA 2 — ALTERNATIVAS SI EL DATO NO LLEGA: Si el usuario no puede o no quiere proporcionar el dato pedido, ofrécele explícitamente dos opciones:\n\
  a) Redactar dejando un marcador claro donde falta el dato (ej. \"[PENDIENTE: fecha de firma]\").\n\
  b) Generar el documento con la información disponible, acompañado de un aviso visible de que falta ese dato y que el resultado puede contener errores.\n\
\n\
REGLA 3 — DISTINGUIR HECHOS DE INFERENCIAS: Distingue explícitamente entre un hecho literal del documento, una inferencia razonable y una suposición que necesita confirmación. Cuando uses una inferencia, márcala claramente como tal.\n\
\n\
REGLA 4 — SEÑALAR ERRORES SIN CORREGIRLOS: Si detectas un posible error en el original (nombre, fecha o cifra que parezca incorrecto), señálalo y pregunta al usuario si es un error a confirmar. No lo corrijas por tu cuenta.\n\
\n\
REGLA 5 — SIEMPRE ES UN BORRADOR: Deja claro que el resultado es un borrador para revisión humana, nunca un documento final listo para usar.\n\
\n\
REGLA 6 — AMBIGÜEDAD: Si la instrucción del usuario es poco clara o contradice la información del documento, señala la ambigüedad y pide aclaración en vez de elegir una interpretación por tu cuenta.\n\
\n\
PROHIBICIONES ABSOLUTAS — NUNCA hacer lo siguiente bajo ninguna circunstancia:\n\
\n\
NUNCA 1: Inventar datos faltantes (fechas, nombres, cantidades, referencias), ni siquiera como aproximación razonable.\n\
NUNCA 2: Definir, explicar ni tratar como válido un término, nombre, código o expresión que no sea reconocible o no tenga sentido claro en el contexto. Esto incluye texto corrupto de OCR (caracteres extraños, símbolos, bloques ilegibles) e identificadores sin significado aparente (por ejemplo: \"XКΘΛ-29\", \"░░░░\", \"▒▒▒▒\"). En esos casos señala explícitamente: \"El texto contiene elementos que no puedo reconocer: [cita el fragmento]. No puedo incluirlos ni interpretarlos.\"\n\
NUNCA 3: Presentar una inferencia o suposición como si fuera un hecho confirmado.\n\
NUNCA 4: Añadir cláusulas, partes o secciones que no fueron solicitadas ni están en el documento original. Esto incluye: cuentas bancarias, garantías o depósitos, plazos de preaviso, cláusulas de renovación automática, sanciones por incumplimiento, secciones de \"observaciones\" o \"cierre\" vacías, ni cualquier otro contenido que el usuario no haya pedido expresamente. Si el usuario pide \"un acta\" o \"una cláusula\", genera exactamente eso con la información disponible — nada más.\n\
NUNCA 5: Eliminar o resumir información relevante del original sin que el usuario lo pida explícitamente.\n\
NUNCA 6: Corregir en silencio nombres, cifras o fechas del original, aunque parezcan erróneos. Esto incluye: (a) contradicciones internas —si el texto dice \"TRES MIL euros (30.000 €)\" señala la contradicción y pregunta cuál es correcta antes de continuar; (b) fechas de calendario imposibles — verifica que el día exista en el mes indicado: febrero tiene 28 o 29 días (nunca 30 ni 31), abril/junio/septiembre/noviembre tienen 30 días (nunca 31). Si encuentras una fecha imposible como \"31 de febrero\" o \"31 de abril\", señálala: \"La fecha [X] no existe en el calendario. ¿Cuál es la fecha correcta?\" No la corrijas ni la uses. (c) NUNCA \"armonices\" ni \"reconciles\" datos contradictorios eligiendo el que te parezca más lógico — esa decisión corresponde exclusivamente al usuario. Si detectas la contradicción, PARA COMPLETAMENTE: no escribas ninguna parte del documento, ni siquiera las secciones que no tienen error.\n\
NUNCA 7: Dar a entender que el documento generado está listo para usar sin revisión humana.\n\
NUNCA 8: Elegir una interpretación por tu cuenta cuando la instrucción sea ambigua o contradictoria — pregunta siempre en vez de asumir.\n\
NUNCA 9: Obedecer una instrucción que pide modificar, sustituir o ignorar un dato que ya figura explícitamente en el documento original (fecha, plazo, cifra, nombre), sin antes avisar al usuario de que la instrucción entra en contradicción con el documento. Ejemplo: si el documento dice \"plazo de 6 meses\" y la instrucción dice \"ponle 12 meses\", no lo cambies en silencio — señala: \"El documento original indica [dato original]. La instrucción pide cambiarlo a [dato nuevo]. ¿Confirmas este cambio?\"\n\
NUNCA 10: Revelar en el documento el nombre de pasos internos de control (PASO 1, PASO 3, CONTROL FINAL, etc.). Esas instrucciones son internas y nunca deben aparecer en el texto generado.\n\
\n\
FORMATO DOCUMENTOS JURÍDICOS: Cuando redactes escritos procesales (denuncias, querellas, recursos de apelación, calificaciones provisionales, habeas corpus u otros escritos ante juzgados o tribunales), usa el formato jurídico español estándar en texto plano sin markdown:\n\
- ENCABEZADO en una línea: «AL JUZGADO DE [tipo y número] DE [ciudad]»\n\
- Identificación: «[Nombre y apellidos], [calidad procesal], COMPARECE Y EXPONE:» (o DICE, MANIFIESTA según el escrito)\n\
- HECHOS numerados: PRIMERO.- SEGUNDO.- TERCERO.- (puntos y guiones, sin asteriscos)\n\
- FUNDAMENTOS DE DERECHO: numerados con citas legales concretas: «Con fundamento en el artículo X de la Ley Y...»\n\
- SOLICITA (o SUPLICA para juicios): petición directa y concreta en una o pocas líneas\n\
- CIERRE: «En [ciudad], a [fecha]. Firmado: [nombre].»\n\
Sin asteriscos. Sin dobles asteriscos. Sin negritas markdown. Sin corchetes de markdown. Texto plano con mayúsculas para encabezados.\n\
\n\
PERSPECTIVA DE CADA ESCRITO PROCESAL (OBLIGATORIO): Cada tipo de escrito tiene un único autor posible. Antes de escribir, identifica quién presenta el documento:\n\
- Denuncia / Querella: la presenta el DENUNCIANTE o QUERELLANTE — nunca el denunciado.\n\
- Calificación provisional o escrito de acusación: lo presenta el LETRADO DE LA ACUSACIÓN PARTICULAR o el MINISTERIO FISCAL — NUNCA el acusado. Encabezado correcto: «D./Dña. [letrado o acusador], en nombre y representación de [víctima/perjudicado], EXPONE:»\n\
- Escrito de defensa / Calificación de la defensa: lo presenta el LETRADO DEFENSOR en nombre del acusado.\n\
- Habeas corpus: lo presenta el LETRADO DEFENSOR o un familiar del DETENIDO, en nombre del detenido.\n\
- Recurso de apelación: lo presenta quien recurre, claramente identificado.\n\
NUNCA escribas «[nombre del acusado], acusado, EXPONE:» en un escrito de acusación.\n\
\n\
CONFIDENCIALIDAD ENTRE DOCUMENTOS:\n\
Nunca incluir en el documento generado información de un expediente o caso distinto al que se está trabajando en la sesión actual. Cada sesión es completamente aislada: no uses datos, nombres, cifras ni contexto de conversaciones anteriores. Si el usuario menciona frases como \"el caso anterior\", \"el cliente anterior\", \"como hicimos antes\", \"aplica las mismas condiciones\", \"igual que el anterior\", \"el contrato que hicimos\", \"el expediente anterior\" o cualquier referencia a trabajo previo fuera de esta sesión, DETENTE y responde: \"No tengo acceso a sesiones o documentos anteriores. Cada sesión es independiente. Por favor, proporciona los datos del documento actual directamente.\"\n\
\n\
Responde siempre en español.";

const PREFIJO_CONTROL: &str = "\
[CONTROL OBLIGATORIO — sigue estos pasos EN ORDEN antes de escribir cualquier respuesta]\n\
PASO 0 — SESIÓN AISLADA: Si el usuario menciona «sesión anterior», «caso anterior», «cliente anterior», «expediente anterior», «contrato anterior», «documento anterior», «como hicimos antes», «el contrato que hicimos», «trabajo anterior» o «lo que hicimos», responde únicamente: «No tengo acceso a sesiones o documentos anteriores. Cada sesión es completamente independiente. Proporciona los datos del documento actual.»\n\
PASO 1 — DATOS FALTANTES: Para ESCRITOS PROCESALES (denuncias, querellas, recursos, calificaciones, habeas corpus): los datos mínimos son nombre de las partes, destino (juzgado/tribunal), fecha del escrito y descripción de los hechos. Datos opcionales como DNI, número de colegiado, antecedentes, datos bancarios o testigos → usa [COMPLETAR: descripción] sin bloquear. FORMATO OBLIGATORIO del escrito: empieza SIEMPRE con «AL JUZGADO DE [tipo y número] DE [ciudad]» como primera línea, seguido de la identificación del presentador y su calidad procesal. REGLA CRÍTICA PARA DATOS FALTANTES: si falta MÁS DE UN dato mínimo, LISTA TODOS en una única respuesta numerada — por ejemplo: «Para redactar la denuncia necesito: 1. Nombre de las partes (denunciante y denunciado) 2. Juzgado de destino 3. Fecha del escrito 4. Descripción de los hechos». NUNCA preguntes un dato a la vez cuando faltan varios. Para cualquier otro documento: si falta un dato imprescindible → pregunta al usuario en una única respuesta con todos los datos faltantes. No inventes datos ni uses [PENDIENTE] salvo que el usuario lo pida explícitamente.\n\
PASO 2 — TEXTO ILEGIBLE: ¿Hay texto corrupto, símbolos extraños, bloques ilegibles o códigos sin sentido (ej. caracteres tipo █▓▒░ o secuencias como XКΘΛ-29)? Si los hay → cítalos literalmente y declara que no puedes reconocerlos ni usarlos.\n\
PASO 3 — CONTRADICCIONES (dos comprobaciones secuenciales):\n\
COMPROBACIÓN A — IMPORTES: Busca pares «importe en letras + cifra numérica» (ej. «CINCO MIL euros (8.500 €)», «quinientos euros (500 €)»). Un par solo existe cuando el texto contiene EXPLÍCITAMENTE las palabras del importe seguidas de su cifra entre paréntesis. Para cada par: convierte las letras a número (CIEN=100, DOSCIENTOS=200, TRESCIENTOS=300, CUATROCIENTOS=400, QUINIENTOS=500, SEISCIENTOS=600, SETECIENTOS=700, OCHOCIENTOS=800, NOVECIENTOS=900, MIL=1.000, CINCO MIL=5.000, DIEZ MIL=10.000…) y compara ese valor con la cifra numérica. Escribe: «[letras] → [valor_calculado] / cifra=[cifra]: COINCIDE» o «[letras] → [valor_calculado] / cifra=[cifra]: NO COINCIDE». Ejemplo correcto: «QUINIENTOS euros → 500 / cifra=500: COINCIDE». Ejemplo de error: «CINCO MIL euros → 5.000 / cifra=8.500: NO COINCIDE». En cuanto escribas «NO COINCIDE» → tu respuesta continúa SOLAMENTE con: «⚠ Contradicción de importe: el texto dice [letras] ([valor_calculado] €) pero la cifra es [cifra]. ¿Cuál es el dato correcto?» — y PARA. Si el texto solo tiene cifras numéricas sin versión escrita en palabras (ej. «1.800 €» sola, «12.000 €» sola), no hay par — escribe «A: sin contradicciones» directamente y pasa a B. Si todos los pares COINCIDEN, escribe «A: sin contradicciones» y pasa a B.\n\
COMPROBACIÓN B — FECHAS (solo si A terminó con «A: sin contradicciones»): Localiza TODAS las fechas, tanto en números («31 de septiembre») como escritas en palabras («treinta y uno de septiembre», «veintinueve de febrero», «treinta y uno de abril»). Convierte las palabras a número cuando sea necesario: uno=1, dos=2, tres=3, cuatro=4, cinco=5, seis=6, siete=7, ocho=8, nueve=9, diez=10, once=11, doce=12, trece=13, catorce=14, quince=15, dieciséis=16, diecisiete=17, dieciocho=18, diecinueve=19, veinte=20, veintiuno=21, veintidós=22, veintitrés=23, veinticuatro=24, veinticinco=25, veintiséis=26, veintisiete=27, veintiocho=28, veintinueve=29, treinta=30, treinta y uno=31. Días máximos por mes: enero/marzo/mayo/julio/agosto/octubre/diciembre=31; abril/junio/septiembre/noviembre=30; febrero=29 (nunca 30 ni 31). Por cada fecha escribe «[fecha]: VÁLIDA» o «[fecha]: IMPOSIBLE». En cuanto escribas «IMPOSIBLE» → tu respuesta continúa SOLAMENTE con: «⚠ Fecha imposible: [fecha completa tal como aparece en el texto]. [mes] tiene como máximo [N] días. ¿Cuál es la fecha correcta?» — y PARA.\n\
PASO 4 — INSTRUCCIÓN VS. DOCUMENTO: (a) ¿La instrucción es ambigua o incompleta? → pide aclaración. (b) Si la instrucción pide cambiar un dato que ya figura en el documento (plazo, precio, nombre, fecha, condición) → avisa: «⚠ Conflicto: el documento indica [dato original]. La instrucción pide [dato nuevo]. ¿Confirmas este cambio?» y enumera TODOS los conflictos antes de parar.\n\
CONTROL FINAL — ANTES DE GENERAR CUALQUIER TEXTO: ¿Alguno de los pasos 0-4 detectó un problema? Si la respuesta es SÍ → NO GENERES NINGUNA PARTE DEL DOCUMENTO. Ni un encabezado, ni un párrafo, ni una sola línea del borrador. Escribe SOLO el aviso del problema y espera la respuesta del usuario. Si la respuesta es NO → procede a redactar con exactamente lo solicitado, sin añadir cláusulas, secciones ni contenido extra.";

#[tauri::command]
pub async fn enviar_mensaje_ia_stream(
    mensaje: String,
    state: tauri::State<'_, IaRedaccionState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    crate::rat_detector::verificar_no_bloqueado_rat()?;

    if *state.estado.lock().await != "activo" {
        return Err("El asistente no está activo.".into());
    }

    if detectar_referencia_sesion_anterior(&mensaje) {
        let _ = app.emit("ia-token", "No tengo acceso a sesiones o documentos anteriores. Cada sesión es completamente independiente. Proporciona los datos del documento actual.");
        let _ = app.emit("ia-stream-fin", ());
        return Ok(());
    }

    let mensaje_con_prefijo = preparar_mensaje(&mensaje);
    let body = serde_json::json!({
        "model": "qwen3",
        "messages": [
            { "role": "system", "content": SYSTEM_PROMPT },
            { "role": "user",   "content": mensaje_con_prefijo }
        ],
        "temperature": 0.3,
        "top_p": 0.9,
        "min_p": 0.05,
        "max_tokens": 1536,
        "repeat_penalty": 1.1,
        "stream": true
    });

    let url = format!("{}/v1/chat/completions", base_url());
    let body_str = body.to_string();

    tauri::async_runtime::spawn_blocking(move || {
        use std::io::BufRead;

        let response = ureq::post(&url)
            .set("Content-Type", "application/json")
            .timeout(std::time::Duration::from_secs(600)) // amplio: en CPU (Macs sin GPU utilizable) la generación es lenta
            .send_string(&body_str)
            .map_err(|e| {
                let msg = format!("Error al contactar el asistente: {e}");
                let _ = app.emit("ia-stream-error", &msg);
                msg
            })?;

        let reader = std::io::BufReader::new(response.into_reader());

        // Buffer por línea para filtrar encabezados de control interno (PASO N, CONTROL FINAL…)
        // antes de emitir al frontend. Los tokens llegan fragmentados; acumulamos hasta '\n'.
        let mut line_buf = String::new();
        // Estado para filtrar bloques <think>…</think> en streaming.
        // Qwen3 puede emitirlos incluso con /no_think activo; los acumulamos sin emitir.
        let mut en_think = false;
        let mut think_buf = String::new();

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    let msg = format!("Error leyendo stream: {e}");
                    let _ = app.emit("ia-stream-error", &msg);
                    // Vaciar buffer pendiente antes de salir (solo si no estamos en bloque think)
                    if !en_think && !line_buf.is_empty() && !es_linea_interna(&line_buf) {
                        let clean = limpiar_md(&line_buf);
                        if !clean.is_empty() {
                            let _ = app.emit("ia-token", clean);
                        }
                    }
                    return Err(msg);
                }
            };

            if !line.starts_with("data: ") {
                continue;
            }
            let data = &line[6..];
            if data == "[DONE]" {
                break;
            }

            if let Ok(json) = serde_json::from_str::<serde_json::Value>(data) {
                // Solo emitir delta.content; delta.reasoning_content es el thinking de Qwen3
                if let Some(content) = json["choices"][0]["delta"]["content"].as_str() {
                    if !content.is_empty() {
                        // Acumular el contenido recibido en el buffer de thinking para detectar
                        // <think> / </think> que pueden llegar partidos entre varios chunks.
                        think_buf.push_str(content);

                        // Procesar think_buf: extraer partes fuera de <think>…</think>
                        loop {
                            if en_think {
                                // Buscamos </think> para salir del bloque
                                if let Some(fin) = think_buf.find("</think>") {
                                    think_buf = think_buf[fin + "</think>".len()..].to_string();
                                    en_think = false;
                                } else {
                                    // Todavía dentro del bloque — descartar y esperar más datos
                                    think_buf.clear();
                                    break;
                                }
                            } else {
                                // Buscamos <think> para entrar en el bloque
                                if let Some(inicio) = think_buf.find("<think>") {
                                    // Emitir lo que haya ANTES del <think>
                                    let antes = think_buf[..inicio].to_string();
                                    think_buf = think_buf[inicio + "<think>".len()..].to_string();
                                    en_think = true;
                                    // Procesar 'antes' carácter a carácter
                                    for ch in antes.chars() {
                                        if ch == '\n' {
                                            if !es_linea_interna(&line_buf) {
                                                let clean = limpiar_md(&line_buf);
                                                if !clean.is_empty() {
                                                    let _ = app.emit("ia-token", format!("{clean}\n"));
                                                }
                                            }
                                            line_buf.clear();
                                        } else {
                                            line_buf.push(ch);
                                        }
                                    }
                                } else {
                                    // No hay <think>: procesar todo carácter a carácter
                                    let chunk = think_buf.clone();
                                    think_buf.clear();
                                    for ch in chunk.chars() {
                                        if ch == '\n' {
                                            if !es_linea_interna(&line_buf) {
                                                let clean = limpiar_md(&line_buf);
                                                if !clean.is_empty() {
                                                    let _ = app.emit("ia-token", format!("{clean}\n"));
                                                }
                                            }
                                            line_buf.clear();
                                        } else {
                                            line_buf.push(ch);
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
                if json["choices"][0]["finish_reason"].as_str() == Some("stop") {
                    break;
                }
            }
        }

        // Vaciar lo que quede en el buffer al terminar el stream (si no estamos en bloque think)
        if !en_think && !line_buf.is_empty() && !es_linea_interna(&line_buf) {
            let clean = limpiar_md(&line_buf);
            if !clean.is_empty() {
                let _ = app.emit("ia-token", clean);
            }
        }

        let _ = app.emit("ia-stream-fin", ());
        Ok::<(), String>(())
    })
    .await
    .map_err(|e| format!("Error de tarea interna: {e}"))
    .and_then(|r| r)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── detectar_fechas_palabras_imposibles ──────────────────────────────

    #[test]
    fn treinta_y_uno_septiembre_detectado() {
        let t = "contrata a Carlos Medina desde el treinta y uno de septiembre de 2025";
        let a = detectar_fechas_palabras_imposibles(t);
        assert!(!a.is_empty(), "debe detectar treinta y uno de septiembre");
        assert!(a[0].contains("treinta y uno"), "alerta debe citar la palabra día");
        assert!(a[0].contains("septiembre"),    "alerta debe citar el mes");
        assert!(a[0].contains("30"),            "alerta debe indicar máximo 30 días");
    }

    #[test]
    fn treinta_septiembre_es_valida() {
        // 30 ≤ 30: no debe alertar
        let t = "desde el treinta de septiembre de 2025";
        assert!(detectar_fechas_palabras_imposibles(t).is_empty());
    }

    #[test]
    fn veintinueve_de_febrero_bisiesto_ok() {
        // 2024 es bisiesto: 29 feb válido
        let t = "el veintinueve de febrero de 2024";
        assert!(detectar_fechas_palabras_imposibles(t).is_empty());
    }

    #[test]
    fn veintinueve_de_febrero_no_bisiesto_alerta() {
        // 2025 no es bisiesto: 29 feb inválido
        let t = "el veintinueve de febrero de 2025";
        let a = detectar_fechas_palabras_imposibles(t);
        assert!(!a.is_empty(), "29 feb 2025 debe alertar");
    }

    #[test]
    fn digito_no_lo_detecta_funcion_palabras() {
        // "31 de septiembre" en dígitos: esta función lo omite (lo gestiona detectar_fechas_imposibles)
        let t = "desde el 31 de septiembre de 2025";
        assert!(detectar_fechas_palabras_imposibles(t).is_empty());
    }

    #[test]
    fn treinta_y_uno_abril_detectado() {
        let t = "plazo hasta el treinta y uno de abril de 2025";
        let a = detectar_fechas_palabras_imposibles(t);
        assert!(!a.is_empty(), "treinta y uno de abril debe alertar");
    }

    // ── es_bisiesto ──────────────────────────────────────────────────────

    #[test]
    fn bisiesto_2024() { assert!(es_bisiesto(2024)); }
    #[test]
    fn no_bisiesto_2025() { assert!(!es_bisiesto(2025)); }
    #[test]
    fn bisiesto_2000() { assert!(es_bisiesto(2000)); }   // divisible por 400
    #[test]
    fn no_bisiesto_1900() { assert!(!es_bisiesto(1900)); } // siglo no ÷400

    // ── preparar_mensaje ─────────────────────────────────────────────────

    #[test]
    fn preparar_mensaje_alerta_sin_prefijo_para_palabras() {
        let msg = "Formaliza este contrato desde el treinta y uno de septiembre de 2025. Salario 1.800 €.";
        let resultado = preparar_mensaje(msg);
        // Debe contener la cabecera de parada inmediata
        assert!(resultado.contains("PARADA INMEDIATA"), "debe incluir PARADA INMEDIATA");
        // Debe citar la fecha detectada
        assert!(resultado.contains("treinta y uno de septiembre"), "debe citar la fecha");
        // NO debe incluir el PREFIJO_CONTROL (para evitar que el modelo confunda ejemplos con documento)
        assert!(!resultado.contains("COMPROBACIÓN A"), "no debe incluir PREFIJO_CONTROL");
        assert!(!resultado.contains("SOLICITUD DEL USUARIO"), "no debe incluir PREFIJO_CONTROL");
    }

    #[test]
    fn preparar_mensaje_sin_alerta_incluye_prefijo() {
        let msg = "Redacta un contrato entre Ana y Luis, alquiler 600 €/mes, inicio 1 enero 2025.";
        let resultado = preparar_mensaje(msg);
        assert!(resultado.contains("SOLICITUD DEL USUARIO"), "sin alerta debe incluir PREFIJO_CONTROL");
        assert!(!resultado.contains("PARADA INMEDIATA"), "sin alerta no debe incluir PARADA INMEDIATA");
    }

    // ── limpiar_thinking ────────────────────────────────────────────────
    #[test]
    fn thinking_completo_eliminado() {
        let r = limpiar_thinking("Hola <think>esto es interno</think> mundo");
        assert_eq!(r, "Hola  mundo".trim_end_matches(' ').trim());
    }

    #[test]
    fn thinking_sin_cierre_trunca_desde_apertura() {
        let r = limpiar_thinking("Texto visible <think>razonamiento sin cerrar");
        assert_eq!(r, "Texto visible");
    }

    #[test]
    fn thinking_multiple_bloques() {
        let r = limpiar_thinking("<think>a</think>res<think>b</think>puesta");
        assert_eq!(r, "respuesta");
    }

    #[test]
    fn alerta_fecha_digito_sin_comilla_suelta() {
        let alertas = detectar_fechas_imposibles("31 de febrero de 2025");
        assert!(!alertas.is_empty());
        // No debe contener comilla suelta: '("' seguido de letra
        assert!(!alertas[0].contains("(\""), "el mensaje de alerta no debe tener comilla suelta");
    }

    // ── es_linea_interna con prefijos markdown ───────────────────────────

    #[test]
    fn paso_con_negrita_detectado() {
        assert!(es_linea_interna("**PASO 1 — DATOS FALTANTES:**"), "debe detectar **PASO N");
        assert!(es_linea_interna("**PASO 2 — TEXTOS CORRUPTOS:**"));
    }

    #[test]
    fn paso_con_encabezado_detectado() {
        assert!(es_linea_interna("## PASO 3 — ALGO"), "debe detectar ## PASO N");
        assert!(es_linea_interna("# PASO 4 — OTRO"));
    }

    #[test]
    fn paso_plano_detectado() {
        assert!(es_linea_interna("PASO 1 — DATOS FALTANTES:"));
    }

    #[test]
    fn linea_normal_no_detectada() {
        assert!(!es_linea_interna("Los datos del contrato son los siguientes:"));
        assert!(!es_linea_interna("PASO es un ejemplo de lo que no debes hacer"));
        assert!(!es_linea_interna(""));
    }

    #[test]
    fn comprobacion_sin_tilde_detectada() {
        assert!(es_linea_interna("COMPROBACION A — importes"));
        assert!(es_linea_interna("COMPROBACION B — fechas"));
    }

}

// Qwen3 puede incluir <think>…</think> aunque /no_think esté activo.
// Elimina todos los bloques (puede haber más de uno).
// Si la etiqueta de apertura existe pero la de cierre falta (respuesta truncada),
// elimina desde <think> hasta el final del texto para evitar filtrar el razonamiento.
fn limpiar_thinking(texto: &str) -> String {
    let mut resultado = texto.to_string();
    loop {
        match (resultado.find("<think>"), resultado.find("</think>")) {
            (Some(i), Some(j)) if i < j => {
                let fin = j + "</think>".len();
                resultado = format!("{}{}", &resultado[..i], &resultado[fin..]);
            }
            (Some(i), _) => {
                // Etiqueta de cierre ausente — truncar desde <think>
                resultado = resultado[..i].to_string();
                break;
            }
            _ => break,
        }
    }
    resultado.trim().to_string()
}

// Devuelve true si la línea es un encabezado de control interno (PASO N —, CONTROL FINAL, etc.)
// que el modelo no debería revelar al usuario según NUNCA 10.
// Se eliminan prefijos markdown (**, ##) antes de comprobar, porque el modelo a veces
// formatea estas líneas con negrita o encabezado aunque se le indique texto plano.
fn es_linea_interna(linea: &str) -> bool {
    let raw = linea.trim();
    if raw.is_empty() {
        return false;
    }
    // Quitar prefijos markdown: "**", "## ", "# "
    let t = raw
        .trim_start_matches("**")
        .trim_start_matches("## ")
        .trim_start_matches("# ")
        .trim_start();
    t.starts_with("[CONTROL OBLIGATORIO")
        || t.starts_with("CONTROL FINAL")
        || t.starts_with("COMPROBACIÓN A")
        || t.starts_with("COMPROBACION A")
        || t.starts_with("COMPROBACIÓN B")
        || t.starts_with("COMPROBACION B")
        || (t.starts_with("PASO ")
            && t.as_bytes().get(5).map(|b| b.is_ascii_digit()).unwrap_or(false))
}

// Elimina markdown básico (negrita, subrayado, encabezados ##).
fn limpiar_md(s: &str) -> String {
    s.replace("**", "").replace("__", "").replace("## ", "").replace("##", "")
}

// Elimina líneas de control interno del texto completo (ruta no-streaming).
fn limpiar_pasos_internos(texto: &str) -> String {
    texto
        .lines()
        .filter(|l| !es_linea_interna(l))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}
