use std::path::PathBuf;
use tauri::Emitter;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

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
                    alertas.push(format!("\"{}\" ({}\" tiene máximo {} días)", texto[frag_start..frag_end].trim(), mes, max_dias));
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

fn preparar_mensaje(mensaje: &str) -> String {
    let alertas = detectar_fechas_imposibles(mensaje);
    if alertas.is_empty() {
        format!("{}{}", PREFIJO_CONTROL, mensaje)
    } else {
        let aviso = alertas.join("; ");
        format!(
            "[ALERTA PREVIA DEL SISTEMA: Se detectaron fechas de calendario imposibles en el texto: {}. \
Señálaselas al usuario antes de continuar. No uses esas fechas en la redacción.]\n{}{}",
            aviso, PREFIJO_CONTROL, mensaje
        )
    }
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
            "--ctx-size",     "8192",
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
REGLA 1 — DATOS FALTANTES: Si detectas que falta un dato necesario (fecha, nombre, cantidad, referencia, cláusula, etc.) para completar lo solicitado, DETENTE y pídeselo al usuario ANTES de redactar nada. No empieces a redactar y luego pongas marcadores [PENDIENTE]; primero pregunta, luego redacta solo si el usuario responde o elige una de las opciones de la REGLA 2. Indica con precisión qué dato falta y para qué parte del documento es necesario.\n\
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
\n\
CONFIDENCIALIDAD ENTRE DOCUMENTOS:\n\
Nunca incluir en el documento generado información de un expediente o caso distinto al que se está trabajando en la sesión actual. Cada sesión es completamente aislada: no uses datos, nombres, cifras ni contexto de conversaciones anteriores. Si el usuario menciona frases como \"el caso anterior\", \"el cliente anterior\", \"como hicimos antes\", \"aplica las mismas condiciones\", \"igual que el anterior\", \"el contrato que hicimos\", \"el expediente anterior\" o cualquier referencia a trabajo previo fuera de esta sesión, DETENTE y responde: \"No tengo acceso a sesiones o documentos anteriores. Cada sesión es independiente. Por favor, proporciona los datos del documento actual directamente.\"\n\
\n\
Responde siempre en español.";

const PREFIJO_CONTROL: &str = "\
[CONTROL OBLIGATORIO — sigue estos pasos EN ORDEN antes de escribir cualquier respuesta]\n\
PASO 0 — SESIÓN AISLADA: Si el usuario menciona «sesión anterior», «caso anterior», «cliente anterior», «expediente anterior», «contrato anterior», «documento anterior», «como hicimos antes», «el contrato que hicimos», «trabajo anterior» o «lo que hicimos», responde únicamente: «No tengo acceso a sesiones o documentos anteriores. Cada sesión es completamente independiente. Proporciona los datos del documento actual.»\n\
PASO 1 — DATOS FALTANTES: ¿Falta algún dato necesario (fecha, nombre, cantidad, referencia)? Si falta → PREGUNTA AHORA, no redactes nada todavía.\n\
PASO 2 — TEXTO ILEGIBLE: ¿Hay texto corrupto, símbolos extraños, bloques ilegibles o códigos sin sentido (ej. caracteres tipo █▓▒░ o secuencias como XКΘΛ-29)? Si los hay → cítalos literalmente y declara que no puedes reconocerlos ni usarlos.\n\
PASO 3 — CONTRADICCIONES (dos comprobaciones secuenciales):\n\
COMPROBACIÓN A — IMPORTES: Busca pares «importe en letras + cifra numérica» (ej. «CINCO MIL euros (8.500 €)», «quinientos euros (500 €)»). Para cada par: convierte las letras a número (CIEN=100, DOSCIENTOS=200, TRESCIENTOS=300, CUATROCIENTOS=400, QUINIENTOS=500, SEISCIENTOS=600, SETECIENTOS=700, OCHOCIENTOS=800, NOVECIENTOS=900, MIL=1.000, CINCO MIL=5.000, DIEZ MIL=10.000…) y compara ese valor con la cifra numérica. Escribe: «[letras] → [valor_calculado] / cifra=[cifra]: COINCIDE» o «[letras] → [valor_calculado] / cifra=[cifra]: NO COINCIDE». Ejemplo correcto: «QUINIENTOS euros → 500 / cifra=500: COINCIDE». Ejemplo de error: «CINCO MIL euros → 5.000 / cifra=8.500: NO COINCIDE». En cuanto escribas «NO COINCIDE» → tu respuesta continúa SOLAMENTE con: «⚠ Contradicción de importe: el texto dice [letras] ([valor_calculado] €) pero la cifra es [cifra]. ¿Cuál es el dato correcto?» — y PARA. Si todos los pares COINCIDEN, escribe «A: sin contradicciones» y pasa a B.\n\
COMPROBACIÓN B — FECHAS (solo si A terminó con «A: sin contradicciones»): Localiza TODAS las fechas «DD de MES». Días máximos: enero/marzo/mayo/julio/agosto/octubre/diciembre=31; abril/junio/septiembre/noviembre=30; febrero=29. Por cada fecha escribe «[fecha]: VÁLIDA» o «[fecha]: IMPOSIBLE». En cuanto escribas «IMPOSIBLE» → tu respuesta continúa SOLAMENTE con: «⚠ Fecha imposible: [fecha completa]. [mes] tiene como máximo [N] días. ¿Cuál es la fecha correcta?» — y PARA.\n\
PASO 4 — INSTRUCCIÓN VS. DOCUMENTO: (a) ¿La instrucción es ambigua o incompleta? → pide aclaración. (b) ¿La instrucción pide cambiar, sustituir o ignorar un dato que ya figura en el documento (plazo, precio, nombre, fecha)? → avisa: \"El documento indica [dato original]. La instrucción pide [dato nuevo]. ¿Confirmas este cambio?\"\n\
CONTROL FINAL — ANTES DE GENERAR CUALQUIER TEXTO: ¿Alguno de los pasos 0-4 detectó un problema? Si la respuesta es SÍ → NO GENERES NINGUNA PARTE DEL DOCUMENTO. Ni un encabezado, ni un párrafo, ni una sola línea del borrador. Escribe SOLO el aviso del problema y espera la respuesta del usuario. Si la respuesta es NO → procede a redactar con exactamente lo solicitado, sin añadir cláusulas, secciones ni contenido extra.\n\
---\n\
SOLICITUD DEL USUARIO: ";

#[tauri::command]
pub async fn enviar_mensaje_ia_stream(
    mensaje: String,
    state: tauri::State<'_, IaRedaccionState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
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
        "max_tokens": 2048,
        "stream": true
    });

    let url = format!("{}/v1/chat/completions", base_url());
    let body_str = body.to_string();

    tauri::async_runtime::spawn_blocking(move || {
        use std::io::BufRead;

        let response = ureq::post(&url)
            .set("Content-Type", "application/json")
            .timeout(std::time::Duration::from_secs(120))
            .send_string(&body_str)
            .map_err(|e| {
                let msg = format!("Error al contactar el asistente: {e}");
                let _ = app.emit("ia-stream-error", &msg);
                msg
            })?;

        let reader = std::io::BufReader::new(response.into_reader());

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    let msg = format!("Error leyendo stream: {e}");
                    let _ = app.emit("ia-stream-error", &msg);
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
                        let _ = app.emit("ia-token", content);
                    }
                }
                if json["choices"][0]["finish_reason"].as_str() == Some("stop") {
                    break;
                }
            }
        }

        let _ = app.emit("ia-stream-fin", ());
        Ok::<(), String>(())
    })
    .await
    .map_err(|e| format!("Error de tarea interna: {e}"))
    .and_then(|r| r)
}

// Qwen3 puede incluir <think>…</think> aunque /no_think esté activo.
// Elimina todos los bloques (puede haber más de uno).
fn limpiar_thinking(texto: &str) -> String {
    let mut resultado = texto.to_string();
    loop {
        match (resultado.find("<think>"), resultado.find("</think>")) {
            (Some(i), Some(j)) if i < j => {
                let fin = j + "</think>".len();
                resultado = format!("{}{}", &resultado[..i], &resultado[fin..]);
            }
            _ => break,
        }
    }
    resultado.trim().to_string()
}
