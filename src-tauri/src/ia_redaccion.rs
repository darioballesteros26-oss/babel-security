use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
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
///
/// SEGURIDAD DE PID: `LLAMA_PID` solo se resetea a 0 en rutas controladas (relanzar,
/// parar, timeout, muerte durante el arranque). Si llama-server crashea POR SU CUENTA
/// a mitad de sesión, el PID queda obsoleto; como el SO recicla PIDs, un SIGKILL ciego
/// podría matar a un proceso ajeno que haya heredado ese número. Por eso, antes de
/// matar, confirmamos que el proceso con ese PID sigue siendo realmente llama-server
/// (por el nombre del ejecutable). Si ya no existe o es otro programa, no hacemos nada.
pub fn matar_llama_si_activo() {
    let pid = LLAMA_PID.swap(0, Ordering::AcqRel);
    if pid == 0 {
        return;
    }
    if !es_proceso_llama(pid) {
        // PID obsoleto o reciclado por otro programa: NO tocarlo.
        log::debug!("[IA] PID {} ya no es llama-server; no se mata.", pid);
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
    log::warn!("[IA] llama-server (PID {}) detenido.", pid);
}

/// Comprueba que el proceso con este PID existe y es llama-server. Defensa contra
/// reciclaje de PID: solo confirma la identidad por el nombre del ejecutable.
fn es_proceso_llama(pid: u32) -> bool {
    use sysinfo::{Pid, PidExt, ProcessExt, System, SystemExt};
    let mut s = System::new();
    let spid = Pid::from_u32(pid);
    if !s.refresh_process(spid) {
        return false; // el proceso ya no existe
    }
    match s.process(spid) {
        Some(p) => p.name().contains("llama-server"),
        None => false,
    }
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
                        "\"{} de {}\" ({} tiene máximo {} días)",
                        palabra_dia, mes_nombre, mes_nombre, max
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

// Modelos candidatos EN ORDEN DE PREFERENCIA.
// Qwen3-4B-Instruct-2507 (ago. 2025) es un salto de calidad sobre el Qwen3-4B original
// (mejor seguimiento de instrucciones y redacción) MISMO tamaño y velocidad, y la
// variante Instruct NO «piensa» (no emite <think>), lo que encaja con /no_think y evita
// gastar tokens. Q4_K_M (~2.3 GB) para 8 GB; Q6_K (~3.1 GB, <4 GB) para 16 GB+.
// Se dejan los Qwen3-4B antiguos como RESPALDO: una instalación previa sigue funcionando
// hasta que se descargue el 2507 a ~/Babel/modelos_ia/.
const MODELOS_CANDIDATOS: &[&str] = &[
    "Qwen3-4B-Instruct-2507-Q4_K_M.gguf",
    "Qwen3-4B-Instruct-2507-Q6_K.gguf",
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

    // Iterar por PREFERENCIA DE MODELO primero (y dentro, por directorio): así el mejor
    // modelo disponible gana esté donde esté. Clave tras introducir el 2507: si el bundle
    // (Resources) aún trae el Qwen3-4B viejo pero ~/Babel/modelos_ia ya tiene el 2507
    // descargado, se usa el 2507 — sin necesidad de rehacer el DMG.
    for nombre in MODELOS_CANDIDATOS {
        for dir in &dirs_busqueda {
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

// Busca llama-server en: 1) Resources/binaries/ (bundle del DMG),
// 2) ~/Babel/ia_stack (persistido desde un DMG anterior; SOBREVIVE a las
// actualizaciones, que solo reemplazan el .app), 3) Homebrew (desarrollo).
pub(crate) fn ruta_llama_server(app: &tauri::AppHandle) -> String {
    if let Ok(res) = app.path().resource_dir() {
        let bundled = res.join("binaries").join("llama-server");
        if bundled.exists() {
            return bundled.to_string_lossy().into_owned();
        }
    }
    let persistente = crate::babel_dir()
        .join("ia_stack")
        .join("Resources")
        .join("binaries")
        .join("llama-server");
    if persistente.exists() {
        return persistente.to_string_lossy().into_owned();
    }
    if std::path::Path::new("/opt/homebrew/bin/llama-server").exists() {
        return "/opt/homebrew/bin/llama-server".into();
    }
    "/usr/local/bin/llama-server".into()
}

// ── Persistencia del stack de IA en ~/Babel (sobrevive a las actualizaciones) ─
// El .app.tar.gz del auto-update NO incluye el stack de IA (modelo Qwen +
// llama-server + backends ggml + dylibs, ~3 GB) para que el update pese poco. Por
// eso, al actualizar, una instalación hecha desde el DMG completo perdería la IA.
// Solución: la PRIMERA vez que arranca una build que SÍ trae el stack (instalación
// desde DMG), lo copiamos a ~/Babel; a partir de ahí la app lo encuentra ahí aunque
// una actualización reemplace el .app. Además deja el modelo DESACOPLADO: cambiarlo
// en el futuro es sustituir el fichero en ~/Babel, sin rehacer la app.
//
// Se replica la estructura del bundle para respetar los rpaths de llama-server
// (@loader_path/../../Frameworks): en ~/Babel/ia_stack/ van Resources/binaries/
// (llama-server + *.so) y Frameworks/ (*.dylib). El modelo va a ~/Babel/modelos_ia/
// (ruta_modelo ya lo busca ahí). NO son datos sensibles → permisos normales, no 0600.
static IA_PERSISTIDA: AtomicBool = AtomicBool::new(false);

fn copiar_dir_recursivo(origen: &std::path::Path, destino: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(destino)?;
    for entrada in std::fs::read_dir(origen)? {
        let entrada = entrada?;
        let tipo = entrada.file_type()?;
        let dst = destino.join(entrada.file_name());
        if tipo.is_dir() {
            copiar_dir_recursivo(&entrada.path(), &dst)?;
        } else if tipo.is_symlink() {
            // Copiar el fichero real al que apunta (evita symlinks colgantes en ~/Babel).
            let real = std::fs::read_link(entrada.path())?;
            let real_abs = if real.is_absolute() { real } else { origen.join(real) };
            if real_abs.is_file() {
                std::fs::copy(&real_abs, &dst)?;
            }
        } else {
            // fs::copy preserva los bits de permiso en Unix (llama-server queda 0755).
            std::fs::copy(entrada.path(), &dst)?;
        }
    }
    Ok(())
}

/// Copia el stack de IA del bundle a ~/Babel la primera vez (si el bundle lo trae y
/// ~/Babel aún no lo tiene). Idempotente y barato cuando ya está hecho. No hace nada
/// en builds de actualización (que no traen el stack) ni si ya se copió. Pesado
/// (~2,3 GB) solo la primera vez tras instalar un DMG → llamar en segundo plano.
pub fn asegurar_ia_persistente(app: &tauri::AppHandle) {
    if IA_PERSISTIDA.swap(true, Ordering::AcqRel) {
        return;
    }
    let res = match app.path().resource_dir() {
        Ok(r) => r,
        Err(_) => return,
    };
    let babel = crate::babel_dir();

    // IMPORTANTE: toda copia va primero a un destino TEMPORAL y solo al terminar se
    // renombra al definitivo (rename atómico, mismo volumen ~/Babel). Si la copia se
    // interrumpe (p. ej. cierran la app a mitad del primer arranque), el destino final
    // nunca llega a existir → en el siguiente arranque se reintenta. Sin esto, una copia
    // a medias dejaría un modelo/runtime incompleto pero "con aspecto de completo" que
    // el check de existencia daría por bueno y nunca se recopiaría (IA rota).

    // 1) Modelo → ~/Babel/modelos_ia/
    let destino_modelos = babel.join("modelos_ia");
    for nombre in MODELOS_CANDIDATOS {
        let origen = res.join("modelos_ia").join(nombre);
        let destino = destino_modelos.join(nombre);
        if origen.exists() && !destino.exists() {
            let _ = std::fs::create_dir_all(&destino_modelos);
            let tmp = destino_modelos.join(format!(".{nombre}.tmp"));
            let _ = std::fs::remove_file(&tmp); // restos de un intento anterior
            match std::fs::copy(&origen, &tmp).and_then(|_| std::fs::rename(&tmp, &destino)) {
                Ok(_) => log::info!("[IA] modelo persistido en {}", destino.display()),
                Err(e) => {
                    log::warn!("[IA] no se pudo persistir el modelo: {e}");
                    let _ = std::fs::remove_file(&tmp);
                }
            }
        }
    }

    // 2) Runtime (llama-server + backends ggml + dylibs) → ~/Babel/ia_stack/
    let llama_bundle = res.join("binaries").join("llama-server");
    let stack = babel.join("ia_stack");
    if llama_bundle.exists() && !stack.exists() {
        let tmp = babel.join(".ia_stack.tmp");
        let _ = std::fs::remove_dir_all(&tmp); // restos de un intento anterior
        let r_bin = copiar_dir_recursivo(
            &res.join("binaries"),
            &tmp.join("Resources").join("binaries"),
        );
        // Contents/Frameworks = el padre de Resources (resource_dir) → ../Frameworks.
        let r_fw = match res.parent().map(|c| c.join("Frameworks")) {
            Some(fw) if fw.exists() => copiar_dir_recursivo(&fw, &tmp.join("Frameworks")),
            _ => Ok(()),
        };
        match (r_bin, r_fw) {
            (Ok(()), Ok(())) => match std::fs::rename(&tmp, &stack) {
                Ok(()) => log::info!("[IA] runtime de IA persistido en {}", stack.display()),
                Err(e) => {
                    log::warn!("[IA] no se pudo renombrar el runtime de IA: {e}");
                    let _ = std::fs::remove_dir_all(&tmp);
                }
            },
            (b, f) => {
                log::warn!("[IA] fallo al persistir el runtime de IA: {:?} {:?}", b.err(), f.err());
                // Dejar a medias es peor que nada: limpiar el temporal para reintentar.
                let _ = std::fs::remove_dir_all(&tmp);
            }
        }
    }
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

// Pre-calienta el fichero del modelo en la caché de disco del sistema SIN instanciar
// el modelo. Objetivo: cuando el usuario abra el asistente, la carga lea el .gguf
// (~2,5 GB) desde RAM en vez de disco → se evita el «tirón» de I/O en frío. NO se
// retiene memoria del modelo (la caché de disco es desechable: el sistema la libera
// si el traductor necesita RAM), por lo que es seguro en equipos de 8 GB donde IA y
// traductor se excluyen mutuamente. No es «cargar medio modelo» (eso no existe:
// la inferencia necesita todas las capas); es calentar solo la lectura del fichero.
// Idempotente: solo se ejecuta una vez por sesión.
static PREFETCH_HECHO: AtomicBool = AtomicBool::new(false);

/// Lee el .gguf del modelo en segundo plano para dejarlo en la caché de disco.
/// Dispararlo al entrar en REDACTAR (antes de pulsar «iniciar asistente») hace que
/// el arranque posterior no sufra el pico de I/O de leer 2,5 GB en frío.
#[tauri::command]
pub async fn precalentar_modelo_ia(app: tauri::AppHandle) -> Result<(), String> {
    // Si el modelo ya está cargado/cargando, el fichero ya está en RAM: nada que hacer.
    if LLAMA_PID.load(Ordering::Acquire) != 0 {
        return Ok(());
    }
    // Sin modelo instalado: nada que precalentar. NO marcamos PREFETCH_HECHO aquí, para
    // que si el usuario instala el modelo más tarde en esta misma sesión el prefetch
    // pueda ejecutarse la primera vez que de verdad exista el fichero.
    let ruta = ruta_modelo(&app);
    if !ruta.exists() {
        return Ok(());
    }
    // Solo una vez por sesión: repetir no aporta (ya estaría en caché). Se marca aquí,
    // tras confirmar que hay algo que precalentar, no antes.
    if PREFETCH_HECHO.swap(true, Ordering::AcqRel) {
        return Ok(());
    }

    // Lectura secuencial descartando los bytes: trae las páginas del .gguf a la caché
    // de disco sin copiarlas a ninguna estructura que las retenga. En SSD son ~1-2 s.
    tauri::async_runtime::spawn_blocking(move || {
        use std::io::Read;
        let mut f = match std::fs::File::open(&ruta) {
            Ok(f) => f,
            Err(e) => {
                log::debug!("[IA] prefetch: no se pudo abrir el modelo: {e}");
                return;
            }
        };
        let mut buf = vec![0u8; 4 * 1024 * 1024]; // en heap: 4 MB en pila desbordaría
        let mut total: u64 = 0;
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => total += n as u64,
                Err(_) => break,
            }
        }
        log::info!("[IA] prefetch del modelo completado: {} MB en caché", total / (1024 * 1024));
    });

    Ok(())
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

    // Opción B: asegurar que el stack de IA está en ~/Babel (para que sobreviva a las
    // actualizaciones). Barato si ya se hizo; la primera vez (instalación desde DMG)
    // copia ~2,3 GB → en spawn_blocking para no bloquear el executor async.
    {
        let app2 = app.clone();
        let _ = tauri::async_runtime::spawn_blocking(move || asegurar_ia_persistente(&app2)).await;
    }

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
    // Calentar el embedder del RAG semántico (opción B) en paralelo, si está instalado,
    // para que la primera búsqueda no espere a que arranque. No pasa nada si no existe.
    tauri::async_runtime::spawn_blocking(|| {
        crate::ia_embeddings::asegurar_embedder();
    });

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
    //
    // CLAVE PARA METAL (GPU): ggml carga sus backends (libggml-metal.so, CPU, BLAS)
    // como plugins vía dlopen EN RUNTIME. Si esos .so conservan la cuarentena, macOS
    // se niega a cargarlos → "no usable GPU found" → la IA cae a CPU (8× más lenta en
    // prefill). Por eso NO basta con limpiar llama-server: hay que limpiar TODA la
    // carpeta de binarios (los .so) y Frameworks (los .dylib). Recursivo (-r).
    #[cfg(target_os = "macos")]
    {
        use std::path::Path;
        let binaries_dir = Path::new(&llama_bin)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_default();
        // Frameworks está en ../../Frameworks respecto a Resources/binaries (vale tanto
        // para el bundle .app como para el stack persistido en ~/Babel/ia_stack).
        let frameworks_dir = binaries_dir.join("..").join("..").join("Frameworks");
        for dir in [&binaries_dir, &frameworks_dir] {
            if !dir.exists() {
                continue;
            }
            match std::process::Command::new("xattr")
                .args(["-r", "-d", "com.apple.quarantine"])
                .arg(dir)
                .output()
            {
                Ok(o) if o.status.success() => log::info!("[IA] quarantine limpiada en {}", dir.display()),
                Ok(_) => log::debug!("[IA] quarantine ya limpia o ausente en {}", dir.display()),
                Err(e) => log::warn!("[IA] no se pudo limpiar quarantine en {}: {e}", dir.display()),
            }
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
    // El recuerdo lleva una ETIQUETA DE VERSIÓN ("cpu:v2"). Así, tras el fix de la
    // cuarentena de los .so (que desbloquea Metal), toda máquina que quedó clavada en
    // CPU con el formato antiguo ("cpu" a secas) vuelve a PROBAR Metal una vez: su hint
    // no coincide con "cpu:v2" → se intenta GPU primero. Si Metal funciona (debería en
    // cualquier Apple Silicon), se guarda "gpu:v2" y queda rápido para siempre.
    const HINT_VER: &str = "v2";
    let hint_path = crate::babel_dir().join("ia_backend.txt");
    let hint = std::fs::read_to_string(&hint_path).unwrap_or_default();
    let intentos: Vec<(&str, &str)> = if hint.trim() == format!("cpu:{HINT_VER}") {
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
                // Persistir el backend ganador (con etiqueta de versión) para la próxima sesión.
                let _ = std::fs::write(
                    &hint_path,
                    if *gpu_layers == "0" { format!("cpu:{HINT_VER}") } else { format!("gpu:{HINT_VER}") },
                );
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
    // Liberar también la RAM del embedder del RAG semántico (si estaba activo).
    crate::ia_embeddings::detener_embedder();
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
            { "role": "system", "content": system_prompt_con_fecha() },
            { "role": "user",   "content": mensaje_con_prefijo }
        ],
        "temperature": 0.2,
        "top_p": 0.9,
        "min_p": 0.05,
        "max_tokens": 1536,
        "repeat_penalty": 1.1,
        "grammar": GRAMMAR_SIN_MARKDOWN,
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

// ── RESUMEN POR BLOQUES (map-reduce) para documentos largos ──────────────────
// Un documento más largo que la ventana de contexto no cabe de una vez. En vez de
// recortarlo, lo leemos ENTERO por bloques: resumimos cada bloque conservando los
// datos clave y, si la unión de resúmenes sigue sin caber, repetimos (reduce).

// Si el documento cabe holgadamente de una vez, no se resume (se usa tal cual).
const UMBRAL_RESUMEN_CHARS: usize = 15_000;
// Tamaño de cada bloque que se envía al modelo para resumir.
const BLOQUE_RESUMEN_CHARS: usize = 12_000;
// Máximo de vueltas de reducción (evita bucles en documentos enormes).
const MAX_VUELTAS_RESUMEN: usize = 2;

const SYSTEM_RESUMEN: &str = "/no_think Eres un extractor de datos fiel. Recibes un FRAGMENTO de un \
documento más largo. Tu única tarea es extraer de forma COMPACTA todos los datos y hechos relevantes de \
ESTE fragmento: nombres, fechas, cantidades, cláusulas, obligaciones, plazos, referencias, identificadores \
y hechos. Copia los datos LITERALES tal cual aparecen (fechas, cifras y nombres exactos). NO inventes nada, \
NO añadas información que no esté en el fragmento, NO saques conclusiones ni redactes. Responde en español, \
en viñetas breves. Si el fragmento no contiene datos relevantes, responde «(sin datos relevantes)».";

// Divide el texto en bloques de ~`tam` caracteres, retrocediendo a un salto de línea
// o espacio para no cortar palabras/frases por la mitad.
fn dividir_en_bloques(texto: &str, tam: usize) -> Vec<String> {
    let chars: Vec<char> = texto.chars().collect();
    let mut bloques = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let mut fin = (i + tam).min(chars.len());
        if fin < chars.len() {
            let limite = i + tam / 2; // no retroceder más de la mitad del bloque
            let mut j = fin;
            while j > limite && chars[j] != '\n' && !chars[j].is_whitespace() {
                j -= 1;
            }
            if j > limite {
                fin = j;
            }
        }
        bloques.push(chars[i..fin].iter().collect());
        i = fin;
    }
    bloques
}

// Llamada no-streaming directa al modelo con un system prompt a medida (sin el
// PREFIJO_CONTROL ni RAG de la redacción: aquí solo queremos extraer datos).
async fn llamar_modelo_simple(system: &str, user: String, max_tokens: u32) -> Result<String, String> {
    let body = serde_json::json!({
        "model": "qwen3",
        "messages": [
            { "role": "system", "content": system },
            { "role": "user",   "content": user }
        ],
        "temperature": 0.2,
        "top_p": 0.9,
        "max_tokens": max_tokens,
        "stream": false
    });
    let url = format!("{}/v1/chat/completions", base_url());
    let body_str = body.to_string();

    let raw = tauri::async_runtime::spawn_blocking(move || {
        ureq::post(&url)
            .set("Content-Type", "application/json")
            .timeout(std::time::Duration::from_secs(600))
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
    Ok(limpiar_thinking(&content).trim().to_string())
}

/// Si el documento es más largo de lo que cabe en el contexto, lo resume ENTERO por
/// bloques (map-reduce) y devuelve el resumen; si cabe, lo devuelve sin tocar.
/// Emite `ia-resumen-progreso` por cada bloque para que la interfaz muestre el avance.
#[tauri::command]
pub async fn resumir_documento_si_largo(
    texto: String,
    state: tauri::State<'_, IaRedaccionState>,
    app: tauri::AppHandle,
) -> Result<String, String> {
    crate::rat_detector::verificar_no_bloqueado_rat()?;

    // Cabe de una vez → no hace falta resumir.
    if texto.chars().count() <= UMBRAL_RESUMEN_CHARS {
        return Ok(texto);
    }
    if *state.estado.lock().await != "activo" {
        return Err("El asistente no está activo.".into());
    }

    let mut nivel = texto;
    let mut vuelta = 0;
    loop {
        let bloques = dividir_en_bloques(&nivel, BLOQUE_RESUMEN_CHARS);
        let total = bloques.len();
        let mut resumenes = Vec::with_capacity(total);
        for (idx, bloque) in bloques.into_iter().enumerate() {
            let _ = app.emit(
                "ia-resumen-progreso",
                serde_json::json!({ "bloque": idx + 1, "total": total, "vuelta": vuelta + 1 }),
            );
            let user = format!("FRAGMENTO {}/{} del documento:\n\n{}", idx + 1, total, bloque);
            let resumen = llamar_modelo_simple(SYSTEM_RESUMEN, user, 800).await?;
            resumenes.push(format!("— Parte {}/{} —\n{}", idx + 1, total, resumen));
        }
        nivel = resumenes.join("\n\n");
        vuelta += 1;
        if nivel.chars().count() <= UMBRAL_RESUMEN_CHARS || vuelta >= MAX_VUELTAS_RESUMEN {
            break;
        }
    }

    let _ = app.emit("ia-resumen-progreso", serde_json::json!({ "fin": true }));
    Ok(format!(
        "[RESUMEN POR BLOQUES — Babel ha leído TODO el documento (demasiado largo para procesarlo de \
una sola vez) y ha extraído los datos clave de cada parte. Trabaja con estos datos; si necesitas un \
fragmento literal que no aparezca aquí, pídeselo al usuario.]\n\n{nivel}"
    ))
}

const SYSTEM_PROMPT: &str = "/no_think Eres Babel, asistente de redacción de documentos jurídicos en español. Tu única tarea es REDACTAR el documento que te piden. Eres un redactor, NO un auditor del caso.

PRINCIPIOS:
1. REDACTA directamente lo solicitado, empezando por el propio documento (sin preámbulos ni explicar lo que vas a hacer).
2. DA POR VÁLIDOS Y CIERTOS todos los datos que te dan (nombres, fechas, cifras, importes, referencias). Copia cada importe con EXACTAMENTE las mismas cifras que el usuario, sin añadir ni quitar dígitos: si dice «6500 euros» escribe «6500 euros» (no 65.000, no 650). Escribe los importes SOLO en cifras, nunca también en letra. No los reinterpretes, no los redondees, no los cambies.
3. NO BUSQUES PROBLEMAS donde no los hay. No cuestiones la viabilidad jurídica del caso ni pidas justificaciones. Ejemplos de lo que es NORMAL y NO debes objetar: un contrato firmado en un año anterior con rentas o pagos impagados recientes (los contratos se prorrogan: es lo habitual); un impago de varias mensualidades; datos personales corrientes. No pidas prórrogas, renovaciones, «bases jurídicas» ni documentos extra que el usuario no necesita aportar para que tú redactes.
4. Datos ESENCIALES son solo los que definen el documento: QUIÉN lo presenta y CONTRA quién, el OBJETO (qué se pide o se pacta) y los IMPORTES centrales. Nunca inventes uno de estos con un valor falso. Datos SECUNDARIOS (fecha de presentación o de firma, número de expediente o de factura, dirección exacta, datos de contacto, juzgado concreto) NO bloquean nada: si faltan, pon un hueco [COMPLETAR: descripción] y redacta igual; jamás son motivo para no redactar ni para preguntar. Si te piden una PLANTILLA, MODELO o datos «de ejemplo», rellena todo con ejemplos o huecos [COMPLETAR] y redacta sin preguntar.
5. ELIGE UNA SOLA CONDUCTA, nunca las dos a la vez: (a) si tienes los datos ESENCIALES (partes, objeto e importes centrales), redacta el documento COMPLETO y no preguntes nada —si falta algún dato secundario pon [COMPLETAR] dentro del texto—; (b) solo si te FALTAN los datos esenciales (p. ej. no sabes ni quién reclama ni cuánto) y no es una plantilla, responde SOLO con una única pregunta que los enumere, sin redactar todavía ni un borrador con huecos.
6. ESTRUCTURA SEGÚN EL TIPO DE DOCUMENTO: un contrato no lleva encabezado judicial; una demanda, denuncia o recurso se dirige al juzgado o tribunal; una carta, burofax o reclamación es una comunicación. Apóyate en los MODELOS y la NORMATIVA adjuntos como guía de estructura.
7. En escritos procesales identifica bien quién los presenta: una acusación la presenta el acusador, nunca el acusado; una defensa, el letrado del acusado.
8. CITA la ley con «art. X ABREV» (por ejemplo art. 1902 CC) y la jurisprudencia como «STC X/AAAA», tomándolas SOLO de la NORMATIVA adjunta; no cites de memoria ni inventes el contenido de un artículo.
9. SOLO avisa con una línea que empiece por «ATENCIÓN:» si un dato es IMPOSIBLE en sí mismo (una fecha que no existe en el calendario, o dos cifras del propio usuario que se contradicen entre sí). En ese caso redacta igualmente marcando el dato como [REVISAR]. Un dato que simplemente te parezca alto, bajo o inusual NO es motivo de aviso: úsalo tal cual. NO objetes NUNCA que una fecha sea futura o pasada: cualquier fecha que exista en el calendario es válida, úsala sin comentarios. Si no hay ningún dato imposible, NO escribas NINGUNA línea «ATENCIÓN» ni comentario sobre la coherencia o viabilidad del caso: termina con el documento y nada más. NUNCA uses «ATENCIÓN» para señalar datos o documentos que falten; para eso usa [COMPLETAR] dentro del texto.
10. El resultado es SIEMPRE un borrador para revisión humana.

CONFIDENCIALIDAD: cada sesión es independiente; no uses datos de casos o documentos anteriores. Si el usuario los menciona, pídele los datos del documento actual.

FORMATO DE SALIDA (ESTRICTO): responde en texto plano. PROHIBIDO ABSOLUTAMENTE: emojis o símbolos decorativos; markdown de cualquier tipo (asteriscos, almohadillas, guiones de lista, comillas invertidas, bloques de código); marcas de cita «>» o «>>»; y enumerar los pasos que vas a dar o tu razonamiento (nada de «PRIMERO.- SE REDACTA...», «SE APLICA LA NORMATIVA...»). Encabezados en MAYÚSCULAS; numeración de cláusulas con «PRIMERO.-» o «1.». La salida debe poder pegarse tal cual en un documento oficial.

CIERRE: termina JUSTO después del documento (la última firma, cláusula o línea del escrito). NO añadas epílogos, resúmenes, preguntas, ofrecimientos de cambios («¿deseas que añada...?»), ni notas sobre lo que asumirás si no te responden. El documento es la respuesta completa; no escribas nada después de él.

Responde siempre en español.";

/// Devuelve el SYSTEM_PROMPT con la FECHA DE HOY inyectada. Sin esto, el corte de
/// conocimiento del modelo le hace creer que fechas normales (de este año o próximas)
/// son "futuras" y las objeta; con la fecha real de referencia deja de hacerlo y puede
/// calcular plazos correctamente. Se construye en cada petición (barato).
fn system_prompt_con_fecha() -> String {
    use chrono::Datelike;
    const MESES: [&str; 12] = [
        "enero", "febrero", "marzo", "abril", "mayo", "junio",
        "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre",
    ];
    let hoy = chrono::Local::now().date_naive();
    let mes = MESES[(hoy.month() as usize) - 1];
    format!(
        "{SYSTEM_PROMPT}\n\nFECHA ACTUAL: hoy es {} de {} de {}. Úsala como fecha de \
referencia para cualquier cálculo de plazos. Cualquier fecha que te dé el usuario \
—de este año o de años próximos— es válida: NO la trates como imposible por ser futura.",
        hoy.day(), mes, hoy.year()
    )
}

// Gramática GBNF (opción C): prohíbe A NIVEL DE MUESTREO los caracteres de markdown
// que romperían el pegado en un documento oficial: asterisco, almohadilla y comilla
// invertida. Todo lo demás se permite —acentos, ñ, «», saltos de línea y el guion bajo
// (que hace falta para las líneas de firma «____»)—. Coste: 0 RAM, 0 descarga. Es un
// refuerzo del filtro `limpiar_md`: si llama-server considerara la gramática inválida la
// ignora silenciosamente, así que el peor caso es volver al comportamiento actual.
const GRAMMAR_SIN_MARKDOWN: &str = "root ::= [^*#`]+";

const PREFIJO_CONTROL: &str = "Redacta el documento solicitado aplicando tus principios. Usa la NORMATIVA adjunta como fuente legal y como guía de estructura. Si falta algún dato esencial, pídelos TODOS juntos en una sola pregunta antes de redactar; si no falta nada esencial, redacta directamente y sin preámbulos.";

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
            { "role": "system", "content": system_prompt_con_fecha() },
            { "role": "user",   "content": mensaje_con_prefijo }
        ],
        "temperature": 0.2,
        "top_p": 0.9,
        "min_p": 0.05,
        "max_tokens": 1536,
        "repeat_penalty": 1.1,
        "grammar": GRAMMAR_SIN_MARKDOWN,
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

    // ── limpiar_md: fuera emojis, código y markdown ──────────────────────

    #[test]
    fn limpiar_md_elimina_emojis_y_codigo() {
        // Emojis y símbolos decorativos fuera; texto y tipografía legal intactos.
        assert_eq!(limpiar_md("Hecho probado ✅ y grave ⚠"), "Hecho probado  y grave ");
        assert_eq!(limpiar_md("Claras 🙂 instrucciones →"), "Claras  instrucciones ");
        assert_eq!(limpiar_md("▸ STC 1/1995 relevante"), " STC 1/1995 relevante");
        // Markdown y código fuera
        assert_eq!(limpiar_md("**PRIMERO.-** texto"), "PRIMERO.- texto");
        assert_eq!(limpiar_md("```rust"), "rust");
        assert_eq!(limpiar_md("> cita markdown"), "cita markdown");
        assert_eq!(limpiar_md("algo >> raro"), "algo  raro");
        // Tipografía legal que DEBE conservarse
        assert_eq!(limpiar_md("Renta de 800 € «según» art. 9 — vivienda…"),
                   "Renta de 800 € «según» art. 9 — vivienda…");
    }

    // ── dividir_en_bloques ───────────────────────────────────────────────

    #[test]
    fn bloques_cubren_todo_el_texto_sin_perder_caracteres() {
        let texto = "palabra ".repeat(5000); // 40 000 chars
        let bloques = dividir_en_bloques(&texto, 12_000);
        assert!(bloques.len() >= 3, "debe partir en varios bloques");
        let reconstruido: String = bloques.concat();
        assert_eq!(reconstruido, texto, "la unión de bloques debe ser el texto íntegro");
    }

    #[test]
    fn texto_corto_un_solo_bloque() {
        let texto = "documento breve";
        let bloques = dividir_en_bloques(texto, 12_000);
        assert_eq!(bloques.len(), 1);
        assert_eq!(bloques[0], texto);
    }

    #[test]
    fn corta_en_espacio_no_a_mitad_de_palabra() {
        // Palabras separadas por espacios: ningún bloque debe empezar/terminar partiendo
        // una palabra (salvo que no haya espacio en la segunda mitad del bloque).
        let texto = "alfa beta gamma delta epsilon zeta ".repeat(1000);
        let bloques = dividir_en_bloques(&texto, 100);
        assert!(bloques.len() > 1);
        // La reconstrucción sigue siendo exacta aunque corte por espacios.
        assert_eq!(bloques.concat(), texto);
    }

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
// ¿Es un emoji o símbolo decorativo/pictográfico? El usuario NO quiere NINGUNO en la
// respuesta. Se preservan la tipografía legal (€ « » — … º ª, acentos) y los signos
// normales; se eliminan emojis, dingbats, flechas, formas geométricas (▸ ■ ●), avisos
// (⚠), selectores de variación y ZWJ.
fn es_emoji(c: char) -> bool {
    let u = c as u32;
    matches!(u,
        0x1F000..=0x1FAFF   // planos de emoji (caras, objetos, símbolos…)
        | 0x2600..=0x27BF   // símbolos misceláneos + dingbats (⚠ ✒ ✍ ✓ ★ ☀ ☎…)
        | 0x2B00..=0x2BFF   // símbolos y flechas misceláneos
        | 0x25A0..=0x25FF   // formas geométricas (▸ ■ ● ▪ ▫ ◆…)
        | 0x2190..=0x21FF   // flechas (→ ← ↔…)
        | 0x2022            // viñeta •
        | 0x200D            // zero-width joiner
        | 0xFE00..=0xFE0F   // selectores de variación (emoji)
        | 0x2139            // ℹ
    )
}

// Limpia la salida del modelo: fuera markdown (** __ ## ` ```), artefactos de código
// (blockquote «>» / «>>») y TODO emoji/símbolo decorativo. Se aplica por línea tanto en
// streaming como en no-streaming, así que es el único punto de saneado de la respuesta.
fn limpiar_md(s: &str) -> String {
    let mut t = s
        .replace("```", "")
        .replace('`', "")
        .replace("**", "")
        .replace("__", "")
        .replace("## ", "")
        .replace("##", "")
        .replace(">>", "");
    // Blockquote markdown al principio de la línea («> texto»)
    let recortado = t.trim_start();
    if let Some(resto) = recortado.strip_prefix('>') {
        t = resto.trim_start().to_string();
    }
    // Eliminar emojis y símbolos decorativos
    t.chars().filter(|&c| !es_emoji(c)).collect()
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
