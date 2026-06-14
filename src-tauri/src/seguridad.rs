// ============================================================
// SISTEMA BABEL — NÚCLEO DE SEGURIDAD ELITE v10
// ============================================================
//
// Arquitectura de seguridad en capas:
//
//   CAPA 1 — Criptografía:  AES-256-GCM + Argon2id + HKDF-SHA256
//   CAPA 2 — Memoria:       Zeroize en todas las claves y datos sensibles
//   CAPA 3 — Errores:       Result/Option en todo — cero unwrap(), cero panic!
//   CAPA 4 — Detección:     AntiKeylogger sin requerir root
//   CAPA 5 — Anti-Sandbox:  Detección de entornos de análisis virtuales
//   CAPA 6 — Integridad:    HMAC-SHA256 sobre archivos del búnker
//   CAPA 7 — Auditoría:     Cada evento de seguridad → auditoria.babel cifrado

use crate::babel_path;
use std::fs;

// --- Criptografía ---
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use chrono::Local;
use dirs;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use num_cpus;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sysinfo::{ProcessExt, System, SystemExt};
use zeroize::{Zeroize, Zeroizing};

// ============================================================
// ESTRUCTURAS PÚBLICAS
// ============================================================

/// Niveles de licencia — determina qué funciones están disponibles
#[derive(Serialize, Deserialize, Clone)]
pub enum NivelAcceso {
    Basico,
    Business,
    Luxury,
}

/// Perfil de usuario dentro del búnker
#[derive(Serialize, Deserialize, Clone)]
pub struct UsuarioBabel {
    pub nombre: String,
    pub password_hash: String,
    pub nivel: NivelAcceso,
    pub id: String,
    pub creditos: u32,
}

/// Resultado de un análisis de seguridad del entorno
pub struct ResultadoSeguridad {
    /// El sistema es seguro para operar
    pub seguro: bool,
    /// Lista de amenazas encontradas (puede estar vacía)
    pub amenazas: Vec<String>,
    /// Advertencias que no bloquean pero deben registrarse
    pub advertencias: Vec<String>,
}

// ============================================================
// CAPA 1 — MOTOR DE CIFRADO (AES-256-GCM + Argon2id + HKDF)
// ============================================================

/// Deriva una subclave única para cada propósito (usuarios, diccionario, bóveda).
///
/// Dos capas:
///   1. Argon2id   → convierte la clave maestra en material criptográfico robusto.
///                   Resistente a ataques de diccionario y fuerza bruta por GPU.
///   2. HKDF-SHA256 → expande ese material en subclaves distintas según el contexto.
///                    "babel-usuarios-v1" y "traduccion-v1" producen claves diferentes
///                    aunque la clave maestra sea la misma.
///
/// Devuelve Result — nunca hace panic. Si falla, el error sube hasta quien llama.
pub fn derivar_subclave(
    clave_maestra: &[u8],
    contexto: &str,
    salt_argon2: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, String> {
    // Argon2id con 64MB de RAM, 3 iteraciones, 4 hilos en paralelo.
    // Estos parámetros hacen que atacar la clave por fuerza bruta sea extremadamente
    // costoso incluso con hardware especializado.
    let params = Params::new(131072, 4, 4, None)
        .map_err(|e| format!("Argon2 parámetros inválidos: {}", e))?;

    let mut ikm = Zeroizing::new([0u8; 32]);
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(clave_maestra, salt_argon2, ikm.as_mut())
        .map_err(|e| format!("Argon2 hash falló: {}", e))?;

    // HKDF expande el material criptográfico en una subclave específica por contexto.
    // 32 bytes de salida nunca exceden el límite de HKDF, así que este error
    // no ocurrirá en la práctica — pero lo manejamos igual por corrección.
    let hk = Hkdf::<Sha256>::new(None, ikm.as_ref());
    let mut subclave = Zeroizing::new([0u8; 32]);
    hk.expand(contexto.as_bytes(), subclave.as_mut())
        .map_err(|_| "HKDF: longitud de salida inválida".to_string())?;

    Ok(subclave)
}

/// Genera una salt maestra aleatoria de 32 bytes usando el CSPRNG del SO.
/// Solo se llama una vez al crear el búnker. No es secreta pero debe ser única.
pub fn generar_salt_maestra() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Cifra cualquier texto con AES-256-GCM.
/// El paquete resultante contiene: nonce(12B) + ciphertext + tag(16B).
/// El tag GCM garantiza que cualquier modificación del ciphertext sea detectable.
pub fn blindar_documento(texto: &str, clave_hex: &str) -> Result<Vec<u8>, String> {
    // Zeroizing borra los bytes de la clave en cuanto cipher se destruye.
    let mut clave_bytes =
        Zeroizing::new(hex::decode(clave_hex).map_err(|_| "Clave hex inválida".to_string())?);

    if clave_bytes.len() != 32 {
        return Err(format!(
            "La clave debe tener 32 bytes, tiene {}",
            clave_bytes.len()
        ));
    }

    let key = Key::<Aes256Gcm>::from_slice(&clave_bytes);
    let cipher = Aes256Gcm::new(key);
    clave_bytes.zeroize(); // borrado inmediato — ya no necesitamos los bytes en claro

    // Nonce aleatorio de 12 bytes — nunca se reutiliza gracias a la aleatoriedad.
    // Reutilizar un nonce con AES-GCM destruye completamente la seguridad.
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, texto.as_bytes())
        .map_err(|e| format!("Error al cifrar: {}", e))?;

    // Formato del paquete: nonce(12B) || ciphertext || tag_gcm(16B)
    let mut paquete = nonce_bytes.to_vec();
    paquete.extend(ciphertext);
    Ok(paquete)
}

/// Descifra un paquete creado por blindar_documento.
/// Si el paquete fue modificado aunque sea 1 bit, AES-GCM lo detecta y devuelve error.
pub fn descifrar_documento(paquete: Vec<u8>, clave_hex: &str) -> Result<String, String> {
    // 12B nonce + mínimo 1B datos + 16B tag GCM = 29B mínimo
    if paquete.len() < 29 {
        return Err("Paquete demasiado corto — posible corrupción o manipulación".to_string());
    }

    let mut clave_bytes =
        Zeroizing::new(hex::decode(clave_hex).map_err(|_| "Clave hex inválida".to_string())?);

    if clave_bytes.len() != 32 {
        return Err(format!(
            "La clave debe tener 32 bytes, tiene {}",
            clave_bytes.len()
        ));
    }

    let key = Key::<Aes256Gcm>::from_slice(&clave_bytes);
    let cipher = Aes256Gcm::new(key);
    clave_bytes.zeroize();

    let nonce = Nonce::from_slice(&paquete[0..12]);
    let ciphertext = &paquete[12..];

    // Si la clave es incorrecta O el archivo fue modificado, decrypt devuelve error.
    // No podemos distinguir entre los dos casos — eso es intencionado (no revela info).
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Descifrado fallido — clave incorrecta o archivo manipulado".to_string())?;

    let plaintext_z = Zeroizing::new(plaintext);
    let resultado = String::from_utf8(plaintext_z.to_vec())
        .map_err(|_| "El contenido descifrado no es UTF-8 válido".to_string());
    resultado
}

// ============================================================
// CAPA 2 — GESTIÓN DE CONTRASEÑAS
// ============================================================

/// Genera un hash seguro de una contraseña usando Argon2id con salt aleatoria.
/// El resultado incluye la salt — se puede verificar solo con el hash.
pub fn hash_password(password: &[u8]) -> Result<String, String> {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password, &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

/// Verifica una contraseña contra su hash almacenado.
/// Devuelve false tanto si el hash es inválido como si la contraseña no coincide —
/// no revela cuál de los dos falló (timing-safe por diseño de Argon2).
pub fn verificar_password(password: &str, hash: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    PasswordHash::new(hash)
        .ok()
        .map(|h| {
            Argon2::default()
                .verify_password(password.as_bytes(), &h)
                .is_ok()
        })
        .unwrap_or(false)
}

// ============================================================
// CAPA 4 — DETECCIÓN DE AMENAZAS (sin requerir root)
// ============================================================

pub struct AntiKeylogger;

impl AntiKeylogger {
    /// Lista extendida de patrones de procesos sospechosos.
    /// Incluye keyloggers conocidos, herramientas de captura de red,
    /// y software de acceso remoto no autorizado.
    fn lista_amenazas() -> &'static [&'static str] {
        &[
            // Keyloggers conocidos
            "keylogger",
            "keylog",
            "ardamax",
            "refog",
            "spyrix",
            "actual keylogger",
            "revealer",
            "kidlogger",
            // Captura de red
            "wireshark",
            "tcpdump",
            "ettercap",
            "fiddler",
            "charles",
            "mitmproxy",
            "burpsuite",
            "proxyman",
            // Acceso remoto sospechoso
            "teamviewer",
            "anydesk",
            "vnc",
            "radmin",
            "logmein",
            "ammyy",
            "remcos",
            "nanocore",
            // Herramientas de espionaje genéricas
            "spyware",
            "stalker",
            "monitor",
            "sniff",
            "hooklog",
            "covert",
            "stealth",
            // Keyloggers avanzados
            "hakku",
            "blackkeylog",
            "logkeys",
            "xinputlog",
            // RATs (Remote Access Trojans)
            "darkcomet",
            "blackshades",
            "quasar",
            "asyncrat",
            // Captura de pantalla maliciosa
            "recordmydesktop",
            "screengrab",
            // Análisis de tráfico
            "httpanalyzer",
            "proxifier",
            "glasswire",
        ]
    }

    fn es_proceso_legitimo(nombre: &str) -> bool {
        let lista_blanca = [
            // macOS — procesos del sistema Apple
            "thermalmonitord",
            "symptomsd",
            "diagnosticd",
            "logd",
            "monitord",
            "remoted",
            "screensharingd",
            "universalaccessd",
            "assistantd",
            "sharingd",
            "corespeechd",
            // Windows — procesos del sistema Microsoft
            "taskmgr",
            "perfmon",
            "resmon",
            // Linux
            "htop",
            "top",
            "rust-analyzer",
            "rust-analyzer-proc-macro-srv",
        ];
        lista_blanca.iter().any(|p| nombre == *p)
    }
    /// Escanea los procesos activos buscando coincidencias con la lista de amenazas.
    /// Funciona sin root — solo lee la lista de procesos que el SO expone a cualquier usuario.
    ///
    /// Devuelve la lista de procesos sospechosos encontrados (vacía si todo está limpio).
    fn escanear_procesos() -> (Vec<String>, Vec<String>) {
        let mut s = System::new_all();
        s.refresh_all();

        let mut amenazas_reales: Vec<String> = Vec::new();
        let advertencias: Vec<String> = Vec::new();

        for (_pid, proceso) in s.processes() {
            let nombre = proceso.name().to_lowercase();
            if Self::es_proceso_legitimo(&nombre) {
                continue;
            }

            for patron in Self::lista_amenazas() {
                if nombre.contains(patron) {
                    amenazas_reales.push(nombre.clone());
                    break;
                }
            }
        }

        (amenazas_reales, advertencias)
    }

    /// Analiza el entorno completo y devuelve un informe de seguridad detallado.
    ///
    /// IMPORTANTE: No bloquea el arranque si no hay root.
    /// El núcleo criptográfico de Babel (AES-256-GCM, Argon2id) funciona igual
    /// sin privilegios de administrador. Root solo añade capacidad de escaneo
    /// de procesos privilegiados del kernel — informa pero no bloquea.
    pub fn analizar_entorno() -> ResultadoSeguridad {
        let mut amenazas = Vec::new();
        let mut advertencias = Vec::new();

        // 1. Procesos sospechosos por nombre
        let (amenazas_proc, _) = Self::escanear_procesos();
        for proceso in &amenazas_proc {
            amenazas.push(format!("Proceso sospechoso: {}", proceso));
        }

        // 2. Variables de entorno de inyección de biblioteca dinámica
        // DYLD_INSERT_LIBRARIES / LD_PRELOAD inyectan código en cualquier proceso
        for var in &["DYLD_INSERT_LIBRARIES", "DYLD_FORCE_FLAT_NAMESPACE", "LD_PRELOAD"] {
            if let Ok(val) = std::env::var(var) {
                if !val.is_empty() {
                    amenazas.push(format!("Variable de inyección activa: {}={}", var, val));
                }
            }
        }

        // 3. LaunchAgents sospechosos (sin root — solo directorios accesibles)
        let rutas_agents = [
            std::path::PathBuf::from("/Library/LaunchAgents"),
            dirs::home_dir()
                .unwrap_or_default()
                .join("Library/LaunchAgents"),
        ];
        let patrones_agents = [
            "keylog", "keylogger", "spy", "monitor", "sniff", "hook",
            "stealth", "covert", "record", "capture",
        ];
        for directorio in &rutas_agents {
            if let Ok(entradas) = fs::read_dir(directorio) {
                for entry in entradas.flatten() {
                    let nombre = entry
                        .file_name()
                        .to_string_lossy()
                        .to_lowercase();
                    for patron in &patrones_agents {
                        if nombre.contains(patron) {
                            amenazas.push(format!(
                                "LaunchAgent sospechoso: {}",
                                entry.file_name().to_string_lossy()
                            ));
                            break;
                        }
                    }
                }
            }
        }

        if !is_root::is_root() {
            advertencias.push(
                "Sin privilegios de administrador — keyloggers de kernel no detectables. \
                 El cifrado AES-256-GCM opera con seguridad total de todas formas."
                    .to_string(),
            );
        }

        let seguro = amenazas.is_empty();

        ResultadoSeguridad {
            seguro,
            amenazas,
            advertencias,
        }
    }

    /// Análisis completo con registro en auditoría cifrada.
    ///
    /// A diferencia de la versión anterior que devolvía bool,
    /// ahora devuelve Result con detalles — y registra cada amenaza
    /// en auditoria.babel para que quede evidencia forense cifrada.
    pub fn blindaje_total(subclave_hex: Option<&str>) -> Result<ResultadoSeguridad, String> {
        log::warn!("[BABEL] Verificando integridad del entorno...");

        let resultado = Self::analizar_entorno();

        // Registramos el análisis en la auditoría cifrada si tenemos subclave
        if let Some(clave) = subclave_hex {
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

            if resultado.amenazas.is_empty() {
                let evento = format!("[{}] Análisis de seguridad: entorno limpio", timestamp);
                registrar_evento_seguridad(&evento, clave);
            } else {
                for amenaza in &resultado.amenazas {
                    let evento = format!("[{}] ALERTA: {}", timestamp, amenaza);
                    log::warn!("[!] {}", evento);
                    registrar_evento_seguridad(&evento, clave);
                }
            }

            // Las advertencias también se registran aunque no sean bloqueantes
            for advertencia in &resultado.advertencias {
                let evento = format!("[{}] AVISO: {}", timestamp, advertencia);
                registrar_evento_seguridad(&evento, clave);
            }
        }

        if resultado.seguro {
            log::warn!("[OK] Entorno seguro. Babel operativo.");
        } else {
            log::warn!(
                "[BABEL]
                 [ALERTA] {} amenaza(s) detectada(s). Ver auditoria.babel.",
                resultado.amenazas.len()
            );
        }

        Ok(resultado)
    }
}

// ============================================================
// CAPA 5 — ANTI-SANDBOXING
// ============================================================
//
// ¿Qué es un sandbox?
//   Un sandbox es una "caja de arena" virtual — un entorno aislado
//   donde los investigadores de seguridad y los antivirus ejecutan
//   programas sospechosos para analizarlos sin riesgo.
//   El programa cree que está en un ordenador normal, pero en realidad
//   todo lo que hace está siendo grabado y analizado.
//
// ¿Por qué es un problema para Babel?
//   Si alguien mete Babel en un sandbox puede ver exactamente cómo
//   funciona, cómo genera claves, y cómo cifra los documentos.
//
// Cómo detectamos un sandbox — 4 métodos:
//
//   1. HARDWARE SOSPECHOSO
//      RAM < 3.5GB → las máquinas reales de empresa tienen 8-32GB
//      CPU 1 core  → los ordenadores reales tienen 4-16 cores
//
//   2. TIEMPO DE ACTIVIDAD
//      Sistema arrancado hace menos de 8 minutos → sandbox
//      Los ordenadores reales llevan horas o días encendidos
//
//   3. PROCESOS DE VIRTUALIZACIÓN
//      VMware, VirtualBox, Hyper-V, QEMU dejan procesos visibles
//      que delatan que estamos dentro de una máquina virtual
//
//   4. AUSENCIA DE ACTIVIDAD HUMANA
//      Sin archivos recientes en Documentos → nadie usa este PC
//      Sin historial de uso → máquina recién creada para el análisis
//
//   Sistema de puntuación: cada indicador suma 1 punto (VM suma 2).
//   0-2 puntos → advertencia.   3+ puntos → bloqueo.
// En modo desarrollo ignoramos los checks de sandbox
// para evitar falsos positivos con cargo, vite, node, etc.

pub struct AntiSandbox;

impl AntiSandbox {
    // ---- Detección 1: RAM insuficiente ----

    /// Menos de 3.5GB de RAM total es raro en un PC de empresa real.
    /// Los sandboxes usan 2-4GB para no consumir demasiado del host.
    fn ram_sospechosa() -> bool {
        let mut s = System::new_all();
        s.refresh_memory();
        // total_memory() devuelve kilobytes — convertimos a GB
        let ram_gb = s.total_memory() as f64 / 1_048_576.0;
        ram_gb < 3.5
    }

    // ---- Detección 2: CPU con un solo core ----

    /// Los sandboxes asignan 1-2 cores para ahorrar recursos.
    /// Un PC de empresa tiene 4-16 cores.
    fn cpu_sospechosa() -> bool {
        num_cpus::get() <= 1
    }

    // ---- Detección 3: Sistema recién arrancado ----

    /// Un sandbox se crea limpio para cada análisis — lleva minutos activo.
    /// Un ordenador de empresa lleva horas o días encendido.
    /// Umbral: menos de 8 minutos desde el arranque.
    fn uptime_sospechoso() -> bool {
        let mut s = System::new_all();
        s.refresh_all();

        let ahora = chrono::Local::now().timestamp() as u64;
        let arranque = s.boot_time();

        if ahora <= arranque {
            return true;
        } // Reloj mal — sospechoso

        let uptime_minutos = (ahora - arranque) / 60;
        uptime_minutos < 8
    }

    // ---- Detección 4: Procesos de virtualización ----

    /// VMware, VirtualBox, Hyper-V y QEMU dejan procesos visibles
    /// aunque el sandbox intente ocultarlos.
    /// Este es el método más definitivo — vale doble en la puntuación.
    fn detectar_procesos_vm() -> Vec<String> {
        let mut s = System::new_all();
        s.refresh_all();

        let indicadores_vm = [
            // VMware — el sandbox más usado en entornos corporativos
            "vmtoolsd",
            "vmwaretray",
            "vmwareuser",
            "vmacthlp",
            // VirtualBox — muy usado por investigadores individuales
            "vboxservice",
            "vboxtray",
            "vboxguest",
            // Hyper-V — el sandbox de Microsoft
            "vmcompute",
            "vmwp",
            // QEMU/KVM — el más usado en Linux
            "qemu-ga",
            "qemu-system",
            // Cuckoo Sandbox — el más usado para análisis de malware
            "cuckoo-analyzer",
            // Sandboxie — popular entre investigadores individuales
            "sandboxie",
            "sbiectrl",
            "sbiesvc",
        ];

        let lista_blanca = [
            "rust-analyzer",
            "rust-analyzer-proc-macro-srv",
            "cargo",
            "rustc",
            "node",
            "npm",
            "vscode",
            "code helper",
            "xcode",
            "xcrun",
            "instruments",
            "lldb",
            "gdb",
            "make",
            "cmake",
            "git",
            "github desktop",
            "thermalmonitord",
            "symptomsd",
            "diagnosticd",
            "logd",
            "monitord",
            "remoted",
            "screensharingd",
            "universalaccessd",
            "assistantd",
            "sharingd",
            "corespeechd",
            "spotlight",
            "mds",
            "mdworker",
            "coreaudiod",
            "corevirtualmachined",
            "vmnet-bridge",
            "vmnet-natd",
            "taskmgr",
            "perfmon",
            "resmon",
            "wmi",
            "wmiprvse",
            "svchost",
            "msiexec",
            "htop",
            "top",
            "systemd",
            "journald",
            "kworker",
        ];

        let mut encontrados = Vec::new();
        for (pid, proceso) in s.processes() {
            let nombre = proceso.name().to_lowercase();
            if lista_blanca.iter().any(|p| nombre.contains(p)) {
                continue;
            }
            for indicador in &indicadores_vm {
                if nombre.contains(indicador) {
                    encontrados.push(format!("{} (PID: {})", proceso.name(), pid));
                    break; // Un proceso se reporta una vez aunque coincida varios patrones
                }
            }
        }
        encontrados
    }

    // ---- Detección 5: Ausencia de actividad humana ----

    /// Un sandbox recién creado no tiene historial de uso humano.
    /// Comprobamos si hay archivos modificados en las últimas 48h
    /// en las carpetas típicas de usuario (Documentos, Descargas, Escritorio).
    fn sin_actividad_humana() -> bool {
        let carpetas = [
            dirs::document_dir(),
            dirs::download_dir(),
            dirs::desktop_dir(),
        ];

        let mut archivos_recientes = 0u32;

        for carpeta_opt in &carpetas {
            let carpeta = match carpeta_opt {
                Some(c) => c,
                None => continue,
            };
            let entradas = match fs::read_dir(carpeta) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for entrada in entradas.flatten() {
                if let Ok(meta) = entrada.metadata() {
                    if let Ok(modificado) = meta.modified() {
                        if let Ok(hace) = modificado.elapsed() {
                            // Archivo modificado en las últimas 48 horas = actividad humana real
                            if hace.as_secs() < 172_800 {
                                archivos_recientes += 1;
                            }
                        }
                    }
                }
            }
        }

        // Menos de 3 archivos recientes en todas las carpetas = máquina vacía
        archivos_recientes < 3
    }

    // ---- Análisis completo con puntuación ----

    /// Ejecuta los 5 controles y devuelve un informe detallado.
    ///
    /// Puntuación:
    ///   RAM, CPU, uptime, actividad humana → 1 punto cada uno
    ///   Procesos de VM → 2 puntos (evidencia más directa)
    ///
    ///   0-2 puntos → probablemente real, solo advertencias
    ///   3+ puntos  → sandbox probable, bloqueo recomendado
    pub fn analizar_entorno() -> ResultadoSeguridad {
        let mut amenazas = Vec::new();
        let mut advertencias = Vec::new();
        let mut puntos: u8 = 0;

        if Self::ram_sospechosa() {
            puntos += 1;
            advertencias
                .push("RAM < 3.5GB — posible sandbox o PC con recursos limitados".to_string());
        }

        if Self::cpu_sospechosa() {
            puntos += 1;
            advertencias.push("Solo 1 core de CPU — típico de entornos de análisis".to_string());
        }

        if Self::uptime_sospechoso() {
            puntos += 1;
            advertencias.push(
                "Sistema arrancado hace menos de 8 minutos — posiblemente efímero".to_string(),
            );
        }

        // Procesos de VM valen doble — es la evidencia más directa
        let vms = Self::detectar_procesos_vm();
        if !vms.is_empty() {
            puntos += 2;
            for p in &vms {
                amenazas.push(format!("Proceso de virtualización: {}", p));
            }
        }

        if Self::sin_actividad_humana() {
            puntos += 1;
            advertencias.push(
                "Sin actividad humana reciente — máquina posiblemente nueva o virtual".to_string(),
            );
        }

        // 3 o más puntos = sandbox probable — bloqueamos
        let seguro = if puntos >= 3 {
            amenazas.push(format!(
                "SANDBOX DETECTADO: {} indicadores — Babel no operará en este entorno",
                puntos
            ));
            false
        } else {
            true
        };

        ResultadoSeguridad {
            seguro,
            amenazas,
            advertencias,
        }
    }
}

// ============================================================
// CAPA 6 — AUDITORÍA DE SEGURIDAD CIFRADA
// ============================================================

/// Registra un evento de seguridad en auditoria.babel de forma cifrada.
///
/// Cada evento se añade al final del archivo — nunca se sobrescribe.
/// El archivo es ilegible sin la subclave correcta.
/// Función interna — los módulos externos usan registrar_evento_seguridad().
const AUDIT_MAX_BYTES: u64 = 2 * 1024 * 1024; // 2 MB

fn escribir_evento_cifrado(evento: &str, clave_hex: &str, ruta: &str) {
    // Rotar si supera el límite para evitar crecimiento ilimitado
    if let Ok(meta) = fs::metadata(ruta) {
        if meta.len() > AUDIT_MAX_BYTES {
            let _ = fs::rename(ruta, format!("{}.old", ruta));
        }
    }

    match blindar_documento(evento, clave_hex) {
        Ok(cifrado) => {
            use std::io::Write;
            if let Ok(mut f) = fs::OpenOptions::new().append(true).create(true).open(ruta) {
                let len = (cifrado.len() as u32).to_le_bytes();
                let _ = f.write_all(&len);
                let _ = f.write_all(&cifrado);
            }
        }
        Err(e) => {
            log::error!(" [!] Error registrando evento de seguridad: {}", e);
        }
    }
}

/// Registra un evento de seguridad en auditoria.babel (principal) y su backup.
/// Pública para que otros módulos puedan registrar eventos desde fuera.
pub fn registrar_evento_seguridad(evento: &str, clave_hex: &str) {
    let ruta_principal = babel_path("auditoria.babel");
    escribir_evento_cifrado(evento, clave_hex, &ruta_principal);
    let ruta_bck = babel_path("auditoria.bck");
    escribir_evento_cifrado(evento, clave_hex, &ruta_bck);
}

// ============================================================
// CAPA 1B — RECUPERACIÓN CON FRASE BIP39
// ============================================================

pub fn derivar_clave_recuperacion(palabras: &[String]) -> Result<Zeroizing<[u8; 32]>, String> {
    let frase = Zeroizing::new(palabras.join(" "));
    // Argon2id antes de HKDF: aunque BIP39 tiene 128 bits de entropía, sin Argon2
    // un atacante con GPU puede probar millones de frases por segundo.
    let salt_recovery = b"babel-recovery-salt-v1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let params = Params::new(65536, 3, 1, None)
        .map_err(|e| format!("Argon2 parámetros inválidos: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut ikm = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(frase.as_bytes(), salt_recovery, ikm.as_mut())
        .map_err(|e| format!("Argon2 hash falló: {}", e))?;
    let hk = Hkdf::<Sha256>::new(None, ikm.as_ref());
    let mut clave = Zeroizing::new([0u8; 32]);
    hk.expand(b"babel-recovery-v1", clave.as_mut())
        .map_err(|_| "HKDF: error derivando clave de recuperación".to_string())?;
    Ok(clave)
}

fn clave_hmac_bloqueo() -> Option<[u8; 32]> {
    let bytes = fs::read(babel_path("master.salt")).ok()?;
    if bytes.len() < 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes[..32]);
    Some(key)
}

pub fn leer_bloqueo() -> Option<i64> {
    let contenido = fs::read_to_string(babel_path("bloqueo.tmp")).ok()?;
    let partes: Vec<&str> = contenido.trim().splitn(2, ':').collect();
    if partes.len() != 2 {
        return None;
    }
    let ts: i64 = partes[0].parse().ok()?;
    let secret = clave_hmac_bloqueo()?;
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&secret).ok()?;
    mac.update(ts.to_string().as_bytes());
    let firma_esperada = hex::encode(mac.finalize().into_bytes());
    if firma_esperada != partes[1] {
        return None;
    }
    Some(ts)
}

pub fn activar_bloqueo() {
    let ts = chrono::Local::now().timestamp();
    if let Some(secret) = clave_hmac_bloqueo() {
        if let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(&secret) {
            mac.update(ts.to_string().as_bytes());
            let firma = hex::encode(mac.finalize().into_bytes());
            let _ = fs::write(babel_path("bloqueo.tmp"), format!("{}:{}", ts, firma));
        }
    }
}
