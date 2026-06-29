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
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
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
    OsRng.fill_bytes(&mut salt);
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

    // Nonce aleatorio de 12 bytes via OsRng (entropía del OS, sin estado thread-local).
    // Reutilizar un nonce con AES-GCM destruye completamente la seguridad.
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    // Un nonce todo-ceros indica fallo catastrófico del RNG — abortamos.
    if nonce_bytes == [0u8; 12] {
        return Err("Fallo del generador de entropía del sistema".to_string());
    }
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
    fn lista_amenazas() -> &'static [&'static str] {
        &[
            // --- Keyloggers multiplataforma ---
            "keylogger", "keylog", "ardamax", "refog", "spyrix",
            "revealer", "kidlogger", "hakku", "blackkeylog", "logkeys",
            "xinputlog", "kgbkeylogger", "perfectkeylogger", "invisiblekeylogger",
            "hawkeye", "webwatcher", "actual keylogger", "spyagent",
            "elite keylogger", "ikeymonitor",
            // --- RATs (Remote Access Trojans) ---
            "darkcomet", "blackshades", "quasar", "asyncrat", "njrat",
            "gh0st", "poisonivy", "bifrost", "cybergate", "prorat",
            "imminent monitor", "luminosity", "limerat", "orcusrat",
            "revengerat", "warzone rat", "netwire", "remcos", "nanocore",
            "pandora rat", "agent tesla", "revenge-rat", "asyncrat",
            // --- Frameworks C2 y post-explotación ---
            "cobalt strike", "msfconsole", "msfvenom", "metasploit",
            "havoc", "sliver", "covenant", "empire", "pupy",
            "mimikatz", "rubeus", "crackmapexec", "psexec",
            // --- Spyware comercial ---
            "flexispy", "mspy", "highster", "spyera", "hoverwatch",
            // --- Password stealers / info stealers ---
            "redline", "raccoon stealer", "vidar", "azorult", "lumma",
            // --- Captura de red ---
            "wireshark", "tcpdump", "ettercap", "fiddler", "charles",
            "mitmproxy", "burpsuite", "proxyman", "tshark", "networkminer",
            "dsniff", "arpspoof", "sslstrip", "responder", "bettercap",
            // --- Acceso remoto no autorizado ---
            "teamviewer", "anydesk", "radmin", "logmein", "ammyy",
            "ultraviewer", "dameware",
            // --- Captura de pantalla / grabación maliciosa ---
            "recordmydesktop", "screengrab",
            // --- Espionaje genérico ---
            "spyware", "stalkerware", "hooklog", "covert",
            // --- Análisis de tráfico ---
            "httpanalyzer", "proxifier", "glasswire",
        ]
    }

    fn es_proceso_legitimo(nombre: &str) -> bool {
        let lista_blanca = [
            // macOS — sistema Apple
            "thermalmonitord", "symptomsd", "diagnosticd", "logd",
            "monitord", "remoted", "screensharingd", "universalaccessd",
            "assistantd", "sharingd", "corespeechd", "coreaudiod",
            "loginwindow", "windowserver", "securityd", "trustd",
            "cfnetwork", "mds", "mdworker", "spotlight",
            "airportd", "bluetoothd", "wifid", "nehelper",
            // mDNS / Bonjour — el patrón "responder" choca con estos daemons legítimos
            "mdnsresponder", "mdnsresponderhelper",
            // Windows — sistema Microsoft
            "taskmgr", "perfmon", "resmon", "wmiprvse", "svchost",
            // Linux
            "htop", "top", "systemd", "journald",
            // Desarrollo
            "rust-analyzer", "rust-analyzer-proc-macro-srv",
        ];
        lista_blanca.iter().any(|&p| nombre == p)
    }

    /// Filtra apps que legítimamente usan Accessibility o Input Monitoring en macOS.
    fn es_app_tcc_legitima(bundle_id: &str) -> bool {
        // Cualquier bundle de Apple es legítimo por definición
        if bundle_id.starts_with("com.apple.") {
            return true;
        }
        let legitimas = [
            // Launchers y productividad
            "com.alfredapp.Alfred",
            "com.runningwithcrayons.Alfred",
            "com.raycast.macos",
            // Automatización de teclado/ratón
            "com.stairways.keyboardmaestro.agent",
            "com.hegenberg.BetterTouchTool",
            "com.folivora.BetterTouchTool",
            "com.popclip.PopClip",
            // Remapeo de teclado
            "org.pqrs.Karabiner-Elements.NormalSessionClient",
            "org.pqrs.karabiner.karabiner_console_user_server",
            // Terminales
            "com.googlecode.iterm2",
            "dev.warp.Warp-Stable",
            "com.apple.Terminal",
            // Gestores de contraseñas (necesitan detectar atajo de teclado)
            "com.1password.1password",
            "com.agilebits.onepassword7",
            "com.bitwarden.desktop",
            // Accesibilidad real
            "com.apple.VoiceOver",
        ];
        legitimas.iter().any(|&l| bundle_id == l)
    }

    /// Escanea procesos activos por nombre y ruta.
    /// Devuelve candidatos sospechosos como (nombre, pid, exe) para análisis posterior.
    fn escanear_procesos() -> (Vec<(String, u32, std::path::PathBuf)>, Vec<String>) {
        let mut s = System::new_all();
        s.refresh_all();

        let mut candidatos: Vec<(String, u32, std::path::PathBuf)> = Vec::new();
        let mut advertencias: Vec<String> = Vec::new();

        for (pid, proceso) in s.processes() {
            let nombre = proceso.name().to_lowercase();
            if Self::es_proceso_legitimo(&nombre) {
                continue;
            }

            for patron in Self::lista_amenazas() {
                if nombre.contains(patron) {
                    candidatos.push((nombre.clone(), pid.as_u32(), proceso.exe().to_path_buf()));
                    break;
                }
            }

            let exe_str = proceso.exe().to_string_lossy().to_lowercase();
            if exe_str.starts_with("/tmp/") || exe_str.starts_with("/private/tmp/") {
                advertencias.push(format!(
                    "Proceso ejecutándose desde /tmp: {} ({})",
                    proceso.name(),
                    proceso.exe().display()
                ));
            }
        }

        (candidatos, advertencias)
    }

    /// Escanea LaunchAgents y LaunchDaemons buscando nombres sospechosos.
    fn escanear_launch_agents_y_daemons() -> Vec<String> {
        let home = dirs::home_dir().unwrap_or_default();
        let directorios = [
            std::path::PathBuf::from("/Library/LaunchAgents"),
            std::path::PathBuf::from("/Library/LaunchDaemons"),
            home.join("Library/LaunchAgents"),
        ];
        let patrones = [
            "keylog", "keylogger", "spy", "sniff", "hook",
            "stealth", "covert", "record", "capture", "rat",
            "inject", "hook", "steal", "exfil",
        ];
        let mut encontrados = Vec::new();
        for directorio in &directorios {
            if let Ok(entradas) = fs::read_dir(directorio) {
                for entry in entradas.flatten() {
                    let nombre = entry.file_name().to_string_lossy().to_lowercase();
                    // Los plists de Apple (com.apple.*) son siempre legítimos
                    if nombre.starts_with("com.apple.") {
                        continue;
                    }
                    for patron in &patrones {
                        if nombre.contains(patron) {
                            encontrados.push(format!(
                                "Launch{} sospechoso: {}",
                                if directorio.to_string_lossy().contains("Daemon") { "Daemon" } else { "Agent" },
                                entry.file_name().to_string_lossy()
                            ));
                            break;
                        }
                    }
                }
            }
        }
        encontrados
    }

    /// Verifica la firma de código de un ejecutable usando `codesign`.
    /// Devuelve `None` si no tiene firma o es inválida.
    /// Devuelve `Some(authority)` con el primer firmante de la cadena si es válida.
    ///
    /// Apple no usa "Developer ID Application:" para sus propios binarios del sistema,
    /// así que ese prefijo distingue apps de tercero de software interno de Apple.
    #[cfg(target_os = "macos")]
    fn verificar_firma_ejecutable(exe: &std::path::Path) -> Option<String> {
        use std::process::Command;

        if exe.as_os_str().is_empty() {
            return Some("(proceso de sistema sin ruta)".to_string());
        }

        let exe_str = exe.to_string_lossy();

        let firmado = Command::new("codesign")
            .args(&["--verify", "--strict", "--", exe_str.as_ref()])
            .output()
            .ok()?
            .status
            .success();

        if !firmado {
            return None;
        }

        // codesign -dv escribe la cadena de certificados en stderr
        let info = Command::new("codesign")
            .args(&["-dv", "--", exe_str.as_ref()])
            .output()
            .ok()?;

        let stderr = String::from_utf8_lossy(&info.stderr);
        for linea in stderr.lines() {
            if let Some(authority) = linea.strip_prefix("Authority=") {
                return Some(authority.to_string());
            }
        }

        Some("Firmado (authority desconocido)".to_string())
    }

    /// Verifica la firma de código en Windows con PowerShell `Get-AuthenticodeSignature`.
    /// Devuelve `None` si no está firmado o la firma es inválida/manipulada.
    /// Devuelve `Some(subject_dn)` con el Subject del certificado si es válida.
    #[cfg(target_os = "windows")]
    fn verificar_firma_ejecutable(exe: &std::path::Path) -> Option<String> {
        use std::process::Command;

        if exe.as_os_str().is_empty() {
            return Some("(proceso de sistema sin ruta)".to_string());
        }

        // Escapar comillas simples para PowerShell
        let exe_str = exe.to_string_lossy().replace('\'', "''");

        let script = format!(
            "$sig = Get-AuthenticodeSignature '{}';\
             if ($sig.Status -eq 'Valid' -and $null -ne $sig.SignerCertificate) \
             {{ Write-Output $sig.SignerCertificate.Subject }} \
             else {{ Write-Output '' }}",
            exe_str
        );

        let out = Command::new("powershell")
            .args(&["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
            .ok()?;

        let subject = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if subject.is_empty() { None } else { Some(subject) }
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    fn verificar_firma_ejecutable(_exe: &std::path::Path) -> Option<String> {
        None
    }

    /// Clasifica un proceso candidato verificando su firma de código.
    /// Devuelve (es_amenaza, mensaje) para que analizar_entorno() lo distribuya
    /// entre amenazas o advertencias según corresponda.
    #[cfg(target_os = "macos")]
    fn clasificar_proceso_sospechoso(
        nombre: &str,
        pid: u32,
        exe: &std::path::Path,
    ) -> (bool, String) {
        match Self::verificar_firma_ejecutable(exe) {
            // Sin ruta: proceso de kernel — no lo bloqueamos pero lo anotamos
            Some(ref f) if f.starts_with("(proceso de sistema") => (
                false,
                format!("Proceso de sistema coincide con patrón (ignorado): {} (PID {})", nombre, pid),
            ),
            // Apple no usa Developer ID para sus propios binarios del SO
            Some(ref firma) if !firma.starts_with("Developer ID Application:") => (
                false,
                format!(
                    "Proceso firmado por Apple coincide con patrón (falso positivo): {} (PID {}) — {}",
                    nombre, pid, firma
                ),
            ),
            // Firmado por tercero — sospechoso pero requiere análisis humano
            Some(ref firma) => (
                true,
                format!(
                    "Proceso sospechoso firmado por tercero '{}': {} (PID {})",
                    firma, nombre, pid
                ),
            ),
            // Sin ruta — proceso de kernel o fantasma
            // En sandbox no podemos confirmar amenaza por los mismos motivos que el caso None
            None if exe.as_os_str().is_empty() => {
                let en_sandbox = std::env::var("APP_SANDBOX_CONTAINER_ID").is_ok();
                (
                    !en_sandbox,
                    format!(
                        "Proceso sin ruta {}: {} (PID {})",
                        if en_sandbox { "(no verificable en sandbox)" } else { "— sospechoso" },
                        nombre, pid
                    ),
                )
            }
            // Sin firma o inaccesible:
            //   • Sin sandbox → binario sin firma = amenaza confirmada
            //   • En sandbox  → codesign no puede leer binarios fuera del contenedor;
            //                    no podemos distinguir "sin firma" de "acceso denegado"
            None => {
                let en_sandbox = std::env::var("APP_SANDBOX_CONTAINER_ID").is_ok();
                if en_sandbox {
                    (false, format!(
                        "Proceso no verificable en sandbox (firma inaccesible): {} (PID {})",
                        nombre, pid
                    ))
                } else {
                    (true, format!(
                        "Proceso sospechoso SIN FIRMA VÁLIDA: {} (PID {}) en {}",
                        nombre, pid, exe.display()
                    ))
                }
            }
        }
    }

    /// Versión Windows: distingue binarios de Microsoft (falsos positivos) de terceros.
    /// El Subject DN de Microsoft contiene `O=Microsoft Corporation`.
    #[cfg(target_os = "windows")]
    fn clasificar_proceso_sospechoso(
        nombre: &str,
        pid: u32,
        exe: &std::path::Path,
    ) -> (bool, String) {
        match Self::verificar_firma_ejecutable(exe) {
            Some(ref f) if f.starts_with("(proceso de sistema") => (
                false,
                format!("Proceso de sistema coincide con patrón (ignorado): {} (PID {})", nombre, pid),
            ),
            // Binario firmado por Microsoft → falso positivo
            Some(ref firma)
                if firma.contains("O=Microsoft Corporation")
                    || firma.contains("CN=Microsoft Windows") =>
            (
                false,
                format!(
                    "Proceso firmado por Microsoft coincide con patrón (falso positivo): {} (PID {})",
                    nombre, pid
                ),
            ),
            Some(ref firma) => (
                true,
                format!(
                    "Proceso sospechoso firmado por tercero '{}': {} (PID {})",
                    firma, nombre, pid
                ),
            ),
            None if exe.as_os_str().is_empty() => (
                true,
                format!("Proceso sospechoso sin ruta accesible: {} (PID {})", nombre, pid),
            ),
            None => (
                true,
                format!(
                    "Proceso sospechoso SIN FIRMA VÁLIDA: {} (PID {}) en {}",
                    nombre,
                    pid,
                    exe.display()
                ),
            ),
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    fn clasificar_proceso_sospechoso(
        nombre: &str,
        pid: u32,
        _exe: &std::path::Path,
    ) -> (bool, String) {
        (true, format!("Proceso sospechoso: {} (PID {})", nombre, pid))
    }

    /// Detecta conexiones TCP externas activas desde procesos sospechosos.
    /// Usa `lsof -iTCP` y filtra loopback (127.0.0.1, ::1) — solo conexiones
    /// hacia IPs externas son relevantes como indicador de exfiltración.
    #[cfg(target_os = "macos")]
    fn detectar_conexiones_procesos_sospechosos(
        candidatos: &[(String, u32, std::path::PathBuf)],
    ) -> Vec<String> {
        use std::process::Command;

        if candidatos.is_empty() {
            return vec![];
        }

        let pid_lista: Vec<String> = candidatos.iter().map(|(_, pid, _)| pid.to_string()).collect();

        let output = match Command::new("lsof")
            .args(&["-iTCP", "-n", "-P", "-p", &pid_lista.join(",")])
            .output()
        {
            Ok(o) => o,
            Err(_) => return vec![],
        };

        let mut conexiones = Vec::new();
        let texto = String::from_utf8_lossy(&output.stdout);

        for linea in texto.lines().skip(1) {
            if !linea.contains("ESTABLISHED") {
                continue;
            }
            if linea.contains("127.0.0.1") || linea.contains("::1") || linea.contains("localhost") {
                continue;
            }
            let cols: Vec<&str> = linea.split_whitespace().collect();
            if cols.len() < 9 {
                continue;
            }
            if let Ok(pid_lsof) = cols[1].parse::<u32>() {
                if let Some((nombre, _, _)) = candidatos.iter().find(|(_, p, _)| *p == pid_lsof) {
                    let destino = cols.last().unwrap_or(&"desconocido");
                    conexiones.push(format!(
                        "Conexión TCP externa desde proceso sospechoso '{}' (PID {}): {}",
                        nombre, pid_lsof, destino
                    ));
                }
            }
        }

        conexiones
    }

    /// Versión Windows: usa `netstat -ano` para correlacionar PIDs sospechosos
    /// con conexiones ESTABLISHED hacia IPs externas.
    /// Formato de netstat: Proto  LocalAddr  ForeignAddr  State  PID
    #[cfg(target_os = "windows")]
    fn detectar_conexiones_procesos_sospechosos(
        candidatos: &[(String, u32, std::path::PathBuf)],
    ) -> Vec<String> {
        use std::process::Command;

        if candidatos.is_empty() {
            return vec![];
        }

        let output = match Command::new("netstat").args(&["-ano"]).output() {
            Ok(o) => o,
            Err(_) => return vec![],
        };

        let mut conexiones = Vec::new();
        let texto = String::from_utf8_lossy(&output.stdout);

        for linea in texto.lines() {
            if !linea.contains("ESTABLISHED") {
                continue;
            }
            if linea.contains("127.0.0.1") || linea.contains("[::1]") {
                continue;
            }
            // cols: Proto LocalAddr ForeignAddr State PID
            let cols: Vec<&str> = linea.split_whitespace().collect();
            if cols.len() < 5 {
                continue;
            }
            if let Ok(pid_net) = cols[4].parse::<u32>() {
                if let Some((nombre, _, _)) = candidatos.iter().find(|(_, p, _)| *p == pid_net) {
                    let destino = cols[2]; // ForeignAddr
                    conexiones.push(format!(
                        "Conexión TCP externa desde proceso sospechoso '{}' (PID {}): {}",
                        nombre, pid_net, destino
                    ));
                }
            }
        }

        conexiones
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    fn detectar_conexiones_procesos_sospechosos(
        _candidatos: &[(String, u32, std::path::PathBuf)],
    ) -> Vec<String> {
        vec![]
    }

    /// Detecta mecanismos de persistencia específicos de Windows:
    ///
    ///   1. Claves Run / RunOnce del registro (HKCU + HKLM) — el vector más común
    ///      para que un keylogger sobreviva al reinicio.
    ///   2. AppInit_DLLs — equivalente de LD_PRELOAD: inyecta una DLL en todos los
    ///      procesos que cargan user32.dll (prácticamente toda la UI de Windows).
    ///      Cualquier valor no vacío aquí es sospechoso.
    ///   3. Carpeta Startup del usuario — otra vía clásica de arranque automático.
    #[cfg(target_os = "windows")]
    fn detectar_persistencia_windows() -> (Vec<String>, Vec<String>) {
        use std::process::Command;

        let mut amenazas = Vec::new();
        let advertencias = Vec::new();
        let patrones = Self::lista_amenazas();

        // ---- 1. Claves Run / RunOnce ----
        let run_keys = [
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ];

        for clave in &run_keys {
            let out = Command::new("reg").args(&["query", clave]).output();
            if let Ok(o) = out {
                if o.status.success() {
                    let texto = String::from_utf8_lossy(&o.stdout);
                    for linea in texto.lines() {
                        // Las líneas con valores tienen formato:
                        //   <nombre>    REG_SZ    <ruta_ejecutable>
                        if !linea.contains("REG_SZ") && !linea.contains("REG_EXPAND_SZ") {
                            continue;
                        }
                        let linea_lower = linea.to_lowercase();
                        for patron in patrones {
                            if linea_lower.contains(patron) {
                                amenazas.push(format!(
                                    "Entrada sospechosa en Run key ({}): {}",
                                    clave,
                                    linea.trim()
                                ));
                                break;
                            }
                        }
                    }
                }
            }
        }

        // ---- 2. AppInit_DLLs (inyección universal de DLL) ----
        let appinit_key =
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
        let out = Command::new("reg")
            .args(&["query", appinit_key, "/v", "AppInit_DLLs"])
            .output();
        if let Ok(o) = out {
            if o.status.success() {
                let texto = String::from_utf8_lossy(&o.stdout);
                for linea in texto.lines() {
                    if !linea.contains("AppInit_DLLs") {
                        continue;
                    }
                    // Extraer el valor tras REG_SZ o REG_MULTI_SZ
                    let valor = linea
                        .splitn(2, "REG_SZ")
                        .nth(1)
                        .or_else(|| linea.splitn(2, "REG_MULTI_SZ").nth(1))
                        .unwrap_or("")
                        .trim();
                    if !valor.is_empty() {
                        amenazas.push(format!(
                            "AppInit_DLLs activo — inyección de DLL en todos los procesos: {}",
                            valor
                        ));
                    }
                }
            }
        }

        // ---- 3. Carpeta Startup del usuario ----
        if let Some(appdata) = dirs::data_dir() {
            let startup = appdata
                .join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs")
                .join("Startup");
            if let Ok(entradas) = fs::read_dir(&startup) {
                for entry in entradas.flatten() {
                    let nombre = entry.file_name().to_string_lossy().to_lowercase();
                    // desktop.ini siempre está ahí — ignorar
                    if nombre == "desktop.ini" {
                        continue;
                    }
                    for patron in patrones {
                        if nombre.contains(patron) {
                            amenazas.push(format!(
                                "Archivo sospechoso en carpeta Startup: {}",
                                entry.file_name().to_string_lossy()
                            ));
                            break;
                        }
                    }
                }
            }
        }

        (amenazas, advertencias)
    }

    #[cfg(not(target_os = "windows"))]
    fn detectar_persistencia_windows() -> (Vec<String>, Vec<String>) {
        (vec![], vec![])
    }

    /// Consulta la base de datos TCC de macOS para detectar apps con permisos
    /// de Input Monitoring (kTCCServiceListenEvent), Accessibility o Screen Recording
    /// que no pertenezcan a Apple ni a apps conocidas como legítimas.
    ///
    /// Input Monitoring es el permiso que permite a una app leer TODAS las pulsaciones
    /// de teclado del sistema — es exactamente el permiso que usa un keylogger.
    #[cfg(target_os = "macos")]
    fn detectar_permisos_accesibilidad() -> (Vec<String>, Vec<String>) {
        use std::process::Command;

        let mut amenazas = Vec::new();
        let mut advertencias = Vec::new();

        // En App Sandbox, TCC.db está fuera del contenedor.
        // Cualquier intento de acceso sería bloqueado por el OS y generaría un evento
        // de auditoría innecesario. El propio sandbox garantiza que ninguna otra app
        // puede capturar pulsaciones sin el entitlement explícito.
        if std::env::var("APP_SANDBOX_CONTAINER_ID").is_ok() {
            advertencias.push(
                "Verificación de permisos TCC omitida — App Sandbox de macOS activo.".to_string()
            );
            return (amenazas, advertencias);
        }

        let home = match dirs::home_dir() {
            Some(h) => h,
            None => return (amenazas, advertencias),
        };

        let tcc_db = home.join("Library/Application Support/com.apple.TCC/TCC.db");
        if !tcc_db.exists() {
            return (amenazas, advertencias);
        }

        // Consulta los tres servicios críticos: captura de teclado, accesibilidad y pantalla
        let query = "SELECT client, service FROM access \
                     WHERE (service='kTCCServiceListenEvent' \
                         OR service='kTCCServiceAccessibility' \
                         OR service='kTCCServiceScreenCapture') \
                     AND auth_value=2;";

        let output = Command::new("sqlite3")
            .arg("-separator").arg("|")
            .arg(tcc_db.to_string_lossy().as_ref())
            .arg(query)
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let texto = String::from_utf8_lossy(&out.stdout);
                for linea in texto.lines() {
                    let partes: Vec<&str> = linea.splitn(2, '|').collect();
                    if partes.len() != 2 {
                        continue;
                    }
                    let cliente = partes[0].trim();
                    let servicio = partes[1].trim();

                    if Self::es_app_tcc_legitima(cliente) {
                        continue;
                    }

                    let desc = match servicio {
                        "kTCCServiceListenEvent"  => "Input Monitoring — puede leer todo el teclado",
                        "kTCCServiceAccessibility" => "Accessibility API — puede monitorizar la UI",
                        "kTCCServiceScreenCapture" => "Screen Recording — puede grabar la pantalla",
                        _ => servicio,
                    };

                    // Input Monitoring es el permiso más crítico: es el keylogger de macOS
                    if servicio == "kTCCServiceListenEvent" {
                        amenazas.push(format!(
                            "App con permiso de captura de teclado ({}): {}",
                            desc, cliente
                        ));
                    } else {
                        advertencias.push(format!(
                            "App con acceso a {} : {}",
                            desc, cliente
                        ));
                    }
                }
            }
            Ok(_) => {
                advertencias.push(
                    "Verificación de Input Monitoring omitida — concede Acceso Completo al Disco \
                     a Babel en Ajustes > Privacidad y Seguridad > Acceso Completo al Disco."
                        .to_string(),
                );
            }
            Err(_) => {
                advertencias.push(
                    "sqlite3 no encontrado — verificación de TCC omitida.".to_string()
                );
            }
        }

        (amenazas, advertencias)
    }

    #[cfg(not(target_os = "macos"))]
    fn detectar_permisos_accesibilidad() -> (Vec<String>, Vec<String>) {
        (vec![], vec![])
    }

    pub fn analizar_entorno() -> ResultadoSeguridad {
        let mut amenazas = Vec::new();
        let mut advertencias = Vec::new();

        // 1. Procesos activos — nombre → candidatos con PID y ruta
        let (candidatos, avisos_proc) = Self::escanear_procesos();
        advertencias.extend(avisos_proc);

        // 1b. Verificar firma de cada candidato
        //     Firmado por Apple → falso positivo (advertencia)
        //     Sin firma → máxima sospecha (amenaza)
        //     Firmado por tercero → amenaza con contexto del firmante
        for (nombre, pid, exe) in &candidatos {
            let (es_amenaza, msg) = Self::clasificar_proceso_sospechoso(nombre, *pid, exe);
            if es_amenaza {
                amenazas.push(msg);
            } else {
                advertencias.push(msg);
            }
        }

        // 1c. Conexiones TCP externas activas desde procesos sospechosos
        for c in Self::detectar_conexiones_procesos_sospechosos(&candidatos) {
            amenazas.push(c);
        }

        // 2. Variables de inyección de biblioteca dinámica
        for var in &[
            "DYLD_INSERT_LIBRARIES",
            "DYLD_FORCE_FLAT_NAMESPACE",
            "DYLD_FRAMEWORK_PATH",
            "DYLD_LIBRARY_PATH",
            "LD_PRELOAD",
        ] {
            if let Ok(val) = std::env::var(var) {
                if !val.is_empty() {
                    amenazas.push(format!("Variable de inyección activa: {}={}", var, val));
                }
            }
        }

        // 3. LaunchAgents y LaunchDaemons sospechosos (macOS)
        for entrada in Self::escanear_launch_agents_y_daemons() {
            amenazas.push(entrada);
        }

        // 3b. Persistencia Windows: Run keys, AppInit_DLLs, carpeta Startup
        let (amenazas_win, avisos_win) = Self::detectar_persistencia_windows();
        amenazas.extend(amenazas_win);
        advertencias.extend(avisos_win);

        // 4. Permisos de accesibilidad macOS — TCC.db
        //    Input Monitoring: permiso exacto que necesita un keylogger en macOS
        let (amenazas_tcc, avisos_tcc) = Self::detectar_permisos_accesibilidad();
        amenazas.extend(amenazas_tcc);
        advertencias.extend(avisos_tcc);

        if uzers::get_current_uid() != 0 {
            advertencias.push(
                "Sin privilegios de administrador — keyloggers de kernel no detectables. \
                 El cifrado AES-256-GCM opera con seguridad total de todas formas."
                    .to_string(),
            );
        }

        ResultadoSeguridad {
            seguro: amenazas.is_empty(),
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
        // total_memory() devuelve bytes desde sysinfo 0.26 — convertimos a GB
        let ram_gb = s.total_memory() as f64 / 1_073_741_824.0;
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
        // En App Sandbox, document_dir/download_dir/desktop_dir apuntan al contenedor,
        // que está vacío. Esto produce siempre archivos_recientes = 0 → falso positivo
        // que puede sumar puntos suficientes para bloquear Babel en su propio arranque.
        if std::env::var("APP_SANDBOX_CONTAINER_ID").is_ok() {
            return false;
        }

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
// Mutex global que serializa las escrituras al log de auditoría.
// P2P y email corren en threads separados — sin esto los bloques len+datos
// pueden intercalarse y corromper el archivo.
static AUDIT_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

const AUDIT_MAX_BYTES: u64 = 2 * 1024 * 1024; // 2 MB

fn escribir_evento_cifrado(evento: &str, clave_hex: &str, ruta: &str) {
    let _guard = AUDIT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

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
                if let Err(e) = f.write_all(&len).and_then(|_| f.write_all(&cifrado)) {
                    log::error!("[!] Fallo escribiendo evento de auditoría en {}: {}", ruta, e);
                }
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

/// Esquema anterior al fix C1: HKDF-SHA256 sin Argon2id.
/// Solo se usa como fallback para migrar recovery.babel generados antes de C1.
pub fn derivar_clave_recuperacion_v0(
    palabras: &[String],
) -> Result<Zeroizing<[u8; 32]>, String> {
    let frase = Zeroizing::new(palabras.join(" "));
    let hk = Hkdf::<Sha256>::new(None, frase.as_bytes());
    let mut clave = Zeroizing::new([0u8; 32]);
    hk.expand(b"babel-recovery-v1", clave.as_mut())
        .map_err(|_| "HKDF v0: error derivando clave".to_string())?;
    Ok(clave)
}

/// Deriva la salt de recuperación v2 (por instalación) desde la salt maestra.
/// Cada instalación tiene una salt maestra distinta → cada recovery tiene una salt propia →
/// no se pueden precalcular rainbow tables entre instalaciones distintas.
/// No es secreta — se puede recalcular siempre que exista master.salt.
pub fn derivar_recovery_salt_v2(salt_maestra: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, salt_maestra);
    let mut salt = [0u8; 32];
    let _ = hk.expand(b"babel-recovery-salt-v2", &mut salt);
    salt
}

/// v2: Argon2id con salt derivada por instalación.
/// Sustituye a derivar_clave_recuperacion (v1) para búnkers nuevos.
/// Los búnkers existentes migran automáticamente al verificar la frase.
pub fn derivar_clave_recuperacion_v2(
    palabras: &[String],
    salt: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, String> {
    let frase = Zeroizing::new(palabras.join(" "));
    let params = Params::new(65536, 3, 1, None)
        .map_err(|e| format!("Argon2 parámetros inválidos: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut ikm = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(frase.as_bytes(), salt, ikm.as_mut())
        .map_err(|e| format!("Argon2 hash falló: {}", e))?;
    let hk = Hkdf::<Sha256>::new(None, ikm.as_ref());
    let mut clave = Zeroizing::new([0u8; 32]);
    hk.expand(b"babel-recovery-v2", clave.as_mut())
        .map_err(|_| "HKDF: error derivando clave de recuperación v2".to_string())?;
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
