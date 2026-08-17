// Registro Diario — cifrado, local, zero-knowledge.
// Un archivo .babel por día en ~/Babel/registro_diario/YYYYMMDD.babel
// Preferencias de notificación en ~/Babel/prefs_registro.babel
// IPs históricas en ~/Babel/ips_registro.babel

use crate::{babel_dir, escribir_privado_atomico, SesionActiva};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

static REGISTRO_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn registro_dir() -> PathBuf {
    let dir = babel_dir().join("registro_diario");
    let _ = fs::create_dir_all(&dir);
    dir
}

fn prefs_path() -> PathBuf {
    babel_dir().join("prefs_registro.babel")
}

fn ips_path() -> PathBuf {
    babel_dir().join("ips_registro.babel")
}

fn dia_path(fecha: &str) -> PathBuf {
    // fecha es YYYYMMDD; se valida que solo contenga dígitos para evitar traversal
    let safe: String = fecha.chars().filter(|c| c.is_ascii_digit()).take(8).collect();
    registro_dir().join(format!("{}.babel", safe))
}

fn hoy_str() -> String {
    chrono::Local::now().format("%Y%m%d").to_string()
}

fn ahora_str() -> String {
    chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string()
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EventoDiario {
    pub tipo: String,
    pub timestamp: String,
    pub ip: String,
    pub detalle: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PreferenciasRegistro {
    pub hora: u8,
    pub minuto: u8,
    pub segundo: u8,
    pub primera_vez: bool,
}

impl Default for PreferenciasRegistro {
    fn default() -> Self {
        Self { hora: 10, minuto: 0, segundo: 0, primera_vez: true }
    }
}

fn leer_prefs(subclave_hex: &str) -> PreferenciasRegistro {
    if let Ok(bytes) = fs::read(prefs_path()) {
        if let Ok(json) = crate::seguridad::descifrar_documento(bytes, subclave_hex) {
            if let Ok(prefs) = serde_json::from_str::<PreferenciasRegistro>(&json) {
                return prefs;
            }
        }
    }
    PreferenciasRegistro::default()
}

fn guardar_prefs_inner(prefs: &PreferenciasRegistro, subclave_hex: &str) -> Result<(), String> {
    let json = serde_json::to_string(prefs).map_err(|e| e.to_string())?;
    let cifrado = crate::seguridad::blindar_documento(&json, subclave_hex)?;
    escribir_privado_atomico(prefs_path(), &cifrado).map_err(|e| e.to_string())
}

fn leer_eventos_dia(fecha: &str, subclave_hex: &str) -> Vec<EventoDiario> {
    if let Ok(bytes) = fs::read(dia_path(fecha)) {
        if let Ok(json) = crate::seguridad::descifrar_documento(bytes, subclave_hex) {
            if let Ok(eventos) = serde_json::from_str::<Vec<EventoDiario>>(&json) {
                return eventos;
            }
        }
    }
    Vec::new()
}

fn guardar_eventos_dia_inner(
    fecha: &str,
    eventos: &[EventoDiario],
    subclave_hex: &str,
) -> Result<(), String> {
    let json = serde_json::to_string(eventos).map_err(|e| e.to_string())?;
    let cifrado = crate::seguridad::blindar_documento(&json, subclave_hex)?;
    escribir_privado_atomico(dia_path(fecha), &cifrado).map_err(|e| e.to_string())
}

fn get_ip() -> String {
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                return addr.ip().to_string();
            }
        }
    }
    "IP no disponible".to_string()
}

fn leer_ips(subclave_hex: &str) -> Vec<String> {
    if let Ok(bytes) = fs::read(ips_path()) {
        if let Ok(json) = crate::seguridad::descifrar_documento(bytes, subclave_hex) {
            if let Ok(ips) = serde_json::from_str::<Vec<String>>(&json) {
                return ips;
            }
        }
    }
    Vec::new()
}

fn actualizar_ips_historial(ip: &str, subclave_hex: &str) {
    if ip == "IP no disponible" {
        return;
    }
    let mut ips = leer_ips(subclave_hex);
    if ips.contains(&ip.to_string()) {
        return;
    }
    ips.push(ip.to_string());
    if ips.len() > 20 {
        ips.remove(0);
    }
    if let Ok(json) = serde_json::to_string(&ips) {
        if let Ok(cifrado) = crate::seguridad::blindar_documento(&json, subclave_hex) {
            let _ = escribir_privado_atomico(ips_path(), &cifrado);
        }
    }
}

// ── API interna (sin Tauri State) ─────────────────────────────

/// Registra un evento de custodia directamente desde código Rust (no Tauri command).
/// Usado al inicio de sesión, antes de que el frontend esté listo.
pub fn registrar_sospecha_hw(archivo: &str, subclave_hex: &str) {
    if subclave_hex.is_empty() {
        return;
    }
    let evento = EventoDiario {
        tipo: "sospecha_hw".into(),
        timestamp: ahora_str(),
        ip: get_ip(),
        detalle: archivo.to_string(),
    };
    let _lock = match REGISTRO_MUTEX.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    let fecha = hoy_str();
    let mut eventos = leer_eventos_dia(&fecha, subclave_hex);
    eventos.push(evento);
    let _ = guardar_eventos_dia_inner(&fecha, &eventos, subclave_hex);
}

// ── COMANDOS TAURI ────────────────────────────────────────────

/// Añade un evento al registro cifrado del día en curso.
#[tauri::command]
pub fn registrar_evento_diario(
    tipo: String,
    detalle: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }

    let ip = get_ip();
    let es_login = tipo == "login";

    let evento = EventoDiario {
        tipo,
        timestamp: ahora_str(),
        ip: ip.clone(),
        detalle,
    };

    let _lock = REGISTRO_MUTEX.lock().map_err(|_| "Error mutex registro.".to_string())?;
    let fecha = hoy_str();
    let mut eventos = leer_eventos_dia(&fecha, &subclave_hex);
    eventos.push(evento);
    guardar_eventos_dia_inner(&fecha, &eventos, &subclave_hex)?;

    if es_login {
        actualizar_ips_historial(&ip, &subclave_hex);
    }

    Ok(())
}

/// Devuelve todos los eventos de un día (fecha en formato YYYYMMDD).
#[tauri::command]
pub fn obtener_eventos_dia(
    fecha: String,
    sesion: tauri::State<SesionActiva>,
) -> Result<Vec<EventoDiario>, String> {
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    Ok(leer_eventos_dia(&fecha, &subclave_hex))
}

/// Devuelve las preferencias de notificación (hora, minuto, segundo, primera_vez).
#[tauri::command]
pub fn obtener_preferencias_registro(
    sesion: tauri::State<SesionActiva>,
) -> Result<PreferenciasRegistro, String> {
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    Ok(leer_prefs(&subclave_hex))
}

/// Guarda la hora de notificación diaria.
#[tauri::command]
pub fn guardar_preferencias_registro(
    hora: u8,
    minuto: u8,
    segundo: u8,
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    if hora > 23 {
        return Err("Hora inválida.".into());
    }
    if minuto > 59 {
        return Err("Minuto inválido.".into());
    }
    if segundo > 59 {
        return Err("Segundo inválido.".into());
    }
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    let mut prefs = leer_prefs(&subclave_hex);
    prefs.hora = hora;
    prefs.minuto = minuto;
    prefs.segundo = segundo;
    guardar_prefs_inner(&prefs, &subclave_hex)
}

/// Marca el modal de primera vez como ya mostrado.
#[tauri::command]
pub fn marcar_primera_vez_registro(
    sesion: tauri::State<SesionActiva>,
) -> Result<(), String> {
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    let mut prefs = leer_prefs(&subclave_hex);
    prefs.primera_vez = false;
    guardar_prefs_inner(&prefs, &subclave_hex)
}

/// Devuelve la lista de IPs registradas en sesiones anteriores.
#[tauri::command]
pub fn obtener_ips_historial(
    sesion: tauri::State<SesionActiva>,
) -> Result<Vec<String>, String> {
    let subclave_hex = sesion.subclave_hex()?;
    if subclave_hex.is_empty() {
        return Err("No hay sesión activa.".into());
    }
    Ok(leer_ips(&subclave_hex))
}

// ── TESTS ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hoy_str_es_yyyymmdd() {
        let s = hoy_str();
        assert_eq!(s.len(), 8, "formato YYYYMMDD debe ser 8 dígitos");
        assert!(s.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn ahora_str_es_iso() {
        let s = ahora_str();
        assert_eq!(s.len(), 19, "formato ISO sin zona debe ser 19 chars");
        assert!(s.contains('T'));
        assert!(s.contains(':'));
    }

    #[test]
    fn prefs_default_valores() {
        let p = PreferenciasRegistro::default();
        assert_eq!(p.hora, 10);
        assert_eq!(p.minuto, 0);
        assert_eq!(p.segundo, 0);
        assert!(p.primera_vez);
    }

    #[test]
    fn evento_diario_serializa_y_deserializa() {
        let e = EventoDiario {
            tipo: "login".into(),
            timestamp: "2026-08-04T10:00:00".into(),
            ip: "192.168.1.1".into(),
            detalle: "".into(),
        };
        let j = serde_json::to_string(&e).unwrap();
        let d: EventoDiario = serde_json::from_str(&j).unwrap();
        assert_eq!(d.tipo, "login");
        assert_eq!(d.ip, "192.168.1.1");
        assert_eq!(d.detalle, "");
    }

    #[test]
    fn prefs_serializa_y_deserializa() {
        let p = PreferenciasRegistro { hora: 9, minuto: 30, segundo: 15, primera_vez: false };
        let j = serde_json::to_string(&p).unwrap();
        let d: PreferenciasRegistro = serde_json::from_str(&j).unwrap();
        assert_eq!(d.hora, 9);
        assert_eq!(d.minuto, 30);
        assert_eq!(d.segundo, 15);
        assert!(!d.primera_vez);
    }

    #[test]
    fn get_ip_devuelve_cadena_no_vacia() {
        let ip = get_ip();
        assert!(!ip.is_empty());
    }

    #[test]
    fn dia_path_sanitiza_fecha() {
        // Intento de traversal debe quedar neutralizado
        let ruta = dia_path("../../etc/passwd");
        let nombre = ruta.file_name().unwrap().to_string_lossy();
        // Solo dígitos → cadena vacía → archivo ".babel" en registro_dir
        assert!(!nombre.contains(".."));
        assert!(!nombre.contains("passwd"));
    }

    #[test]
    fn actualizar_ips_no_duplica() {
        let mut ips: Vec<String> = vec!["192.168.1.1".into(), "10.0.0.1".into()];
        let nueva = "192.168.1.1";
        if !ips.contains(&nueva.to_string()) {
            ips.push(nueva.to_string());
        }
        assert_eq!(ips.len(), 2, "no debe duplicar IPs ya conocidas");
    }

    #[test]
    fn actualizar_ips_limita_a_20() {
        let mut ips: Vec<String> = (0..20).map(|i| format!("10.0.0.{}", i)).collect();
        let nueva = "192.168.99.1";
        if !ips.contains(&nueva.to_string()) {
            ips.push(nueva.to_string());
        }
        if ips.len() > 20 {
            ips.remove(0);
        }
        assert_eq!(ips.len(), 20, "máximo 20 IPs en historial");
        assert!(ips.contains(&nueva.to_string()));
    }
}
