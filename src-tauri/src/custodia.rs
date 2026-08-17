// Custodia — vinculación de archivos .babel en ~/Babel/guardados/ a hardware autorizado.
//
// Cada archivo importado queda registrado con el HW ID del dispositivo que lo creó.
// Al iniciar sesión, Babel comprueba que el dispositivo actual esté autorizado para
// cada archivo con entrada de custodia. Si no lo está, elimina la copia silenciosamente
// y registra el evento como "sospecha_hw" en el registro diario.
//
// Autorización: el archivo es accesible si:
//   a) No tiene entrada de custodia (archivo legacy, sin restricción), O
//   b) El HW ID del dispositivo actual aparece en su lista de autorizados, O
//   c) Al menos un HW ID de un dispositivo emparejado aparece en su lista
//      (el archivo llegó de una fuente confiable vía sincronización).
//
// Exenciones:
//   - Archivos en ~/Babel/archivos/ (traducciones) → no aplica custodia.
//   - Archivos compartidos por email (HTML autónomo) → fuera del vault, no aplica.

use std::collections::HashMap;
use std::fs;
use serde::{Deserialize, Serialize};

static CUSTODIA_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn custodia_path() -> std::path::PathBuf {
    let dir = crate::babel_dir().join("sinc");
    let _ = fs::create_dir_all(&dir);
    dir.join("custodia.babel")
}

// ── Tipos ─────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct CustodiaIndex {
    entradas: HashMap<String, Vec<String>>,
}

impl CustodiaIndex {
    /// Un archivo es accesible si no tiene entrada (legacy) o si el hw_id local
    /// o el de algún dispositivo emparejado está en su lista de autorizados.
    pub fn es_autorizado(&self, nombre: &str, hw_id_local: &str, hw_ids_pareados: &[String]) -> bool {
        match self.entradas.get(nombre) {
            None => true, // sin entrada → archivo legacy, sin restricción
            Some(ids) => {
                ids.contains(&hw_id_local.to_string())
                    || ids.iter().any(|id| hw_ids_pareados.contains(id))
            }
        }
    }

    /// Registra hw_id como autorizado para el archivo. Sin duplicados.
    pub fn agregar(&mut self, nombre: &str, hw_id: &str) {
        let ids = self.entradas.entry(nombre.to_string()).or_default();
        let hw = hw_id.to_string();
        if !ids.contains(&hw) {
            ids.push(hw);
        }
    }

    /// Autoriza hw_id en TODOS los archivos registrados (llamado al emparejar un nuevo dispositivo).
    pub fn autorizar_hw_en_todos(&mut self, hw_id: &str) {
        let hw = hw_id.to_string();
        for ids in self.entradas.values_mut() {
            if !ids.contains(&hw) {
                ids.push(hw.clone());
            }
        }
    }

    /// Devuelve los nombres de archivos cuyo hw_id local y ningún hw_id pareado están autorizados.
    pub fn archivos_no_autorizados(&self, hw_id_local: &str, hw_ids_pareados: &[String]) -> Vec<String> {
        self.entradas
            .iter()
            .filter(|(_, ids)| {
                !ids.contains(&hw_id_local.to_string())
                    && !ids.iter().any(|id| hw_ids_pareados.contains(id))
            })
            .map(|(nombre, _)| nombre.clone())
            .collect()
    }

    /// Elimina la entrada de un archivo del índice.
    pub fn quitar(&mut self, nombre: &str) {
        self.entradas.remove(nombre);
    }

    pub fn tiene_entrada(&self, nombre: &str) -> bool {
        self.entradas.contains_key(nombre)
    }
}

// ── I/O cifrado ───────────────────────────────────────────────────────────────

fn cargar_custodia(subclave_hex: &str) -> CustodiaIndex {
    if subclave_hex.is_empty() {
        return CustodiaIndex::default();
    }
    let path = custodia_path();
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return CustodiaIndex::default(),
        Err(e) => {
            log::error!("[CUSTODIA] Error leyendo custodia.babel: {}", e);
            return CustodiaIndex::default();
        }
    };
    match crate::seguridad::descifrar_documento(bytes, subclave_hex)
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
    {
        Some(idx) => idx,
        None => {
            log::warn!("[CUSTODIA] custodia.babel existe pero no pudo descifrarse — verificación saltada en esta sesión");
            CustodiaIndex::default()
        }
    }
}

fn guardar_custodia(idx: &CustodiaIndex, subclave_hex: &str) {
    if subclave_hex.is_empty() {
        return;
    }
    if let Ok(json) = serde_json::to_string(idx) {
        if let Ok(cifrado) = crate::seguridad::blindar_documento(&json, subclave_hex) {
            if let Err(e) = crate::escribir_privado_atomico(custodia_path(), cifrado) {
                log::error!("[CUSTODIA] Error guardando custodia: {}", e);
            }
        }
    }
}

// ── Hardware ID ───────────────────────────────────────────────────────────────

/// Devuelve el identificador de hardware único del dispositivo actual.
/// macOS: IOPlatformUUID (ioreg). Windows: MachineGuid (registro). Fallback: hostname.
pub fn obtener_hw_id() -> String {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("ioreg")
            .args(["-d2", "-c", "IOPlatformExpertDevice"])
            .output()
            .ok()
            .and_then(|o| {
                let s = String::from_utf8_lossy(&o.stdout).to_string();
                s.lines()
                    .find(|l| l.contains("IOPlatformUUID"))
                    .and_then(|l| l.split('"').nth(3))
                    .map(|u| u.to_string())
            })
            .unwrap_or_else(|| {
                hostname::get()
                    .map(|h| h.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "babel-hw-fallback".to_string())
            })
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("reg")
            .args(["query", r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"])
            .output()
            .ok()
            .and_then(|o| {
                let s = String::from_utf8_lossy(&o.stdout).to_string();
                s.lines()
                    .find(|l| l.contains("MachineGuid"))
                    .and_then(|l| l.split_whitespace().last())
                    .map(|u| u.trim().to_string())
            })
            .unwrap_or_else(|| {
                hostname::get()
                    .map(|h| h.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "babel-hw-fallback".to_string())
            })
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "babel-hw-fallback".to_string())
    }
}

// ── API pública ───────────────────────────────────────────────────────────────

/// Registra nombre_archivo como vinculado al HW ID del dispositivo actual.
/// Llamado cuando un archivo se cifra y guarda en ~/Babel/guardados/.
pub fn registrar_archivo(nombre_archivo: &str, subclave_hex: &str) {
    if subclave_hex.is_empty() || nombre_archivo.is_empty() {
        return;
    }
    let hw_id = obtener_hw_id();
    if hw_id.is_empty() {
        return;
    }
    let _lock = CUSTODIA_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let mut idx = cargar_custodia(subclave_hex);
    idx.agregar(nombre_archivo, &hw_id);
    guardar_custodia(&idx, subclave_hex);
}

/// Autoriza hw_id en todos los archivos del índice (llamado al emparejar un dispositivo nuevo).
pub fn autorizar_hw_en_todos(hw_id: &str, subclave_hex: &str) {
    if subclave_hex.is_empty() || hw_id.is_empty() {
        return;
    }
    let _lock = CUSTODIA_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let mut idx = cargar_custodia(subclave_hex);
    idx.autorizar_hw_en_todos(hw_id);
    guardar_custodia(&idx, subclave_hex);
}

/// Escanea ~/Babel/guardados/, elimina archivos no autorizados para este dispositivo
/// y devuelve los nombres de los eliminados (para registrarlos en el historial).
/// hw_ids_pareados: HW IDs de dispositivos con los que este dispositivo está emparejado.
pub fn verificar_y_limpiar(subclave_hex: &str, hw_ids_pareados: &[String]) -> Vec<String> {
    if subclave_hex.is_empty() {
        return Vec::new();
    }
    let hw_id = obtener_hw_id();
    if hw_id.is_empty() {
        return Vec::new();
    }

    let _lock = CUSTODIA_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let mut idx = cargar_custodia(subclave_hex);
    let no_autorizados = idx.archivos_no_autorizados(&hw_id, hw_ids_pareados);

    if no_autorizados.is_empty() {
        return Vec::new();
    }

    let guardados = crate::babel_dir().join("guardados");
    let mut eliminados = Vec::new();
    let mut indice_modificado = false;

    for nombre in &no_autorizados {
        let ruta = guardados.join(nombre);
        // remove_file es la única operación: evita TOCTOU de exists()+remove.
        // NotFound = el archivo ya no estaba → limpiar entrada del índice igualmente.
        // Cualquier otro error = el archivo sigue en disco → conservar la entrada
        //   para que sea detectado de nuevo en la próxima sesión.
        match fs::remove_file(&ruta) {
            Ok(_) => {
                eliminados.push(nombre.clone());
                idx.quitar(nombre);
                indice_modificado = true;
                log::warn!("[CUSTODIA] Copia no autorizada eliminada: {}", nombre);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                idx.quitar(nombre);
                indice_modificado = true;
            }
            Err(e) => {
                // El archivo sigue en disco; NO quitar del índice para reintentarlo
                // en la siguiente sesión.
                log::error!("[CUSTODIA] No se pudo eliminar {}: {}", nombre, e);
            }
        }
    }

    if indice_modificado {
        guardar_custodia(&idx, subclave_hex);
    }

    eliminados
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hw_id_no_vacio() {
        let id = obtener_hw_id();
        assert!(!id.is_empty(), "obtener_hw_id debe devolver un valor no vacío");
    }

    #[test]
    fn sin_entrada_siempre_autorizado() {
        let idx = CustodiaIndex::default();
        // Archivo sin entrada en el índice → autorizado (backward compat con archivos legacy)
        assert!(idx.es_autorizado("archivo.babel", "hw-A", &[]));
        assert!(idx.es_autorizado("archivo.babel", "hw-A", &["hw-B".into()]));
    }

    #[test]
    fn hw_local_en_lista_es_autorizado() {
        let mut idx = CustodiaIndex::default();
        idx.agregar("doc.babel", "hw-A");
        assert!(idx.es_autorizado("doc.babel", "hw-A", &[]));
        assert!(idx.es_autorizado("doc.babel", "hw-A", &["hw-X".into()]));
    }

    #[test]
    fn hw_pareado_en_lista_es_autorizado() {
        let mut idx = CustodiaIndex::default();
        idx.agregar("doc.babel", "hw-A"); // creado en A
        // Dispositivo B lee el archivo; A es su par → autorizado
        let pareados = vec!["hw-A".to_string()];
        assert!(idx.es_autorizado("doc.babel", "hw-B", &pareados));
    }

    #[test]
    fn hw_no_autorizado_no_par_es_rechazado() {
        let mut idx = CustodiaIndex::default();
        idx.agregar("doc.babel", "hw-A");
        // Dispositivo C: hw-A no es su hw local ni está en sus pares → no autorizado
        let pareados = vec!["hw-B".to_string()];
        assert!(!idx.es_autorizado("doc.babel", "hw-C", &pareados));
        assert!(!idx.es_autorizado("doc.babel", "hw-C", &[]));
    }

    #[test]
    fn agregar_no_duplica() {
        let mut idx = CustodiaIndex::default();
        idx.agregar("f.babel", "hw-A");
        idx.agregar("f.babel", "hw-A"); // duplicado
        idx.agregar("f.babel", "hw-A");
        let ids = idx.entradas.get("f.babel").unwrap();
        assert_eq!(ids.len(), 1, "agregar varias veces el mismo hw_id no debe duplicar");
    }

    #[test]
    fn autorizar_hw_en_todos_añade_a_existentes() {
        let mut idx = CustodiaIndex::default();
        idx.agregar("a.babel", "hw-A");
        idx.agregar("b.babel", "hw-A");
        // Dispositivo B se empareja → autorizar hw-B en todos
        idx.autorizar_hw_en_todos("hw-B");
        assert!(idx.es_autorizado("a.babel", "hw-B", &[]));
        assert!(idx.es_autorizado("b.babel", "hw-B", &[]));
    }

    #[test]
    fn archivos_no_autorizados_lista_correcta() {
        let mut idx = CustodiaIndex::default();
        idx.agregar("mio.babel",    "hw-A"); // este dispositivo (A)
        idx.agregar("ajeno.babel",  "hw-X"); // de dispositivo desconocido
        idx.agregar("pareado.babel","hw-B"); // del par de A

        let hw_local = "hw-A";
        let pareados  = vec!["hw-B".to_string()];
        let no_auth = idx.archivos_no_autorizados(hw_local, &pareados);

        assert!(no_auth.contains(&"ajeno.babel".to_string()),
            "archivo de hw desconocido debe ser no autorizado");
        assert!(!no_auth.contains(&"mio.babel".to_string()),
            "archivo propio no debe aparecer");
        assert!(!no_auth.contains(&"pareado.babel".to_string()),
            "archivo del par no debe aparecer");
    }

    #[test]
    fn quitar_elimina_entrada() {
        let mut idx = CustodiaIndex::default();
        idx.agregar("doc.babel", "hw-A");
        assert!(idx.tiene_entrada("doc.babel"));
        idx.quitar("doc.babel");
        assert!(!idx.tiene_entrada("doc.babel"),
            "quitar debe eliminar la entrada del índice");
        // Sin entrada → autorizado (backward compat)
        assert!(idx.es_autorizado("doc.babel", "hw-X", &[]));
    }

    #[test]
    fn sospecha_hw_evento_serializa() {
        let evento = crate::registro_diario::EventoDiario {
            tipo: "sospecha_hw".into(),
            timestamp: "2026-08-16T22:00:00".into(),
            ip: "192.168.1.5".into(),
            detalle: "extraño_12345.babel".into(),
        };
        let j = serde_json::to_string(&evento).unwrap();
        let d: crate::registro_diario::EventoDiario = serde_json::from_str(&j).unwrap();
        assert_eq!(d.tipo, "sospecha_hw");
        assert_eq!(d.detalle, "extraño_12345.babel");
    }
}
