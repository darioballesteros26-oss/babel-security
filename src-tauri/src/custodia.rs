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
//
// Schema v2 (2026-08-17): los identificadores de hardware se almacenan como HwEntry
// con tipo explícito ("se" | "tpm" | "uuid"). El formato v1 (Vec<String> de UUIDs)
// se deserializa automáticamente como tipo="uuid" para migración transparente.

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

/// Entrada de hardware en el índice de custodia.
/// El campo `tipo` indica el mecanismo de vinculación:
///   "se"   — clave pública EC del Secure Enclave (macOS)
///   "tpm"  — clave pública EC del TPM (Windows)
///   "uuid" — UUID plano de la plataforma (fallback)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct HwEntry {
    pub tipo: String,
    pub id: String,
}

impl HwEntry {
    /// Construye un HwEntry desde la representación string del hw_id.
    /// "se:<hex>"  → tipo="se",  id=<hex>
    /// "tpm:<hex>" → tipo="tpm", id=<hex>
    /// (sin prefijo) → tipo="uuid", id=<str>
    pub fn from_hw_id(hw_id: &str) -> Self {
        if let Some(pubkey) = hw_id.strip_prefix("se:") {
            HwEntry { tipo: "se".into(), id: pubkey.to_string() }
        } else if let Some(pubkey) = hw_id.strip_prefix("tpm:") {
            HwEntry { tipo: "tpm".into(), id: pubkey.to_string() }
        } else {
            HwEntry { tipo: "uuid".into(), id: hw_id.to_string() }
        }
    }

    /// Comprueba si este HwEntry corresponde al hw_id dado (con prefijo).
    fn matches_hw_id(&self, hw_id: &str) -> bool {
        match self.tipo.as_str() {
            "se"  => hw_id == format!("se:{}", self.id),
            "tpm" => hw_id == format!("tpm:{}", self.id),
            _     => hw_id == self.id,
        }
    }
}

/// Enum auxiliar para deserializar tanto el formato v1 (String) como v2 (HwEntry).
#[derive(Deserialize)]
#[serde(untagged)]
enum HwEntradaRaw {
    Legacy(String),
    Nueva(HwEntry),
}

/// Índice de custodia. Se serializa como JSON y se cifra en custodia.babel.
///
/// Serialización hacia disco: siempre en formato v2 (Vec<HwEntry>).
/// Deserialización desde disco: acepta v1 (Vec<String>) y v2 (Vec<HwEntry>).
#[derive(Serialize, Clone, Default)]
pub struct CustodiaIndex {
    entradas: HashMap<String, Vec<HwEntry>>,
}

impl<'de> Deserialize<'de> for CustodiaIndex {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(default)]
            entradas: HashMap<String, Vec<HwEntradaRaw>>,
        }
        let wire = Wire::deserialize(d)?;
        let entradas = wire
            .entradas
            .into_iter()
            .map(|(k, vs)| {
                let entries = vs
                    .into_iter()
                    .map(|e| match e {
                        HwEntradaRaw::Legacy(s) => HwEntry { tipo: "uuid".into(), id: s },
                        HwEntradaRaw::Nueva(e) => e,
                    })
                    .collect();
                (k, entries)
            })
            .collect();
        Ok(CustodiaIndex { entradas })
    }
}

impl CustodiaIndex {
    /// Un archivo es accesible si no tiene entrada (legacy) o si el hw_id local
    /// o el de algún dispositivo emparejado está en su lista de autorizados.
    pub fn es_autorizado(
        &self,
        nombre: &str,
        hw_id_local: &str,
        hw_ids_pareados: &[String],
    ) -> bool {
        match self.entradas.get(nombre) {
            None => true, // sin entrada → archivo legacy, sin restricción
            Some(entries) => {
                entries.iter().any(|e| e.matches_hw_id(hw_id_local))
                    || entries
                        .iter()
                        .any(|e| hw_ids_pareados.iter().any(|p| e.matches_hw_id(p)))
            }
        }
    }

    /// Registra hw_id como autorizado para el archivo. Sin duplicados.
    pub fn agregar(&mut self, nombre: &str, hw_id: &str) {
        let entry = HwEntry::from_hw_id(hw_id);
        let entries = self.entradas.entry(nombre.to_string()).or_default();
        // Sin duplicados: comparamos por id (no por tipo+id) para tolerar
        // casos donde el mismo dispositivo migre de uuid a se.
        if !entries.iter().any(|e| e.id == entry.id) {
            entries.push(entry);
        }
    }

    /// Autoriza hw_id en TODOS los archivos registrados (llamado al emparejar un nuevo dispositivo).
    pub fn autorizar_hw_en_todos(&mut self, hw_id: &str) {
        let entry = HwEntry::from_hw_id(hw_id);
        for entries in self.entradas.values_mut() {
            if !entries.iter().any(|e| e.id == entry.id) {
                entries.push(entry.clone());
            }
        }
    }

    /// Devuelve los nombres de archivos cuyo hw_id local y ningún hw_id pareado están autorizados.
    pub fn archivos_no_autorizados(
        &self,
        hw_id_local: &str,
        hw_ids_pareados: &[String],
    ) -> Vec<String> {
        self.entradas
            .iter()
            .filter(|(_, entries)| {
                !entries.iter().any(|e| e.matches_hw_id(hw_id_local))
                    && !entries
                        .iter()
                        .any(|e| hw_ids_pareados.iter().any(|p| e.matches_hw_id(p)))
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
            log::warn!(
                "[CUSTODIA] custodia.babel existe pero no pudo descifrarse — verificación saltada en esta sesión"
            );
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

/// Devuelve el identificador de hardware del dispositivo actual.
/// Delega en enclave::obtener_hw_id() que intenta SE/TPM antes de UUID plano.
pub fn obtener_hw_id() -> String {
    crate::enclave::obtener_hw_id()
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
        idx.agregar("doc.babel", "hw-A");
        let pareados = vec!["hw-A".to_string()];
        assert!(idx.es_autorizado("doc.babel", "hw-B", &pareados));
    }

    #[test]
    fn hw_no_autorizado_no_par_es_rechazado() {
        let mut idx = CustodiaIndex::default();
        idx.agregar("doc.babel", "hw-A");
        let pareados = vec!["hw-B".to_string()];
        assert!(!idx.es_autorizado("doc.babel", "hw-C", &pareados));
        assert!(!idx.es_autorizado("doc.babel", "hw-C", &[]));
    }

    #[test]
    fn agregar_no_duplica() {
        let mut idx = CustodiaIndex::default();
        idx.agregar("f.babel", "hw-A");
        idx.agregar("f.babel", "hw-A");
        idx.agregar("f.babel", "hw-A");
        let ids = idx.entradas.get("f.babel").unwrap();
        assert_eq!(ids.len(), 1, "agregar varias veces el mismo hw_id no debe duplicar");
    }

    #[test]
    fn autorizar_hw_en_todos_añade_a_existentes() {
        let mut idx = CustodiaIndex::default();
        idx.agregar("a.babel", "hw-A");
        idx.agregar("b.babel", "hw-A");
        idx.autorizar_hw_en_todos("hw-B");
        assert!(idx.es_autorizado("a.babel", "hw-B", &[]));
        assert!(idx.es_autorizado("b.babel", "hw-B", &[]));
    }

    #[test]
    fn archivos_no_autorizados_lista_correcta() {
        let mut idx = CustodiaIndex::default();
        idx.agregar("mio.babel", "hw-A");
        idx.agregar("ajeno.babel", "hw-X");
        idx.agregar("pareado.babel", "hw-B");

        let hw_local = "hw-A";
        let pareados = vec!["hw-B".to_string()];
        let no_auth = idx.archivos_no_autorizados(hw_local, &pareados);

        assert!(
            no_auth.contains(&"ajeno.babel".to_string()),
            "archivo de hw desconocido debe ser no autorizado"
        );
        assert!(
            !no_auth.contains(&"mio.babel".to_string()),
            "archivo propio no debe aparecer"
        );
        assert!(
            !no_auth.contains(&"pareado.babel".to_string()),
            "archivo del par no debe aparecer"
        );
    }

    #[test]
    fn quitar_elimina_entrada() {
        let mut idx = CustodiaIndex::default();
        idx.agregar("doc.babel", "hw-A");
        assert!(idx.tiene_entrada("doc.babel"));
        idx.quitar("doc.babel");
        assert!(
            !idx.tiene_entrada("doc.babel"),
            "quitar debe eliminar la entrada del índice"
        );
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

    // ── Tests schema v2 ────────────────────────────────────────────────────────

    #[test]
    fn hw_entry_from_hw_id_uuid() {
        let e = HwEntry::from_hw_id("6B29FC40-CA28-4D95-8C21-DEADBEEF");
        assert_eq!(e.tipo, "uuid");
        assert_eq!(e.id, "6B29FC40-CA28-4D95-8C21-DEADBEEF");
    }

    #[test]
    fn hw_entry_from_hw_id_se() {
        let pubkey = "04".repeat(32) + "ff";
        let hw_id = format!("se:{}", pubkey);
        let e = HwEntry::from_hw_id(&hw_id);
        assert_eq!(e.tipo, "se");
        assert_eq!(e.id, pubkey);
    }

    #[test]
    fn hw_entry_from_hw_id_tpm() {
        let pubkey = "04aabbcc";
        let hw_id = format!("tpm:{}", pubkey);
        let e = HwEntry::from_hw_id(&hw_id);
        assert_eq!(e.tipo, "tpm");
        assert_eq!(e.id, pubkey);
    }

    #[test]
    fn hw_entry_matches_hw_id() {
        let e_uuid = HwEntry { tipo: "uuid".into(), id: "ABCD-1234".into() };
        assert!(e_uuid.matches_hw_id("ABCD-1234"));
        assert!(!e_uuid.matches_hw_id("XXXX-9999"));

        let e_se = HwEntry { tipo: "se".into(), id: "04deadbeef".into() };
        assert!(e_se.matches_hw_id("se:04deadbeef"));
        assert!(!e_se.matches_hw_id("04deadbeef")); // sin prefijo → no coincide
        assert!(!e_se.matches_hw_id("tpm:04deadbeef"));

        let e_tpm = HwEntry { tipo: "tpm".into(), id: "04cafebabe".into() };
        assert!(e_tpm.matches_hw_id("tpm:04cafebabe"));
        assert!(!e_tpm.matches_hw_id("se:04cafebabe"));
    }

    #[test]
    fn se_id_autoriza_correctamente() {
        let mut idx = CustodiaIndex::default();
        let hw_se = "se:04aabbccddeeff";
        idx.agregar("doc.babel", hw_se);
        assert!(idx.es_autorizado("doc.babel", hw_se, &[]));
        assert!(!idx.es_autorizado("doc.babel", "se:04FFFFFF", &[]));
        assert!(!idx.es_autorizado("doc.babel", "04aabbccddeeff", &[])); // sin prefijo
    }

    #[test]
    fn migracion_v1_string_a_hwentry() {
        // Simular JSON en formato v1 (Vec<String>) y verificar que se deserializa
        // correctamente como Vec<HwEntry> con tipo="uuid".
        let json_v1 = r#"{"entradas":{"doc.babel":["UUID-VIEJO-1","UUID-VIEJO-2"]}}"#;
        let idx: CustodiaIndex = serde_json::from_str(json_v1).expect("debe deserializar formato v1");
        assert!(idx.tiene_entrada("doc.babel"));
        assert!(idx.es_autorizado("doc.babel", "UUID-VIEJO-1", &[]));
        assert!(idx.es_autorizado("doc.babel", "UUID-VIEJO-2", &[]));
        assert!(!idx.es_autorizado("doc.babel", "UUID-DESCONOCIDO", &[]));
    }

    #[test]
    fn migracion_v2_hwentry_preserva_tipo() {
        let json_v2 = r#"{"entradas":{"doc.babel":[{"tipo":"se","id":"04abcdef"}]}}"#;
        let idx: CustodiaIndex = serde_json::from_str(json_v2).expect("debe deserializar formato v2");
        assert!(idx.es_autorizado("doc.babel", "se:04abcdef", &[]));
        assert!(!idx.es_autorizado("doc.babel", "04abcdef", &[]));
    }

    #[test]
    fn agregar_uuid_y_se_no_se_duplican_si_mismo_id() {
        let mut idx = CustodiaIndex::default();
        // Mismo id en tipo diferente: de uuid → se (migración manual)
        // La deduplicación es por .id, no por tipo+id
        idx.agregar("f.babel", "ABCD-1234");      // uuid
        idx.agregar("f.babel", "ABCD-1234");      // duplicado uuid → no agrega
        let len = idx.entradas.get("f.babel").unwrap().len();
        assert_eq!(len, 1, "no debe haber duplicado por id idéntico");
    }
}
