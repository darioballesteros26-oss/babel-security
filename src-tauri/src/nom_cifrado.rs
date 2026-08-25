// Índice cifrado de nombres de archivo.
//
// Propósito: los archivos cifrados en guardados/ y archivos/ usan nombres
// opacos en disco ({id}_{hex16}_{ts}.babel) para que no sea posible deducir
// el contenido de un documento a partir de su nombre de archivo visible en el
// sistema de archivos.  Este módulo mantiene un índice AES-256-GCM que mapea
// nombre_en_disco → nombre_original_visible, solo legible con la subclave del
// usuario autenticado.
//
// Archivos de índice:
//   ~/Babel/guardados/.nomindex.babel
//   ~/Babel/archivos/.nomindex.babel
//
// Serialización interna: JSON {"disk_name.babel": "nombre_original", ...}
// Compatibilidad: archivos anteriores sin entrada en el índice muestran el
// nombre derivado de su ruta (mismo comportamiento legacy que antes).

use std::collections::HashMap;
use crate::seguridad;

/// Carga el índice de nombres cifrado desde `ruta`.
/// Devuelve un mapa disk_filename → nombre_visible.
/// Devuelve mapa vacío si el archivo no existe o no se puede descifrar.
pub fn leer(ruta: &str, subclave_hex: &str) -> HashMap<String, String> {
    std::fs::read(ruta)
        .ok()
        .and_then(|b| seguridad::descifrar_documento(b, subclave_hex).ok())
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default()
}

fn guardar(idx: &HashMap<String, String>, ruta: &str, subclave_hex: &str) -> Result<(), String> {
    let json = serde_json::to_string(idx).map_err(|e| e.to_string())?;
    let cifrado = seguridad::blindar_documento(&json, subclave_hex).map_err(|e| e.to_string())?;
    crate::escribir_privado_atomico(ruta, &cifrado).map_err(|e| e.to_string())
}

/// Registra una nueva entrada disk_filename → nombre_visible (o actualiza la existente).
/// Llamar mientras se mantiene BUZON_INDEX_MUTEX para serializar con otras mutaciones de índices.
pub fn registrar(
    nombre_disco: &str,
    nombre_visible: &str,
    ruta: &str,
    subclave_hex: &str,
) -> Result<(), String> {
    let mut idx = leer(ruta, subclave_hex);
    idx.insert(nombre_disco.to_string(), nombre_visible.to_string());
    guardar(&idx, ruta, subclave_hex)
}

/// Actualiza el nombre visible de una entrada existente.
pub fn actualizar(
    nombre_disco: &str,
    nombre_nuevo: &str,
    ruta: &str,
    subclave_hex: &str,
) -> Result<(), String> {
    registrar(nombre_disco, nombre_nuevo, ruta, subclave_hex)
}

/// Elimina la entrada para un nombre en disco (al borrar el archivo).
/// Silencioso ante errores — la limpieza del índice no debe bloquear al usuario.
pub fn eliminar(nombre_disco: &str, ruta: &str, subclave_hex: &str) {
    let mut idx = leer(ruta, subclave_hex);
    if idx.remove(nombre_disco).is_some() {
        let _ = guardar(&idx, ruta, subclave_hex);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Clave AES-256 de 32 bytes para tests (no usada en producción).
    const TEST_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn leer_devuelve_vacio_si_no_existe() {
        let idx = leer("/tmp/__nomindex_inexistente_babel__", TEST_KEY);
        assert!(idx.is_empty(), "debe devolver mapa vacío si el archivo no existe");
    }

    #[test]
    fn nombre_disco_opaco_no_contiene_nombre_original() {
        let nombre_original = "informe_confidencial";
        let hex_opaco: u64 = 0xdeadbeef_cafebabe;
        let nombre_disco = format!("usuario_{:016x}_1700000000.babel", hex_opaco);
        assert!(
            !nombre_disco.contains(nombre_original),
            "el nombre en disco no debe revelar el contenido"
        );
        assert!(nombre_disco.contains("deadbeef"), "debe contener el componente hex");
    }

    #[test]
    fn roundtrip_registrar_leer_actualizar_eliminar() {
        let ruta = std::env::temp_dir()
            .join("__test_nomindex_babel__.babel")
            .to_string_lossy()
            .to_string();
        let _ = std::fs::remove_file(&ruta);

        // Registrar
        let r = registrar("abc123.babel", "informe_secreto", &ruta, TEST_KEY);
        assert!(r.is_ok(), "registrar debe funcionar: {:?}", r);

        // Leer de vuelta
        let idx = leer(&ruta, TEST_KEY);
        assert_eq!(idx.get("abc123.babel").map(|s| s.as_str()), Some("informe_secreto"));

        // Actualizar
        let r2 = actualizar("abc123.babel", "informe_renombrado", &ruta, TEST_KEY);
        assert!(r2.is_ok());
        let idx2 = leer(&ruta, TEST_KEY);
        assert_eq!(idx2.get("abc123.babel").map(|s| s.as_str()), Some("informe_renombrado"));

        // Eliminar
        eliminar("abc123.babel", &ruta, TEST_KEY);
        let idx3 = leer(&ruta, TEST_KEY);
        assert!(!idx3.contains_key("abc123.babel"), "debe estar eliminado del índice");

        let _ = std::fs::remove_file(&ruta);
    }

    #[test]
    fn busqueda_dedup_en_nomindex() {
        let ruta = std::env::temp_dir()
            .join("__test_nomindex2_babel__.babel")
            .to_string_lossy()
            .to_string();
        let _ = std::fs::remove_file(&ruta);

        let _ = registrar("aaa001.babel", "Informe Fiscal Q1", &ruta, TEST_KEY);
        let _ = registrar("aaa002.babel", "Contrato Proveedor", &ruta, TEST_KEY);

        let idx = leer(&ruta, TEST_KEY);
        let buscado = "informe fiscal q1";
        let existe = idx.values().any(|v| v.to_lowercase() == buscado);
        assert!(existe, "dedup debe encontrar el nombre original en el índice");

        let no_existe = idx.values().any(|v| v.to_lowercase() == "nombre_que_no_existe");
        assert!(!no_existe, "no debe encontrar nombre inexistente");

        let _ = std::fs::remove_file(&ruta);
    }
}
