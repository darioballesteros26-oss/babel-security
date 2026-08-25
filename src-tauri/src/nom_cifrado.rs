// Índice cifrado de nombres de archivo.
//
// Propósito: los archivos cifrados en guardados/ y archivos/ usan nombres
// opacos en disco ({id}_{hex16}_{ts}.babel) para que no sea posible deducir
// el contenido de un documento a partir de su nombre de archivo visible en el
// sistema de archivos.  Este módulo mantiene un índice AES-256-GCM que mapea
// nombre_en_disco → MetaEntrada (nombre_original, ts_importacion, bytes_orig).
//
// Archivos de índice:
//   ~/Babel/guardados/.nomindex.babel
//   ~/Babel/archivos/.nomindex.babel
//
// Formato JSON:
//   {"disk.babel": {"nombre":"original.pdf","ts":1700000000,"bytes":1048576}, ...}
// Compatibilidad hacia atrás:
//   Entradas legacy (valor = String plana) se leen como MetaEntrada con ts=0/bytes=0.

use std::collections::HashMap;
use crate::seguridad;

/// Una entrada en el índice cifrado de nombres.
#[derive(serde::Serialize, Clone, Default)]
pub struct MetaEntrada {
    pub nombre: String,
    /// Unix timestamp de importación (segundos). 0 = legacy (desconocido).
    #[serde(skip_serializing_if = "es_cero")]
    pub ts: u64,
    /// Tamaño original del documento en bytes. 0 = legacy (desconocido).
    #[serde(skip_serializing_if = "es_cero")]
    pub bytes: u64,
}

fn es_cero(v: &u64) -> bool { *v == 0 }

// Deserialización compatible con el formato legacy (valor = String plana).
impl<'de> serde::Deserialize<'de> for MetaEntrada {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_json::Value::deserialize(d)?;
        if let Some(s) = v.as_str() {
            return Ok(MetaEntrada { nombre: s.to_string(), ts: 0, bytes: 0 });
        }
        let nombre = v["nombre"].as_str()
            .ok_or_else(|| serde::de::Error::missing_field("nombre"))?
            .to_string();
        Ok(MetaEntrada {
            nombre,
            ts: v["ts"].as_u64().unwrap_or(0),
            bytes: v["bytes"].as_u64().unwrap_or(0),
        })
    }
}

/// Carga el índice de nombres cifrado desde `ruta`.
/// Devuelve mapa vacío si el archivo no existe o no se puede descifrar.
pub fn leer(ruta: &str, subclave_hex: &str) -> HashMap<String, MetaEntrada> {
    std::fs::read(ruta)
        .ok()
        .and_then(|b| seguridad::descifrar_documento(b, subclave_hex).ok())
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default()
}

fn guardar(idx: &HashMap<String, MetaEntrada>, ruta: &str, subclave_hex: &str) -> Result<(), String> {
    let json = serde_json::to_string(idx).map_err(|e| e.to_string())?;
    let cifrado = seguridad::blindar_documento(&json, subclave_hex).map_err(|e| e.to_string())?;
    crate::escribir_privado_atomico(ruta, &cifrado).map_err(|e| e.to_string())
}

/// Registra nombre_disco → (nombre_visible, ts_importacion, bytes_originales).
/// Llamar mientras se mantiene BUZON_INDEX_MUTEX para serializar con otras mutaciones de índices.
pub fn registrar(
    nombre_disco: &str,
    nombre_visible: &str,
    ts: u64,
    bytes: u64,
    ruta: &str,
    subclave_hex: &str,
) -> Result<(), String> {
    let mut idx = leer(ruta, subclave_hex);
    idx.insert(nombre_disco.to_string(), MetaEntrada {
        nombre: nombre_visible.to_string(),
        ts,
        bytes,
    });
    guardar(&idx, ruta, subclave_hex)
}

/// Renombra la entrada visible preservando ts y bytes existentes.
pub fn actualizar(
    nombre_disco: &str,
    nombre_nuevo: &str,
    ruta: &str,
    subclave_hex: &str,
) -> Result<(), String> {
    let mut idx = leer(ruta, subclave_hex);
    let entrada = idx.entry(nombre_disco.to_string()).or_default();
    entrada.nombre = nombre_nuevo.to_string();
    guardar(&idx, ruta, subclave_hex)
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

        let r = registrar("abc123.babel", "informe_secreto", 1700000000, 1048576, &ruta, TEST_KEY);
        assert!(r.is_ok(), "registrar debe funcionar: {:?}", r);

        let idx = leer(&ruta, TEST_KEY);
        let entrada = idx.get("abc123.babel").expect("debe existir la entrada");
        assert_eq!(entrada.nombre, "informe_secreto");
        assert_eq!(entrada.ts, 1700000000);
        assert_eq!(entrada.bytes, 1048576);

        // actualizar solo el nombre, ts y bytes se preservan
        let r2 = actualizar("abc123.babel", "informe_renombrado", &ruta, TEST_KEY);
        assert!(r2.is_ok());
        let idx2 = leer(&ruta, TEST_KEY);
        let e2 = idx2.get("abc123.babel").unwrap();
        assert_eq!(e2.nombre, "informe_renombrado");
        assert_eq!(e2.ts, 1700000000, "ts debe preservarse tras actualizar");
        assert_eq!(e2.bytes, 1048576, "bytes debe preservarse tras actualizar");

        eliminar("abc123.babel", &ruta, TEST_KEY);
        let idx3 = leer(&ruta, TEST_KEY);
        assert!(!idx3.contains_key("abc123.babel"), "debe estar eliminado del índice");

        let _ = std::fs::remove_file(&ruta);
    }

    #[test]
    fn deserializa_formato_legacy_string() {
        let ruta = std::env::temp_dir()
            .join("__test_nomindex_legacy_babel__.babel")
            .to_string_lossy()
            .to_string();
        let _ = std::fs::remove_file(&ruta);

        // Escribir formato legacy directo (JSON con valor String)
        let json = r#"{"viejo.babel":"nombre_viejo"}"#;
        let cifrado = crate::seguridad::blindar_documento(json, TEST_KEY).unwrap();
        std::fs::write(&ruta, cifrado).unwrap();

        let idx = leer(&ruta, TEST_KEY);
        let e = idx.get("viejo.babel").expect("debe leer formato legacy");
        assert_eq!(e.nombre, "nombre_viejo");
        assert_eq!(e.ts, 0, "ts debe ser 0 en formato legacy");
        assert_eq!(e.bytes, 0, "bytes debe ser 0 en formato legacy");

        let _ = std::fs::remove_file(&ruta);
    }

    #[test]
    fn busqueda_dedup_en_nomindex() {
        let ruta = std::env::temp_dir()
            .join("__test_nomindex2_babel__.babel")
            .to_string_lossy()
            .to_string();
        let _ = std::fs::remove_file(&ruta);

        let _ = registrar("aaa001.babel", "Informe Fiscal Q1", 0, 0, &ruta, TEST_KEY);
        let _ = registrar("aaa002.babel", "Contrato Proveedor", 0, 0, &ruta, TEST_KEY);

        let idx = leer(&ruta, TEST_KEY);
        let buscado = "informe fiscal q1";
        let existe = idx.values().any(|v| v.nombre.to_lowercase() == buscado);
        assert!(existe, "dedup debe encontrar el nombre original en el índice");

        let no_existe = idx.values().any(|v| v.nombre.to_lowercase() == "nombre_que_no_existe");
        assert!(!no_existe, "no debe encontrar nombre inexistente");

        let _ = std::fs::remove_file(&ruta);
    }
}
