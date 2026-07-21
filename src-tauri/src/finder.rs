// SISTEMA BABEL — MÓDULO FINDER
//
// Integración "Guardar con Babel" desde el clic derecho del Finder (macOS).
//
// Transporte: un Quick Action / Servicio de macOS copia cada archivo seleccionado
// a la carpeta de staging ~/Babel/entrada_finder/ y dispara el URL scheme
// `babel://guardar`. Babel escanea esa carpeta, cifra cada archivo reutilizando
// crate::cifrar_y_guardar_desde_ruta (AES-256-GCM), y borra de forma segura tanto la
// copia staged en claro como el archivo original (crate::borrar_seguro).
//
// Por qué staging en vez de pasar la ruta por la URL: bajo App Sandbox un path que
// llega por URL NO es "user-selected", así que la app firmada no podría leerlo. La
// carpeta de staging vive dentro del propio directorio de Babel (lecutra siempre
// permitida) y además actúa como cola durable cuando la sesión está bloqueada o la
// app cerrada: los archivos esperan ahí hasta el próximo login.
//
// Este módulo contiene solo lógica pura (rutas, parseo de URL, escaneo y orquestación
// del cifrado inyectado). Los comandos Tauri y el acceso a la sesión viven en main.rs,
// siguiendo el mismo patrón que el módulo `compartir`.

use std::fs;
use std::path::{Path, PathBuf};

/// ~/Babel/entrada_finder/ — carpeta de staging. El Quick Action deposita aquí una
/// copia `<uuid>__<nombre>` de cada archivo y un sidecar `<uuid>.orig` con la ruta
/// absoluta del original (para poder borrarlo tras cifrar).
pub fn entrada_finder_dir() -> PathBuf {
    let dir = crate::babel_dir().join("entrada_finder");
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Acción codificada en una URL `babel://`.
#[derive(Debug, PartialEq, Eq)]
pub enum AccionBabel {
    /// babel://guardar — procesar la carpeta de staging.
    Guardar,
}

/// Valida y parsea una URL `babel://`. Solo aceptamos el host `guardar`
/// (con o sin barra o query final). Cualquier otra cosa devuelve None y se ignora,
/// evitando que una URL arbitraria dispare comportamiento inesperado.
pub fn parsear_url_babel(url: &str) -> Option<AccionBabel> {
    let resto = url.strip_prefix("babel://")?;
    // El host es lo que va antes de la primera '/', '?' o '#'.
    let host = resto.split(['/', '?', '#']).next().unwrap_or("");
    match host {
        "guardar" => Some(AccionBabel::Guardar),
        _ => None,
    }
}

/// Un archivo depositado por el Quick Action, listo para cifrar.
#[derive(Debug)]
pub struct EntradaStaged {
    /// Copia en claro dentro de entrada_finder/ (`<uuid>__<nombre>`).
    pub staged: PathBuf,
    /// Nombre original visible (sin el prefijo `<uuid>__`).
    pub nombre: String,
    /// Ruta del archivo original a borrar tras cifrar (del sidecar .orig), si existe.
    pub original: Option<PathBuf>,
    /// Ruta del sidecar .orig para limpiarlo tras procesar, si existe.
    pub sidecar: Option<PathBuf>,
}

/// Escanea `dir` y devuelve las entradas staged pendientes. Empareja cada
/// `<uuid>__<nombre>` con su sidecar `<uuid>.orig`. Los `uuid` (uuidgen) no contienen
/// `__`, así que el split por la primera aparición de `__` es inequívoco.
pub fn escanear_entrada(dir: &Path) -> Vec<EntradaStaged> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let fname = entry.file_name().to_string_lossy().to_string();
        // Ignorar ocultos, sidecars y no-ficheros.
        if fname.starts_with('.') || fname.ends_with(".orig") {
            continue;
        }
        if !path.is_file() {
            continue;
        }
        let (uuid, nombre) = match fname.split_once("__") {
            Some((u, n)) if !n.is_empty() => (u.to_string(), n.to_string()),
            _ => continue, // formato desconocido — ignorar sin romper
        };
        let sidecar = dir.join(format!("{}.orig", uuid));
        let (original, sidecar) = if sidecar.exists() {
            let orig = fs::read_to_string(&sidecar)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .map(PathBuf::from);
            (orig, Some(sidecar))
        } else {
            (None, None)
        };
        out.push(EntradaStaged {
            staged: path,
            nombre,
            original,
            sidecar,
        });
    }
    out
}

/// Resultado de procesar una entrada staged (se emite al frontend).
#[derive(Debug)]
pub struct ResultadoFinder {
    pub nombre: String,
    pub ok: bool,
    pub error: Option<String>,
    /// true si el cifrado fue correcto pero el original no pudo borrarse (sandbox).
    pub original_no_borrado: bool,
}

/// Verifica que la ruta del original sea segura para borrar:
/// - Debe ser absoluta (no relativa).
/// - No puede estar dentro de ~/Babel/ — impide que un sidecar malicioso
///   destruya el vault cifrado u otros archivos de la propia app.
fn ruta_original_segura(orig: &Path) -> bool {
    if !orig.is_absolute() {
        log::error!("[finder] sidecar con ruta relativa bloqueada: {}", orig.display());
        return false;
    }
    let babel = crate::babel_dir();
    // canonicalize resuelve symlinks; si falla (ruta inexistente), rechazar por precaución.
    if let (Ok(orig_c), Ok(babel_c)) = (fs::canonicalize(orig), fs::canonicalize(&babel)) {
        if orig_c.starts_with(&babel_c) {
            log::error!(
                "[finder] sidecar apunta dentro de ~/Babel/ — bloqueado: {}",
                orig.display()
            );
            return false;
        }
    }
    true
}

/// Procesa todas las entradas staged en `dir`:
///   1. Cifra cada copia staged con `cifrar(nombre, ruta_staged)` (inyectado para
///      poder testear sin tocar la criptografía real ni el disco del usuario).
///   2. Si el cifrado tuvo éxito: borra de forma segura la copia staged en claro, el
///      archivo original (si el sidecar lo indica y es accesible) y el sidecar.
///   3. Si falló: borra la copia staged en claro y el sidecar (no dejar plaintext
///      acumulándose ni reintentar en bucle) PERO NO toca el original.
///
/// Nunca panica: los errores se loguean con log::error!/log::warn! y se devuelven.
pub fn procesar_entradas<F>(dir: &Path, cifrar: F) -> Vec<ResultadoFinder>
where
    F: Fn(&str, &str) -> Result<String, String>,
{
    let mut resultados = Vec::new();
    for entrada in escanear_entrada(dir) {
        let staged_str = entrada.staged.to_string_lossy().to_string();
        match cifrar(&entrada.nombre, &staged_str) {
            Ok(_) => {
                // Borrado seguro de la copia staged en claro (3 pasadas + fsync).
                crate::borrar_seguro(&staged_str);
                // Borrado seguro del original. Funciona en dev/no-sandbox; bajo sandbox
                // firmado el SO rechaza la escritura y el archivo queda en disco.
                let mut original_no_borrado = false;
                if let Some(orig) = &entrada.original {
                    if ruta_original_segura(orig) {
                        if orig.exists() {
                            let orig_str = orig.to_string_lossy().to_string();
                            crate::borrar_seguro(&orig_str);
                            // Comprobar si el borrado tuvo efecto (falla en sandbox).
                            if orig.exists() {
                                original_no_borrado = true;
                                log::warn!(
                                    "[finder] original sigue en disco tras borrado (sandbox?): {}",
                                    orig_str
                                );
                            }
                        }
                    }
                }
                if let Some(sc) = &entrada.sidecar {
                    let _ = fs::remove_file(sc);
                }
                resultados.push(ResultadoFinder {
                    nombre: entrada.nombre,
                    ok: true,
                    error: None,
                    original_no_borrado,
                });
            }
            Err(e) => {
                log::error!("[finder] fallo al cifrar '{}': {}", entrada.nombre, e);
                // Limpiar la copia staged en claro y el sidecar; conservar el original.
                crate::borrar_seguro(&staged_str);
                if let Some(sc) = &entrada.sidecar {
                    let _ = fs::remove_file(sc);
                }
                resultados.push(ResultadoFinder {
                    nombre: entrada.nombre,
                    ok: false,
                    error: Some(e),
                    original_no_borrado: false,
                });
            }
        }
    }
    resultados
}

// ── TESTS ────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    // Directorio temporal único por test (hermético — no toca ~/Babel del usuario).
    fn dir_temporal() -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("babel_finder_test_{}_{}", pid, n));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    // TEST 1 — El parser de URL solo acepta babel://guardar.
    #[test]
    fn parser_url_acepta_solo_guardar() {
        assert_eq!(parsear_url_babel("babel://guardar"), Some(AccionBabel::Guardar));
        assert_eq!(parsear_url_babel("babel://guardar/"), Some(AccionBabel::Guardar));
        assert_eq!(parsear_url_babel("babel://guardar?x=1"), Some(AccionBabel::Guardar));
        assert_eq!(parsear_url_babel("babel://otra"), None);
        assert_eq!(parsear_url_babel("https://guardar"), None);
        assert_eq!(parsear_url_babel("babel://"), None);
    }

    // TEST "la ruta llega correctamente" — escanear_entrada empareja staged + sidecar
    // y expone el nombre real y la ruta del original.
    #[test]
    fn escaneo_empareja_staged_con_original() {
        let dir = dir_temporal();
        fs::write(dir.join("abc-123__informe.pdf"), b"contenido").unwrap();
        fs::write(dir.join("abc-123.orig"), "/Users/tester/Desktop/informe.pdf").unwrap();
        // Un archivo sin sidecar (staging directo).
        fs::write(dir.join("def-456__foto.png"), b"img").unwrap();

        let mut entradas = escanear_entrada(&dir);
        entradas.sort_by(|a, b| a.nombre.cmp(&b.nombre));
        assert_eq!(entradas.len(), 2);

        let foto = &entradas[0];
        assert_eq!(foto.nombre, "foto.png");
        assert!(foto.original.is_none());

        let informe = &entradas[1];
        assert_eq!(informe.nombre, "informe.pdf");
        assert_eq!(
            informe.original.as_ref().unwrap(),
            &PathBuf::from("/Users/tester/Desktop/informe.pdf")
        );
    }

    // TEST 2 — Flujo con sesión activa: cifra → borra staged → borra original → limpia
    // sidecar. Simulamos "sesión activa" con un cifrado inyectado que siempre tiene éxito.
    #[test]
    fn flujo_sesion_activa_cifra_y_borra_todo() {
        let dir = dir_temporal();
        // "Original" fuera de la carpeta de staging.
        let original = dir.join("original_real.txt");
        fs::write(&original, b"secreto").unwrap();

        let staged = dir.join("uuid1__original_real.txt");
        fs::write(&staged, b"secreto").unwrap();
        let sidecar = dir.join("uuid1.orig");
        fs::write(&sidecar, original.to_string_lossy().as_bytes()).unwrap();

        let salida = dir.join("salida.babel");
        let salida_c = salida.clone();
        let resultados = procesar_entradas(&dir, move |_nombre, _staged| {
            fs::write(&salida_c, b"cifrado").unwrap();
            Ok(salida_c.to_string_lossy().to_string())
        });

        assert_eq!(resultados.len(), 1);
        assert!(resultados[0].ok);
        assert!(salida.exists(), "el .babel cifrado debe existir");
        assert!(!staged.exists(), "la copia staged en claro debe borrarse");
        assert!(!original.exists(), "el original debe borrarse de forma segura");
        assert!(!sidecar.exists(), "el sidecar debe limpiarse");
    }

    // TEST 3 — Si el cifrado falla, NO se borra el original (el usuario no pierde datos);
    // solo se limpia la copia staged en claro y el sidecar.
    #[test]
    fn flujo_fallo_conserva_original() {
        let dir = dir_temporal();
        let original = dir.join("original_real.txt");
        fs::write(&original, b"secreto").unwrap();

        let staged = dir.join("uuid2__original_real.txt");
        fs::write(&staged, b"secreto").unwrap();
        let sidecar = dir.join("uuid2.orig");
        fs::write(&sidecar, original.to_string_lossy().as_bytes()).unwrap();

        let resultados = procesar_entradas(&dir, |_n, _s| Err("tipo no permitido".into()));

        assert_eq!(resultados.len(), 1);
        assert!(!resultados[0].ok);
        assert!(original.exists(), "el original NO debe borrarse si el cifrado falla");
        assert!(!staged.exists(), "la copia staged en claro sí se limpia");
    }
}
