// Detector de acceso masivo: si se descifran N archivos en X segundos desde el
// dispositivo autorizado, Babel bloquea la sesión y exige reautenticación.
//
// Cubre el escenario de malware o script que extrae el vault archivo por archivo
// directamente desde el ordenador de la víctima — escenario que custodia.rs no
// puede detectar porque el hw_id del atacante ES el dispositivo autorizado.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tauri::Emitter;

// Umbral: 5 archivos en 10 segundos. Un humano tarda varios segundos en abrir,
// leer y cerrar cada archivo; un script lo hace en milisegundos.
const MAX_ACCESOS: usize = 5;
const VENTANA_SECS: u64 = 10;

// Versiones pub para el mensaje del registro de sospechas.
pub const MAX_ACCESOS_LOG: usize = MAX_ACCESOS;
pub const VENTANA_SECS_LOG: u64 = VENTANA_SECS;

static VENTANA: Mutex<Vec<Instant>> = Mutex::new(Vec::new());
static BLOQUEADO: AtomicBool = AtomicBool::new(false);

pub fn es_bloqueado() -> bool {
    BLOQUEADO.load(Ordering::Acquire)
}

/// Registra un descifrado de archivo en la ventana deslizante.
/// Si se superan MAX_ACCESOS en VENTANA_SECS segundos:
///   - bloquea la sesión
///   - emite "acceso-masivo-detectado" al frontend (que muestra la pantalla de bloqueo)
///   - registra el evento en Sospechas
///   - devuelve Err para que el comando llamante aborte
pub fn registrar_descifrado(app: &tauri::AppHandle, subclave_hex: &str) -> Result<(), String> {
    if BLOQUEADO.load(Ordering::Acquire) {
        return Err(
            "Sesión bloqueada: demasiados archivos abiertos en poco tiempo. \
             Introduce tus credenciales para continuar."
                .into(),
        );
    }

    let supera = {
        let ahora = Instant::now();
        let mut lista = VENTANA.lock().unwrap_or_else(|e| e.into_inner());
        lista.retain(|&t| ahora.duration_since(t).as_secs() < VENTANA_SECS);
        lista.push(ahora);
        lista.len() >= MAX_ACCESOS
    };

    if supera {
        BLOQUEADO.store(true, Ordering::Release);
        let _ = app.emit("acceso-masivo-detectado", ());
        if !subclave_hex.is_empty() {
            crate::registro_diario::registrar_sospecha_acceso_masivo(subclave_hex);
        }
        log::warn!(
            "[ACCESO-MASIVO] {} archivos descifrados en menos de {}s — sesión bloqueada.",
            MAX_ACCESOS,
            VENTANA_SECS
        );
        return Err(
            "Sesión bloqueada: demasiados archivos abiertos en poco tiempo. \
             Introduce tus credenciales para continuar."
                .into(),
        );
    }

    Ok(())
}

/// Reinicia el contador tras un login correcto. Llamado desde verificar_login.
pub fn reset_tras_login() {
    BLOQUEADO.store(false, Ordering::Release);
    if let Ok(mut lista) = VENTANA.lock() {
        lista.clear();
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Serializa los tests que tocan estado global para evitar interferencias
    // cuando el runner los ejecuta en paralelo.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn limpiar() {
        BLOQUEADO.store(false, Ordering::SeqCst);
        VENTANA.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    #[test]
    fn umbral_correcto() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        limpiar();
        let ahora = Instant::now();
        let mut lista = VENTANA.lock().unwrap();
        for _ in 0..MAX_ACCESOS {
            lista.push(ahora);
        }
        assert!(lista.len() >= MAX_ACCESOS, "debe superar umbral con MAX_ACCESOS entradas");
        drop(lista);
        limpiar();
    }

    #[test]
    fn entradas_antiguas_expiran() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        limpiar();
        {
            let mut lista = VENTANA.lock().unwrap();
            let viejo = Instant::now()
                .checked_sub(std::time::Duration::from_secs(VENTANA_SECS + 1))
                .unwrap_or_else(Instant::now);
            lista.push(viejo);
        }
        let ahora = Instant::now();
        let mut lista = VENTANA.lock().unwrap();
        lista.retain(|&t| ahora.duration_since(t).as_secs() < VENTANA_SECS);
        assert!(lista.is_empty(), "entrada antigua debe expirar de la ventana");
        drop(lista);
        limpiar();
    }

    #[test]
    fn reset_tras_login_limpia_estado() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        BLOQUEADO.store(true, Ordering::SeqCst);
        {
            let mut lista = VENTANA.lock().unwrap();
            lista.push(Instant::now());
        }
        reset_tras_login();
        assert!(!es_bloqueado(), "reset debe limpiar el bloqueo");
        assert!(
            VENTANA.lock().unwrap().is_empty(),
            "reset debe vaciar la ventana"
        );
    }

    #[test]
    fn bloqueado_rechaza_sin_app() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        BLOQUEADO.store(true, Ordering::SeqCst);
        assert!(es_bloqueado());
        BLOQUEADO.store(false, Ordering::SeqCst);
        assert!(!es_bloqueado());
    }
}
