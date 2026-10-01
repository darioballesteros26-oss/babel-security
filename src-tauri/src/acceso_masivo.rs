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


/// Núcleo puro de la ventana deslizante: expira las entradas de más de
/// VENTANA_SECS, registra `ahora` y devuelve si se alcanza el umbral de bloqueo.
/// Extraído de `registrar_descifrado` para poder testear la decisión destructiva
/// (bloqueo de sesión) sin un `AppHandle` vivo.
fn registrar_en_ventana(lista: &mut Vec<Instant>, ahora: Instant) -> bool {
    lista.retain(|&t| ahora.duration_since(t).as_secs() < VENTANA_SECS);
    lista.push(ahora);
    lista.len() >= MAX_ACCESOS
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
        registrar_en_ventana(&mut lista, ahora)
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

    // ── Integración de la ruta destructiva (bloqueo de sesión) ──────────────────
    // Objetivo: que un usuario LEGÍTIMO nunca se bloquee, y que una ráfaga de
    // extracción automática SÍ. Usamos instantes sintéticos para controlar el tiempo
    // sin dormir el test.

    use std::time::Duration;

    #[test]
    fn atacante_rafaga_bloquea_al_quinto() {
        let base = Instant::now();
        let mut lista = Vec::new();
        let mut disparo = None;
        for i in 0..MAX_ACCESOS {
            // Ráfaga: 10 ms entre descifrados (imposible para un humano).
            let t = base + Duration::from_millis((i as u64) * 10);
            if registrar_en_ventana(&mut lista, t) {
                disparo = Some(i);
                break;
            }
        }
        assert_eq!(
            disparo,
            Some(MAX_ACCESOS - 1),
            "una ráfaga de {} descifrados debe bloquear en el último",
            MAX_ACCESOS
        );
    }

    #[test]
    fn usuario_ritmo_humano_nunca_bloquea() {
        // 1 descifrado cada 3 s durante 30 s: un usuario revisando documentos.
        // Con ventana de 10 s nunca hay 5 simultáneos → jamás debe bloquear.
        let base = Instant::now();
        let mut lista = Vec::new();
        let mut bloqueo = false;
        for i in 0..10u64 {
            bloqueo |= registrar_en_ventana(&mut lista, base + Duration::from_secs(i * 3));
        }
        assert!(!bloqueo, "un ritmo humano (1 cada 3 s) no debe bloquear nunca");
    }

    #[test]
    fn rafaga_con_pausa_no_bloquea_por_ventana_deslizante() {
        // 4 descifrados rápidos (bajo el umbral), pausa > ventana, y otros 4 rápidos.
        // Las primeras 4 entradas expiran, así que nunca se acumulan 5 → no bloquea.
        let base = Instant::now();
        let mut lista = Vec::new();
        let mut bloqueo = false;
        for i in 0..(MAX_ACCESOS - 1) as u64 {
            bloqueo |= registrar_en_ventana(&mut lista, base + Duration::from_millis(i * 10));
        }
        let despues = base + Duration::from_secs(VENTANA_SECS + 1);
        for i in 0..(MAX_ACCESOS - 1) as u64 {
            bloqueo |= registrar_en_ventana(&mut lista, despues + Duration::from_millis(i * 10));
        }
        assert!(
            !bloqueo,
            "4 + pausa > {}s + 4 no debe bloquear (la ventana descarta las viejas)",
            VENTANA_SECS
        );
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
        assert!(
            !BLOQUEADO.load(Ordering::SeqCst),
            "reset debe limpiar el bloqueo"
        );
        assert!(
            VENTANA.lock().unwrap().is_empty(),
            "reset debe vaciar la ventana"
        );
    }
}
