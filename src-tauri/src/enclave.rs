// Vinculación de hardware mediante Secure Enclave (macOS Apple Silicon / T2),
// TPM (Windows), o UUID plano como fallback.
//
// La clave privada NUNCA sale del chip de seguridad. El identificador del
// dispositivo es la clave pública EC P-256, que tiene la forma:
//   "se:<hex_65_bytes>"  — Secure Enclave (macOS)
//   "tpm:<hex_65_bytes>" — TPM (Windows)
//   "<uuid>"             — UUID plano (fallback sin chip de seguridad)
//
// La mejora sobre UUID plano: un atacante que copie el disco obtiene la clave
// pública (que ya estaba en custodia.babel), pero NO la privada (que vive en
// el hardware). Por tanto no puede presentar el mismo identificador desde otro
// dispositivo, a diferencia del UUID que puede leerse y replicarse.

/// Nivel de protección de la vinculación de hardware en este dispositivo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NivelSeguridad {
    SecureEnclave,
    Tpm,
    /// Fallback: el UUID plano puede copiarse con acceso físico al disco.
    UuidPlano,
}

impl std::fmt::Display for NivelSeguridad {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SecureEnclave => write!(f, "secure_enclave"),
            Self::Tpm => write!(f, "tpm"),
            Self::UuidPlano => write!(f, "uuid_plano"),
        }
    }
}

/// Identificador único del dispositivo actual.
/// Intenta Secure Enclave (macOS) o TPM (Windows) primero;
/// cae a UUID plano si el chip de seguridad no está disponible.
pub fn obtener_hw_id() -> String {
    #[cfg(target_os = "macos")]
    {
        if let Some(id) = macos_se::hw_id_se() {
            return id;
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(id) = windows_tpm::hw_id_tpm() {
            return id;
        }
    }
    obtener_uuid_plano()
}

/// Nivel de seguridad del hw_id que retornaría `obtener_hw_id()` ahora mismo.
pub fn nivel_seguridad_actual() -> NivelSeguridad {
    let id = obtener_hw_id();
    if id.starts_with("se:") {
        NivelSeguridad::SecureEnclave
    } else if id.starts_with("tpm:") {
        NivelSeguridad::Tpm
    } else {
        NivelSeguridad::UuidPlano
    }
}

// ── UUID plano (fallback universal) ──────────────────────────────────────────

fn obtener_uuid_plano() -> String {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("ioreg")
            .args(["-d2", "-c", "IOPlatformExpertDevice"])
            .output()
            .ok()
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .find(|l| l.contains("IOPlatformUUID"))
                    .and_then(|l| l.split('"').nth(3))
                    .map(|u| u.to_string())
            })
            .unwrap_or_else(|| hostname_fallback())
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("reg")
            .args([
                "query",
                r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography",
                "/v",
                "MachineGuid",
            ])
            .output()
            .ok()
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .find(|l| l.contains("MachineGuid"))
                    .and_then(|l| l.split_whitespace().last())
                    .map(|u| u.trim().to_string())
            })
            .unwrap_or_else(|| hostname_fallback())
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        hostname_fallback()
    }
}

fn hostname_fallback() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "babel-hw-fallback".to_string())
}

// ── macOS Secure Enclave ──────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod macos_se {
    use std::os::raw::c_void;
    use core_foundation_sys::{
        base::{kCFAllocatorDefault, CFRelease, CFTypeRef, CFIndex},
        data::{CFDataCreate, CFDataGetBytePtr, CFDataGetLength, CFDataRef},
        dictionary::{
            kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks,
            CFDictionaryCreate, CFDictionaryRef,
        },
        number::{CFNumberCreate, kCFNumberSInt32Type},
    };

    // kCFBooleanTrue no está en core-foundation-sys 0.8; lo declaramos directamente.
    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        static kCFBooleanTrue: CFTypeRef;
    }

    type SecKeyRef = *const c_void;
    type CFErrorRef = *mut c_void;
    type OSStatus = i32;

    // Etiqueta que identifica la clave de Babel en el Keychain del SE.
    const SE_TAG: &[u8] = b"com.security.babel.hwbinding.v1";

    // Security.framework — constantes y funciones de clave y Keychain.
    // Todos los atributos kSec* son CFStringRef internamente, pero se tratan
    // como CFTypeRef (void*) porque en el diccionario son valores opacos.
    #[link(name = "Security", kind = "framework")]
    extern "C" {
        // Tipos de clave
        static kSecAttrKeyType: CFTypeRef;
        static kSecAttrKeyTypeECSECPrimeRandom: CFTypeRef;
        static kSecAttrKeySizeInBits: CFTypeRef;

        // Secure Enclave
        static kSecAttrTokenID: CFTypeRef;
        static kSecAttrTokenIDSecureEnclave: CFTypeRef;

        // Atributos de clave privada
        static kSecPrivateKeyAttrs: CFTypeRef;
        static kSecAttrIsPermanent: CFTypeRef;
        static kSecAttrApplicationTag: CFTypeRef;

        // Keychain query
        static kSecClass: CFTypeRef;
        static kSecClassKey: CFTypeRef;
        static kSecReturnRef: CFTypeRef;
        static kSecMatchLimit: CFTypeRef;
        static kSecMatchLimitOne: CFTypeRef;

        // Funciones de clave
        fn SecKeyCreateRandomKey(params: CFDictionaryRef, err: *mut CFErrorRef) -> SecKeyRef;
        fn SecKeyCopyPublicKey(key: SecKeyRef) -> SecKeyRef;
        fn SecKeyCopyExternalRepresentation(key: SecKeyRef, err: *mut CFErrorRef) -> CFDataRef;
        fn SecItemCopyMatching(query: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
    }

    /// Construye un CFDictionary desde slices paralelas de claves y valores.
    /// Todos los punteros deben ser CFTypeRef válidos con retainCount >= 1.
    unsafe fn cf_dict(keys: &[CFTypeRef], vals: &[CFTypeRef]) -> CFDictionaryRef {
        debug_assert_eq!(keys.len(), vals.len());
        CFDictionaryCreate(
            kCFAllocatorDefault,
            keys.as_ptr() as *const *const c_void,
            vals.as_ptr() as *const *const c_void,
            keys.len() as CFIndex,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        )
    }

    /// Busca la clave SE existente en el Keychain y devuelve los bytes de la
    /// clave pública (65 bytes, punto EC sin comprimir: 04 || X || Y).
    unsafe fn buscar_en_keychain() -> Option<Vec<u8>> {
        let tag = CFDataCreate(
            kCFAllocatorDefault,
            SE_TAG.as_ptr(),
            SE_TAG.len() as CFIndex,
        );
        if tag.is_null() {
            return None;
        }

        let q = cf_dict(
            &[kSecClass, kSecAttrApplicationTag, kSecReturnRef, kSecMatchLimit],
            &[
                kSecClassKey,
                tag as CFTypeRef,
                kCFBooleanTrue as CFTypeRef,
                kSecMatchLimitOne,
            ],
        );
        CFRelease(tag as CFTypeRef);
        if q.is_null() {
            return None;
        }

        let mut out: CFTypeRef = std::ptr::null();
        let st = SecItemCopyMatching(q, &mut out);
        CFRelease(q as CFTypeRef);

        if st != 0 || out.is_null() {
            return None;
        }

        let pub_k = SecKeyCopyPublicKey(out as SecKeyRef);
        CFRelease(out);
        if pub_k.is_null() {
            return None;
        }

        let mut e: CFErrorRef = std::ptr::null_mut();
        let data = SecKeyCopyExternalRepresentation(pub_k, &mut e);
        CFRelease(pub_k);
        if data.is_null() {
            if !e.is_null() {
                CFRelease(e as CFTypeRef);
            }
            return None;
        }

        let n = CFDataGetLength(data) as usize;
        let bytes = std::slice::from_raw_parts(CFDataGetBytePtr(data), n).to_vec();
        CFRelease(data as CFTypeRef);
        Some(bytes)
    }

    /// Genera un nuevo par de claves EC P-256 en el Secure Enclave y persiste
    /// la clave privada en el Keychain del dispositivo. Devuelve la clave pública.
    unsafe fn crear_en_se() -> Option<Vec<u8>> {
        let tag = CFDataCreate(
            kCFAllocatorDefault,
            SE_TAG.as_ptr(),
            SE_TAG.len() as CFIndex,
        );
        if tag.is_null() {
            return None;
        }

        // Atributos de la clave privada: persistente + etiqueta de identificación
        let priv_d = cf_dict(
            &[kSecAttrIsPermanent, kSecAttrApplicationTag],
            &[kCFBooleanTrue as CFTypeRef, tag as CFTypeRef],
        );
        CFRelease(tag as CFTypeRef);
        if priv_d.is_null() {
            return None;
        }

        let bits: i32 = 256;
        let bits_n = CFNumberCreate(
            kCFAllocatorDefault,
            kCFNumberSInt32Type,
            &bits as *const i32 as *const c_void,
        );
        if bits_n.is_null() {
            CFRelease(priv_d as CFTypeRef);
            return None;
        }

        // kSecAttrTokenIDSecureEnclave fuerza la generación dentro del chip
        let params = cf_dict(
            &[
                kSecAttrKeyType,
                kSecAttrKeySizeInBits,
                kSecAttrTokenID,
                kSecPrivateKeyAttrs,
            ],
            &[
                kSecAttrKeyTypeECSECPrimeRandom,
                bits_n as CFTypeRef,
                kSecAttrTokenIDSecureEnclave,
                priv_d as CFTypeRef,
            ],
        );
        CFRelease(bits_n as CFTypeRef);
        CFRelease(priv_d as CFTypeRef);
        if params.is_null() {
            return None;
        }

        let mut e: CFErrorRef = std::ptr::null_mut();
        let priv_k = SecKeyCreateRandomKey(params, &mut e);
        CFRelease(params as CFTypeRef);

        if priv_k.is_null() {
            if !e.is_null() {
                CFRelease(e as CFTypeRef);
            }
            return None;
        }

        let pub_k = SecKeyCopyPublicKey(priv_k);
        CFRelease(priv_k);
        if pub_k.is_null() {
            return None;
        }

        let mut e2: CFErrorRef = std::ptr::null_mut();
        let data = SecKeyCopyExternalRepresentation(pub_k, &mut e2);
        CFRelease(pub_k);
        if data.is_null() {
            if !e2.is_null() {
                CFRelease(e2 as CFTypeRef);
            }
            return None;
        }

        let n = CFDataGetLength(data) as usize;
        let bytes = std::slice::from_raw_parts(CFDataGetBytePtr(data), n).to_vec();
        CFRelease(data as CFTypeRef);
        Some(bytes)
    }

    /// Devuelve "se:<hex>" con la clave pública EC del Secure Enclave,
    /// o None si el SE no está disponible en este dispositivo.
    pub fn hw_id_se() -> Option<String> {
        let bytes = unsafe { buscar_en_keychain().or_else(|| crear_en_se()) }?;
        // Punto EC sin comprimir: 04 (1) + X (32) + Y (32) = 65 bytes
        if bytes.len() < 33 {
            return None;
        }
        Some(format!("se:{}", hex::encode(&bytes)))
    }
}

// ── Windows TPM ───────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
mod windows_tpm {
    // NCrypt API — Trusted Platform Module key storage.
    // Usa el proveedor "Microsoft Platform Crypto Provider" que delega en el TPM.
    // Si el TPM no está disponible, hw_id_tpm() devuelve None y el llamador
    // cae a UUID plano.
    //
    // La clave privada EC P-256 generada aquí NO puede exportarse del TPM
    // (se crea sin flag NCRYPT_ALLOW_EXPORT_FLAG).
    #[link(name = "Ncrypt")]
    extern "system" {
        fn NCryptOpenStorageProvider(
            ph: *mut isize,
            name: *const u16,
            flags: u32,
        ) -> i32;
        fn NCryptOpenKey(
            prov: isize,
            ph: *mut isize,
            name: *const u16,
            spec: u32,
            flags: u32,
        ) -> i32;
        fn NCryptCreatePersistedKey(
            prov: isize,
            ph: *mut isize,
            alg: *const u16,
            name: *const u16,
            spec: u32,
            flags: u32,
        ) -> i32;
        fn NCryptFinalizeKey(key: isize, flags: u32) -> i32;
        fn NCryptExportKey(
            key: isize,
            exp: isize,
            blob_type: *const u16,
            params: *mut u8,
            out: *mut u8,
            out_len: u32,
            result: *mut u32,
            flags: u32,
        ) -> i32;
        fn NCryptFreeObject(obj: isize) -> i32;
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    const SUCCESS: i32 = 0;
    // ECCPUBLICBLOB: 4 bytes magic + 4 bytes cbKey + cbKey bytes X + cbKey bytes Y
    const COORD: usize = 32; // P-256: 32 bytes por coordenada
    const BLOB_LEN: u32 = (8 + 2 * COORD) as u32;

    pub fn hw_id_tpm() -> Option<String> {
        let prov_name = wide("Microsoft Platform Crypto Provider");
        let key_name = wide("BabelHWBinding");
        let alg = wide("ECDSA_P256");
        let blob_type = wide("ECCPUBLICBLOB");

        let mut prov: isize = 0;
        if unsafe { NCryptOpenStorageProvider(&mut prov, prov_name.as_ptr(), 0) } != SUCCESS {
            // Sin TPM disponible → fallback a UUID
            return None;
        }

        let mut key: isize = 0;
        let st_open =
            unsafe { NCryptOpenKey(prov, &mut key, key_name.as_ptr(), 0, 0) };
        if st_open != SUCCESS {
            // Crear nueva clave EC P-256 en el TPM
            let st_c = unsafe {
                NCryptCreatePersistedKey(
                    prov,
                    &mut key,
                    alg.as_ptr(),
                    key_name.as_ptr(),
                    0,
                    0,
                )
            };
            if st_c != SUCCESS {
                unsafe {
                    NCryptFreeObject(prov);
                }
                return None;
            }
            if unsafe { NCryptFinalizeKey(key, 0) } != SUCCESS {
                unsafe {
                    NCryptFreeObject(key);
                    NCryptFreeObject(prov);
                }
                return None;
            }
        }

        // Exportar clave pública como ECCPUBLICBLOB
        let mut buf = vec![0u8; BLOB_LEN as usize];
        let mut out_len: u32 = 0;
        let st_e = unsafe {
            NCryptExportKey(
                key,
                0,
                blob_type.as_ptr(),
                std::ptr::null_mut(),
                buf.as_mut_ptr(),
                BLOB_LEN,
                &mut out_len,
                0,
            )
        };
        unsafe {
            NCryptFreeObject(key);
            NCryptFreeObject(prov);
        }

        if st_e != SUCCESS || out_len as usize != 8 + 2 * COORD {
            return None;
        }

        // Convertir a punto EC sin comprimir: 04 || X || Y
        let x = &buf[8..8 + COORD];
        let y = &buf[8 + COORD..8 + 2 * COORD];
        let mut pub_bytes = vec![0x04u8];
        pub_bytes.extend_from_slice(x);
        pub_bytes.extend_from_slice(y);

        Some(format!("tpm:{}", hex::encode(&pub_bytes)))
    }
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
    fn nivel_seguridad_coherente_con_id() {
        let id = obtener_hw_id();
        let nivel = nivel_seguridad_actual();
        match nivel {
            NivelSeguridad::SecureEnclave => {
                assert!(id.starts_with("se:"), "nivel SE pero id no tiene prefijo 'se:'")
            }
            NivelSeguridad::Tpm => {
                assert!(id.starts_with("tpm:"), "nivel TPM pero id no tiene prefijo 'tpm:'")
            }
            NivelSeguridad::UuidPlano => {
                assert!(
                    !id.starts_with("se:") && !id.starts_with("tpm:"),
                    "nivel UUID pero id tiene prefijo de chip"
                )
            }
        }
    }

    // Test de SE marcado como #[ignore]: sólo pasa en hardware Apple Silicon / T2.
    // Ejecutar manualmente con: cargo test -- --ignored
    #[test]
    #[ignore = "requiere Secure Enclave (Apple Silicon o Intel T2) — ejecutar manualmente"]
    fn se_genera_clave_y_la_recupera() {
        #[cfg(target_os = "macos")]
        {
            let id1 = macos_se::hw_id_se().expect("SE debe estar disponible en este hardware");
            assert!(id1.starts_with("se:"), "debe tener prefijo 'se:'");
            let hex = id1.strip_prefix("se:").unwrap();
            // Punto EC P-256 sin comprimir: 04 (1B) + X (32B) + Y (32B) = 65 bytes = 130 hex chars
            assert_eq!(hex.len(), 130, "clave pública P-256 debe ser 65 bytes (130 hex chars)");
            // Segunda llamada debe devolver LA MISMA clave (recuperada del Keychain)
            let id2 = macos_se::hw_id_se().expect("segunda llamada debe recuperar la clave existente");
            assert_eq!(id1, id2, "hw_id_se debe ser estable entre llamadas");
        }
        #[cfg(not(target_os = "macos"))]
        {
            panic!("test sólo aplicable en macOS");
        }
    }

    // Test de TPM marcado como #[ignore]: sólo pasa en hardware Windows con TPM.
    #[test]
    #[ignore = "requiere TPM (Windows) — ejecutar manualmente en hardware con TPM 2.0"]
    fn tpm_genera_clave_y_la_recupera() {
        #[cfg(target_os = "windows")]
        {
            let id1 = windows_tpm::hw_id_tpm().expect("TPM debe estar disponible");
            assert!(id1.starts_with("tpm:"));
            let hex = id1.strip_prefix("tpm:").unwrap();
            assert_eq!(hex.len(), 130, "clave pública P-256 = 65 bytes = 130 hex chars");
            let id2 = windows_tpm::hw_id_tpm().expect("segunda llamada debe recuperar clave");
            assert_eq!(id1, id2, "hw_id_tpm debe ser estable entre llamadas");
        }
        #[cfg(not(target_os = "windows"))]
        {
            panic!("test sólo aplicable en Windows");
        }
    }

    #[test]
    fn uuid_plano_fallback_no_vacio() {
        let uuid = obtener_uuid_plano();
        assert!(!uuid.is_empty(), "UUID plano no debe ser vacío");
        assert!(uuid.len() > 3, "UUID plano debe tener al menos 4 caracteres");
    }

    #[test]
    fn nivel_seguridad_display() {
        assert_eq!(NivelSeguridad::SecureEnclave.to_string(), "secure_enclave");
        assert_eq!(NivelSeguridad::Tpm.to_string(), "tpm");
        assert_eq!(NivelSeguridad::UuidPlano.to_string(), "uuid_plano");
    }
}
