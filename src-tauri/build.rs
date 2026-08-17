fn main() {
    tauri_build::build();

    // Huella de build para la capa de integridad de binario (Parte 2).
    // Se genera en tiempo de compilación y se embebe como constante en el binario.
    // El verificador en runtime la compara contra ~/Babel/.integridad para detectar
    // sustitución del binario por una build diferente.
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    // XOR con un salt fijo para que dos builds en el mismo segundo difieran
    // si el salt cambia en un futuro refactor, y para que no sea sólo temporal.
    let a = ts ^ 0xdeadbeef_cafebabe_u64;
    let b = ts.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    let fp = format!("babel-fp-{:016x}{:016x}", a, b);
    println!("cargo:rustc-env=BABEL_BUILD_FINGERPRINT={}", fp);

    // Hace que cargo re-ejecute build.rs si cambia
    println!("cargo:rerun-if-changed=build.rs");
}
