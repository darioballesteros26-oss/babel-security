# Babel Security

App de escritorio **Tauri v2** (Rust + frontend web) para cifrar, traducir, editar,
firmar y compartir documentos, 100 % local y offline. Incluye un **sidecar Python**
(`servidor_babel/`) para traducción (CTranslate2), IA de redacción (llama.cpp / Qwen),
OCR (PaddleOCR-VL) y firma PAdES. App version: `0.2.8` (ver `src-tauri/Cargo.toml`).
Identifier Tauri: `com.security.babel`.

## Comandos (build / test / run)

```bash
# Tests Rust (la suite principal; ~214 tests)
cd src-tauri && cargo test --bin babel-interfaz
cargo test --bin babel-interfaz pdf_reducir      # un solo módulo (rápido)
cargo clippy --bin babel-interfaz                # lints / cazador de bugs

# Sintaxis del sidecar Python
python3 -m py_compile servidor_babel/*.py

# App en desarrollo (arranca Vite + ventana Tauri)
npm run tauri dev

# Empaquetado (DMG completo con modelos, ~3 GB)
./crear_dmg_bundle.sh            # bundle app + firma.py crudo
./servidor_babel/build_sidecar.sh   # sidecar PyInstaller (para updates .app.tar.gz)
./preparar_usb.sh                # pack USB (~5.5 GB con modelos)
```

> Nota: tras `cargo clean` el primer build es completo (varios minutos: llama.cpp,
> pdfium, etc.). Mantén `target/` caliente para feedback rápido.

## Arquitectura

**Vault**: todo en `~/Babel` (ruta FIJA, `babel_dir()`), independiente del identifier.
Ficheros internos SIEMPRE con permisos 0600 vía `escribir_privado` / `escribir_privado_atomico`.

**Rust — `src-tauri/src/`**
- `main.rs` — comandos Tauri (monolito, ~7.6k líneas). Punto de entrada de todo el IPC.
- `seguridad.rs` — motor de cifrado: **AES-256-GCM + Argon2id (128 MB / 4 iter / 4 lanes) + HKDF-SHA256**, todo con `zeroize`.
- `pdf_reducir.rs` — pipeline de compresión de PDF/DOCX (ver abajo).
- `custodia.rs` — device binding: cada `.babel` se liga al hardware (Secure Enclave). `verificar_y_limpiar` borra al login los ficheros no autorizados en este equipo.
- `acceso_masivo.rs` — anti-exfiltración: `registrar_descifrado` bloquea la sesión tras 5 descifrados en 10 s.
- `rat_detector.rs` — detección de control remoto (TeamViewer/AnyDesk/screensharing…) + bloqueo del vault.
- `enclave.rs` — identidad de hardware (SE/TPM) para el device binding.
- `integridad.rs` — verificación del binario (codesign + fingerprint). **Parcialmente desactivada** hasta tener Developer ID / Authenticode (ver TODOs).
- `compartir.rs` — compartir seguro: HTML autónomo autodescifrable (**PBKDF2-SHA256 600k + AES-256-GCM**), constante única `ITERACIONES_PBKDF2`.
- `sincronizacion.rs` / `babel_p2p.rs` / `conexion_directa.rs` — sync P2P entre dispositivos (TCP + STUN + emparejamiento).
- `gmail_oauth.rs` — OAuth 2.0 PKCE (scope mail.google.com); `traductor.rs` gestiona email/IMAP.
- `ia_redaccion.rs` — asistente de redacción (arranca `llama-server` con Qwen, fallback GPU→CPU).
- `ia_biblioteca.rs` — RAG jurídico (BM25) sobre biblioteca en `~/Babel/biblioteca_juridica`.
- `img_a_pdf.rs`, `pdf_union.rs`, `finder.rs`, `registro_diario.rs`, `nom_cifrado.rs`, `buzon_b2.rs`.

**Pipeline de compresión PDF** (`pdf_reducir.rs`, corre en cada import; solo acepta el
resultado si es más pequeño y valida con PDFium):
1. `optimizar_imagenes_pdf` — recompresión (JPEG/DCTDecode sobredimensionados → downsample;
   crudo/Flate → 1-bit o JPEG q85) **+ recorte por DPI de colocación** (mide el CTM de los
   content streams: una foto grande colocada pequeña se recorta a 300 DPI) **+ dedup** de
   imágenes byte-idénticas, todo en una sola carga/guardado de lopdf.
2. `subset_fuentes` — elimina glifos no usados de fuentes TrueType.
3. `comprimir_streams` — FlateDecode nivel 9 sobre streams sin filtro.
DOCX/PPTX/XLSX: `reducir_docx` (downsample de imágenes + re-deflate del XML).

**Python — `servidor_babel/`**
- `server.py` — Flask; enruta traducción, OCR (PaddleOCR-VL) y firma.
- `traduccion_small100.py` (<12 GB RAM) / `traduccion_madlad.py` (≥12 GB) — CTranslate2 int8; `traduccion_comun.py` = utilidades (incl. `hilos_intra`). El tier se elige por RAM.
- `firma.py` — firma PAdES-B-B; `md_to_pdf.py`, `pymupdf4llm_extract.py`.

**Frontend**: `index.html` (SPA en un único archivo ~200 KB) + Vite/TS + editor Tiptap.

## Invariantes de seguridad (NO romper)
- Nunca escribir **plaintext** a disco fuera de temporales gestionados; usar `escribir_privado` (0600).
- No reutilizar nonces de AES-GCM (siempre `OsRng`); no bajar los parámetros de Argon2.
- Device binding y anti-acceso-masivo se aplican por rutas ya cableadas (`verificar_y_limpiar`, `registrar_descifrado`); no duplicarlas.
- Los ficheros compartidos SALEN del dispositivo: mantener PBKDF2 ≥ 600k y sincronizado entre Rust y el `const ITER` del JS.
- Los datos ajenos/credenciales de terceros no se tocan (device binding limpia, no exfiltra).

## Convenciones
- **Comandos Tauri con trabajo pesado** (cifrado, pipeline PDF, red, subprocesos) →
  `async fn` + `tauri::async_runtime::spawn_blocking`, para no congelar el event-loop.
  Los diálogos nativos `blocking_*` deben ir dentro de `spawn_blocking`.
- Código y comentarios en **español**; estilo de commits `tipo(scope): descripción`.
- Flujo directo en `main` (o ramas cortas fusionadas por fast-forward). El release se
  dispara con un tag `v*` → GitHub Actions.
- Tests: la lógica pura (cripto, compresión) tiene buena cobertura unitaria; los comandos
  Tauri no tienen tests de integración (requieren app viva).
