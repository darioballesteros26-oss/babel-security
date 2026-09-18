#!/usr/bin/env bash
# preparar_usb.sh — USB autocontenido de Babel Security (solo macOS)
#   Traducción: auto-tier MADLAD-3B (≥12 GB RAM) / SMaLL-100 (8 GB RAM)
#   IA redacción: Qwen3-4B-Q6_K (llama-server bundleado)
#   Firma digital: PAdES-B-B vía pyHanko (firma.py)
#
# USO:
#   ./preparar_usb.sh /Volumes/BABEL_USB
#   ./preparar_usb.sh ~/Desktop/USB_BABEL              ← prueba sin USB físico
#   ./preparar_usb.sh /Volumes/BABEL_USB --reset-cache ← fuerza reinstalación Python
#
# VARIABLES DE ENTORNO (opcionales):
#   BABEL_DIR        — directorio raíz de Babel  (por defecto: ~/Desktop/Babel)
#   HOMEBREW_PREFIX  — prefijo de Homebrew        (por defecto: /opt/homebrew)
#
# PREREQUISITO (solo una vez):
#   TAURI_SIGNING_PRIVATE_KEY=$(cat ~/.babel-update-key) TAURI_SIGNING_PRIVATE_KEY_PASSWORD="" \
#     npm run tauri build -- --target aarch64-apple-darwin
#
# Contenido del USB (total ~8 GB):
#   App + dylibs:       ~577 MB (Security Babel.app + Frameworks)
#   DMG instalación:    ~520 MB (para instalar permanentemente en un Mac)
#   tessdata:           ~150 MB (8 idiomas Tesseract)
#   Python + pkgs:      ~440 MB (Flask, CTranslate2, pymupdf, pdf2docx, pyhanko…)
#   MADLAD-400-3B int8: ~2.8 GB (traducción calidad legal, Apache 2.0 — máquinas ≥12 GB)
#   SMaLL-100 int8:     ~330 MB (traducción rápida, MIT — máquinas 8 GB; auto-tier)
#   PaddleOCR-VL-1.5:  ~1.1 GB (OCR avanzado, Apache 2.0; opcional)
#   Qwen3-4B-Q6_K:     ~3.1 GB (IA redacción jurídica; llama-server incluido)
#
# Tiempos esperados:
#   1ª vez (descarga Python + paquetes): ~15-25 min
#   Siguientes (binario ya en USB):      ~2-3 min  (solo actualiza MacOS/ + Frameworks)
#   --reset-cache:                       ~15-25 min (fuerza reinstalación Python)
set -euo pipefail

USB="${1:-}"
if [[ -z "$USB" ]]; then
  echo "Uso: $0 <ruta_destino> [--reset-cache]"
  echo "  Ejemplo: $0 /Volumes/BABEL_USB"
  exit 1
fi
case "$USB" in
  "~/"*) USB="$HOME/${USB#\~/}" ;;
  "~")   USB="$HOME" ;;
esac

BABEL="${BABEL_DIR:-$HOME/Desktop/Babel}"
INTERFAZ="$BABEL/babel-interfaz"
SERVIDOR_SRC="$INTERFAZ/servidor_babel"
BREW="${HOMEBREW_PREFIX:-/opt/homebrew}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR="$HOME/.cache/babel_usb"
ARCH=$(uname -m)

RESET_CACHE=0
for _arg in "${@:2}"; do
  [[ "$_arg" == "--reset-cache" || "$_arg" == "-r" ]] && RESET_CACHE=1
done

T_TOTAL=$SECONDS

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   BABEL USB — PREPARADOR v6 (auto-tier)  ║"
echo "╚══════════════════════════════════════════╝"
echo "  Destino : $USB"
echo "  Arch    : $ARCH"
echo "  Babel   : $BABEL"
[[ $RESET_CACHE -eq 1 ]] && echo "  Modo    : --reset-cache"
echo ""

# ── 0. Prerrequisitos ────────────────────────────────────────────────────
echo "┌─ [0/6] Comprobando prerrequisitos..."
_prereq_ok=1
check_ruta() {
  local ruta="$1" desc="$2" fix="${3:-}"
  if [[ ! -e "$ruta" ]]; then
    echo "  ✗ Falta: $desc"
    [[ -n "$fix" ]] && echo "    → $fix"
    _prereq_ok=0
  fi
}

check_ruta "$INTERFAZ/src-tauri" \
           "repositorio babel-interfaz" \
           "Ajusta BABEL_DIR=/ruta/a/Babel"

check_ruta "$BREW/opt/tesseract" \
           "tesseract" "brew install tesseract"
check_ruta "$BREW/opt/leptonica" \
           "leptonica" "brew install leptonica"
check_ruta "$BREW/Cellar/tesseract-lang" \
           "tesseract-lang" "brew install tesseract-lang"

# Auto-tier: el servidor elige MADLAD (≥12 GB) o SMaLL-100 (menos) según la RAM del destino.
# Busca modelos en: 1) servidor_babel/modelos_usb/, 2) src-tauri/modelos_usb/, 3) ya en USB.
# MADLAD es opcional: si no está, el servidor usa SMaLL-100.
_DEST_MOD="$USB/Security Babel.app/Contents/Resources/servidor/modelos_usb"

# Devuelve la ruta local donde existe el modelo, o vacío si no se encuentra.
_buscar_modelo_local() {
  local nombre="$1" archivo="$2"
  for _base in \
    "$SERVIDOR_SRC/modelos_usb" \
    "$INTERFAZ/src-tauri/modelos_usb" \
    "$BABEL/modelos_usb"; do
    [[ -f "$_base/$nombre/$archivo" ]] && echo "$_base/$nombre" && return 0
  done
  return 0
}

_check_modelo_madlad() {
  local src dst
  src=$(_buscar_modelo_local "madlad400-3b-int8" "model.bin")
  dst="$_DEST_MOD/madlad400-3b-int8"
  if [[ -n "$src" && -f "$src/spiece.model" ]]; then
    echo "  ✓ MADLAD-400-3B int8 ($(du -sh "$src" | cut -f1)) [local: $src]"
    MADLAD_SRC="$src"
  elif [[ -f "$dst/model.bin" && -f "$dst/spiece.model" ]]; then
    echo "  ✓ MADLAD-400-3B int8 ($(du -sh "$dst" | cut -f1)) [ya en USB — se omite copia]"
    MADLAD_YA_EN_USB=1
  else
    echo "  ℹ MADLAD-400-3B no encontrado — se usará solo SMaLL-100 (tier 8 GB)"
    echo "    (opcional: python3 -m ctranslate2.converters.transformers --model google/madlad400-3b-mt --output_dir $SERVIDOR_SRC/modelos_usb/madlad400-3b-int8 --quantization int8 --force)"
  fi
}
_check_modelo_small100() {
  local src dst
  src=$(_buscar_modelo_local "small100-int8" "model.bin")
  dst="$_DEST_MOD/small100-int8"
  if [[ -n "$src" && -f "$src/sentencepiece.bpe.model" ]]; then
    echo "  ✓ SMaLL-100 int8 ($(du -sh "$src" | cut -f1)) [local: $src]"
    SMALL100_SRC="$src"
  elif [[ -f "$dst/model.bin" && -f "$dst/sentencepiece.bpe.model" ]]; then
    echo "  ✓ SMaLL-100 int8 ($(du -sh "$dst" | cut -f1)) [ya en USB — se omite copia]"
    SMALL_YA_EN_USB=1
  else
    echo "  ✗ Falta SMaLL-100 int8 (necesario)"
    echo "    → python3 -m ctranslate2.converters.transformers --model alirezamsh/small100 --output_dir $SERVIDOR_SRC/modelos_usb/small100-int8 --quantization int8 --force"
    _prereq_ok=0
  fi
}
MADLAD_YA_EN_USB=0
SMALL_YA_EN_USB=0
MADLAD_SRC=""
SMALL100_SRC=""
_check_modelo_madlad
_check_modelo_small100

check_ruta "$BREW/bin/llama-server" \
           "llama-server" "brew install llama.cpp"
check_ruta "$HOME/Babel/modelos_ia/Qwen3-4B-Q6_K.gguf" \
           "modelo IA Qwen3-4B-Q6_K.gguf (~3.1 GB)" \
           "Descarga en https://huggingface.co/bartowski/Qwen3-4B-GGUF y ponlo en ~/Babel/modelos_ia/"

check_ruta "$SERVIDOR_SRC/server.py"              "server.py"
check_ruta "$SERVIDOR_SRC/traduccion_madlad.py"   "traduccion_madlad.py (motor MADLAD, tier ≥12 GB)"
check_ruta "$SERVIDOR_SRC/traduccion_small100.py" "traduccion_small100.py (motor SMaLL-100, tier 8 GB)"
check_ruta "$SERVIDOR_SRC/traduccion_comun.py"    "traduccion_comun.py (utilidades compartidas)"
check_ruta "$SERVIDOR_SRC/pymupdf4llm_extract.py" "pymupdf4llm_extract.py (primera pasada PDF)"
check_ruta "$SERVIDOR_SRC/md_to_pdf.py"           "md_to_pdf.py (PDF desde Markdown con reportlab)"
check_ruta "$SERVIDOR_SRC/firma.py"               "firma.py (firma digital PAdES-B-B)"

if [[ $_prereq_ok -eq 0 ]]; then
  echo ""
  echo "  Prerrequisitos ausentes. Corrígelos y vuelve a ejecutar."
  exit 1
fi
echo "└─ Prerrequisitos OK"

TESS_VER=$(ls "$BREW/Cellar/tesseract/" | sort -V | tail -1)
LANG_VER=$(ls "$BREW/Cellar/tesseract-lang/" | sort -V | tail -1)
TESS_DIR="$BREW/Cellar/tesseract/$TESS_VER"
LANG_DIR="$BREW/Cellar/tesseract-lang/$LANG_VER"

mkdir -p "$USB" "$CACHE_DIR"

# ── 1. App compilada ─────────────────────────────────────────────────────
echo ""
echo "┌─ [1/6] Buscando app compilada..."
# Busca primero el build con target explícito (aarch64-apple-darwin), luego el genérico
APP_SRC=""
if [[ -d "$INTERFAZ/src-tauri/target/aarch64-apple-darwin/release/bundle/macos" ]]; then
  APP_SRC=$(find "$INTERFAZ/src-tauri/target/aarch64-apple-darwin/release/bundle/macos" \
              -name "*.app" -maxdepth 1 2>/dev/null | head -1)
fi
if [[ -z "$APP_SRC" && -d "$INTERFAZ/src-tauri/target/release/bundle/macos" ]]; then
  APP_SRC=$(find "$INTERFAZ/src-tauri/target/release/bundle/macos" \
              -name "*.app" -maxdepth 1 2>/dev/null | head -1)
fi

if [[ -z "$APP_SRC" ]]; then
  echo ""
  echo "  ✗ No hay build de release. Compila con:"
  echo "    TAURI_SIGNING_PRIVATE_KEY=\$(cat ~/.babel-update-key) TAURI_SIGNING_PRIVATE_KEY_PASSWORD=\"\" \\"
  echo "      npm run tauri build -- --target aarch64-apple-darwin"
  exit 1
fi

APP_NAME=$(basename "$APP_SRC")
APP="$USB/$APP_NAME"
BINARY="$APP/Contents/MacOS/babel-interfaz"
FRAMEWORKS="$APP/Contents/Frameworks"
RESOURCES="$APP/Contents/Resources"
echo "  ✓ $APP_NAME"

T1=$SECONDS
if [[ -d "$APP" ]]; then
  # Smart update: solo reemplaza binario y Frameworks.
  # Preserva modelos_ia/, servidor/modelos_usb/, python/ y tessdata/ ya presentes.
  echo "  App ya existe — actualizando solo binario y Frameworks..."
  rsync -a --delete "$APP_SRC/Contents/MacOS/" "$APP/Contents/MacOS/"
  cp -f "$APP_SRC/Contents/Info.plist" "$APP/Contents/" 2>/dev/null || true
  cp -f "$APP_SRC/Contents/PkgInfo"    "$APP/Contents/" 2>/dev/null || true
  echo "  ✓ Binario actualizado ($(( SECONDS - T1 ))s)"
else
  echo "  Primera instalación — copiando app completa..."
  cp -R "$APP_SRC" "$USB/"
  echo "  ✓ App copiada ($(( SECONDS - T1 ))s)"
fi
mkdir -p "$FRAMEWORKS" "$RESOURCES"/{tessdata,python,servidor/modelos,servidor/modelos_usb,modelos_ia,binaries}
echo "└─ App lista ($(( SECONDS - T1 ))s)"

# ── 2. dylibs (Tesseract + Leptonica + deps) ────────────────────────────
echo ""
echo "┌─ [2/6] Bundleando dylibs..."
T2=$SECONDS

declare -a DYLIBS=(
  "$BREW/opt/tesseract/lib/libtesseract.5.dylib"
  "$BREW/opt/leptonica/lib/libleptonica.6.dylib"
  "$BREW/opt/libarchive/lib/libarchive.13.dylib"
  "$BREW/opt/libpng/lib/libpng16.16.dylib"
  "$BREW/opt/jpeg-turbo/lib/libjpeg.8.dylib"
  "$BREW/opt/giflib/lib/libgif.dylib"
  "$BREW/opt/libtiff/lib/libtiff.6.dylib"
  "$BREW/opt/webp/lib/libwebp.7.dylib"
  "$BREW/opt/webp/lib/libwebpmux.3.dylib"
  "$BREW/opt/webp/lib/libsharpyuv.0.dylib"
  "$BREW/opt/openjpeg/lib/libopenjp2.7.dylib"
  "$BREW/opt/xz/lib/liblzma.5.dylib"
  "$BREW/opt/zstd/lib/libzstd.1.dylib"
  "$BREW/opt/lz4/lib/liblz4.1.dylib"
  "$BREW/opt/libb2/lib/libb2.1.dylib"
  # llama.cpp — necesarias para llama-server bundleado
  "$BREW/opt/ggml/lib/libggml.0.dylib"
  "$BREW/opt/ggml/lib/libggml-base.0.dylib"
  "$BREW/opt/openssl@3/lib/libssl.3.dylib"
  "$BREW/opt/openssl@3/lib/libcrypto.3.dylib"
)

bundle_lib() {
  local src="$1"
  [[ ! -e "$src" ]] && return 0
  local real name
  real=$(readlink -f "$src")
  name=$(basename "$src")
  [[ -f "$FRAMEWORKS/$name" ]] && return 0
  cp "$real" "$FRAMEWORKS/$name"
  chmod 755 "$FRAMEWORKS/$name"
}

for src in "${DYLIBS[@]}"; do bundle_lib "$src"; done

codesign --remove-signature "$BINARY" 2>/dev/null || true
for lib in "$FRAMEWORKS/"*.dylib; do
  codesign --remove-signature "$lib" 2>/dev/null || true
done
for lib in "$FRAMEWORKS/"*.dylib; do
  name=$(basename "$lib")
  install_name_tool -id "@rpath/$name" "$lib" 2>/dev/null || true
  while IFS= read -r ref; do
    ref_name=$(basename "$ref")
    [[ -f "$FRAMEWORKS/$ref_name" ]] && \
      install_name_tool -change "$ref" "@rpath/$ref_name" "$lib" 2>/dev/null || true
  done < <(otool -L "$lib" 2>/dev/null | awk 'NR>1{print $1}' | grep "$BREW")
done
install_name_tool -add_rpath "@executable_path/../Frameworks" "$BINARY" 2>/dev/null || true
while IFS= read -r ref; do
  ref_name=$(basename "$ref")
  [[ -f "$FRAMEWORKS/$ref_name" ]] && \
    install_name_tool -change "$ref" "@rpath/$ref_name" "$BINARY" 2>/dev/null || true
done < <(otool -L "$BINARY" 2>/dev/null | awk 'NR>1{print $1}' | grep "$BREW")

# Auto-detectar dylibs que falten
MISSING_FOUND=0
for lib in "$FRAMEWORKS/"*.dylib "$BINARY"; do
  while IFS= read -r dep; do
    dep_name=$(basename "$dep")
    if [[ ! -f "$FRAMEWORKS/$dep_name" ]]; then
      found=$(find "$BREW/opt" -name "$dep_name" 2>/dev/null | head -1)
      if [[ -n "$found" ]]; then
        echo "  + auto-añadiendo: $dep_name"
        bundle_lib "$found"
        codesign --remove-signature "$FRAMEWORKS/$dep_name" 2>/dev/null || true
        install_name_tool -id "@rpath/$dep_name" "$FRAMEWORKS/$dep_name" 2>/dev/null || true
        MISSING_FOUND=$((MISSING_FOUND + 1))
      fi
    fi
  done < <(otool -L "$lib" 2>/dev/null | awk 'NR>1{print $1}' | grep "@rpath")
done
[[ $MISSING_FOUND -gt 0 ]] && echo "  + $MISSING_FOUND dylibs adicionales detectadas"
# llama-server + sus dylibs privadas (libllama-server-impl, libllama, libllama-common, libmtmd)
LLAMA_BIN_SRC=$(readlink -f "$BREW/bin/llama-server")
LLAMA_LIB_DIR=$(dirname "$LLAMA_BIN_SRC")/../lib
LLAMA_LIB_DIR=$(cd "$LLAMA_LIB_DIR" && pwd)
_llama_dest="$RESOURCES/binaries/llama-server"
_llama_src_size=$(stat -f%z "$LLAMA_BIN_SRC" 2>/dev/null || echo 0)
_llama_dst_size=$(stat -f%z "$_llama_dest" 2>/dev/null || echo 0)
if [[ "$_llama_src_size" != "$_llama_dst_size" ]]; then
  cp "$LLAMA_BIN_SRC" "$_llama_dest"
fi
chmod 755 "$RESOURCES/binaries/llama-server"
codesign --remove-signature "$RESOURCES/binaries/llama-server" 2>/dev/null || true
# Dylibs privadas de llama.cpp (no están en Homebrew opt, viven junto al binario)
for _lib in libllama-server-impl.dylib libllama-common.0.dylib libmtmd.0.dylib libllama.0.dylib; do
  _real=$(find "$LLAMA_LIB_DIR" -name "${_lib%.dylib}.*.dylib" 2>/dev/null | sort -V | tail -1)
  [[ -z "$_real" ]] && _real="$LLAMA_LIB_DIR/$_lib"
  if [[ -f "$_real" ]]; then
    _dest_name=$(basename "$_real")
    # Eliminar symlink o archivo anterior para evitar "Too many levels of symbolic links"
    rm -f "$FRAMEWORKS/$_dest_name"
    cp "$_real" "$FRAMEWORKS/$_dest_name"
    chmod 755 "$FRAMEWORKS/$_dest_name"
    codesign --remove-signature "$FRAMEWORKS/$_dest_name" 2>/dev/null || true
    install_name_tool -id "@rpath/$_dest_name" "$FRAMEWORKS/$_dest_name" 2>/dev/null || true
    # Symlink base→versionado solo cuando los nombres difieren (evita symlink circular)
    if [[ "$_lib" != "$_dest_name" ]]; then
      ln -sf "$_dest_name" "$FRAMEWORKS/$_lib" 2>/dev/null || true
    fi
  fi
done
# Reparchar RPATHs del binario llama-server para apuntar a Frameworks
install_name_tool -add_rpath "@executable_path/../../../Frameworks" \
  "$RESOURCES/binaries/llama-server" 2>/dev/null || true
install_name_tool -add_rpath "@loader_path/../../../Frameworks" \
  "$RESOURCES/binaries/llama-server" 2>/dev/null || true
for _ref in $(otool -L "$RESOURCES/binaries/llama-server" 2>/dev/null | awk 'NR>1{print $1}' | grep "$BREW"); do
  _ref_name=$(basename "$_ref")
  [[ -f "$FRAMEWORKS/$_ref_name" ]] && \
    install_name_tool -change "$_ref" "@rpath/$_ref_name" "$RESOURCES/binaries/llama-server" 2>/dev/null || true
done
echo "  ✓ llama-server bundleado ($(du -sh "$RESOURCES/binaries/llama-server" | cut -f1))"
echo "└─ $(ls "$FRAMEWORKS/"*.dylib 2>/dev/null | wc -l | tr -d ' ') dylibs ($(( SECONDS - T2 ))s)"

# ── 3. tessdata + modelos + tokenizadores (en paralelo) ─────────────────
echo ""
echo "┌─ [3/6] Copiando tessdata, modelos traducción y modelo IA..."
echo "  (esto puede tardar varios minutos — ~6 GB en total)"
T3=$SECONDS

# tessdata (omite copia si ya hay ≥8 idiomas)
(
  _tess_count=$(ls "$RESOURCES/tessdata/"*.traineddata 2>/dev/null | wc -l | tr -d ' ')
  if [[ $_tess_count -ge 8 ]]; then
    echo "  ✓ tessdata ya presente ($_tess_count idiomas) — omitida copia"
  else
    for f in eng.traineddata osd.traineddata; do
      [[ -f "$TESS_DIR/share/tessdata/$f" ]] && \
        cp "$TESS_DIR/share/tessdata/$f" "$RESOURCES/tessdata/"
    done
    for lang in spa fra deu ara rus chi_sim; do
      src="$LANG_DIR/share/tessdata/${lang}.traineddata"
      [[ -f "$src" ]] && cp "$src" "$RESOURCES/tessdata/"
    done
    echo "  ✓ tessdata"
  fi
) &
PID_TESS=$!

# Modelos de traducción (auto-tier): MADLAD-3B opcional + SMaLL-100 requerido.
# Usa las rutas resueltas en el paso 0 (MADLAD_SRC / SMALL100_SRC).
(
  # MADLAD (opcional)
  if [[ $MADLAD_YA_EN_USB -eq 1 ]]; then
    echo "  ✓ MADLAD-3B ya en USB — omitida copia"
  elif [[ -n "$MADLAD_SRC" ]]; then
    rm -rf "$RESOURCES/servidor/modelos_usb/madlad400-3b-int8"
    rsync -a --info=progress2 "$MADLAD_SRC/" \
      "$RESOURCES/servidor/modelos_usb/madlad400-3b-int8/" 2>/dev/null || \
    cp -R "$MADLAD_SRC" "$RESOURCES/servidor/modelos_usb/madlad400-3b-int8"
    echo "  ✓ MADLAD-3B ($(du -sh "$RESOURCES/servidor/modelos_usb/madlad400-3b-int8" | cut -f1))"
  fi
  # SMaLL-100 (requerido)
  if [[ $SMALL_YA_EN_USB -eq 1 ]]; then
    echo "  ✓ SMaLL-100 ya en USB — omitida copia"
  elif [[ -n "$SMALL100_SRC" ]]; then
    rm -rf "$RESOURCES/servidor/modelos_usb/small100-int8"
    rsync -a --info=progress2 "$SMALL100_SRC/" \
      "$RESOURCES/servidor/modelos_usb/small100-int8/" 2>/dev/null || \
    cp -R "$SMALL100_SRC" "$RESOURCES/servidor/modelos_usb/small100-int8"
    echo "  ✓ SMaLL-100 ($(du -sh "$RESOURCES/servidor/modelos_usb/small100-int8" | cut -f1))"
  fi
) &
PID_MOD=$!

# Código del servidor (pipeline PDF de doble pasada incluido)
for f in server.py traduccion_madlad.py traduccion_small100.py traduccion_comun.py \
          pymupdf4llm_extract.py md_to_pdf.py firma.py; do
  [[ -f "$SERVIDOR_SRC/$f" ]] && cp "$SERVIDOR_SRC/$f" "$RESOURCES/servidor/"
done
echo "  ✓ código servidor (7 archivos, pipeline PDF + firma PAdES-B-B)"

# Modelo IA: Qwen3-4B-Q6_K (~3.1 GB) — omitir si ya está en el USB
(
  mkdir -p "$RESOURCES/modelos_ia"
  _q6k_dest="$RESOURCES/modelos_ia/Qwen3-4B-Q6_K.gguf"
  _q6k_src="$HOME/Babel/modelos_ia/Qwen3-4B-Q6_K.gguf"
  if [[ -f "$_q6k_dest" ]]; then
    _dest_mb=$(du -m "$_q6k_dest" | cut -f1)
    if [[ $_dest_mb -ge 2900 ]]; then
      echo "  ✓ Qwen3-4B-Q6_K ya en USB (${_dest_mb}MB) — omitida copia"
    else
      rsync -a --info=progress2 "$_q6k_src" "$_q6k_dest" 2>/dev/null || cp "$_q6k_src" "$_q6k_dest"
      echo "  ✓ Qwen3-4B-Q6_K ($(du -sh "$_q6k_dest" | cut -f1))"
    fi
  else
    echo "  Copiando Qwen3-4B-Q6_K.gguf (~3.1 GB, puede tardar 2-4 min)..."
    rsync -a --info=progress2 "$_q6k_src" "$_q6k_dest" 2>/dev/null || cp "$_q6k_src" "$_q6k_dest"
    echo "  ✓ Qwen3-4B-Q6_K ($(du -sh "$_q6k_dest" | cut -f1))"
  fi
) &
PID_IA=$!

wait $PID_TESS
wait $PID_MOD
wait $PID_IA

# PaddleOCR-VL-1.5 (~1.1 GB tras cuantización) — copia si está descargado localmente,
# o descarga la primera vez. Licencia: Apache 2.0.
# LM cuantizado localmente a Q4_K_M (286 MB); mmproj BF16 (841 MB, CLIP — no cuantizable).
# Fuente LM original: noctrex/PaddleOCR-VL-1.5-GGUF (Q8_0 → Q4_K_M local)
# Fuente mmproj: PaddlePaddle/PaddleOCR-VL-1.5-GGUF
PADDLE_SRC="$SERVIDOR_SRC/modelos/paddleocr-vl"
PADDLE_DEST="$RESOURCES/servidor/modelos/paddleocr-vl"
mkdir -p "$PADDLE_DEST"

_paddle_lm_src=""
for f in "PaddleOCR-VL-1.5-Q4_K_M.gguf" "PaddleOCR-VL-1.5-Q8_0.gguf" "PaddleOCR-VL-1.5.gguf" "PaddleOCR-VL-1.5-BF16.gguf"; do
  [[ -f "$PADDLE_SRC/$f" ]] && _paddle_lm_src="$PADDLE_SRC/$f" && break
done
_paddle_mm_src=""
for f in "PaddleOCR-VL-1.5-mmproj.gguf" "mmproj-BF16.gguf" "mmproj-F16.gguf"; do
  [[ -f "$PADDLE_SRC/$f" ]] && _paddle_mm_src="$PADDLE_SRC/$f" && break
done

if [[ -n "$_paddle_lm_src" && -n "$_paddle_mm_src" ]]; then
  echo ""
  echo "  Copiando PaddleOCR-VL-1.5 (~1.1 GB)..."
  cp "$_paddle_lm_src" "$PADDLE_DEST/"
  cp "$_paddle_mm_src" "$PADDLE_DEST/"
  [[ -f "$PADDLE_SRC/chat_template.jinja" ]] && cp "$PADDLE_SRC/chat_template.jinja" "$PADDLE_DEST/"
  echo "  ✓ PaddleOCR-VL-1.5 ($(du -sh "$PADDLE_DEST" | cut -f1))"
else
  echo ""
  echo "  PaddleOCR-VL no presente localmente — descargando (~1.1 GB, solo 1ª vez)..."
  if python3 -c "
from huggingface_hub import hf_hub_download
DEST = r'$PADDLE_DEST'
# LM: Q4_K_M local preferido; si no hay, descargar BF16 oficial
import os
if not any(os.path.exists(os.path.join(DEST, f)) for f in ['PaddleOCR-VL-1.5-Q4_K_M.gguf','PaddleOCR-VL-1.5-Q8_0.gguf']):
    hf_hub_download(repo_id='PaddlePaddle/PaddleOCR-VL-1.5-GGUF', filename='PaddleOCR-VL-1.5.gguf', local_dir=DEST)
hf_hub_download(repo_id='PaddlePaddle/PaddleOCR-VL-1.5-GGUF', filename='PaddleOCR-VL-1.5-mmproj.gguf', local_dir=DEST)
hf_hub_download(repo_id='PaddlePaddle/PaddleOCR-VL-1.5-GGUF', filename='chat_template.jinja', local_dir=DEST)
" 2>/dev/null; then
    echo "  ✓ PaddleOCR-VL-1.5 ($(du -sh "$PADDLE_DEST" | cut -f1))"
  else
    echo "  ⚠ PaddleOCR-VL no descargado — PDF usará pymupdf4llm como primera pasada"
  fi
fi

echo "└─ Todos los recursos copiados ($(( SECONDS - T3 ))s)"

# ── 4. Python portable + paquetes ───────────────────────────────────────
echo ""
echo "┌─ [4/6] Python portable + paquetes..."
T4=$SECONDS

if [[ "$ARCH" == "arm64" ]]; then
  PY_PATTERN="aarch64-apple-darwin-install_only.tar.gz"
else
  PY_PATTERN="x86_64-apple-darwin-install_only.tar.gz"
fi

PY_CACHE_ARCHIVE="$CACHE_DIR/python_${ARCH}.tar.gz"
PY_CACHE_ENV="$CACHE_DIR/python_env_${ARCH}"

# Paquetes — cambiar esta lista invalida la caché automáticamente
PAQUETES=(
  "flask>=3.0"
  "flask-cors>=4.0"
  "ctranslate2>=4.5,<5"
  "transformers>=4.30,<5"
  "sentencepiece>=0.1.99"
  "numpy>=1.24"
  "protobuf>=3.20"
  "pymupdf>=1.23"
  "pymupdf4llm>=0.0.20"
  "llama-cpp-python>=0.3.0"
  "pdf2docx>=0.5.0"
  "reportlab>=4.0"
  "pyhanko>=0.28"
)
STAMP_CONTENT="${PAQUETES[*]}"
STAMP_FILE="$CACHE_DIR/python_env_${ARCH}.stamp"

CACHE_VALID=0
if [[ $RESET_CACHE -eq 0 && -x "$PY_CACHE_ENV/bin/python3" && -f "$STAMP_FILE" ]]; then
  if [[ "$(cat "$STAMP_FILE")" == "$STAMP_CONTENT" ]]; then
    CACHE_VALID=1
  else
    echo "  Paquetes actualizados — invalidando caché..."
    rm -rf "$PY_CACHE_ENV"
  fi
elif [[ $RESET_CACHE -eq 1 ]]; then
  echo "  --reset-cache: borrando caché Python..."
  rm -rf "$PY_CACHE_ENV" "$PY_CACHE_ARCHIVE"
fi

if [[ $CACHE_VALID -eq 1 ]]; then
  # Si Python ya está en el USB y el stamp coincide, no hace falta re-copiar
  _usb_py="$RESOURCES/python/bin/python3"
  _usb_stamp="$RESOURCES/python/.babel_stamp"
  if [[ -x "$_usb_py" && -f "$_usb_stamp" && "$(cat "$_usb_stamp" 2>/dev/null)" == "$STAMP_CONTENT" ]]; then
    echo "  ✓ Python ya en USB y actualizado — omitida copia"
  else
    echo "  ✓ Caché hit — copiando Python sin internet..."
    rm -rf "$RESOURCES/python"
    rsync -a "$PY_CACHE_ENV/" "$RESOURCES/python/"
    echo "$STAMP_CONTENT" > "$_usb_stamp"
  fi
else
  if [[ ! -f "$PY_CACHE_ARCHIVE" ]]; then
    echo "  Descargando Python portable (~80 MB)..."
    PY_URL=$(curl -s "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest" \
      | python3 -c "
import sys, json
data = json.load(sys.stdin)
hits = [a['browser_download_url'] for a in data.get('assets', [])
        if '3.12' in a['name'] and '$PY_PATTERN' in a['name']
        and 'freethreaded' not in a['name'] and 'stripped' not in a['name']]
if not hits:
    hits = [a['browser_download_url'] for a in data.get('assets', [])
            if '3.13' in a['name'] and '$PY_PATTERN' in a['name']
            and 'freethreaded' not in a['name'] and 'stripped' not in a['name']]
print(hits[0] if hits else '')
" 2>/dev/null)
    [[ -z "$PY_URL" ]] && echo "  ERROR: no se encontró Python portable" && exit 1
    curl -L "$PY_URL" -o "$PY_CACHE_ARCHIVE" --progress-bar
  fi

  echo "  Extrayendo Python..."
  mkdir -p "$PY_CACHE_ENV"
  tar -xzf "$PY_CACHE_ARCHIVE" -C "$PY_CACHE_ENV" --strip-components=1 2>/dev/null || \
  tar -xzf "$PY_CACHE_ARCHIVE" -C "$PY_CACHE_ENV" 2>/dev/null

  PYBIN="$PY_CACHE_ENV/bin/python3"
  echo "  Instalando paquetes (~5-10 min, incluye llama-cpp-python y pdf2docx)..."
  "$PYBIN" -m pip install --quiet --no-warn-script-location \
    "${PAQUETES[@]}" 2>&1 | tail -5

  # ── Limpieza: ~83 MB de archivos no necesarios en runtime ────────────
  echo "  Limpiando entorno Python (~83 MB de archivos innecesarios)..."
  # 1. __pycache__ y .pyc (~25 MB)
  find "$PY_CACHE_ENV" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
  find "$PY_CACHE_ENV" -name "*.pyc" -delete 2>/dev/null || true
  # 2. Modelos transformers no usados — conservar t5 (tokenizer MADLAD) y auto.
  #    SMaLL-100 usa su propio SMALL100Tokenizer (tokenization_small100.py, va con el
  #    modelo) que solo importa transformers.tokenization_utils (core, no en models/);
  #    m2m_100 se conserva por prudencia (misma arquitectura), no es estrictamente necesario.
  TRANS_MODELS="$PY_CACHE_ENV/lib/python3.*/site-packages/transformers/models"
  for model_dir in $TRANS_MODELS/*/; do
    model_name=$(basename "$model_dir")
    case "$model_name" in
      m2m_100|t5|auto) ;;  # conservar — T5Tokenizer de MADLAD (t5); m2m_100 por prudencia
      *) rm -rf "$model_dir" 2>/dev/null || true ;;
    esac
  done
  # 3. PyInstaller — herramienta de empaquetado, no runtime (~4 MB)
  find "$PY_CACHE_ENV" -type d -name "PyInstaller" -exec rm -rf {} + 2>/dev/null || true
  find "$PY_CACHE_ENV" -name "PyInstaller*" -maxdepth 4 -exec rm -rf {} + 2>/dev/null || true
  # 4. hf_xet — protocolo de subida a HuggingFace, inútil offline (~7 MB)
  find "$PY_CACHE_ENV" -type d -name "hf_xet*" -exec rm -rf {} + 2>/dev/null || true
  # 5. pip y setuptools — gestores de paquetes, innecesarios en runtime (~8 MB)
  #    Nota: se borran DESPUÉS de instalar todo lo necesario
  find "$PY_CACHE_ENV" -maxdepth 4 -type d -name "pip" -exec rm -rf {} + 2>/dev/null || true
  find "$PY_CACHE_ENV" -maxdepth 4 -type d -name "setuptools" -exec rm -rf {} + 2>/dev/null || true
  find "$PY_CACHE_ENV" -name "pip-*.dist-info" -type d -exec rm -rf {} + 2>/dev/null || true
  find "$PY_CACHE_ENV" -name "setuptools-*.dist-info" -type d -exec rm -rf {} + 2>/dev/null || true
  PY_SIZE_CLEAN=$(du -sh "$PY_CACHE_ENV" 2>/dev/null | cut -f1)
  echo "  ✓ Entorno limpio: $PY_SIZE_CLEAN"
  # ── Fin limpieza ──────────────────────────────────────────────────────

  echo "$STAMP_CONTENT" > "$STAMP_FILE"
  echo "  Copiando entorno al USB..."
  rsync -a "$PY_CACHE_ENV/" "$RESOURCES/python/"
  echo "$STAMP_CONTENT" > "$RESOURCES/python/.babel_stamp"
fi

PY_VER=$("$RESOURCES/python/bin/python3" --version 2>&1)
echo "└─ $PY_VER listo ($(( SECONDS - T4 ))s)"

# ── 5. Firma del bundle ──────────────────────────────────────────────────
echo ""
echo "  Limpiando AppleDouble y firmando bundle..."
find "$APP" -name '._*' -delete 2>/dev/null || true
codesign -f -s - --deep "$APP" 2>&1 | grep -v "^$" | head -3 || \
  echo "  Aviso: codesign con error (puede ser normal en exFAT)"
find "$APP" -name '._*' -delete 2>/dev/null || true
xattr -rd com.apple.quarantine "$APP" 2>/dev/null || true
echo "  Bundle firmado"

# ── 5. DMG ───────────────────────────────────────────────────────────────
echo ""
echo "┌─ [5/6] Copiando DMG de instalación..."
T5=$SECONDS

# Busca el DMG más reciente en el bundle de release
DMG_SRC=""
for _dir in \
  "$INTERFAZ/src-tauri/target/aarch64-apple-darwin/release/bundle/dmg" \
  "$INTERFAZ/src-tauri/target/release/bundle/dmg"; do
  _found=$(find "$_dir" -name "*.dmg" -maxdepth 1 2>/dev/null | sort -V | tail -1)
  [[ -n "$_found" ]] && DMG_SRC="$_found" && break
done

if [[ -n "$DMG_SRC" ]]; then
  DMG_NAME=$(basename "$DMG_SRC")
  DMG_DEST="$USB/$DMG_NAME"
  _dmg_src_size=$(stat -f%z "$DMG_SRC" 2>/dev/null || echo 0)
  _dmg_dst_size=$(stat -f%z "$DMG_DEST" 2>/dev/null || echo 0)
  if [[ "$_dmg_src_size" == "$_dmg_dst_size" && $_dmg_dst_size -gt 0 ]]; then
    echo "  ✓ DMG ya presente ($(du -sh "$DMG_DEST" | cut -f1)) — omitida copia"
  else
    echo "  Copiando $DMG_NAME ($(du -sh "$DMG_SRC" | cut -f1))..."
    cp "$DMG_SRC" "$DMG_DEST"
    echo "  ✓ $DMG_NAME copiado ($(( SECONDS - T5 ))s)"
  fi
else
  echo "  ⚠ No se encontró ningún DMG — compila con: npm run tauri build"
fi
echo "└─ DMG ($(( SECONDS - T5 ))s)"

# ── 6. Smoke test ────────────────────────────────────────────────────────
echo ""
echo "┌─ [6/6] Verificando integridad..."
T6=$SECONDS
_smoke_ok=1

# Modelo MADLAD-3B (tier ≥12 GB, opcional)
MADLAD_DIR="$RESOURCES/servidor/modelos_usb/madlad400-3b-int8"
if [[ -f "$MADLAD_DIR/model.bin" && -f "$MADLAD_DIR/spiece.model" ]]; then
  MADLAD_MB=$(du -m "$MADLAD_DIR/model.bin" | cut -f1)
  if [[ $MADLAD_MB -lt 2500 ]]; then
    echo "  ⚠ MADLAD model.bin parece incompleto (${MADLAD_MB}MB, esperado ≥2500MB)"
  else
    echo "  ✓ MADLAD-400-3B int8 ($(du -sh "$MADLAD_DIR" | cut -f1)) — tier ≥12 GB"
  fi
else
  echo "  ℹ MADLAD-400-3B no incluido — USB usará SMaLL-100 en todas las máquinas"
fi

# Modelo SMaLL-100 (tier 8 GB): model.bin + tokenizer SentencePiece + tokenizer propio
SMALL_DIR="$RESOURCES/servidor/modelos_usb/small100-int8"
if [[ ! -f "$SMALL_DIR/model.bin" ]]; then
  echo "  ✗ Falta small100-int8/model.bin"
  _smoke_ok=0
elif [[ ! -f "$SMALL_DIR/sentencepiece.bpe.model" ]]; then
  echo "  ✗ Falta el tokenizer small100-int8/sentencepiece.bpe.model"
  _smoke_ok=0
elif [[ ! -f "$SMALL_DIR/tokenization_small100.py" ]]; then
  echo "  ✗ Falta small100-int8/tokenization_small100.py (tokenizer propio de SMaLL-100)"
  _smoke_ok=0
else
  SMALL_MB=$(du -m "$SMALL_DIR/model.bin" | cut -f1)
  if [[ $SMALL_MB -lt 250 ]]; then
    echo "  ✗ model.bin parece incompleto (${SMALL_MB}MB, esperado ≥250MB)"
    _smoke_ok=0
  else
    echo "  ✓ SMaLL-100 int8 ($(du -sh "$SMALL_DIR" | cut -f1))"
  fi
fi

# tessdata
TDATA_COUNT=$(ls "$RESOURCES/tessdata/"*.traineddata 2>/dev/null | wc -l | tr -d ' ')
if [[ $TDATA_COUNT -lt 7 ]]; then
  echo "  ✗ Solo $TDATA_COUNT idiomas tessdata (esperados ≥7)"
  _smoke_ok=0
else
  echo "  ✓ tessdata ($TDATA_COUNT idiomas)"
fi

# Python: importar paquetes clave incluyendo pymupdf4llm (primera pasada PDF)
find "$RESOURCES/python" -name '._*' -delete 2>/dev/null || true
if "$RESOURCES/python/bin/python3" -c \
     "import flask, ctranslate2, transformers, sentencepiece, fitz, pymupdf4llm, llama_cpp, pdf2docx; print('OK')" \
     2>/dev/null | grep -q "OK"; then
  echo "  ✓ Paquetes Python OK (flask, ctranslate2, fitz, pymupdf4llm, llama_cpp, pdf2docx)"
else
  echo "  ✗ Error importando paquetes Python"
  echo "    → Prueba: $0 $USB --reset-cache"
  _smoke_ok=0
fi

# PaddleOCR-VL-1.5 (opcional — segunda pasada para PDFs escaneados)
_paddle_dest="$RESOURCES/servidor/modelos/paddleocr-vl"
_paddle_lm_ok=0
for _pf in "PaddleOCR-VL-1.5-Q4_K_M.gguf" "PaddleOCR-VL-1.5-Q8_0.gguf" "PaddleOCR-VL-1.5.gguf" "PaddleOCR-VL-1.5-BF16.gguf"; do
  [[ -f "$_paddle_dest/$_pf" ]] && _paddle_lm_ok=1 && break
done
_paddle_mm_ok=0
for _pf in "PaddleOCR-VL-1.5-mmproj.gguf" "mmproj-BF16.gguf" "mmproj-F16.gguf"; do
  [[ -f "$_paddle_dest/$_pf" ]] && _paddle_mm_ok=1 && break
done

if [[ $_paddle_lm_ok -eq 1 && $_paddle_mm_ok -eq 1 ]]; then
  PADDLE_MB=$(du -m "$_paddle_dest" 2>/dev/null | cut -f1)
  if [[ $PADDLE_MB -lt 1000 ]]; then
    echo "  ⚠ PaddleOCR-VL parece incompleto (${PADDLE_MB}MB, esperado ≥1000MB)"
  else
    echo "  ✓ PaddleOCR-VL-1.5 presente (${PADDLE_MB}MB) — OCR avanzado disponible"
  fi
else
  echo "  ℹ PaddleOCR-VL no descargado — PDF usará pymupdf4llm (normal si no se descargó)"
fi

# Modelo IA + llama-server
if [[ ! -f "$RESOURCES/modelos_ia/Qwen3-4B-Q6_K.gguf" ]]; then
  echo "  ✗ Falta modelos_ia/Qwen3-4B-Q6_K.gguf"
  _smoke_ok=0
else
  IA_MB=$(du -m "$RESOURCES/modelos_ia/Qwen3-4B-Q6_K.gguf" | cut -f1)
  if [[ $IA_MB -lt 2900 ]]; then
    echo "  ✗ Qwen3-4B-Q6_K.gguf parece incompleto (${IA_MB}MB, esperado ≥2900MB)"
    _smoke_ok=0
  else
    echo "  ✓ Qwen3-4B-Q6_K.gguf (${IA_MB}MB)"
  fi
fi

if [[ ! -x "$RESOURCES/binaries/llama-server" ]]; then
  echo "  ✗ Falta binaries/llama-server"
  _smoke_ok=0
else
  echo "  ✓ llama-server bundleado"
fi

# Archivos servidor (incluye firma.py para PAdES-B-B)
for f in server.py traduccion_madlad.py traduccion_small100.py traduccion_comun.py firma.py; do
  if [[ ! -f "$RESOURCES/servidor/$f" ]]; then
    echo "  ✗ Falta servidor/$f"
    _smoke_ok=0
  fi
done
echo "  ✓ Archivos servidor presentes (incluye firma.py)"

if [[ $_smoke_ok -eq 1 ]]; then
  echo "└─ Integridad OK ($(( SECONDS - T6 ))s)"
else
  echo "└─ ⚠ Problemas detectados — revisa los errores"
fi

# ── Resumen final ────────────────────────────────────────────────────────
T_FINAL=$(( SECONDS - T_TOTAL ))
USB_SIZE=$(du -sh "$USB" 2>/dev/null | cut -f1)
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║         USB BABEL — LISTO ✓              ║"
echo "╚══════════════════════════════════════════╝"
echo ""
printf "  %-22s %s\n" "Tiempo total:"    "${T_FINAL}s (~$((T_FINAL/60))m $((T_FINAL%60))s)"
printf "  %-22s %s\n" "Tamaño USB:"      "$USB_SIZE"
printf "  %-22s %s\n" "Traducción:"      "MADLAD-3B (≥12GB) / SMaLL-100 (8GB) — auto"
printf "  %-22s %s\n" "IA redacción:"    "Qwen3-4B-Q6_K + llama-server bundleado"
printf "  %-22s %s\n" "Firma digital:"   "PAdES-B-B vía pyHanko (firma.py)"
printf "  %-22s %s\n" "Caché Python:"    "$CACHE_DIR"
echo ""
echo "  Contenido USB:"
ls -1 "$USB"
echo ""
echo "  Usar en macOS:"
echo "    Ejecutar directamente → doble clic en ${APP_NAME}"
echo "      (1ª vez: clic derecho → Abrir para pasar Gatekeeper)"
echo "      El servidor arranca solo y elige modelo según la RAM."
echo "    Instalar en este Mac  → abrir el .dmg y arrastrar al Dock/Aplicaciones"
echo ""
echo "  NOTA: La próxima vez este script tardará ~3-5 min (Python cacheado)"
