#!/usr/bin/env bash
# preparar_usb.sh — USB autocontenido de Babel Security (MarianMT tc-big + Qwen)
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
#   cd ~/Desktop/Babel/babel-interfaz && npm run tauri -- build
#
# Contenido del USB (total ~5.6 GB incluyendo PaddleOCR-VL cuantizado):
#   App:               ~26 MB  (babel Security.app + dylibs)
#   tessdata:          ~150 MB (8 idiomas Tesseract)
#   Python + pkgs:     ~450 MB (Flask, CTranslate2, Qwen, pymupdf, pdf2docx, pymupdf4llm…)
#   MarianMT:          ~2.9 GB (13 pares tc-big int8)
#   Qwen 1.5B Q4:      ~1.0 GB (revisor/limpiador/PDF cleanup)
#   Tokenizadores:     ~46 MB
#   PaddleOCR-VL-1.5:  ~1.1 GB (LM Q4_K_M 286 MB + mmproj BF16 841 MB, Apache 2.0)
#
# Tiempos esperados:
#   1ª vez (descarga Python + paquetes + modelos): ~15-25 min
#   Siguientes (todo cacheado):                    ~3-5 min
set -euo pipefail

USB="${1:-}"
if [[ -z "$USB" ]]; then
  echo "Uso: $0 <ruta_destino> [--reset-cache]"
  echo "  Ejemplo: $0 /Volumes/BABEL_USB"
  exit 1
fi
USB="$(eval echo "$USB")"

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
echo "║    BABEL USB — PREPARADOR v4 (tc-big)    ║"
echo "╚══════════════════════════════════════════╝"
echo "  Destino : $USB"
echo "  Arch    : $ARCH"
echo "  Babel   : $BABEL"
[[ $RESET_CACHE -eq 1 ]] && echo "  Modo    : --reset-cache"
echo ""

# ── 0. Prerrequisitos ────────────────────────────────────────────────────
echo "┌─ [0/7] Comprobando prerrequisitos..."
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

check_ruta "$SERVIDOR_SRC/modelos_usb/modelos" \
           "modelos MarianMT tc-big (modelos_usb/modelos/)" \
           "Ejecuta: python3 $SERVIDOR_SRC/descargar_modelos_premium.py"

# Al menos un par de idiomas debe existir
if [[ -d "$SERVIDOR_SRC/modelos_usb/modelos" ]]; then
  _n_pares=$(ls "$SERVIDOR_SRC/modelos_usb/modelos" 2>/dev/null | wc -l | tr -d ' ')
  if [[ $_n_pares -lt 1 ]]; then
    echo "  ✗ modelos_usb/modelos/ está vacío — ejecuta descargar_modelos_premium.py"
    _prereq_ok=0
  else
    echo "  ✓ $_n_pares pares MarianMT encontrados"
  fi
fi

check_ruta "$SERVIDOR_SRC/modelos_usb/qwen.gguf" \
           "Qwen 1.5B Q4_K_M (modelos_usb/qwen.gguf)" \
           "Descarga de HuggingFace: Qwen/Qwen2.5-1.5B-Instruct-GGUF"

check_ruta "$SERVIDOR_SRC/modelos_usb/tokenizers" \
           "tokenizadores MarianMT (modelos_usb/tokenizers/)" \
           "Ejecuta: python3 $SERVIDOR_SRC/descargar_modelos_premium.py"

check_ruta "$SERVIDOR_SRC/server.py"              "server.py"
check_ruta "$SERVIDOR_SRC/revisor.py"             "revisor.py"
check_ruta "$SERVIDOR_SRC/traductor_usb.py"       "traductor_usb.py"
check_ruta "$SERVIDOR_SRC/traductor.py"           "traductor.py (fallback)"
check_ruta "$SERVIDOR_SRC/pymupdf4llm_extract.py" "pymupdf4llm_extract.py (primera pasada PDF)"
check_ruta "$SERVIDOR_SRC/paddleocr_extract.py"   "paddleocr_extract.py (segunda pasada PDF OCR)"

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
echo "┌─ [1/7] Buscando app compilada..."
APP_SRC=$(find "$INTERFAZ/src-tauri/target/release/bundle/macos" \
            -name "*.app" 2>/dev/null | head -1)

if [[ -z "$APP_SRC" ]]; then
  echo ""
  echo "  ✗ No hay build de release. Compila con:"
  echo "    cd $INTERFAZ && npm run tauri -- build"
  exit 1
fi

APP_NAME=$(basename "$APP_SRC")
echo "  ✓ $APP_NAME"

T1=$SECONDS
rm -rf "$USB/$APP_NAME"
cp -R "$APP_SRC" "$USB/"
APP="$USB/$APP_NAME"
BINARY="$APP/Contents/MacOS/babel-interfaz"
FRAMEWORKS="$APP/Contents/Frameworks"
RESOURCES="$APP/Contents/Resources"
mkdir -p "$FRAMEWORKS" "$RESOURCES"/{tessdata,python,servidor/modelos,servidor/modelos_usb}
echo "└─ App copiada ($(( SECONDS - T1 ))s)"

# ── 2. dylibs (Tesseract + Leptonica + deps) ────────────────────────────
echo ""
echo "┌─ [2/7] Bundleando dylibs..."
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
echo "└─ $(ls "$FRAMEWORKS/"*.dylib 2>/dev/null | wc -l | tr -d ' ') dylibs ($(( SECONDS - T2 ))s)"

# ── 3. tessdata + modelos + tokenizadores (en paralelo) ─────────────────
echo ""
echo "┌─ [3/7] Copiando tessdata, modelos MarianMT, tokenizadores y Qwen..."
echo "  (esto puede tardar varios minutos — ~4 GB)"
T3=$SECONDS

# tessdata
(
  for f in eng.traineddata osd.traineddata; do
    [[ -f "$TESS_DIR/share/tessdata/$f" ]] && \
      cp "$TESS_DIR/share/tessdata/$f" "$RESOURCES/tessdata/"
  done
  for lang in spa fra deu ara rus chi_sim; do
    src="$LANG_DIR/share/tessdata/${lang}.traineddata"
    [[ -f "$src" ]] && cp "$src" "$RESOURCES/tessdata/"
  done
  echo "  ✓ tessdata"
) &
PID_TESS=$!

# Modelos MarianMT tc-big (~2.9 GB)
(
  rm -rf "$RESOURCES/servidor/modelos_usb/modelos"
  rsync -a --info=progress2 \
    "$SERVIDOR_SRC/modelos_usb/modelos/" \
    "$RESOURCES/servidor/modelos_usb/modelos/" 2>/dev/null || \
  cp -R "$SERVIDOR_SRC/modelos_usb/modelos" \
        "$RESOURCES/servidor/modelos_usb/"
  echo "  ✓ modelos MarianMT ($(du -sh "$RESOURCES/servidor/modelos_usb/modelos" | cut -f1))"
) &
PID_MOD=$!

# Tokenizadores (~46 MB)
(
  rm -rf "$RESOURCES/servidor/modelos_usb/tokenizers"
  cp -R "$SERVIDOR_SRC/modelos_usb/tokenizers" \
        "$RESOURCES/servidor/modelos_usb/"
  echo "  ✓ tokenizadores"
) &
PID_TOK=$!

# Qwen 1.5B Q4_K_M (~1 GB) — también como modelos/qwen-1.5b-q4.gguf para revisor.py
(
  cp "$SERVIDOR_SRC/modelos_usb/qwen.gguf" \
     "$RESOURCES/servidor/modelos/qwen-1.5b-q4.gguf"
  echo "  ✓ Qwen 1.5B ($(du -sh "$RESOURCES/servidor/modelos/qwen-1.5b-q4.gguf" | cut -f1))"
) &
PID_QWEN=$!

# Código del servidor (7 archivos: pipeline PDF de doble pasada incluido)
for f in server.py revisor.py traductor_usb.py traductor.py \
          pymupdf4llm_extract.py paddleocr_extract.py; do
  [[ -f "$SERVIDOR_SRC/$f" ]] && cp "$SERVIDOR_SRC/$f" "$RESOURCES/servidor/"
done
echo "  ✓ código servidor (6 archivos, pipeline PDF doble pasada)"

wait $PID_TESS
wait $PID_TOK
wait $PID_QWEN
wait $PID_MOD

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
  if "$BABEL/babel_env/bin/python3" -c "
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
echo "┌─ [4/7] Python portable + paquetes..."
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
  "pypdfium2>=4.0"
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
  echo "  ✓ Caché hit — copiando Python sin internet..."
  rm -rf "$RESOURCES/python"
  rsync -a "$PY_CACHE_ENV/" "$RESOURCES/python/"
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
  # 2. Modelos transformers no usados — solo conservar marian y auto (~46 MB)
  TRANS_MODELS="$PY_CACHE_ENV/lib/python3.*/site-packages/transformers/models"
  for model_dir in $TRANS_MODELS/*/; do
    model_name=$(basename "$model_dir")
    case "$model_name" in
      marian|auto) ;;  # conservar
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

# ── 6. Launchers ─────────────────────────────────────────────────────────
echo ""
echo "┌─ [5/7] Creando launchers..."

# Copiar recursos Windows fuera del .app
mkdir -p "$USB/win/recursos"
rsync -a --delete "$RESOURCES/tessdata/"  "$USB/win/recursos/tessdata/"
rsync -a --delete "$RESOURCES/servidor/"  "$USB/win/recursos/servidor/"

# Windows: el symlink Unix modelos/qwen-1.5b-q4.gguf no funciona en NTFS/exFAT.
# Si rsync lo copió como symlink, reemplazarlo con el archivo real.
_qwen_win="$USB/win/recursos/servidor/modelos/qwen-1.5b-q4.gguf"
_qwen_real="$RESOURCES/servidor/modelos_usb/qwen.gguf"
if [[ -L "$_qwen_win" || ! -f "$_qwen_win" ]]; then
  [[ -L "$_qwen_win" ]] && rm "$_qwen_win"
  mkdir -p "$(dirname "$_qwen_win")"
  cp "$_qwen_real" "$_qwen_win"
fi
echo "  ✓ win/recursos/ sincronizado (Qwen symlink resuelto)"

cat > "$USB/LANZAR_BABEL.bat" << 'WIN_EOF'
@echo off
chcp 65001 > nul
setlocal EnableDelayedExpansion

:: Rutas base (%~dp0 termina siempre en \)
set "USB=%~dp0"
set "WIN_EXE=%USB%win\babel-interfaz.exe"
set "PYWIN=%USB%win\python_win\python.exe"
set "SERVIDOR=%USB%win\recursos\servidor\server.py"
set "USB_MOD=%USB%win\recursos\servidor\modelos_usb"
set "LOG=%USB%win\servidor_log.txt"

if not exist "%WIN_EXE%" (
  echo [ERROR] Falta win\babel-interfaz.exe
  echo         Compila en Windows con: cargo tauri build
  pause & exit /b 1
)
if not exist "%PYWIN%" (
  echo [ERROR] Falta win\python_win\python.exe
  echo         Descarga Python 3.12 embeddable de python.org y ponlo en win\python_win\
  pause & exit /b 1
)
if not exist "%SERVIDOR%" (
  echo [ERROR] Falta el servidor. Regenera el USB con preparar_usb.sh
  pause & exit /b 1
)

:: Token aleatorio de 32 hex
for /f "delims=" %%i in ('powershell -NoProfile -Command "[guid]::NewGuid().ToString(\"N\")"') do set "BABEL_NLLB_TOKEN=babel_%%i"

:: Entorno (comillas en todas las rutas para soportar espacios)
set "TESSDATA_PREFIX=%USB%win\recursos\tessdata"
set "TRANSFORMERS_OFFLINE=1"
set "HF_DATASETS_OFFLINE=1"
set "TOKENIZERS_PARALLELISM=false"
set "BABEL_DIR_USB=%USB_MOD%"
set "PATH=%USB%win\python_win;%PATH%"

:: Arrancar servidor en segundo plano; log en win\servidor_log.txt
echo Iniciando servidor Babel (MarianMT + Qwen)...
start /B "" cmd /c ""%PYWIN%" "%SERVIDOR%" >> "%LOG%" 2>&1"

:: Esperar hasta que el puerto 5002 responda (máx. 90 s, sondeo cada 2 s)
echo Esperando servidor...
set "_LISTO=0"
for /L %%i in (1,1,45) do (
  if "!_LISTO!" == "0" (
    powershell -NoProfile -Command "try{$c=New-Object Net.Sockets.TcpClient;$c.Connect('127.0.0.1',5002);$c.Close();exit 0}catch{exit 1}" >nul 2>&1
    if !ERRORLEVEL! == 0 set "_LISTO=1"
    if "!_LISTO!" == "0" timeout /t 2 /nobreak >nul
  )
)
if "!_LISTO!" == "0" (
  echo.
  echo [ERROR] El servidor no respondio en 90 segundos.
  echo         Revisa el log: %LOG%
  pause & exit /b 1
)

:: Lanzar app y esperar a que el usuario la cierre
echo Servidor listo. Abriendo Babel Security...
start /WAIT "" "%WIN_EXE%"

:: Apagar el servidor al cerrar la app
echo Cerrando servidor...
taskkill /F /IM python.exe >nul 2>&1

endlocal
WIN_EOF
echo "  ✓ LANZAR_BABEL.bat"

cat > "$USB/autorun.inf" << 'INF_EOF'
[autorun]
label=Babel Security
icon=babel Security.app\Contents\Resources\icon.ico
INF_EOF
echo "└─ Launchers creados"

# ── 7. Smoke test ────────────────────────────────────────────────────────
echo ""
echo "┌─ [6/7] Verificando integridad..."
T6=$SECONDS
_smoke_ok=1

# Modelos: al menos 5 pares MarianMT
_n=$(ls "$RESOURCES/servidor/modelos_usb/modelos" 2>/dev/null | wc -l | tr -d ' ')
if [[ $_n -lt 5 ]]; then
  echo "  ✗ Solo $_n pares MarianMT (esperados ≥5)"
  _smoke_ok=0
else
  echo "  ✓ $_n pares MarianMT ($(du -sh "$RESOURCES/servidor/modelos_usb/modelos" | cut -f1))"
fi

# Qwen
QWEN_USB="$RESOURCES/servidor/modelos/qwen-1.5b-q4.gguf"
if [[ ! -f "$QWEN_USB" ]]; then
  echo "  ✗ Falta qwen-1.5b-q4.gguf"
  _smoke_ok=0
else
  QWEN_MB=$(du -m "$QWEN_USB" | cut -f1)
  if [[ $QWEN_MB -lt 900 ]]; then
    echo "  ✗ qwen-1.5b-q4.gguf parece incompleto (${QWEN_MB}MB, esperado ≥900MB)"
    _smoke_ok=0
  else
    echo "  ✓ Qwen (${QWEN_MB}MB)"
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

# Archivos servidor
for f in server.py revisor.py traductor_usb.py; do
  if [[ ! -f "$RESOURCES/servidor/$f" ]]; then
    echo "  ✗ Falta servidor/$f"
    _smoke_ok=0
  fi
done
echo "  ✓ Archivos servidor presentes"

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
printf "  %-22s %s\n" "Pares idiomas:"   "$_n"
printf "  %-22s %s\n" "Caché Python:"    "$CACHE_DIR"
echo ""
echo "  Contenido USB:"
ls -1 "$USB"
echo ""
echo "  macOS   → doble clic en ${APP_NAME}"
echo "            (1ª vez: clic derecho → Abrir para pasar Gatekeeper)"
echo "            El servidor MarianMT + Qwen arranca automáticamente."
echo "  Windows → doble clic en LANZAR_BABEL.bat"
echo "            (requiere añadir win/babel-interfaz.exe y win/python_win/)"
echo ""
echo "  NOTA: La próxima vez este script tardará ~3-5 min (Python cacheado)"
