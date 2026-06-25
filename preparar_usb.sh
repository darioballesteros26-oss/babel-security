#!/usr/bin/env bash
# preparar_usb.sh — USB autocontenido de Babel (versión rápida, sin compilar)
#
# USO:
#   ./preparar_usb.sh /Volumes/BABEL_USB
#   ./preparar_usb.sh ~/Desktop/USB_BABEL              ← prueba sin USB físico
#   ./preparar_usb.sh /Volumes/BABEL_USB --reset-cache ← fuerza reinstalación Python
#
# VARIABLES DE ENTORNO (opcionales, para sobreescribir rutas por defecto):
#   BABEL_DIR        — directorio raíz de Babel  (por defecto: ~/Desktop/Babel)
#   HOMEBREW_PREFIX  — prefijo de Homebrew        (por defecto: /opt/homebrew)
#
# PREREQUISITO (solo una vez, fuera de este script):
#   cd ~/Desktop/Babel/babel-interfaz && npm run tauri -- build
#
# Tiempos esperados:
#   1ª vez (descarga Python + paquetes): ~7-10 min
#   Siguientes (todo cacheado):          ~30-60 seg
set -euo pipefail

USB="${1:-}"
if [[ -z "$USB" ]]; then
  echo "Uso: $0 <ruta_destino> [--reset-cache]"
  echo "  Ejemplo: $0 /Volumes/BABEL_USB"
  echo "  Ejemplo: $0 ~/Desktop/USB_BABEL"
  exit 1
fi
USB="$(eval echo "$USB")"

# ── Rutas configurables por env var ─────────────────────────────────────
BABEL="${BABEL_DIR:-$HOME/Desktop/Babel}"
INTERFAZ="$BABEL/babel-interfaz"
BREW="${HOMEBREW_PREFIX:-/opt/homebrew}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR="$HOME/.cache/babel_usb"
ARCH=$(uname -m)   # arm64 o x86_64

# ── Flags ────────────────────────────────────────────────────────────────
RESET_CACHE=0
for _arg in "${@:2}"; do
  [[ "$_arg" == "--reset-cache" || "$_arg" == "-r" ]] && RESET_CACHE=1
done

T_TOTAL=$SECONDS

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║       BABEL USB — PREPARADOR v3          ║"
echo "╚══════════════════════════════════════════╝"
echo "  Destino: $USB   |   Arch: $ARCH"
[[ $RESET_CACHE -eq 1 ]] && echo "  Modo: --reset-cache activo"
echo ""

# ── Prerrequisitos ───────────────────────────────────────────────────────
echo "┌─ [0/7] Comprobando prerrequisitos..."
_prereq_ok=1
check_ruta() {
  local ruta="$1" desc="$2" fix="${3:-}"
  if [[ ! -e "$ruta" ]]; then
    echo "  ✗ Falta: $desc"
    echo "    Ruta: $ruta"
    [[ -n "$fix" ]] && echo "    → $fix"
    _prereq_ok=0
  fi
}

check_ruta "$INTERFAZ/src-tauri" \
           "repositorio babel-interfaz" \
           "Ajusta con: BABEL_DIR=/ruta/a/Babel $0 $USB"
check_ruta "$BREW/opt/tesseract" \
           "tesseract (Homebrew)" \
           "brew install tesseract"
check_ruta "$BREW/opt/leptonica" \
           "leptonica (Homebrew)" \
           "brew install leptonica"
check_ruta "$BREW/Cellar/tesseract-lang" \
           "tesseract-lang (Homebrew)" \
           "brew install tesseract-lang"
check_ruta "$BABEL/nllb-600M-int8-ct2" \
           "modelo NLLB cuantizado (int8 CTranslate2)" \
           "Convierte el modelo con ct2-opus-mt-train o descarga de HuggingFace"
check_ruta "$HOME/.cache/huggingface/hub/models--facebook--nllb-200-distilled-600M" \
           "tokenizer NLLB (caché HuggingFace)" \
           "python3 -c \"from transformers import AutoTokenizer; AutoTokenizer.from_pretrained('facebook/nllb-200-distilled-600M')\""
check_ruta "$SCRIPT_DIR/nllb_server_usb.py" \
           "nllb_server_usb.py" \
           "Debe estar en el mismo directorio que este script"

if [[ $_prereq_ok -eq 0 ]]; then
  echo ""
  echo "  Prerrequisito(s) ausente(s). Corrige los errores y vuelve a ejecutar."
  exit 1
fi
echo "└─ Prerrequisitos OK"

# Ahora es seguro expandir versiones de tesseract (ls falla si el dir no existe)
TESS_VER=$(ls "$BREW/Cellar/tesseract/" | sort -V | tail -1)
LANG_VER=$(ls "$BREW/Cellar/tesseract-lang/" | sort -V | tail -1)
TESS_DIR="$BREW/Cellar/tesseract/$TESS_VER"
LANG_DIR="$BREW/Cellar/tesseract-lang/$LANG_VER"

mkdir -p "$USB"/win "$CACHE_DIR"

# ── 1. Buscar app ya compilada (no se compila aquí) ─────────────────────
echo ""
echo "┌─ [1/7] Buscando app compilada..."
APP_SRC=$(find "$INTERFAZ/src-tauri/target/release/bundle/macos" \
            -name "*.app" 2>/dev/null | head -1)

if [[ -z "$APP_SRC" ]]; then
  echo ""
  echo "  ✗ No hay build de release. Compila una vez con:"
  echo ""
  echo "    cd $INTERFAZ"
  echo "    npm run tauri -- build"
  echo ""
  echo "  (Tarda ~8 min pero solo hay que hacerlo una vez.)"
  echo "  Después vuelve a correr este script."
  exit 1
fi

APP_NAME=$(basename "$APP_SRC")
echo "  ✓ Encontrado: $APP_NAME"

T1=$SECONDS
rm -rf "$USB/$APP_NAME"
cp -R "$APP_SRC" "$USB/"
APP="$USB/$APP_NAME"
BINARY="$APP/Contents/MacOS/babel-interfaz"
FRAMEWORKS="$APP/Contents/Frameworks"
RESOURCES="$APP/Contents/Resources"
mkdir -p "$FRAMEWORKS" "$RESOURCES"/{tessdata,servidor/nllb_model,tokenizer}
echo "└─ App copiada ($(( SECONDS - T1 ))s)"

# ── 2. Empaquetar dylibs (Tesseract + Leptonica + dependencias) ─────────
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
  [[ -f "$FRAMEWORKS/$name" ]] && return 0   # ya copiada
  cp "$real" "$FRAMEWORKS/$name"
  chmod 755 "$FRAMEWORKS/$name"
}

for src in "${DYLIBS[@]}"; do bundle_lib "$src"; done

# Quitar firma antes de parchear (necesario en Apple Silicon)
codesign --remove-signature "$BINARY" 2>/dev/null || true
for lib in "$FRAMEWORKS/"*.dylib; do
  codesign --remove-signature "$lib" 2>/dev/null || true
done

# Parchear id y referencias internas de cada dylib
for lib in "$FRAMEWORKS/"*.dylib; do
  name=$(basename "$lib")
  install_name_tool -id "@rpath/$name" "$lib" 2>/dev/null || true
  while IFS= read -r ref; do
    ref_name=$(basename "$ref")
    [[ -f "$FRAMEWORKS/$ref_name" ]] && \
      install_name_tool -change "$ref" "@rpath/$ref_name" "$lib" 2>/dev/null || true
  done < <(otool -L "$lib" 2>/dev/null | awk 'NR>1{print $1}' | grep "$BREW")
done

# Parchear el binario principal
install_name_tool -add_rpath "@executable_path/../Frameworks" "$BINARY" 2>/dev/null || true
while IFS= read -r ref; do
  ref_name=$(basename "$ref")
  [[ -f "$FRAMEWORKS/$ref_name" ]] && \
    install_name_tool -change "$ref" "@rpath/$ref_name" "$BINARY" 2>/dev/null || true
done < <(otool -L "$BINARY" 2>/dev/null | awk 'NR>1{print $1}' | grep "$BREW")

# Scanner automático: detectar dependencias de Homebrew que aún falten en Frameworks
echo "  Verificando dependencias completas..."
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
      else
        echo "  AVISO: $dep_name no encontrado en Homebrew (puede ser del sistema)"
      fi
    fi
  done < <(otool -L "$lib" 2>/dev/null | awk 'NR>1{print $1}' | grep "@rpath")
done
[[ $MISSING_FOUND -gt 0 ]] && echo "  Se añadieron $MISSING_FOUND dylibs adicionales"

echo "└─ $(ls "$FRAMEWORKS/"*.dylib | wc -l | tr -d ' ') dylibs bundleadas ($(( SECONDS - T2 ))s)"

# ── 3. Tessdata + modelo + tokenizer  ──────────────────────────────────
# Se copian en PARALELO para reducir el tiempo total
echo ""
echo "┌─ [3/7] Copiando tessdata, modelo NLLB y tokenizer en paralelo..."
T3=$SECONDS

# Tessdata (en segundo plano)
(
  for f in eng.traineddata osd.traineddata; do
    [[ -f "$TESS_DIR/share/tessdata/$f" ]] && cp "$TESS_DIR/share/tessdata/$f" "$RESOURCES/tessdata/"
  done
  for lang in spa fra deu ara rus chi_sim; do
    src="$LANG_DIR/share/tessdata/${lang}.traineddata"
    [[ -f "$src" ]] && cp "$src" "$RESOURCES/tessdata/"
  done
) &
PID_TESS=$!

# Modelo NLLB (~600MB, en segundo plano)
(
  rm -rf "$RESOURCES/servidor/nllb_model"
  rsync -a "$BABEL/nllb-600M-int8-ct2/" "$RESOURCES/servidor/nllb_model/"
) &
PID_MODEL=$!

# Tokenizer (~22MB, en segundo plano)
(
  HF_BASE="$HOME/.cache/huggingface/hub/models--facebook--nllb-200-distilled-600M"
  SNAP=$(ls "$HF_BASE/snapshots/" | sort | tail -1)
  SNAP_DIR="$HF_BASE/snapshots/$SNAP"
  for fname in sentencepiece.bpe.model tokenizer.json tokenizer_config.json \
               special_tokens_map.json config.json generation_config.json; do
    [[ -f "$SNAP_DIR/$fname" ]] && cp "$(readlink -f "$SNAP_DIR/$fname")" "$RESOURCES/tokenizer/$fname"
  done
) &
PID_TOK=$!

# Servidor adaptado (instantáneo)
cp "$SCRIPT_DIR/nllb_server_usb.py" "$RESOURCES/servidor/"

# Esperar los tres en paralelo
wait $PID_TESS && echo "  ✓ tessdata ($(ls "$RESOURCES/tessdata/"*.traineddata 2>/dev/null | wc -l | tr -d ' ') idiomas)"
wait $PID_MODEL && echo "  ✓ modelo NLLB ($(du -sh "$RESOURCES/servidor/nllb_model" 2>/dev/null | cut -f1))"
wait $PID_TOK  && echo "  ✓ tokenizer"

echo "└─ Todo copiado en paralelo ($(( SECONDS - T3 ))s)"

# ── 4. Python portable + paquetes (con caché persistente) ──────────────
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

# Paquetes requeridos — cambiar esta lista invalida la caché automáticamente
PAQUETES=(
  "flask>=3.0"
  "flask-cors>=4.0"
  "ctranslate2>=4.5,<5"
  "transformers>=4.30,<5"
  "sentencepiece>=0.1.99"
  "numpy>=1.24"
  "protobuf>=3.20"
)
STAMP_CONTENT="${PAQUETES[*]}"
STAMP_FILE="$CACHE_DIR/python_env_${ARCH}.stamp"

# Comprobar si la caché es válida (ejecutable existe + stamp coincide)
CACHE_VALID=0
if [[ $RESET_CACHE -eq 0 && -x "$PY_CACHE_ENV/bin/python3" && -f "$STAMP_FILE" ]]; then
  if [[ "$(cat "$STAMP_FILE")" == "$STAMP_CONTENT" ]]; then
    CACHE_VALID=1
  else
    echo "  Paquetes actualizados — invalidando caché Python..."
    rm -rf "$PY_CACHE_ENV"
  fi
elif [[ $RESET_CACHE -eq 1 ]]; then
  echo "  --reset-cache: borrando caché Python..."
  rm -rf "$PY_CACHE_ENV" "$PY_CACHE_ARCHIVE"
fi

if [[ $CACHE_VALID -eq 1 ]]; then
  echo "  ✓ Caché hit — copiando Python+paquetes (sin internet)..."
  rm -rf "$RESOURCES/python"
  rsync -a "$PY_CACHE_ENV/" "$RESOURCES/python/"
  echo "  ✓ Python copiado desde caché"
else
  # Caché MISS: descargar, extraer e instalar paquetes una vez
  if [[ ! -f "$PY_CACHE_ARCHIVE" ]]; then
    echo "  Descargando Python portable (1ª vez, ~80MB)..."
    PY_URL=$(curl -s "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest" \
      | python3 -c "
import sys, json
data = json.load(sys.stdin)
hits = [a['browser_download_url'] for a in data.get('assets', [])
        if '3.12' in a['name']
        and '$PY_PATTERN' in a['name']
        and 'freethreaded' not in a['name']
        and 'stripped' not in a['name']]
if not hits:
    hits = [a['browser_download_url'] for a in data.get('assets', [])
            if '3.13' in a['name']
            and '$PY_PATTERN' in a['name']
            and 'freethreaded' not in a['name']
            and 'stripped' not in a['name']]
print(hits[0] if hits else '')
" 2>/dev/null)

    [[ -z "$PY_URL" ]] && echo "  ERROR: No se encontró Python portable." && exit 1
    echo "  URL: $(basename "$PY_URL")"
    curl -L "$PY_URL" -o "$PY_CACHE_ARCHIVE" --progress-bar
  else
    echo "  ✓ Archivo Python ya descargado en caché"
  fi

  echo "  Extrayendo Python..."
  mkdir -p "$PY_CACHE_ENV"
  tar -xzf "$PY_CACHE_ARCHIVE" -C "$PY_CACHE_ENV" --strip-components=1 2>/dev/null || \
  tar -xzf "$PY_CACHE_ARCHIVE" -C "$PY_CACHE_ENV" 2>/dev/null

  PYBIN="$PY_CACHE_ENV/bin/python3"

  echo "  Instalando paquetes (1ª vez — sin torch, ~2-4 min)..."
  "$PYBIN" -m pip install --quiet --no-warn-script-location \
    "${PAQUETES[@]}" 2>&1 | tail -3

  # Guardar stamp para invalidación futura
  echo "$STAMP_CONTENT" > "$STAMP_FILE"

  echo "  Copiando entorno Python al USB..."
  rsync -a "$PY_CACHE_ENV/" "$RESOURCES/python/"
  echo "  ✓ (próxima vez será instantáneo desde caché)"
fi

PY_VER=$("$RESOURCES/python/bin/python3" --version 2>&1)
T4_END=$(( SECONDS - T4 ))
echo "└─ $PY_VER listo (${T4_END}s)"

# Firmar el bundle completo DESPUÉS de añadir todos los recursos
# exFAT crea archivos AppleDouble (._*) al escribir xattrs — hay que limpiarlos antes
# Y después: codesign también genera ._* al escribir _CodeSignature/ en exFAT
echo "  Limpiando AppleDouble antes de firmar..."
find "$APP" -name '._*' -delete 2>/dev/null || true
echo "  Re-firmando bundle con recursos incluidos..."
codesign -f -s - --deep "$APP" 2>&1 || echo "  Aviso: codesign salió con error (puede ser normal en exFAT)"
find "$APP" -name '._*' -delete 2>/dev/null || true

# Quitar quarantine en la máquina de origen.
# Otros Macs re-aplican quarantine al copiar desde USB — clic derecho → Abrir la 1ª vez.
xattr -rd com.apple.quarantine "$APP" 2>/dev/null || true

# ── 5. Launchers y autorun ──────────────────────────────────────────────
echo ""
echo "┌─ [5/7] Creando launchers..."
# macOS: la propia app arranca el servidor desde Contents/Resources/ (ver main.rs)
# Solo se crean los launchers de Windows.

# ── Windows launcher ────────────────────────────────────────────────────
cat > "$USB/LANZAR_BABEL.bat" << 'WIN_EOF'
@echo off
chcp 65001 > nul
setlocal

set "USB=%~dp0"
set "WIN_EXE=%USB%win\babel-interfaz.exe"
set "PYWIN=%USB%python_win\python.exe"

if not exist "%WIN_EXE%" (
  echo [ERROR] Falta: win\babel-interfaz.exe
  echo Compila en Windows con: cargo tauri build
  echo y copia el .exe a la carpeta win\ del USB.
  pause & exit /b 1
)
if not exist "%PYWIN%" (
  echo [ERROR] Falta: python_win\python.exe
  echo Descarga Python embeddable de python.org y extraelo en python_win\
  pause & exit /b 1
)

set TESSDATA_PREFIX=%USB%tessdata
set TRANSFORMERS_OFFLINE=1
set HF_DATASETS_OFFLINE=1
set TOKENIZERS_PARALLELISM=false
set BABEL_NLLB_TOKEN=babel_usb_win_token

start /B "" "%PYWIN%" "%USB%servidor\nllb_server_usb.py"
timeout /t 20 /nobreak > NUL
start "" "%WIN_EXE%"
WIN_EOF
echo "  ✓ LANZAR_BABEL.bat"

cat > "$USB/autorun.inf" << 'INF_EOF'
[autorun]
label=Babel Security
icon=babel Security.app\Contents\Resources\icon.ico
INF_EOF
echo "  ✓ autorun.inf"

echo "└─ Launchers creados"

# ── 6. Smoke test — verificar integridad antes de declarar éxito ────────
echo ""
echo "┌─ [6/7] Verificando integridad..."
T6=$SECONDS
_smoke_ok=1

# Modelo: archivos clave presentes y tamaño mínimo razonable
for _f in model.bin config.json; do
  if [[ ! -f "$RESOURCES/servidor/nllb_model/$_f" ]]; then
    echo "  ✗ Modelo incompleto — falta: $_f"
    _smoke_ok=0
  fi
done

if [[ $_smoke_ok -eq 1 ]]; then
  MODEL_BIN="$RESOURCES/servidor/nllb_model/model.bin"
  # stat -f%z funciona en macOS; fallback a du para compatibilidad
  BIN_BYTES=$(stat -f%z "$MODEL_BIN" 2>/dev/null || \
              du -k "$MODEL_BIN" 2>/dev/null | awk '{print $1 * 1024}' || echo 0)
  BIN_MB=$(( BIN_BYTES / 1024 / 1024 ))
  if [[ $BIN_BYTES -lt $((500 * 1024 * 1024)) ]]; then
    echo "  ✗ model.bin parece incompleto (${BIN_MB}MB, esperado ≥500MB)"
    _smoke_ok=0
  else
    echo "  ✓ Modelo NLLB ($(du -sh "$RESOURCES/servidor/nllb_model" | cut -f1))"
  fi
fi

# Tessdata: mínimo 7 idiomas
TDATA_COUNT=$(ls "$RESOURCES/tessdata/"*.traineddata 2>/dev/null | wc -l | tr -d ' ')
if [[ $TDATA_COUNT -lt 7 ]]; then
  echo "  ✗ Solo $TDATA_COUNT archivos tessdata (esperados ≥7)"
  _smoke_ok=0
else
  echo "  ✓ Tessdata ($TDATA_COUNT idiomas)"
fi

# Python: importar los paquetes clave sin cargar el modelo
# Limpiar ._* del directorio python antes de importar (transformers escanea todos los .py)
find "$RESOURCES/python" -name '._*' -delete 2>/dev/null || true
echo "  Comprobando importaciones Python..."
if "$RESOURCES/python/bin/python3" -c \
     "import flask, ctranslate2, transformers, sentencepiece; print('OK')" \
     2>/dev/null | grep -q "OK"; then
  echo "  ✓ Paquetes Python importan correctamente"
else
  echo "  ✗ Error importando paquetes Python"
  echo "    → Vuelve a ejecutar con: $0 $USB --reset-cache"
  _smoke_ok=0
fi

if [[ $_smoke_ok -eq 1 ]]; then
  echo "└─ Integridad OK ✓ ($(( SECONDS - T6 ))s)"
else
  echo "└─ ⚠ Se encontraron problemas — revisa los errores arriba"
fi

# ── 7. Resumen ──────────────────────────────────────────────────────────
T_FINAL=$(( SECONDS - T_TOTAL ))
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║           USB BABEL — LISTO ✓            ║"
echo "╚══════════════════════════════════════════╝"
echo ""
printf "  %-20s %s\n" "Tiempo total:"   "${T_FINAL}s (~$((T_FINAL/60))m $((T_FINAL%60))s)"
printf "  %-20s %s\n" "Tamaño USB:"     "$(du -sh "$USB" 2>/dev/null | cut -f1)"
printf "  %-20s %s\n" "Caché Python:"   "$CACHE_DIR"
echo ""
echo "  Estructura visible en el USB:"
ls -1 "$USB"
echo ""
echo "  macOS   → doble clic en ${APP_NAME}"
echo "            (1ª vez: clic derecho → Abrir para pasar Gatekeeper)"
echo "            El servidor de traducción arranca automáticamente."
echo "  Windows → doble clic en LANZAR_BABEL.bat"
echo "            (requiere añadir win/babel-interfaz.exe)"
echo ""
echo "  NOTA: La próxima vez que ejecutes este script"
echo "  tardará ~30-60 seg (Python cacheado en $CACHE_DIR)"
