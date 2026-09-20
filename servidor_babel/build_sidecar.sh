#!/usr/bin/env bash
# build_sidecar.sh — Compila server.py en un binario autónomo (sin Python del sistema)
# Resultado: src-tauri/binaries/servidor_babel-aarch64-apple-darwin  (Mac ARM)
#
# Requisitos previos (una sola vez):
#   pip install pyinstaller flask flask-cors ctranslate2 sentencepiece \
#               pymupdf llama-cpp-python pymupdf4llm pyhanko pyhanko-certvalidator
#
# Uso:
#   cd babel-interfaz/servidor_babel
#   bash build_sidecar.sh
#
# Después de construir, el binario se copia automáticamente a src-tauri/binaries/.
# Tauri lo detecta por el sufijo de plataforma (aarch64-apple-darwin en Mac ARM).
#
# NOTE (firma Apple):
#   Al distribuir con Developer ID, el binario necesita el entitlement
#   com.apple.security.cs.allow-dyld-environment-variables (para ctranslate2 + OpenMP).
#   Añadirlo en src-tauri/Entitlements.plist si aparece "killed: 9" en producción firmada.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
BINARIES_DIR="$REPO_ROOT/src-tauri/binaries"

# Plataforma — ajusta si construyes en x86_64
ARCH="$(uname -m)"
if [ "$ARCH" = "arm64" ]; then
  SUFFIX="aarch64-apple-darwin"
elif [ "$ARCH" = "x86_64" ]; then
  SUFFIX="x86_64-apple-darwin"
else
  echo "Plataforma no reconocida: $ARCH"
  exit 1
fi

cd "$SCRIPT_DIR"

# Localizar python con PyInstaller y las dependencias del servidor.
# Prioridad: babel_env local > pyenv > homebrew > sistema.
_PY=""
for _candidate in \
  "$HOME/Desktop/Babel copia/babel_env/bin/python3" \
  "$HOME/Desktop/Babel/babel_env/bin/python3" \
  "$HOME/.pyenv/shims/python3" \
  "/opt/homebrew/bin/python3" \
  "/usr/local/bin/python3" \
  "/usr/bin/python3"; do
  if [ -x "$_candidate" ] && "$_candidate" -m PyInstaller --version &>/dev/null; then
    _PY="$_candidate"
    break
  fi
done
if [ -z "$_PY" ]; then
  echo "ERROR: No se encontró python con PyInstaller. Ejecuta:"
  echo "  pip install pyinstaller flask flask-cors ctranslate2 sentencepiece pymupdf llama-cpp-python pymupdf4llm pyhanko pyhanko-certvalidator"
  exit 1
fi
echo "  Python: $_PY ($(\"$_PY\" --version 2>&1))"

echo "[1/3] Construyendo con PyInstaller..."
"$_PY" -m PyInstaller \
  --onefile \
  --name servidor_babel \
  --noconfirm \
  --clean \
  --add-data "traduccion_comun.py:." \
  --add-data "traduccion_small100.py:." \
  --add-data "traduccion_madlad.py:." \
  --add-data "firma.py:." \
  --hidden-import ctranslate2 \
  --hidden-import sentencepiece \
  --hidden-import flask \
  --hidden-import flask_cors \
  --hidden-import fitz \
  --hidden-import pymupdf4llm \
  --hidden-import pyhanko \
  --hidden-import pyhanko_certvalidator \
  --hidden-import pyhanko.sign \
  --hidden-import pyhanko.pdf_utils \
  --hidden-import transformers \
  --hidden-import transformers.tokenization_utils \
  --hidden-import transformers.utils \
  --hidden-import transformers.models.m2m_100 \
  --hidden-import transformers.models.m2m_100.tokenization_m2m_100 \
  server.py

echo "[2/3] Copiando binario a src-tauri/binaries/..."
mkdir -p "$BINARIES_DIR"
cp "dist/servidor_babel" "$BINARIES_DIR/servidor_babel-$SUFFIX"
cp "dist/servidor_babel" "$BINARIES_DIR/servidor_babel"
chmod +x "$BINARIES_DIR/servidor_babel-$SUFFIX" "$BINARIES_DIR/servidor_babel"

echo "[3/3] Limpiando artefactos de build..."
rm -rf build dist servidor_babel.spec

echo ""
echo "Binario listo: $BINARIES_DIR/servidor_babel-$SUFFIX"
echo "Tamaño: $(du -sh "$BINARIES_DIR/servidor_babel-$SUFFIX" | cut -f1)"
echo ""
echo "Siguiente paso: npm run tauri build"
