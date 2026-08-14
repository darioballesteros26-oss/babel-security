#!/usr/bin/env bash
# build_sidecar.sh — Compila server.py en un binario autónomo (sin Python del sistema)
# Resultado: src-tauri/binaries/servidor_babel-aarch64-apple-darwin  (Mac ARM)
#
# Requisitos previos (una sola vez):
#   pip install pyinstaller flask flask-cors ctranslate2 sentencepiece \
#               pymupdf llama-cpp-python pymupdf4llm
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

echo "[1/3] Construyendo con PyInstaller..."
python3 -m PyInstaller \
  --onefile \
  --name servidor_babel \
  --noconfirm \
  --clean \
  --add-data "traduccion_comun.py:." \
  --add-data "traduccion_small100.py:." \
  --add-data "traduccion_madlad.py:." \
  --hidden-import ctranslate2 \
  --hidden-import sentencepiece \
  --hidden-import flask \
  --hidden-import flask_cors \
  --hidden-import fitz \
  --hidden-import pymupdf4llm \
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
