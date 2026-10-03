#!/usr/bin/env bash
# crear_dmg_bundle.sh — DMG completo con llama-server + dylibs portables (sin Homebrew)
# Parchea TODAS las rutas hardcodeadas /opt/homebrew/... en los binarios de llama.cpp
set -euo pipefail

INTERFAZ="$(cd "$(dirname "$0")" && pwd)"
BUILD_APP="$INTERFAZ/src-tauri/target/release/bundle/macos/Security Babel.app"
# Versión leída de tauri.conf.json (antes estaba hardcodeada y derivaba del real).
VERSION="$(grep -m1 '"version"' "$INTERFAZ/src-tauri/tauri.conf.json" | sed 's/.*: *"//;s/".*//')"
DMG_OUT="$HOME/Desktop/Security Babel_Full_${VERSION}.dmg"
TMPDIR_BUILD=$(mktemp -d)
APP_DEST="$TMPDIR_BUILD/Security Babel.app"

rm -f "$DMG_OUT"

echo "[0/9] Construyendo la app (frontend + Rust + bundle)..."
# Flujo en UN solo comando: este script compila la app y luego la empaqueta.
# bundle.createUpdaterArtifacts:true (necesario para el canal de actualización) hace
# que `tauri build` intente firmar el .app.tar.gz. Le pasamos la clave del updater si
# existe → el build termina en 0. Sin clave, la firma del .app.tar.gz falla PERO el
# .app se genera igual, así que toleramos ese fallo concreto y validamos el .app abajo.
UPDATE_KEY="$HOME/.babel-update-key"
if [ -f "$UPDATE_KEY" ]; then
  TAURI_SIGNING_PRIVATE_KEY="$(cat "$UPDATE_KEY")" TAURI_SIGNING_PRIVATE_KEY_PASSWORD="" \
    npm --prefix "$INTERFAZ" run tauri build
else
  echo "   (sin ~/.babel-update-key: se ignora el fallo de firma del .app.tar.gz; el .app igual se genera)"
  npm --prefix "$INTERFAZ" run tauri build || true
fi
if [ ! -d "$BUILD_APP" ]; then
  echo "ERROR: no se generó la app en $BUILD_APP (¿falló la compilación?)"; exit 1
fi

echo "[1/9] App base..."
cp -R "$BUILD_APP" "$APP_DEST"
mkdir -p "$APP_DEST/Contents/Frameworks"
mkdir -p "$APP_DEST/Contents/Resources/binaries"

echo "[2/9] Modelo IA Qwen3..."
mkdir -p "$APP_DEST/Contents/Resources/modelos_ia"
# Preferir Q4_K_M (ligero, rápido en CPU); caer a Q6_K si no está.
if [ -f ~/Babel/modelos_ia/Qwen3-4B-Q4_K_M.gguf ]; then
  cp ~/Babel/modelos_ia/Qwen3-4B-Q4_K_M.gguf "$APP_DEST/Contents/Resources/modelos_ia/"
  echo "   modelo: Qwen3-4B-Q4_K_M (ligero)"
else
  cp ~/Babel/modelos_ia/Qwen3-4B-Q6_K.gguf "$APP_DEST/Contents/Resources/modelos_ia/"
  echo "   modelo: Qwen3-4B-Q6_K (fallback)"
fi

echo "[3/9] SMaLL-100..."
mkdir -p "$APP_DEST/Contents/Resources/servidor/modelos_usb"
cp -R "$INTERFAZ/src-tauri/modelos_usb/small100-int8" "$APP_DEST/Contents/Resources/servidor/modelos_usb/"

echo "[4/9] Servidor Python..."
for f in server.py traduccion_comun.py traduccion_small100.py traduccion_madlad.py firma.py; do
  cp "$INTERFAZ/servidor_babel/$f" "$APP_DEST/Contents/Resources/servidor/"
done

echo "[5/9] Python portable..."
cp -R ~/.cache/babel_usb/python_env_arm64 "$APP_DEST/Contents/Resources/python"

echo "[6/9] tessdata..."
mkdir -p "$APP_DEST/Contents/Resources/tessdata"
for lang in spa eng fra deu ara chi_sim por ita; do
  src="/opt/homebrew/share/tessdata/${lang}.traineddata"
  [ -f "$src" ] && cp "$src" "$APP_DEST/Contents/Resources/tessdata/" || true
done

echo "[7/9] llama-server + dylibs..."
LLAMA_DEST="$APP_DEST/Contents/Resources/binaries/llama-server"
FW="$APP_DEST/Contents/Frameworks"

# Copiar todos los binarios llama.cpp
cp /opt/homebrew/bin/llama-server                         "$LLAMA_DEST"
cp /opt/homebrew/lib/libllama.0.dylib                    "$FW/"
cp /opt/homebrew/lib/libllama-common.0.dylib             "$FW/"
cp /opt/homebrew/lib/libllama-server-impl.dylib          "$FW/"
cp /opt/homebrew/lib/libmtmd.0.dylib                     "$FW/"
cp /opt/homebrew/opt/ggml/lib/libggml.0.dylib            "$FW/"
cp /opt/homebrew/opt/ggml/lib/libggml-base.0.dylib       "$FW/"
cp /opt/homebrew/opt/openssl@3/lib/libssl.3.dylib        "$FW/"
cp /opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib     "$FW/"
cp /opt/homebrew/opt/libomp/lib/libomp.dylib             "$FW/"  # necesario por libggml-base

echo "   Parcheando rutas en llama-server..."
# Quitar rpath Homebrew y añadir el del bundle
install_name_tool -delete_rpath "@loader_path/../lib"         "$LLAMA_DEST" 2>/dev/null || true
install_name_tool -add_rpath    "@executable_path/../../Frameworks" "$LLAMA_DEST"
install_name_tool -add_rpath    "@loader_path/../../Frameworks"     "$LLAMA_DEST"
install_name_tool -change "/opt/homebrew/opt/ggml/lib/libggml.0.dylib"       "@rpath/libggml.0.dylib"       "$LLAMA_DEST"
install_name_tool -change "/opt/homebrew/opt/ggml/lib/libggml-base.0.dylib"  "@rpath/libggml-base.0.dylib"  "$LLAMA_DEST"
install_name_tool -change "/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib"   "@rpath/libssl.3.dylib"        "$LLAMA_DEST"
install_name_tool -change "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib" "@rpath/libcrypto.3.dylib"    "$LLAMA_DEST"

echo "   Parcheando libllama.0.dylib..."
install_name_tool -change "/opt/homebrew/opt/ggml/lib/libggml.0.dylib"       "@rpath/libggml.0.dylib"       "$FW/libllama.0.dylib"
install_name_tool -change "/opt/homebrew/opt/ggml/lib/libggml-base.0.dylib"  "@rpath/libggml-base.0.dylib"  "$FW/libllama.0.dylib"
install_name_tool -add_rpath "@loader_path"                                                                  "$FW/libllama.0.dylib" 2>/dev/null || true

echo "   Parcheando libllama-common.0.dylib..."
install_name_tool -change "/opt/homebrew/opt/ggml/lib/libggml.0.dylib"         "@rpath/libggml.0.dylib"       "$FW/libllama-common.0.dylib"
install_name_tool -change "/opt/homebrew/opt/ggml/lib/libggml-base.0.dylib"    "@rpath/libggml-base.0.dylib"  "$FW/libllama-common.0.dylib"
install_name_tool -change "/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib"     "@rpath/libssl.3.dylib"        "$FW/libllama-common.0.dylib"
install_name_tool -change "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib"  "@rpath/libcrypto.3.dylib"     "$FW/libllama-common.0.dylib"
install_name_tool -add_rpath "@loader_path"                                                                   "$FW/libllama-common.0.dylib" 2>/dev/null || true

echo "   Parcheando libllama-server-impl.dylib..."
install_name_tool -change "/opt/homebrew/opt/ggml/lib/libggml.0.dylib"         "@rpath/libggml.0.dylib"       "$FW/libllama-server-impl.dylib"
install_name_tool -change "/opt/homebrew/opt/ggml/lib/libggml-base.0.dylib"    "@rpath/libggml-base.0.dylib"  "$FW/libllama-server-impl.dylib"
install_name_tool -change "/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib"     "@rpath/libssl.3.dylib"        "$FW/libllama-server-impl.dylib"
install_name_tool -change "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib"  "@rpath/libcrypto.3.dylib"     "$FW/libllama-server-impl.dylib"
install_name_tool -add_rpath "@loader_path"                                                                   "$FW/libllama-server-impl.dylib" 2>/dev/null || true

echo "   Parcheando libmtmd.0.dylib..."
install_name_tool -change "/opt/homebrew/opt/ggml/lib/libggml.0.dylib"       "@rpath/libggml.0.dylib"       "$FW/libmtmd.0.dylib"
install_name_tool -change "/opt/homebrew/opt/ggml/lib/libggml-base.0.dylib"  "@rpath/libggml-base.0.dylib"  "$FW/libmtmd.0.dylib"
install_name_tool -add_rpath "@loader_path"                                                                  "$FW/libmtmd.0.dylib" 2>/dev/null || true

echo "   Parcheando libggml.0.dylib (libomp)..."
install_name_tool -change "/opt/homebrew/opt/libomp/lib/libomp.dylib"  "@rpath/libomp.dylib"  "$FW/libggml.0.dylib"
install_name_tool -add_rpath "@loader_path"                                                    "$FW/libggml.0.dylib" 2>/dev/null || true

echo "   Parcheando libggml-base.0.dylib (libomp)..."
install_name_tool -change "/opt/homebrew/opt/libomp/lib/libomp.dylib"  "@rpath/libomp.dylib"  "$FW/libggml-base.0.dylib"
install_name_tool -add_rpath "@loader_path"                                                    "$FW/libggml-base.0.dylib" 2>/dev/null || true

echo "   Parcheando libssl.3.dylib (ruta Cellar → @rpath)..."
# libssl referencia libcrypto con la ruta del Cellar (/opt/homebrew/Cellar/openssl@3/3.6.3/...)
CELLAR_CRYPTO=$(otool -L "$FW/libssl.3.dylib" | grep "libcrypto" | awk '{print $1}')
if [ -n "$CELLAR_CRYPTO" ]; then
  install_name_tool -change "$CELLAR_CRYPTO" "@rpath/libcrypto.3.dylib" "$FW/libssl.3.dylib"
fi
install_name_tool -add_rpath "@loader_path"  "$FW/libssl.3.dylib" 2>/dev/null || true

echo "   Empaquetando backends ggml (Metal GPU + CPU por chip + BLAS)..."
# ggml carga los backends como plugins .so en runtime. Sin ellos NO hay ni GPU ni CPU
# y el modelo no carga (fallo real en Macs sin Homebrew, p. ej. MacBook Neo). Los
# ponemos JUNTO a llama-server (uno de los directorios donde ggml busca) y además
# fijamos GGML_BACKEND_PATH a esta carpeta al arrancar (ver ia_redaccion.rs).
BACKENDS_DIR="$APP_DEST/Contents/Resources/binaries"
GGML_LIBEXEC=$(ls -d /opt/homebrew/Cellar/ggml/*/libexec 2>/dev/null | sort -V | tail -1)
if [ -z "$GGML_LIBEXEC" ] || [ ! -d "$GGML_LIBEXEC" ]; then
  echo "ERROR: no encuentro los backends ggml (.so) en Homebrew ($GGML_LIBEXEC)"; exit 1
fi
for so in "$GGML_LIBEXEC"/libggml-*.so; do
  [ -f "$so" ] || continue
  base=$(basename "$so")
  cp "$so" "$BACKENDS_DIR/$base"
  # Resolver @rpath/libggml-base.0.dylib y @rpath/libomp.dylib desde Frameworks
  install_name_tool -add_rpath "@loader_path/../../Frameworks"     "$BACKENDS_DIR/$base" 2>/dev/null || true
  install_name_tool -add_rpath "@executable_path/../../Frameworks" "$BACKENDS_DIR/$base" 2>/dev/null || true
  # Los backends CPU referencian libomp con ruta absoluta de Homebrew
  install_name_tool -change "/opt/homebrew/opt/libomp/lib/libomp.dylib" "@rpath/libomp.dylib" "$BACKENDS_DIR/$base" 2>/dev/null || true
  echo "     + $base"
done

echo "   Verificando rpaths finales del llama-server:"
otool -l "$LLAMA_DEST" | grep -A2 "LC_RPATH" | grep "path"

echo "[8/9] Limpiar, firmar y empaquetar..."
find "$APP_DEST" -name '._*' -delete 2>/dev/null || true
xattr -rc "$APP_DEST" 2>/dev/null || true

# Firmar de dentro hacia fuera: dylibs + backends .so primero, luego binarios, luego bundle
for dylib in "$FW"/*.dylib; do
  codesign --force -s - "$dylib" 2>/dev/null || true
done
for backend in "$BACKENDS_DIR"/libggml-*.so; do
  [ -f "$backend" ] && codesign --force -s - "$backend" 2>/dev/null || true
done
codesign --force -s - "$LLAMA_DEST"
codesign --force -s - "$APP_DEST/Contents/MacOS/babel-interfaz"
codesign --force -s - "$APP_DEST"

echo "[9/9] Creando DMG..."
ln -s /Applications "$TMPDIR_BUILD/Applications"
hdiutil create -volname "Security Babel" -srcfolder "$TMPDIR_BUILD" -ov -format UDZO -o "$DMG_OUT"
rm -rf "$TMPDIR_BUILD"

echo ""
echo "✓ DMG listo:"
ls -lh "$DMG_OUT"
