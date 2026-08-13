#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# publicar_actualizacion.sh
# Uso: ./publicar_actualizacion.sh "v0.1.1" "Corrección de bugs y mejoras"
# ─────────────────────────────────────────────────────────────────────────────

set -e

VERSION="${1:?Indica la versión, p.ej. v0.1.1}"
NOTAS="${2:?Indica las notas del release}"
PRIVATE_KEY_PATH="$HOME/.babel-update-key"
REPO="darioballesteros26-oss/babel-security"

echo "▸ Construyendo Babel $VERSION ..."
TAURI_SIGNING_PRIVATE_KEY_PATH="$PRIVATE_KEY_PATH" \
  npm run tauri build -- --target aarch64-apple-darwin

DMG=$(find src-tauri/target/aarch64-apple-darwin/release/bundle/dmg -name "*.dmg" | head -1)
SIG="${DMG}.sig"

if [ ! -f "$SIG" ]; then
  echo "✗ No se generó la firma (.sig). Comprueba que TAURI_SIGNING_PRIVATE_KEY_PATH es correcto."
  exit 1
fi

# Firma en base64 (contenido del .sig)
FIRMA=$(cat "$SIG")
FECHA=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Número de versión sin la "v"
VER_NUM="${VERSION#v}"

# Nombre del DMG limpio para la URL (sin espacios)
DMG_NOMBRE=$(basename "$DMG" | sed 's/ /%20/g')

echo "▸ Generando latest.json ..."
cat > latest.json <<EOF
{
  "version": "$VER_NUM",
  "notes": "$NOTAS",
  "pub_date": "$FECHA",
  "platforms": {
    "darwin-aarch64": {
      "signature": "$FIRMA",
      "url": "https://github.com/$REPO/releases/download/$VERSION/$DMG_NOMBRE"
    }
  }
}
EOF

echo "▸ Creando release $VERSION en GitHub ..."
gh release create "$VERSION" \
  "$DMG" \
  "$SIG" \
  "latest.json" \
  --repo "$REPO" \
  --title "Security Babel $VERSION" \
  --notes "$NOTAS"

echo ""
echo "✓ Release $VERSION publicado."
echo "  Los usuarios de Babel verán el aviso de actualización en los próximos 15 minutos."
