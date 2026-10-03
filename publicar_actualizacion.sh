#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# publicar_actualizacion.sh — publica una actualización de Babel (macOS arm64)
#
#   Uso:  ./publicar_actualizacion.sh v0.2.10 "Notas de la versión"
#
# Genera el artefacto que consume el AUTO-UPDATER de Tauri v2 (.app.tar.gz + .sig),
# el latest.json que apunta a él, y crea la GitHub Release. Los usuarios con una
# versión anterior ven el aviso en ~15 min.
#
# IMPORTANTE (lecciones aprendidas — por eso este script existe):
#   · El updater usa el .app.tar.gz, NO el .dmg (el .dmg es solo para instalación
#     manual nueva, y además el completo con modelos se hace con crear_dmg_bundle.sh).
#   · En Tauri v2 la variable de firma es TAURI_SIGNING_PRIVATE_KEY (no _PATH, que
#     era de v1); si no, el build no firma.
#   · El build solo genera el .app.tar.gz si bundle.createUpdaterArtifacts = true.
#   · El sello de firma (firma.py) viaja dentro del SIDECAR → si tocaste el servidor
#     Python hay que recompilar el sidecar ANTES (servidor_babel/build_sidecar.sh).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

VERSION="${1:?Indica la versión, p.ej. v0.2.10}"
NOTAS="${2:?Indica las notas del release}"
VER_NUM="${VERSION#v}"

REPO="darioballesteros26-oss/babel-security"
KEY="$HOME/.babel-update-key"
TARGET="aarch64-apple-darwin"
ROOT="$(cd "$(dirname "$0")" && pwd)"
PRODUCT="Security Babel"
TARGZ_SRC="$ROOT/src-tauri/target/$TARGET/release/bundle/macos/${PRODUCT}.app.tar.gz"
# Nombre versionado (con espacio; GitHub lo convierte a puntos en la URL del asset).
# Etiqueta de arquitectura "aarch64" (no el triple completo), como v0.2.8/0.2.9.
ASSET_LOCAL="${PRODUCT}_${VER_NUM}_aarch64.app.tar.gz"
ASSET_URL="${PRODUCT// /.}_${VER_NUM}_aarch64.app.tar.gz"     # con puntos, como en la URL
STAGE="$(mktemp -d)"

rojo()  { printf '\033[31m%s\033[0m\n' "$*"; }
verde() { printf '\033[32m%s\033[0m\n' "$*"; }

# ── Comprobaciones previas ───────────────────────────────────────────────────
echo "▸ Comprobaciones previas…"

[ -f "$KEY" ] || { rojo "✗ No existe la clave de firma $KEY"; exit 1; }
command -v gh >/dev/null   || { rojo "✗ Falta la CLI de GitHub (gh)"; exit 1; }

# Debe estar en main, limpio y sincronizado con el remoto (la release apunta al HEAD remoto).
RAMA="$(git -C "$ROOT" rev-parse --abbrev-ref HEAD)"
[ "$RAMA" = "main" ] || { rojo "✗ No estás en main (estás en $RAMA)"; exit 1; }
if [ -n "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ]; then
  rojo "✗ Hay cambios sin commitear. Commitea y pushea antes de publicar."; exit 1
fi
git -C "$ROOT" fetch -q origin main
if [ "$(git -C "$ROOT" rev-parse HEAD)" != "$(git -C "$ROOT" rev-parse origin/main)" ]; then
  rojo "✗ main local y origin/main difieren. Haz push (o pull) antes de publicar."; exit 1
fi

# La versión del código debe coincidir con la que vas a publicar.
VER_CONF="$(grep -m1 '"version"' "$ROOT/src-tauri/tauri.conf.json" | sed 's/.*: *"//;s/".*//')"
if [ "$VER_CONF" != "$VER_NUM" ]; then
  rojo "✗ tauri.conf.json está en $VER_CONF pero publicas $VER_NUM."
  echo  "  Sube la versión en src-tauri/tauri.conf.json y src-tauri/Cargo.toml, commitea y pushea."
  exit 1
fi

# createUpdaterArtifacts debe estar activo o no se genera el .app.tar.gz.
grep -q '"createUpdaterArtifacts" *: *true' "$ROOT/src-tauri/tauri.conf.json" || {
  rojo "✗ Falta \"createUpdaterArtifacts\": true en el bundle de tauri.conf.json"; exit 1; }

# El tag no debe existir ya.
if gh release view "$VERSION" --repo "$REPO" >/dev/null 2>&1; then
  rojo "✗ La release $VERSION ya existe en GitHub."; exit 1
fi

# Sidecar presente y NO más viejo que el servidor Python (si no, llevaría un firma.py caduco).
SIDECAR="$ROOT/src-tauri/binaries/servidor_babel-$TARGET"
[ -f "$SIDECAR" ] || { rojo "✗ No existe el sidecar $SIDECAR — ejecútalo: cd servidor_babel && bash build_sidecar.sh"; exit 1; }
PY_NUEVO="$(find "$ROOT/servidor_babel" -name '*.py' -newer "$SIDECAR" -print -quit)"
if [ -n "$PY_NUEVO" ]; then
  rojo "✗ El sidecar es más viejo que el servidor Python (p.ej. $(basename "$PY_NUEVO"))."
  echo  "  Recompílalo antes: cd servidor_babel && bash build_sidecar.sh"
  exit 1
fi
verde "  ✓ Todo correcto (main, limpio, versión $VER_NUM, sidecar al día)."

# ── Build ────────────────────────────────────────────────────────────────────
# createUpdaterArtifacts:true hace que `tauri build` intente FIRMAR el .app.tar.gz;
# sin la clave en el entorno sale con error (y set -e cortaría). Le pasamos la clave
# del updater → build en 0 y .sig generado. (Luego renombramos a nombre versionado
# y re-firmamos ese fichero para dejar el trusted comment coherente.)
echo "▸ Construyendo Babel ${VERSION}…"
TAURI_SIGNING_PRIVATE_KEY="$(cat "$KEY")" TAURI_SIGNING_PRIVATE_KEY_PASSWORD="" \
  npm --prefix "$ROOT" run tauri build -- --target "$TARGET"

[ -f "$TARGZ_SRC" ] || { rojo "✗ No se generó el .app.tar.gz ($TARGZ_SRC)"; exit 1; }

# ── Renombrar a nombre versionado y firmar ese fichero ───────────────────────
echo "▸ Firmando el artefacto…"
cp "$TARGZ_SRC" "$STAGE/$ASSET_LOCAL"
( cd "$ROOT" && TAURI_SIGNING_PRIVATE_KEY_PASSWORD="" \
    npx tauri signer sign -f "$KEY" "$STAGE/$ASSET_LOCAL" >/dev/null )
[ -f "$STAGE/$ASSET_LOCAL.sig" ] || { rojo "✗ No se generó la firma .sig"; exit 1; }
FIRMA="$(cat "$STAGE/$ASSET_LOCAL.sig")"

# ── latest.json (apunta al .app.tar.gz, no al dmg) ───────────────────────────
echo "▸ Generando latest.json…"
FECHA="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
cat > "$STAGE/latest.json" <<EOF
{
  "version": "$VER_NUM",
  "notes": "$NOTAS",
  "pub_date": "$FECHA",
  "platforms": {
    "darwin-aarch64": {
      "signature": "$FIRMA",
      "url": "https://github.com/$REPO/releases/download/$VERSION/$ASSET_URL"
    }
  }
}
EOF

# ── Publicar ─────────────────────────────────────────────────────────────────
echo "▸ Creando release $VERSION en GitHub…"
gh release create "$VERSION" \
  "$STAGE/$ASSET_LOCAL" \
  "$STAGE/$ASSET_LOCAL.sig" \
  "$STAGE/latest.json" \
  --repo "$REPO" \
  --target main \
  --title "$PRODUCT $VERSION" \
  --notes "$NOTAS"

# ── Verificación end-to-end ──────────────────────────────────────────────────
echo "▸ Verificando el endpoint del updater…"
SERVED="$(curl -sL "https://github.com/$REPO/releases/latest/download/latest.json")"
VER_SERVED="$(printf '%s' "$SERVED" | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])' 2>/dev/null || echo '?')"
URL_SERVED="$(printf '%s' "$SERVED" | python3 -c 'import json,sys; print(json.load(sys.stdin)["platforms"]["darwin-aarch64"]["url"])' 2>/dev/null || echo '?')"
CODE="$(curl -sL -o /dev/null -w '%{http_code}' "$URL_SERVED" 2>/dev/null || echo '???')"

rm -rf "$STAGE"

echo ""
if [ "$VER_SERVED" = "$VER_NUM" ] && [ "$CODE" = "200" ]; then
  verde "✓ Release $VERSION publicada y verificada."
  echo  "  El endpoint sirve la versión $VER_SERVED y el artefacto descarga (HTTP $CODE)."
  echo  "  Los usuarios verán el aviso de actualización en los próximos ~15 min."
else
  rojo  "⚠ Release creada, pero la verificación no cuadró:"
  echo  "   versión servida = $VER_SERVED (esperada $VER_NUM), HTTP del artefacto = $CODE"
  echo  "   Revisa la release en https://github.com/$REPO/releases/tag/$VERSION"
fi
