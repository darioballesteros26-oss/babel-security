#!/bin/bash
# Instalar Fondo Personal — doble clic.
# 1) Te deja elegir tu foto.  2) La deja fija como fondo.
# 3) Instala un LaunchAgent que la reaplica en cada inicio de sesión
#    (y cada 20 s) para que el MDM del colegio no te la pise al reiniciar.

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
DEST_IMG="$HOME/.fondo_personal.img"
DEST_SH="$HOME/.fondo_personal.sh"
AGENTE="$HOME/Library/LaunchAgents/local.fondo.personal.plist"
ETIQUETA="local.fondo.personal"

# --- 1) Elegir la foto con el diálogo del sistema ---
FOTO="$(osascript -e 'POSIX path of (choose file with prompt "Elige tu foto de fondo:" of type {"public.image"})' 2>/dev/null || true)"
if [ -z "$FOTO" ] || [ ! -f "$FOTO" ]; then
  osascript -e 'display dialog "No se eligió ninguna imagen. Cancelado." buttons {"OK"} default button 1 with icon caution' >/dev/null 2>&1
  exit 1
fi

# --- 2) Copiar la imagen a un sitio estable del usuario ---
cp "$FOTO" "$DEST_IMG"

# --- 3) Copiar el script reaplicador ---
cp "$DIR/fondo_personal.sh" "$DEST_SH"
chmod +x "$DEST_SH"

# --- 4) Crear el LaunchAgent (arranque de sesión + cada 20 s) ---
mkdir -p "$HOME/Library/LaunchAgents"
cat > "$AGENTE" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$ETIQUETA</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>$DEST_SH</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StartInterval</key>
    <integer>20</integer>
    <key>WatchPaths</key>
    <array>
        <string>/Library/Managed Preferences/com.apple.desktop.plist</string>
    </array>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
PLIST

# --- 5) (Re)cargar el agente ---
launchctl unload "$AGENTE" 2>/dev/null || true
launchctl load "$AGENTE" 2>/dev/null || true

# --- 6) Aplicar ya mismo ---
osascript -e "tell application \"System Events\" to set picture of every desktop to (\"$DEST_IMG\" as POSIX file)" >/dev/null 2>&1 || true

osascript -e 'display dialog "Listo. Tu fondo personal quedará puesto en cada inicio de sesión.\n\nPara quitarlo: ejecuta \"Quitar Fondo Personal.command\"." buttons {"Perfecto"} default button 1' >/dev/null 2>&1

exit 0
