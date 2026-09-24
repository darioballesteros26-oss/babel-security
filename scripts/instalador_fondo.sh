#!/bin/bash
# instalador.sh — motor all-in-one de "Fondo Personal.app".
# Doble clic:
#   - si NO está instalado -> elige foto -> instala LaunchAgent + aplica.
#   - si YA está instalado -> diálogo Quitar / Cambiar foto / Cancelar.
# Objetivo: mantener TU fondo en el iMac del colegio pese al MDM que lo pisa.

DIR="$(cd "$(dirname "$0")" && pwd)"          # = Resources del bundle
DEST_IMG="$HOME/.fondo_personal.img"
DEST_SH="$HOME/.fondo_personal.sh"
AGENTE="$HOME/Library/LaunchAgents/local.fondo.personal.plist"
ETIQUETA="local.fondo.personal"
MDM_PLIST="/Library/Managed Preferences/com.apple.desktop.plist"

msg() { osascript -e "display dialog \"$1\" buttons {\"OK\"} default button 1" >/dev/null 2>&1; }

elegir_foto() {
  osascript -e 'POSIX path of (choose file with prompt "Elige tu foto de fondo:" of type {"public.image"})' 2>/dev/null || true
}

instalar() {
  local FOTO
  FOTO="$(elegir_foto)"
  if [ -z "$FOTO" ] || [ ! -f "$FOTO" ]; then
    msg "No se eligió ninguna imagen. Cancelado."
    exit 1
  fi

  cp "$FOTO" "$DEST_IMG"
  cp "$DIR/fondo_personal.sh" "$DEST_SH"
  chmod +x "$DEST_SH"

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
        <string>$MDM_PLIST</string>
    </array>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
PLIST

  launchctl unload "$AGENTE" 2>/dev/null || true
  launchctl load "$AGENTE" 2>/dev/null || true

  # Aplicar YA (con UI delante -> dispara el permiso de Automatización si hace falta)
  osascript -e "tell application \"System Events\" to set picture of every desktop to (\"$DEST_IMG\" as POSIX file)" >/dev/null 2>&1 || true

  msg "Listo. Tu fondo personal quedará puesto al iniciar sesión y se repondrá al instante si el colegio lo cambia.\n\nVuelve a abrir esta app para cambiar la foto o quitarlo."
}

cambiar() {
  local FOTO
  FOTO="$(elegir_foto)"
  if [ -z "$FOTO" ] || [ ! -f "$FOTO" ]; then
    msg "No se eligió ninguna imagen. No se cambió nada."
    exit 1
  fi
  cp "$FOTO" "$DEST_IMG"
  osascript -e "tell application \"System Events\" to set picture of every desktop to (\"$DEST_IMG\" as POSIX file)" >/dev/null 2>&1 || true
  msg "Foto de fondo actualizada."
}

quitar() {
  launchctl unload "$AGENTE" 2>/dev/null || true
  rm -f "$AGENTE" "$DEST_SH" "$DEST_IMG"
  msg "Fondo personal desactivado. En el próximo reinicio volverá el fondo del colegio."
}

# --- Enrutado según estado ---
if [ -f "$AGENTE" ]; then
  ELECCION="$(osascript -e 'button returned of (display dialog "Fondo Personal ya está activo.\n\n¿Qué quieres hacer?" buttons {"Cancelar", "Quitar", "Cambiar foto"} default button "Cambiar foto")' 2>/dev/null || echo "Cancelar")"
  case "$ELECCION" in
    "Cambiar foto") cambiar ;;
    "Quitar")       quitar ;;
    *)              exit 0 ;;
  esac
else
  instalar
fi

exit 0
