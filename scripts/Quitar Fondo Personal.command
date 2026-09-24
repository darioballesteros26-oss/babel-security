#!/bin/bash
# Quitar Fondo Personal — doble clic. Desactiva el reaplicador y borra los archivos.
AGENTE="$HOME/Library/LaunchAgents/local.fondo.personal.plist"

launchctl unload "$AGENTE" 2>/dev/null || true
rm -f "$AGENTE" "$HOME/.fondo_personal.sh" "$HOME/.fondo_personal.img"

osascript -e 'display dialog "Fondo personal desactivado. En el próximo reinicio volverá el fondo del colegio." buttons {"OK"} default button 1' >/dev/null 2>&1
exit 0
