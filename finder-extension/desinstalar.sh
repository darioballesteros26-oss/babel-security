#!/bin/bash
# Desinstala el Quick Action "Guardar con Babel" y su helper.
set -euo pipefail

SOPORTE="$HOME/Library/Application Support/Babel"
SERVICIOS="$HOME/Library/Services"
WORKFLOW="Guardar con Babel.workflow"

rm -rf "$SERVICIOS/$WORKFLOW"
rm -f "$SOPORTE/guardar_con_babel.sh"
/System/Library/CoreServices/pbs -flush 2>/dev/null || true

echo "✓ Desinstalado. (No se toca la cola ~/Babel/entrada_finder ni tus archivos cifrados.)"
