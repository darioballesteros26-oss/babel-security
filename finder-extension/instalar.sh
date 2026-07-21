#!/bin/bash
# ============================================================================
# Instalador del Quick Action "Guardar con Babel" (clic derecho del Finder)
# ============================================================================
# - Copia el helper guardar_con_babel.sh a ~/Library/Application Support/Babel/
# - Instala el bundle .workflow en ~/Library/Services/
# - Refresca el registro de Servicios de macOS
#
# No requiere permisos de administrador ni firma de código: los Quick Actions de
# usuario viven en ~/Library/Services. (La app Babel es la que registra el URL
# scheme babel://; ver README.md.)
# ============================================================================
set -euo pipefail

AQUI="$(cd "$(dirname "$0")" && pwd)"
SOPORTE="$HOME/Library/Application Support/Babel"
SERVICIOS="$HOME/Library/Services"
WORKFLOW="Guardar con Babel.workflow"

echo "· Instalando helper…"
mkdir -p "$SOPORTE"
cp -f "$AQUI/guardar_con_babel.sh" "$SOPORTE/guardar_con_babel.sh"
chmod +x "$SOPORTE/guardar_con_babel.sh"

echo "· Instalando Quick Action en ${SERVICIOS}…"
mkdir -p "$SERVICIOS"
rm -rf "$SERVICIOS/$WORKFLOW"
cp -R "$AQUI/$WORKFLOW" "$SERVICIOS/$WORKFLOW"

echo "· Refrescando el registro de Servicios…"
/System/Library/CoreServices/pbs -flush 2>/dev/null || true

echo ""
echo "✓ Instalado."
echo "  Clic derecho sobre un archivo (PDF/DOCX/TXT/PNG/JPG) en el Finder →"
echo "  'Acciones rápidas' (o 'Servicios') → 'Guardar con Babel'."
echo ""
echo "  Si no aparece de inmediato, ábrelo una vez en"
echo "  Ajustes del Sistema → Extensiones → Finder / Acciones rápidas,"
echo "  o cierra y abre sesión."
