#!/bin/bash
# fondo_personal.sh — reaplica TU fondo si el MDM lo ha vuelto a pisar.
# Se ejecuta en cada inicio de sesión y cada pocos segundos vía LaunchAgent.
# No pelea sin parar: solo cambia el fondo si NO es ya el tuyo (evita parpadeo).

IMG="$HOME/.fondo_personal.img"     # tu imagen (copiada por el instalador)

[ -f "$IMG" ] || exit 0             # sin imagen, no hace nada

# Ruta actual del fondo (según System Events)
ACTUAL="$(osascript -e 'tell application "System Events" to get picture of current desktop' 2>/dev/null)"

# Si ya es el nuestro, no tocar nada
[ "$ACTUAL" = "$IMG" ] && exit 0

# Reaplicar en TODOS los escritorios/monitores
osascript -e "tell application \"System Events\" to set picture of every desktop to (\"$IMG\" as POSIX file)" >/dev/null 2>&1

exit 0
