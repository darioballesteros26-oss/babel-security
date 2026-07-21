#!/bin/bash
# ============================================================================
# Guardar con Babel — helper del Quick Action del Finder (macOS)
# ============================================================================
# Recibe rutas de archivos como argumentos (una por selección del Finder), copia
# cada archivo de tipo compatible a la carpeta de STAGING de Babel y dispara el
# URL scheme babel://guardar para que Babel lo cifre e importe.
#
# Por qué staging (una copia) en vez de pasar la ruta por la URL: bajo App Sandbox
# un path que llega por URL NO es "user-selected" y la app firmada no podría leerlo.
# La carpeta de staging vive dentro del directorio de Babel (lectura siempre
# permitida) y además actúa como cola durable si la sesión está bloqueada/cerrada.
#
# El original NO se borra aquí: lo borra Babel de forma segura (borrar_seguro, 3
# pasadas) SOLO tras cifrar con éxito, usando la ruta guardada en el sidecar .orig.
# ============================================================================
set -u

# Extensiones aceptadas (deben coincidir con cifrar_y_guardar_desde_ruta en Rust).
EXTS_OK="pdf docx txt png jpg jpeg"

# Destino: dentro del contenedor sandbox si existe (build firmado/hardened), o en
# ~/Babel/entrada_finder para el build de desarrollo/DMG (no sandboxed).
if [ -d "$HOME/Library/Containers/com.babel.seguridad" ]; then
  DEST="$HOME/Library/Containers/com.babel.seguridad/Data/Babel/entrada_finder"
else
  DEST="$HOME/Babel/entrada_finder"
fi
mkdir -p "$DEST" 2>/dev/null || exit 0

algo=0
for f in "$@"; do
  [ -f "$f" ] || continue
  base="$(basename "$f")"
  ext="$(printf '%s' "${base##*.}" | tr '[:upper:]' '[:lower:]')"
  case " $EXTS_OK " in
    *" $ext "*) : ;;          # compatible
    *) continue ;;            # tipo no compatible → se ignora sin error
  esac

  uuid="$(uuidgen)"
  # Copiar la copia staged en claro. Si falla (permisos), saltar sin romper.
  cp -f "$f" "$DEST/${uuid}__${base}" 2>/dev/null || continue
  # Sidecar con la ruta absoluta del original (para el borrado seguro tras cifrar).
  printf '%s' "$f" > "$DEST/${uuid}.orig" 2>/dev/null
  algo=1
done

# Disparar Babel una sola vez; escaneará toda la carpeta de staging. Si Babel está
# cerrado, `open` lo lanza; si la sesión está bloqueada, mostrará el login.
if [ "$algo" = "1" ]; then
  open "babel://guardar"
fi

exit 0
