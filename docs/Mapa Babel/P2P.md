# 🔄 P2P (Sincronización)

[[Babel]] · `sincronizacion.rs`, `babel_p2p.rs`, `conexion_directa.rs`, `buzon_b2.rs`
Sincronizar la bóveda entre tus dispositivos, cifrado extremo a extremo, sin servidor central.

## Emparejar dispositivos
- **Solicitar** — `solicitar_emparejamiento_sinc`
- **Aceptar / rechazar** — `aceptar_emparejamiento_sinc`, `rechazar_emparejamiento_sinc`
- **Ver solicitud** — `obtener_solicitud_sinc`
- **Listar emparejados** — `listar_dispositivos_emparejados`
- **Desemparejar** — `desemparejar_dispositivo`

## Descubrir
- **Buscar dispositivos** — `buscar_dispositivos_sinc`, `buscar_peers_p2p`
- **Peers pendientes** — `listar_peers_pendientes_cmd`, `aprobar_peer_pendiente_cmd`
- **Probar conexión** — `probar_conexion_dispositivo`

## Servidor de sincronización
- **Arrancar / parar** — `iniciar_sinc_servidor`, `detener_sinc_servidor`, `iniciar_servidor_p2p`
- **NAT traversal** (STUN) — `conexion_directa.rs` (conectar fuera de la LAN)

## Transferir
- **Enviar archivo** — `enviar_archivo_p2p`
- **Chat / mensajes** — `enviar_mensaje_p2p`, `obtener_mensajes_p2p`
- **Cola pendiente** — `contar_pendientes_b2`

## Info del equipo
- **IP / nombre local** — `obtener_ip_local`, `obtener_nombre_local`

> Los HW-IDs pareados (`cargar_emparejados`) los usa [[Seguridad]] (device binding) para no borrar archivos legítimos de otro equipo tuyo. Todo cifrado con [[Seguridad]].
