# 🔐 Seguridad

[[Babel]] · `seguridad.rs`, `custodia.rs`, `enclave.rs`, `rat_detector.rs`, `acceso_masivo.rs`, `integridad.rs`, `registro_diario.rs`

## Bóveda y login
- **Crear bóveda** — `crear_acceso_bunker`
- **Estado de la bóveda** — `comprobar_estado_bunker`
- **Iniciar sesión** — `verificar_login`
- **Autologin** (keychain) — `autologin_tauri`
- **Ver usuario** — `obtener_usuario_con_maestra`
- **Cerrar sesión** — `cerrar_sesion_rust`, `olvidar_sesion_tauri`

## Cifrado (motor, interno)
- **Derivar clave** — `derivar_subclave` (Argon2id → HKDF)
- **Cifrar / descifrar** — `blindar_documento` / `descifrar_documento` (AES-256-GCM)
- **Login hash** — `hash_password` / `verificar_password`

## Recuperación de cuenta
- **Generar / ver frase** (BIP39) — `generar_frase_recuperacion`, `ver_frase_recuperacion`
- **Recuperar** — `recuperar_y_autenticar`
- **HTML de la frase** — `guardar_html_frase`, `borrar_html_frase`

## Device binding (custodia)
- **Vincular archivo al hardware** — `registrar_archivo`
- **Barrer lo no autorizado al login** — `verificar_y_limpiar`
- **HW-ID del equipo** — `enclave::obtener_hw_id` (Secure Enclave / TPM), `nivel_seguridad_actual`

## Anti-intrusión — control remoto (RAT)
- **Estado del bloqueo** — `estado_bloqueo_rat`
- **Desbloquear con frase** (BIP39) — `desbloquear_rat_bip39`
- **Desbloqueo entre pares** — `solicitar_desbloqueo_a_pares`, `obtener_solicitud_desbloqueo_rat`, `confirmar_desbloqueo_rat_cmd`, `rechazar_solicitud_desbloqueo_rat`

### Cómo detecta (interno, `rat_detector.rs`)
- **Monitor** — `iniciar_monitor_rat` arranca tras login; escanea cada **15 s** (`detectar_rat_activo`). `detener_monitor_rat` lo para al logout y limpia estado + confiables.
- **Lista** — `PROCESOS_RAT`: TeamViewer, AnyDesk, Chrome Remote Desktop, RustDesk, LogMeIn, Splashtop, NoMachine, Jump Desktop, ScreenConnect, DWService, MeshCentral, BeyondTrust, AeroAdmin, Remotix, GoTo Assist, Vine VNC + Screen Sharing de macOS (+ variantes Windows).
- **Mecanismo** — enumera procesos con **sysinfo** (ve también procesos de root y da el nombre base) y hace **match por substring** en minúsculas. Sustituye a `pgrep -x`, que fallaba con argv[0] de ruta completa (p. ej. `/sbin/launchd`) y con variantes como `TeamViewer_Desktop`.
- **Screen Sharing nativo** — es on-demand y corre como root: se bloquea solo si **`netstat -an`** ve una conexión VNC `ESTABLISHED` (puerto 5900). Antes se usaba `lsof -i`, que como usuario normal **no ve los sockets de root** → falso negativo en el vector más probable.
- **Al detectar** — `activar_bloqueo_rat`: pone `RAT_BLOQUEADO`, mata `llama-server`, emite `rat-detectado` (overlay) y registra `sospecha_rat`. Todo comando crítico pasa por `verificar_no_bloqueado_rat`.
- **Confianza de sesión** — marcar un RAT como confiable exige frase BIP39 (`desbloquear_rat_bip39` con `marcar_confiable`); se limpia al logout.
- **Protocolo de desbloqueo P2P** — HMAC por par (clave única del emparejamiento); el receptor **nunca** acepta la clave estática del binario y exige IP emparejada + ventana de 60 s. Ver [[P2P]].

## Anti-intrusión — entorno
- **Anti-keylogger** — `escanear_keylogger_ahora`, `activar_entrada_segura`, `desactivar_entrada_segura`
- **Captura de pantalla** — `hay_captura_de_pantalla` (detección en vivo: `bloqueo` tapa el contenido con overlay, `aviso` solo advierte). Alta confianza = match **exacto** (`screensharingd`, `obs`) + mirroring/AirPlay; baja confianza = substring (Zoom, Teams, Loom…). La ventana de Babel se excluye de la captura con `excluir_ventana_de_captura` (macOS `NSWindowSharingNone`; Windows pendiente `WDA_EXCLUDEFROMCAPTURE`).
- **Entorno seguro** — `verificar_entorno_seguro`
- **Acceso masivo** — `acceso_masivo::registrar_descifrado` (bloquea tras 5 descifrados/10 s)
- **Integridad del binario** — `obtener_estado_integridad`

## Registro / auditoría
- **Bitácora** — `registrar_evento_diario`, `obtener_eventos_dia`, `obtener_ips_historial`
- **Preferencias / primera vez** — `obtener_preferencias_registro`, `guardar_preferencias_registro`, `marcar_primera_vez_registro`
- **Sospechas** (internas) — `registrar_sospecha_hw`, `registrar_sospecha_rat`, `registrar_sospecha_acceso_masivo`

> Cifra los datos de [[Archivos]], [[P2P]] y [[Funciones secundarias]]. Los HW-IDs pareados vienen de [[P2P]].
