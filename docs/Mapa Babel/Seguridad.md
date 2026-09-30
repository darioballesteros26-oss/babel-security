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

## Anti-intrusión — entorno
- **Anti-keylogger** — `escanear_keylogger_ahora`, `activar_entrada_segura`, `desactivar_entrada_segura`
- **Captura de pantalla** — `hay_captura_de_pantalla`
- **Entorno seguro** — `verificar_entorno_seguro`
- **Acceso masivo** — `acceso_masivo::registrar_descifrado` (bloquea tras 5 descifrados/10 s)
- **Integridad del binario** — `obtener_estado_integridad`

## Registro / auditoría
- **Bitácora** — `registrar_evento_diario`, `obtener_eventos_dia`, `obtener_ips_historial`
- **Preferencias / primera vez** — `obtener_preferencias_registro`, `guardar_preferencias_registro`, `marcar_primera_vez_registro`
- **Sospechas** (internas) — `registrar_sospecha_hw`, `registrar_sospecha_rat`, `registrar_sospecha_acceso_masivo`

> Cifra los datos de [[Archivos]], [[P2P]] y [[Funciones secundarias]]. Los HW-IDs pareados vienen de [[P2P]].
