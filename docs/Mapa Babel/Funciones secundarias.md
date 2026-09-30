# ⚙️ Funciones secundarias

[[Babel]] · Apoyo que no es el núcleo (documentos / seguridad / traducción).

## Ajustes
- **Cargar / guardar** — `load_settings`, `save_settings`
- **Idioma de la interfaz** — `cambiar_idioma`
- **Autologin (keychain)** — `guardar_preferencia_autologin`, `leer_preferencia_autologin`
- (modo rápido de traducción → [[Traducción]]; preferencias de registro → [[Seguridad]])

## Email (Gmail)
- **Conectar** (OAuth PKCE) — `iniciar_oauth_gmail_tauri`, `estado_oauth_gmail_tauri`, `revocar_oauth_gmail_tauri`
- **Configuración** — `guardar_config_email_tauri`, `tiene_config_email`, `obtener_firma_email`
- **Leer** — `obtener_emails_tauri`, `obtener_email_completo_tauri`
- **Escribir / adjuntar** — `enviar_solo_texto_tauri`, `seleccionar_archivo_email_dialogo`
- **Gestionar** — `archivar_email_tauri`, `eliminar_email_tauri`, `marcar_destacado_tauri`, `marcar_no_leido_tauri`

## Actualizaciones
- **Instalar actualización** — `instalar_actualizacion` (tauri-plugin-updater + minisign; `.app.tar.gz`)

## Términos / legal
- **Aceptar / comprobar** — `aceptar_terminos`, `comprobar_terminos_aceptados`

## Integración Finder
- **"Guardar con Babel"** (clic derecho) — `procesar_entrada_finder` (URL scheme `babel://` + Quick Action + token CSRF)

## Misc
- `greet` — comando de ejemplo de Tauri (scaffolding).

> Los tokens de email se cifran con [[Seguridad]]; traducir un correo usa [[Traducción]].
