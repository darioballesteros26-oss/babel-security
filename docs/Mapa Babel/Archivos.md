# 📁 Archivos

[[Babel]] · `main.rs`, `pdf_reducir.rs`, `img_a_pdf.rs`, `pdf_union.rs`, `compartir.rs`, `ia_redaccion.rs`, `nom_cifrado.rs`
("Carpetas" en la UI = `buzon` en el código.)

## Carpetas
- **Crear** — `crear_buzon`, `crear_buzon_guardado`
- **Listar** — `listar_buzones`, `listar_buzones_guardados`
- **Renombrar** — `renombrar_buzon`, `renombrar_buzon_guardado`
- **Eliminar** — `eliminar_buzon`, `eliminar_buzon_guardado`
- **Sincronizar cambios** — `aplicar_pendientes_buzon`, `verificar_buzones_todos`

## Crear archivo (editor + IA)
- **Editar DOCX en sitio** — `leer_docx_editable`, `actualizar_documento_guardado`
- **Asistente IA de redacción** — `iniciar_ia_redaccion`, `estado_ia_redaccion`, `parar_ia_redaccion`
  - **Chatear con la IA** — `enviar_mensaje_ia`, `enviar_mensaje_ia_stream`
  - **Contexto del documento** — `extraer_texto_para_ia`, `leer_resultado`
  - (Qwen local vía llama-server, fallback GPU→CPU; RAG jurídico en [[Traducción]])
- **Modo watch** (auto-cifrar) — `iniciar_modo_watch`

## Documentos
- **Importar** — `importar_archivo_dialogo`, `importar_carpeta_dialogo`
- **Guardar cifrado** — `guardar_documento_desde_bytes`, `guardar_documento_sin_traducir`, `guardar_documento_pdf_desde_docx`
- **Abrir / ver** — `ver_archivo`, `listar_archivos_guardados`, `archivo_guardado_existe`
- **Mover** — `mover_archivo`, `mover_archivo_guardado`
- **Renombrar** — `renombrar_archivo`
- **Eliminar** — `eliminar_archivo`, `borrar_archivo_fuente`, `borrar_archivo_original`
- **Exportar** — `exportar_archivo`, `exportar_archivos_a_carpeta`
- **Temporales / rutas** — `preparar_temp_bytes`, `seleccionar_ruta_dialogo`

## Compartir y copiar
- **Compartir (HTML autodescifrable)** — `compartir_a_url`, `generar_archivo_compartir`
- **Compartir nativo (macOS)** — `compartir_archivo_nativo`, `compartir_directo`
- **Enviar cifrado** — `enviar_archivo_cifrado_tauri`, `enviar_bytes_cifrados_tauri`
- **Contactos** — `listar_contactos_compartir`, `olvidar_contacto`, `actualizar_password_contacto`, `ver_password_contacto`
- **Destinos** — `cargar_destinos_compartir`, `guardar_destinos_compartir`

## PDF
- **Comprimir** (auto al importar) — `optimizar_imagenes_pdf`, `subset_fuentes`, `comprimir_streams` (+ recorte por DPI)
- **Unir** — `unir_pdfs`, `preparar_union_pdfs`
- **Contar / extraer páginas** — `contar_paginas_pdf`, `extraer_paginas_pdf`
- **Imagen → PDF** — `convertir_imagenes_a_pdf`
- **Herramientas** — `verificar_herramientas_pdf`

## Firmar
- **Firmar PDF** (PAdES) — `firmar_pdf_cifrado`, `seleccionar_cert_p12`, `titular_del_cert`

## Finder (navegación)
- **Abrir / revelar** — `abrir_carpeta_babel`, `abrir_carpeta_guardados`, `revelar_en_finder`

> Cifra con [[Seguridad]]; traducir un archivo → [[Traducción]]; enviar a otro equipo → [[P2P]].
