# 🌐 Traducción

[[Babel]] · `traductor.rs`, `ia_biblioteca.rs` + sidecar `servidor_babel/`
(El asistente IA de redacción está en [[Archivos]] → "Crear archivo".)

## Traducir
- **Texto** — `traducir_texto`
- **Documento (subido)** — `traducir_documento`, `traducir_documento_dialogo`
- **Documento (por ruta)** — `traducir_documento_ruta`
- **Archivo ya guardado** — `traducir_archivo_guardado`
- **Cancelar** — `cancelar_traduccion_activa`

## Motor de traducción
- **Arrancar / estado del servidor** — `asegurar_servidor_traduccion`, `estado_servidor_cmd`
- **Modo rápido** — `set_modo_rapido`
- **Diccionario personalizado** — `cambiar_categoria_diccionario`
- Tier por RAM: **SMaLL-100** (<12 GB) / **MADLAD-400** (≥12 GB), CTranslate2 int8 (sidecar).
- Round-trip fiel de formato — `reconstruir_parrafo`, `separar_prefijo_md`.

## RAG jurídico
- **Buscar normativa** — `ia_biblioteca::buscar_normativa` (BM25 sobre ~3200 fragmentos: leyes BOE + STCs + modelos MEP), `obtener_biblioteca`, `precalentar`.

## OCR
- Extracción de texto de PDF/imagen escaneada vía **PaddleOCR-VL** (sidecar).

> El sidecar sirve también el OCR/firma de [[Archivos]] y la IA de "Crear archivo". Traducir un correo → [[Funciones secundarias]].
