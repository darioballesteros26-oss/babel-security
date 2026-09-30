# 🗺️ Babel — Mapa de funciones

App Tauri (Rust + web) para cifrar, traducir, editar, firmar y compartir documentos,
100 % local. Este vault mapea la app en **5 grandes partes**; cada nota lista las
funciones/acciones concretas de esa parte.

> Abre esta carpeta en Obsidian (*Open folder as vault*) y pulsa el **Graph view** (⌘G) para ver el mapa.

## Las 5 partes

- [[Seguridad]] — cifrado, login, bóveda, device binding, anti-intrusión, recuperación.
- [[Traducción]] — traducir documentos/texto/email + asistente IA + RAG jurídico.
- [[Archivos]] — carpetas, documentos, importar/guardar/mover/eliminar, compartir, copiar, PDF, firmar.
- [[P2P]] — sincronización y transferencia entre dispositivos.
- [[Funciones secundarias]] — **ajustes**, email, actualizaciones, términos, Finder.

## Notas
- Entrada: `main.rs` (comandos Tauri). Datos en `~/Babel` (ruta fija), ficheros 0600.
- "Carpetas" en la UI = `buzon` en el código (interno).
