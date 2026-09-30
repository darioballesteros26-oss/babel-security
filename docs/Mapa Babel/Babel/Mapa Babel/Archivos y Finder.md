# 📁 Archivos y Finder

Importar, guardar y abrir archivos cifrados; integración con el Finder de macOS.
**Módulos:** `main.rs` (comandos), `finder.rs`, `nom_cifrado.rs`

## Flujos clave
- `guardar_documento_desde_bytes` / `guardar_documento_sin_traducir` — import (drag-drop) → pasa por [[Compresión PDF]] → cifra → guarda en `~/Babel/guardados`. Son `async + spawn_blocking` (no congelan la UI).
- `cifrar_y_guardar_desde_bytes` / `_desde_ruta` — núcleo compartido; registra en [[Custodia y Device Binding]].
- `nom_cifrado` — índice cifrado de nombres visibles (los ficheros en disco tienen nombre opaco).
- `finder.rs` — "Guardar con Babel" (clic derecho): URL scheme `babel://` + Quick Action + token CSRF.

## Relacionado
Cifra con [[Cifrado]], comprime con [[Compresión PDF]], vincula con [[Custodia y Device Binding]]. Ver [[Babel]].
