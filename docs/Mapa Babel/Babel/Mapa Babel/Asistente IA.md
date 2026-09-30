# 🤖 Asistente IA

Redacción documental/jurídica asistida, 100 % local.
**Módulos:** `ia_redaccion.rs`, `ia_biblioteca.rs`

## Redacción (`ia_redaccion.rs`)
Arranca `llama-server` con **Qwen** (fallback GPU→CPU), `--cache-reuse` para reutilizar el prompt de sistema, KV cache q4_0. Detecta datos faltantes y para a preguntar.
- `matar_llama_si_activo` — libera RAM (exclusión con la traducción).
- `SYSTEM_PROMPT` — jerarquía de reglas de redacción.

## RAG jurídico (`ia_biblioteca.rs`)
Recuperación **BM25** sobre `~/Babel/biblioteca_juridica` (~3200 fragmentos: leyes BOE + STCs + modelos MEP).
- `buscar_normativa(query, max_chars)` — devuelve el bloque de normativa relevante.
- `obtener_biblioteca` (OnceLock), `precalentar`.

## Relacionado
Motor llama vía [[Sidecar Python]] (OCR) y binario propio. Compite en RAM con [[Traducción]]. Ver [[Babel]].
