import os
import threading
from llama_cpp import Llama

DIR_MODELOS = os.path.join(os.path.dirname(__file__), "modelos")
RUTA_GGUF = os.path.join(DIR_MODELOS, "qwen-0.5b-q4.gguf")

LANG_NAMES = {
    "es": "Spanish", "en": "English", "fr": "French", "ar": "Arabic",
    "de": "German", "ru": "Russian", "zh": "Chinese",
}

_llm = None
_lock = threading.Lock()


def cargar_modelo():
    global _llm
    print("[QWEN] Cargando revisor...")
    _llm = Llama(
        model_path=RUTA_GGUF,
        n_ctx=2048,
        n_gpu_layers=-1,  # offload todo a Metal en M3
        verbose=False,
    )
    print("[QWEN] Revisor listo.")


def revisar(original: str, traduccion: str, par: str, contexto: str = "") -> str:
    if _llm is None:
        return traduccion

    # Qwen 0.5B entra en bucles con frases muy cortas — no hay contexto que revisar
    if len(original.split()) < 8:
        return traduccion

    lang_orig, lang_dest = par.split("-")
    nombre_orig = LANG_NAMES.get(lang_orig, lang_orig)
    nombre_dest = LANG_NAMES.get(lang_dest, lang_dest)

    # Truncar contexto para no sobrepasar n_ctx=2048 con documentos largos
    ctx_truncado = contexto[-200:].strip() if contexto else ""

    messages = [
        {
            "role": "system",
            "content": (
                "You are a professional translation post-editor. "
                "Given a source text, a machine translation, and optional surrounding context, "
                "return ONLY the corrected translation. "
                "If the translation is already correct, return it unchanged. "
                "Never add explanations."
            ),
        },
        {
            "role": "user",
            "content": (
                f"Source language: {nombre_orig}\n"
                f"Target language: {nombre_dest}\n"
                f"Context: {ctx_truncado or '(none)'}\n"
                f"Source: {original}\n"
                f"Translation: {traduccion}\n"
                f"Corrected translation:"
            ),
        },
    ]

    with _lock:
        out = _llm.create_chat_completion(
            messages,
            max_tokens=min(len(traduccion.split()) * 3, 256),
            temperature=0.1,
            repeat_penalty=1.3,
            stop=["Source:", "Context:"],
        )

    revisada = out["choices"][0]["message"]["content"].strip()

    # Descartar si Qwen repite o alucina (más del doble de tokens que la traducción base)
    if not revisada or len(revisada) > len(traduccion) * 2:
        return traduccion

    return revisada
