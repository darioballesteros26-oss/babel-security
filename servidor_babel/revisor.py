import os
import threading
from llama_cpp import Llama

DIR_MODELOS = os.path.join(os.path.dirname(__file__), "modelos")
RUTA_GGUF = os.path.join(DIR_MODELOS, "qwen-0.5b-q4.gguf")

LANG_NAMES = {
    "es": "Spanish", "en": "English", "fr": "French", "ar": "Arabic"
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

    lang_orig, lang_dest = par.split("-")
    nombre_orig = LANG_NAMES.get(lang_orig, lang_orig)
    nombre_dest = LANG_NAMES.get(lang_dest, lang_dest)

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
                f"Context: {contexto or '(none)'}\n"
                f"Source: {original}\n"
                f"Translation: {traduccion}\n"
                f"Corrected translation:"
            ),
        },
    ]

    with _lock:
        out = _llm.create_chat_completion(
            messages,
            max_tokens=512,
            temperature=0.1,
            stop=["Source:", "Context:", "\n\n"],
        )

    revisada = out["choices"][0]["message"]["content"].strip()
    return revisada if revisada else traduccion
