import os
import re
import threading
from functools import lru_cache
from llama_cpp import Llama

# Detectores de script para validar que la revisión de Qwen está en el idioma correcto
_RE_ARABE  = re.compile(r'[؀-ۿ]')
_RE_LATIN  = re.compile(r'[a-zA-Z]')
_RE_CIRIL  = re.compile(r'[Ѐ-ӿ]')
_RE_HAN    = re.compile(r'[一-鿿]')

# Script esperado por idioma destino (None = no se verifica)
_SCRIPT_DEST = {
    "ar": _RE_ARABE,
    "ru": _RE_CIRIL,
    "zh": _RE_HAN,
}

# Idiomas donde Qwen 1.5B aporta mejoras reales.
# Para el resto (árabe, chino, ruso, japonés…) Qwen es poco fiable y los guards
# lo rechazarían de todas formas — saltamos la llamada para ahorrar ~2-3 s/párrafo.
_IDIOMAS_CON_REVISION = {"es", "en", "fr", "de", "pt", "it"}

# Palabras que cambian la polaridad/sentido de una frase (por idioma destino).
_RE_POLAR = {
    "es": re.compile(r'\b(no|sin|contra|nunca|jamás|tampoco|ni|excepto|salvo)\b', re.IGNORECASE),
    "en": re.compile(r'\b(not|without|against|never|except|unless|nor)\b', re.IGNORECASE),
    "fr": re.compile(r'\b(pas|sans|contre|jamais|sauf|ni)\b', re.IGNORECASE),
    "de": re.compile(r'\b(nicht|ohne|gegen|niemals|außer)\b', re.IGNORECASE),
}


def _palabras_norm(texto: str) -> set:
    return set(re.sub(r'[^\w]', ' ', texto.lower()).split())

DIR_MODELOS = os.path.join(os.path.dirname(__file__), "modelos")
RUTA_GGUF = os.path.join(DIR_MODELOS, "qwen-1.5b-q4.gguf")

LANG_NAMES = {
    "es": "Spanish", "en": "English", "fr": "French", "ar": "Arabic",
    "de": "German", "ru": "Russian", "zh": "Chinese", "pt": "Portuguese",
    "it": "Italian",
}

_llm = None
_lock = threading.Lock()


def cargar_modelo():
    global _llm
    print("[QWEN] Cargando revisor...")
    _llm = Llama(
        model_path=RUTA_GGUF,
        n_ctx=4096,
        n_gpu_layers=-1,
        verbose=False,
    )
    print("[QWEN] Revisor listo.")


@lru_cache(maxsize=512)
def _revisar_cached(original: str, traduccion: str, par: str) -> str:
    """Núcleo cacheado — misma entrada produce mismo resultado sin llamar a Qwen de nuevo."""
    lang_orig, lang_dest = par.split("-")
    nombre_orig = LANG_NAMES.get(lang_orig, lang_orig)
    nombre_dest = LANG_NAMES.get(lang_dest, lang_dest)

    messages = [
        {
            "role": "system",
            "content": (
                "You are a professional legal translation post-editor. "
                "Fix ONLY clear grammatical errors or obvious mistranslations. "
                "Do NOT add words, adverbs, adjectives, or phrases not implied by the source. "
                "Do NOT change the polarity or meaning of the sentence. "
                "If the translation is already acceptable, return it UNCHANGED. "
                "Return ONLY the corrected translation. Never add explanations."
            ),
        },
        {
            "role": "user",
            "content": (
                f"Source language: {nombre_orig}\n"
                f"Target language: {nombre_dest}\n"
                f"Source: {original}\n"
                f"Translation: {traduccion}\n"
                f"Corrected translation:"
            ),
        },
    ]

    with _lock:
        out = _llm.create_chat_completion(
            messages,
            max_tokens=min(len(traduccion.split()) * 2 + 20, 400),
            temperature=0.1,
            repeat_penalty=1.3,
            stop=["Source:", "Context:", "\n\n"],
        )

    revisada = out["choices"][0]["message"]["content"].strip()

    # Descartar si Qwen alucina (más del doble de tokens que la base)
    if not revisada or len(revisada) > len(traduccion) * 2:
        return traduccion

    # Guardia de script
    detector = _SCRIPT_DEST.get(lang_dest)
    if detector:
        if not detector.search(revisada):
            return traduccion
        if lang_dest == "ar":
            for tok in revisada.split():
                if _RE_ARABE.search(tok) and _RE_LATIN.search(tok):
                    return traduccion

    # Guardias semánticas para idiomas latinos
    pat_pol = _RE_POLAR.get(lang_dest)
    if pat_pol:
        if len(pat_pol.findall(traduccion)) != len(pat_pol.findall(revisada)):
            return traduccion

    orig_norm = _palabras_norm(original)
    base_norm = _palabras_norm(traduccion)
    rev_norm  = _palabras_norm(revisada)
    nuevas_contenido = {
        w for w in (rev_norm - base_norm - orig_norm)
        if len(w) >= 5 and w.isalpha()
    }
    if nuevas_contenido:
        return traduccion

    return revisada


def limpiar_bloques_pdf(bloques: list[str]) -> list[str]:
    """Usa Qwen para limpiar texto extraído de PDF: une fragmentos, quita artefactos.
    Solo actúa si el modelo está cargado; en caso contrario devuelve los bloques tal cual."""
    if _llm is None or not bloques:
        return bloques

    texto = "\n".join(bloques)
    # Limitar para no desbordar el contexto
    if len(texto) > 3000:
        return bloques

    messages = [
        {
            "role": "system",
            "content": (
                "You are a PDF text cleanup tool. "
                "Fix ONLY structural issues in the extracted text:\n"
                "1. Join lines that are clearly part of the same sentence.\n"
                "2. Remove lone numbers or letters that are page artifacts.\n"
                "3. Fix hyphenation splits (word- + continuation).\n"
                "Do NOT translate, add, or remove actual content. "
                "Return one paragraph per line. Return ONLY the cleaned text."
            ),
        },
        {
            "role": "user",
            "content": f"PDF text:\n{texto}\n\nCleaned:",
        },
    ]

    with _lock:
        out = _llm.create_chat_completion(
            messages,
            max_tokens=min(len(texto.split()) * 2, 800),
            temperature=0.05,
            stop=["PDF text:", "\n\n\n"],
        )

    result = out["choices"][0]["message"]["content"].strip()
    # Rechazar si Qwen eliminó más del 30 % del contenido (posible alucinación)
    if not result or len(result) < len(texto) * 0.7:
        return bloques

    return [l for l in result.split("\n") if l.strip()]


def revisar(original: str, traduccion: str, par: str, contexto: str = "") -> str:
    if _llm is None:
        return traduccion

    # Frases muy cortas no mejoran con Qwen
    if len(original.split()) < 5:
        return traduccion

    lang_dest = par.split("-")[1] if "-" in par else par

    # Short-circuit para idiomas donde Qwen no es fiable:
    # árabe, chino, ruso, japonés, coreano → saltar la llamada completamente.
    if lang_dest not in _IDIOMAS_CON_REVISION:
        return traduccion

    return _revisar_cached(original, traduccion, par)
