import os
import re
import threading
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

# Idiomas de escritura latina — aplicar guardias semánticas adicionales
_IDIOMAS_LATIN = {"es", "en", "fr", "de", "pt", "it"}

# Palabras que cambian la polaridad/sentido de una frase (por idioma destino).
# Si Qwen añade o elimina alguna, la revisión se rechaza.
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
    "de": "German", "ru": "Russian", "zh": "Chinese",
}

_llm = None
_lock = threading.Lock()


def cargar_modelo():
    global _llm
    print("[QWEN] Cargando revisor...")
    _llm = Llama(
        model_path=RUTA_GGUF,
        n_ctx=4096,
        n_gpu_layers=-1,  # offload todo a Metal en M3
        verbose=False,
    )
    print("[QWEN] Revisor listo.")


def revisar(original: str, traduccion: str, par: str, contexto: str = "") -> str:
    if _llm is None:
        return traduccion

    # Qwen 1.5B maneja bien frases a partir de 5 palabras
    if len(original.split()) < 5:
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
            max_tokens=min(len(traduccion.split()) * 3, 512),
            temperature=0.1,
            repeat_penalty=1.3,
            stop=["Source:", "Context:"],
        )

    revisada = out["choices"][0]["message"]["content"].strip()

    # Descartar si Qwen repite o alucina (más del doble de tokens que la traducción base)
    if not revisada or len(revisada) > len(traduccion) * 2:
        return traduccion

    # Validar script: si el idioma destino requiere un script no latino (árabe, ruso, chino)
    detector = _SCRIPT_DEST.get(lang_dest)
    if detector:
        # Rechazar si Qwen no produjo ni un solo carácter del script correcto
        if not detector.search(revisada):
            return traduccion
        # Para árabe: rechazar si Qwen introdujo tokens mixtos árabe-latino (re-garble)
        if lang_dest == "ar":
            for tok in revisada.split():
                if _RE_ARABE.search(tok) and _RE_LATIN.search(tok):
                    return traduccion

    # Para idiomas de escritura latina: guardias semánticas anti-alucinación
    if lang_dest in _IDIOMAS_LATIN:
        # Guardia 1 — polaridad: rechazar si Qwen añade o elimina palabras que invierten
        # el sentido ("contra", "no", "sin", "nunca"…). Un cambio en su recuento indica
        # que la revisión puede haber invertido o matizado el significado de forma errónea.
        pat_pol = _RE_POLAR.get(lang_dest)
        if pat_pol:
            if len(pat_pol.findall(traduccion)) != len(pat_pol.findall(revisada)):
                return traduccion

        # Guardia 2 — palabras de contenido añadidas: rechazar si Qwen introduce palabras
        # (≥5 letras) que no estaban ni en la traducción base ni en el texto original.
        # Esto previene alucinaciones del tipo "alegremente", "tristemente", etc.
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
