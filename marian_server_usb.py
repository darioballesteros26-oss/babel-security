"""
Servidor de traducción MarianMT para el USB de Babel (tier premium).
Reemplaza nllb_server_usb.py — usa CTranslate2 int8 + MarianTokenizer.
Sin PyTorch: solo ctranslate2 + transformers (tokenizer) + llama-cpp-python (Qwen).

Misma API HTTP que el servidor anterior:
  GET  /ping          → {"ok": true}              (sin token)
  POST /traducir      → {"traduccion": "..."}     (requiere X-Babel-Token)
    body: {"texto": "...", "par": "es-en", "contexto": "..."}

Estructura esperada (relativa a este archivo, dentro de Resources/servidor/):
  modelos/
    es-en/   ← CTranslate2 int8
    en-es/
    ...
  tokenizers/
    es-en/   ← MarianTokenizer (sentencepiece)
    ...
  qwen.gguf  ← Qwen GGUF revisor (opcional)
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import ctranslate2
from transformers import MarianTokenizer
import os
import re
import threading
from pathlib import Path

# ---------------------------------------------------------------------------
# Rutas relativas al USB
# ---------------------------------------------------------------------------
_SERVIDOR_DIR = Path(__file__).parent
DIR_MODELOS   = _SERVIDOR_DIR / "modelos"
DIR_TOKENIZERS = _SERVIDOR_DIR / "tokenizers"
RUTA_QWEN     = _SERVIDOR_DIR / "qwen.gguf"

os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
os.environ.setdefault("HF_DATASETS_OFFLINE", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

BABEL_TOKEN   = os.environ.get("BABEL_NLLB_TOKEN", "")
MAX_INPUT_CHARS = 10_000

# ---------------------------------------------------------------------------
# Pares soportados y prefijos de idioma destino para modelos multilingüe
# ---------------------------------------------------------------------------
# Los modelos de familia (cat_oci_spa, itc, zle) mapean múltiples idiomas.
# Para indicar el idioma destino concreto hay que añadir ">>código<<" al inicio
# del texto fuente. Códigos verificados en las tarjetas de modelo Helsinki-NLP.
_TARGET_PREFIX = {
    "en-es": ">>spa<<",   # en-cat_oci_spa → español
    "ar-es": ">>spa<<",   # ar-itc        → español
    "es-ru": ">>rus<<",   # es-zle        → ruso
    "en-ru": ">>rus<<",   # en-zle        → ruso
}

# Todos los pares soportados (tc-big + small fallback)
PARES_SOPORTADOS = {
    # tc-big
    "es-en", "en-es", "es-ar", "ar-es",
    "fr-en", "en-fr", "ar-en", "en-ar",
    "de-es", "es-ru", "ru-es", "en-ru", "ru-en",
    # small fallback
    "es-fr", "fr-es", "de-en", "en-de", "zh-en", "en-zh",
}

# ---------------------------------------------------------------------------
# Carga de modelos
# ---------------------------------------------------------------------------
_traductores: dict[str, ctranslate2.Translator] = {}
_tokenizers:  dict[str, MarianTokenizer]        = {}
_tok_lock = threading.Lock()

# Qwen revisor (opcional — se carga solo si el GGUF existe)
_llm = None
_LANG_NAMES = {
    "es": "Spanish", "en": "English", "fr": "French", "ar": "Arabic",
    "de": "German",  "ru": "Russian", "zh": "Chinese",
}


def cargar_modelos():
    device = "auto"  # CTranslate2 elige CPU (USB no garantiza GPU)
    pares_cargados = 0
    for par in sorted(PARES_SOPORTADOS):
        dir_mod = DIR_MODELOS / par
        dir_tok = DIR_TOKENIZERS / par
        if not dir_mod.exists():
            print(f"[MARIAN] AVISO: modelo {par} no encontrado en {dir_mod}")
            continue
        try:
            _traductores[par] = ctranslate2.Translator(
                str(dir_mod), device="cpu", inter_threads=2,
            )
            _tokenizers[par] = MarianTokenizer.from_pretrained(str(dir_tok))
            pares_cargados += 1
            print(f"[MARIAN] {par} listo")
        except Exception as e:
            print(f"[MARIAN] ERROR cargando {par}: {e}")

    print(f"[MARIAN] {pares_cargados}/{len(PARES_SOPORTADOS)} pares cargados")


def cargar_qwen():
    global _llm
    if not RUTA_QWEN.exists():
        print("[QWEN] GGUF no encontrado, revisor desactivado")
        return
    try:
        from llama_cpp import Llama
        _llm = Llama(
            model_path=str(RUTA_QWEN),
            n_ctx=2048, n_threads=4, n_gpu_layers=0,
            verbose=False,
        )
        print("[QWEN] Revisor listo")
    except Exception as e:
        print(f"[QWEN] No disponible: {e}")


# ---------------------------------------------------------------------------
# Traducción con MarianMT (CTranslate2)
# ---------------------------------------------------------------------------
def _preparar_texto(texto: str, par: str) -> str:
    """Normaliza all-caps y añade prefijo de idioma destino si el modelo lo necesita."""
    if texto == texto.upper() and sum(c.isalpha() for c in texto) >= 4:
        texto = texto.lower()
    prefijo = _TARGET_PREFIX.get(par, "")
    return f"{prefijo} {texto}".strip() if prefijo else texto


def _traducir_segmento(texto: str, par: str) -> str:
    """Traduce un único segmento de texto (≤380 chars)."""
    tok = _tokenizers[par]
    txt_prep = _preparar_texto(texto, par)
    with _tok_lock:
        ids    = tok.encode(txt_prep)
        tokens = tok.convert_ids_to_tokens(ids)

    max_len = min(max(len(tokens) * 3, 256), 1024)
    results = _traductores[par].translate_batch(
        [tokens],
        beam_size=4,
        max_decoding_length=max_len,
    )
    salida_tokens = results[0].hypotheses[0]

    with _tok_lock:
        return tok.decode(tok.convert_tokens_to_ids(salida_tokens), skip_special_tokens=True)


def _dividir_frases(texto: str, max_chars: int = 380) -> list[str]:
    """Divide texto en segmentos de ≤max_chars en límites de oración."""
    if len(texto) <= max_chars:
        return [texto]
    oraciones = re.split(r'(?<=[.!?؟])\s+', texto)
    chunks, actual = [], ""
    for o in oraciones:
        if not o:
            continue
        if not actual:
            actual = o
        elif len(actual) + 1 + len(o) <= max_chars:
            actual += " " + o
        else:
            chunks.append(actual)
            actual = o
    if actual:
        chunks.append(actual)
    return chunks or [texto]


def _verificar_calidad(original: str, resultado: str, par: str):
    """Lanza RuntimeError si el resultado parece basura (garble, repetición, truncado)."""
    if sum(c.isalpha() for c in resultado) < 4:
        raise RuntimeError("Sin suficientes letras")

    palabras = [re.sub(r'[^a-zA-Z]', '', p).lower() for p in resultado.split()]
    palabras = [p for p in palabras if p.isalpha() and len(p) > 3]
    if palabras and max(palabras.count(p) for p in set(palabras)) > 2:
        raise RuntimeError(f"Repetición en {par}")

    palabras_res = resultado.split()
    if len(palabras_res) >= 5:
        prefijos = [w[:2].lower() for w in palabras_res if sum(c.isalpha() for c in w) >= 2]
        if len(prefijos) >= 5:
            conteo = {}
            for p in prefijos:
                conteo[p] = conteo.get(p, 0) + 1
            if max(conteo.values()) / len(prefijos) >= 0.70:
                raise RuntimeError(f"Garble fonético en {par}")

        tokens_1char = sum(1 for w in palabras_res if len(w) == 1 and w.isalpha())
        if tokens_1char / len(palabras_res) > 0.25:
            raise RuntimeError(f"Garble tokenización en {par}")

    n_in = len(original.split())
    n_out = len(palabras_res)
    if 3 <= n_in <= 5 and n_out / n_in < 0.5:
        raise RuntimeError(f"Traducción truncada en {par}")


def traducir(texto: str, par: str) -> str:
    """Traduce texto completo, dividiéndolo en frases si es largo."""
    if par not in _traductores:
        raise ValueError(f"Par no disponible: {par}")

    frases = _dividir_frases(texto)
    partes = []
    for frase in frases:
        if not frase.strip():
            continue
        resultado = _traducir_segmento(frase, par)
        _verificar_calidad(frase, resultado, par)
        partes.append(resultado)
    return " ".join(partes)


# ---------------------------------------------------------------------------
# Revisor Qwen (opcional)
# ---------------------------------------------------------------------------
def revisar(original: str, traduccion: str, par: str, contexto: str = "") -> str:
    """Pasa la traducción por Qwen para corregir coherencia y estilo."""
    if _llm is None or len(original.split()) < 8:
        return traduccion
    lang_orig, lang_dest = par.split("-")
    nombre_orig = _LANG_NAMES.get(lang_orig, lang_orig)
    nombre_dest = _LANG_NAMES.get(lang_dest, lang_dest)
    ctx = contexto[-200:].strip() if contexto else ""
    messages = [
        {"role": "system", "content": (
            "You are a professional translator and proofreader. "
            "Your task is to improve a machine translation while keeping the meaning. "
            "Output ONLY the corrected translation, nothing else."
        )},
        {"role": "user", "content": (
            f"Source language: {nombre_orig}\n"
            f"Target language: {nombre_dest}\n"
            f"Context: {ctx or '(none)'}\n"
            f"Source: {original}\n"
            f"Translation: {traduccion}\n"
            f"Corrected translation:"
        )},
    ]
    try:
        respuesta = _llm.create_chat_completion(messages=messages, max_tokens=512, temperature=0.1)
        corregida = respuesta["choices"][0]["message"]["content"].strip()
        return corregida if corregida else traduccion
    except Exception:
        return traduccion


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)
CORS(app)


@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"ok": True, "motor": "marian"})


@app.route("/traducir", methods=["POST"])
def endpoint_traducir():
    if not BABEL_TOKEN or request.headers.get("X-Babel-Token") != BABEL_TOKEN:
        return jsonify({"error": "No autorizado"}), 401

    data   = request.json or {}
    texto  = data.get("texto", "").strip()
    par    = data.get("par", "").strip()
    ctx    = data.get("contexto", "")

    if not texto:
        return jsonify({"traduccion": ""})
    if par not in PARES_SOPORTADOS:
        return jsonify({"error": f"Par no soportado: {par}"}), 400
    if len(texto) > MAX_INPUT_CHARS:
        return jsonify({"error": f"Texto demasiado largo (máx {MAX_INPUT_CHARS} chars)"}), 400

    try:
        trad = traducir(texto, par)
        trad = revisar(texto, trad, par, ctx)
        return jsonify({"traduccion": trad})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except RuntimeError as e:
        # Garble detectado — Rust usará el diccionario como fallback
        return jsonify({"error": str(e)}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("[BABEL USB] Cargando modelos MarianMT...")
    cargar_modelos()
    print("[BABEL USB] Cargando revisor Qwen...")
    cargar_qwen()
    print("[BABEL USB] Servidor listo en :5002")
    app.run(host="127.0.0.1", port=5002, debug=False)
