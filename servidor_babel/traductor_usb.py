"""
Traductor USB — MarianMT tc-big (Helsinki-NLP) cuantizados a int8 con CTranslate2.
Funcionan sin conexión, cargados desde modelos_usb/.

PARES DIRECTOS (un solo modelo tc-big):
  ar↔en, ar↔es, de→es, en↔ar, en↔es, en↔fr, en↔ru, es↔en, es→ru, fr↔en, ru↔en, ru↔es

PARES POR CADENA (dos pasos tc-big, calidad ligeramente menor):
  fr↔es (vía en), fr↔ar (vía en), de→en (vía es), de→ru (vía es→ru), ru→fr (vía en)
  es→ar usa cadena es→en→ar como rescate si el modelo itc-ar produce garble

CALIDAD GENERAL:
  - tc-big son los modelos más grandes de Helsinki-NLP para cada par: calidad profesional
    en documentos formales, legales y técnicos en los pares principales.
  - Pares directos ≈ 8.5/10. Cadenas de dos pasos ≈ 7.5/10 (acumula error).
  - Post-edición con Qwen 2.5 1.5B Q4_K_M mejora fluidez y corrige errores de concordancia.
  - Límite real: textos con ironía, modismos culturales o jerga muy especializada.

LIMITACIONES:
  - Ventana de 512 tokens (~380 caracteres/segmento) — textos más largos se fragmentan.
  - Modelos multilingüe (en-cat_oci_spa, itc-ar, zle) requieren prefijo de idioma destino;
    ya configurados en PREFIJOS.
"""

import os
import re
import threading

try:
    import ctranslate2
    from transformers import MarianTokenizer
    _CT2_DISPONIBLE = True
except ImportError:
    _CT2_DISPONIBLE = False

DIR_BASE = os.path.dirname(__file__)
# En producción (PyInstaller), BABEL_DIR_USB apunta al volumen del USB.
# En desarrollo, usa modelos_usb/ junto al script.
_usb_env = os.environ.get("BABEL_DIR_USB")
DIR_USB  = _usb_env if _usb_env else os.path.join(DIR_BASE, "modelos_usb")
DIR_MOD  = os.path.join(DIR_USB, "modelos")
DIR_TOK  = os.path.join(DIR_USB, "tokenizers")

# Pares con modelo tc-big directo en modelos_usb/modelos/
PARES_DIRECTOS = [
    "ar-en", "ar-es", "de-es",
    "en-ar", "en-es", "en-fr", "en-ru",
    # es-ar excluido: itc-ar genera garble bajo presión de memoria; usa la cadena es-en→en-ar
    "es-en", "es-ru",
    "fr-en", "ru-en", "ru-es",
]

# Modelos multilingüe que necesitan prefijo de idioma en la entrada
# para indicar el idioma destino (o fuente) deseado.
# Solo los confirmados por verificar_prefijos() en descargar_modelos_premium.py.
PREFIJOS = {
    "en-es": ">>spa<<",   # opus-mt-tc-big-en-cat_oci_spa → forzar español
    "ar-es": ">>spa<<",   # opus-mt-tc-big-ar-itc → forzar español
    "es-ru": ">>rus<<",   # opus-mt-tc-big-es-zle → forzar ruso
    "en-ru": ">>rus<<",   # opus-mt-tc-big-en-zle → forzar ruso
    "es-ar": ">>ara<<",   # opus-mt-tc-big-itc-ar → forzar árabe estándar (sin esto mezcla tokens)
    "en-ar": ">>ara<<",   # opus-mt-tc-big-en-ar → forzar árabe estándar
}

# Cadenas de rescate para pares sin modelo directo en modelos_usb/
# fr-es y es-fr usan dos pasos tc-big, cada uno mejor que el modelo small directo.
CADENAS = {
    "fr-es": ["fr-en", "en-es"],
    "es-fr": ["es-en", "en-fr"],
    "fr-ar": ["fr-en", "en-ar"],
    "ar-fr": ["ar-en", "en-fr"],
    "de-en": ["de-es", "es-en"],
    "de-ru": ["de-es", "es-ru"],
    "ru-fr": ["ru-en", "en-fr"],
    # Rescate árabe: si itc-ar genera garble con vocabulario romance, pivota por inglés
    "es-ar": ["es-en", "en-ar"],
}

_modelos: dict     = {}
_tokenizers: dict  = {}
_lock              = threading.Lock()
_MAX_CHARS_SEG     = 380


def disponible() -> bool:
    """True si los modelos USB están presentes y ctranslate2 instalado."""
    return (
        _CT2_DISPONIBLE
        and os.path.isdir(DIR_MOD)
        and any(True for _ in os.scandir(DIR_MOD))
    )


def cargar_modelos():
    if not _CT2_DISPONIBLE:
        print("[USB] ctranslate2 no disponible — ruta USB desactivada")
        return

    print(f"[USB] Cargando modelos tc-big desde {DIR_USB}")
    for par in PARES_DIRECTOS:
        dir_mod = os.path.join(DIR_MOD, par)
        dir_tok = os.path.join(DIR_TOK, par)
        if not os.path.isdir(dir_mod):
            continue
        try:
            modelo     = ctranslate2.Translator(dir_mod, device="cpu", inter_threads=2)
            tok_origen = dir_tok if os.path.isdir(dir_tok) else f"Helsinki-NLP/opus-mt-tc-big-{par}"
            tokenizer  = MarianTokenizer.from_pretrained(tok_origen)
            _modelos[par]    = modelo
            _tokenizers[par] = tokenizer
            print(f"[USB] OK {par}")
        except Exception as e:
            print(f"[USB] Error cargando {par}: {e}")

    print(f"[USB] {len(_modelos)} modelos listos")


def dividir_frases(texto: str) -> list:
    if len(texto) <= _MAX_CHARS_SEG:
        return [texto]
    oraciones = re.split(r'(?<=[.!?؟])\s+', texto)
    chunks, actual = [], ""
    for o in oraciones:
        if not o:
            continue
        if not actual:
            actual = o
        elif len(actual) + 1 + len(o) <= _MAX_CHARS_SEG:
            actual += " " + o
        else:
            chunks.append(actual)
            actual = o
    if actual:
        chunks.append(actual)
    return chunks if chunks else [texto]


def _traducir_directo(texto: str, par: str) -> str:
    if par not in _modelos:
        raise RuntimeError(f"Modelo USB {par} no disponible")

    translator = _modelos[par]
    tokenizer  = _tokenizers[par]

    prefijo     = PREFIJOS.get(par)
    texto_input = f"{prefijo} {texto}" if prefijo else texto

    input_ids  = tokenizer.encode(texto_input, truncation=True, max_length=512)
    src_tokens = [tokenizer.convert_ids_to_tokens(input_ids)]

    with _lock:
        results = translator.translate_batch(
            src_tokens,
            beam_size=4,
            no_repeat_ngram_size=2,
            max_decoding_length=min(len(input_ids) * 3, 512),
        )

    out_tokens = results[0].hypotheses[0]
    out_ids    = tokenizer.convert_tokens_to_ids(out_tokens)
    resultado  = tokenizer.decode(out_ids, skip_special_tokens=True)

    if sum(c.isalpha() for c in texto) < 4:
        raise RuntimeError("Sin suficientes letras")

    # Garble árabe: doble check para output que debería ser árabe
    if par.endswith("-ar"):
        _ar = re.compile(r'[؀-ۿ]')
        _lat = re.compile(r'[a-zA-Z]')
        toks = resultado.split()
        # 1) Token mixto (árabe y latín en una misma palabra)
        for tok in toks:
            if _ar.search(tok) and _lat.search(tok):
                raise RuntimeError(f"Garble árabe-latino en USB {par}: '{tok}'")
        # 2) Demasiadas palabras latinas puras en output que debería ser árabe
        puro_latin = [w for w in toks if _lat.search(w) and not _ar.search(w) and w.isalpha() and len(w) > 3]
        if len(toks) > 3 and len(puro_latin) / len(toks) > 0.15:
            raise RuntimeError(f"Garble árabe — {len(puro_latin)} palabras latinas en output: {puro_latin[:3]}")

    # Detección de repetición
    palabras = [re.sub(r'[^\w]', '', p).lower() for p in resultado.split()]
    palabras = [p for p in palabras if p.isalpha() and len(p) > 3]
    if palabras and max(palabras.count(p) for p in set(palabras)) > 2:
        raise RuntimeError(f"Repetición en USB {par}")

    # Detección de garble fonético
    palabras_r = resultado.split()
    if len(palabras_r) >= 5:
        prefijos_w = [
            "".join(c for c in w.lower() if c.isalpha())[:2]
            for w in palabras_r
            if sum(c.isalpha() for c in w) >= 2
        ]
        if len(prefijos_w) >= 5:
            conteo = {}
            for p in prefijos_w:
                conteo[p] = conteo.get(p, 0) + 1
            if conteo and max(conteo.values()) / len(prefijos_w) >= 0.70:
                raise RuntimeError(f"Garble en USB {par}")

    # Detección de truncado en frases cortas
    n_in, n_out = len(texto.split()), len(palabras_r)
    if 3 <= n_in <= 5 and n_out / n_in < 0.5:
        raise RuntimeError(f"Truncado en USB {par}")

    return resultado


def _traducir_con_cadena(texto: str, par: str) -> str:
    if par not in _modelos and par not in CADENAS:
        raise ValueError(f"Par no soportado en USB: {par}")

    try:
        return _traducir_directo(texto, par)
    except RuntimeError as e_dir:
        cadena = CADENAS.get(par)
        if not cadena:
            raise
        if not all(paso in _modelos for paso in cadena):
            raise RuntimeError(f"USB {par}: directo falló y cadena incompleta ({e_dir})")
        try:
            inter = texto
            for paso in cadena:
                inter = _traducir_directo(inter, paso)
            return inter
        except RuntimeError as e_cad:
            raise RuntimeError(f"USB {par}: directo={e_dir}; cadena={e_cad}")


def traducir(texto: str, par: str) -> str:
    era_mayusculas = texto == texto.upper() and sum(c.isalpha() for c in texto) >= 4
    texto_norm = texto.lower() if era_mayusculas else texto

    frases = dividir_frases(texto_norm)
    if len(frases) == 1:
        return _traducir_con_cadena(texto_norm, par)

    partes = []
    for frase in frases:
        if frase.strip():
            partes.append(_traducir_con_cadena(frase, par))
    return " ".join(partes)
