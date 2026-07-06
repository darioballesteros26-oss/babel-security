from transformers import MarianMTModel, MarianTokenizer
import torch
import os
import re

# Pares directos principales
PARES = ["es-en", "en-es", "es-fr", "fr-es", "es-ar", "ar-es"]

# Auxiliares: modelos puente para cadenas de pivote
PARES_AUXILIARES = ["fr-en", "de-en", "en-de", "ru-en", "en-ru", "zh-en", "en-zh"]

# Pares que cargan en float32: float16 en MPS genera garbage en estos modelos
PARES_FLOAT32 = {"fr-es", "es-ar"}

# Cadenas de pivote — todos los pasos deben ser modelos directos en _modelos
CADENAS = {
    # Rescate fr-es cuando el directo falla
    "fr-es": ["fr-en", "en-es"],
    # Pares ES/FR/AR sin modelo directo
    "en-fr": ["en-es", "es-fr"],
    "en-ar": ["en-es", "es-ar"],
    "ar-en": ["ar-es", "es-en"],
    "fr-ar": ["fr-es", "es-ar"],
    "ar-fr": ["ar-es", "es-fr"],
    # Pares con DE (puente via EN)
    "es-de": ["es-en", "en-de"],
    "de-es": ["de-en", "en-es"],
    "fr-de": ["fr-en", "en-de"],
    "de-fr": ["de-en", "en-es", "es-fr"],
    "ar-de": ["ar-es", "es-en", "en-de"],
    "de-ar": ["de-en", "en-es", "es-ar"],
    # Pares con RU (puente via EN)
    "es-ru": ["es-en", "en-ru"],
    "ru-es": ["ru-en", "en-es"],
    "fr-ru": ["fr-en", "en-ru"],
    "ru-fr": ["ru-en", "en-es", "es-fr"],
    "ar-ru": ["ar-es", "es-en", "en-ru"],
    "ru-ar": ["ru-en", "en-es", "es-ar"],
    # Pares con ZH (puente via EN)
    "es-zh": ["es-en", "en-zh"],
    "zh-es": ["zh-en", "en-es"],
    "fr-zh": ["fr-en", "en-zh"],
    "zh-fr": ["zh-en", "en-es", "es-fr"],
    "ar-zh": ["ar-es", "es-en", "en-zh"],
    "zh-ar": ["zh-en", "en-es", "es-ar"],
    # Pares cruzados DE/RU/ZH
    "de-ru": ["de-en", "en-ru"],
    "ru-de": ["ru-en", "en-de"],
    "de-zh": ["de-en", "en-zh"],
    "zh-de": ["zh-en", "en-de"],
    "ru-zh": ["ru-en", "en-zh"],
    "zh-ru": ["zh-en", "en-ru"],
}

_modelos: dict = {}
_tokenizers: dict = {}
_device = "mps" if torch.backends.mps.is_available() else "cpu"

# Límite de caracteres por segmento enviado a MarianMT.
# El modelo tiene ventana de 512 tokens (~380 chars en español/inglés).
_MAX_CHARS_SEGMENTO = 380


def dividir_frases(texto: str) -> list:
    """Divide texto en frases de hasta _MAX_CHARS_SEGMENTO caracteres.
    Corta en límites de oración (., !, ?, ؟) para que cada segmento
    llegue completo a MarianMT y no se trunque en mitad de una frase."""
    if len(texto) <= _MAX_CHARS_SEGMENTO:
        return [texto]
    # Dividir en oraciones en límites de puntuación seguidos de espacio
    oraciones = re.split(r'(?<=[.!?؟])\s+', texto)
    chunks = []
    actual = ""
    for oracion in oraciones:
        if not oracion:
            continue
        if not actual:
            actual = oracion
        elif len(actual) + 1 + len(oracion) <= _MAX_CHARS_SEGMENTO:
            actual += " " + oracion
        else:
            chunks.append(actual)
            actual = oracion
    if actual:
        chunks.append(actual)
    return chunks if chunks else [texto]


def cargar_modelos():
    print(f"[MARIAN] Dispositivo: {_device}")
    todos = PARES + [p for p in PARES_AUXILIARES if p not in PARES]
    for par in todos:
        nombre_hf = f"Helsinki-NLP/opus-mt-{par}"
        usar_float16 = _device == "mps" and par not in PARES_FLOAT32
        precision = "float16" if usar_float16 else "float32"
        print(f"[MARIAN] Cargando {par} ({precision})...")
        try:
            tokenizer = MarianTokenizer.from_pretrained(nombre_hf)
            model = MarianMTModel.from_pretrained(nombre_hf)
            if usar_float16:
                model = model.half()
            model = model.to(_device)
            model.eval()
            _modelos[par] = model
            _tokenizers[par] = tokenizer
        except Exception as e:
            # Auxiliares son opcionales — solo afectan a la cadena de rescate
            print(f"[MARIAN] Aviso: no se pudo cargar {par}: {e}")
    print("[MARIAN] Modelos listos.")


def _traducir_directo(texto: str, par: str) -> str:
    """Traduce con el modelo indicado. Lanza RuntimeError si el resultado es basura."""
    if par not in _modelos:
        raise RuntimeError(f"Modelo {par} no disponible")

    tokenizer = _tokenizers[par]
    model = _modelos[par]

    inputs = tokenizer(
        [texto],
        return_tensors="pt",
        padding=True,
        truncation=True,
        max_length=512,
    ).to(_device)

    n_src = inputs["input_ids"].shape[1]
    with torch.no_grad():
        ids = model.generate(
            **inputs,
            num_beams=4,
            max_new_tokens=min(n_src * 3, 512),
            no_repeat_ngram_size=2,
            early_stopping=True,
        )

    resultado = tokenizer.decode(ids[0], skip_special_tokens=True)

    if sum(c.isalpha() for c in texto) < 4:
        raise RuntimeError("Sin suficientes letras")

    # Repetición: alguna palabra significativa (>3 chars) aparece más de 2 veces.
    # Strips punctuation first so "date," and "date" count as the same word.
    palabras = [re.sub(r'[^a-zA-Z]', '', p).lower() for p in resultado.split()]
    palabras = [p for p in palabras if p.isalpha() and len(p) > 3]
    if palabras and max(palabras.count(p) for p in set(palabras)) > 2:
        raise RuntimeError(f"Repetición en modelo {par}")

    # Garble fonético: mayoría de palabras con el mismo prefijo de 2 letras
    # Solo aplica en textos largos para evitar falsos positivos en frases cortas
    palabras_resultado = resultado.split()
    if len(palabras_resultado) >= 5:
        prefijos = [
            "".join(c for c in w.lower() if c.isalpha())[:2]
            for w in palabras_resultado
            if sum(c.isalpha() for c in w) >= 2
        ]
        if len(prefijos) >= 5:
            # Regla de mayoría: si >= 70% comparten el mismo prefijo es garble
            conteo_pref = {}
            for p in prefijos:
                conteo_pref[p] = conteo_pref.get(p, 0) + 1
            max_pref = max(conteo_pref.values())
            if max_pref / len(prefijos) >= 0.70:
                raise RuntimeError(f"Garble fonético en modelo {par}")

    # Garble de tokenización: demasiados tokens de 1 carácter alfabético en el output
    # (síntoma de ALL CAPS no normalizado o fallo del tokenizer)
    if len(palabras_resultado) >= 5:
        tokens_1char = sum(1 for w in palabras_resultado if len(w) == 1 and w.isalpha())
        if tokens_1char / len(palabras_resultado) > 0.25:
            raise RuntimeError(f"Garble de tokenización en modelo {par}")

    # Traducción truncada: para frases cortas (≤5 palabras), si el output tiene
    # menos de la mitad de palabras que el input, es probable que sea incompleto
    n_in = len(texto.split())
    n_out = len(palabras_resultado)
    if n_in <= 5 and n_in >= 3 and n_out / n_in < 0.5:
        raise RuntimeError(f"Traducción truncada en modelo {par}")

    return resultado


def _traducir_con_cadena(texto: str, par: str) -> str:
    """Traduce un segmento con el modelo directo o la cadena de rescate."""
    if par not in _modelos and par not in CADENAS:
        raise ValueError(f"Par no soportado: {par}")

    error_directo = None
    try:
        return _traducir_directo(texto, par)
    except RuntimeError as e:
        error_directo = e

    cadena = CADENAS.get(par)
    if not cadena:
        raise RuntimeError(str(error_directo))

    pasos_ok = all(paso in _modelos for paso in cadena)
    if not pasos_ok:
        raise RuntimeError(
            f"Modelo {par} degradado y cadena de rescate no disponible. "
            f"Ejecuta descargar_modelos.py para instalar los modelos auxiliares."
        )

    try:
        intermedio = texto
        for paso in cadena:
            intermedio = _traducir_directo(intermedio, paso)
        return intermedio
    except RuntimeError as e_cadena:
        raise RuntimeError(
            f"Traducción {par} no disponible "
            f"(directo: {error_directo}; cadena: {e_cadena})"
        )


def traducir(texto: str, par: str) -> str:
    """Traduce texto dividiéndolo en frases si es largo.
    Normaliza all-caps a title case antes de traducir para evitar
    garble de tokenización con modelos MarianMT."""
    # ALL CAPS → minúsculas (title case genera "De" etc. que confunden al tokenizador)
    era_mayusculas = (
        texto == texto.upper()
        and sum(c.isalpha() for c in texto) >= 4
    )
    texto_norm = texto.lower() if era_mayusculas else texto

    frases = dividir_frases(texto_norm)
    if len(frases) == 1:
        return _traducir_con_cadena(texto_norm, par)
    partes = []
    for frase in frases:
        if not frase.strip():
            continue
        partes.append(_traducir_con_cadena(frase, par))
    return " ".join(partes)
