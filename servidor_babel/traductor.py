import ctranslate2
from transformers import MarianTokenizer
import os

PARES = ["es-en", "en-es", "es-fr", "fr-es", "es-ar", "ar-es"]
DIR_MODELOS = os.path.join(os.path.dirname(__file__), "modelos")

_modelos: dict = {}
_tokenizers: dict = {}


def cargar_modelos():
    for par in PARES:
        ruta = os.path.join(DIR_MODELOS, f"ct2-{par}")
        nombre_hf = f"Helsinki-NLP/opus-mt-{par}"
        print(f"[MARIAN] Cargando {par}...")
        _modelos[par] = ctranslate2.Translator(ruta, device="cpu", inter_threads=2)
        _tokenizers[par] = MarianTokenizer.from_pretrained(nombre_hf)
    print("[MARIAN] Todos los modelos listos.")


def traducir(texto: str, par: str) -> str:
    if par not in _modelos:
        raise ValueError(f"Par no soportado: {par}")

    tokenizer = _tokenizers[par]
    translator = _modelos[par]

    ids = tokenizer.encode(texto, add_special_tokens=True)
    tokens = tokenizer.convert_ids_to_tokens(ids)

    max_len = min(max(len(tokens) * 2, 128), 512)

    results = translator.translate_batch(
        [tokens],
        max_decoding_length=max_len,
        beam_size=2,
    )

    output_tokens = results[0].hypotheses[0]
    return tokenizer.decode(
        tokenizer.convert_tokens_to_ids(output_tokens),
        skip_special_tokens=True,
    )
