from transformers import MarianMTModel, MarianTokenizer
import torch
import os

PARES = ["es-en", "en-es", "es-fr", "fr-es", "es-ar", "ar-es"]

_modelos: dict = {}
_tokenizers: dict = {}
_device = "mps" if torch.backends.mps.is_available() else "cpu"


def cargar_modelos():
    print(f"[MARIAN] Dispositivo: {_device}")
    for par in PARES:
        nombre_hf = f"Helsinki-NLP/opus-mt-{par}"
        print(f"[MARIAN] Cargando {par}...")
        tokenizer = MarianTokenizer.from_pretrained(nombre_hf)
        model = MarianMTModel.from_pretrained(nombre_hf)
        if _device == "mps":
            model = model.half()  # float16 en Metal — mitad de RAM, misma calidad
        model = model.to(_device)
        model.eval()
        _modelos[par] = model
        _tokenizers[par] = tokenizer
    print("[MARIAN] Todos los modelos listos.")


def traducir(texto: str, par: str) -> str:
    if par not in _modelos:
        raise ValueError(f"Par no soportado: {par}")

    tokenizer = _tokenizers[par]
    model = _modelos[par]

    inputs = tokenizer(
        [texto],
        return_tensors="pt",
        padding=True,
        truncation=True,
        max_length=512,
    ).to(_device)

    with torch.no_grad():
        ids = model.generate(**inputs, num_beams=2, max_new_tokens=512)

    return tokenizer.decode(ids[0], skip_special_tokens=True)
