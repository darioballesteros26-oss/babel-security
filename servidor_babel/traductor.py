from transformers import MarianMTModel, MarianTokenizer
import torch
import os

# Pares directos principales
PARES = ["es-en", "en-es", "es-fr", "fr-es", "es-ar", "ar-es"]

# Auxiliares para cadenas de rescate (solo fr-en es viable; en-ar está roto)
PARES_AUXILIARES = ["fr-en"]

# Pares que cargan en float32: float16 en MPS genera garbage en estos modelos
PARES_FLOAT32 = {"fr-es", "es-ar"}

# Cadenas de rescate: si el directo falla, se encadenan estos pasos en orden
# es-ar no tiene cadena (en-ar está roto, no hay alternativa viable)
CADENAS = {
    "fr-es": ["fr-en", "en-es"],
}

_modelos: dict = {}
_tokenizers: dict = {}
_device = "mps" if torch.backends.mps.is_available() else "cpu"


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
    # Excluimos palabras cortas (artículos, preposiciones) que repiten naturalmente.
    palabras = [p for p in resultado.lower().split() if p.isalpha() and len(p) > 3]
    if palabras and max(palabras.count(p) for p in set(palabras)) > 2:
        raise RuntimeError(f"Repetición en modelo {par}")

    # Garble fonético: 5+ palabras con el mismo prefijo de 2 letras
    # Solo aplica en textos largos para evitar falsos positivos en frases cortas
    palabras_resultado = resultado.split()
    if len(palabras_resultado) >= 5:
        prefijos = [
            "".join(c for c in w.lower() if c.isalpha())[:2]
            for w in palabras_resultado
            if sum(c.isalpha() for c in w) >= 2
        ]
        if len(prefijos) >= 5 and len(set(prefijos)) <= 1:
            raise RuntimeError(f"Garble fonético en modelo {par}")

    return resultado


def traducir(texto: str, par: str) -> str:
    """
    Traduce texto con el modelo directo.
    Si el par tiene cadena definida y el directo falla, intenta la cadena.
    Si todo falla, lanza RuntimeError para que Rust use el diccionario.
    """
    if par not in _modelos and par not in CADENAS:
        raise ValueError(f"Par no soportado: {par}")

    # Intentar modelo directo
    error_directo: Exception | None = None
    try:
        return _traducir_directo(texto, par)
    except RuntimeError as e:
        error_directo = e

    # Intentar cadena de rescate (solo si está definida)
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
