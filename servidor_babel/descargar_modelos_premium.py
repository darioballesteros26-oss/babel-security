#!/usr/bin/env python3
"""
Descarga y cuantiza (CTranslate2 int8) los modelos MarianMT tc-big + small fallback
para el tier premium del USB de Babel.

Requisitos (en babel_env, instalar una sola vez):
  pip install ctranslate2 transformers sentencepiece huggingface_hub

Uso:
  ~/Desktop/Babel/babel_env/bin/python3.9 descargar_modelos_premium.py

Salida:
  servidor_babel/modelos_usb/
    modelos/   ← CTranslate2 int8, un subdirectorio por par
    tokenizers/ ← MarianTokenizer, un subdirectorio por par
    qwen.gguf
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

DIR_BASE = Path(__file__).parent
DIR_USB  = DIR_BASE / "modelos_usb"
DIR_MOD  = DIR_USB / "modelos"
DIR_TOK  = DIR_USB / "tokenizers"

# --- Modelos tc-big (mayor calidad, ~114 MB cada uno cuantizado) ---
TC_BIG = {
    "es-en": "Helsinki-NLP/opus-mt-tc-big-cat_oci_spa-en",
    "en-es": "Helsinki-NLP/opus-mt-tc-big-en-cat_oci_spa",
    "es-ar": "Helsinki-NLP/opus-mt-tc-big-itc-ar",
    "ar-es": "Helsinki-NLP/opus-mt-tc-big-ar-itc",
    "fr-en": "Helsinki-NLP/opus-mt-tc-big-fr-en",
    "en-fr": "Helsinki-NLP/opus-mt-tc-big-en-fr",
    "ar-en": "Helsinki-NLP/opus-mt-tc-big-ar-en",
    "en-ar": "Helsinki-NLP/opus-mt-tc-big-en-ar",
    "de-es": "Helsinki-NLP/opus-mt-tc-big-de-es",
    "es-ru": "Helsinki-NLP/opus-mt-tc-big-es-zle",
    "ru-es": "Helsinki-NLP/opus-mt-tc-big-zle-es",
    "en-ru": "Helsinki-NLP/opus-mt-tc-big-en-zle",
    "ru-en": "Helsinki-NLP/opus-mt-tc-big-zle-en",
}

# --- Modelos small fallback (pares sin tc-big, ~77 MB cada uno) ---
SMALL = {
    "es-fr": "Helsinki-NLP/opus-mt-es-fr",
    "fr-es": "Helsinki-NLP/opus-mt-fr-es",
    "de-en": "Helsinki-NLP/opus-mt-de-en",
    "en-de": "Helsinki-NLP/opus-mt-en-de",
    "zh-en": "Helsinki-NLP/opus-mt-zh-en",
    "en-zh": "Helsinki-NLP/opus-mt-en-zh",
}

QWEN_REPO     = "Qwen/Qwen2.5-0.5B-Instruct-GGUF"
QWEN_FILENAME = "qwen2.5-0.5b-instruct-q4_k_m.gguf"
QWEN_DESTINO  = DIR_USB / "qwen.gguf"


def convertir_modelo(nombre_hf: str, par: str) -> bool:
    """Descarga y convierte un modelo a CTranslate2 int8. Devuelve True si OK."""
    dir_salida = DIR_MOD / par
    if dir_salida.exists() and any(dir_salida.iterdir()):
        print(f"  [ya existe] {par}")
        return True

    print(f"  [convirtiendo] {par} ← {nombre_hf}")
    dir_salida.mkdir(parents=True, exist_ok=True)

    # ct2-opus-mt-converter es el CLI oficial de CTranslate2 para modelos Helsinki-NLP
    cmd = [
        sys.executable, "-m", "ctranslate2.converters.opus_mt",
        "--model", nombre_hf,
        "--output_dir", str(dir_salida),
        "--quantization", "int8",
        "--force",
    ]
    # Intentar con el CLI si el módulo no funciona directamente
    cli = shutil.which("ct2-opus-mt-converter")
    if cli:
        cmd = [cli, "--model", nombre_hf, "--output_dir", str(dir_salida),
               "--quantization", "int8", "--force"]

    try:
        # Primero intentar con la API Python de ctranslate2
        import ctranslate2
        converter = ctranslate2.converters.OpusMTConverter(nombre_hf)
        converter.convert(str(dir_salida), quantization="int8", force=True)
        print(f"  [OK] {par} → {dir_salida}")
        return True
    except (ImportError, AttributeError):
        pass

    # Fallback: subprocess con CLI
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  [ERROR] {par}: {result.stderr[-300:]}")
        shutil.rmtree(dir_salida, ignore_errors=True)
        return False

    print(f"  [OK] {par} → {dir_salida}")
    return True


def guardar_tokenizer(nombre_hf: str, par: str) -> bool:
    """Guarda el tokenizer MarianMT para el par dado."""
    dir_salida = DIR_TOK / par
    if dir_salida.exists() and any(dir_salida.iterdir()):
        print(f"  [ya existe tokenizer] {par}")
        return True

    print(f"  [tokenizer] {par} ← {nombre_hf}")
    try:
        from transformers import MarianTokenizer
        tok = MarianTokenizer.from_pretrained(nombre_hf)
        tok.save_pretrained(str(dir_salida))
        print(f"  [OK tokenizer] {par}")
        return True
    except Exception as e:
        print(f"  [ERROR tokenizer] {par}: {e}")
        return False


def descargar_qwen() -> bool:
    if QWEN_DESTINO.exists():
        print("  [ya existe] qwen.gguf")
        return True
    try:
        from huggingface_hub import hf_hub_download
    except ImportError:
        print("  [ERROR] huggingface_hub no instalado. pip install huggingface_hub")
        return False

    print(f"  [descargando] Qwen GGUF (~350 MB)...")
    try:
        descargado = hf_hub_download(
            repo_id=QWEN_REPO,
            filename=QWEN_FILENAME,
            local_dir=str(DIR_USB),
        )
        shutil.move(descargado, str(QWEN_DESTINO))
        print(f"  [OK] qwen.gguf → {QWEN_DESTINO}")
        return True
    except Exception as e:
        print(f"  [ERROR] Qwen: {e}")
        return False


if __name__ == "__main__":
    DIR_MOD.mkdir(parents=True, exist_ok=True)
    DIR_TOK.mkdir(parents=True, exist_ok=True)

    todos = list(TC_BIG.items()) + list(SMALL.items())
    total = len(todos)
    ok = 0

    print(f"\n[1/{total+1}] Modelos MarianMT tc-big (13 pares, ~114 MB c/u cuantizado):")
    for par, hf in TC_BIG.items():
        if convertir_modelo(hf, par) and guardar_tokenizer(hf, par):
            ok += 1

    print(f"\n[2/{total+1}] Modelos MarianMT small fallback (6 pares, ~77 MB c/u):")
    for par, hf in SMALL.items():
        if convertir_modelo(hf, par) and guardar_tokenizer(hf, par):
            ok += 1

    print(f"\n[{total+1}/{total+1}] Qwen-2.5-0.5B revisor:")
    qwen_ok = descargar_qwen()

    print(f"\n{'='*50}")
    print(f"Modelos: {ok}/{total} OK  |  Qwen: {'OK' if qwen_ok else 'FALLO'}")
    print(f"Salida: {DIR_USB}")
    print("\nSiguiente paso: copiar modelos_usb/ al USB con preparar_usb.sh")
    if ok < total:
        print("AVISO: algunos modelos fallaron — revisar errores arriba")
        sys.exit(1)
