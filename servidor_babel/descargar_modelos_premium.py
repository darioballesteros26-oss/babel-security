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

# Todos tc-big, ~114 MB cada uno cuantizado a int8 (de 444 MB float32)
MODELOS = {
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

QWEN_REPO     = "Qwen/Qwen2.5-0.5B-Instruct-GGUF"
QWEN_FILENAME = "qwen2.5-0.5b-instruct-q4_k_m.gguf"
QWEN_DESTINO  = DIR_USB / "qwen.gguf"
# El GGUF del servidor de desarrollo — se copia en vez de re-descargar
QWEN_LOCAL    = DIR_BASE / "modelos" / "qwen-0.5b-q4.gguf"


def convertir_modelo(nombre_hf: str, par: str) -> bool:
    """Descarga (si no está en caché) y convierte un modelo a CTranslate2 int8."""
    dir_salida = DIR_MOD / par
    if dir_salida.exists() and any(dir_salida.iterdir()):
        print(f"  [ya existe] {par}")
        return True

    print(f"  [convirtiendo] {par} ← {nombre_hf}")
    dir_salida.mkdir(parents=True, exist_ok=True)
    try:
        import ctranslate2
        converter = ctranslate2.converters.OpusMTConverter(nombre_hf)
        converter.convert(str(dir_salida), quantization="int8", force=True)
        print(f"  [OK] {par} → {dir_salida}")
        return True
    except Exception as e:
        print(f"  [ERROR] {par}: {e}")
        shutil.rmtree(dir_salida, ignore_errors=True)
        return False


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
    # Reusar el GGUF del servidor de desarrollo si existe (evita re-descarga)
    if QWEN_LOCAL.exists():
        shutil.copy2(str(QWEN_LOCAL), str(QWEN_DESTINO))
        print(f"  [copiado] qwen.gguf desde servidor dev")
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


def verificar_prefijos():
    """Imprime los códigos de idioma que acepta cada modelo multilingüe.
    Ejecutar tras la descarga para confirmar que >>spa<< y >>rus<< son correctos."""
    from transformers import MarianTokenizer
    multilingues = {
        "en-es": ">>spa<<",
        "ar-es": ">>spa<<",
        "es-ru": ">>rus<<",
        "en-ru": ">>rus<<",
    }
    print("\n[Verificación de prefijos — modelos multilingüe]")
    for par, prefijo_esperado in multilingues.items():
        dir_tok = DIR_TOK / par
        if not dir_tok.exists():
            print(f"  {par}: tokenizer no descargado aún")
            continue
        tok = MarianTokenizer.from_pretrained(str(dir_tok))
        vocab = tok.get_vocab()
        codigos = sorted([k for k in vocab if k.startswith(">>") and k.endswith("<<")])
        ok = prefijo_esperado in codigos
        estado = "OK" if ok else "AVISO — prefijo puede ser incorrecto"
        print(f"  {par}: {codigos[:8]}  →  usando {prefijo_esperado}  [{estado}]")


if __name__ == "__main__":
    DIR_MOD.mkdir(parents=True, exist_ok=True)
    DIR_TOK.mkdir(parents=True, exist_ok=True)

    total = len(MODELOS)
    ok = 0

    print(f"\nModelos MarianMT tc-big — {total} pares, ~114 MB c/u cuantizado a int8:")
    for par, hf in MODELOS.items():
        if convertir_modelo(hf, par) and guardar_tokenizer(hf, par):
            ok += 1

    print(f"\n[{total+1}/{total+1}] Qwen-2.5-0.5B revisor:")
    qwen_ok = descargar_qwen()

    verificar_prefijos()

    print(f"\n{'='*50}")
    print(f"Modelos: {ok}/{total} OK  |  Qwen: {'OK' if qwen_ok else 'FALLO'}")
    print(f"Salida: {DIR_USB}")
    print("\nSiguiente paso: copiar modelos_usb/ al USB con preparar_usb.sh")
    if ok < total:
        print("AVISO: algunos modelos fallaron — revisar errores arriba")
        sys.exit(1)
