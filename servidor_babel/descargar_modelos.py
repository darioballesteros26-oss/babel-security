#!/usr/bin/env python3
"""Setup one-shot: pre-descarga modelos MarianMT + Qwen GGUF.
Ejecutar una sola vez antes de arrancar server.py.
"""

import os
import shutil
import sys

# Pares principales + auxiliares para cadenas de rescate fr→en→es y es→en→ar
PARES = [
    "es-en", "en-es", "es-fr", "fr-es", "es-ar", "ar-es",
    "fr-en",  # auxiliar para cadena fr→en→es si el directo fr-es falla
]
DIR_BASE = os.path.dirname(os.path.abspath(__file__))
DIR_MODELOS = os.path.join(DIR_BASE, "modelos")


def descargar_marian():
    try:
        from transformers import MarianMTModel, MarianTokenizer
    except ImportError:
        print("ERROR: transformers no instalado.")
        sys.exit(1)

    for par in PARES:
        nombre_hf = f"Helsinki-NLP/opus-mt-{par}"
        print(f"  [Descargando] {nombre_hf} ...")
        try:
            MarianTokenizer.from_pretrained(nombre_hf)
            MarianMTModel.from_pretrained(nombre_hf)
            print(f"  [Listo] {par}")
        except Exception as e:
            print(f"  [Error] {par}: {e}")


def descargar_qwen():
    ruta_destino = os.path.join(DIR_MODELOS, "qwen-1.5b-q4.gguf")
    if os.path.isfile(ruta_destino):
        print("  [OK ya existe] Qwen GGUF")
        return

    try:
        from huggingface_hub import hf_hub_download
    except ImportError:
        print("ERROR: huggingface_hub no instalado.")
        sys.exit(1)

    print("  [Descargando] Qwen2.5-1.5B-Instruct GGUF (~1 GB)...")
    descargado = hf_hub_download(
        repo_id="Qwen/Qwen2.5-1.5B-Instruct-GGUF",
        filename="qwen2.5-1.5b-instruct-q4_k_m.gguf",
        local_dir=DIR_MODELOS,
    )
    shutil.move(descargado, ruta_destino)
    print(f"  [Listo] Qwen → {ruta_destino}")


if __name__ == "__main__":
    os.makedirs(DIR_MODELOS, exist_ok=True)

    print("\n[1/2] Modelos MarianMT (Helsinki-NLP):")
    descargar_marian()

    print("\n[2/2] Qwen-2.5-0.5B revisor:")
    descargar_qwen()

    print("\n✓ Setup completo. Arranca el servidor con:")
    print(f"  cd {DIR_BASE} && python server.py")
