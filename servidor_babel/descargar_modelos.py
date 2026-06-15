#!/usr/bin/env python3
"""Setup one-shot: descarga y convierte modelos MarianMT + Qwen GGUF.
Ejecutar una sola vez antes de arrancar server.py.
"""

import os
import shutil
import sys

PARES = ["es-en", "en-es", "es-fr", "fr-es", "es-ar", "ar-es"]
DIR_BASE = os.path.dirname(os.path.abspath(__file__))
DIR_MODELOS = os.path.join(DIR_BASE, "modelos")


def convertir_marian():
    try:
        from ctranslate2.converters import OpusMTConverter
    except ImportError:
        print("ERROR: ctranslate2 no instalado.")
        print("  pip install ctranslate2")
        sys.exit(1)

    for par in PARES:
        nombre_hf = f"Helsinki-NLP/opus-mt-{par}"
        salida = os.path.join(DIR_MODELOS, f"ct2-{par}")
        if os.path.isdir(salida) and os.listdir(salida):
            print(f"  [OK ya existe] {par}")
            continue
        print(f"  [Descargando y convirtiendo] {nombre_hf} ...")
        converter = OpusMTConverter(nombre_hf)
        converter.convert(salida, quantization="int8", force=True)
        print(f"  [Listo] {par} → {salida}")


def descargar_qwen():
    ruta_destino = os.path.join(DIR_MODELOS, "qwen-0.5b-q4.gguf")
    if os.path.isfile(ruta_destino):
        print("  [OK ya existe] Qwen GGUF")
        return

    try:
        from huggingface_hub import hf_hub_download
    except ImportError:
        print("ERROR: huggingface_hub no instalado.")
        print("  pip install huggingface-hub")
        sys.exit(1)

    print("  [Descargando] Qwen2.5-0.5B-Instruct GGUF ...")
    descargado = hf_hub_download(
        repo_id="Qwen/Qwen2.5-0.5B-Instruct-GGUF",
        filename="qwen2.5-0.5b-instruct-q4_k_m.gguf",
        local_dir=DIR_MODELOS,
    )
    shutil.move(descargado, ruta_destino)
    print(f"  [Listo] Qwen → {ruta_destino}")


if __name__ == "__main__":
    os.makedirs(DIR_MODELOS, exist_ok=True)

    print("\n[1/2] Modelos MarianMT (Bergamot/Helsinki-NLP):")
    convertir_marian()

    print("\n[2/2] Qwen-2.5-0.5B revisor:")
    descargar_qwen()

    print("\n✓ Setup completo. Arranca el servidor con:")
    print(f"  cd {DIR_BASE} && python server.py")
