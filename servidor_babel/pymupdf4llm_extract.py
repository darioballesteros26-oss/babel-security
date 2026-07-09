#!/usr/bin/env python3
"""
pymupdf4llm_extract.py — Primera pasada PDF: extrae Markdown estructurado.
Detecta encabezados, tablas, listas y multi-columna sin GPU.
Salida: Markdown utf-8 por stdout. Exit 1 si falla.
"""
import sys
import os

os.environ["TOKENIZERS_PARALLELISM"] = "false"

if len(sys.argv) < 2:
    sys.stderr.write("Uso: pymupdf4llm_extract.py <ruta_pdf>\n")
    sys.exit(1)

try:
    import pymupdf4llm

    md = pymupdf4llm.to_markdown(
        sys.argv[1],
        show_progress=False,
    )

    if not md or not md.strip():
        sys.stderr.write("pymupdf4llm: sin texto extraído\n")
        sys.exit(1)

    sys.stdout.buffer.write(md.encode("utf-8"))

except Exception as e:
    sys.stderr.write(f"pymupdf4llm error: {e}\n")
    sys.exit(1)
