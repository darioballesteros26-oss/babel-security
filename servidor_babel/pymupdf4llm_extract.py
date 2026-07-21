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

import re as _re

# Patrones de cabecera/pie de página corregibles: líneas cortas con referencia de página.
# Estas líneas son artefactos de extracción — no forman parte del contenido del documento.
_PATRON_CABECERA = _re.compile(
    r'^(página|page|pág\.?|pagina)\s+\w+$'      # Página Uno, Page 1, Pág. 5
    r'|^\d+\s+de\s+\d+$'                          # 1 de 50
    r'|^-\s*\d+\s*-$'                             # - 1 -
    r'|^\[\s*\d+\s*\]$',                          # [1]
    _re.IGNORECASE
)


def _filtrar_cabeceras(texto: str) -> str:
    """Elimina líneas que son cabeceras/pies correntes del PDF (artefactos de extracción)."""
    lineas = texto.split('\n')
    resultado = []
    for linea in lineas:
        s = linea.strip()
        if s and len(s) < 50 and _PATRON_CABECERA.match(s):
            continue
        resultado.append(linea)
    # Colapsar secuencias de más de 2 líneas vacías consecutivas generadas al eliminar cabeceras
    out, prev_blank = [], 0
    for linea in resultado:
        if not linea.strip():
            prev_blank += 1
            if prev_blank <= 2:
                out.append(linea)
        else:
            prev_blank = 0
            out.append(linea)
    return '\n'.join(out)


try:
    import pymupdf4llm

    md = pymupdf4llm.to_markdown(
        sys.argv[1],
        show_progress=False,
    )

    if not md or not md.strip():
        sys.stderr.write("pymupdf4llm: sin texto extraído\n")
        sys.exit(1)

    md = _filtrar_cabeceras(md)

    sys.stdout.buffer.write(md.encode("utf-8"))

except Exception as e:
    sys.stderr.write(f"pymupdf4llm error: {e}\n")
    sys.exit(1)
