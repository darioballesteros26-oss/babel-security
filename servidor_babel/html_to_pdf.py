#!/usr/bin/env python3
"""
html_to_pdf.py — Renderiza HTML a PDF con PyMuPDF (API Story), SIN LibreOffice.
Uso: html_to_pdf.py <entrada.html> <salida.pdf>
Salida: exit 0 ok, exit 1 error (mensaje en stderr).

Se usa para convertir documentos DOCX a PDF dentro de la app: el lado Rust
convierte el DOCX a HTML (docx_a_html) y este script lo maqueta a PDF (A4 con
márgenes), paginando automáticamente. Fidelidad: texto, encabezados, listas,
negritas/cursivas, tablas y color — suficiente para documentos de texto.
"""
import sys

if len(sys.argv) < 3:
    sys.stderr.write("Uso: html_to_pdf.py <entrada.html> <salida.pdf>\n")
    sys.exit(1)

try:
    import pymupdf  # PyMuPDF >= 1.24 (nombre moderno)
except ImportError:
    try:
        import fitz as pymupdf  # nombre antiguo
    except ImportError:
        sys.stderr.write("PyMuPDF no instalado\n")
        sys.exit(1)

try:
    with open(sys.argv[1], encoding="utf-8") as f:
        html = f.read()
except Exception as e:
    sys.stderr.write(f"Error leyendo HTML: {e}\n")
    sys.exit(1)

try:
    MEDIA = pymupdf.paper_rect("A4")
    WHERE = MEDIA + (50, 50, -50, -50)  # márgenes ~1,8 cm
    story = pymupdf.Story(html=html)
    writer = pymupdf.DocumentWriter(sys.argv[2])
    more = 1
    while more:
        dev = writer.begin_page(MEDIA)
        more, _ = story.place(WHERE)
        story.draw(dev)
        writer.end_page()
    writer.close()
except Exception as e:
    sys.stderr.write(f"Error generando PDF: {e}\n")
    sys.exit(1)

sys.exit(0)
