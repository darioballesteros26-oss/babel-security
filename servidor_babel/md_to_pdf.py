#!/usr/bin/env python3
"""
md_to_pdf.py — Convierte texto Markdown traducido a PDF con reportlab.
Uso: md_to_pdf.py <entrada.md> <salida.pdf>
Salida: exit 0 ok, exit 1 error (mensaje en stderr).
"""
import sys, re

if len(sys.argv) < 3:
    sys.stderr.write("Uso: md_to_pdf.py <entrada.md> <salida.pdf>\n")
    sys.exit(1)

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, HRFlowable,
        Table, TableStyle, Preformatted, ListFlowable, ListItem,
    )
except ImportError:
    sys.stderr.write("reportlab no instalado\n")
    sys.exit(1)

try:
    with open(sys.argv[1], encoding="utf-8") as f:
        md = f.read()
except Exception as e:
    sys.stderr.write(f"Error leyendo entrada: {e}\n")
    sys.exit(1)

# ── Estilos ──────────────────────────────────────────────────────────────────
base = getSampleStyleSheet()
S_NORMAL = ParagraphStyle("bn", parent=base["Normal"],
    fontSize=11, leading=17, spaceAfter=6)
S_H1 = ParagraphStyle("bh1", parent=base["Heading1"],
    fontSize=19, leading=23, spaceBefore=14, spaceAfter=8,
    textColor=colors.HexColor("#111111"))
S_H2 = ParagraphStyle("bh2", parent=base["Heading2"],
    fontSize=15, leading=19, spaceBefore=10, spaceAfter=6,
    textColor=colors.HexColor("#222222"))
S_H3 = ParagraphStyle("bh3", parent=base["Heading3"],
    fontSize=13, leading=17, spaceBefore=8, spaceAfter=4,
    textColor=colors.HexColor("#333333"))
S_CODE = ParagraphStyle("bcode", parent=base["Code"],
    fontSize=9, leading=13, fontName="Courier",
    leftIndent=10, backColor=colors.HexColor("#f4f4f4"))

# ── Inline formatting ────────────────────────────────────────────────────────
def inline(s):
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"\*(.+?)\*",     r"<i>\1</i>", s)
    s = re.sub(r"__(.+?)__",     r"<b>\1</b>", s)
    s = re.sub(r"_(.+?)_",       r"<i>\1</i>", s)
    return s

# ── Parser ───────────────────────────────────────────────────────────────────
story = []
para_buf  = []
list_buf  = []
table_buf = []   # list[list[str]]
code_buf  = []
in_code   = False

def flush_para():
    if para_buf:
        story.append(Paragraph(inline(" ".join(para_buf)), S_NORMAL))
        story.append(Spacer(1, 3))
        para_buf.clear()

def flush_list():
    if list_buf:
        story.append(ListFlowable(
            [ListItem(Paragraph(inline(item), S_NORMAL), leftIndent=12) for item in list_buf],
            bulletType="bullet", leftIndent=18
        ))
        story.append(Spacer(1, 4))
        list_buf.clear()

def flush_table():
    if table_buf:
        col_n = max(len(r) for r in table_buf)
        rows = [r + [""] * (col_n - len(r)) for r in table_buf]
        t = Table([[Paragraph(inline(c), S_NORMAL) for c in row] for row in rows],
                  hAlign="LEFT", repeatRows=1)
        t.setStyle(TableStyle([
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#aaaaaa")),
            ("BACKGROUND",    (0, 0), (-1,  0), colors.HexColor("#e8e8e8")),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("FONTSIZE",      (0, 0), (-1, -1), 10),
        ]))
        story.append(t)
        story.append(Spacer(1, 8))
        table_buf.clear()

for line in md.splitlines():
    s = line.strip()

    # ── Code fence ──────────────────────────────────────────────────────────
    if s.startswith("```"):
        if in_code:
            story.append(Preformatted("\n".join(code_buf), S_CODE))
            story.append(Spacer(1, 6))
            code_buf.clear()
            in_code = False
        else:
            flush_para(); flush_list(); flush_table()
            in_code = True
        continue
    if in_code:
        code_buf.append(line)
        continue

    # ── Empty line ──────────────────────────────────────────────────────────
    if not s:
        flush_para(); flush_list(); flush_table()
        continue

    # ── Horizontal rule ─────────────────────────────────────────────────────
    if len(s) >= 3 and all(c in "-=_" for c in s):
        flush_para(); flush_list(); flush_table()
        story.append(HRFlowable(width="100%", thickness=0.5,
                                color=colors.HexColor("#cccccc")))
        story.append(Spacer(1, 6))
        continue

    # ── Headings ────────────────────────────────────────────────────────────
    if s.startswith("### "):
        flush_para(); flush_list(); flush_table()
        story.append(Paragraph(inline(s[4:]), S_H3)); continue
    if s.startswith("## "):
        flush_para(); flush_list(); flush_table()
        story.append(Paragraph(inline(s[3:]), S_H2)); continue
    if s.startswith("# "):
        flush_para(); flush_list(); flush_table()
        story.append(Paragraph(inline(s[2:]), S_H1)); continue

    # ── Table ────────────────────────────────────────────────────────────────
    if s.startswith("|") and s.endswith("|"):
        flush_para(); flush_list()
        cells = [c.strip() for c in s[1:-1].split("|")]
        # Skip separator rows like | --- | :---: |
        if all(re.fullmatch(r"[:\-\s]+", c) for c in cells if c):
            continue
        table_buf.append(cells)
        continue
    if table_buf:
        flush_table()

    # ── Unordered list ──────────────────────────────────────────────────────
    if s.startswith("- ") or s.startswith("* "):
        flush_para()
        list_buf.append(s[2:]); continue

    # ── Ordered list ────────────────────────────────────────────────────────
    m = re.match(r"^\d+\.\s+(.*)", s)
    if m:
        flush_para()
        list_buf.append(m.group(1)); continue

    if list_buf:
        flush_list()

    # ── Regular paragraph ───────────────────────────────────────────────────
    para_buf.append(s)

# Flush tail
flush_para(); flush_list(); flush_table()
if code_buf:
    story.append(Preformatted("\n".join(code_buf), S_CODE))

# ── Build PDF ────────────────────────────────────────────────────────────────
try:
    doc = SimpleDocTemplate(
        sys.argv[2], pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2.5*cm, bottomMargin=2.5*cm,
    )
    doc.build(story)
    sys.exit(0)
except Exception as e:
    sys.stderr.write(f"Error construyendo PDF: {e}\n")
    sys.exit(1)
