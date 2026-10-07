#!/usr/bin/env python3
"""
regenerar_embeddings.py — Recalcula ~/Babel/biblioteca_juridica/embeddings.bin a partir
de index.json, replicando EXACTAMENTE la lógica de Rust (ia_biblioteca::doc_text +
ia_embeddings): prefijo de documento, recorte a 900 chars, L2-normalización y formato
binario [u32 LE dim][f32 LE × dim × n].

Requiere el embedder EmbeddingGemma escuchando en 127.0.0.1:8766 (/v1/embeddings).
Imprescindible tras añadir/quitar fragmentos, o el RAG denso cae a BM25 (count mismatch).
"""
import json, os, struct, sys, time, urllib.request

INDEX = os.path.expanduser("~/Babel/biblioteca_juridica/index.json")
OUT   = os.path.expanduser("~/Babel/biblioteca_juridica/embeddings.bin")
VERSION = os.path.expanduser("~/Babel/biblioteca_juridica/version.txt")
URL   = "http://127.0.0.1:8766/v1/embeddings"
PREFIJO_DOC = "title: none | text: "
CHUNK = 16

def doc_text(f):
    # Equivale a ia_biblioteca::doc_text: "{texto} {articulo abrev titulo}", primeros 900 chars.
    extra = [s for s in (f.get("articulo") or "", f.get("abrev") or "", f.get("titulo") or "") if s]
    full = f"{f.get('texto','')} {' '.join(extra)}"
    return full[:900]

def embed(textos):
    body = json.dumps({"input": textos}).encode("utf-8")
    req = urllib.request.Request(URL, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        data = json.load(r)["data"]
    out = []
    for row in data:
        v = row["embedding"]
        norm = sum(x * x for x in v) ** 0.5
        out.append([x / norm for x in v] if norm > 0 else v)
    return out

def esperar_embedder():
    for _ in range(80):
        try:
            embed(["ping"]); return True
        except Exception:
            time.sleep(0.5)
    return False

def main():
    if not esperar_embedder():
        sys.stderr.write("El embedder no responde en 127.0.0.1:8766\n"); sys.exit(1)
    frags = json.load(open(INDEX, encoding="utf-8"))["fragmentos"]
    n = len(frags)
    print(f"Fragmentos: {n}. Calculando embeddings…")
    all_vecs = []
    for i in range(0, n, CHUNK):
        chunk = [PREFIJO_DOC + doc_text(f) for f in frags[i:i + CHUNK]]
        all_vecs.extend(embed(chunk))
        if (i // CHUNK) % 20 == 0:
            print(f"  {min(i + CHUNK, n)}/{n}")
    dim = len(all_vecs[0])
    if any(len(v) != dim for v in all_vecs):
        sys.stderr.write("Dimensiones inconsistentes\n"); sys.exit(1)
    with open(OUT, "wb") as fo:
        fo.write(struct.pack("<I", dim))
        for v in all_vecs:
            fo.write(struct.pack(f"<{dim}f", *v))
    # version.txt = nº de fragmentos. Es la «versión» de la biblioteca (solo crece): la app
    # la usa para actualizar la biblioteca de usuarios EXISTENTES cuando el DMG trae más.
    with open(VERSION, "w") as fv:
        fv.write(str(n))
    print(f"OK: {len(all_vecs)} vectores dim {dim} → {OUT} ({os.path.getsize(OUT)} bytes); version.txt={n}")

if __name__ == "__main__":
    main()
