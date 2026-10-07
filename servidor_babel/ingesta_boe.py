#!/usr/bin/env python3
"""
ingesta_boe.py — Descarga leyes CONSOLIDADAS del BOE (fuente oficial) y las añade a
la biblioteca jurídica local (RAG) en el mismo formato que el resto de fragmentos.

Por qué así: es la ÚNICA forma FIABLE de ampliar con leyes reales a gran escala —
el texto viene literal del BOE, no inventado. La API de datos abiertos del BOE sirve
cada ley consolidada como un XML de «bloques» (preceptos = artículos, encabezados =
títulos/capítulos/secciones). Tomamos la ÚLTIMA versión de cada precepto (el texto
vigente) y creamos un fragmento por artículo.

Idempotente (no duplica por abrev+articulo) y con copia de seguridad.
Uso:  python3 ingesta_boe.py
"""
import json
import os
import re
import shutil
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from datetime import date

INDEX = os.path.expanduser("~/Babel/biblioteca_juridica/index.json")

# (abrev de cita, id BOE, nombre de la ley)  — grandes códigos civil/laboral/administrativo
# Si algún id del BOE no responde, el script lo salta solo (no corrompe el índice).
LEYES = [
    ("CC",    "BOE-A-1889-4763",  "Código Civil"),
    ("LEC",   "BOE-A-2000-323",   "Ley 1/2000 de Enjuiciamiento Civil"),
    ("ET",    "BOE-A-2015-11430", "Estatuto de los Trabajadores (RDL 2/2015)"),
    ("LRJS",  "BOE-A-2011-15936", "Ley 36/2011 Reguladora de la Jurisdicción Social"),
    ("LPAC",  "BOE-A-2015-10565", "Ley 39/2015 del Procedimiento Administrativo Común"),
    ("LRJSP", "BOE-A-2015-10566", "Ley 40/2015 de Régimen Jurídico del Sector Público"),
    ("LAU",   "BOE-A-1994-26003", "Ley 29/1994 de Arrendamientos Urbanos"),
    # ── Ampliación 2026-10-07: grandes leyes que faltaban ──
    ("LJCA",  "BOE-A-1998-16718", "Ley 29/1998 de la Jurisdicción Contencioso-administrativa"),
    ("LGT",   "BOE-A-2003-23186", "Ley 58/2003 General Tributaria"),
    ("LPH",   "BOE-A-1960-10906", "Ley 49/1960 sobre Propiedad Horizontal"),
    ("LSC",   "BOE-A-2010-10544", "RDL 1/2010 Ley de Sociedades de Capital"),
    ("LGSS",  "BOE-A-2015-11724", "RDL 8/2015 Ley General de la Seguridad Social"),
    ("LOPDGDD","BOE-A-2018-16673","LO 3/2018 de Protección de Datos y garantía de derechos digitales"),
    ("TRLGDCU","BOE-A-2007-20555","RDL 1/2007 Ley General para la Defensa de Consumidores y Usuarios"),
    ("TRLC",  "BOE-A-2020-4859",  "RDL 1/2020 Texto Refundido de la Ley Concursal"),
    ("CCom",  "BOE-A-1885-6627",  "Código de Comercio"),
    ("LH",    "BOE-A-1946-2453",  "Ley Hipotecaria"),
    ("LJV",   "BOE-A-2015-7391",  "Ley 15/2015 de la Jurisdicción Voluntaria"),
    ("LRC",   "BOE-A-2011-12628", "Ley 20/2011 del Registro Civil"),
]

API = "https://www.boe.es/datosabiertos/api/legislacion-consolidada/id/{id}/texto"
MAX_TEXTO = 4000  # el visor solo muestra ~800; capamos para no inflar el índice


def descargar_xml(boe_id):
    url = API.format(id=boe_id)
    req = urllib.request.Request(url, headers={"Accept": "application/xml"})
    for intento in range(3):
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                return r.read().decode("utf-8")
        except Exception as e:  # noqa: BLE001
            print(f"   reintento {intento+1} ({boe_id}): {e}", file=sys.stderr)
            time.sleep(2)
    return None


def texto_de_version(version):
    """Une el texto de los <p> de una <version>, en orden, limpio."""
    partes = []
    for p in version.findall("p"):
        txt = "".join(p.itertext()).strip()
        if txt:
            partes.append(txt)
    return "\n".join(partes)


def parsear_ley(abrev, boe_id, ley, xml_txt):
    root = ET.fromstring(xml_txt)
    texto = root.find("./data/texto")
    if texto is None:
        return []

    fuente = f"https://www.boe.es/buscar/act.php?id={boe_id}"
    hoy = date.today().isoformat()
    libro = titulo_ctx = capitulo = seccion = None
    frags = []

    for bloque in texto.findall("bloque"):
        tipo = bloque.get("tipo")
        versions = bloque.findall("version")
        if not versions:
            continue
        ultima = versions[-1]  # versión vigente

        if tipo == "encabezado":
            # Clasificar por las clases de <p> (libro_/titulo_/capitulo_/seccion_)
            num = tit = None
            nivel = None
            for p in ultima.findall("p"):
                cls = p.get("class") or ""
                val = "".join(p.itertext()).strip()
                if cls.endswith("_num"):
                    num = val
                    nivel = cls[:-4]
                elif cls.endswith("_tit"):
                    tit = val
            etiqueta = " — ".join(x for x in (num, tit) if x)
            if nivel == "libro":
                libro, titulo_ctx, capitulo, seccion = etiqueta, None, None, None
            elif nivel == "titulo":
                titulo_ctx, capitulo, seccion = etiqueta, None, None
            elif nivel == "capitulo":
                capitulo, seccion = etiqueta, None
            elif nivel == "seccion":
                seccion = etiqueta
            continue

        if tipo != "precepto":
            continue

        # Normalizar el número de artículo. El BOE usa indistintamente «Art 1»,
        # «Artículo 1» o «Artículo\xa01» (espacio duro). Queremos solo «1» / «1 bis»
        # para que la cita y el boost funcionen. Las disposiciones («Disposición
        # adicional primera») se quedan con su nombre completo.
        titulo_bloque = (bloque.get("titulo") or "").replace("\xa0", " ").strip()
        m = re.match(r"^Art(?:\.|ículo)?\s+(.+)$", titulo_bloque, re.IGNORECASE)
        articulo = m.group(1).strip() if m else titulo_bloque
        if not articulo:
            continue

        cuerpo = texto_de_version(ultima)
        if not cuerpo or len(cuerpo) < 10:
            continue
        if len(cuerpo) > MAX_TEXTO:
            corte = cuerpo.rfind(" ", 0, MAX_TEXTO)
            cuerpo = cuerpo[: corte if corte > 0 else MAX_TEXTO] + " […]"

        # titulo del fragmento = contexto más específico disponible
        contexto = capitulo or titulo_ctx or libro or ley
        frags.append({
            "ley": ley,
            "abrev": abrev,
            "boe_id": boe_id,
            "articulo": articulo,
            "titulo": contexto,
            "capitulo": capitulo,
            "seccion": seccion,
            "texto": cuerpo,
            "fuente_url": fuente,
            "fecha_consolidada": hoy,
        })
    return frags


def main():
    if not os.path.exists(INDEX):
        print(f"ERROR: no existe {INDEX}", file=sys.stderr)
        sys.exit(1)

    with open(INDEX, encoding="utf-8") as fh:
        data = json.load(fh)
    frags = data.get("fragmentos", [])
    existentes = {(f.get("abrev"), f.get("articulo")) for f in frags}

    total_nuevos = 0
    for abrev, boe_id, ley in LEYES:
        print(f"· {abrev} — {ley} ({boe_id})…", flush=True)
        xml_txt = descargar_xml(boe_id)
        if not xml_txt:
            print(f"   ⚠ no se pudo descargar {abrev}, se omite", file=sys.stderr)
            continue
        try:
            nuevos = parsear_ley(abrev, boe_id, ley, xml_txt)
        except Exception as e:  # noqa: BLE001
            print(f"   ⚠ error parseando {abrev}: {e}", file=sys.stderr)
            continue
        añadidos = 0
        for fr in nuevos:
            clave = (fr["abrev"], fr["articulo"])
            if clave in existentes:
                continue
            existentes.add(clave)
            frags.append(fr)
            añadidos += 1
        total_nuevos += añadidos
        print(f"   + {añadidos} artículos ({len(nuevos)} parseados)")

    if total_nuevos == 0:
        print("Sin cambios.")
        return

    data["fragmentos"] = frags
    data["total_fragmentos"] = len(frags)
    backup = INDEX + ".bak-" + time.strftime("%Y%m%d-%H%M%S")
    shutil.copy2(INDEX, backup)
    with open(INDEX, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    size_mb = os.path.getsize(INDEX) / 1e6
    print(f"\n+ {total_nuevos} artículos nuevos. Total fragmentos: {len(frags)}. "
          f"index.json: {size_mb:.1f} MB. Backup: {backup}")


if __name__ == "__main__":
    main()
