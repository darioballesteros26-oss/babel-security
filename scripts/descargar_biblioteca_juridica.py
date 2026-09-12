#!/usr/bin/env python3
"""
Babel — Descargador de Biblioteca Jurídica (Derecho Penal)
Fuente: BOE textos consolidados — dominio público (art. 13 LPI)
Uso: python3 descargar_biblioteca_juridica.py
"""

import urllib.request
import re
import json
import os
import time
import html

BIBLIOTECA_DIR = os.path.expanduser("~/Babel/biblioteca_juridica")
USER_AGENT = "BabelApp/1.0 biblioteca-juridica-local (uso educativo)"

LEYES = [
    {
        "nombre": "Constitución Española",
        "abrev": "CE",
        "boe_id": "BOE-A-1978-31229",
        "area": "constitucional",
    },
    {
        "nombre": "Código Penal",
        "abrev": "CP",
        "boe_id": "BOE-A-1995-25444",
        "area": "penal",
    },
    {
        "nombre": "Ley de Enjuiciamiento Criminal",
        "abrev": "LECrim",
        "boe_id": "BOE-A-1882-6036",
        "area": "procesal_penal",
    },
    {
        "nombre": "Ley Orgánica del Poder Judicial",
        "abrev": "LOPJ",
        "boe_id": "BOE-A-1985-12666",
        "area": "organica",
    },
    {
        "nombre": "Ley Orgánica General Penitenciaria",
        "abrev": "LOGP",
        "boe_id": "BOE-A-1979-23708",
        "area": "penal",
    },
    {
        "nombre": "Ley Orgánica Responsabilidad Penal Menores",
        "abrev": "LORPM",
        "boe_id": "BOE-A-2000-641",
        "area": "penal",
    },
    {
        "nombre": "Ley Orgánica Violencia de Género",
        "abrev": "LOVG",
        "boe_id": "BOE-A-2004-21760",
        "area": "penal",
    },
]


def limpiar(texto):
    """Elimina etiquetas HTML, decodifica entidades, normaliza espacios."""
    texto = re.sub(r'<[^>]+>', '', texto)
    texto = html.unescape(texto)
    return ' '.join(texto.split())


def fetch_html(boe_id):
    url = f"https://www.boe.es/buscar/act.php?id={boe_id}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=90) as r:
        return r.read().decode("utf-8", errors="replace"), url


def extraer_fecha(html_text):
    m = re.search(r'publicada el (\d{2}/\d{2}/\d{4})', html_text)
    return m.group(1) if m else "desconocida"


def parsear_ley(html_text, nombre, abrev, boe_id, url):
    """
    Extrae artículos del HTML consolidado del BOE.
    Estructura: h4 (secciones) > h5.articulo (cabecera artículo) > p.parrafo (texto)
    """
    # Eventos en orden de posición: secciones, artículos, párrafos
    eventos = []

    for m in re.finditer(r'<h4\s+class="([^"]*)"[^>]*>(.*?)</h4>', html_text, re.S):
        cls, contenido = m.group(1), limpiar(m.group(2))
        if contenido:
            eventos.append((m.start(), 'seccion', cls, contenido))

    for m in re.finditer(r'<h5\s+class="articulo"[^>]*>(.*?)</h5>', html_text, re.S):
        contenido = limpiar(m.group(1))
        if contenido:
            eventos.append((m.start(), 'cabecera', contenido))

    for m in re.finditer(r'<p\s+class="parrafo"[^>]*>(.*?)</p>', html_text, re.S):
        contenido = limpiar(m.group(1))
        if contenido:
            eventos.append((m.start(), 'parrafo', contenido))

    eventos.sort(key=lambda x: x[0])

    fecha = extraer_fecha(html_text)
    fragmentos = []

    # Estado de sección actual
    sec = {"titulo": None, "capitulo_num": None, "capitulo_tit": None, "seccion": None}
    art_actual = None
    parrafos_actuales = []

    def guardar_articulo():
        if art_actual is None or not parrafos_actuales:
            return
        texto = ' '.join(parrafos_actuales).strip()
        if not texto:
            return

        # Extrae el número/identificador del artículo
        # Cubre: "Artículo 31 bis.", "Artículo 1º.", "Disposición final quinta.", etc.
        art_id = re.sub(r'^Art[íi]culo\s+', '', art_actual).rstrip('.').strip()
        # Normaliza "1º" → "1"
        art_id = re.sub(r'(\d+)[ºª°]', r'\1', art_id)

        capitulo = None
        if sec["capitulo_num"] or sec["capitulo_tit"]:
            partes = [p for p in [sec["capitulo_num"], sec["capitulo_tit"]] if p]
            capitulo = ' — '.join(partes)

        fragmentos.append({
            "ley": nombre,
            "abrev": abrev,
            "boe_id": boe_id,
            "articulo": art_id,
            "titulo": sec["titulo"],
            "capitulo": capitulo,
            "seccion": sec["seccion"],
            "texto": texto,
            "fuente_url": url,
            "fecha_consolidada": fecha,
        })

    for ev in eventos:
        tipo = ev[1]

        if tipo == 'seccion':
            cls, contenido = ev[2], ev[3]
            if 'titulo_num' in cls:
                sec["titulo"] = contenido
                sec["capitulo_num"] = None
                sec["capitulo_tit"] = None
                sec["seccion"] = None
            elif 'titulo_tit' in cls:
                # Combina num + tit si hay num
                if sec["titulo"] and not ' — ' in sec["titulo"]:
                    sec["titulo"] = sec["titulo"] + ' — ' + contenido
                else:
                    sec["titulo"] = contenido
            elif 'titulo' in cls:
                sec["titulo"] = contenido
                sec["capitulo_num"] = None
                sec["capitulo_tit"] = None
                sec["seccion"] = None
            elif 'capitulo_num' in cls:
                sec["capitulo_num"] = contenido
                sec["capitulo_tit"] = None
                sec["seccion"] = None
            elif 'capitulo_tit' in cls:
                sec["capitulo_tit"] = contenido
                sec["seccion"] = None
            elif 'capitulo' in cls:
                sec["capitulo_num"] = contenido
                sec["capitulo_tit"] = None
                sec["seccion"] = None
            elif 'seccion' in cls:
                sec["seccion"] = contenido

        elif tipo == 'cabecera':
            guardar_articulo()
            art_actual = ev[2]
            parrafos_actuales = []

        elif tipo == 'parrafo':
            if art_actual is not None:
                parrafos_actuales.append(ev[2])

    guardar_articulo()
    return fragmentos


def main():
    os.makedirs(BIBLIOTECA_DIR, exist_ok=True)
    print(f"Directorio: {BIBLIOTECA_DIR}\n")

    todos = []
    resumen = []

    for ley in LEYES:
        print(f"→ {ley['nombre']} ({ley['boe_id']})...", end=' ', flush=True)
        try:
            html_text, url = fetch_html(ley['boe_id'])
            frags = parsear_ley(html_text, ley['nombre'], ley['abrev'], ley['boe_id'], url)
            fecha = extraer_fecha(html_text)
            print(f"✓ {len(frags)} fragmentos (consolidado {fecha})")

            # Archivo individual por ley
            fpath = os.path.join(BIBLIOTECA_DIR, f"{ley['abrev'].lower()}.json")
            with open(fpath, 'w', encoding='utf-8') as f:
                json.dump(frags, f, ensure_ascii=False, indent=2)

            todos.extend(frags)
            resumen.append({
                "nombre": ley['nombre'],
                "abrev": ley['abrev'],
                "boe_id": ley['boe_id'],
                "area": ley['area'],
                "fragmentos": len(frags),
                "fecha_consolidada": fecha,
                "fuente_url": url,
                "archivo": f"{ley['abrev'].lower()}.json",
            })
            time.sleep(2)  # Pausa cortesía entre peticiones

        except Exception as e:
            print(f"✗ Error: {e}")
            resumen.append({
                "nombre": ley['nombre'],
                "abrev": ley['abrev'],
                "boe_id": ley['boe_id'],
                "error": str(e),
            })

    # Index maestro: metadatos + todos los fragmentos
    index = {
        "version": "1.0",
        "generado": "2026-09-12",
        "descripcion": "Biblioteca jurídica Derecho Penal — Babel Security",
        "copyright": "Dominio público — art. 13 Ley de Propiedad Intelectual española",
        "total_fragmentos": len(todos),
        "fuentes": resumen,
        "fragmentos": todos,
    }
    index_path = os.path.join(BIBLIOTECA_DIR, "index.json")
    with open(index_path, 'w', encoding='utf-8') as f:
        json.dump(index, f, ensure_ascii=False, indent=2)

    # Resumen final
    print(f"\n{'='*60}")
    print(f"✅ Biblioteca creada: {len(todos)} fragmentos totales")
    print(f"   Ruta: {BIBLIOTECA_DIR}")
    print(f"\nFuentes:")
    for s in resumen:
        if 'error' in s:
            print(f"  ✗ {s['nombre']}: {s['error']}")
        else:
            print(f"  ✓ {s['nombre']}: {s['fragmentos']} fragmentos")

    # Ejemplo de fragmento
    if todos:
        print(f"\nEjemplo — primer fragmento del Código Penal:")
        cp_frags = [f for f in todos if f['abrev'] == 'CP']
        if cp_frags:
            ej = cp_frags[0]
            print(json.dumps(ej, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
