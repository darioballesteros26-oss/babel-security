"""
traduccion_comun.py — utilidades compartidas por los motores de traducción
(traduccion_madlad.py y traduccion_small100.py). Solo lógica independiente del modelo;
la tokenización, que sí difiere (prefijo <2xx> de MADLAD vs tgt_lang en el source de
SMaLL-100), vive en cada módulo.
"""

_PUNTUACION_FINAL = frozenset('.!?:;…»"\'')


def normalizar(texto: str) -> tuple[str, bool]:
    """Añade un punto si el texto no termina en puntuación. Devuelve (texto_norm, se_añadió).
    Los modelos generan ruido de cola en fragmentos cortos ("Introducción" → "Introduction
    to the"); darles una frase 'cerrada' lo evita. El punto artificial se quita luego con
    quitar_punto_anadido()."""
    t = texto.rstrip()
    if t and t[-1] not in _PUNTUACION_FINAL:
        return t + '.', True
    return t, False


def preparar_batch(textos: list) -> tuple[list, list, list, list]:
    """Prepara un lote: filtra vacíos (los modelos devuelven basura para "") y normaliza.
    Devuelve (indices_validos, textos_norm, puntos_anadidos, resultado_base), donde
    resultado_base ya tiene la longitud correcta con "" en las posiciones vacías."""
    indices = [i for i, t in enumerate(textos) if t and t.strip()]
    resultado = [""] * len(textos)
    norm, puntos = [], []
    for i in indices:
        t, se = normalizar(textos[i])
        norm.append(t)
        puntos.append(se)
    return indices, norm, puntos, resultado


def quitar_punto_anadido(trad: str, se_anadio: bool) -> str:
    """Si normalizar() añadió un punto artificial, lo quita del resultado traducido."""
    if se_anadio and trad.endswith('.'):
        return trad[:-1]
    return trad
