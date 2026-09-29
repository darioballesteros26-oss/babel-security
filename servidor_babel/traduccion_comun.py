"""
traduccion_comun.py — utilidades compartidas por los motores de traducción
(traduccion_madlad.py y traduccion_small100.py). Solo lógica independiente del modelo;
la tokenización, que sí difiere (prefijo <2xx> de MADLAD vs tgt_lang en el source de
SMaLL-100), vive en cada módulo.
"""

import os

_PUNTUACION_FINAL = frozenset('.!?:;…»"\'')


def hilos_intra() -> int:
    """Núcleos que CTranslate2 usa por traducción (intra_threads).
    Antes era 4 fijo: 0 (todos) provocaba contención de memoria y cuelgues con lotes
    grandes en máquinas con poca RAM. Mantenemos ese suelo de 4 y no bajamos de ahí,
    pero en máquinas con más núcleos subimos moderadamente dejando 2 libres, con tope
    de 8 para no reintroducir la contención en equipos grandes."""
    n = os.cpu_count() or 4
    return min(8, max(4, n - 2))


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
