"""
traduccion_small100.py — SMaLL-100 via CTranslate2 int8 (licencia MIT, comercial).
Modelo distilado de M2M-100 (~330M params, model.bin int8 ≈ 320 MB, ~0.6 GB RAM):
misma arquitectura M2M-100 pero mucho más ligero y rápido, con calidad competitiva.
Reemplaza al tier ligero (M2M-100 1.2B) en máquinas de poca RAM.

Tokenización SMaLL-100 (distinta a M2M-100): el idioma DESTINO se fija con
`tokenizer.tgt_lang`, lo que hace que el token de idioma (`__en__`, `__es__`, ...) se
añada como PREFIJO DEL SOURCE (no del target). Por tanto NO se pasa `target_prefix` al
decoder y la salida se decodifica ENTERA (sin descartar el primer token). El tokenizer
es una clase propia (`SMALL100Tokenizer`), que vive en `tokenization_small100.py` dentro
de la carpeta del modelo (no está en `transformers`).
"""
import os
import re
import sys
import threading

import traduccion_comun as comun

# La inferencia usa CTranslate2, NO torch/tensorflow. Evitar que transformers los importe
# (solo se usa el tokenizer, basado en sentencepiece) ahorra ~140 MB de RAM. torch ni
# siquiera está instalado en el USB.
os.environ.setdefault("USE_TORCH", "0")
os.environ.setdefault("USE_TF", "0")

DIR_BASE = os.path.dirname(__file__)
_usb_env = os.environ.get("BABEL_DIR_USB")
DIR_USB = _usb_env if _usb_env else os.path.join(DIR_BASE, "modelos_usb")
DIR_MODELO = os.path.join(DIR_USB, "small100-int8")

try:
    import ctranslate2
    # SMALL100Tokenizer es una clase propia del modelo (no está en transformers);
    # vive en tokenization_small100.py dentro de la carpeta del modelo.
    if DIR_MODELO not in sys.path:
        sys.path.insert(0, DIR_MODELO)
    from tokenization_small100 import SMALL100Tokenizer
    _CT2_OK = True
except ImportError:
    _CT2_OK = False

# SMaLL-100 es un modelo pequeño y rápido → se puede permitir el beam estándar de MT (4)
# para mejorar la calidad sin penalizar mucho la velocidad. greedy=1 (modo rápido) sigue
# disponible vía el parámetro beam.
BEAM = 4

_translator = None
_tokenizer = None
# RLock (reentrante): traducir() lo toma y dentro llama a cargar_modelo() —que también
# lo toma— para recargar el modelo si fue descargado por inactividad.
_lock = threading.RLock()


def disponible() -> bool:
    return _CT2_OK and os.path.isdir(DIR_MODELO)


def esta_cargado() -> bool:
    return _translator is not None


def cargar_modelo():
    """Carga el modelo (idempotente y seguro para recarga tras descargar())."""
    global _translator, _tokenizer
    with _lock:
        if _translator is not None:
            return
        print(f"[SMaLL-100] Cargando desde {DIR_MODELO} ...")
        # intra_threads=4: 4 cores por traducción. 0 (todos) causaba contención de
        # memoria y cuelgues con lotes grandes en máquinas con poca RAM libre.
        _translator = ctranslate2.Translator(
            DIR_MODELO,
            device="cpu",
            inter_threads=1,
            intra_threads=4,
            compute_type="int8",
        )
        _tokenizer = SMALL100Tokenizer.from_pretrained(DIR_MODELO)
        print("[SMaLL-100] Listo.")


def descargar():
    """Libera el modelo de la RAM (~0.6 GB). Se recarga solo en la próxima traducción."""
    global _translator, _tokenizer
    with _lock:
        _translator = None
        _tokenizer = None


def _tokenizar(texto: str, tgt: str) -> list:
    """Codifica el source. Fijar tgt_lang hace que el tokenizer añada el token de idioma
    destino (__en__, __es__, ...) como primer token del source — así funciona SMaLL-100."""
    _tokenizer.tgt_lang = tgt
    ids = _tokenizer.encode(texto, truncation=True, max_length=1024)
    return _tokenizer.convert_ids_to_tokens(ids)


_RE_ESPACIO_PUNT = re.compile(r'\s+([.,;:!?)\]»…])')
_RE_ESPACIO_ABRE = re.compile(r'([(\[«¿¡])\s+')


def _limpiar(t: str) -> str:
    """SentencePiece deja a veces espacio antes de puntuación ('Hi world .') o después de
    apertura. Se normaliza sin tocar el contenido."""
    t = _RE_ESPACIO_PUNT.sub(r'\1', t)
    t = _RE_ESPACIO_ABRE.sub(r'\1', t)
    return t.strip()


def _decodificar(tokens: list) -> str:
    # A diferencia de M2M, la salida NO empieza por el token de idioma (SMaLL-100 lo pone
    # en el source), así que se decodifica ENTERA (sin descartar el primer token).
    ids = _tokenizer.convert_tokens_to_ids(tokens)
    return _limpiar(_tokenizer.decode(ids, skip_special_tokens=True))


def traducir(texto: str, par: str, beam: int = 0) -> str:
    if not texto or not texto.strip():
        return ""
    cargar_modelo()  # recarga si fue descargado por inactividad (idempotente)
    _, tgt = par.split("-")
    t_norm, se_anadio = comun.normalizar(texto)
    source = _tokenizar(t_norm, tgt)
    with _lock:
        result = _translator.translate_batch(
            [source],
            beam_size=beam or BEAM,
            # Cap proporcional al origen (el modelo para solo al llegar al <eos>, así que
            # subir el techo NO ralentiza los párrafos cortos; solo evita cortar los largos).
            max_decoding_length=min(len(source) * 2 + 50, 1024),
        )
    trad = _decodificar(result[0].hypotheses[0])
    return comun.quitar_punto_anadido(trad, se_anadio)


def mantener_caliente(par: str = "en-es") -> bool:
    """Traducción mínima para mantener el modelo residente en RAM (anti-swap).
    NO bloquea: si ya hay una traducción real en curso (lock tomado), sale sin hacer
    nada — esa traducción ya mantiene las páginas calientes y no queremos que el
    keepalive robe el lock y congele una petición real del usuario."""
    if _translator is None:
        return False
    if not _lock.acquire(blocking=False):
        return False
    try:
        _, tgt = par.split("-")
        source = _tokenizar("Hello.", tgt)
        _translator.translate_batch([source], beam_size=1, max_decoding_length=8)
        return True
    except Exception:
        return False
    finally:
        _lock.release()


def traducir_batch(textos: list, par: str, beam: int = 0) -> list:
    if not textos:
        return []
    cargar_modelo()  # recarga si fue descargado por inactividad (idempotente)
    _, tgt = par.split("-")

    indices_validos, textos_norm, puntos_anadidos, resultado = comun.preparar_batch(textos)
    if not indices_validos:
        return resultado

    src_batch = [_tokenizar(t, tgt) for t in textos_norm]
    max_in = max(len(t) for t in src_batch)
    with _lock:
        results = _translator.translate_batch(
            src_batch,
            beam_size=beam or BEAM,
            max_decoding_length=min(max_in * 2 + 50, 1024),
            max_batch_size=128,
        )
    for pos, i in enumerate(indices_validos):
        trad = _decodificar(results[pos].hypotheses[0])
        resultado[i] = comun.quitar_punto_anadido(trad, puntos_anadidos[pos])
    return resultado
