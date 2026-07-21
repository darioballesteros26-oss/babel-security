"""
traduccion_m2m.py — M2M-100 1.2B via CTranslate2 int8 (licencia MIT, comercial).
Un solo modelo multilingüe directo (sin pivotes ni revisor). ~1.5-2 GB RAM.

M2M-100 tokeniza distinto a MADLAD: el idioma ORIGEN se fija con `tokenizer.src_lang`
y el idioma DESTINO se fuerza pasando su token (`__en__`, `__es__`, ...) como
`target_prefix` al decoder. El primer token de salida es ese token de idioma y se
descarta.
"""
import os
import re
import threading

import traduccion_comun as comun

# La inferencia usa CTranslate2, NO torch/tensorflow. Evitar que transformers los importe
# (solo se usa el tokenizer, basado en sentencepiece) ahorra ~140 MB de RAM. torch ni
# siquiera está instalado en el USB.
os.environ.setdefault("USE_TORCH", "0")
os.environ.setdefault("USE_TF", "0")

try:
    import ctranslate2
    from transformers import M2M100Tokenizer
    _CT2_OK = True
except ImportError:
    _CT2_OK = False

DIR_BASE = os.path.dirname(__file__)
_usb_env = os.environ.get("BABEL_DIR_USB")
DIR_USB = _usb_env if _usb_env else os.path.join(DIR_BASE, "modelos_usb")
DIR_MODELO = os.path.join(DIR_USB, "m2m100-1.2b-int8")

# beam search: M2M-100 es rápido (~0.1s/párr greedy), así que subir el beam mejora la
# calidad del tier de 8 GB —el más flojo— con coste de velocidad asumible. greedy=1 era
# demasiado pobre para uso profesional; 4 es el beam estándar de MT.
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
        print(f"[M2M] Cargando desde {DIR_MODELO} ...")
        # intra_threads=4: 4 cores por traducción. 0 (todos) causaba contención de
        # memoria y cuelgues con lotes grandes en máquinas con poca RAM libre.
        _translator = ctranslate2.Translator(
            DIR_MODELO,
            device="cpu",
            inter_threads=1,
            intra_threads=4,
            compute_type="int8",
        )
        # Tokenizer: preferir ficheros locales (USB offline) y si no, el id de HF (cache).
        tok_src = DIR_MODELO if os.path.isfile(os.path.join(DIR_MODELO, "tokenizer_config.json")) else "facebook/m2m100_1.2B"
        _tokenizer = M2M100Tokenizer.from_pretrained(tok_src)
        print("[M2M] Listo.")


def descargar():
    """Libera el modelo de la RAM (~2 GB). Se recarga solo en la próxima traducción."""
    global _translator, _tokenizer
    with _lock:
        _translator = None
        _tokenizer = None


def _token_destino(lang: str) -> str:
    """Token de idioma destino de M2M-100: 'en' -> '__en__'."""
    l2t = getattr(_tokenizer, "lang_code_to_token", None)
    if l2t and lang in l2t:
        return l2t[lang]
    return f"__{lang}__"


def _tokenizar_origen(texto: str, src: str) -> list:
    _tokenizer.src_lang = src
    ids = _tokenizer.encode(texto, truncation=True, max_length=1024)
    return _tokenizer.convert_ids_to_tokens(ids)


_RE_ESPACIO_PUNT = re.compile(r'\s+([.,;:!?)\]»…])')
_RE_ESPACIO_ABRE = re.compile(r'([(\[«¿¡])\s+')


def _limpiar(t: str) -> str:
    """M2M-100/SentencePiece deja a veces espacio antes de puntuación ('Hi world .')
    o después de apertura. Se normaliza sin tocar el contenido."""
    t = _RE_ESPACIO_PUNT.sub(r'\1', t)
    t = _RE_ESPACIO_ABRE.sub(r'\1', t)
    return t.strip()


def _decodificar(tokens: list) -> str:
    # El primer token es el de idioma destino (target_prefix) — descartarlo.
    tokens = tokens[1:] if tokens else tokens
    ids = _tokenizer.convert_tokens_to_ids(tokens)
    return _limpiar(_tokenizer.decode(ids, skip_special_tokens=True))


def traducir(texto: str, par: str, beam: int = 0) -> str:
    if not texto or not texto.strip():
        return ""
    cargar_modelo()  # recarga si fue descargado por inactividad (idempotente)
    src, tgt = par.split("-")
    t_norm, se_anadio = comun.normalizar(texto)
    source = _tokenizar_origen(t_norm, src)
    prefijo = [_token_destino(tgt)]
    with _lock:
        result = _translator.translate_batch(
            [source],
            target_prefix=[prefijo],
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
        src, tgt = par.split("-")
        source = _tokenizar_origen("Hello.", src)
        _translator.translate_batch(
            [source], target_prefix=[[_token_destino(tgt)]],
            beam_size=1, max_decoding_length=8,
        )
        return True
    except Exception:
        return False
    finally:
        _lock.release()


def traducir_batch(textos: list, par: str, beam: int = 0) -> list:
    if not textos:
        return []
    cargar_modelo()  # recarga si fue descargado por inactividad (idempotente)
    src, tgt = par.split("-")

    indices_validos, textos_norm, puntos_anadidos, resultado = comun.preparar_batch(textos)
    if not indices_validos:
        return resultado

    src_batch = [_tokenizar_origen(t, src) for t in textos_norm]
    max_in = max(len(t) for t in src_batch)
    prefijo = [_token_destino(tgt)]
    with _lock:
        results = _translator.translate_batch(
            src_batch,
            target_prefix=[prefijo] * len(src_batch),
            beam_size=beam or BEAM,
            max_decoding_length=min(max_in * 2 + 50, 1024),
            max_batch_size=128,
        )
    for pos, i in enumerate(indices_validos):
        trad = _decodificar(results[pos].hypotheses[0])
        resultado[i] = comun.quitar_punto_anadido(trad, puntos_anadidos[pos])
    return resultado
