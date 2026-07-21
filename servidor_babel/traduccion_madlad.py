"""
traduccion_madlad.py — MADLAD-400-3B-MT via CTranslate2 int8 (licencia Apache 2.0).
Modelo dedicado a traducción (sin alucinaciones de LLM), calidad profesional/legal.
Prefijo de idioma destino: <2{bcp47}> al inicio del input — "<2es> Hello" → "Hola".

BEAM: beam search (>1) mejora la calidad frente a greedy, a cambio de velocidad.
Para textos legales priorizamos calidad; si un documento largo va muy lento, bajar BEAM.
"""
import os
import threading

import traduccion_comun as comun

# La inferencia usa CTranslate2, NO torch/tensorflow. Evitar que transformers los importe
# (solo se usa el tokenizer) ahorra ~140 MB de RAM. torch ni está instalado en el USB.
os.environ.setdefault("USE_TORCH", "0")
os.environ.setdefault("USE_TF", "0")

try:
    import ctranslate2
    from transformers import T5Tokenizer
    _CT2_OK = True
except ImportError:
    _CT2_OK = False

DIR_BASE = os.path.dirname(__file__)
_usb_env = os.environ.get("BABEL_DIR_USB")
DIR_USB = _usb_env if _usb_env else os.path.join(DIR_BASE, "modelos_usb")
DIR_MODELO = os.path.join(DIR_USB, "madlad400-3b-int8")

BEAM = 4  # calidad legal; greedy (1) es ~3-4x más rápido pero algo peor

_translator = None
_tokenizer = None
# RLock (reentrante): traducir() lo toma y dentro llama a cargar_modelo() para recargar
# el modelo si fue descargado por inactividad.
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
        print(f"[MADLAD] Cargando desde {DIR_MODELO} ...")
        # intra_threads=4: 4 cores por traducción. 0 (todos) causaba contención de
        # memoria y cuelgues con lotes grandes en máquinas con poca RAM libre.
        _translator = ctranslate2.Translator(
            DIR_MODELO,
            device="cpu",
            inter_threads=1,
            intra_threads=4,
            compute_type="int8",
        )
        if not os.path.isfile(os.path.join(DIR_MODELO, "spiece.model")):
            raise RuntimeError(
                f"[MADLAD] Tokenizer no encontrado en {DIR_MODELO}. "
                "Reinstala los modelos con preparar_usb.sh o descargar_modelos.py."
            )
        _tokenizer = T5Tokenizer.from_pretrained(DIR_MODELO, local_files_only=True)
        print("[MADLAD] Listo.")


def descargar():
    """Libera el modelo de la RAM (~3.5 GB). Se recarga solo en la próxima traducción."""
    global _translator, _tokenizer
    with _lock:
        _translator = None
        _tokenizer = None


def _tokenizar(texto: str, par: str) -> list:
    lang_dest = par.split("-")[1]
    ids = _tokenizer(f"<2{lang_dest}> {texto}", truncation=True, max_length=512).input_ids
    return _tokenizer.convert_ids_to_tokens(ids)


def _decodificar(tokens: list) -> str:
    ids = _tokenizer.convert_tokens_to_ids(tokens)
    return _tokenizer.decode(ids, skip_special_tokens=True)


def traducir(texto: str, par: str, beam: int = 0) -> str:
    if not texto or not texto.strip():
        return ""
    cargar_modelo()  # recarga si fue descargado por inactividad (idempotente)
    t_norm, se_anadio = comun.normalizar(texto)
    tokens = _tokenizar(t_norm, par)
    with _lock:
        result = _translator.translate_batch(
            [tokens],
            beam_size=beam or BEAM,
            max_decoding_length=min(len(tokens) * 2 + 20, 350),
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
        tokens = _tokenizar("Hello.", par)
        _translator.translate_batch([tokens], beam_size=1, max_decoding_length=8)
        return True
    except Exception:
        return False
    finally:
        _lock.release()


def traducir_batch(textos: list, par: str, beam: int = 0) -> list:
    if not textos:
        return []
    cargar_modelo()  # recarga si fue descargado por inactividad (idempotente)

    indices_validos, textos_norm, puntos_anadidos, resultado = comun.preparar_batch(textos)
    if not indices_validos:
        return resultado

    src_batch = [_tokenizar(t, par) for t in textos_norm]
    max_in = max(len(t) for t in src_batch)
    with _lock:
        results = _translator.translate_batch(
            src_batch,
            beam_size=beam or BEAM,
            max_decoding_length=min(max_in * 2 + 20, 350),
            max_batch_size=128,
        )
    for pos, i in enumerate(indices_validos):
        trad = _decodificar(results[pos].hypotheses[0])
        resultado[i] = comun.quitar_punto_anadido(trad, puntos_anadidos[pos])
    return resultado
