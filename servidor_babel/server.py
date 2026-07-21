import sys
import os
import time
import hmac
import threading
from collections import defaultdict

sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, request, jsonify
from flask_cors import CORS
import traduccion_madlad
import traduccion_small100


def _ram_total_gb() -> float:
    """RAM física total (GB). Portable macOS/Linux vía sysconf."""
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / (1024 ** 3)
    except (ValueError, OSError, AttributeError):
        return 8.0  # ante la duda, asumir máquina justa → SMaLL-100


# Auto-tier: MADLAD-3B (~3.5 GB, calidad profesional/legal) necesita holgura de RAM;
# en máquinas de 8 GB se swapea y congela. Umbral 12 GB separa limpiamente 8 de 16 GB.
# El tier ligero es SMaLL-100 (~0.6 GB, distilado de M2M-100, rápido).
# Fallback: si el modelo preferido no está en disco, usar el que haya.
_UMBRAL_MADLAD_GB = 12.0
_RAM_GB = _ram_total_gb()
# Override manual opcional: BABEL_MODELO=madlad|small100 fuerza el motor (auto = por RAM).
# Útil si la detección de RAM no encaja en una máquina concreta (p.ej. 16 GB muy cargada).
_FORZADO = os.environ.get("BABEL_MODELO", "auto").strip().lower()

if _FORZADO == "madlad" and traduccion_madlad.disponible():
    mt, _MODELO_NOMBRE, _MOTIVO = traduccion_madlad, "madlad400-3b", "forzado (BABEL_MODELO)"
elif _FORZADO in ("small100", "small") and traduccion_small100.disponible():
    mt, _MODELO_NOMBRE, _MOTIVO = traduccion_small100, "small100", "forzado (BABEL_MODELO)"
elif _RAM_GB >= _UMBRAL_MADLAD_GB and traduccion_madlad.disponible():
    mt, _MODELO_NOMBRE, _MOTIVO = traduccion_madlad, "madlad400-3b", f"auto: {_RAM_GB:.0f} GB ≥ {_UMBRAL_MADLAD_GB:.0f} GB"
elif traduccion_small100.disponible():
    mt, _MODELO_NOMBRE, _MOTIVO = traduccion_small100, "small100", f"auto: {_RAM_GB:.0f} GB < {_UMBRAL_MADLAD_GB:.0f} GB"
elif traduccion_madlad.disponible():
    mt, _MODELO_NOMBRE, _MOTIVO = traduccion_madlad, "madlad400-3b", "único disponible"
else:
    mt, _MODELO_NOMBRE, _MOTIVO = traduccion_small100, "small100", "ninguno presente (error al cargar)"

print(f"[server] modelo {_MODELO_NOMBRE} ({_MOTIVO})", flush=True)

# Cache de traducciones: evita re-traducir párrafos idénticos en el mismo documento.
# Clave (texto, par, beam) → traducción. FIFO simple: borra la mitad al llegar al límite.
_cache_trad: dict = {}
_CACHE_MAX = 4096


def _cache_get(texto: str, par: str, beam: int):
    return _cache_trad.get((texto, par, beam))


def _cache_set(texto: str, par: str, beam: int, resultado: str) -> None:
    if len(_cache_trad) >= _CACHE_MAX:
        n = _CACHE_MAX // 2
        for k in list(_cache_trad)[:n]:
            del _cache_trad[k]
    _cache_trad[(texto, par, beam)] = resultado


def _traducir_uno(texto: str, par: str, beam: int) -> str:
    hit = _cache_get(texto, par, beam)
    if hit is not None:
        return hit
    result = mt.traducir(texto, par, beam)
    _cache_set(texto, par, beam, result)
    return result


def _traducir_batch_con_cache(textos: list, par: str, beam: int) -> list:
    """Traduce en batch aprovechando el cache: solo llama al modelo para los miss."""
    resultados = [""] * len(textos)
    miss_idx, miss_txt = [], []
    for i, t in enumerate(textos):
        if not t:
            continue
        hit = _cache_get(t, par, beam)
        if hit is not None:
            resultados[i] = hit
        else:
            miss_idx.append(i)
            miss_txt.append(t)
    if miss_txt:
        trad_batch = mt.traducir_batch(miss_txt, par, beam)
        for idx, txt, trad in zip(miss_idx, miss_txt, trad_batch):
            resultados[idx] = trad
            _cache_set(txt, par, beam, trad)
    return resultados


_tasa_lock = threading.Lock()
_tasa_por_ip: dict = defaultdict(list)
_MAX_PETICIONES = 600
_VENTANA_SEGUNDOS = 60


def _verificar_tasa(ip: str) -> bool:
    ahora = time.monotonic()
    with _tasa_lock:
        hist = _tasa_por_ip[ip]
        hist[:] = [t for t in hist if ahora - t < _VENTANA_SEGUNDOS]
        if len(hist) >= _MAX_PETICIONES:
            return False
        hist.append(ahora)
        return True


app = Flask(__name__)
CORS(app, origins=[
    "tauri://localhost",
    "http://tauri.localhost",
    "http://localhost:1420",
    "http://127.0.0.1:1420",
])

_TOKEN_DEFECTO = "babel-local-default-token-2026-no-compartir"
_TOKEN_FILE = os.path.join(os.path.expanduser("~"), "Babel", "servidor_token.txt")


def _obtener_o_generar_token() -> str:
    """Lee ~/Babel/servidor_token.txt o genera uno nuevo y lo persiste."""
    try:
        with open(_TOKEN_FILE) as f:
            tok = f.read().strip()
        if len(tok) >= 32:
            return tok
    except (OSError, IOError):
        pass
    import secrets
    tok = "babel_" + secrets.token_hex(24)
    try:
        os.makedirs(os.path.dirname(_TOKEN_FILE), exist_ok=True)
        with open(_TOKEN_FILE, "w") as f:
            f.write(tok)
        os.chmod(_TOKEN_FILE, 0o600)
    except (OSError, IOError):
        pass
    return tok


BABEL_TOKEN = os.environ.get("BABEL_NLLB_TOKEN") or _obtener_o_generar_token()
MAX_INPUT_CHARS = 10_000

PARES_PERMITIDOS = {
    "es-en", "en-es", "es-fr", "fr-es", "es-ar", "ar-es",
    "fr-en", "en-fr", "en-ar", "ar-en", "fr-ar", "ar-fr",
    "es-de", "de-es", "fr-de", "de-fr", "ar-de", "de-ar",
    "es-ru", "ru-es", "fr-ru", "ru-fr", "ar-ru", "ru-ar",
    "es-zh", "zh-es", "fr-zh", "zh-fr", "ar-zh", "zh-ar",
    "de-ru", "ru-de", "de-zh", "zh-de", "ru-zh", "zh-ru",
    "en-de", "de-en", "en-ru", "ru-en", "en-zh", "zh-en",
}

if BABEL_TOKEN and len(BABEL_TOKEN) < 32:
    import warnings
    warnings.warn("BABEL_NLLB_TOKEN es demasiado corto (< 32 caracteres). Genera uno más seguro.")


def _verificar_token():
    # compare_digest: comparación en tiempo constante (evita timing side-channel).
    recibido = request.headers.get("X-Babel-Token", "")
    if not BABEL_TOKEN or not hmac.compare_digest(recibido, BABEL_TOKEN):
        return jsonify({"error": "No autorizado"}), 401
    return None


# ── PaddleOCR-VL — modelo en memoria (warm) ──────────────────────────────────
_OCR_LLM = None
_OCR_LOCK = threading.Lock()


def _cargar_ocr() -> bool:
    global _OCR_LLM
    if _OCR_LLM is not None:
        return True
    with _OCR_LOCK:
        if _OCR_LLM is not None:
            return True
        _DIR = os.path.dirname(os.path.abspath(__file__))
        # BABEL_DIR_MODELOS permite compartir el modelo OCR sin duplicarlo (Windows lo
        # lee del bundle .app). Fallback: la carpeta local junto a server.py.
        _dir_modelos = os.environ.get("BABEL_DIR_MODELOS") or os.path.join(_DIR, "modelos")
        MODEL_DIR = os.path.join(_dir_modelos, "paddleocr-vl")
        LM_NAMES = [
            "PaddleOCR-VL-1.5-Q4_K_M.gguf",
            "PaddleOCR-VL-1.5-Q8_0.gguf",
            "PaddleOCR-VL-1.5.gguf",
            "PaddleOCR-VL-1.5-BF16.gguf",
        ]
        PROJ_NAMES = [
            "PaddleOCR-VL-1.5-mmproj.gguf",
            "mmproj-BF16.gguf",
            "mmproj-F16.gguf",
        ]
        lm = next((os.path.join(MODEL_DIR, f) for f in LM_NAMES if os.path.isfile(os.path.join(MODEL_DIR, f))), None)
        proj = next((os.path.join(MODEL_DIR, f) for f in PROJ_NAMES if os.path.isfile(os.path.join(MODEL_DIR, f))), None)
        if not lm or not proj:
            return False
        try:
            from llama_cpp import Llama
            from llama_cpp.llama_chat_format import MTMDChatHandler
            handler = MTMDChatHandler(clip_model_path=proj, verbose=False, use_gpu=True)
            _OCR_LLM = Llama(model_path=lm, chat_handler=handler,
                              n_ctx=4096, n_gpu_layers=-1, verbose=False)
            print("[server] PaddleOCR-VL cargado en memoria", flush=True)
            return True
        except Exception as e:
            print(f"[server] Error cargando PaddleOCR-VL: {e}", file=sys.stderr)
            return False


@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"ok": True, "modelo": _MODELO_NOMBRE})


@app.route("/traducir", methods=["POST"])
def traducir_endpoint():
    err = _verificar_token()
    if err:
        return err

    ip = request.remote_addr or "local"
    if not _verificar_tasa(ip):
        return jsonify({"error": "Demasiadas peticiones — espera un momento"}), 429

    data = request.json or {}
    texto = data.get("texto", "").strip()
    par = data.get("par", "es-en")

    if par not in PARES_PERMITIDOS:
        return jsonify({"error": f"Par no soportado: {par}"}), 400

    if not texto:
        return jsonify({"traduccion": ""})

    if len(texto) > MAX_INPUT_CHARS:
        return jsonify({"error": f"Texto demasiado largo (máx {MAX_INPUT_CHARS} caracteres)"}), 400

    beam = data.get("beam")
    beam = beam if isinstance(beam, int) and 1 <= beam <= 8 else 0
    _marcar_uso()
    try:
        return jsonify({"traduccion": _traducir_uno(texto, par, beam), "revisada": False})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 503
    except Exception as e:
        print(f"[server] Error interno: {e}", file=sys.stderr)
        return jsonify({"error": "Error interno del servidor"}), 500


@app.route("/traducir_batch", methods=["POST"])
def traducir_batch_endpoint():
    err = _verificar_token()
    if err:
        return err

    ip = request.remote_addr or "local"
    if not _verificar_tasa(ip):
        return jsonify({"error": "Demasiadas peticiones — espera un momento"}), 429

    data = request.json or {}
    textos = data.get("textos", [])
    par = data.get("par", "es-en")

    if par not in PARES_PERMITIDOS:
        return jsonify({"error": f"Par no soportado: {par}"}), 400

    if not isinstance(textos, list) or len(textos) > 500:
        return jsonify({"error": "textos debe ser lista de máx 500 elementos"}), 400

    # Preservar la longitud de la lista (los no-str → ""): el cliente mapea
    # traducciones por índice; descartar elementos desalinearía los párrafos.
    textos = [t[:MAX_INPUT_CHARS] if isinstance(t, str) else "" for t in textos]

    beam = data.get("beam")
    beam = beam if isinstance(beam, int) and 1 <= beam <= 8 else 0
    _marcar_uso()
    try:
        return jsonify({"traducciones": _traducir_batch_con_cache(textos, par, beam)})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        print(f"[server] Error interno: {e}", file=sys.stderr)
        return jsonify({"error": "Error interno del servidor"}), 500


@app.route("/ocr_pdf", methods=["POST"])
def ocr_pdf_endpoint():
    err = _verificar_token()
    if err:
        return err

    data = request.json or {}
    ruta = data.get("ruta", "")
    # Solo ficheros .pdf reales: reduce la superficie de lectura arbitraria del endpoint.
    if not ruta or not os.path.isfile(ruta) or not ruta.lower().endswith(".pdf"):
        return jsonify({"error": "Ruta PDF no válida"}), 400

    if not _cargar_ocr():
        return jsonify({"error": "Modelo PaddleOCR-VL no disponible"}), 503

    try:
        import fitz, base64 as _b64
        doc = fitz.open(ruta)
        resultados = []
        for i, page in enumerate(doc):
            if i >= 60:
                break
            pix = page.get_pixmap(dpi=150)
            img_b64 = _b64.b64encode(pix.tobytes("jpeg")).decode()
            res = _OCR_LLM.create_chat_completion(
                messages=[{"role": "user", "content": [
                    {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{img_b64}"}},
                    {"type": "text", "text": "OCR:"},
                ]}],
                max_tokens=2048,
                temperature=0,
            )
            texto = res["choices"][0]["message"]["content"].strip()
            if texto:
                resultados.append(texto)
        return jsonify({"texto": "\n\n".join(resultados)})
    except Exception as e:
        print(f"[server] OCR error: {e}", file=sys.stderr)
        return jsonify({"error": "Error procesando el PDF"}), 500


# Gestión de memoria. Por DEFECTO el modelo se mantiene siempre caliente (0 = no descargar):
# en máquinas justas de RAM, descargarlo y recargarlo bajo presión de swap CONGELA la primera
# traducción (thrashing). Poner BABEL_IDLE_DESCARGA_S=300 (segundos) activa la descarga en
# reposo — solo recomendable en máquinas con RAM de sobra (libera ~2-3.5 GB en reposo).
_IDLE_DESCARGA_S = int(os.environ.get("BABEL_IDLE_DESCARGA_S", "0"))
_ultimo_uso = time.monotonic()


def _marcar_uso():
    global _ultimo_uso
    _ultimo_uso = time.monotonic()


def _gestor_memoria():
    """Cada 60 s: si el modelo se ha usado hace poco, lo mantiene caliente (anti-swap);
    si lleva > _IDLE_DESCARGA_S sin usarse, lo descarga y libera la RAM. mantener_caliente()
    NO bloquea (se salta si hay una traducción en curso)."""
    while True:
        time.sleep(60)
        try:
            if not mt.esta_cargado():
                continue  # ya descargado; se recargará en la próxima traducción
            if _IDLE_DESCARGA_S > 0 and time.monotonic() - _ultimo_uso > _IDLE_DESCARGA_S:
                mt.descargar()
                print("[server] modelo descargado por inactividad (RAM liberada)", flush=True)
            else:
                mt.mantener_caliente()  # por defecto: siempre caliente (sin recargas)
        except Exception:
            pass  # Si falla, silencioso — no interrumpir el servidor


if __name__ == "__main__":
    mt.cargar_modelo()
    # Warmup: traducir un mini-batch para que los pesos queden hot en L2/L3
    # antes del primer request real. Sin esto, el primer batch grande puede
    # tardar minutos si el OS ha swapeado partes del modelo.
    try:
        mt.traducir_batch(["Hello.", "The contract.", "First article.",
                           "Yes.", "No.", "Good morning."], "en-es")
        print("[server] Warmup OK.", flush=True)
    except Exception as e:
        print(f"[server] Warmup error (no crítico): {e}", file=sys.stderr)
    t = threading.Thread(target=_gestor_memoria, daemon=True)
    t.start()
    app.run(host="127.0.0.1", port=5002, debug=False)
