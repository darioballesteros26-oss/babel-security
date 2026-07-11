import sys
import os
import time
import threading
from collections import defaultdict

# Permite importar traductor y revisor desde el mismo directorio
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, request, jsonify
from flask_cors import CORS
from functools import lru_cache
import traductor
import traductor_usb
import revisor

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

# True si los modelos tc-big están disponibles en modelos_usb/
_USAR_USB = traductor_usb.disponible()

app = Flask(__name__)
# Solo orígenes legítimos: Tauri en producción y localhost en desarrollo
CORS(app, origins=[
    "tauri://localhost",
    "http://tauri.localhost",
    "http://localhost:1420",
    "http://127.0.0.1:1420",
])

# Token compartido con la app. Si no se pasa por entorno se usa un valor por defecto
# FIJO e idéntico al de la app (traductor.rs::NLLB_TOKEN_DEFECTO). Así la app traduce
# se abra como se abra (doble clic o script) sin configurar nada. Es defensa en
# profundidad sobre un puerto solo-localhost; el modo USB sigue usando token aleatorio.
_TOKEN_DEFECTO = "babel-local-default-token-2026-no-compartir"
BABEL_TOKEN = os.environ.get("BABEL_NLLB_TOKEN") or _TOKEN_DEFECTO
MAX_INPUT_CHARS = 10_000

# F-3: lista blanca de pares soportados — rechaza valores arbitrarios
PARES_PERMITIDOS = {
    "es-en", "en-es", "es-fr", "fr-es", "es-ar", "ar-es",
    "fr-en", "en-fr", "en-ar", "ar-en", "fr-ar", "ar-fr",
    "es-de", "de-es", "fr-de", "de-fr", "ar-de", "de-ar",
    "es-ru", "ru-es", "fr-ru", "ru-fr", "ar-ru", "ru-ar",
    "es-zh", "zh-es", "fr-zh", "zh-fr", "ar-zh", "zh-ar",
    "de-ru", "ru-de", "de-zh", "zh-de", "ru-zh", "zh-ru",
    "en-de", "de-en", "en-ru", "ru-en", "en-zh", "zh-en",
}

# F-2: el token debe tener al menos 32 caracteres para ser útil
if BABEL_TOKEN and len(BABEL_TOKEN) < 32:
    import warnings
    warnings.warn("BABEL_NLLB_TOKEN es demasiado corto (< 32 caracteres). Genera uno más seguro.")


def _verificar_token():
    """F-1/F-2: comprobación centralizada del token."""
    if not BABEL_TOKEN or request.headers.get("X-Babel-Token") != BABEL_TOKEN:
        return jsonify({"error": "No autorizado"}), 401
    return None


@app.route("/ping", methods=["GET"])
def ping():
    # Liveness PÚBLICA (sin token): el badge de la app la consulta desde el webview,
    # donde no dispone del token. Solo revela que el servidor está arriba en un puerto
    # que ya está restringido a 127.0.0.1. /traducir sigue exigiendo token.
    return jsonify({"ok": True, "usb": _USAR_USB})


@lru_cache(maxsize=1024)
def _traducir_base(texto: str, par: str) -> str:
    """Cache de traducción base (MarianMT/USB). Párrafos idénticos no se traducen dos veces."""
    if _USAR_USB:
        return traductor_usb.traducir(texto, par)
    return traductor.traducir(texto, par)


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
    contexto = data.get("contexto", "")

    # F-3: validar el par contra la lista blanca
    if par not in PARES_PERMITIDOS:
        return jsonify({"error": f"Par no soportado: {par}"}), 400

    if not texto:
        return jsonify({"traduccion": ""})

    if len(texto) > MAX_INPUT_CHARS:
        return jsonify({"error": f"Texto demasiado largo (máx {MAX_INPUT_CHARS} caracteres)"}), 400

    sin_revision = bool(data.get("sin_revision", False))

    try:
        traduccion_base = _traducir_base(texto, par)
        if sin_revision:
            return jsonify({"traduccion": traduccion_base, "revisada": False})
        traduccion_final = revisor.revisar(texto, traduccion_base, par, contexto)
        return jsonify({"traduccion": traduccion_final, "revisada": True})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except RuntimeError as e:
        # Traducción degradada — Rust usará el diccionario como fallback
        return jsonify({"error": str(e)}), 503
    except Exception as e:
        return jsonify({"error": f"Error interno: {e}"}), 500


@app.route("/revisar_solo", methods=["POST"])
def revisar_solo_endpoint():
    """Qwen review sobre una traducción ya hecha — no relanza MarianMT."""
    err = _verificar_token()
    if err:
        return err
    data = request.json or {}
    original   = data.get("original", "").strip()
    traduccion = data.get("traduccion", "").strip()
    par        = data.get("par", "es-en")
    if not original or not traduccion:
        return jsonify({"traduccion": traduccion})
    if par not in PARES_PERMITIDOS:
        return jsonify({"traduccion": traduccion})
    try:
        revisada = revisor.revisar(original, traduccion, par)
        return jsonify({"traduccion": revisada})
    except Exception:
        return jsonify({"traduccion": traduccion})


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
    sin_revision = bool(data.get("sin_revision", False))

    if par not in PARES_PERMITIDOS:
        return jsonify({"error": f"Par no soportado: {par}"}), 400

    if not isinstance(textos, list) or len(textos) > 500:
        return jsonify({"error": "textos debe ser lista de máx 500 elementos"}), 400

    textos = [t[:MAX_INPUT_CHARS] for t in textos if isinstance(t, str)]

    try:
        if _USAR_USB:
            traducciones = traductor_usb.traducir_batch(textos, par)
        else:
            traducciones = traductor.traducir_batch(textos, par)

        if not sin_revision:
            traducciones = [
                revisor.revisar(orig, trad, par)
                for orig, trad in zip(textos, traducciones)
            ]

        return jsonify({"traducciones": traducciones})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Error interno: {e}"}), 500


@app.route("/limpiar_pdf", methods=["POST"])
def limpiar_pdf_endpoint():
    err = _verificar_token()
    if err:
        return err

    data = request.json or {}
    bloques = data.get("bloques", [])

    if not isinstance(bloques, list) or not bloques:
        return jsonify({"bloques": []})

    if len(bloques) > 15000:
        return jsonify({"error": "Demasiados bloques (máx 15000)"}), 400

    # Rechazar bloques individuales demasiado grandes
    bloques = [b[:2000] for b in bloques if isinstance(b, str)]

    try:
        limpios = revisor.limpiar_bloques_pdf(bloques)
        return jsonify({"bloques": limpios})
    except Exception as e:
        return jsonify({"bloques": bloques, "aviso": str(e)})


if __name__ == "__main__":
    if _USAR_USB:
        print("[server] Modelos tc-big detectados — usando traductor USB (mayor calidad)")
        traductor_usb.cargar_modelos()
    else:
        print("[server] Usando modelos MarianMT estándar")
        traductor.cargar_modelos()
    revisor.cargar_modelo()
    app.run(host="127.0.0.1", port=5002, debug=False)
