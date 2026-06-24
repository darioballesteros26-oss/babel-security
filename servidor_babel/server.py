import sys
import os

# Permite importar traductor y revisor desde el mismo directorio
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, request, jsonify
from flask_cors import CORS
import traductor
import revisor

app = Flask(__name__)
# Solo orígenes legítimos: Tauri en producción y localhost en desarrollo
CORS(app, origins=[
    "tauri://localhost",
    "http://tauri.localhost",
    "http://localhost:1420",
    "http://127.0.0.1:1420",
])

BABEL_TOKEN = os.environ.get("BABEL_NLLB_TOKEN", "")
MAX_INPUT_CHARS = 10_000

# F-3: lista blanca de pares soportados — rechaza valores arbitrarios
PARES_PERMITIDOS = {"es-en", "en-es", "es-fr", "fr-es", "es-ar", "ar-es"}

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
    # F-1: /ping también requiere token para no revelar que el servidor está activo
    err = _verificar_token()
    if err:
        return err
    return jsonify({"ok": True})


@app.route("/traducir", methods=["POST"])
def traducir_endpoint():
    err = _verificar_token()
    if err:
        return err

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

    try:
        traduccion_base = traductor.traducir(texto, par)
        traduccion_final = revisor.revisar(texto, traduccion_base, par, contexto)
        return jsonify({"traduccion": traduccion_final, "revisada": True})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except RuntimeError as e:
        # Traducción degradada — Rust usará el diccionario como fallback
        return jsonify({"error": str(e)}), 503
    except Exception as e:
        return jsonify({"error": f"Error interno: {e}"}), 500


if __name__ == "__main__":
    traductor.cargar_modelos()
    revisor.cargar_modelo()
    app.run(host="127.0.0.1", port=5002, debug=False)
