"""
Punto de entrada para producción — empaquetado con PyInstaller.
Detecta automáticamente los modelos en el USB montado en /Volumes/.
"""
import sys
import os

# PyInstaller extrae los archivos a un directorio temporal (_MEIPASS).
# Añadimos ese directorio al path para que los imports funcionen igual que en dev.
if getattr(sys, "frozen", False):
    _BASE = sys._MEIPASS  # type: ignore[attr-defined]
else:
    _BASE = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, _BASE)

# Indicar al módulo traductor_usb dónde buscar los modelos antes de importarlo.
# Se pasa vía variable de entorno para no romper la API del módulo.
def _buscar_dir_usb() -> str:
    # 1) Argumento de línea de comandos: --modelos-usb /ruta
    for i, arg in enumerate(sys.argv):
        if arg == "--modelos-usb" and i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    # 2) Variable de entorno
    env = os.environ.get("BABEL_MODELOS_USB")
    if env and os.path.isdir(env):
        return env
    # 3) Escanear /Volumes/ (macOS) buscando un USB con los modelos
    volumes = "/Volumes"
    if os.path.isdir(volumes):
        for vol in sorted(os.listdir(volumes)):
            candidato = os.path.join(volumes, vol, "modelos_usb")
            if os.path.isdir(candidato):
                return os.path.join(volumes, vol)
    # 4) Fallback: directorio del ejecutable
    return _BASE

_DIR_USB = _buscar_dir_usb()
os.environ["BABEL_DIR_USB"] = _DIR_USB

# Ahora importar los módulos (ya leen BABEL_DIR_USB si está definido)
from flask import Flask, request, jsonify
from flask_cors import CORS
import traductor_usb
import revisor

_USAR_USB = traductor_usb.disponible()

app = Flask(__name__)
CORS(app, origins=[
    "tauri://localhost",
    "http://tauri.localhost",
    "http://localhost:1420",
    "http://127.0.0.1:1420",
])

_TOKEN_DEFECTO = "babel-local-default-token-2026-no-compartir"
BABEL_TOKEN = os.environ.get("BABEL_NLLB_TOKEN") or _TOKEN_DEFECTO
MAX_INPUT_CHARS = 10_000

PARES_PERMITIDOS = {
    "es-en", "en-es", "es-fr", "fr-es", "es-ar", "ar-es",
    "fr-en", "en-fr", "en-ar", "ar-en", "fr-ar", "ar-fr",
    "de-es", "es-de", "fr-de", "de-fr",
    "es-ru", "ru-es", "en-ru", "ru-en",
    "de-ru", "ru-de", "de-en", "en-de",
}


def _verificar_token():
    if not BABEL_TOKEN or request.headers.get("X-Babel-Token") != BABEL_TOKEN:
        return jsonify({"error": "No autorizado"}), 401
    return None


@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"ok": True, "usb": _USAR_USB})


@app.route("/traducir", methods=["POST"])
def traducir_endpoint():
    err = _verificar_token()
    if err:
        return err

    data = request.json or {}
    texto = data.get("texto", "").strip()
    par = data.get("par", "es-en")
    contexto = data.get("contexto", "")

    if par not in PARES_PERMITIDOS:
        return jsonify({"error": f"Par no soportado: {par}"}), 400
    if not texto:
        return jsonify({"traduccion": ""})
    if len(texto) > MAX_INPUT_CHARS:
        return jsonify({"error": f"Texto demasiado largo (máx {MAX_INPUT_CHARS} caracteres)"}), 400

    try:
        traduccion_base = traductor_usb.traducir(texto, par)
        traduccion_final = revisor.revisar(texto, traduccion_base, par, contexto)
        return jsonify({"traduccion": traduccion_final, "revisada": True})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 503
    except Exception as e:
        return jsonify({"error": f"Error interno: {e}"}), 500


if __name__ == "__main__":
    print(f"[USB] Directorio modelos: {_DIR_USB}")
    if _USAR_USB:
        print("[USB] Modelos tc-big detectados — cargando...")
        traductor_usb.cargar_modelos()
    else:
        print("[USB] Modelos no encontrados — servidor sin traducción")
    revisor.cargar_modelo()
    app.run(host="127.0.0.1", port=5002, debug=False)
