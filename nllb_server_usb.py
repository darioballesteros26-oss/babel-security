from flask import Flask, request, jsonify
from flask_cors import CORS
import ctranslate2
from transformers import AutoTokenizer
import os
import threading
from pathlib import Path

# Rutas relativas al USB (este script está en USB/servidor/)
_USB_ROOT = Path(__file__).parent.parent
MODEL_DIR = str(_USB_ROOT / "servidor" / "nllb_model")
TOKENIZER_DIR = str(_USB_ROOT / "tokenizer")

# Modo offline: nunca intentar descargar nada de internet
os.environ["TRANSFORMERS_OFFLINE"] = "1"
os.environ["HF_DATASETS_OFFLINE"] = "1"
os.environ["TOKENIZERS_PARALLELISM"] = "false"

BABEL_TOKEN = os.environ.get("BABEL_NLLB_TOKEN", "")
MAX_INPUT_CHARS = 10_000

# NLLB usa codes más específicos que los genéricos del frontend
_LANG_NORM = {
    "ara_Arab": "arb_Arab",  # Árabe estándar moderno
    "zho_Hans": "zho_Hans",  # Chino simplificado (ya correcto)
    "zho_Hant": "zho_Hant",  # Chino tradicional (ya correcto)
}

app = Flask(__name__)
CORS(app)

print("[NLLB] Cargando modelo desde:", MODEL_DIR)
translator = ctranslate2.Translator(MODEL_DIR, device="cpu", inter_threads=2)
tokenizer = AutoTokenizer.from_pretrained(TOKENIZER_DIR)
tokenizer_lock = threading.Lock()
print("[NLLB] Modelo listo.")


@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"ok": True})


@app.route("/traducir", methods=["POST"])
def traducir():
    if not BABEL_TOKEN or request.headers.get("X-Babel-Token") != BABEL_TOKEN:
        return jsonify({"error": "No autorizado"}), 401

    data = request.json or {}
    texto = data.get("texto", "").strip()
    origen = _LANG_NORM.get(data.get("origen", "spa_Latn"), data.get("origen", "spa_Latn"))
    destino = _LANG_NORM.get(data.get("destino", "eng_Latn"), data.get("destino", "eng_Latn"))

    if not texto:
        return jsonify({"traduccion": ""})

    if len(texto) > MAX_INPUT_CHARS:
        return jsonify({"error": f"Texto demasiado largo (máx {MAX_INPUT_CHARS} caracteres)"}), 400

    try:
        with tokenizer_lock:
            tokenizer.src_lang = origen
            tokens = tokenizer.convert_ids_to_tokens(tokenizer.encode(texto))

        max_len = min(max(len(tokens) * 2, 512), 1024)

        results = translator.translate_batch(
            [tokens],
            target_prefix=[[destino]],
            max_decoding_length=max_len,
            beam_size=2,
        )
        output_tokens = results[0].hypotheses[0][1:]

        with tokenizer_lock:
            traduccion = tokenizer.decode(
                tokenizer.convert_tokens_to_ids(output_tokens),
                skip_special_tokens=True,
            )

        return jsonify({"traduccion": traduccion})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=False)
