from flask import Flask, request, jsonify
from flask_cors import CORS
import ctranslate2
from transformers import AutoTokenizer
import os
import threading

app = Flask(__name__)
CORS(app)

MODEL_DIR = os.path.expanduser("~/Desktop/Babel/nllb-600M-int8-ct2")
BABEL_TOKEN = os.environ.get("BABEL_NLLB_TOKEN", "")
MAX_INPUT_CHARS = 10_000

print("[NLLB] Cargando modelo...")
translator = ctranslate2.Translator(MODEL_DIR, device="cpu", inter_threads=2)
tokenizer = AutoTokenizer.from_pretrained("facebook/nllb-200-distilled-600M")
tokenizer_lock = threading.Lock()
print("[NLLB] Modelo listo.")

@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"ok": True})

@app.route("/traducir", methods=["POST"])
def traducir():
    # Validar token de seguridad
    if not BABEL_TOKEN or request.headers.get("X-Babel-Token") != BABEL_TOKEN:
        return jsonify({"error": "No autorizado"}), 401

    data = request.json
    texto = data.get("texto", "")
    origen = data.get("origen", "spa_Latn")
    destino = data.get("destino", "eng_Latn")

    if not texto.strip():
        return jsonify({"traduccion": ""})

    # Limitar tamaño del input
    if len(texto) > MAX_INPUT_CHARS:
        return jsonify({"error": f"Texto demasiado largo (máx {MAX_INPUT_CHARS} caracteres)"}), 400

    try:
        with tokenizer_lock:
            tokenizer.src_lang = origen
            tokens = tokenizer.convert_ids_to_tokens(tokenizer.encode(texto))

        # max_decoding_length proporcional al input: al menos 512, hasta 1024
        max_len = min(max(len(tokens) * 2, 512), 1024)

        results = translator.translate_batch(
            [tokens],
            target_prefix=[[destino]],
            max_decoding_length=max_len,
            beam_size=2
        )
        output_tokens = results[0].hypotheses[0][1:]

        with tokenizer_lock:
            traduccion = tokenizer.decode(
                tokenizer.convert_tokens_to_ids(output_tokens),
                skip_special_tokens=True
            )

        return jsonify({"traduccion": traduccion})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=False)
