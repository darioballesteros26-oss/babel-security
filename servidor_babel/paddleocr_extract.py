#!/usr/bin/env python3
"""
paddleocr_extract.py — Segunda pasada PDF: OCR avanzado con PaddleOCR-VL-1.5.

Fuente del modelo (Apache 2.0):
  LM  : cuantizado localmente Q4_K_M (286 MB) desde noctrex/PaddleOCR-VL-1.5-GGUF Q8_0
        fallback: Q8_0 (475 MB) o BF16 oficial (936 MB)
  PROJ: PaddlePaddle/PaddleOCR-VL-1.5-GGUF → PaddleOCR-VL-1.5-mmproj.gguf (841 MB BF16)
        Nota: llama-quantize no soporta arquitectura CLIP, mmproj no cuantizable.

Arquitectura: ERNIE-4.5-0.3B + Visual Encoder propio (no Qwen).
Runtime: llama-cpp-python MTMDChatHandler (API multimodal genérica GGUF).

Salida: texto OCR utf-8 por stdout. Exit 1 si falta el modelo.
"""
import sys
import os
import base64

os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["LLAMA_CPP_LOG_LEVEL"] = "40"   # solo errores críticos

if len(sys.argv) < 2:
    sys.stderr.write("Uso: paddleocr_extract.py <ruta_pdf>\n")
    sys.exit(1)

RUTA_PDF  = sys.argv[1]
_DIR      = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(_DIR, "modelos", "paddleocr-vl")

# Q4_K_M (286 MB) tiene prioridad; fallback Q8_0 o BF16
_LM_CANDIDATOS = [
    "PaddleOCR-VL-1.5-Q4_K_M.gguf", # 286 MB — cuantizado localmente
    "PaddleOCR-VL-1.5-Q8_0.gguf",   # 475 MB — noctrex cuantizado
    "PaddleOCR-VL-1.5.gguf",         # 936 MB — oficial BF16
    "PaddleOCR-VL-1.5-BF16.gguf",
    "PaddleOCR-VL-1.5-F16.gguf",
]
_PROJ_CANDIDATOS = [
    "PaddleOCR-VL-1.5-mmproj.gguf",  # oficial BF16 (882 MB)
    "mmproj-BF16.gguf",
    "mmproj-F16.gguf",
]

def _buscar(candidatos):
    for nombre in candidatos:
        ruta = os.path.join(MODEL_DIR, nombre)
        if os.path.isfile(ruta):
            return ruta
    return None

LM_GGUF = _buscar(_LM_CANDIDATOS)
MM_GGUF = _buscar(_PROJ_CANDIDATOS)

if not LM_GGUF or not MM_GGUF:
    sys.stderr.write(
        f"PaddleOCR-VL no encontrado en: {MODEL_DIR}\n"
        f"  LM buscado: {_LM_CANDIDATOS}\n"
        f"  mmproj buscado: {_PROJ_CANDIDATOS}\n"
    )
    sys.exit(1)

try:
    import fitz                                             # pymupdf
    from llama_cpp import Llama
    from llama_cpp.llama_chat_format import MTMDChatHandler # GGUF multimodal genérico

    chat_handler = MTMDChatHandler(
        clip_model_path=MM_GGUF,
        verbose=False,
        use_gpu=True,   # Metal en Apple Silicon
    )
    llm = Llama(
        model_path=LM_GGUF,
        chat_handler=chat_handler,
        n_ctx=4096,
        n_gpu_layers=-1,
        verbose=False,
    )

    doc       = fitz.open(RUTA_PDF)
    resultados = []
    MAX_PAG   = 60

    for i, page in enumerate(doc):
        if i >= MAX_PAG:
            break

        # Renderizar a 150 DPI: equilibrio calidad/velocidad para OCR
        pix     = page.get_pixmap(dpi=150)
        img_b64 = base64.b64encode(pix.tobytes("jpeg")).decode()

        # Prompt fijo: "OCR:" activa el modo reconocimiento de texto plano en PaddleOCR-VL
        resultado = llm.create_chat_completion(
            messages=[{
                "role": "user",
                "content": [
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:image/jpeg;base64,{img_b64}"},
                    },
                    {"type": "text", "text": "OCR:"},
                ],
            }],
            max_tokens=2048,
            temperature=0,
        )
        texto = resultado["choices"][0]["message"]["content"].strip()
        if texto:
            resultados.append(texto)

    sys.stdout.buffer.write("\n\n".join(resultados).encode("utf-8"))

except Exception as e:
    sys.stderr.write(f"paddleocr_extract error: {e}\n")
    sys.exit(1)
