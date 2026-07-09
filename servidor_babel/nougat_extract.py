#!/usr/bin/env python3
"""
nougat_extract.py — Extrae texto estructurado de PDF con Nougat (facebook/nougat-small).
Salida: Markdown limpio por stdout (utf-8). Código de salida 1 si falla.

Uso: python3 nougat_extract.py <ruta_pdf>
El modelo debe estar en <directorio_de_este_script>/modelos/nougat-small/
"""
import sys
import os

os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["TRANSFORMERS_VERBOSITY"] = "error"

if len(sys.argv) < 2:
    sys.stderr.write("Uso: nougat_extract.py <ruta_pdf>\n")
    sys.exit(1)

RUTA_PDF   = sys.argv[1]
MODELO_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "modelos", "nougat-small")

if not os.path.isdir(MODELO_DIR):
    sys.stderr.write(f"Modelo Nougat no encontrado en: {MODELO_DIR}\n")
    sys.exit(1)

try:
    import torch
    from functools import partial
    from torch.utils.data import DataLoader
    from nougat import NougatModel
    from nougat.utils.dataset import LazyDataset
    from nougat.postprocessing import close_envs

    # Apple Silicon: Metal Performance Shaders; resto: CPU
    if torch.backends.mps.is_available():
        device = torch.device("mps")
    else:
        device = torch.device("cpu")

    model = NougatModel.from_pretrained(MODELO_DIR)
    model.eval()
    model.to(device)

    dataset = LazyDataset(
        RUTA_PDF,
        partial(model.encoder.prepare_input, random_padding=False),
    )
    dataloader = DataLoader(
        dataset,
        batch_size=1,
        shuffle=False,
        collate_fn=LazyDataset.ignore_none_collate,
    )

    resultados = []
    for i, (sample, _is_last) in enumerate(dataloader):
        if i >= 60:           # máximo 60 páginas
            break
        with torch.no_grad():
            output = model.inference(
                image_tensors=sample.to(device),
                early_stopping=False,
            )
        pred = output["predictions"][0]
        # Descartar páginas en blanco o que Nougat no reconoció
        if pred and "[MISSING_PAGE" not in pred and pred.strip():
            resultados.append(close_envs(pred).strip())

    sys.stdout.buffer.write("\n\n".join(resultados).encode("utf-8"))

except Exception as e:
    sys.stderr.write(f"nougat_extract error: {e}\n")
    sys.exit(1)
