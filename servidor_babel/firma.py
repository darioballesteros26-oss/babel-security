"""Firma digital PAdES-B-B vía pyHanko.

Expone dos rutas Flask:
  POST /firmar       — recibe pdf_b64 + cert_b64 + password; devuelve pdf_b64 firmado
  POST /cert_titular — recibe cert_b64 + password; devuelve nombre del titular
"""
from __future__ import annotations
import base64
from io import BytesIO
from flask import request, jsonify

_PYHANKO_OK = False
try:
    from pyhanko.sign import signers, fields
    from pyhanko.sign.signers import PdfSigner
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.pdf_utils.layout import BoxConstraints
    from pyhanko.stamp import TextStamp, TextStampStyle
    _PYHANKO_OK = True
except ImportError:
    pass


def _geometria_pagina(pdf_bytes: bytes):
    """Geometría de la 1ª página: (x0, y0, x1, y1, rot).

    - Esquinas reales del MediaBox (no asume origen 0,0; hay PDF desplazados).
    - `rot` = rotación efectiva del /Rotate normalizada a 0/90/180/270.
    Ambos, MediaBox y /Rotate, pueden heredarse del árbol de páginas.
    """
    try:
        r = PdfFileReader(BytesIO(pdf_bytes))
        nodo = r.root["/Pages"]["/Kids"][0].get_object()
        mb = None
        rot = None
        while nodo is not None:
            if mb is None and "/MediaBox" in nodo:
                mb = nodo["/MediaBox"]
            if rot is None and "/Rotate" in nodo:
                rot = nodo["/Rotate"]
            if mb is not None and rot is not None:
                break
            padre = nodo.get("/Parent")
            nodo = padre.get_object() if padre is not None else None
        rot = int(rot) % 360 if rot is not None else 0
        if rot not in (0, 90, 180, 270):
            rot = 0
        if mb:
            x0, y0, x1, y1 = (float(v) for v in mb)
            return (min(x0, x1), min(y0, y1), max(x0, x1), max(y0, y1), rot)
    except Exception:
        pass
    return (0.0, 0.0, 595.0, 842.0, 0)  # A4


def _campos_existentes(pdf_bytes: bytes):
    """Nombres de campos de formulario ya presentes en el PDF."""
    usados = set()
    try:
        r = PdfFileReader(BytesIO(pdf_bytes))
        acro = r.root.get("/AcroForm")
        if acro is not None:
            for f in acro.get_object().get("/Fields", []):
                nombre = f.get_object().get("/T")
                if nombre:
                    usados.add(str(nombre))
    except Exception:
        pass
    return usados


def _nombre_campo_libre(usados) -> str:
    """Nombre de campo de firma que no choque con firmas ya presentes.

    Permite firmar un PDF que ya tiene una firma (co-firma) sin colisión.
    """
    base = "Firma"
    if base not in usados:
        return base
    i = 2
    while f"{base}_{i}" in usados:
        i += 1
    return f"{base}_{i}"


def _incrustar_sello(pdf_bytes: bytes, titular: str, desplaz: float = 0.0) -> bytes:
    """Dibuja el sello «FIRMADO DIGITALMENTE …» como CONTENIDO de la 1ª página.

    Clave del diseño: el sello va en el content stream de la página (operador
    `Do` sobre un Form XObject), NO como apariencia de un widget de firma. El
    visor inline de WKWebView (el que usa Babel) NO pinta la apariencia del
    widget de firma —quedaba invisible en la app aunque Adobe/poppler sí la
    mostraran—, pero SÍ renderiza el contenido de la página. Así el sello se ve
    en cualquier visor. La validez criptográfica la aporta la firma PAdES que se
    añade después (invisible) en `_firmar`.
    """
    x0, y0, x1_pag, y1_pag, _rot = _geometria_pagina(pdf_bytes)
    ancho = x1_pag - x0
    margen = 24.0
    caja_ancho = min(300.0, max(140.0, ancho - 2 * margen))
    caja_alto = 64.0

    estilo = TextStampStyle(
        stamp_text="FIRMADO DIGITALMENTE\n%(signer)s\n%(ts)s",
        border_width=2,
        border_color=(0.13, 0.55, 0.13),  # verde: señal de firma correcta
        timestamp_format="%d/%m/%Y %H:%M",
    )
    writer = IncrementalPdfFileWriter(BytesIO(pdf_bytes), strict=False)
    stamp = TextStamp(
        writer, estilo,
        text_params={"signer": titular},
        box=BoxConstraints(width=caja_ancho, height=caja_alto),
    )
    # apply() recibe la esquina INFERIOR-izquierda del sello en coords de página.
    # Lo anclamos arriba-izquierda: y = borde superior − margen − alto − apilado.
    stamp.apply(0, x0 + margen, y1_pag - margen - caja_alto - desplaz)
    buf = BytesIO()
    writer.write(buf)
    return buf.getvalue()


def _firmar(pdf_bytes: bytes, p12_bytes: bytes, password: str, titular: str = "") -> bytes:
    if not _PYHANKO_OK:
        raise RuntimeError("pyhanko no instalado — ejecuta: pip install pyhanko")
    signer = signers.SimpleSigner.load_pkcs12_data(
        pkcs12_bytes=p12_bytes,
        other_certs=[],
        passphrase=password.encode() if password else None,
    )
    if not titular:
        titular = _titular(p12_bytes, password)

    # Los PDF cifrados/protegidos no se pueden firmar sin la contraseña de apertura:
    # damos un mensaje claro en vez del críptico "No key available to decrypt".
    # strict=False: tolera "hybrid cross-reference sections" y otras violaciones
    # menores de la spec, muy comunes en PDFs reales (escáneres, gestores docs).
    probe = IncrementalPdfFileWriter(BytesIO(pdf_bytes), strict=False)
    if probe.security_handler is not None:
        raise ValueError(
            "El PDF está protegido con contraseña. Quítale la protección de apertura "
            "antes de firmarlo."
        )

    # Co-firma: si ya había firmas, apilar el nuevo sello debajo (sentido visual).
    usados = _campos_existentes(pdf_bytes)
    apilado = len([n for n in usados if n == "Firma" or n.startswith("Firma_")])
    desplaz = apilado * (64.0 + 8.0)

    # 1) Sello VISIBLE incrustado en el contenido de la página (se ve en todo visor).
    pdf_sellado = _incrustar_sello(pdf_bytes, titular, desplaz)

    # 2) Firma digital PAdES INVISIBLE sobre el PDF ya sellado. La marca visual la
    #    aporta el contenido del paso 1; la firma solo aporta validez criptográfica,
    #    de ahí que no lleve caja/apariencia (evita doble sello en Adobe/poppler).
    campo = _nombre_campo_libre(usados)
    writer = IncrementalPdfFileWriter(BytesIO(pdf_sellado), strict=False)
    fields.append_signature_field(
        writer,
        sig_field_spec=fields.SigFieldSpec(campo),  # sin box → firma invisible
    )
    pdf_signer = PdfSigner(
        signers.PdfSignatureMetadata(field_name=campo),
        signer=signer,
    )
    out = BytesIO()
    pdf_signer.sign_pdf(writer, existing_fields_only=True, output=out)
    return out.getvalue()


def _titular(p12_bytes: bytes, password: str) -> str:
    try:
        from cryptography.hazmat.primitives.serialization import pkcs12
        from cryptography.x509.oid import NameOID
        pwd = password.encode() if password else None
        _, cert, _ = pkcs12.load_key_and_certificates(p12_bytes, pwd)
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if attrs:
            return attrs[0].value
        return cert.subject.rfc4514_string()
    except Exception as e:
        raise ValueError(f"No se pudo leer el certificado: {e}")


def registrar_rutas(app, verificar_token):
    @app.route("/firmar", methods=["POST"])
    def firmar_endpoint():
        err = verificar_token()
        if err:
            return err
        if not _PYHANKO_OK:
            return jsonify({"error": "pyhanko no instalado en este entorno"}), 503
        data = request.json or {}
        pdf_b64  = data.get("pdf_b64", "")
        cert_b64 = data.get("cert_b64", "")
        password = data.get("password", "")
        titular  = data.get("titular", "")
        if not pdf_b64 or not cert_b64:
            return jsonify({"error": "Faltan pdf_b64 o cert_b64"}), 400
        try:
            pdf_bytes  = base64.b64decode(pdf_b64)
            p12_bytes  = base64.b64decode(cert_b64)
        except Exception:
            return jsonify({"error": "Datos base64 inválidos"}), 400
        try:
            resultado = _firmar(pdf_bytes, p12_bytes, password, titular)
            del p12_bytes
            return jsonify({"pdf_b64": base64.b64encode(resultado).decode()})
        except Exception as e:
            del p12_bytes
            return jsonify({"error": str(e)}), 500

    @app.route("/cert_titular", methods=["POST"])
    def cert_titular_endpoint():
        err = verificar_token()
        if err:
            return err
        data = request.json or {}
        cert_b64 = data.get("cert_b64", "")
        password = data.get("password", "")
        if not cert_b64:
            return jsonify({"error": "Falta cert_b64"}), 400
        try:
            p12_bytes = base64.b64decode(cert_b64)
        except Exception:
            return jsonify({"error": "Datos base64 inválidos"}), 400
        try:
            nombre = _titular(p12_bytes, password)
            del p12_bytes
            return jsonify({"nombre": nombre})
        except Exception as e:
            return jsonify({"error": str(e)}), 400
