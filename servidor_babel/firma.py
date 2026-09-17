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
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    _PYHANKO_OK = True
except ImportError:
    pass


def _firmar(pdf_bytes: bytes, p12_bytes: bytes, password: str) -> bytes:
    if not _PYHANKO_OK:
        raise RuntimeError("pyhanko no instalado — ejecuta: pip install pyhanko")
    signer = signers.SimpleSigner.load_pkcs12_data(
        pkcs12_bytes=p12_bytes,
        other_certs=[],
        passphrase=password.encode() if password else None,
    )
    writer = IncrementalPdfFileWriter(BytesIO(pdf_bytes))
    fields.append_signature_field(writer, sig_field_spec=fields.SigFieldSpec("Firma"))
    out = BytesIO()
    signers.sign_pdf(
        writer,
        signers.PdfSignatureMetadata(field_name="Firma"),
        signer=signer,
        output=out,
    )
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
        if not pdf_b64 or not cert_b64:
            return jsonify({"error": "Faltan pdf_b64 o cert_b64"}), 400
        try:
            pdf_bytes  = base64.b64decode(pdf_b64)
            p12_bytes  = base64.b64decode(cert_b64)
        except Exception:
            return jsonify({"error": "Datos base64 inválidos"}), 400
        try:
            resultado = _firmar(pdf_bytes, p12_bytes, password)
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
