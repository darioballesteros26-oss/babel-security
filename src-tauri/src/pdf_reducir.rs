// ============================================================
// REDUCIR PDF — sin pérdida visible, nativo y en RAM.
//
// Re-encoda las imágenes JPEG (DCTDecode) SOBREDIMENSIONADAS a ~150-200 DPI y
// calidad 82, conservando texto y vectores intactos (solo se tocan los streams de
// imagen). Usa lopdf para la cirugía de streams + el crate `image` para decodificar
// y recomprimir el JPEG. El llamador valida el resultado con PDFium antes de aceptarlo.
//
// Garantías: nunca deja el archivo más grande (keep-smaller por imagen y global),
// no toca imágenes pequeñas (evita pérdida generacional), respeta transparencias
// (salta máscaras SMask/Mask e ImageMask) y conserva gris vs color.
// ============================================================

use image::codecs::jpeg::JpegEncoder;
use image::imageops::FilterType;
use image::{ColorType, GenericImageView, ImageFormat};
use lopdf::{Dictionary, Document, Object, ObjectId};
use std::collections::BTreeSet;

// Lado mayor máximo tras reducir (~170 DPI en A4). Por encima de esto, downsample.
const CAP_PX: u32 = 2000;
// Calidad JPEG de recompresión: 82 = sin pérdida visible en documentos.
const CALIDAD: u8 = 82;

/// Reduce el peso de un PDF re-encodando sus imágenes JPEG grandes. Devuelve
/// `Some(bytes)` solo si el resultado es más pequeño; `None` si no había nada que
/// reducir o no compensó (el llamador conserva el original).
pub fn reducir(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut doc = Document::load_mem(bytes).ok()?;
    let n_paginas = doc.get_pages().len();

    // Pass 1: IDs usados como máscara de otra imagen (alfa/transparencia) → no tocar.
    let mut mascaras: BTreeSet<ObjectId> = BTreeSet::new();
    for obj in doc.objects.values() {
        if let Object::Stream(s) = obj {
            for clave in [b"SMask".as_ref(), b"Mask".as_ref()] {
                if let Ok(Object::Reference(id)) = s.dict.get(clave) {
                    mascaras.insert(*id);
                }
            }
        }
    }

    let mut cambiado = false;
    for (id, obj) in doc.objects.iter_mut() {
        if mascaras.contains(id) {
            continue;
        }
        let Object::Stream(s) = obj else { continue };
        if !es_imagen(&s.dict) || es_image_mask(&s.dict) || !filtro_es_dct(&s.dict) {
            continue;
        }

        // El contenido de un stream DCTDecode ES el JPEG tal cual.
        let Ok(img) = image::load_from_memory_with_format(&s.content, ImageFormat::Jpeg) else {
            continue;
        };
        let (w, h) = img.dimensions();
        let maxdim = w.max(h);
        if maxdim <= CAP_PX {
            continue; // no sobredimensionada → no recomprimir (evita pérdida generacional)
        }

        let factor = CAP_PX as f32 / maxdim as f32;
        let nw = ((w as f32 * factor).round() as u32).max(1);
        let nh = ((h as f32 * factor).round() as u32).max(1);
        let peq = img.resize_exact(nw, nh, FilterType::Lanczos3);

        // Conservar gris vs color para no triplicar el tamaño de un escaneo en gris.
        let gris = matches!(
            img.color(),
            ColorType::L8 | ColorType::La8 | ColorType::L16 | ColorType::La16
        );
        let mut buf: Vec<u8> = Vec::new();
        let enc_ok = if gris {
            JpegEncoder::new_with_quality(&mut buf, CALIDAD).encode_image(&peq.to_luma8())
        } else {
            JpegEncoder::new_with_quality(&mut buf, CALIDAD).encode_image(&peq.to_rgb8())
        };
        if enc_ok.is_err() || buf.len() + 32 >= s.content.len() {
            continue; // fallo o no mejora → dejar la imagen original
        }

        s.dict.set("Width", nw as i64);
        s.dict.set("Height", nh as i64);
        s.dict.set("BitsPerComponent", 8i64);
        s.dict.set(
            "ColorSpace",
            Object::Name(if gris { b"DeviceGray".to_vec() } else { b"DeviceRGB".to_vec() }),
        );
        s.dict.set("Filter", Object::Name(b"DCTDecode".to_vec()));
        s.dict.remove(b"DecodeParms");
        s.dict.remove(b"DecodeParams");
        s.set_content(buf);
        cambiado = true;
    }

    if !cambiado {
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    doc.save_to(&mut out).ok()?;
    if out.len() >= bytes.len() {
        return None; // no compensó
    }
    // Auto-validación: el PDF resultante debe recargar y conservar el nº de páginas.
    // Si no, se descarta (el llamador conserva el original).
    match Document::load_mem(&out) {
        Ok(d) if d.get_pages().len() == n_paginas => Some(out),
        _ => None,
    }
}

fn es_imagen(d: &Dictionary) -> bool {
    matches!(d.get(b"Subtype"), Ok(Object::Name(n)) if n == b"Image")
}

fn es_image_mask(d: &Dictionary) -> bool {
    matches!(d.get(b"ImageMask"), Ok(Object::Boolean(true)))
}

// Solo DCTDecode "puro" (nombre o array de un elemento). Filtros encadenados o
// distintos (CCITT, JBIG2, Flate) se dejan intactos.
fn filtro_es_dct(d: &Dictionary) -> bool {
    match d.get(b"Filter") {
        Ok(Object::Name(n)) => n == b"DCTDecode",
        Ok(Object::Array(a)) => {
            a.len() == 1 && matches!(&a[0], Object::Name(n) if n == b"DCTDecode")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgb};
    use lopdf::{dictionary, Stream};

    // JPEG grande y con entropía (para que downsampling reduzca de verdad).
    fn jpeg_grande(lado: u32) -> Vec<u8> {
        let img = ImageBuffer::from_fn(lado, lado, |x, y| {
            Rgb([((x * 7 + y * 13) % 256) as u8, ((x * 3 + y * 5) % 256) as u8, ((x ^ y) % 256) as u8])
        });
        let mut buf = Vec::new();
        JpegEncoder::new_with_quality(&mut buf, 92)
            .encode_image(&img)
            .unwrap();
        buf
    }

    // PDF mínimo válido de 1 página que dibuja una imagen JPEG.
    fn pdf_con_imagen(jpeg: &[u8], lado: i64) -> Vec<u8> {
        let mut doc = Document::with_version("1.5");
        let img_id = doc.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => lado,
                "Height" => lado,
                "ColorSpace" => "DeviceRGB",
                "BitsPerComponent" => 8i64,
                "Filter" => "DCTDecode",
            },
            jpeg.to_vec(),
        ));
        let content_id = doc.add_object(Stream::new(
            dictionary! {},
            b"q 200 0 0 200 0 0 cm /Im0 Do Q".to_vec(),
        ));
        let pages_id = doc.new_object_id();
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 200.into()],
            "Contents" => content_id,
            "Resources" => dictionary! {
                "XObject" => dictionary! { "Im0" => img_id },
            },
        });
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![page_id.into()],
                "Count" => 1i64,
            }),
        );
        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        doc.trailer.set("Root", catalog_id);
        let mut out = Vec::new();
        doc.save_to(&mut out).unwrap();
        out
    }

    #[test]
    fn reduce_imagen_grande() {
        let pdf = pdf_con_imagen(&jpeg_grande(3000), 3000);
        let reducido = reducir(&pdf).expect("debería reducir un PDF con imagen 3000px");
        assert!(reducido.len() < pdf.len(), "el resultado no es más pequeño");

        // El PDF sigue siendo válido y la imagen quedó a <=CAP_PX.
        let doc = Document::load_mem(&reducido).unwrap();
        let mut ancho_img = 0i64;
        for obj in doc.objects.values() {
            if let Object::Stream(s) = obj {
                if es_imagen(&s.dict) {
                    ancho_img = s.dict.get(b"Width").unwrap().as_i64().unwrap();
                }
            }
        }
        assert!(ancho_img > 0 && ancho_img as u32 <= CAP_PX, "ancho tras reducir: {}", ancho_img);
    }

    #[test]
    fn imagen_pequena_no_se_toca() {
        // Imagen 800px (< CAP) → no hay reducción → None.
        let pdf = pdf_con_imagen(&jpeg_grande(800), 800);
        assert!(reducir(&pdf).is_none(), "no debería tocar imágenes pequeñas");
    }
}
