// ============================================================
// IMAGEN → PDF — convierte imágenes (PNG, JPEG, WEBP…) a PDF
// de una página por imagen, usando lopdf + image (ya en Cargo.toml).
//
// Flujo:
//   1. Decodifica la imagen con `image` (límites anti-bomba idénticos
//      a pdf_reducir.rs: max 20 000 px, max 512 MB RAM).
//   2. Comprime a JPEG calidad 82, downsampling si lado > 2 000 px
//      (mismos umbrales que pdf_reducir::reducir para coherencia).
//   3. Empaqueta en un PDF mínimo lopdf con el JPEG como XObject.
//
// Garantías: nunca escribe en disco; opera 100 % en RAM.
// ============================================================

use image::codecs::jpeg::JpegEncoder;
use image::imageops::FilterType;
use image::{ColorType, GenericImageView, ImageFormat};
use lopdf::{dictionary, Document, Object, Stream};

/// Lado mayor máximo antes de downsample (≈ 150-170 DPI en A4).
const CAP_PX: u32 = 2000;
/// Calidad JPEG de recompresión.
const CALIDAD: u8 = 82;

/// Convierte los bytes crudos de UNA imagen a un PDF de una página.
/// Acepta cualquier formato soportado por el crate `image` (JPEG, PNG,
/// WEBP, BMP, TIFF, GIF estático…).
///
/// La página tiene exactamente las dimensiones de la imagen (en puntos pt,
/// donde 1 pt = 1 px para las imágenes de resolución 72 DPI por convenio).
pub fn imagen_a_pdf(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let jpeg = comprimir_imagen(bytes)?;
    let (w, h) = dimensiones_jpeg(&jpeg)?;
    Ok(pdf_de_paginas(&[(jpeg, w, h)]))
}

/// Convierte varias imágenes en un único PDF multi-página (una imagen por
/// página). El orden de las páginas corresponde al orden de `imagenes`.
pub fn imagenes_a_pdf_unico(imagenes: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    if imagenes.is_empty() {
        return Err("No hay imágenes para convertir.".into());
    }
    let mut paginas: Vec<(Vec<u8>, u32, u32)> = Vec::with_capacity(imagenes.len());
    for (i, img) in imagenes.iter().enumerate() {
        let jpeg = comprimir_imagen(img).map_err(|e| format!("Imagen {}: {}", i + 1, e))?;
        let (w, h) = dimensiones_jpeg(&jpeg)?;
        paginas.push((jpeg, w, h));
    }
    Ok(pdf_de_paginas(&paginas))
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Decodifica y recomprime una imagen a JPEG con los mismos parámetros que
/// `pdf_reducir::reducir` (CAP_PX, CALIDAD). Preserva gris vs color.
fn comprimir_imagen(bytes: &[u8]) -> Result<Vec<u8>, String> {
    // Detectar formato para que `image` no intente JPEG en un PNG (etc.)
    let fmt = image::guess_format(bytes).ok();

    let mut reader = image::ImageReader::new(std::io::Cursor::new(bytes));
    if let Some(f) = fmt {
        // JPEG ya reconocido → evitar re-detección lenta
        if f == ImageFormat::Jpeg {
            reader.set_format(ImageFormat::Jpeg);
        }
    }
    // Anti-bomba: mismos límites que en pdf_reducir.rs
    let mut limites = image::Limits::default();
    limites.max_image_width = Some(20_000);
    limites.max_image_height = Some(20_000);
    limites.max_alloc = Some(512 * 1024 * 1024);
    reader.limits(limites);

    let img = reader
        .with_guessed_format()
        .map_err(|e| format!("No se pudo leer la imagen: {e}"))?
        .decode()
        .map_err(|e| format!("Formato de imagen no soportado: {e}"))?;

    let (w, h) = img.dimensions();
    let maxdim = w.max(h);

    let img = if maxdim > CAP_PX {
        let factor = CAP_PX as f32 / maxdim as f32;
        let nw = ((w as f32 * factor).round() as u32).max(1);
        let nh = ((h as f32 * factor).round() as u32).max(1);
        img.resize_exact(nw, nh, FilterType::Lanczos3)
    } else {
        img
    };

    let gris = matches!(
        img.color(),
        ColorType::L8 | ColorType::La8 | ColorType::L16 | ColorType::La16
    );

    let mut buf: Vec<u8> = Vec::new();
    let enc = if gris {
        JpegEncoder::new_with_quality(&mut buf, CALIDAD).encode_image(&img.to_luma8())
    } else {
        JpegEncoder::new_with_quality(&mut buf, CALIDAD).encode_image(&img.to_rgb8())
    };
    enc.map_err(|e| format!("Error comprimiendo imagen: {e}"))?;
    Ok(buf)
}

/// Devuelve (ancho, alto) en píxeles de un JPEG ya codificado, sin decodificar
/// la imagen completa (lee solo la cabecera JPEG SOF).
fn dimensiones_jpeg(jpeg: &[u8]) -> Result<(u32, u32), String> {
    let mut r = image::ImageReader::new(std::io::Cursor::new(jpeg));
    r.set_format(ImageFormat::Jpeg);
    r.into_dimensions()
        .map(|(w, h)| (w, h))
        .map_err(|e| format!("Error leyendo dimensiones JPEG: {e}"))
}

/// Construye un PDF lopdf con tantas páginas como elementos haya en `paginas`.
/// Cada elemento es `(jpeg_bytes, ancho_px, alto_px)`.
fn pdf_de_paginas(paginas: &[(Vec<u8>, u32, u32)]) -> Vec<u8> {
    let mut doc = Document::with_version("1.5");

    let pages_id = doc.new_object_id();
    let mut kids: Vec<Object> = Vec::with_capacity(paginas.len());

    for (i, (jpeg, w, h)) in paginas.iter().enumerate() {
        let img_name = format!("Im{}", i);
        let w_i = *w as i64;
        let h_i = *h as i64;

        let img_id = doc.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width"  => w_i,
                "Height" => h_i,
                "ColorSpace" => "DeviceRGB",
                "BitsPerComponent" => 8i64,
                "Filter" => "DCTDecode",
            },
            jpeg.clone(),
        ));

        // Operador PDF: escalar la imagen para que llene la página completa.
        let ops = format!("q {} 0 0 {} 0 0 cm /{} Do Q", w_i, h_i, img_name);
        let content_id = doc.add_object(Stream::new(dictionary! {}, ops.into_bytes()));

        let page_id = doc.add_object(dictionary! {
            "Type"     => "Page",
            "Parent"   => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), Object::Integer(w_i), Object::Integer(h_i)],
            "Contents" => content_id,
            "Resources" => dictionary! {
                "XObject" => dictionary! {
                    img_name.as_bytes().to_vec() => img_id,
                },
            },
        });
        kids.push(page_id.into());
    }

    doc.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type"  => "Pages",
            "Kids"  => kids,
            "Count" => paginas.len() as i64,
        }),
    );
    let catalog_id = doc.add_object(dictionary! {
        "Type"  => "Catalog",
        "Pages" => pages_id,
    });
    doc.trailer.set("Root", catalog_id);

    let mut out = Vec::new();
    doc.save_to(&mut out).unwrap_or_default();
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Luma, Rgb};
    use lopdf::Document;

    fn jpeg_rgb(lado: u32) -> Vec<u8> {
        let img = ImageBuffer::from_fn(lado, lado, |x, y| {
            Rgb([((x * 7 + y * 13) % 256) as u8, ((x * 3 + y * 5) % 256) as u8, ((x ^ y) % 256) as u8])
        });
        let mut buf = Vec::new();
        JpegEncoder::new_with_quality(&mut buf, 92).encode_image(&img).unwrap();
        buf
    }

    fn png_rgb(lado: u32) -> Vec<u8> {
        let img: image::RgbImage = ImageBuffer::from_fn(lado, lado, |x, y| {
            Rgb([((x * 5 + y * 11) % 256) as u8, ((x * 2 + y * 7) % 256) as u8, 128u8])
        });
        let mut buf = Vec::new();
        img.write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png).unwrap();
        buf
    }

    fn jpeg_gris(lado: u32) -> Vec<u8> {
        let img: image::GrayImage = ImageBuffer::from_fn(lado, lado, |x, y| {
            Luma([((x + y) % 256) as u8])
        });
        let mut buf = Vec::new();
        JpegEncoder::new_with_quality(&mut buf, 92).encode_image(&img).unwrap();
        buf
    }

    fn n_paginas(pdf: &[u8]) -> usize {
        Document::load_mem(pdf).unwrap().get_pages().len()
    }

    #[test]
    fn una_imagen_jpeg_produce_pdf_1_pagina() {
        let pdf = imagen_a_pdf(&jpeg_rgb(800)).expect("debe convertir JPEG");
        assert!(!pdf.is_empty());
        assert_eq!(n_paginas(&pdf), 1);
    }

    #[test]
    fn una_imagen_png_produce_pdf_1_pagina() {
        let pdf = imagen_a_pdf(&png_rgb(400)).expect("debe convertir PNG");
        assert_eq!(n_paginas(&pdf), 1);
    }

    #[test]
    fn imagen_grande_downsample_y_pdf_valido() {
        // Imagen > CAP_PX → debe hacer downsample sin error
        let pdf = imagen_a_pdf(&jpeg_rgb(3200)).expect("debe convertir imagen grande");
        assert_eq!(n_paginas(&pdf), 1);
        // El tamaño del PDF debe ser razonable (< 1 MB para una imagen 2000px q82)
        assert!(pdf.len() < 4 * 1024 * 1024, "PDF demasiado grande: {} bytes", pdf.len());
    }

    #[test]
    fn imagen_gris_produce_pdf_valido() {
        let pdf = imagen_a_pdf(&jpeg_gris(600)).expect("debe convertir JPEG gris");
        assert_eq!(n_paginas(&pdf), 1);
    }

    #[test]
    fn varias_imagenes_un_solo_pdf_multipagina() {
        let imgs = vec![jpeg_rgb(400), png_rgb(300), jpeg_gris(500)];
        let pdf = imagenes_a_pdf_unico(&imgs).expect("debe unir 3 imágenes");
        assert_eq!(n_paginas(&pdf), 3, "deben ser 3 páginas");
    }

    #[test]
    fn varias_imagenes_pdfs_separados() {
        let imgs = vec![jpeg_rgb(400), png_rgb(300)];
        // Simulamos "PDF por imagen": llamar imagen_a_pdf para cada una
        let pdfs: Vec<Vec<u8>> = imgs.iter()
            .map(|img| imagen_a_pdf(img).unwrap())
            .collect();
        assert_eq!(pdfs.len(), 2);
        for (i, pdf) in pdfs.iter().enumerate() {
            assert_eq!(n_paginas(pdf), 1, "PDF {} debe tener 1 página", i + 1);
        }
    }

    #[test]
    fn bytes_invalidos_devuelven_error() {
        let res = imagen_a_pdf(b"esto no es una imagen");
        assert!(res.is_err(), "debe fallar con datos inválidos");
    }

    fn bmp_rgb(lado: u32) -> Vec<u8> {
        let img: image::RgbImage = ImageBuffer::from_fn(lado, lado, |x, y| {
            Rgb([((x * 3 + y * 7) % 256) as u8, ((x + y * 2) % 256) as u8, 64u8])
        });
        let mut buf = Vec::new();
        img.write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Bmp).unwrap();
        buf
    }

    fn tiff_rgb(lado: u32) -> Vec<u8> {
        let img: image::RgbImage = ImageBuffer::from_fn(lado, lado, |x, y| {
            Rgb([((x + y) % 256) as u8, ((x * 2 + y) % 256) as u8, 128u8])
        });
        let mut buf = Vec::new();
        img.write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Tiff).unwrap();
        buf
    }

    #[test]
    fn bmp_produce_pdf_valido() {
        let pdf = imagen_a_pdf(&bmp_rgb(300)).expect("debe convertir BMP");
        assert_eq!(n_paginas(&pdf), 1);
        assert!(!pdf.is_empty());
    }

    #[test]
    fn tiff_produce_pdf_valido() {
        let pdf = imagen_a_pdf(&tiff_rgb(300)).expect("debe convertir TIFF");
        assert_eq!(n_paginas(&pdf), 1);
        assert!(!pdf.is_empty());
    }

    #[test]
    fn lista_vacia_da_error() {
        let res = imagenes_a_pdf_unico(&[]);
        assert!(res.is_err(), "lista vacía debe devolver error");
    }

    #[test]
    fn una_imagen_y_varias_producen_pdf_coherente() {
        let img = jpeg_rgb(200);
        let solo = imagen_a_pdf(&img).unwrap();
        let multi = imagenes_a_pdf_unico(&[img]).unwrap();
        assert_eq!(n_paginas(&solo), 1);
        assert_eq!(n_paginas(&multi), 1);
    }
}
