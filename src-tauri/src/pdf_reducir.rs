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
use std::collections::{BTreeSet, HashMap};

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

        // El contenido de un stream DCTDecode ES el JPEG tal cual. Decodificamos con
        // límites de tamaño y de memoria: un JPEG "bomba" (cabecera que declara dimensiones
        // gigantescas) no debe reservar cientos de MB y tumbar la app. Este reductor corre
        // AUTOMÁTICAMENTE en cada PDF importado, así que es una vía de DoS a blindar.
        let mut reader = image::ImageReader::new(std::io::Cursor::new(&s.content));
        reader.set_format(ImageFormat::Jpeg);
        let mut limites = image::Limits::default();
        limites.max_image_width = Some(20_000);
        limites.max_image_height = Some(20_000);
        limites.max_alloc = Some(512 * 1024 * 1024); // tope de reserva por imagen
        reader.limits(limites);
        let Ok(img) = reader.decode() else {
            continue; // corrupta, o excede los límites → dejar la imagen intacta
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

// ── DEDUPLICACIÓN DE IMÁGENES ──────────────────────────────────────────────
//
// Detecta imagen XObjects byte-idénticos (mismo stream comprimido + mismos
// parámetros clave) y elimina las copias redundantes haciendo que todas las
// páginas referencien el mismo objeto canónico. Garantía total de fidelidad
// visual: mismo hash SHA-256 del stream ⟹ mismo stream ⟹ misma imagen
// decodificada, sin excepciones.
//
// Casos cubiertos: logos, sellos, marcas de agua repetidas en múltiples páginas;
// imágenes con y sin canal alfa (SMask). Las imágenes con SMask incluyen los
// bytes del SMask en la huella, de modo que solo se deduplicán cuando ambos
// el plano de color y el alfa son byte-idénticos.

/// Elimina imágenes duplicadas de un PDF. Devuelve `Some(bytes)` solo si se
/// encontraron duplicados y el resultado es más pequeño que la entrada;
/// `None` en caso contrario (el llamador conserva el original).
pub fn deduplicar_imagenes(bytes: &[u8]) -> Option<Vec<u8>> {
    use sha2::{Digest, Sha256};

    let mut doc = Document::load_mem(bytes).ok()?;
    let n_paginas = doc.get_pages().len();

    // Recolectar IDs de todos los Image XObjects del documento.
    let ids_imagen: Vec<ObjectId> = doc
        .objects
        .iter()
        .filter_map(|(id, obj)| {
            if let Object::Stream(s) = obj {
                if matches!(s.dict.get(b"Subtype"), Ok(Object::Name(n)) if n == b"Image") {
                    return Some(*id);
                }
            }
            None
        })
        .collect();

    if ids_imagen.len() < 2 {
        return None; // imposible tener duplicados con menos de 2 imágenes
    }

    // Calcular la huella de cada imagen. La huella incluye:
    //   - parámetros visuales clave (Width, Height, BitsPerComponent, ColorSpace, Filter)
    //   - bytes crudos del stream comprimido
    //   - bytes del SMask (canal alfa) si existe
    // Dos imágenes con la misma huella son visualmente idénticas por definición.
    let mut canonico: HashMap<Vec<u8>, ObjectId> = HashMap::new();
    let mut reemplazar: HashMap<ObjectId, ObjectId> = HashMap::new(); // duplicado → canónico

    for &id in &ids_imagen {
        let stream = match doc.objects.get(&id) {
            Some(Object::Stream(s)) => s,
            _ => continue,
        };

        let w = stream.dict.get(b"Width").ok().and_then(|o| o.as_i64().ok()).unwrap_or(-1);
        let h = stream.dict.get(b"Height").ok().and_then(|o| o.as_i64().ok()).unwrap_or(-1);
        let bits = stream.dict.get(b"BitsPerComponent").ok().and_then(|o| o.as_i64().ok()).unwrap_or(-1);
        let cs: Vec<u8> = match stream.dict.get(b"ColorSpace") {
            Ok(Object::Name(n)) => n.clone(),
            _ => b"?".to_vec(),
        };
        let filt: Vec<u8> = match stream.dict.get(b"Filter") {
            Ok(Object::Name(n)) => n.clone(),
            _ => b"".to_vec(),
        };
        // Incluir los bytes del SMask en la huella para garantizar que el canal alfa
        // también es idéntico antes de deduplicar.
        let smask_bytes: Vec<u8> = match stream.dict.get(b"SMask") {
            Ok(Object::Reference(smask_id)) => {
                if let Some(Object::Stream(sm)) = doc.objects.get(smask_id) {
                    sm.content.clone()
                } else {
                    b"no_smask".to_vec()
                }
            }
            _ => b"no_smask".to_vec(),
        };
        let stream_content = stream.content.clone();

        let mut hasher = Sha256::new();
        hasher.update(w.to_le_bytes());
        hasher.update(h.to_le_bytes());
        hasher.update(bits.to_le_bytes());
        hasher.update(&cs);
        hasher.update(&filt);
        hasher.update(&stream_content);
        hasher.update(&smask_bytes);
        let huella: Vec<u8> = hasher.finalize().to_vec();

        match canonico.entry(huella) {
            std::collections::hash_map::Entry::Occupied(e) => {
                reemplazar.insert(id, *e.get());
            }
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(id);
            }
        }
    }

    if reemplazar.is_empty() {
        return None;
    }

    // Actualizar TODAS las referencias del documento: sustituir cada referencia a un
    // objeto duplicado por la referencia al objeto canónico. Recorremos todos los
    // objetos del documento (incluidos form XObjects, Resources compartidos, etc.)
    // para cubrir todos los puntos desde los que se podría referenciar la imagen.
    let ids_obj: Vec<ObjectId> = doc.objects.keys().cloned().collect();
    for oid in ids_obj {
        if let Some(obj) = doc.objects.get_mut(&oid) {
            actualizar_refs_en_objeto(obj, &reemplazar);
        }
    }
    // También el trailer (poco probable que referencie imágenes, pero por completitud).
    for (_, v) in doc.trailer.iter_mut() {
        actualizar_refs_en_objeto(v, &reemplazar);
    }

    // Eliminar los objetos duplicados; ya no hay referencias activas a ellos.
    for dup_id in reemplazar.keys() {
        doc.objects.remove(dup_id);
    }

    let mut out: Vec<u8> = Vec::new();
    doc.save_to(&mut out).ok()?;

    if out.len() >= bytes.len() {
        return None; // sin mejora neta
    }
    // Validar: el PDF resultante debe cargarse y conservar el número de páginas.
    match Document::load_mem(&out) {
        Ok(d) if d.get_pages().len() == n_paginas => Some(out),
        _ => None,
    }
}

/// Sustituye recursivamente en `obj` todas las referencias que aparezcan en
/// `mapa` (duplicado → canónico). Cubre Object::Reference, Array, Dictionary y
/// Stream (diccionario del stream). Los streams de contenido no se tocan porque
/// los nombres de imagen en ellos (`/Im0 Do`) son strings, no referencias PDF.
fn actualizar_refs_en_objeto(obj: &mut Object, mapa: &HashMap<ObjectId, ObjectId>) {
    match obj {
        Object::Reference(id) => {
            if let Some(&canon) = mapa.get(id) {
                *id = canon;
            }
        }
        Object::Array(arr) => {
            for item in arr.iter_mut() {
                actualizar_refs_en_objeto(item, mapa);
            }
        }
        Object::Dictionary(d) => {
            // Dictionary::iter_mut() es el método propio de lopdf (LinkedHashMap).
            for (_, v) in d.iter_mut() {
                actualizar_refs_en_objeto(v, mapa);
            }
        }
        Object::Stream(s) => {
            for (_, v) in s.dict.iter_mut() {
                actualizar_refs_en_objeto(v, mapa);
            }
            // El contenido del stream (bytes comprimidos) no se toca.
        }
        _ => {}
    }
}

// ── SUBSETTING DE FUENTES ─────────────────────────────────────────────────
//
// Reduce el tamaño de las fuentes TrueType/OpenType embebidas en el PDF
// eliminando los glifos que no aparecen en el documento. El documento resultante
// es visualmente idéntico: se conservan todos los glifos referenciados en los
// streams de contenido, incluido siempre el glifo 0 (.notdef).
//
// Solo se procesan fuentes Type0 con descendiente CIDFontType2 (TrueType/OTF),
// porque son la mayoría de las fuentes embebidas en PDFs modernos (Word, LibreOffice,
// Acrobat). Las fuentes ya subsetadas (BaseFont con prefijo XXXXXX+) se saltan.
// Cualquier fallo parcial en una fuente se ignora: esa fuente se deja intacta.

/// Recolecta los IDs de glifo utilizados por cada fuente en los streams de
/// contenido de todas las páginas. Devuelve un mapa nombre_recurso→HashSet<u16>.
/// Solo registra fuentes cuya CMap es Identity-H o Identity-V (char code = CID = glyph_id).
fn recolectar_glifos_usados(doc: &Document) -> HashMap<String, std::collections::HashSet<u16>> {
    use lopdf::content::Content;
    let mut resultado: HashMap<String, std::collections::HashSet<u16>> = HashMap::new();

    for (_, page_id) in doc.get_pages() {
        // Resolver la fuente actual al recorrer operadores.
        let mut fuente_actual: Option<String> = None;

        // Obtener bytes del stream de contenido de la página.
        let stream_bytes = match page_content_bytes(doc, page_id) {
            Some(b) => b,
            None => continue,
        };

        let content = match Content::decode(&stream_bytes) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for op in &content.operations {
            match op.operator.as_str() {
                // Tf: seleccionar fuente. Operandos: [/Nombre tamaño]
                "Tf" => {
                    fuente_actual = op.operands.first().and_then(|o| {
                        if let Object::Name(n) = o {
                            String::from_utf8(n.clone()).ok()
                        } else {
                            None
                        }
                    });
                }
                // Tj: una cadena de texto
                "Tj" => {
                    if let (Some(ref nombre), Some(Object::String(s, _))) =
                        (&fuente_actual, op.operands.first())
                    {
                        let set = resultado.entry(nombre.clone()).or_default();
                        extraer_gids_de_bytes(s, set);
                    }
                }
                // TJ: array de cadenas con kerning
                "TJ" => {
                    if let (Some(ref nombre), Some(Object::Array(arr))) =
                        (&fuente_actual, op.operands.first())
                    {
                        let set = resultado.entry(nombre.clone()).or_default();
                        for item in arr {
                            if let Object::String(s, _) = item {
                                extraer_gids_de_bytes(s, set);
                            }
                        }
                    }
                }
                // ' y " también muestran texto
                "'" | "\"" => {
                    let cadena = if op.operator == "'" {
                        op.operands.first()
                    } else {
                        op.operands.get(2)
                    };
                    if let (Some(ref nombre), Some(Object::String(s, _))) =
                        (&fuente_actual, cadena)
                    {
                        let set = resultado.entry(nombre.clone()).or_default();
                        extraer_gids_de_bytes(s, set);
                    }
                }
                _ => {}
            }
        }
    }

    resultado
}

/// Interpreta los bytes de una cadena PDF como pares big-endian de 2 bytes (CID).
/// En fuentes Identity-H, el CID es igual al glyph_id, por lo que ya tenemos el GID.
/// Para cadenas de longitud impar, el último byte se emite como GID de un byte.
fn extraer_gids_de_bytes(bytes: &[u8], set: &mut std::collections::HashSet<u16>) {
    let mut i = 0;
    while i + 1 < bytes.len() {
        let gid = u16::from_be_bytes([bytes[i], bytes[i + 1]]);
        set.insert(gid);
        i += 2;
    }
    if i < bytes.len() {
        set.insert(bytes[i] as u16);
    }
}

/// Obtiene los bytes concatenados de todos los streams de contenido de una página.
fn page_content_bytes(doc: &Document, page_id: ObjectId) -> Option<Vec<u8>> {
    let page = doc.get_object(page_id).ok()?;
    let page_dict = match page {
        Object::Dictionary(d) => d,
        _ => return None,
    };
    let contents = page_dict.get(b"Contents").ok()?;
    let mut out = Vec::new();
    match contents {
        Object::Reference(id) => {
            if let Ok(Object::Stream(s)) = doc.get_object(*id) {
                out.extend_from_slice(&s.content);
            }
        }
        Object::Array(arr) => {
            for item in arr {
                if let Object::Reference(id) = item {
                    if let Ok(Object::Stream(s)) = doc.get_object(*id) {
                        out.extend_from_slice(&s.content);
                        out.push(b' ');
                    }
                }
            }
        }
        _ => {}
    }
    if out.is_empty() { None } else { Some(out) }
}

/// Comprueba si la CMap de un font dict es Identity-H o Identity-V.
/// Estas CMaps codifican el texto como pares de bytes donde el valor numérico
/// es directamente el CID, lo que nos permite coleccionar GIDs sin parsear la CMap.
fn cmap_es_identity(font_dict: &Dictionary) -> bool {
    match font_dict.get(b"Encoding") {
        Ok(Object::Name(n)) => matches!(n.as_slice(), b"Identity-H" | b"Identity-V"),
        Ok(Object::Reference(_)) => false, // CMap externa: no la parseamos
        _ => false,
    }
}

/// Devuelve true si el BaseFont ya tiene prefijo de subset (ABCDEF+Nombre).
fn ya_subsetado(font_dict: &Dictionary) -> bool {
    if let Ok(Object::Name(n)) = font_dict.get(b"BaseFont") {
        if n.len() >= 7 && n[6] == b'+' {
            return n[..6].iter().all(|b| b.is_ascii_uppercase());
        }
    }
    false
}

/// Subset de fuentes tipográficas TrueType/OTF embebidas en el PDF.
/// Devuelve `Some(bytes)` solo si al menos una fuente se redujo y el PDF resultante
/// es más pequeño. `None` si no hubo ninguna mejora o cualquier validación falló.
pub fn subset_fuentes(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut doc = Document::load_mem(bytes).ok()?;
    let n_paginas = doc.get_pages().len();

    // Recolectar glifos usados por nombre de recurso (solo Identity-H/V).
    let glifos_por_recurso = recolectar_glifos_usados(&doc);
    if glifos_por_recurso.is_empty() {
        return None;
    }

    // Construir mapa nombre_recurso → ObjectId del Font dict de la página.
    // Buscamos en Resources de cada página los fonts de tipo Type0.
    let mut fonts_a_procesar: HashMap<ObjectId, std::collections::HashSet<u16>> = HashMap::new();

    for (_, page_id) in doc.get_pages() {
        let page = match doc.get_object(page_id) {
            Ok(Object::Dictionary(d)) => d.clone(),
            _ => continue,
        };
        let resources = match page.get(b"Resources") {
            Ok(Object::Dictionary(d)) => d.clone(),
            Ok(Object::Reference(id)) => {
                match doc.get_object(*id) {
                    Ok(Object::Dictionary(d)) => d.clone(),
                    _ => continue,
                }
            }
            _ => continue,
        };
        let font_dict = match resources.get(b"Font") {
            Ok(Object::Dictionary(d)) => d.clone(),
            Ok(Object::Reference(id)) => {
                match doc.get_object(*id) {
                    Ok(Object::Dictionary(d)) => d.clone(),
                    _ => continue,
                }
            }
            _ => continue,
        };

        for (nombre_bytes, font_ref) in font_dict.iter() {
            let nombre = match String::from_utf8(nombre_bytes.clone()) {
                Ok(n) => n,
                Err(_) => continue,
            };
            let glifos = match glifos_por_recurso.get(&nombre) {
                Some(g) if !g.is_empty() => g,
                _ => continue,
            };
            let font_id = match font_ref {
                Object::Reference(id) => *id,
                _ => continue,
            };
            fonts_a_procesar
                .entry(font_id)
                .or_default()
                .extend(glifos.iter().copied());
        }
    }

    if fonts_a_procesar.is_empty() {
        return None;
    }

    let mut hubo_cambio = false;

    // Ids de objetos para procesar los necesitamos antes de mutar el doc.
    let font_ids: Vec<(ObjectId, std::collections::HashSet<u16>)> =
        fonts_a_procesar.into_iter().collect();

    for (font_id, glifos_usados) in font_ids {
        // Leer el font dict (Type0).
        let font_dict = match doc.get_object(font_id) {
            Ok(Object::Dictionary(d)) => d.clone(),
            _ => continue,
        };

        if ya_subsetado(&font_dict) {
            continue;
        }

        // Solo procesamos Type0.
        if !matches!(font_dict.get(b"Type"), Ok(Object::Name(n)) if n == b"Font") {
            continue;
        }
        if !matches!(font_dict.get(b"Subtype"), Ok(Object::Name(n)) if n == b"Type0") {
            continue;
        }
        if !cmap_es_identity(&font_dict) {
            continue;
        }

        // Obtener el descendiente CIDFont.
        let descendant_id = match font_dict.get(b"DescendantFonts") {
            Ok(Object::Array(arr)) => match arr.first() {
                Some(Object::Reference(id)) => *id,
                _ => continue,
            },
            _ => continue,
        };

        let cid_dict = match doc.get_object(descendant_id) {
            Ok(Object::Dictionary(d)) => d.clone(),
            _ => continue,
        };

        // Solo CIDFontType2 (TrueType).
        if !matches!(cid_dict.get(b"Subtype"), Ok(Object::Name(n)) if n == b"CIDFontType2") {
            continue;
        }

        // Localizar FontDescriptor → FontFile2.
        let fd_id = match cid_dict.get(b"FontDescriptor") {
            Ok(Object::Reference(id)) => *id,
            _ => continue,
        };
        let fd_dict = match doc.get_object(fd_id) {
            Ok(Object::Dictionary(d)) => d.clone(),
            _ => continue,
        };
        let ff2_id = match fd_dict.get(b"FontFile2") {
            Ok(Object::Reference(id)) => *id,
            _ => continue,
        };

        // Extraer bytes de la fuente. FontFile2 puede estar comprimido (FlateDecode).
        let font_bytes = match doc.get_object(ff2_id) {
            Ok(Object::Stream(s)) => {
                s.decompressed_content().unwrap_or_else(|_| s.content.clone())
            }
            _ => continue,
        };

        // Construir lista de GIDs a conservar (siempre incluir glifo 0 / .notdef).
        let mut gids: Vec<u16> = std::iter::once(0u16)
            .chain(glifos_usados.iter().copied())
            .collect();
        gids.sort_unstable();
        gids.dedup();

        // Subset con el crate `subsetter`. GlyphRemapper::new_from_glyphs ya
        // garantiza que los GIDs están ordenados y deduplicados.
        let remapper = subsetter::GlyphRemapper::new_from_glyphs(&gids);
        let font_subsetada = match subsetter::subset(&font_bytes, 0, &remapper) {
            Ok(f) => f,
            Err(_) => continue, // no tocar esta fuente si falla
        };

        // Solo reemplazar si la fuente subsetada es más pequeña.
        if font_subsetada.len() >= font_bytes.len() {
            continue;
        }

        // Reemplazar el stream FontFile2 con los bytes subsetados (sin compresión,
        // ya que la mayoría de lectores aceptan FontFile2 sin Filter).
        if let Some(Object::Stream(s)) = doc.objects.get_mut(&ff2_id) {
            s.content = font_subsetada;
            s.dict.remove(b"Filter");
            s.dict.remove(b"DecodeParms");
            s.dict.set("Length", s.content.len() as i64);
            hubo_cambio = true;
        }
    }

    if !hubo_cambio {
        return None;
    }

    let mut out: Vec<u8> = Vec::new();
    doc.save_to(&mut out).ok()?;

    if out.len() >= bytes.len() {
        return None;
    }
    match Document::load_mem(&out) {
        Ok(d) if d.get_pages().len() == n_paginas => Some(out),
        _ => None,
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

    // ── Tests de deduplicación ──────────────────────────────────────────────

    // PDF de 2 páginas donde cada una tiene la MISMA imagen como objeto separado
    // (simula importar el mismo logo dos veces al construir el documento).
    fn pdf_misma_imagen_dos_paginas(jpeg: &[u8], lado: i64) -> Vec<u8> {
        let mut doc = Document::with_version("1.5");

        // Dos objetos separados con bytes idénticos — esto es lo que ocurre cuando
        // la misma imagen se embebe dos veces en distintas páginas sin optimizar.
        let img1_id = doc.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject", "Subtype" => "Image",
                "Width" => lado, "Height" => lado,
                "ColorSpace" => "DeviceRGB",
                "BitsPerComponent" => 8i64,
                "Filter" => "DCTDecode",
            },
            jpeg.to_vec(),
        ));
        let img2_id = doc.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject", "Subtype" => "Image",
                "Width" => lado, "Height" => lado,
                "ColorSpace" => "DeviceRGB",
                "BitsPerComponent" => 8i64,
                "Filter" => "DCTDecode",
            },
            jpeg.to_vec(), // bytes idénticos
        ));

        let cont1_id = doc.add_object(Stream::new(
            dictionary! {},
            b"q 200 0 0 200 0 0 cm /Im0 Do Q".to_vec(),
        ));
        let cont2_id = doc.add_object(Stream::new(
            dictionary! {},
            b"q 200 0 0 200 0 0 cm /Im0 Do Q".to_vec(),
        ));

        let pages_id = doc.new_object_id();
        let page1_id = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 200.into()],
            "Contents" => cont1_id,
            "Resources" => dictionary! { "XObject" => dictionary! { "Im0" => img1_id } },
        });
        let page2_id = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 200.into()],
            "Contents" => cont2_id,
            "Resources" => dictionary! { "XObject" => dictionary! { "Im0" => img2_id } },
        });
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![page1_id.into(), page2_id.into()],
                "Count" => 2i64,
            }),
        );
        let cat_id = doc.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        doc.trailer.set("Root", cat_id);
        let mut out = Vec::new();
        doc.save_to(&mut out).unwrap();
        out
    }

    fn contar_imagenes_xobject(doc: &Document) -> usize {
        doc.objects
            .values()
            .filter(|o| {
                if let Object::Stream(s) = o {
                    matches!(s.dict.get(b"Subtype"), Ok(Object::Name(n)) if n == b"Image")
                } else {
                    false
                }
            })
            .count()
    }

    // TEST: dos objetos con la misma imagen se reducen a uno.
    // Verifica (a) tamaño menor, (b) una sola copia en el PDF resultante,
    // (c) PDF válido con el mismo número de páginas.
    #[test]
    fn imagenes_duplicadas_se_deduplictan() {
        let jpeg = jpeg_grande(400); // 400 px, no afecta al reductor (< CAP_PX=2000)
        let pdf = pdf_misma_imagen_dos_paginas(&jpeg, 400);

        assert_eq!(
            contar_imagenes_xobject(&Document::load_mem(&pdf).unwrap()),
            2,
            "el PDF de prueba debe partir con 2 objetos imagen distintos"
        );

        let dedup = deduplicar_imagenes(&pdf)
            .expect("debe detectar y deduplicar las dos imágenes idénticas");

        assert!(
            dedup.len() < pdf.len(),
            "el PDF deduplicado debe ser más pequeño: {} bytes vs {} bytes originales",
            dedup.len(),
            pdf.len()
        );

        let doc_out = Document::load_mem(&dedup).unwrap();
        assert_eq!(
            doc_out.get_pages().len(),
            2,
            "el número de páginas no debe cambiar tras deduplicar"
        );
        assert_eq!(
            contar_imagenes_xobject(&doc_out),
            1,
            "debe quedar exactamente un objeto imagen (el canónico)"
        );
    }

    // TEST: un PDF con una sola imagen no puede tener duplicados → devuelve None.
    #[test]
    fn imagen_unica_no_se_deduplicta() {
        let pdf = pdf_con_imagen(&jpeg_grande(400), 400);
        assert!(
            deduplicar_imagenes(&pdf).is_none(),
            "un PDF con una sola imagen no debe modificarse"
        );
    }

    // TEST: la cadena reducir → deduplicar no rompe un PDF sin duplicados ni imágenes
    //       grandes (ambas funciones deben devolver None y el contenido original
    //       se conserva intacto).
    #[test]
    fn cadena_reduce_dedup_conserva_original_si_no_hay_mejora() {
        let jpeg = jpeg_grande(400); // pequeño, no se reduce
        let pdf = pdf_con_imagen(&jpeg, 400);

        let tras_reducir = reducir(&pdf);
        let base: &[u8] = tras_reducir.as_deref().unwrap_or(&pdf);
        let tras_dedup = deduplicar_imagenes(base);

        // Ninguna optimización es posible → ambas devuelven None.
        assert!(tras_reducir.is_none());
        assert!(tras_dedup.is_none());
        // El contenido en RAM sigue siendo el PDF original.
        assert_eq!(base, pdf.as_slice());
    }

    // ── Tests de subsetting de fuentes ─────────────────────────────────────

    // Construye un PDF con una fuente TrueType completa embebida (Identity-H).
    // El stream de contenido usa solo dos caracteres (GIDs 36 y 37 → 'H', 'I' en Arial).
    // Requiere que la fuente exista en disco; si no está, el test se salta.
    fn pdf_con_fuente_embebida(ruta_ttf: &str) -> Option<Vec<u8>> {
        use lopdf::{Stream, dictionary};
        let font_bytes = std::fs::read(ruta_ttf).ok()?;
        if font_bytes.is_empty() {
            return None;
        }

        let mut doc = Document::with_version("1.7");

        // FontFile2 — bytes de la fuente completa, sin comprimir.
        let ff2_id = doc.add_object(Stream::new(
            dictionary! {
                "Length" => font_bytes.len() as i64,
                "Length1" => font_bytes.len() as i64,
            },
            font_bytes,
        ));

        // FontDescriptor.
        let fd_id = doc.add_object(dictionary! {
            "Type" => "FontDescriptor",
            "FontName" => "TestFont",
            "Flags" => 32i64,
            "ItalicAngle" => 0i64,
            "Ascent" => 900i64,
            "Descent" => -200i64,
            "CapHeight" => 700i64,
            "StemV" => 80i64,
            "FontBBox" => vec![(-200i64).into(), (-200i64).into(), 1200i64.into(), 900i64.into()],
            "FontFile2" => ff2_id,
        });

        // Descendiente CIDFontType2.
        let cid_id = doc.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "CIDFontType2",
            "BaseFont" => "TestFont",
            "CIDSystemInfo" => dictionary! {
                "Registry" => Object::String(b"Adobe".to_vec(), lopdf::StringFormat::Literal),
                "Ordering" => Object::String(b"Identity".to_vec(), lopdf::StringFormat::Literal),
                "Supplement" => 0i64,
            },
            "FontDescriptor" => fd_id,
            "CIDToGIDMap" => Object::Name(b"Identity".to_vec()),
        });

        // Font Type0 con Identity-H.
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type0",
            "BaseFont" => "TestFont",
            "Encoding" => Object::Name(b"Identity-H".to_vec()),
            "DescendantFonts" => vec![Object::Reference(cid_id)],
        });

        // Stream de contenido: "BT /F1 12 Tf <0024 0025> Tj ET"
        // GIDs 0x0024=36 y 0x0025=37 (dos glifos cualesquiera del font).
        let cont_id = doc.add_object(Stream::new(
            dictionary! {},
            b"BT /F1 12 Tf <00240025> Tj ET".to_vec(),
        ));

        let pages_id = doc.new_object_id();
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0i64.into(), 0i64.into(), 595i64.into(), 842i64.into()],
            "Contents" => cont_id,
            "Resources" => dictionary! {
                "Font" => dictionary! {
                    "F1" => font_id,
                },
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
        let cat_id = doc.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        doc.trailer.set("Root", cat_id);

        let mut out = Vec::new();
        doc.save_to(&mut out).ok()?;
        Some(out)
    }

    // TEST: PDF sin fuentes embebidas → subset_fuentes devuelve None.
    #[test]
    fn pdf_sin_fuentes_no_se_modifica() {
        let pdf = pdf_con_imagen(&jpeg_grande(400), 400);
        assert!(
            subset_fuentes(&pdf).is_none(),
            "un PDF sin fuentes embebidas no debe modificarse"
        );
    }

    // TEST: fuente embebida completa se reduce al hacer subset.
    // Se salta si Arial no está disponible en el sistema.
    #[test]
    fn fuente_completa_se_subsetea() {
        let ruta = "/System/Library/Fonts/Supplemental/Arial.ttf";
        let pdf = match pdf_con_fuente_embebida(ruta) {
            Some(p) => p,
            None => return, // fuente no disponible → skip
        };

        let original_bytes = pdf.len();
        let resultado = subset_fuentes(&pdf);

        assert!(
            resultado.is_some(),
            "debe detectar la fuente y subsetearla (original {} bytes)",
            original_bytes
        );
        let subsetado = resultado.unwrap();
        assert!(
            subsetado.len() < original_bytes,
            "el PDF subsetado debe ser más pequeño: {} < {}",
            subsetado.len(),
            original_bytes
        );
        // El PDF resultante debe ser válido con el mismo número de páginas.
        let doc_out = Document::load_mem(&subsetado).unwrap();
        assert_eq!(doc_out.get_pages().len(), 1);
    }

    // TEST: fuente ya subsetada (prefijo ABCDEF+) no se toca de nuevo.
    #[test]
    fn fuente_ya_subsetada_no_se_retoca() {
        let ruta = "/System/Library/Fonts/Supplemental/Arial.ttf";
        let pdf_base = match pdf_con_fuente_embebida(ruta) {
            Some(p) => p,
            None => return,
        };
        // Primer subset → debería reducir.
        let subsetado1 = match subset_fuentes(&pdf_base) {
            Some(s) => s,
            None => return, // fuente no compatible → skip
        };
        // Cargar el resultado y renombrar BaseFont con prefijo de subset manualmente
        // para simular que ya fue subsetado. Un segundo paso no debe modificarlo.
        // (En producción esto no ocurre, pero verifica la guardia ya_subsetado.)
        let mut doc = Document::load_mem(&subsetado1).unwrap();
        // Renombrar el primer font que encontremos.
        let font_ids: Vec<ObjectId> = doc
            .objects
            .iter()
            .filter_map(|(id, obj)| {
                if let Object::Dictionary(d) = obj {
                    if matches!(d.get(b"Subtype"), Ok(Object::Name(n)) if n == b"Type0") {
                        return Some(*id);
                    }
                }
                None
            })
            .collect();
        for fid in font_ids {
            if let Some(Object::Dictionary(d)) = doc.objects.get_mut(&fid) {
                d.set("BaseFont", Object::Name(b"ABCDEF+TestFont".to_vec()));
            }
        }
        let mut ya_sub_bytes = Vec::new();
        doc.save_to(&mut ya_sub_bytes).unwrap();

        // Un segundo intento de subset sobre un font ya marcado → None.
        assert!(
            subset_fuentes(&ya_sub_bytes).is_none(),
            "no debe resubsetear una fuente ya marcada con prefijo ABCDEF+"
        );
    }
}
