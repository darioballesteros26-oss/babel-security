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

// ── COMPRESIÓN DE ÚLTIMA GENERACIÓN DE IMÁGENES ───────────────────────────
//
// Cuarta etapa de la pipeline. Actúa sobre imágenes almacenadas en crudo
// (sin filtro o FlateDecode sin predictor) que las etapas anteriores no han
// tocado (reducir solo maneja DCTDecode sobredimensionados).
//
// • B/N puro (todos los píxeles exactamente 0 ó 255): convierte a 1 bit/px
//   + FlateDecode. Equivalente funcional a JBIG2 en Rust estable; el PDF
//   resultante es válido en todos los lectores. NOTA: PDF no admite WebP,
//   AVIF ni JPEG XL como filtros de stream (la spec fija DCTDecode,
//   JPXDecode, FlateDecode, CCITTFaxDecode, JBIG2Decode); la conversión
//   1-bit FlateDecode es la alternativa nativa más compacta disponible.
// • Color o escala de grises: re-encoda como JPEG a calidad 85 (DCTDecode).
//   Sin pérdida perceptible por encima de calidad 80.
//
// Garantías: nunca reemplaza si no mejora el tamaño, no toca máscaras,
// no toca imágenes con predictor activo (riesgo de corrupción), valida
// el PDF resultante con nº de páginas antes de aceptarlo.

struct CandImagen {
    id: ObjectId,
    w: u32,
    h: u32,
    canales: u8, // 1 = DeviceGray, 3 = DeviceRGB
    pixels: Vec<u8>,
    original_len: usize,
}

pub fn comprimir_imagenes(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut doc = Document::load_mem(bytes).ok()?;
    let n_paginas = doc.get_pages().len();

    // Recopilar IDs de máscaras para no tocarlas (canal alfa / transparencia).
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

    // Primera pasada: recopilar candidatos (clonamos lo que necesitamos para
    // no mantener referencias inmutables al mutar doc después).
    let mut candidatos: Vec<CandImagen> = Vec::new();

    for (id, obj) in &doc.objects {
        if mascaras.contains(id) {
            continue;
        }
        let Object::Stream(s) = obj else { continue };
        if !es_imagen(&s.dict) || es_image_mask(&s.dict) {
            continue;
        }
        // DCTDecode → ya lo gestiona `reducir`.
        if filtro_es_dct(&s.dict) {
            continue;
        }
        // CCITTFaxDecode / JBIG2Decode → ya optimizados para B/N.
        if filtro_es_ccitt_o_jbig2(&s.dict) {
            continue;
        }
        // Solo FlateDecode sin predictor, o sin filtro (píxeles crudos).
        let tiene_flate = filtro_es_flate(&s.dict);
        let sin_filtro = filtro_es_ninguno(&s.dict);
        if !tiene_flate && !sin_filtro {
            continue;
        }
        // Predictor activo: decompressed_content() no unaplicaría el predictor.
        if tiene_predictor(&s.dict) {
            continue;
        }

        let w = match s.dict.get(b"Width").ok().and_then(|o| o.as_i64().ok()) {
            Some(v) if v > 0 => v as u32,
            _ => continue,
        };
        let h = match s.dict.get(b"Height").ok().and_then(|o| o.as_i64().ok()) {
            Some(v) if v > 0 => v as u32,
            _ => continue,
        };
        let bpc = s.dict.get(b"BitsPerComponent").ok()
            .and_then(|o| o.as_i64().ok())
            .unwrap_or(8);
        if bpc != 8 {
            continue; // 1-bit y 16-bit se dejan intactos
        }
        let canales: u8 = match s.dict.get(b"ColorSpace") {
            Ok(Object::Name(n)) => match n.as_slice() {
                b"DeviceGray" => 1,
                b"DeviceRGB" => 3,
                _ => continue, // CMYK, Indexed u otros: no tocar
            },
            _ => continue,
        };
        // Ignorar imágenes con Decode array personalizado (puede invertir colores).
        if s.dict.get(b"Decode").is_ok() {
            continue;
        }

        let original_len = s.content.len();
        // Umbral mínimo: imágenes muy pequeñas no compensan el esfuerzo.
        if original_len < 4096 {
            continue;
        }
        // Anti-bomba: límite de reserva de memoria (mismo que en `reducir`).
        let tam_raw = w as usize * h as usize * canales as usize;
        if tam_raw > 512 * 1024 * 1024 {
            continue;
        }

        let pixels: Vec<u8> = if sin_filtro {
            s.content.clone()
        } else {
            // FlateDecode: descomprimir.
            match s.decompressed_content() {
                Ok(p) => p,
                Err(_) => continue,
            }
        };

        // Verificar que el tamaño coincide con los metadatos (detecta predictores
        // ocultos o streams corruptos antes de intentar recomprimir).
        if pixels.len() != tam_raw {
            continue;
        }

        candidatos.push(CandImagen { id: *id, w, h, canales, pixels, original_len });
    }

    if candidatos.is_empty() {
        return None;
    }

    let mut cambiado = false;

    for cand in candidatos {
        let es_bw = cand.canales == 1 && pixels_son_binarios(&cand.pixels);

        let (nuevo_content, nuevo_filtro, nuevo_bpc) = if es_bw {
            // 1 bit/px + FlateDecode — equivalente a JBIG2 en soporte universal.
            let packed = pack_1bit(&cand.pixels, cand.w, cand.h);
            let compressed = match zlib_comprimir(&packed) {
                Some(c) => c,
                None => continue,
            };
            (compressed, b"FlateDecode" as &[u8], 1i64)
        } else {
            // Re-encodar como JPEG q85 (sin pérdida perceptible).
            let mut buf: Vec<u8> = Vec::new();
            let ok = if cand.canales == 1 {
                match image::GrayImage::from_raw(cand.w, cand.h, cand.pixels.clone()) {
                    Some(img) => {
                        JpegEncoder::new_with_quality(&mut buf, 85).encode_image(&img).is_ok()
                    }
                    None => false,
                }
            } else {
                match image::RgbImage::from_raw(cand.w, cand.h, cand.pixels.clone()) {
                    Some(img) => {
                        JpegEncoder::new_with_quality(&mut buf, 85).encode_image(&img).is_ok()
                    }
                    None => false,
                }
            };
            if !ok {
                continue;
            }
            (buf, b"DCTDecode" as &[u8], 8i64)
        };

        // Solo reemplazar si el nuevo contenido es genuinamente más pequeño.
        if nuevo_content.len() + 32 >= cand.original_len {
            continue;
        }

        if let Some(Object::Stream(s)) = doc.objects.get_mut(&cand.id) {
            s.dict.remove(b"Filter");
            s.dict.remove(b"DecodeParms");
            s.dict.remove(b"DecodeParams");
            s.dict.set("Filter", Object::Name(nuevo_filtro.to_vec()));
            s.dict.set("BitsPerComponent", nuevo_bpc);
            s.set_content(nuevo_content);
            cambiado = true;
        }
    }

    if !cambiado {
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

fn filtro_es_ccitt_o_jbig2(d: &Dictionary) -> bool {
    match d.get(b"Filter") {
        Ok(Object::Name(n)) => {
            matches!(n.as_slice(), b"CCITTFaxDecode" | b"JBIG2Decode")
        }
        Ok(Object::Array(a)) => a.iter().any(|item| {
            matches!(item, Object::Name(n) if matches!(n.as_slice(), b"CCITTFaxDecode" | b"JBIG2Decode"))
        }),
        _ => false,
    }
}

fn filtro_es_flate(d: &Dictionary) -> bool {
    match d.get(b"Filter") {
        Ok(Object::Name(n)) => n == b"FlateDecode",
        Ok(Object::Array(a)) => {
            a.len() == 1 && matches!(&a[0], Object::Name(n) if n == b"FlateDecode")
        }
        _ => false,
    }
}

fn filtro_es_ninguno(d: &Dictionary) -> bool {
    d.get(b"Filter").is_err()
}

fn tiene_predictor(d: &Dictionary) -> bool {
    let check_parms = |parms: &Dictionary| -> bool {
        matches!(parms.get(b"Predictor"), Ok(o) if o.as_i64().unwrap_or(1) > 1)
    };
    match d.get(b"DecodeParms") {
        Ok(Object::Dictionary(parms)) => check_parms(parms),
        Ok(Object::Array(arr)) => arr.iter().any(|item| {
            if let Object::Dictionary(parms) = item { check_parms(parms) } else { false }
        }),
        _ => false,
    }
}

/// Devuelve `true` si todos los píxeles son negro puro o blanco puro, o ruido de
/// cuantización imperceptible (≤16 = "prácticamente negro", ≥239 = "prácticamente blanco").
/// El umbral captura documentos legales/notariales escaneados que salen del escáner con
/// valores 2-12 en zonas negras y 243-253 en zonas blancas, en lugar de los 0/255 exactos
/// que solo produce imagen sintética. pack_1bit binariza cualquier valor ≤127 a negro y
/// >127 a blanco, así que la conversión es visualmente idéntica al original.
fn pixels_son_binarios(pixels: &[u8]) -> bool {
    pixels.iter().all(|&p| p <= 16 || p >= 239)
}

/// Empaqueta píxeles 8-bit B/N en formato 1-bit MSB-first (convención PDF):
/// 0=negro → bit 0, 255=blanco → bit 1.
fn pack_1bit(pixels: &[u8], w: u32, h: u32) -> Vec<u8> {
    let row_bytes = (w as usize + 7) / 8;
    let mut out = vec![0u8; row_bytes * h as usize];
    for row in 0..h as usize {
        for col in 0..w as usize {
            let px = pixels[row * w as usize + col];
            let bit = if px > 127 { 1u8 } else { 0u8 };
            let byte_idx = row * row_bytes + col / 8;
            let bit_pos = 7 - (col % 8); // MSB first
            out[byte_idx] |= bit << bit_pos;
        }
    }
    out
}

fn zlib_comprimir(data: &[u8]) -> Option<Vec<u8>> {
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
    enc.write_all(data).ok()?;
    enc.finish().ok()
}

// ── COMPRESIÓN DE IMÁGENES EN DOCX ────────────────────────────────────────
//
// Un DOCX es un ZIP con archivos XML + recursos en word/media/. Las imágenes
// ahí embebidas son JPEG o PNG ya comprimidos, pero a menudo sobredimensionados
// (capturas de pantalla, fotos de cámara sin reducir). Esta función aplica la
// misma lógica de downsampling que `reducir` pero sobre el ZIP de DOCX:
//   - Solo toca JPEG en word/media/, ppt/media/ y xl/media/.
//   - Imágenes con lado > CAP_PX se reducen a CAP_PX con Lanczos3 + q82.
//   - Las imágenes ya pequeñas y el resto de archivos se copian sin modificar.
//   - El resultado solo se acepta si es más pequeño que la entrada.

/// Reduce el peso de un DOCX (o PPTX/XLSX) re-encodando sus imágenes JPEG grandes.
/// Devuelve `Some(bytes)` solo si el resultado es más pequeño; `None` en caso contrario.
pub fn reducir_docx(bytes: &[u8]) -> Option<Vec<u8>> {
    use std::io::{Cursor, Read, Write};

    let mut archivo = zip::ZipArchive::new(Cursor::new(bytes)).ok()?;
    let mut escritor = zip::ZipWriter::new(Cursor::new(Vec::with_capacity(bytes.len())));
    let mut cambiado = false;

    for i in 0..archivo.len() {
        // Leer nombre y, si es JPEG media, el contenido — en un solo borrow del archivo.
        let (nombre, contenido_jpeg) = {
            let mut entrada = archivo.by_index(i).ok()?;
            let nombre = entrada.name().to_string();
            let contenido = if es_jpeg_media(&nombre) {
                let mut c = Vec::new();
                entrada.read_to_end(&mut c).ok()?;
                Some(c)
            } else {
                None
            };
            (nombre, contenido)
        }; // ZipFile liberado aquí → archivo libre de nuevo

        if let Some(jpeg) = contenido_jpeg {
            let datos: Vec<u8> = match reducir_jpeg_raw(&jpeg) {
                Some(c) if c.len() + 32 < jpeg.len() => { cambiado = true; c }
                _ => jpeg,
            };
            // JPEG ya está comprimido: guardarlo como Stored en el ZIP evita la
            // doble compresión y es lo que hace Office por defecto con imágenes.
            let opciones = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            escritor.start_file(&nombre, opciones).ok()?;
            escritor.write_all(&datos).ok()?;
        } else {
            // Copiar el resto de archivos en crudo sin re-comprimir: más rápido y
            // preserva metadatos, fechas y la compresión original del ZIP.
            let entrada_raw = archivo.by_index_raw(i).ok()?;
            escritor.raw_copy_file(entrada_raw).ok()?;
        }
    }

    if !cambiado {
        return None;
    }

    let salida = escritor.finish().ok()?.into_inner();
    if salida.len() >= bytes.len() {
        return None;
    }
    // Validar que el resultado sigue siendo un ZIP legible.
    if zip::ZipArchive::new(Cursor::new(&salida)).is_err() {
        return None;
    }
    Some(salida)
}

/// Verdadero si la entrada del ZIP es una imagen JPEG en la carpeta media de
/// cualquier tipo de documento Office (Word, PowerPoint, Excel).
fn es_jpeg_media(nombre: &str) -> bool {
    let n = nombre.to_ascii_lowercase();
    (n.starts_with("word/media/") || n.starts_with("ppt/media/") || n.starts_with("xl/media/"))
        && (n.ends_with(".jpg") || n.ends_with(".jpeg"))
}

/// Intenta reducir bytes JPEG crudos usando la misma lógica que `reducir`:
/// downsampling Lanczos3 a CAP_PX si el lado mayor supera ese límite, calidad q82.
/// Devuelve `None` si no es posible decodificar o si la imagen ya es pequeña.
fn reducir_jpeg_raw(jpeg: &[u8]) -> Option<Vec<u8>> {
    let mut reader = image::ImageReader::new(std::io::Cursor::new(jpeg));
    reader.set_format(ImageFormat::Jpeg);
    let mut limites = image::Limits::default();
    limites.max_image_width = Some(20_000);
    limites.max_image_height = Some(20_000);
    limites.max_alloc = Some(512 * 1024 * 1024);
    reader.limits(limites);
    let img = reader.decode().ok()?;
    let (w, h) = img.dimensions();
    if w.max(h) <= CAP_PX {
        return None;
    }
    let factor = CAP_PX as f32 / w.max(h) as f32;
    let nw = ((w as f32 * factor).round() as u32).max(1);
    let nh = ((h as f32 * factor).round() as u32).max(1);
    let peq = img.resize_exact(nw, nh, FilterType::Lanczos3);
    let gris = matches!(
        img.color(),
        ColorType::L8 | ColorType::La8 | ColorType::L16 | ColorType::La16
    );
    let mut buf = Vec::new();
    let ok = if gris {
        JpegEncoder::new_with_quality(&mut buf, CALIDAD).encode_image(&peq.to_luma8()).is_ok()
    } else {
        JpegEncoder::new_with_quality(&mut buf, CALIDAD).encode_image(&peq.to_rgb8()).is_ok()
    };
    if ok { Some(buf) } else { None }
}

// ── COMPRESIÓN ESTADÍSTICA DE STREAMS (TÉCNICA D) ────────────────────────
//
// Quinta etapa del pipeline. Aplica FlateDecode nivel 9 (máxima compresión
// zlib) sobre todo stream sin filtro que no sea una imagen. Actúa sobre:
//
//   • Streams de contenido de página (operadores PDF: BT, q, cm, Do…)
//   • Fuentes sin comprimir — subset_fuentes elimina el Filter de FontFile2
//     para simplificar la escritura; esta etapa lo re-aplica con nivel óptimo.
//   • Streams auxiliares: ToUnicode, CMap, perfiles ICC, metadatos, etc.
//
// Por qué FlateDecode y no Brotli/zstd/LZMA:
//   PDF solo admite filtros de stream definidos por la spec (ISO 32000):
//   DCTDecode, JPXDecode, FlateDecode, CCITTFaxDecode, JBIG2Decode, LZW y
//   unos pocos auxiliares. Brotli no está en la lista; usarlo produciría un
//   PDF corrupto para cualquier lector (Adobe, Preview, Foxit, etc.).
//   FlateDecode nivel 9 es el mejor compresor lossless disponible dentro de
//   la spec PDF. La compresión zstd de comprimir_b64 actúa como capa exterior
//   sobre el .babel y ya cubre el "mejor compresor general"; esta etapa hace
//   que el PDF en sí mismo sea más pequeño (útil si el usuario lo exporta).
//
// Rendimiento: ~50-200 ms por MB en hardware moderno (zlib best). Para el
// caso de uso de Babel (documentos de trabajo < 150 MB), es aceptable.
//
// Lossless garantizado: FlateDecode (DEFLATE) es reversible sin excepción.
// La etapa nunca reemplaza si no mejora, y valida el PDF antes de aceptarlo.

pub fn comprimir_streams(bytes: &[u8]) -> Option<Vec<u8>> {
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;

    let mut doc = Document::load_mem(bytes).ok()?;
    let n_paginas = doc.get_pages().len();

    let mut cambiado = false;

    for obj in doc.objects.values_mut() {
        let Object::Stream(s) = obj else { continue };

        // Cualquier filtro existente (FlateDecode, DCTDecode, JBIG2…) indica que
        // el contenido ya está comprimido o tiene codificación especial. No tocar.
        if !filtro_es_ninguno(&s.dict) {
            continue;
        }
        // Imágenes → gestionadas por las etapas anteriores.
        if es_imagen(&s.dict) {
            continue;
        }

        let original_len = s.content.len();
        // Umbral mínimo: en streams < 512 bytes el overhead de cabecera zlib
        // (2 bytes) + checksum Adler-32 (4 bytes) + metadatos PDF puede igualar
        // o superar el ahorro. El beneficio real empieza aquí.
        if original_len < 512 {
            continue;
        }

        let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
        if enc.write_all(&s.content).is_err() {
            continue;
        }
        let compressed = match enc.finish() {
            Ok(c) => c,
            Err(_) => continue,
        };

        if compressed.len() + 32 >= original_len {
            continue; // no mejora o empeora → dejar intacto
        }

        s.dict.set("Filter", Object::Name(b"FlateDecode".to_vec()));
        s.dict.remove(b"DecodeParms");
        s.set_content(compressed);
        cambiado = true;
    }

    if !cambiado {
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
    use flate2::{write::ZlibEncoder, Compression};
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

    // ── Verificación de defensas: SMask / predictor / CMYK / metadatos ────────

    // PDF con una imagen RGB y su canal alfa como SMask separado.
    // Ambos objetos tienen content len > 4096 y dimensiones válidas, de modo que
    // sin la defensa ambos serían candidatos para comprimir_imagenes.
    fn pdf_con_smask(w: i64, h: i64) -> Vec<u8> {
        let alpha: Vec<u8> = (0..(w * h) as usize)
            .map(|i| (i % 200) as u8) // valores continuos (no binarios) → no B/N
            .collect();
        let rgb: Vec<u8> = (0..(w * h * 3) as usize)
            .map(|i| ((i * 7) % 256) as u8)
            .collect();

        let mut doc = Document::with_version("1.5");
        let smask_id = doc.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject", "Subtype" => "Image",
                "Width" => w, "Height" => h,
                "ColorSpace" => "DeviceGray", "BitsPerComponent" => 8i64,
            },
            alpha,
        ));
        let img_id = doc.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject", "Subtype" => "Image",
                "Width" => w, "Height" => h,
                "ColorSpace" => "DeviceRGB", "BitsPerComponent" => 8i64,
                "SMask" => Object::Reference(smask_id),
            },
            rgb,
        ));
        let cont_id = doc.add_object(Stream::new(
            dictionary! {},
            b"q 200 0 0 200 0 0 cm /Im0 Do Q".to_vec(),
        ));
        let pages_id = doc.new_object_id();
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id,
            "MediaBox" => vec![0i64.into(), 0i64.into(), 200i64.into(), 200i64.into()],
            "Contents" => cont_id,
            "Resources" => dictionary! {
                "XObject" => dictionary! { "Im0" => img_id },
            },
        });
        doc.objects.insert(pages_id, Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page_id.into()],
            "Count" => 1i64,
        }));
        let cat = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", cat);
        let mut out = Vec::new();
        doc.save_to(&mut out).unwrap();
        out
    }

    // DEFENSA SMask: la imagen registrada como canal alfa de otra imagen NO debe
    // ser tocada por comprimir_imagenes aunque sea candidata por tipo/tamaño.
    // Si se comprimiera con JPEG, los gradientes del canal alfa se corromperían.
    #[test]
    fn defensa_smask_imagen_alpha_no_se_toca() {
        let pdf = pdf_con_smask(80, 80); // 80x80 = 6400 bytes por canal → > umbral 4096

        // Capturar el contenido del objeto SMask en el PDF original.
        let doc_orig = Document::load_mem(&pdf).unwrap();
        let smask_content_orig: Vec<Vec<u8>> = doc_orig.objects.values()
            .filter_map(|o| {
                if let Object::Stream(s) = o {
                    if matches!(s.dict.get(b"Subtype"), Ok(Object::Name(n)) if n == b"Image")
                        && !s.dict.get(b"SMask").is_ok() // es el SMask, no la principal
                        && matches!(s.dict.get(b"ColorSpace"), Ok(Object::Name(n)) if n == b"DeviceGray")
                    {
                        return Some(s.content.clone());
                    }
                }
                None
            })
            .collect();
        assert_eq!(smask_content_orig.len(), 1, "debe haber exactamente un objeto SMask DeviceGray");

        // Aunque comprimir_imagenes podría ver al SMask como candidato DeviceGray,
        // la defensa de mascaras_set lo excluye antes de que llegue al procesamiento.
        // El PDF resultante puede cambiar (la imagen principal RGB sí es candidata),
        // pero el objeto SMask debe conservar su contenido intacto.
        let resultado = comprimir_imagenes(&pdf); // puede ser Some() o None
        let pdf_out = resultado.as_deref().unwrap_or(&pdf);
        let doc_out = Document::load_mem(pdf_out).unwrap();

        // Buscar en el resultado el objeto SMask y verificar que su contenido NO cambió.
        let smask_content_out: Vec<Vec<u8>> = doc_out.objects.values()
            .filter_map(|o| {
                if let Object::Stream(s) = o {
                    if matches!(s.dict.get(b"Subtype"), Ok(Object::Name(n)) if n == b"Image")
                        && !s.dict.get(b"SMask").is_ok()
                        && matches!(s.dict.get(b"ColorSpace"), Ok(Object::Name(n)) if n == b"DeviceGray")
                    {
                        return Some(s.content.clone());
                    }
                }
                None
            })
            .collect();

        assert_eq!(smask_content_out.len(), 1, "el SMask debe seguir existiendo tras comprimir");
        assert_eq!(
            smask_content_out[0], smask_content_orig[0],
            "el contenido del canal alfa (SMask) NO debe modificarse"
        );
    }

    // PDF con imagen FlateDecode + Predictor=15 (PNG sub-row predictor).
    // El predictor transforma los bytes antes de comprimir, así que
    // decompressed_content() devuelve bytes con el predictor aplicado, NO píxeles crudos.
    fn pdf_con_predictor(w: i64, h: i64, predictor: i64) -> Vec<u8> {
        use flate2::{write::ZlibEncoder, Compression};
        use std::io::Write;
        // Contenido artificial: no es un stream predictor real, pero tiene el tamaño
        // suficiente para superar el umbral de 4096. comprimir_imagenes debe saltar
        // porque tiene_predictor() detecta el Predictor>1 ANTES de descomprimir.
        let contenido_falso: Vec<u8> = (0..(w * h) as usize * 5)
            .map(|i| (i % 251) as u8)
            .collect();
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::fast());
        enc.write_all(&contenido_falso).unwrap();
        let compressed = enc.finish().unwrap();

        let mut doc = Document::with_version("1.5");
        let img_id = doc.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject", "Subtype" => "Image",
                "Width" => w, "Height" => h,
                "ColorSpace" => "DeviceGray", "BitsPerComponent" => 8i64,
                "Filter" => "FlateDecode",
                "DecodeParms" => dictionary! {
                    "Predictor" => predictor,
                    "Colors" => 1i64,
                    "Columns" => w,
                },
            },
            compressed,
        ));
        let cont_id = doc.add_object(Stream::new(dictionary! {}, b"q 100 0 0 100 0 0 cm /Im0 Do Q".to_vec()));
        let pages_id = doc.new_object_id();
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id,
            "MediaBox" => vec![0i64.into(), 0i64.into(), 100i64.into(), 100i64.into()],
            "Contents" => cont_id,
            "Resources" => dictionary! { "XObject" => dictionary! { "Im0" => img_id } },
        });
        doc.objects.insert(pages_id, Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1i64,
        }));
        let cat = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", cat);
        let mut out = Vec::new();
        doc.save_to(&mut out).unwrap();
        out
    }

    // DEFENSA Predictor: FlateDecode con Predictor=15 → comprimir_imagenes no toca.
    // Si se procesara, los bytes descomprimidos incluirían marcadores de fila del
    // predictor (1 byte extra por fila) y pixels.len() != tam_raw → ya lo bloquearía
    // la verificación de tamaño, pero la defensa tiene_predictor() lo detiene antes.
    #[test]
    fn defensa_predictor_15_no_se_toca() {
        let pdf = pdf_con_predictor(100, 100, 15);
        // El contenido del stream FlateDecode con predictor no debe ser re-encodado.
        let doc_orig = Document::load_mem(&pdf).unwrap();
        let content_orig: Vec<u8> = doc_orig.objects.values()
            .find_map(|o| if let Object::Stream(s) = o {
                if matches!(s.dict.get(b"Subtype"), Ok(Object::Name(n)) if n == b"Image") {
                    Some(s.content.clone())
                } else { None }
            } else { None })
            .unwrap();

        // comprimir_imagenes debe devolver None (sin cambios) porque la imagen
        // tiene Predictor>1 → la defensa la excluye en la primera pasada.
        assert!(
            comprimir_imagenes(&pdf).is_none(),
            "imagen con Predictor=15 no debe modificarse (la defensa tiene_predictor la excluye)"
        );

        // Verificar que el contenido es idéntico (None implica sin cambios, pero doble check).
        let doc_out = Document::load_mem(&pdf).unwrap();
        let content_out: Vec<u8> = doc_out.objects.values()
            .find_map(|o| if let Object::Stream(s) = o {
                if matches!(s.dict.get(b"Subtype"), Ok(Object::Name(n)) if n == b"Image") {
                    Some(s.content.clone())
                } else { None }
            } else { None })
            .unwrap();
        assert_eq!(content_orig, content_out, "contenido del stream no debe cambiar");
    }

    // DEFENSA CMYK: imagen DeviceCMYK (4 canales) → comprimir_imagenes no toca.
    // Razón: el mapeo de canales CMYK es no trivial; comprimir como JPEG RGB
    // alteraría el espacio de color y produciría colores incorrectos al imprimir.
    #[test]
    fn defensa_cmyk_se_salta() {
        let w = 80i64;
        let h = 80i64;
        // CMYK: 4 canales, 80*80*4 = 25600 bytes > umbral 4096
        let pixels_cmyk: Vec<u8> = (0..(w * h * 4) as usize).map(|i| (i % 200) as u8).collect();

        let mut doc = Document::with_version("1.5");
        let img_id = doc.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject", "Subtype" => "Image",
                "Width" => w, "Height" => h,
                "ColorSpace" => "DeviceCMYK", "BitsPerComponent" => 8i64,
            },
            pixels_cmyk,
        ));
        let cont_id = doc.add_object(Stream::new(dictionary! {}, b"q 80 0 0 80 0 0 cm /Im0 Do Q".to_vec()));
        let pages_id = doc.new_object_id();
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id,
            "MediaBox" => vec![0i64.into(), 0i64.into(), 80i64.into(), 80i64.into()],
            "Contents" => cont_id,
            "Resources" => dictionary! { "XObject" => dictionary! { "Im0" => img_id } },
        });
        doc.objects.insert(pages_id, Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1i64,
        }));
        let cat = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", cat);
        let mut pdf = Vec::new();
        doc.save_to(&mut pdf).unwrap();

        assert!(
            comprimir_imagenes(&pdf).is_none(),
            "imagen DeviceCMYK no debe modificarse (ColorSpace no reconocido → skip)"
        );
    }

    // DEFENSA metadatos mentidos: imagen que declara Width=200,Height=200 pero
    // su contenido real no tiene 200*200*3 bytes. Sin esta verificación,
    // GrayImage/RgbImage::from_raw devolvería None (lo que ya lo bloquearía),
    // pero la defensa pixels.len() != tam_raw lo detecta antes, más explícitamente.
    #[test]
    fn defensa_metadatos_mentidos_se_saltan() {
        let w = 200i64;
        let h = 200i64;
        // Declaramos 200x200 RGB pero solo ponemos 8000 bytes (≠ 200*200*3=120000).
        // Sí supera el umbral de 4096, así que llegaríamos al chequeo de tamaño.
        let contenido_falso: Vec<u8> = vec![128u8; 8000];

        let mut doc = Document::with_version("1.5");
        let img_id = doc.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject", "Subtype" => "Image",
                "Width" => w, "Height" => h,
                "ColorSpace" => "DeviceRGB", "BitsPerComponent" => 8i64,
            },
            contenido_falso.clone(),
        ));
        let cont_id = doc.add_object(Stream::new(dictionary! {}, b"q 200 0 0 200 0 0 cm /Im0 Do Q".to_vec()));
        let pages_id = doc.new_object_id();
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id,
            "MediaBox" => vec![0i64.into(), 0i64.into(), 200i64.into(), 200i64.into()],
            "Contents" => cont_id,
            "Resources" => dictionary! { "XObject" => dictionary! { "Im0" => img_id } },
        });
        doc.objects.insert(pages_id, Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1i64,
        }));
        let cat = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", cat);
        let mut pdf = Vec::new();
        doc.save_to(&mut pdf).unwrap();

        assert!(
            comprimir_imagenes(&pdf).is_none(),
            "imagen con píxeles reales ≠ W×H×canales no debe modificarse (verificación de tamaño)"
        );
    }

    // ── Benchmark pipeline completo (ignorado en CI, ejecutar con --ignored) ──

    // Construye un PDF realista de 4 páginas con:
    //   - JPEG grande 2500px (reducir)
    //   - Copia byte-idéntica del mismo JPEG (deduplicar_imagenes)
    //   - Imagen B&N cruda 500×500 (comprimir_imagenes B/N path)
    //   - Imagen RGB cruda 400×400 (comprimir_imagenes color path)
    //   - Fuente TrueType embebida si Arial está disponible (subset_fuentes)
    //   - Streams de contenido sin comprimir (comprimir_streams / técnica D)
    // Mide el tamaño antes/después de CADA etapa por separado, del pipeline completo,
    // y el tiempo de cada etapa. Ejecutar:
    //   cargo test benchmark -- --ignored --nocapture
    #[test]
    #[ignore]
    fn benchmark_pipeline_5_etapas() {
        fn cuenta_xobjects_imagen(doc: &Document) -> usize {
            doc.objects.values().filter(|o| {
                if let Object::Stream(s) = o {
                    matches!(s.dict.get(b"Subtype"), Ok(Object::Name(n)) if n == b"Image")
                } else { false }
            }).count()
        }

        fn pct(de: usize, a: usize) -> f64 {
            if de == 0 { return 0.0; }
            (de as f64 - a as f64) / de as f64 * 100.0
        }

        // ── Construir PDF ──────────────────────────────────────────────────
        let mut doc = Document::with_version("1.7");

        // JPEG 2500×2500 (→ reducir lo bajará a ≤2000px).
        let jpeg = jpeg_grande(2500);
        let img_jpeg1 = doc.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject", "Subtype" => "Image",
                "Width" => 2500i64, "Height" => 2500i64,
                "ColorSpace" => "DeviceRGB", "BitsPerComponent" => 8i64,
                "Filter" => "DCTDecode",
            },
            jpeg.clone(),
        ));
        // Copia byte-idéntica del JPEG (→ deduplicar la elimina).
        let img_jpeg2 = doc.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject", "Subtype" => "Image",
                "Width" => 2500i64, "Height" => 2500i64,
                "ColorSpace" => "DeviceRGB", "BitsPerComponent" => 8i64,
                "Filter" => "DCTDecode",
            },
            jpeg.clone(),
        ));

        // Imagen B&N cruda 500×500 (→ comprimir_imagenes la pasa a 1-bit FlateDecode).
        let pixels_bw: Vec<u8> = (0u32..500).flat_map(|row| {
            let v = if row % 40 < 20 { 0u8 } else { 255u8 };
            std::iter::repeat(v).take(500)
        }).collect();
        let img_bw = doc.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject", "Subtype" => "Image",
                "Width" => 500i64, "Height" => 500i64,
                "ColorSpace" => "DeviceGray", "BitsPerComponent" => 8i64,
            },
            pixels_bw,
        ));

        // Imagen RGB cruda 400×400 (→ comprimir_imagenes la pasa a DCTDecode q85).
        let pixels_rgb: Vec<u8> = (0u32..400).flat_map(|y| {
            (0u32..400).flat_map(move |x| {
                [((x*5 + y*3) % 256) as u8, ((x*2 + y*7) % 256) as u8, ((x ^ y) % 256) as u8]
            })
        }).collect();
        let img_rgb = doc.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject", "Subtype" => "Image",
                "Width" => 400i64, "Height" => 400i64,
                "ColorSpace" => "DeviceRGB", "BitsPerComponent" => 8i64,
            },
            pixels_rgb,
        ));

        // Fuente Arial embebida (→ subset_fuentes la recorta a los glifos usados).
        let ruta_arial = "/System/Library/Fonts/Supplemental/Arial.ttf";
        let (font_id_p1, font_id_p4) = if let Ok(font_bytes) = std::fs::read(ruta_arial) {
            // Fuente para página 1.
            let ff2a = doc.add_object(Stream::new(
                dictionary! { "Length" => font_bytes.len() as i64, "Length1" => font_bytes.len() as i64 },
                font_bytes.clone(),
            ));
            let fda = doc.add_object(dictionary! {
                "Type" => "FontDescriptor", "FontName" => "Arial",
                "Flags" => 32i64, "ItalicAngle" => 0i64,
                "Ascent" => 905i64, "Descent" => -210i64,
                "CapHeight" => 728i64, "StemV" => 80i64,
                "FontBBox" => vec![(-665i64).into(), (-210i64).into(), 2000i64.into(), 728i64.into()],
                "FontFile2" => ff2a,
            });
            let cida = doc.add_object(dictionary! {
                "Type" => "Font", "Subtype" => "CIDFontType2", "BaseFont" => "Arial",
                "CIDSystemInfo" => dictionary! {
                    "Registry" => Object::String(b"Adobe".to_vec(), lopdf::StringFormat::Literal),
                    "Ordering" => Object::String(b"Identity".to_vec(), lopdf::StringFormat::Literal),
                    "Supplement" => 0i64,
                },
                "FontDescriptor" => fda,
                "CIDToGIDMap" => Object::Name(b"Identity".to_vec()),
            });
            let fa = doc.add_object(dictionary! {
                "Type" => "Font", "Subtype" => "Type0", "BaseFont" => "Arial",
                "Encoding" => Object::Name(b"Identity-H".to_vec()),
                "DescendantFonts" => vec![Object::Reference(cida)],
            });
            // Fuente para página 4 (copia separada para que deduplicar también tenga trabajo).
            let ff2b = doc.add_object(Stream::new(
                dictionary! { "Length" => font_bytes.len() as i64, "Length1" => font_bytes.len() as i64 },
                font_bytes,
            ));
            let fdb = doc.add_object(dictionary! {
                "Type" => "FontDescriptor", "FontName" => "Arial",
                "Flags" => 32i64, "ItalicAngle" => 0i64,
                "Ascent" => 905i64, "Descent" => -210i64,
                "CapHeight" => 728i64, "StemV" => 80i64,
                "FontBBox" => vec![(-665i64).into(), (-210i64).into(), 2000i64.into(), 728i64.into()],
                "FontFile2" => ff2b,
            });
            let cidb = doc.add_object(dictionary! {
                "Type" => "Font", "Subtype" => "CIDFontType2", "BaseFont" => "Arial",
                "CIDSystemInfo" => dictionary! {
                    "Registry" => Object::String(b"Adobe".to_vec(), lopdf::StringFormat::Literal),
                    "Ordering" => Object::String(b"Identity".to_vec(), lopdf::StringFormat::Literal),
                    "Supplement" => 0i64,
                },
                "FontDescriptor" => fdb,
                "CIDToGIDMap" => Object::Name(b"Identity".to_vec()),
            });
            let fb = doc.add_object(dictionary! {
                "Type" => "Font", "Subtype" => "Type0", "BaseFont" => "Arial",
                "Encoding" => Object::Name(b"Identity-H".to_vec()),
                "DescendantFonts" => vec![Object::Reference(cidb)],
            });
            (Some(fa), Some(fb))
        } else {
            (None, None)
        };

        let tiene_arial = font_id_p1.is_some();

        // Páginas
        let pages_id = doc.new_object_id();

        let make_page = |doc: &mut Document, img: ObjectId, font_opt: Option<ObjectId>, texto: &[u8]| -> ObjectId {
            let contenido = if font_opt.is_some() {
                let mut v = b"BT /F1 14 Tf 50 700 Td <00480065006C006C006F> Tj ET\n".to_vec();
                v.extend_from_slice(b"q 400 0 0 400 50 200 cm /Im0 Do Q");
                v
            } else {
                b"q 400 0 0 400 50 50 cm /Im0 Do Q".to_vec()
            };
            let cont_id = doc.add_object(Stream::new(dictionary! {}, contenido));
            let recursos = if let Some(fid) = font_opt {
                dictionary! {
                    "XObject" => dictionary! { "Im0" => img },
                    "Font" => dictionary! { "F1" => fid },
                }
            } else {
                dictionary! { "XObject" => dictionary! { "Im0" => img } }
            };
            doc.add_object(dictionary! {
                "Type" => "Page", "Parent" => pages_id,
                "MediaBox" => vec![0i64.into(), 0i64.into(), 595i64.into(), 842i64.into()],
                "Contents" => cont_id,
                "Resources" => recursos,
            })
        };

        let pag1 = make_page(&mut doc, img_jpeg1, font_id_p1, b"Hola"); // JPEG grande + Arial
        let pag2 = make_page(&mut doc, img_jpeg2, None, b"");            // JPEG duplicado
        let pag3 = {
            // Página con DOS imágenes (B&N + RGB).
            let cont_id = doc.add_object(Stream::new(
                dictionary! {},
                b"q 300 0 0 300 50 500 cm /BW Do Q q 300 0 0 300 250 100 cm /RGB Do Q".to_vec(),
            ));
            doc.add_object(dictionary! {
                "Type" => "Page", "Parent" => pages_id,
                "MediaBox" => vec![0i64.into(), 0i64.into(), 595i64.into(), 842i64.into()],
                "Contents" => cont_id,
                "Resources" => dictionary! {
                    "XObject" => dictionary! { "BW" => img_bw, "RGB" => img_rgb },
                },
            })
        };
        let pag4 = {
            let cont_id = doc.add_object(Stream::new(dictionary! {}, b"q 200 0 0 200 50 500 cm /Im0 Do Q".to_vec()));
            let font_res = if let Some(fid) = font_id_p4 {
                dictionary! {
                    "XObject" => dictionary! { "Im0" => img_rgb },
                    "Font" => dictionary! { "F1" => fid },
                }
            } else {
                dictionary! { "XObject" => dictionary! { "Im0" => img_rgb } }
            };
            doc.add_object(dictionary! {
                "Type" => "Page", "Parent" => pages_id,
                "MediaBox" => vec![0i64.into(), 0i64.into(), 595i64.into(), 842i64.into()],
                "Contents" => cont_id,
                "Resources" => font_res,
            })
        };

        doc.objects.insert(pages_id, Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![pag1.into(), pag2.into(), pag3.into(), pag4.into()],
            "Count" => 4i64,
        }));
        let cat = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", cat);

        let mut original = Vec::new();
        doc.save_to(&mut original).unwrap();
        let doc_orig = Document::load_mem(&original).unwrap();
        let img_count_orig = cuenta_xobjects_imagen(&doc_orig);

        // ── Medir cada etapa POR SEPARADO sobre el original (con tiempos) ─
        use std::time::Instant;

        let t = Instant::now(); let solo_reducir   = reducir(&original);          let ms_r = t.elapsed().as_millis();
        let t = Instant::now(); let solo_dedup     = deduplicar_imagenes(&original); let ms_d = t.elapsed().as_millis();
        let t = Instant::now(); let solo_subset    = subset_fuentes(&original);    let ms_s = t.elapsed().as_millis();
        let t = Instant::now(); let solo_comprimir = comprimir_imagenes(&original); let ms_c = t.elapsed().as_millis();
        let t = Instant::now(); let solo_streams   = comprimir_streams(&original);  let ms_st = t.elapsed().as_millis();

        // ── Medir pipeline completo (tiempos acumulados) ──────────────────
        // Nota: reducir se vuelve a ejecutar aquí para que ms_pipeline incluya
        // la etapa más costosa y el total sea comparable con la suma de aisaldos.
        let t = Instant::now();
        let pipeline_reducir = reducir(&original);
        let base1 = pipeline_reducir.as_deref().unwrap_or(&original);
        let tras_dedup   = deduplicar_imagenes(base1);
        let base2 = tras_dedup.as_deref().unwrap_or(base1);
        let tras_subset  = subset_fuentes(base2);
        let base3 = tras_subset.as_deref().unwrap_or(base2);
        let tras_comprimir = comprimir_imagenes(base3);
        let base4 = tras_comprimir.as_deref().unwrap_or(base3);
        let tras_streams = comprimir_streams(base4);
        let final_bytes = tras_streams.as_deref().unwrap_or(base4);
        let ms_pipeline = t.elapsed().as_millis();

        let tam0   = original.len();
        let tam_r  = solo_reducir.as_ref().map(|v| v.len()).unwrap_or(tam0);
        let tam_d  = solo_dedup.as_ref().map(|v| v.len()).unwrap_or(tam0);
        let tam_s  = solo_subset.as_ref().map(|v| v.len()).unwrap_or(tam0);
        let tam_c  = solo_comprimir.as_ref().map(|v| v.len()).unwrap_or(tam0);
        let tam_st = solo_streams.as_ref().map(|v| v.len()).unwrap_or(tam0);
        let tam_fin = final_bytes.len();

        // Reducción incremental de D sobre el resultado acumulado de A+B+C
        let tam_antes_d = base4.len();
        let reduccion_d_incremental = pct(tam_antes_d, tam_fin);

        // ── Validar salida ────────────────────────────────────────────────
        let doc_fin = Document::load_mem(final_bytes).expect("PDF final debe parsear");
        let paginas_fin = doc_fin.get_pages().len();
        let img_count_fin = cuenta_xobjects_imagen(&doc_fin);

        // ── Imprimir resultados ───────────────────────────────────────────
        println!("\n╔═══════════════════════════════════════════════════════════════╗");
        println!("║       BENCHMARK PIPELINE COMPRESIÓN HIPER-AGRESIVA (5 ETAPAS)║");
        println!("╠═══════════════════════════════════════════════════════════════╣");
        println!("║  Contenido del PDF de prueba:                                 ║");
        println!("║    • 4 páginas                                                ║");
        println!("║    • JPEG 2500×2500 px + copia duplicada                      ║");
        println!("║    • Imagen B&N cruda 500×500 px                              ║");
        println!("║    • Imagen RGB cruda 400×400 px                              ║");
        println!("║    • Fuente Arial embebida: {}                             ║", if tiene_arial {"SÍ "} else {"NO "});
        println!("╠═══════════════════════════════════════════════════════════════╣");
        println!("║  MEDICIÓN AISLADA (cada etapa sobre el original + tiempo)     ║");
        println!("║  Original:                {:>8} KB                           ║", tam0 / 1024);
        println!("║  A reducir:               {:>8} KB  ({:+.1}%)  {:>5} ms        ║", tam_r  / 1024, -pct(tam0, tam_r),  ms_r);
        println!("║  B deduplicar:            {:>8} KB  ({:+.1}%)  {:>5} ms        ║", tam_d  / 1024, -pct(tam0, tam_d),  ms_d);
        println!("║  C subset fuentes:        {:>8} KB  ({:+.1}%)  {:>5} ms        ║", tam_s  / 1024, -pct(tam0, tam_s),  ms_s);
        println!("║  C comprimir imágenes:    {:>8} KB  ({:+.1}%)  {:>5} ms        ║", tam_c  / 1024, -pct(tam0, tam_c),  ms_c);
        println!("║  D comprimir streams:     {:>8} KB  ({:+.1}%)  {:>5} ms        ║", tam_st / 1024, -pct(tam0, tam_st), ms_st);
        println!("╠═══════════════════════════════════════════════════════════════╣");
        println!("║  PIPELINE COMPLETO (secuencial, acumulativo)                  ║");
        println!("║  Original:                {:>8} KB  (100.0%)                 ║", tam0 / 1024);
        println!("║  Tras A reducir:          {:>8} KB  ({:.1}% del orig)        ║", base1.len() / 1024, base1.len() as f64 / tam0 as f64 * 100.0);
        println!("║  Tras B deduplicar:       {:>8} KB  ({:.1}% del orig)        ║", base2.len() / 1024, base2.len() as f64 / tam0 as f64 * 100.0);
        println!("║  Tras C subset fuentes:   {:>8} KB  ({:.1}% del orig)        ║", base3.len() / 1024, base3.len() as f64 / tam0 as f64 * 100.0);
        println!("║  Tras C comprimir imgs:   {:>8} KB  ({:.1}% del orig)        ║", base4.len() / 1024, base4.len() as f64 / tam0 as f64 * 100.0);
        println!("║  Tras D comprimir strs:   {:>8} KB  ({:.1}% del orig)        ║", tam_fin / 1024, tam_fin as f64 / tam0 as f64 * 100.0);
        println!("║  ──────────────────────────────────────────────────────────── ║");
        println!("║  Reducción total A+B+C+D: {:.1}% ({} KB → {} KB)             ║", pct(tam0, tam_fin), tam0 / 1024, tam_fin / 1024);
        println!("║  Aporte incremental D:    {:.1}% ({} KB → {} KB)             ║", reduccion_d_incremental, tam_antes_d / 1024, tam_fin / 1024);
        println!("║  Tiempo pipeline total:   {:>5} ms                            ║", ms_pipeline);
        println!("╠═══════════════════════════════════════════════════════════════╣");
        println!("║  VERIFICACIÓN INTEGRIDAD:                                     ║");
        println!("║  Páginas antes: 4  →  después: {}                             ║", paginas_fin);
        println!("║  XObjects imagen antes: {}  →  después: {} {}               ║",
            img_count_orig, img_count_fin,
            if img_count_fin <= img_count_orig { "✓" } else { "⚠" }
        );
        println!("║  PDF resultante parseable: SÍ ✓                              ║");
        println!("╚═══════════════════════════════════════════════════════════════╝");

        // Assertions mínimas para que el test falle si algo sale mal.
        assert_eq!(paginas_fin, 4, "el PDF final debe tener 4 páginas");
        assert!(tam_fin < tam0, "el pipeline debe producir un PDF más pequeño");
        assert!(img_count_fin >= 1, "debe quedar al menos una imagen");
    }

    // ── Tests de comprimir_imagenes ────────────────────────────────────────

    // Construye un PDF con una imagen almacenada SIN filtro (píxeles crudos).
    // `color_space` debe ser "DeviceGray" (canales=1) o "DeviceRGB" (canales=3).
    fn pdf_sin_filtro(pixels: &[u8], w: i64, h: i64, color_space: &str) -> Vec<u8> {
        let mut doc = Document::with_version("1.5");
        let img_id = doc.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => w,
                "Height" => h,
                "ColorSpace" => Object::Name(color_space.as_bytes().to_vec()),
                "BitsPerComponent" => 8i64,
            },
            pixels.to_vec(),
        ));
        let cont_id = doc.add_object(Stream::new(
            dictionary! {},
            format!("q {} 0 0 {} 0 0 cm /Im0 Do Q", w, h).into_bytes(),
        ));
        let pages_id = doc.new_object_id();
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0i64.into(), 0i64.into(), w.into(), h.into()],
            "Contents" => cont_id,
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
        let cat_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", cat_id);
        let mut out = Vec::new();
        doc.save_to(&mut out).unwrap();
        out
    }

    // TEST: imagen B/N puro (escala de grises, todos los píxeles 0 ó 255, sin filtro)
    // → comprimir_imagenes debe convertirla a 1-bit + FlateDecode y reducir el tamaño.
    #[test]
    fn imagen_bw_cruda_se_comprime_a_1bit() {
        let (w, h) = (400u32, 400u32);
        // Simula texto escaneado: franjas horizontales negro/blanco.
        // Raw 8-bit: 160 KB. 1-bit FlateDecode: fracción de eso.
        let pixels: Vec<u8> = (0..h)
            .flat_map(|row| {
                let val = if row % 20 < 10 { 0u8 } else { 255u8 };
                std::iter::repeat(val).take(w as usize)
            })
            .collect();
        assert!(pixels.iter().all(|&p| p == 0 || p == 255), "test mal construido");

        let pdf = pdf_sin_filtro(&pixels, w as i64, h as i64, "DeviceGray");
        let comprimido = comprimir_imagenes(&pdf)
            .expect("debe comprimir imagen B/N cruda a 1-bit FlateDecode");

        assert!(
            comprimido.len() < pdf.len(),
            "PDF comprimido ({} B) no es menor que el original ({} B)",
            comprimido.len(),
            pdf.len()
        );

        // Verificar que la imagen resultante tiene BitsPerComponent=1 y Filter=FlateDecode.
        let doc_out = Document::load_mem(&comprimido).unwrap();
        let mut bpc_encontrado = 0i64;
        let mut filtro_encontrado = Vec::new();
        for obj in doc_out.objects.values() {
            if let Object::Stream(s) = obj {
                if es_imagen(&s.dict) {
                    bpc_encontrado = s.dict.get(b"BitsPerComponent")
                        .ok().and_then(|o| o.as_i64().ok()).unwrap_or(-1);
                    filtro_encontrado = match s.dict.get(b"Filter") {
                        Ok(Object::Name(n)) => n.clone(),
                        _ => vec![],
                    };
                }
            }
        }
        assert_eq!(bpc_encontrado, 1, "BitsPerComponent debe ser 1 tras comprimir imagen B/N");
        assert_eq!(filtro_encontrado, b"FlateDecode", "Filter debe ser FlateDecode");
        // El PDF sigue siendo válido.
        assert_eq!(doc_out.get_pages().len(), 1);
    }

    // TEST: imagen color cruda (RGB, sin filtro) → comprimir_imagenes debe
    // re-encodarla como DCTDecode (JPEG q85) y reducir el tamaño significativamente.
    #[test]
    fn imagen_color_cruda_se_comprime_a_jpeg() {
        let (w, h) = (400u32, 400u32);
        // Gradiente de color con entropía suficiente para que JPEG comprime mejor que crudo.
        let pixels: Vec<u8> = (0..h)
            .flat_map(|y| {
                (0..w).flat_map(move |x| {
                    [
                        ((x * 5 + y * 3) % 256) as u8,
                        ((x * 2 + y * 7) % 256) as u8,
                        ((x ^ y) % 256) as u8,
                    ]
                })
            })
            .collect();

        let pdf = pdf_sin_filtro(&pixels, w as i64, h as i64, "DeviceRGB");
        let comprimido = comprimir_imagenes(&pdf)
            .expect("debe comprimir imagen RGB cruda a DCTDecode");

        assert!(
            comprimido.len() < pdf.len(),
            "PDF comprimido ({} B) no es menor que el original ({} B)",
            comprimido.len(),
            pdf.len()
        );

        // Verificar que el filtro es ahora DCTDecode.
        let doc_out = Document::load_mem(&comprimido).unwrap();
        let mut filtro_encontrado = Vec::new();
        for obj in doc_out.objects.values() {
            if let Object::Stream(s) = obj {
                if es_imagen(&s.dict) {
                    filtro_encontrado = match s.dict.get(b"Filter") {
                        Ok(Object::Name(n)) => n.clone(),
                        _ => vec![],
                    };
                }
            }
        }
        assert_eq!(filtro_encontrado, b"DCTDecode", "Filter debe ser DCTDecode tras comprimir imagen color");
        assert_eq!(doc_out.get_pages().len(), 1);
    }

    // TEST: imagen B/N ya en DCTDecode → comprimir_imagenes no la toca (la gestiona `reducir`).
    #[test]
    fn imagen_bw_jpeg_no_se_retoca() {
        // Imagen JPEG en escala de grises: ya DCTDecode → comprimir_imagenes devuelve None.
        let pdf = pdf_con_imagen(&jpeg_grande(400), 400);
        assert!(
            comprimir_imagenes(&pdf).is_none(),
            "no debe tocar imágenes ya en DCTDecode"
        );
    }

    // TEST: imagen cruda demasiado pequeña (<4 KB) no justifica el esfuerzo → None.
    #[test]
    fn imagen_pequena_no_comprime() {
        let (w, h) = (20u32, 20u32); // 20x20x3 = 1200 bytes < 4096
        let pixels: Vec<u8> = vec![128u8; w as usize * h as usize * 3];
        let pdf = pdf_sin_filtro(&pixels, w as i64, h as i64, "DeviceRGB");
        assert!(
            comprimir_imagenes(&pdf).is_none(),
            "imágenes pequeñas (<4 KB) no deben tocarse"
        );
    }

    // ── Tests de comprimir_streams (técnica D) ─────────────────────────────

    // Construye un PDF con un stream de contenido sin filtro de tamaño arbitrario.
    // Usa texto PDF repetitivo (alta compresibilidad) para garantizar que
    // FlateDecode produzca un resultado genuinamente más pequeño.
    fn pdf_con_stream_grande_sin_comprimir(tam_bytes: usize) -> Vec<u8> {
        // Operadores PDF repetitivos → alta entropía para zlib pero comprimible.
        let linea = b"BT /F1 12 Tf 50 700 Td (Babel Security documento confidencial) Tj ET\n";
        let mut contenido: Vec<u8> = Vec::with_capacity(tam_bytes + linea.len());
        while contenido.len() < tam_bytes {
            contenido.extend_from_slice(linea);
        }
        contenido.truncate(tam_bytes);

        let mut doc = Document::with_version("1.5");
        let cont_id = doc.add_object(Stream::new(dictionary! {}, contenido));
        let pages_id = doc.new_object_id();
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id,
            "MediaBox" => vec![0i64.into(), 0i64.into(), 595i64.into(), 842i64.into()],
            "Contents" => cont_id,
            "Resources" => dictionary! {},
        });
        doc.objects.insert(pages_id, Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1i64,
        }));
        let cat = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", cat);
        let mut out = Vec::new();
        doc.save_to(&mut out).unwrap();
        out
    }

    // TEST: stream de contenido sin filtro y suficientemente grande
    // → comprimir_streams lo comprime con FlateDecode y produce PDF más pequeño.
    #[test]
    fn stream_grande_sin_filtro_se_comprime() {
        let pdf = pdf_con_stream_grande_sin_comprimir(8_000);
        let comprimido = comprimir_streams(&pdf)
            .expect("debe comprimir un stream grande sin filtro");
        assert!(
            comprimido.len() < pdf.len(),
            "PDF con stream comprimido ({} B) debe ser menor que original ({} B)",
            comprimido.len(),
            pdf.len()
        );
        // El PDF resultante debe ser válido con el mismo número de páginas.
        let doc_out = Document::load_mem(&comprimido).unwrap();
        assert_eq!(doc_out.get_pages().len(), 1);
    }

    // TEST: stream ya FlateDecode → comprimir_streams no lo toca (devuelve None).
    #[test]
    fn stream_ya_flatedecodado_no_se_retoca() {
        // Crear PDF con el stream ya comprimido con FlateDecode.
        let contenido_raw: Vec<u8> = b"BT /F1 12 Tf 50 700 Td (Hola) Tj ET\n"
            .iter().cycle().take(4000).copied().collect();
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
        use std::io::Write;
        enc.write_all(&contenido_raw).unwrap();
        let comprimido_raw = enc.finish().unwrap();

        let mut doc = Document::with_version("1.5");
        let cont_id = doc.add_object(Stream::new(
            dictionary! { "Filter" => "FlateDecode" },
            comprimido_raw,
        ));
        let pages_id = doc.new_object_id();
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id,
            "MediaBox" => vec![0i64.into(), 0i64.into(), 595i64.into(), 842i64.into()],
            "Contents" => cont_id,
            "Resources" => dictionary! {},
        });
        doc.objects.insert(pages_id, Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1i64,
        }));
        let cat = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", cat);
        let mut pdf = Vec::new();
        doc.save_to(&mut pdf).unwrap();

        assert!(
            comprimir_streams(&pdf).is_none(),
            "un stream ya FlateDecode no debe volver a comprimirse"
        );
    }

    // TEST: PDF con imagen JPEG → comprimir_streams no toca las imágenes
    // (ya gestionadas por técnicas anteriores; re-comprimir sería redundante).
    #[test]
    fn imagenes_no_se_tocan_en_comprimir_streams() {
        let pdf = pdf_con_imagen(&jpeg_grande(400), 400);
        // El PDF tiene un stream de imagen DCTDecode → filter existente → skip.
        // El stream de contenido ("q 200 0 0 200 0 0 cm /Im0 Do Q") es < 512 bytes → skip.
        // Resultado esperado: None (nada que comprimir de forma útil).
        assert!(
            comprimir_streams(&pdf).is_none(),
            "imágenes DCTDecode no deben tocarse en comprimir_streams"
        );
    }

    // TEST DE INTEGRIDAD ROUND-TRIP: el stream comprimido por FlateDecode se
    // descomprime exactamente igual al original — ningún byte debe cambiar.
    // Este test verifica la garantía lossless explícitamente.
    #[test]
    fn integridad_round_trip_stream_comprimido() {
        let tam = 4_000usize;
        let pdf = pdf_con_stream_grande_sin_comprimir(tam);

        // Capturar el contenido original del stream de contenido.
        let doc_orig = Document::load_mem(&pdf).unwrap();
        let contenido_orig: Vec<u8> = doc_orig.objects.values()
            .find_map(|o| {
                if let Object::Stream(s) = o {
                    // El stream de contenido no es una imagen y no tiene filtro.
                    if s.content.len() >= 512 && filtro_es_ninguno(&s.dict) && !es_imagen(&s.dict) {
                        return Some(s.content.clone());
                    }
                }
                None
            })
            .expect("debe existir el stream de contenido sin filtro");

        // Comprimir.
        let pdf_comprimido = comprimir_streams(&pdf)
            .expect("debe comprimir el stream grande");

        // Cargar el resultado y descomprimir el stream ahora FlateDecode.
        let doc_out = Document::load_mem(&pdf_comprimido).unwrap();
        let contenido_descomprimido: Vec<u8> = doc_out.objects.values()
            .find_map(|o| {
                if let Object::Stream(s) = o {
                    if filtro_es_flate(&s.dict) && !es_imagen(&s.dict) {
                        // decompressed_content() descomprime el FlateDecode.
                        return s.decompressed_content().ok();
                    }
                }
                None
            })
            .expect("debe existir el stream comprimido con FlateDecode en el resultado");

        assert_eq!(
            contenido_orig, contenido_descomprimido,
            "el contenido del stream debe ser bit-por-bit idéntico tras comprimir y descomprimir"
        );
    }

    // TEST PIPELINE COMPLETO A+C+D: el pipeline de 5 etapas produce un PDF
    // válido, con el mismo número de páginas, y más pequeño que el original.
    #[test]
    fn pipeline_completo_5_etapas_pdf_valido() {
        // PDF con imagen grande (activa reducir) y stream de texto grande (activa comprimir_streams).
        let jpeg = jpeg_grande(2500);
        let mut doc = Document::with_version("1.5");
        let img_id = doc.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject", "Subtype" => "Image",
                "Width" => 2500i64, "Height" => 2500i64,
                "ColorSpace" => "DeviceRGB", "BitsPerComponent" => 8i64,
                "Filter" => "DCTDecode",
            },
            jpeg,
        ));
        // Stream de contenido grande (comprimible con técnica D).
        let linea = b"q 400 0 0 400 50 200 cm /Im0 Do Q BT /F1 12 Tf 50 700 Td (Babel) Tj ET\n";
        let mut ops: Vec<u8> = Vec::new();
        while ops.len() < 3_000 { ops.extend_from_slice(linea); }
        ops.truncate(3_000);
        let cont_id = doc.add_object(Stream::new(dictionary! {}, ops));
        let pages_id = doc.new_object_id();
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id,
            "MediaBox" => vec![0i64.into(), 0i64.into(), 595i64.into(), 842i64.into()],
            "Contents" => cont_id,
            "Resources" => dictionary! { "XObject" => dictionary! { "Im0" => img_id } },
        });
        doc.objects.insert(pages_id, Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1i64,
        }));
        let cat = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", cat);
        let mut original = Vec::new();
        doc.save_to(&mut original).unwrap();

        // Pipeline completo: reducir → deduplicar → subset_fuentes → comprimir_imagenes → comprimir_streams
        let b1 = reducir(&original);
        let base1 = b1.as_deref().unwrap_or(&original);
        let b2 = deduplicar_imagenes(base1);
        let base2 = b2.as_deref().unwrap_or(base1);
        let b3 = subset_fuentes(base2);
        let base3 = b3.as_deref().unwrap_or(base2);
        let b4 = comprimir_imagenes(base3);
        let base4 = b4.as_deref().unwrap_or(base3);
        let b5 = comprimir_streams(base4);
        let final_bytes = b5.as_deref().unwrap_or(base4);

        // El pipeline debe haber reducido el tamaño (el JPEG grande garantiza esto).
        assert!(
            final_bytes.len() < original.len(),
            "el pipeline A+C+D debe producir un PDF más pequeño: {} < {}",
            final_bytes.len(), original.len()
        );

        // El PDF resultante debe ser válido con el mismo número de páginas.
        let doc_fin = Document::load_mem(final_bytes).expect("el PDF final debe ser válido");
        assert_eq!(
            doc_fin.get_pages().len(), 1,
            "el número de páginas no debe cambiar tras el pipeline completo"
        );
    }

    // ── Tests de umbral suave B/N (mejora pixels_son_binarios) ──────────────

    // TEST: imagen "casi B/N" con ruido de escáner (valores 4 y 251 en lugar de 0/255)
    // → comprimir_imagenes debe detectarla como B/N y comprimirla a 1-bit FlateDecode.
    // Antes de la mejora del umbral, este caso devolvía None porque ningún píxel era
    // exactamente 0 ó 255.
    #[test]
    fn imagen_casi_bw_con_ruido_escaner_se_comprime() {
        let (w, h) = (400u32, 400u32);
        // Simula texto escaneado: el escáner produce 4 (≈negro) y 251 (≈blanco)
        // en lugar de los valores exactos 0/255 que solo genera imagen sintética.
        let pixels: Vec<u8> = (0..h)
            .flat_map(|row| {
                let val: u8 = if row % 20 < 10 { 4 } else { 251 };
                std::iter::repeat(val).take(w as usize)
            })
            .collect();
        assert!(
            pixels.iter().any(|&p| p != 0 && p != 255),
            "test mal construido: debe tener valores distintos de 0 y 255"
        );

        let pdf = pdf_sin_filtro(&pixels, w as i64, h as i64, "DeviceGray");
        let comprimido = comprimir_imagenes(&pdf)
            .expect("imagen casi B/N con ruido de escáner debe comprimirse a 1-bit");

        assert!(comprimido.len() < pdf.len());

        let doc_out = Document::load_mem(&comprimido).unwrap();
        for obj in doc_out.objects.values() {
            if let Object::Stream(s) = obj {
                if es_imagen(&s.dict) {
                    let bpc = s.dict.get(b"BitsPerComponent").ok()
                        .and_then(|o| o.as_i64().ok()).unwrap_or(-1);
                    assert_eq!(bpc, 1, "BitsPerComponent debe ser 1 para imagen casi B/N");
                }
            }
        }
    }

    // TEST: imagen genuinamente gris (valores intermedios como 128) → NO se trata como B/N.
    // El umbral 16/239 no debe confundir escala de grises real con B/N ruidoso.
    #[test]
    fn imagen_gris_real_no_se_trata_como_bw() {
        let (w, h) = (100u32, 100u32);
        // Gradiente gris con valores en todo el rango → no es B/N.
        let pixels: Vec<u8> = (0..(w * h) as usize).map(|i| (i % 256) as u8).collect();
        // Hay valores entre 17 y 238 → pixels_son_binarios debe devolver false.
        assert!(pixels.iter().any(|&p| p > 16 && p < 239), "test mal construido");

        // comprimir_imagenes puede comprimirla como JPEG (no como 1-bit),
        // pero lo importante es verificar que no aplica el path B/N.
        // Con 100×100 = 10000 bytes > 4096 umbral, sí es candidata al path color.
        let pdf = pdf_sin_filtro(&pixels, w as i64, h as i64, "DeviceGray");
        if let Some(comprimido) = comprimir_imagenes(&pdf) {
            let doc_out = Document::load_mem(&comprimido).unwrap();
            for obj in doc_out.objects.values() {
                if let Object::Stream(s) = obj {
                    if es_imagen(&s.dict) {
                        let bpc = s.dict.get(b"BitsPerComponent").ok()
                            .and_then(|o| o.as_i64().ok()).unwrap_or(-1);
                        assert_ne!(bpc, 1, "imagen gris real NO debe comprimirse a 1-bit");
                    }
                }
            }
        }
        // Si devuelve None (no mejoró), también es correcto: no se aplicó 1-bit.
    }

    // ── Tests de reducir_docx ────────────────────────────────────────────────

    // Construye un ZIP mínimo con una imagen JPEG en word/media/. Simula la estructura
    // de un DOCX sin necesidad de XML válido (reducir_docx solo accede a las imágenes).
    fn docx_con_jpeg(jpeg: &[u8], nombre_imagen: &str) -> Vec<u8> {
        use std::io::Write;
        let mut buf = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut buf);
            let mut w = zip::ZipWriter::new(cursor);
            w.start_file(
                format!("word/media/{}", nombre_imagen),
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            ).unwrap();
            w.write_all(jpeg).unwrap();
            w.start_file(
                "[Content_Types].xml",
                zip::write::SimpleFileOptions::default(),
            ).unwrap();
            w.write_all(b"<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"></Types>").unwrap();
            w.finish().unwrap();
        }
        buf
    }

    // TEST: DOCX con JPEG de 3000px → reducir_docx lo baja a ≤CAP_PX y produce un ZIP más pequeño.
    #[test]
    fn docx_jpeg_grande_se_reduce() {
        let jpeg = jpeg_grande(3000);
        let docx = docx_con_jpeg(&jpeg, "image1.jpg");

        let reducido = reducir_docx(&docx)
            .expect("debe reducir DOCX con JPEG de 3000px");

        assert!(
            reducido.len() < docx.len(),
            "DOCX reducido ({} B) no es menor que el original ({} B)",
            reducido.len(), docx.len()
        );

        // El resultado debe ser un ZIP válido con la imagen presente.
        let mut archivo = zip::ZipArchive::new(std::io::Cursor::new(&reducido)).unwrap();
        assert!(
            archivo.by_name("word/media/image1.jpg").is_ok(),
            "la imagen debe seguir presente en el DOCX reducido"
        );
    }

    // TEST: DOCX con JPEG pequeño (<= CAP_PX) → reducir_docx devuelve None (no hay qué reducir).
    #[test]
    fn docx_jpeg_pequeno_no_se_toca() {
        let jpeg = jpeg_grande(800); // 800px < CAP_PX=2000
        let docx = docx_con_jpeg(&jpeg, "image1.jpg");
        assert!(
            reducir_docx(&docx).is_none(),
            "DOCX con JPEG ≤ CAP_PX no debe modificarse"
        );
    }

    // TEST: ZIP sin imágenes JPEG en word/media/ → reducir_docx devuelve None.
    #[test]
    fn docx_sin_imagenes_no_se_modifica() {
        use std::io::Write;
        let mut buf = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut buf);
            let mut w = zip::ZipWriter::new(cursor);
            w.start_file("word/document.xml",
                zip::write::SimpleFileOptions::default()).unwrap();
            w.write_all(b"<w:document/>").unwrap();
            w.finish().unwrap();
        }
        assert!(
            reducir_docx(&buf).is_none(),
            "DOCX sin imágenes JPEG no debe modificarse"
        );
    }
}
