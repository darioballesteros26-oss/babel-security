// Estampado de texto permanente sobre un PDF ya existente.
//
// El visor (modo «AÑADIR TEXTO») envía una lista de anotaciones con la posición
// —ya convertida a puntos PDF, origen abajo-izquierda— y Babel las incrusta en el
// contenido de cada página con una fuente Helvetica estándar (sin incrustar, con
// WinAnsiEncoding para que ñ/á/é… salgan bien). El texto queda como texto real del
// PDF: seleccionable, buscable y permanente, sin tocar el contenido previo.

use lopdf::content::{Content, Operation};
use lopdf::{Dictionary, Document, Object, ObjectId, Stream, StringFormat};
use serde::Deserialize;

/// Una anotación de texto a estampar en el PDF.
#[derive(Debug, Clone, Deserialize)]
pub struct AnotacionTexto {
    /// Página destino, 1-indexada (como la ve el usuario).
    pub pagina: u32,
    /// Coordenada X del inicio del texto, en puntos PDF (origen abajo-izquierda).
    pub x: f64,
    /// Coordenada Y de la línea base de la PRIMERA línea, en puntos PDF.
    pub y: f64,
    /// Tamaño de fuente en puntos.
    pub tamano: f64,
    /// Texto a estampar (puede contener saltos de línea).
    pub texto: String,
}

// Nombre del recurso de fuente que añadimos a cada página. Poco probable que
// colisione con fuentes existentes del documento.
const NOMBRE_FUENTE: &[u8] = b"FBabelTxt";

/// Estampa las anotaciones sobre el PDF y devuelve los bytes del PDF resultante.
/// No modifica el contenido previo: cada anotación se añade como contenido nuevo.
pub fn estampar_textos(pdf: &[u8], anotaciones: &[AnotacionTexto]) -> Result<Vec<u8>, String> {
    if anotaciones.is_empty() {
        return Err("No hay texto que añadir.".into());
    }

    let mut doc = Document::load_mem(pdf).map_err(|e| format!("PDF ilegible: {}", e))?;

    // Fuente Helvetica estándar (no se incrusta: es una de las 14 base de PDF).
    // WinAnsiEncoding cubre el español (ñ á é í ó ú ü ¿ ¡ …).
    let mut fuente = Dictionary::new();
    fuente.set("Type", Object::Name(b"Font".to_vec()));
    fuente.set("Subtype", Object::Name(b"Type1".to_vec()));
    fuente.set("BaseFont", Object::Name(b"Helvetica".to_vec()));
    fuente.set("Encoding", Object::Name(b"WinAnsiEncoding".to_vec()));
    let fuente_id = doc.add_object(fuente);

    // Mapa nº de página (1-indexado) → ObjectId de la página.
    let paginas: std::collections::BTreeMap<u32, ObjectId> = doc.get_pages();

    // Agrupar anotaciones por página para preparar cada página una sola vez.
    let mut por_pagina: std::collections::BTreeMap<u32, Vec<&AnotacionTexto>> =
        std::collections::BTreeMap::new();
    for anot in anotaciones {
        por_pagina.entry(anot.pagina).or_default().push(anot);
    }

    for (&num, anots) in &por_pagina {
        let page_id = *paginas
            .get(&num)
            .ok_or_else(|| format!("La página {} no existe.", num))?;

        asegurar_fuente(&mut doc, page_id, fuente_id)?;
        // Aislar el estado gráfico del contenido original (algunos PDFs invierten
        // el eje Y y no lo restauran, lo que dejaría nuestro texto boca abajo).
        aislar_contenido_original(&mut doc, page_id);

        for anot in anots {
            let content = construir_contenido(anot);
            doc.add_to_page_content(page_id, content)
                .map_err(|e| format!("No se pudo escribir en la página {}: {}", num, e))?;
        }
    }

    let mut salida = Vec::new();
    doc.save_to(&mut salida)
        .map_err(|e| format!("No se pudo guardar el PDF: {}", e))?;
    Ok(salida)
}

/// Garantiza que la página referencie nuestra fuente bajo `NOMBRE_FUENTE` dentro
/// de `/Resources /Font`, sin pisar recursos existentes ni heredados.
fn asegurar_fuente(doc: &mut Document, page_id: ObjectId, fuente_id: ObjectId) -> Result<(), String> {
    // Si la página NO tiene /Resources propios, hereda del nodo /Pages. Crear unos
    // vacíos los ocultaría y rompería el contenido existente, así que clonamos los
    // heredados más cercanos antes de añadir nada.
    let tiene_propios = doc
        .get_dictionary(page_id)
        .map(|d| d.has(b"Resources"))
        .unwrap_or(false);
    if !tiene_propios {
        let heredados: Dictionary = {
            let (_, ids) = doc
                .get_page_resources(page_id)
                .map_err(|e| format!("Recursos ilegibles: {}", e))?;
            ids.first()
                .and_then(|id| doc.get_dictionary(*id).ok())
                .cloned()
                .unwrap_or_default()
        };
        let page = doc
            .get_object_mut(page_id)
            .and_then(Object::as_dict_mut)
            .map_err(|e| format!("Página ilegible: {}", e))?;
        page.set("Resources", heredados);
    }

    // ¿Dónde vive el diccionario /Font? Puede ser inline, una referencia, o no existir.
    enum Destino {
        Inline,
        Ref(ObjectId),
    }
    let destino = {
        let res = doc
            .get_or_create_resources(page_id)
            .and_then(Object::as_dict_mut)
            .map_err(|e| format!("Recursos ilegibles: {}", e))?;
        match res.get(b"Font") {
            Ok(Object::Reference(id)) => Destino::Ref(*id),
            Ok(Object::Dictionary(_)) => Destino::Inline,
            _ => {
                res.set("Font", Object::Dictionary(Dictionary::new()));
                Destino::Inline
            }
        }
    };

    match destino {
        Destino::Inline => {
            let res = doc
                .get_or_create_resources(page_id)
                .and_then(Object::as_dict_mut)
                .map_err(|e| format!("Recursos ilegibles: {}", e))?;
            let fonts = res
                .get_mut(b"Font")
                .and_then(Object::as_dict_mut)
                .map_err(|e| format!("Diccionario de fuentes ilegible: {}", e))?;
            fonts.set(NOMBRE_FUENTE.to_vec(), Object::Reference(fuente_id));
        }
        Destino::Ref(id) => {
            let fonts = doc
                .get_object_mut(id)
                .and_then(Object::as_dict_mut)
                .map_err(|e| format!("Diccionario de fuentes ilegible: {}", e))?;
            fonts.set(NOMBRE_FUENTE.to_vec(), Object::Reference(fuente_id));
        }
    }
    Ok(())
}

/// Envuelve el contenido existente de la página en `q … Q`, insertando un flujo
/// `q` al principio y uno `Q` al final. Así cualquier transformación que el
/// contenido original deje activa (p. ej. un volteo del eje Y sin restaurar) queda
/// contenida y nuestro texto, añadido después, parte del sistema de coordenadas
/// por defecto del PDF (origen abajo-izquierda, Y hacia arriba).
///
/// Si la página no referencia sus flujos por array/referencia (caso raro de flujo
/// directo), no se toca: `get_page_contents` devuelve vacío y se omite el envoltorio.
fn aislar_contenido_original(doc: &mut Document, page_id: ObjectId) {
    let existentes = doc.get_page_contents(page_id);
    if existentes.is_empty() {
        return;
    }
    let q_id = doc.add_object(Stream::new(Dictionary::new(), b"q\n".to_vec()));
    let qq_id = doc.add_object(Stream::new(Dictionary::new(), b"Q\n".to_vec()));

    let mut nuevos: Vec<Object> = Vec::with_capacity(existentes.len() + 2);
    nuevos.push(Object::Reference(q_id));
    nuevos.extend(existentes.into_iter().map(Object::Reference));
    nuevos.push(Object::Reference(qq_id));

    if let Ok(page) = doc.get_object_mut(page_id).and_then(Object::as_dict_mut) {
        page.set("Contents", Object::Array(nuevos));
    }
}

/// Construye el flujo de contenido que dibuja el texto. Envuelto en q/Q para no
/// heredar estado gráfico de contenido previo; color negro; multilínea con
/// interlineado 1,2×.
fn construir_contenido(anot: &AnotacionTexto) -> Content<Vec<Operation>> {
    let tam = anot.tamano as f32;
    let interlineado = tam * 1.2;

    let mut ops: Vec<Operation> = vec![
        Operation::new("q", vec![]),
        Operation::new("BT", vec![]),
        Operation::new(
            "Tf",
            vec![Object::Name(NOMBRE_FUENTE.to_vec()), Object::Real(tam)],
        ),
        // Color de relleno negro.
        Operation::new(
            "rg",
            vec![Object::Real(0.0), Object::Real(0.0), Object::Real(0.0)],
        ),
        Operation::new(
            "Td",
            vec![Object::Real(anot.x as f32), Object::Real(anot.y as f32)],
        ),
    ];

    for (i, linea) in anot.texto.split('\n').enumerate() {
        if i > 0 {
            // Bajar a la siguiente línea.
            ops.push(Operation::new(
                "Td",
                vec![Object::Real(0.0), Object::Real(-interlineado)],
            ));
        }
        ops.push(Operation::new(
            "Tj",
            vec![Object::String(a_winansi(linea), StringFormat::Literal)],
        ));
    }

    ops.push(Operation::new("ET", vec![]));
    ops.push(Operation::new("Q", vec![]));
    Content { operations: ops }
}

/// Convierte texto UTF-8 a bytes WinAnsiEncoding (cp1252). Los caracteres latinos
/// comunes (incl. acentos y ñ) coinciden con Latin-1 (≥ 0xA0). Algunos signos
/// tipográficos del rango 0x80–0x9F se mapean explícitamente; lo no representable
/// cae a '?'. No se escapan paréntesis/barras aquí: lopdf lo hace al serializar
/// la cadena literal.
fn a_winansi(s: &str) -> Vec<u8> {
    s.chars()
        .map(|c| match c {
            // ASCII y Latin-1 directo.
            '\u{0000}'..='\u{00FF}' => c as u8,
            // Signos tipográficos frecuentes (cp1252 0x80–0x9F).
            '\u{20AC}' => 0x80, // €
            '\u{201A}' => 0x82, // ‚
            '\u{0192}' => 0x83, // ƒ
            '\u{201E}' => 0x84, // „
            '\u{2026}' => 0x85, // …
            '\u{2020}' => 0x86, // †
            '\u{2021}' => 0x87, // ‡
            '\u{02C6}' => 0x88, // ˆ
            '\u{2030}' => 0x89, // ‰
            '\u{0160}' => 0x8A, // Š
            '\u{2039}' => 0x8B, // ‹
            '\u{0152}' => 0x8C, // Œ
            '\u{2018}' => 0x91, // ‘
            '\u{2019}' => 0x92, // ’
            '\u{201C}' => 0x93, // “
            '\u{201D}' => 0x94, // ”
            '\u{2022}' => 0x95, // •
            '\u{2013}' => 0x96, // –
            '\u{2014}' => 0x97, // —
            '\u{02DC}' => 0x98, // ˜
            '\u{2122}' => 0x99, // ™
            '\u{0161}' => 0x9A, // š
            '\u{203A}' => 0x9B, // ›
            '\u{0153}' => 0x9C, // œ
            '\u{0178}' => 0x9F, // Ÿ
            _ => b'?',
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // PDF mínimo de 1 página A4-ish sin recursos propios (hereda de /Pages),
    // para ejercitar el camino de recursos heredados.
    fn pdf_una_pagina() -> Vec<u8> {
        b"%PDF-1.4\n\
1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n\
2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 595 842] >>endobj\n\
3 0 obj<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>endobj\n\
4 0 obj<< /Length 44 >>stream\nBT /F1 12 Tf 50 700 Td (Hola) Tj ET\nendstream endobj\n\
trailer<< /Root 1 0 R >>\n%%EOF"
            .to_vec()
    }

    #[test]
    fn estampa_texto_simple() {
        let base = pdf_una_pagina();
        let anots = vec![AnotacionTexto {
            pagina: 1,
            x: 100.0,
            y: 500.0,
            tamano: 14.0,
            texto: "Firmado en Madrid".into(),
        }];
        let salida = estampar_textos(&base, &anots).expect("debe estampar");
        // Se puede recargar y el texto nuevo aparece al extraer.
        let doc = Document::load_mem(&salida).expect("PDF válido");
        let txt = doc.extract_text(&[1]).unwrap_or_default();
        assert!(txt.contains("Firmado en Madrid"), "texto no estampado: {txt:?}");
        // El contenido previo NO se toca: el operador original sigue en la página.
        // (La fixture referencia una /F1 inexistente, así que extract_text no lo lee;
        // comprobamos el flujo de contenido crudo, que es lo que importa.)
        let pages = doc.get_pages();
        let page_id = *pages.get(&1).unwrap();
        let contenido = doc.get_page_content(page_id);
        assert!(
            contenido.windows(4).any(|w| w == b"Hola"),
            "se perdió el contenido original"
        );
    }

    #[test]
    fn acentos_y_enie_se_conservan() {
        let base = pdf_una_pagina();
        let anots = vec![AnotacionTexto {
            pagina: 1,
            x: 50.0,
            y: 400.0,
            tamano: 12.0,
            texto: "Año español: ñ á é í ó ú ü ¿ ¡".into(),
        }];
        let salida = estampar_textos(&base, &anots).expect("debe estampar");
        let doc = Document::load_mem(&salida).expect("PDF válido");
        let txt = doc.extract_text(&[1]).unwrap_or_default();
        assert!(txt.contains("Año español"), "acentos perdidos: {txt:?}");
    }

    #[test]
    fn multilinea_genera_dos_lineas() {
        let base = pdf_una_pagina();
        let anots = vec![AnotacionTexto {
            pagina: 1,
            x: 50.0,
            y: 400.0,
            tamano: 12.0,
            texto: "Primera\nSegunda".into(),
        }];
        let salida = estampar_textos(&base, &anots).expect("debe estampar");
        let doc = Document::load_mem(&salida).expect("PDF válido");
        let txt = doc.extract_text(&[1]).unwrap_or_default();
        assert!(txt.contains("Primera"), "falta primera línea: {txt:?}");
        assert!(txt.contains("Segunda"), "falta segunda línea: {txt:?}");
    }

    // Página cuyo contenido invierte el eje Y y NO lo restaura: nuestro texto, sin
    // aislamiento, saldría boca abajo. Verificamos que el contenido original queda
    // envuelto en q … Q antes de estampar.
    fn pdf_con_volteo() -> Vec<u8> {
        b"%PDF-1.4\n\
1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n\
2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 595 842] >>endobj\n\
3 0 obj<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>endobj\n\
4 0 obj<< /Length 46 >>stream\n1 0 0 -1 0 842 cm BT /F1 12 Tf 0 0 Td (X) Tj ET\nendstream endobj\n\
trailer<< /Root 1 0 R >>\n%%EOF"
            .to_vec()
    }

    #[test]
    fn aisla_el_contenido_original_para_no_heredar_volteo() {
        let base = pdf_con_volteo();
        let anots = vec![AnotacionTexto {
            pagina: 1,
            x: 50.0,
            y: 700.0,
            tamano: 12.0,
            texto: "Derecho".into(),
        }];
        let salida = estampar_textos(&base, &anots).expect("debe estampar");
        let doc = Document::load_mem(&salida).expect("PDF válido");
        let pages = doc.get_pages();
        let page_id = *pages.get(&1).unwrap();

        // El PRIMER flujo de contenido debe ser nuestro "q" de aislamiento.
        let flujos = doc.get_page_contents(page_id);
        assert!(flujos.len() >= 3, "faltan flujos de envoltorio: {}", flujos.len());
        if let Ok(Object::Stream(s)) = doc.get_object(flujos[0]) {
            assert_eq!(s.content, b"q\n", "el primer flujo no es el 'q' de aislamiento");
        } else {
            panic!("primer flujo de contenido no es un stream");
        }
        // Y el texto nuevo sigue presente.
        let txt = doc.extract_text(&[1]).unwrap_or_default();
        assert!(txt.contains("Derecho"), "texto no estampado: {txt:?}");
    }

    #[test]
    fn pagina_inexistente_es_error() {
        let base = pdf_una_pagina();
        let anots = vec![AnotacionTexto {
            pagina: 9,
            x: 0.0,
            y: 0.0,
            tamano: 12.0,
            texto: "x".into(),
        }];
        assert!(estampar_textos(&base, &anots).is_err());
    }

    #[test]
    fn lista_vacia_es_error() {
        let base = pdf_una_pagina();
        assert!(estampar_textos(&base, &[]).is_err());
    }
}
