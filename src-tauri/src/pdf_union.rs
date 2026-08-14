// ============================================================
// UNIÓN DE PDFs — 100% nativo con PDFium (motor de Chromium, licencia BSD-3).
//
// Sustituye al camino Python/PyMuPDF: la unión ocurre EN MEMORIA (los bytes en
// claro nunca tocan el disco) y sin depender del servidor. PDFium copia las
// páginas preservando texto y vectores (no rasteriza), igual que PyMuPDF.
//
// La librería nativa (libpdfium.dylib / pdfium.dll) se empaqueta como resource
// del bundle Tauri; `bind_pdfium` la localiza en ese directorio y, en su defecto,
// cae a la librería del sistema.
// ============================================================

use pdfium_render::prelude::*;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

// PDFium exige que `Pdfium::new` se llame UNA sola vez por proceso (inicializa
// bindings globales); volver a llamarlo aborta. Guardamos la instancia en un
// singleton. La feature `thread_safe` (activa por defecto) hace `Pdfium: Send+Sync`
// y serializa internamente las llamadas, así que compartir esta &'static entre
// los distintos `spawn_blocking` de las uniones es seguro.
static PDFIUM: OnceLock<Pdfium> = OnceLock::new();
static INIT_LOCK: Mutex<()> = Mutex::new(());

/// Devuelve la instancia global de PDFium, enlazándola una sola vez. `dirs` son
/// los directorios candidatos donde buscar la librería nativa; solo se usan en
/// la primera llamada.
pub fn pdfium(dirs: &[impl AsRef<Path>]) -> Result<&'static Pdfium, String> {
    if let Some(p) = PDFIUM.get() {
        return Ok(p);
    }
    // Serializa la inicialización para no llamar nunca a Pdfium::new dos veces.
    let _g = INIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(p) = PDFIUM.get() {
        return Ok(p);
    }
    let p = bind_pdfium(dirs)?;
    let _ = PDFIUM.set(p);
    Ok(PDFIUM.get().expect("PDFium recién inicializado"))
}

/// Enlaza con la librería PDFium probando cada directorio candidato en orden
/// (donde el bundle coloca libpdfium.dylib / pdfium.dll) y, si ninguno sirve,
/// cae a la librería del sistema. No llamar más de una vez por proceso.
fn bind_pdfium(dirs: &[impl AsRef<Path>]) -> Result<Pdfium, String> {
    for dir in dirs {
        if let Ok(bindings) =
            Pdfium::bind_to_library(Pdfium::pdfium_platform_library_name_at_path(dir.as_ref()))
        {
            return Ok(Pdfium::new(bindings));
        }
    }
    let bindings = Pdfium::bind_to_system_library()
        .map_err(|e| format!("No se pudo cargar el motor PDF: {}", e))?;
    Ok(Pdfium::new(bindings))
}

/// Carga un PDF desde memoria, traduciendo los errores de PDFium a mensajes
/// claros para el usuario (cifrado con contraseña vs. dañado).
fn cargar<'a>(pdfium: &'a Pdfium, bytes: &'a [u8]) -> Result<PdfDocument<'a>, String> {
    pdfium
        .load_pdf_from_byte_slice(bytes, None)
        .map_err(|e| match e {
            PdfiumError::PdfiumLibraryInternalError(PdfiumInternalError::PasswordError) => {
                "El PDF está protegido con contraseña.".to_string()
            }
            _ => "El PDF está dañado o no se puede leer.".to_string(),
        })
}

// PDFium (la librería C) NO es segura para llamadas concurrentes: la feature
// `thread_safe` solo aporta `Send+Sync`, no serializa las llamadas. Este lock
// de proceso serializa cada operación completa (carga + trabajo + save) para que
// dos uniones simultáneas nunca aborten el proceso.
static PDF_LOCK: Mutex<()> = Mutex::new(());

/// Cuenta las páginas de un PDF en memoria. Error claro si está cifrado/corrupto.
pub fn contar_paginas(pdfium: &Pdfium, bytes: &[u8]) -> Result<usize, String> {
    let _g = PDF_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let doc = cargar(pdfium, bytes)?;
    Ok(doc.pages().len() as usize)
}

/// Une los PDFs de `entradas` en el orden dado y devuelve el PDF resultante en
/// memoria. Todo-o-nada: si una entrada falla, retorna Err sin salida parcial.
pub fn unir(pdfium: &Pdfium, entradas: &[&[u8]]) -> Result<Vec<u8>, String> {
    if entradas.len() < 2 {
        return Err("Se necesitan al menos 2 PDFs para unir.".into());
    }
    let _g = PDF_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut dest = pdfium
        .create_new_pdf()
        .map_err(|e| format!("No se pudo crear el PDF unido: {}", e))?;

    for (i, &bytes) in entradas.iter().enumerate() {
        let src = cargar(pdfium, bytes).map_err(|e| format!("PDF #{}: {}", i + 1, e))?;
        dest.pages_mut()
            .append(&src)
            .map_err(|e| format!("No se pudieron añadir las páginas del PDF #{}: {}", i + 1, e))?;
    }

    dest.save_to_bytes()
        .map_err(|e| format!("No se pudo generar el PDF unido: {}", e))
}

/// Extrae el texto de cada página de un PDF en memoria (una String por página).
/// Serializado bajo el mismo lock que el resto de operaciones PDFium.
#[cfg(test)]
pub fn texto_por_pagina(pdfium: &Pdfium, bytes: &[u8]) -> Result<Vec<String>, String> {
    let _g = PDF_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let doc = cargar(pdfium, bytes)?;
    Ok(doc
        .pages()
        .iter()
        .map(|pg| pg.text().map(|t| t.all()).unwrap_or_default())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Localiza libpdfium para los tests: usa el dylib vendorizado del repo.
    // Comparte el singleton global (Pdfium::new solo puede invocarse una vez).
    fn pdfium() -> &'static Pdfium {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("binaries/pdfium");
        super::pdfium(&[dir]).expect("PDFium no disponible para los tests")
    }

    // Escribe un objeto PDF registrando su offset (1-based) para la tabla xref.
    fn push_obj(out: &mut Vec<u8>, offsets: &mut [usize], id: usize, body: &str) {
        offsets[id] = out.len();
        out.extend_from_slice(format!("{} 0 obj\n{}\nendobj\n", id, body).as_bytes());
    }

    // Genera un PDF válido (con xref correcta) donde cada `&str` es una página con
    // ese texto en Helvetica. Determinista, sin depender de la API de creación de PDFium.
    fn make_pdf(textos: &[&str]) -> Vec<u8> {
        let n = textos.len();
        let total = 3 + 2 * n; // catalog, pages, font, + (página + contenido) por hoja
        let mut offsets = vec![0usize; total + 1];
        let mut out = Vec::new();
        out.extend_from_slice(b"%PDF-1.4\n");

        push_obj(&mut out, &mut offsets, 1, "<< /Type /Catalog /Pages 2 0 R >>");
        let kids: String = (0..n).map(|i| format!("{} 0 R", 4 + 2 * i)).collect::<Vec<_>>().join(" ");
        push_obj(&mut out, &mut offsets, 2,
            &format!("<< /Type /Pages /Kids [{}] /Count {} >>", kids, n));
        push_obj(&mut out, &mut offsets, 3,
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");

        for (i, t) in textos.iter().enumerate() {
            let page_id = 4 + 2 * i;
            let content_id = 5 + 2 * i;
            push_obj(&mut out, &mut offsets, page_id, &format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Contents {} 0 R \
                 /Resources << /Font << /F1 3 0 R >> >> >>", content_id));
            let stream = format!("BT /F1 24 Tf 40 150 Td ({}) Tj ET", t);
            push_obj(&mut out, &mut offsets, content_id,
                &format!("<< /Length {} >>\nstream\n{}\nendstream", stream.len(), stream));
        }

        let xref_off = out.len();
        out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", total + 1).as_bytes());
        for id in 1..=total {
            out.extend_from_slice(format!("{:010} 00000 n \n", offsets[id]).as_bytes());
        }
        out.extend_from_slice(format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF",
            total + 1, xref_off).as_bytes());
        out
    }

    // PDF de `n` páginas, cada una con el texto "Pagina {k}".
    fn pdf_de(n: usize) -> Vec<u8> {
        let textos: Vec<String> = (1..=n).map(|k| format!("Pagina {}", k)).collect();
        make_pdf(&textos.iter().map(|s| s.as_str()).collect::<Vec<_>>())
    }

    fn texto_de(pdfium: &Pdfium, bytes: &[u8]) -> String {
        texto_por_pagina(pdfium, bytes).unwrap().join("\n")
    }

    #[test]
    fn contar_paginas_ok() {
        let p = pdfium();
        assert_eq!(contar_paginas(p, &pdf_de(3)).unwrap(), 3);
        assert_eq!(contar_paginas(p, &pdf_de(1)).unwrap(), 1);
    }

    #[test]
    fn unir_dos_pdfs() {
        let p = pdfium();
        let (a, b) = (pdf_de(2), pdf_de(3));
        let out = unir(p, &[a.as_slice(), b.as_slice()]).unwrap();
        assert_eq!(contar_paginas(p, &out).unwrap(), 5);
    }

    #[test]
    fn unir_cinco_pdfs() {
        let p = pdfium();
        let entradas: Vec<Vec<u8>> = (1..=5).map(pdf_de).collect();
        let refs: Vec<&[u8]> = entradas.iter().map(|v| v.as_slice()).collect();
        let esperado: usize = (1..=5).sum();
        let out = unir(p, &refs).unwrap();
        assert_eq!(contar_paginas(p, &out).unwrap(), esperado);
    }

    #[test]
    fn respeta_el_orden() {
        // a = 1 pág ("SOLO_A"), b = 2 págs. Al unir [b, a] la última página es "SOLO_A".
        let p = pdfium();
        let a = make_pdf(&["SOLO_A"]);
        let b = make_pdf(&["B_UNO", "B_DOS"]);
        let out = unir(p, &[b.as_slice(), a.as_slice()]).unwrap();
        let paginas = texto_por_pagina(p, &out).unwrap();
        let ultima = paginas.last().expect("el PDF unido no tiene páginas");
        assert!(ultima.contains("SOLO_A"), "última página inesperada: {:?}", ultima);
    }

    #[test]
    fn texto_sigue_extraible() {
        let p = pdfium();
        let (u, v) = (pdf_de(1), pdf_de(1));
        let out = unir(p, &[u.as_slice(), v.as_slice()]).unwrap();
        assert!(texto_de(p, &out).contains("Pagina 1"));
    }

    #[test]
    fn pdf_corrupto_da_error() {
        let p = pdfium();
        let basura = b"esto no es un PDF".to_vec();
        assert!(contar_paginas(p, &basura).is_err());
        let bueno = pdf_de(1);
        assert!(unir(p, &[bueno.as_slice(), basura.as_slice()]).is_err());
    }
}
