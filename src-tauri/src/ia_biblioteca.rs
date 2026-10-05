use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use serde::Deserialize;

static BIBLIOTECA: OnceLock<Option<IndiceJuridico>> = OnceLock::new();

/// Embeddings densos de los fragmentos (opción B del RAG). Orden = mismo que
/// `IndiceJuridico::fragmentos`. Se rellena en `asegurar_embeddings` (carga de disco o
/// precálculo). Si queda en None, la búsqueda usa solo BM25 (sin regresión).
static EMBEDDINGS: Mutex<Option<Vec<Vec<f32>>>> = Mutex::new(None);
static EMB_PROCESADO: AtomicBool = AtomicBool::new(false);

/// Umbral mínimo de similitud coseno para que un fragmento denso cuente como relevante.
/// Si tras el filtro no queda nada, la búsqueda cae a BM25 (ver `buscar_normativa`).
const UMBRAL_COSENO: f32 = 0.30;

#[derive(Deserialize, Clone)]
pub struct FragmentoJuridico {
    pub abrev: String,
    pub articulo: String,
    pub titulo: Option<String>,
    pub capitulo: Option<String>,
    pub seccion: Option<String>,
    pub texto: String,
}

struct IndiceJuridico {
    fragmentos: Vec<FragmentoJuridico>,
    /// Inverted index: normalized_term -> [(doc_idx, tf)]
    indice: HashMap<String, Vec<(usize, f32)>>,
    df: HashMap<String, usize>,
    longitudes: Vec<usize>,
    longitud_media: f32,
}

/// Spanish stop words filtered during tokenization.
const STOP_WORDS: &[&str] = &[
    "de", "la", "el", "en", "que", "los", "las", "por", "con", "se",
    "del", "al", "su", "un", "una", "lo", "no", "es", "son", "fue",
    "ser", "ha", "han", "esta", "este", "estos", "estas", "como",
    "cuando", "cual", "para", "sobre", "entre", "sin", "hasta", "desde",
    "durante", "mediante", "ante", "bajo", "contra", "hacia", "le", "les",
    "mis", "sus", "asi", "tambien", "sino", "pues", "solo", "bien",
    "vez", "dicho", "dichos", "segun", "cada", "todo", "todos", "toda",
    "todas", "otro", "otros", "podr", "sera", "seran", "debera", "deberan",
    "podra", "podran", "tener", "hacer", "ello", "ellos", "ellas",
];

fn tokenizar(texto: &str) -> Vec<String> {
    let lower = texto
        .to_lowercase()
        .replace('á', "a")
        .replace('é', "e")
        .replace('í', "i")
        .replace('ó', "o")
        .replace(['ú', 'ü'], "u")
        .replace('ñ', "n");
    lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 3)
        .filter(|t| !STOP_WORDS.contains(t))
        .map(|t| t.to_string())
        .collect()
}

/// Maps common-language terms to legal synonyms for better recall.
fn expandir_sinonimos(terminos: &mut Vec<String>) {
    const SINONIMOS: &[(&str, &[&str])] = &[
        ("matar",      &["homicidio", "muerte"]),
        ("mato",       &["homicidio", "muerte"]),
        ("maten",      &["homicidio"]),
        ("asesinar",   &["asesinato", "homicidio"]),
        ("asesinato",  &["homicidio", "muerte"]),
        ("muertes",    &["homicidio", "muerte"]),
        ("robar",      &["hurto", "robo"]),
        ("robo",       &["hurto"]),
        ("hurtar",     &["hurto", "robo"]),
        ("carcel",     &["prision", "penitenciaria"]),
        ("preso",      &["detenido", "privacion", "libertad"]),
        ("presos",     &["detenidos"]),
        ("detencion",  &["privacion", "libertad"]),
        ("juicio",     &["proceso", "oral", "enjuiciamiento"]),
        ("juez",       &["tribunal", "magistrado"]),
        ("acusado",    &["imputado", "encausado"]),
        ("multa",      &["pena", "pecuniaria"]),
        ("pena",       &["condena", "sancion", "prision"]),
        ("victima",    &["perjudicado", "ofendido"]),
        ("abogado",    &["letrado", "defensor"]),
        ("menor",      &["menores", "lorpm"]),
        ("menores",    &["menor", "lorpm", "responsabilidad"]),
        ("droga",      &["sustancias", "estupefacientes"]),
        ("drogas",     &["sustancias", "estupefacientes", "trafico"]),
        ("narcotrafico",&["trafico", "drogas", "estupefacientes"]),
        ("secuestro",  &["detenciones", "ilegales", "privacion"]),
        ("estafa",     &["fraude", "engano", "perjuicio"]),
        ("falsedad",   &["falso", "falsificacion", "documental"]),
        ("falsificacion",&["falsedad", "documental"]),
        ("terrorismo", &["terrorista", "organizacion"]),
        ("violencia",  &["lesiones", "agresion"]),
        ("genero",     &["violencia", "mujer", "lovg"]),
        ("inocencia",  &["presuncion"]),
        ("defensa",    &["asistencia", "letrado", "derecho"]),
        ("tutela",     &["judicial", "efectiva", "derechos"]),
        ("habeas",     &["corpus", "privacion"]),
        ("recurso",    &["apelacion", "casacion"]),
        ("sentencia",  &["condena", "absolucion", "fallo"]),
        ("absolucion", &["sentencia", "inocencia"]),
        ("violacion",  &["agresion", "sexual"]),
        ("violar",     &["agresion", "sexual"]),
        ("denuncia",   &["querella", "acusacion"]),
        ("querella",   &["denuncia", "acusacion"]),
        ("fiscal",     &["ministerio", "publico"]),
        ("fraude",     &["estafa", "engano"]),
        ("lesiones",   &["lesion", "violencia", "agresion"]),
        ("libertad",   &["provisional", "prision", "detencion"]),
        ("prision",    &["privacion", "libertad", "penitenciaria"]),
        ("derechos",   &["fundamental", "constitucional"]),
        ("corrupcion", &["cohecho", "prevaricacion", "malversacion"]),
        ("soborno",    &["cohecho"]),
    ];

    let snapshot: Vec<String> = terminos.clone();
    for term in &snapshot {
        for (key, vals) in SINONIMOS {
            if *key == term.as_str() {
                for v in *vals {
                    let v = v.to_string();
                    if !terminos.contains(&v) {
                        terminos.push(v);
                    }
                }
            }
        }
    }
}

/// Extrae CITAS EXPLÍCITAS de la consulta para reforzarlas en la búsqueda:
/// - números de artículo precedidos de «art»/«artículo»/«arts.» (1-3 dígitos), y
/// - referencias de jurisprudencia del TC con forma «N/AAAA» (p. ej. STC 1/1995).
/// Solo se cogen números tras un indicador «art» para NO confundir cifras sueltas del
/// documento (importes, años, plazos) con artículos. Devuelve refs normalizadas en
/// minúscula: artículos como "138" y STCs como "1/1995".
fn referencias_articulo(query: &str) -> Vec<String> {
    let q = query.to_lowercase();
    let mut refs: Vec<String> = Vec::new();

    // STC «N/AAAA» (patrón inequívoco: lo cogemos aparezca donde aparezca).
    for tok in q.split(|c: char| !(c.is_ascii_digit() || c == '/')) {
        if let Some((a, b)) = tok.split_once('/') {
            if !a.is_empty()
                && a.chars().all(|c| c.is_ascii_digit())
                && b.len() >= 2
                && b.chars().all(|c| c.is_ascii_digit())
            {
                refs.push(tok.to_string());
            }
        }
    }

    // «art[ículo] N»: número de artículo solo tras un indicador, para evitar ruido.
    let palabras: Vec<&str> = q.split_whitespace().collect();
    for (i, w) in palabras.iter().enumerate() {
        if w.starts_with("art") {
            for j in 1..=2 {
                if let Some(nw) = palabras.get(i + j) {
                    let num: String = nw.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if !num.is_empty() && num.len() <= 3 {
                        refs.push(num);
                        break;
                    }
                }
            }
        }
    }

    refs.sort();
    refs.dedup();
    refs
}

impl IndiceJuridico {
    fn construir(fragmentos: Vec<FragmentoJuridico>) -> Self {
        let n = fragmentos.len();
        let mut df: HashMap<String, usize> = HashMap::new();
        let mut tfs_por_doc: Vec<HashMap<String, usize>> = Vec::with_capacity(n);
        let mut longitudes = Vec::with_capacity(n);

        for frag in &fragmentos {
            // Include articulo number + abrev so "art. 138 CP" queries find the right fragment.
            // Also inject scope disambiguation tokens to reduce cross-law false matches:
            // LORPM fragments get "menores edad" boosted so they rank lower on adult queries.
            // LOHC fragments get "habeas corpus adultos" to rank higher on HC queries.
            let scope_boost = match frag.abrev.as_str() {
                "LORPM" => " menores edad menor adolescente juvenil lorpm",
                "LOHC"  => " habeas corpus detencion ilegal adulto libertad inmediata",
                "LOVG"  => " violencia genero mujer victima",
                "MEP"   => " modelo escrito procesal plantilla formato estructura como redactar",
                _       => "",
            };
            let contenido = format!(
                "{} {} {} {} {} {}{}",
                frag.texto,
                frag.articulo,
                frag.abrev,
                frag.titulo.as_deref().unwrap_or(""),
                frag.capitulo.as_deref().unwrap_or(""),
                frag.seccion.as_deref().unwrap_or(""),
                scope_boost
            );
            let tokens = tokenizar(&contenido);
            longitudes.push(tokens.len().max(1));

            let mut tfs: HashMap<String, usize> = HashMap::new();
            for tok in &tokens {
                *tfs.entry(tok.clone()).or_insert(0) += 1;
            }
            for term in tfs.keys() {
                *df.entry(term.clone()).or_insert(0) += 1;
            }
            tfs_por_doc.push(tfs);
        }

        let longitud_media = if n > 0 {
            longitudes.iter().sum::<usize>() as f32 / n as f32
        } else {
            1.0
        };

        let mut indice: HashMap<String, Vec<(usize, f32)>> = HashMap::new();
        for (doc_idx, tfs) in tfs_por_doc.iter().enumerate() {
            for (term, &tf) in tfs {
                indice
                    .entry(term.clone())
                    .or_default()
                    .push((doc_idx, tf as f32));
            }
        }

        Self { fragmentos, indice, df, longitudes, longitud_media }
    }

    fn buscar(&self, query: &str, max: usize, umbral: f32) -> Vec<(f32, &FragmentoJuridico)> {
        let n = self.fragmentos.len() as f32;
        const K1: f32 = 1.2;
        const B: f32 = 0.75;

        let mut terminos = tokenizar(query);
        expandir_sinonimos(&mut terminos);

        if terminos.is_empty() {
            return vec![];
        }

        let mut scores: HashMap<usize, f32> = HashMap::new();

        for term in &terminos {
            let df = *self.df.get(term).unwrap_or(&0) as f32;
            if df < 0.5 {
                continue;
            }
            // BM25 IDF formula
            let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();

            if let Some(postings) = self.indice.get(term) {
                for &(doc_idx, tf) in postings {
                    let dl = self.longitudes[doc_idx] as f32;
                    let norm = 1.0 - B + B * dl / self.longitud_media;
                    let tf_bm25 = tf * (K1 + 1.0) / (tf + K1 * norm);
                    *scores.entry(doc_idx).or_insert(0.0) += idf * tf_bm25;
                }
            }
        }

        // BOOST POR CITA EXPLÍCITA: si la consulta cita «art. N» o «STC N/AAAA», el
        // fragmento de ESE artículo/sentencia debe aparecer sí o sí. Es la señal más
        // fuerte de intención del usuario, así que domina el ranking BM25 general.
        // Las refs con «/» son STC (solo casan con fragmentos STC); el resto son números
        // de artículo (solo casan con leyes, no con STC, para no cruzar "24" con "24/1988").
        let refs = referencias_articulo(query);
        if !refs.is_empty() {
            const BOOST: f32 = 20.0;
            for (idx, frag) in self.fragmentos.iter().enumerate() {
                let art = frag.articulo.to_lowercase();
                let es_stc = frag.abrev == "STC";
                let casa = refs.iter().any(|r| {
                    if r.contains('/') {
                        es_stc && art == *r
                    } else {
                        !es_stc && (art == *r || art.starts_with(&format!("{r} ")))
                    }
                });
                if casa {
                    *scores.entry(idx).or_insert(0.0) += BOOST;
                }
            }
        }

        let mut resultados: Vec<(f32, &FragmentoJuridico)> = scores
            .into_iter()
            .filter(|&(_, s)| s >= umbral)
            .map(|(idx, s)| (s, &self.fragmentos[idx]))
            .collect();

        resultados.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        resultados.truncate(max);
        resultados
    }
}

fn ruta_biblioteca() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_default()
        .join("Babel")
        .join("biblioteca_juridica")
        .join("index.json")
}

// ── RAG semántico (opción B): embeddings densos + búsqueda híbrida ──────────────────

fn ruta_embeddings_bin() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_default()
        .join("Babel")
        .join("biblioteca_juridica")
        .join("embeddings.bin")
}

/// Texto representativo de un fragmento para embeberlo. DEBE coincidir con el usado al
/// generar el fichero de embeddings (texto + artículo + abreviatura + título, 900 chars).
fn doc_text(f: &FragmentoJuridico) -> String {
    let extra: Vec<&str> = [f.articulo.as_str(), f.abrev.as_str(), f.titulo.as_deref().unwrap_or("")]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();
    let full = format!("{} {}", f.texto, extra.join(" "));
    full.chars().take(900).collect()
}

/// Formato del fichero: [u32 LE dim][f32 LE × dim × n]. `n` se infiere del tamaño.
/// Devuelve None (→ BM25) si no existe, está corrupto o el nº de vectores no cuadra.
fn cargar_embeddings_de_disco(n_frags: usize) -> Option<Vec<Vec<f32>>> {
    let datos = std::fs::read(ruta_embeddings_bin()).ok()?;
    if datos.len() < 4 {
        return None;
    }
    let dim = u32::from_le_bytes([datos[0], datos[1], datos[2], datos[3]]) as usize;
    if dim == 0 {
        return None;
    }
    let total_floats = (datos.len() - 4) / 4;
    if total_floats % dim != 0 {
        return None;
    }
    let count = total_floats / dim;
    if count != n_frags {
        log::warn!("[EMB] embeddings.bin tiene {count} vectores pero hay {n_frags} fragmentos: se ignora");
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let mut v = Vec::with_capacity(dim);
        for j in 0..dim {
            let off = 4 + (i * dim + j) * 4;
            v.push(f32::from_le_bytes([datos[off], datos[off + 1], datos[off + 2], datos[off + 3]]));
        }
        out.push(v);
    }
    Some(out)
}

fn guardar_embeddings_en_disco(embs: &[Vec<f32>]) {
    let Some(dim) = embs.first().map(|v| v.len()) else { return };
    let mut buf = Vec::with_capacity(4 + embs.len() * dim * 4);
    buf.extend_from_slice(&(dim as u32).to_le_bytes());
    for v in embs {
        for x in v {
            buf.extend_from_slice(&x.to_le_bytes());
        }
    }
    let ruta = ruta_embeddings_bin();
    if let Err(e) = std::fs::write(&ruta, &buf) {
        log::warn!("[EMB] no se pudieron guardar los embeddings: {e}");
    } else {
        log::info!("[EMB] embeddings guardados: {} vectores dim {dim}", embs.len());
    }
}

/// En segundo plano al arrancar: deja los embeddings de la biblioteca listos en RAM.
/// 1) Si existe `embeddings.bin` y cuadra con el nº de fragmentos → lo carga.
/// 2) Si no, y hay embedder instalado → los precalcula (una vez, ~minutos) y los guarda.
/// 3) Si no hay embedder → no hace nada (la búsqueda seguirá en BM25).
pub fn asegurar_embeddings() {
    if EMB_PROCESADO.swap(true, Ordering::AcqRel) {
        return;
    }
    let Some(biblio) = obtener_biblioteca() else { return };
    let n = biblio.fragmentos.len();

    if let Some(v) = cargar_embeddings_de_disco(n) {
        *EMBEDDINGS.lock().unwrap() = Some(v);
        log::info!("[EMB] embeddings cargados de disco ({n} fragmentos)");
        return;
    }
    if !crate::ia_embeddings::disponible() {
        log::info!("[EMB] sin modelo embedder: la biblioteca usará solo BM25");
        return;
    }

    log::info!("[EMB] precalculando embeddings de {n} fragmentos (una sola vez)…");
    let mut all: Vec<Vec<f32>> = Vec::with_capacity(n);
    let textos: Vec<String> = biblio
        .fragmentos
        .iter()
        .map(|f| format!("{}{}", crate::ia_embeddings::PREFIJO_DOC, doc_text(f)))
        .collect();
    for chunk in textos.chunks(16) {
        match crate::ia_embeddings::embed(chunk) {
            Some(mut e) => all.append(&mut e),
            None => {
                log::warn!("[EMB] fallo al precalcular embeddings: se usará BM25");
                return;
            }
        }
    }
    guardar_embeddings_en_disco(&all);
    *EMBEDDINGS.lock().unwrap() = Some(all);
    log::info!("[EMB] embeddings listos ({n} fragmentos)");
}

/// Búsqueda SEMÁNTICA: coseno entre la consulta y cada fragmento, con BOOST por cita
/// explícita de artículo/STC (lo único que el denso no hace tan bien como BM25).
/// Devuelve índices de fragmento ordenados. None si no hay embeddings o el embedder no
/// responde → el llamador cae a BM25.
fn buscar_dense(biblio: &IndiceJuridico, query: &str, max: usize) -> Option<Vec<(f32, usize)>> {
    // Embeber la consulta ANTES de tomar el lock (es una llamada de red).
    let qv = crate::ia_embeddings::embed_query(query)?;
    let guard = EMBEDDINGS.lock().ok()?;
    let embs = guard.as_ref()?;
    if embs.len() != biblio.fragmentos.len() || embs.first().map(|v| v.len()) != Some(qv.len()) {
        return None;
    }

    let refs = referencias_articulo(query);
    let mut scored: Vec<(f32, usize)> = Vec::with_capacity(embs.len());
    for (i, e) in embs.iter().enumerate() {
        // Coseno = producto escalar (ambos vectores están L2-normalizados).
        let mut cos = 0.0f32;
        for k in 0..qv.len() {
            cos += qv[k] * e[k];
        }
        // BOOST por cita explícita (misma lógica que BM25): el artículo/STC citado sube
        // al top sí o sí. Sumar 1.0 lo garantiza (el coseno vive en [-1, 1]).
        if !refs.is_empty() {
            let frag = &biblio.fragmentos[i];
            let art = frag.articulo.to_lowercase();
            let es_stc = frag.abrev == "STC";
            let casa = refs.iter().any(|r| {
                if r.contains('/') {
                    es_stc && art == *r
                } else {
                    !es_stc && (art == *r || art.starts_with(&format!("{r} ")))
                }
            });
            if casa {
                cos += 1.0;
            }
        }
        if cos >= UMBRAL_COSENO {
            scored.push((cos, i));
        }
    }
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    scored.truncate(max);
    Some(scored)
}

fn cargar_biblioteca() -> Option<IndiceJuridico> {
    let ruta = ruta_biblioteca();
    if !ruta.exists() {
        return None;
    }
    let datos = std::fs::read_to_string(&ruta).ok()?;

    #[derive(Deserialize)]
    struct Index {
        fragmentos: Vec<FragmentoJuridico>,
    }

    let index: Index = serde_json::from_str(&datos).ok()?;
    if index.fragmentos.is_empty() {
        return None;
    }
    Some(IndiceJuridico::construir(index.fragmentos))
}

/// Returns a reference to the global BM25 index, loading it on first access.
/// Thread-safe: OnceLock guarantees at-most-once initialization.
pub fn obtener_biblioteca() -> Option<&'static IndiceJuridico> {
    BIBLIOTECA.get_or_init(cargar_biblioteca).as_ref()
}

/// Pre-warms the index at app startup so the first query has no latency.
pub fn precalentar() {
    let _ = obtener_biblioteca();
}

/// Searches for relevant legal fragments for `query`.
/// Returns `(formatted_block, found_something)`.
/// `max_chars`: approximate character budget for the entire normativa block.
pub fn buscar_normativa(query: &str, max_chars: usize) -> (String, bool) {
    let Some(biblio) = obtener_biblioteca() else {
        return (
            "[NORMATIVA: biblioteca jurídica no disponible — ~/Babel/biblioteca_juridica/index.json no encontrado]".into(),
            false,
        );
    };

    // Recuperar un conjunto AMPLIO (20) para que, tras el filtro de ámbito por ley, aún
    // queden holgadamente los 5 que se citan al modelo.
    // HÍBRIDO (opción B): intentar primero la búsqueda SEMÁNTICA (encuentra la ley
    // aunque el usuario no use las palabras técnicas). Si no hay embeddings, el embedder
    // no responde, o no supera el umbral, cae a BM25 → cero regresión.
    let resultados_brutos: Vec<(f32, &FragmentoJuridico)> = match buscar_dense(biblio, query, 20) {
        Some(idxs) if !idxs.is_empty() => {
            idxs.into_iter().map(|(s, i)| (s, &biblio.fragmentos[i])).collect()
        }
        _ => biblio.buscar(query, 20, 1.0),
    };

    // Post-retrieval scope filter: remove law fragments whose scope of application
    // doesn't match the query context, to avoid cross-law citation errors.
    let query_lower = query.to_lowercase();
    let es_contexto_menores = ["menor ", "menores", "adolescente", "juvenil", "lorpm", "joven"]
        .iter()
        .any(|t| query_lower.contains(t));
    let es_contexto_violencia_genero = ["genero", "género", "lovg", "violencia doméstica", "violencia de género"]
        .iter()
        .any(|t| query_lower.contains(t));

    let resultados: Vec<_> = resultados_brutos
        .into_iter()
        .filter(|(_, frag)| {
            // LORPM only applies to juveniles: skip for adult criminal contexts
            if frag.abrev == "LORPM" && !es_contexto_menores {
                return false;
            }
            // LOVG only applies to gender violence contexts
            if frag.abrev == "LOVG" && !es_contexto_violencia_genero {
                return false;
            }
            true
        })
        .collect();

    if resultados.is_empty() {
        return (
            "[NORMATIVA JURÍDICA LOCAL: no se han encontrado artículos relacionados con esta solicitud en la biblioteca local]".into(),
            false,
        );
    }

    let mut bloque = String::from(
        "[NORMATIVA JURÍDICA LOCAL — cita cada fuente que uses: leyes como «art. X ABREV» (ej: art. 138 CP, art. 24 CE, art. 520 LECrim); jurisprudencia TC como «STC X/YEAR» (ej: STC 1/1995)]\n",
    );
    let mut chars_usados = bloque.len();

    for (_, frag) in resultados.iter().take(5) {
        let titulo_str = frag.titulo.as_deref().map(|t| format!(" | {}", t)).unwrap_or_default();
        let texto_truncado = if frag.texto.len() > 800 {
            // Retroceder hasta el límite de carácter UTF-8 más próximo a 800 bytes
            let mut end = 800;
            while end > 0 && !frag.texto.is_char_boundary(end) { end -= 1; }
            format!("{}…", &frag.texto[..end])
        } else {
            frag.texto.clone()
        };
        // STC → "STC X/YEAR"; MEP → "Modelo: titulo"; leyes → "ABREV art. X"
        let cabecera = if frag.abrev == "STC" {
            format!("▸ STC {}{}", frag.articulo, titulo_str)
        } else if frag.abrev == "MEP" {
            let titulo = frag.titulo.as_deref().unwrap_or("Modelo procesal");
            format!("▸ {}", titulo)
        } else {
            format!("▸ {} art. {}{}", frag.abrev, frag.articulo, titulo_str)
        };
        let entrada = format!("\n{}\n{}\n", cabecera, texto_truncado);
        if chars_usados + entrada.len() > max_chars {
            break;
        }
        bloque.push_str(&entrada);
        chars_usados += entrada.len();
    }

    (bloque, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fragmento(abrev: &str, articulo: &str, texto: &str) -> FragmentoJuridico {
        FragmentoJuridico {
            abrev: abrev.into(),
            articulo: articulo.into(),
            titulo: None,
            capitulo: None,
            seccion: None,
            texto: texto.into(),
        }
    }

    fn indice_prueba() -> IndiceJuridico {
        IndiceJuridico::construir(vec![
            fragmento("CP", "138", "El que matare a otro será castigado como reo de homicidio con prisión de diez a quince años."),
            fragmento("CP", "234", "El que con ánimo de lucro tomare las cosas muebles ajenas sin la voluntad de su dueño será castigado por hurto."),
            fragmento("CE", "24", "Todas las personas tienen derecho a obtener la tutela efectiva de los jueces y tribunales."),
            fragmento("LECrim", "520", "La detención preventiva no podrá durar más del tiempo estrictamente necesario. El detenido tiene derecho a asistencia de abogado."),
            fragmento("CP", "139", "Será castigado con pena de prisión de quince a veinticinco años como reo de asesinato el que matare a otro concurriendo alevosía."),
        ])
    }

    #[test]
    fn homicidio_recupera_art138() {
        let idx = indice_prueba();
        let res = idx.buscar("redacta un escrito sobre un caso de homicidio", 3, 0.5);
        assert!(!res.is_empty(), "debe encontrar al menos un resultado");
        assert!(res[0].1.articulo == "138" || res[0].1.articulo == "139",
            "el top resultado debe ser homicidio CP");
    }

    #[test]
    fn matar_sinonimo_encuentra_homicidio() {
        let idx = indice_prueba();
        let res = idx.buscar("alguien que mato a otra persona", 3, 0.5);
        assert!(!res.is_empty());
        let arts: Vec<&str> = res.iter().map(|(_, f)| f.articulo.as_str()).collect();
        assert!(arts.contains(&"138") || arts.contains(&"139"),
            "expansión de sinónimo 'matar' debe recuperar arts. 138/139");
    }

    #[test]
    fn hurto_recuperado_por_robar() {
        let idx = indice_prueba();
        let res = idx.buscar("quiero saber sobre robar objetos ajenos", 3, 0.5);
        assert!(!res.is_empty());
        assert!(res.iter().any(|(_, f)| f.articulo == "234"), "debe recuperar art. 234 (hurto)");
    }

    #[test]
    fn tutela_judicial_recupera_ce24() {
        let idx = indice_prueba();
        let res = idx.buscar("derecho a la tutela judicial efectiva", 3, 0.5);
        assert!(!res.is_empty());
        assert_eq!(res[0].1.articulo, "24", "top result debe ser CE art. 24");
    }

    #[test]
    fn query_irrelevante_devuelve_vacio() {
        let idx = indice_prueba();
        let res = idx.buscar("compra de inmuebles hipoteca registro", 3, 1.0);
        // Should not find relevant fragments (all are criminal law, not real estate)
        assert!(res.is_empty() || res[0].0 < 2.0, "query irrelevante no debe devolver resultados de alta puntuación");
    }

    // ── Boost por cita explícita de artículo / STC ───────────────────────

    #[test]
    fn referencias_extrae_articulo_y_stc() {
        assert_eq!(referencias_articulo("según el art. 138 del CP"), vec!["138"]);
        // STC N/AAAA + artículo, orden alfabético tras sort/dedup
        assert_eq!(referencias_articulo("ver STC 1/1995 y el artículo 24"), vec!["1/1995", "24"]);
        // Cifras sueltas del documento (importes, años) NO deben tomarse como artículos
        assert!(referencias_articulo("pagó 800 euros en el año 2024").is_empty());
    }

    #[test]
    fn cita_explicita_de_articulo_sube_al_top() {
        let idx = indice_prueba();
        // Pide EXPLÍCITAMENTE el 139 (asesinato): debe ganar al 138 pese a que el texto
        // genérico de homicidio suele rankear primero.
        let res = idx.buscar("redacta conforme al art. 139", 3, 0.5);
        assert!(!res.is_empty());
        assert_eq!(res[0].1.articulo, "139", "la cita explícita del art. 139 debe quedar top");
    }

    #[test]
    fn cita_articulo_procesal_recuperada() {
        let idx = indice_prueba();
        // "art. 520 LECrim" debe recuperar ese artículo aunque la consulta no describa el tema.
        let res = idx.buscar("aplica el art. 520", 3, 0.5);
        assert!(res.iter().any(|(_, f)| f.articulo == "520"),
            "la cita del art. 520 debe recuperar el fragmento de LECrim 520");
    }

    #[test]
    fn stc_boost_no_cruza_con_numero_de_articulo() {
        // Un índice con una STC "24/1988" y la CE art. 24: pedir "art. 24" NO debe
        // disparar la STC 24/1988 (refs de artículo solo casan con leyes, no con STC).
        let idx = IndiceJuridico::construir(vec![
            fragmento("CE", "24", "Derecho a la tutela judicial efectiva de jueces y tribunales."),
            fragmento("STC", "24/1988", "Doctrina del Tribunal Constitucional sobre la presunción de inocencia."),
        ]);
        let res = idx.buscar("conforme al art. 24", 2, 0.5);
        assert_eq!(res[0].1.abrev, "CE", "art. 24 debe casar con la ley CE, no con la STC 24/1988");
    }

    #[test]
    fn buscar_normativa_formato_correcto() {
        // Solo testar la función sobre el índice real si existe el archivo
        let ruta = dirs::home_dir()
            .unwrap_or_default()
            .join("Babel")
            .join("biblioteca_juridica")
            .join("index.json");
        if !ruta.exists() {
            return; // Skip in CI
        }
        let (bloque, encontrado) = buscar_normativa("homicidio código penal", 6000);
        if encontrado {
            assert!(bloque.contains("NORMATIVA JURÍDICA LOCAL"), "bloque debe tener cabecera");
            assert!(bloque.contains("CP") || bloque.contains("CE") || bloque.contains("LECrim"),
                "debe incluir referencia a alguna ley");
        }
    }

    #[test]
    fn tokenizar_normaliza_acentos() {
        let tokens = tokenizar("Artículo sobre detención provisional");
        assert!(tokens.contains(&"articulo".to_string()));
        assert!(tokens.contains(&"detencion".to_string()));
        assert!(tokens.contains(&"provisional".to_string()));
    }
}

#[cfg(test)]
mod test_mep {
    use super::*;

    /// La biblioteca jurídica (index.json, ~3200 fragmentos) NO está en el repo: es data
    /// bundled en ~/Babel/biblioteca_juridica. Estos son tests de INTEGRACIÓN del corpus
    /// real; si no está disponible (p. ej. un CI limpio), se omiten en vez de fallar.
    fn corpus_o_skip() -> bool {
        if obtener_biblioteca().is_some() {
            true
        } else {
            eprintln!("[test_mep] biblioteca jurídica no disponible — test omitido");
            false
        }
    }

    #[test]
    fn embeddings_disco_cuadran_con_fragmentos() {
        if !corpus_o_skip() { return; }
        // Solo si el fichero de embeddings existe en este equipo (no se distribuye).
        if !ruta_embeddings_bin().exists() {
            eprintln!("[test] embeddings.bin no presente — test omitido");
            return;
        }
        let n = obtener_biblioteca().unwrap().fragmentos.len();
        let embs = cargar_embeddings_de_disco(n)
            .expect("embeddings.bin existe pero no carga o el nº de vectores no cuadra");
        assert_eq!(embs.len(), n, "un vector por fragmento");
        assert!(embs[0].len() >= 256, "dimensión de embedding razonable (got {})", embs[0].len());
    }

    #[test]
    fn mep_recuperado_en_query_calificacion() {
        if !corpus_o_skip() { return; }
        let (bloque, _) = buscar_normativa("Redacta una calificación provisional de la acusación por delito de estafa", 8000);
        assert!(bloque.contains("MEP") || bloque.contains("Modelo de calificación"),
            "Debe recuperar modelo MEP para calificación: {}", &bloque[..200.min(bloque.len())]);
    }
    #[test]
    fn mep_o_ley_recuperado_en_query_denuncia() {
        if !corpus_o_skip() { return; }
        let (bloque, _) = buscar_normativa("Redacta una denuncia por robo con fuerza en domicilio", 8000);
        // Para queries de crimen específico, la ley (CP art. 238) es lo más relevante.
        // MEP puede o no aparecer en el top-6 dependiendo del ranking BM25.
        assert!(bloque.contains("CP") || bloque.contains("LECRIM") || bloque.contains("MEP"),
            "Debe recuperar CP o LECrim o MEP para denuncia: {}", &bloque[..200.min(bloque.len())]);
    }
    #[test]
    fn mep_recuperado_en_query_habeas_corpus() {
        if !corpus_o_skip() { return; }
        let (bloque, _) = buscar_normativa("Redacta un habeas corpus para persona detenida más de 72 horas", 8000);
        assert!(bloque.contains("MEP") || bloque.contains("habeas corpus") || bloque.contains("LOHC"),
            "Debe recuperar modelo habeas corpus: {}", &bloque[..200.min(bloque.len())]);
    }
}
