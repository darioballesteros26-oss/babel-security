use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::OnceLock;

use serde::Deserialize;

static BIBLIOTECA: OnceLock<Option<IndiceJuridico>> = OnceLock::new();

#[derive(Deserialize, Clone)]
pub struct FragmentoJuridico {
    pub ley: String,
    pub abrev: String,
    pub articulo: String,
    pub titulo: Option<String>,
    pub capitulo: Option<String>,
    pub seccion: Option<String>,
    pub texto: String,
    pub fecha_consolidada: String,
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
        .replace('ú', "u")
        .replace('ü', "u")
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

impl IndiceJuridico {
    fn construir(fragmentos: Vec<FragmentoJuridico>) -> Self {
        let n = fragmentos.len();
        let mut df: HashMap<String, usize> = HashMap::new();
        let mut tfs_por_doc: Vec<HashMap<String, usize>> = Vec::with_capacity(n);
        let mut longitudes = Vec::with_capacity(n);

        for frag in &fragmentos {
            // Include articulo number + abrev so "art. 138 CP" queries find the right fragment
            let contenido = format!(
                "{} {} {} {} {} {}",
                frag.texto,
                frag.articulo,
                frag.abrev,
                frag.titulo.as_deref().unwrap_or(""),
                frag.capitulo.as_deref().unwrap_or(""),
                frag.seccion.as_deref().unwrap_or("")
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

    let resultados = biblio.buscar(query, 10, 1.0);

    if resultados.is_empty() {
        return (
            "[NORMATIVA JURÍDICA LOCAL: no se han encontrado artículos relacionados con esta solicitud en la biblioteca local]".into(),
            false,
        );
    }

    let mut bloque = String::from(
        "[NORMATIVA JURÍDICA LOCAL — cita con «art. X ABREV» (ej: art. 138 CP, art. 24 CE, art. 520 LECrim) cada artículo que uses en tu respuesta]\n",
    );
    let mut chars_usados = bloque.len();

    for (_, frag) in resultados.iter().take(5) {
        let titulo_str = frag.titulo.as_deref().map(|t| format!(" | {}", t)).unwrap_or_default();
        // Truncate long articles (e.g. LECrim 520) to stay within token budget
        let texto_truncado = if frag.texto.len() > 800 {
            format!("{}…", &frag.texto[..800])
        } else {
            frag.texto.clone()
        };
        let entrada = format!(
            "\n▸ {} art. {}{}\n{}\n",
            frag.abrev, frag.articulo, titulo_str, texto_truncado
        );
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
            ley: format!("Ley {}", abrev),
            abrev: abrev.into(),
            articulo: articulo.into(),
            titulo: None,
            capitulo: None,
            seccion: None,
            texto: texto.into(),
            fecha_consolidada: "2026-01-01".into(),
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
