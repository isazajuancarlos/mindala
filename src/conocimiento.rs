// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: MIT

//! R5 · fuentes de CONOCIMIENTO. El eje de INTELIGENCIA que no es un repo: novedades,
//! advisories e incidentes que hay que conocer para estar al día —seguridad, cripto,
//! IA, mejoras de Rust, paradigmas—. Mientras R1-R3 traen TÉCNICAS empaquetadas como
//! repositorios, R5 trae SABER: un ítem de feed (título + enlace + fecha), categorizado
//! por relevancia a nuestro stack (reusa `categoria`, D9) y recordado en `bd` para que
//! el digest destaque solo lo nuevo (D5).
//!
//! Dep-free A PROPÓSITO: el parseo de RSS/Atom es por ESCANEO DE TEXTO (como
//! `fuentes::extraer_repos_de_texto`), no con un parser XML —`quick-xml`, el candidato
//! obvio, arrastra RUSTSEC-2026-0194/0195, justo lo que el lazo R6 caza—. Los feeds
//! curados son RSS/Atom estables; un extractor tolerante de `<item>`/`<entry>` basta.
//! Solo `traer_feed` toca la red, keyless igual que `github` (regla 1).

use crate::github::cliente;
use anyhow::{Context, Result};

/// Un ítem de conocimiento pescado de un feed: lo mínimo que el digest necesita.
/// El resumen/cuerpo NO se ALMACENA (ruido; el criterio abre el enlace si le interesa),
/// pero SÍ se captura para CATEGORIZAR por texto completo: un advisory cuyo título es
/// genérico (`RUSTSEC-2026-xxxx`) suele nombrar el crate/dominio en el cuerpo (D16, antes
/// se categorizaba solo por el título y se perdía esa señal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemSaber {
    pub titulo: String,
    pub url: String,
    /// Fecha de publicación si el feed la da, o `""` (ausencia, no relleno; D20).
    pub fecha: String,
    /// Resumen/cuerpo del feed, SOLO para categorizar por texto completo (no se almacena).
    /// Acotado para no categorizar sobre un artículo entero.
    pub resumen: String,
}

/// Feeds curados, keyless (RSS/Atom). Se amplía como el mapa de relevancia.
/// El foco es lo que toca a nuestros proyectos en las áreas donde Xiliux compite:
/// **seguridad/hacking, criptografía e IA**, más el ecosistema Rust. El criterio de
/// selección es la DENSIDAD DE «CÓMO»: se prefiere la fuente que explica la TÉCNICA
/// (research, ingeniería) sobre la que solo da el titular —porque de una técnica sale
/// una idea implementable para un producto, de un titular no—. El mapa (`categoria`)
/// rutea cada ítem al proyecto que lo aprovecha (hacking/LLM→nexus, cripto→quipu…).
/// Todos verificados el 2026-09-28: parsean con el extractor dep-free y traen ítems.
pub const FUENTES: &[(&str, &str)] = &[
    // -- Ecosistema Rust (base: el lazo R6 dep→CVE y el lenguaje) --------------
    // Advisories de crates Rust (Atom) — complementa R6 mirando el flujo COMPLETO
    // de RustSec, no solo lo que ya consumimos.
    ("rustsec", "https://rustsec.org/feed.xml"),
    // Novedades semanales del ecosistema Rust (RSS).
    ("this-week-in-rust", "https://this-week-in-rust.org/rss.xml"),
    // Anuncios oficiales del lenguaje: releases, cambios de edición (Atom).
    ("rust-blog", "https://blog.rust-lang.org/feed.xml"),

    // -- Seguridad / hacking (→ nexus): la TÉCNICA de ataque y defensa --------
    // PortSwigger Research: técnicas web/appsec de primera mano (el «cómo» de HTTP
    // request smuggling, SSRF, desync…). Alta densidad de técnica.
    ("portswigger", "https://portswigger.net/research/rss"),
    // Google Project Zero: vuln research profundo, cadenas de explotación.
    ("project-zero", "https://googleprojectzero.blogspot.com/feeds/posts/default"),
    // Noticias de seguridad para el barrido de CONTEXTO (titulares; menor «cómo»,
    // pero es el pulso de qué se está rompiendo).
    ("the-hacker-news", "https://feeds.feedburner.com/TheHackersNews"),

    // -- Criptografía (→ quipu): ingeniería y academia -----------------------
    // Trail of Bits: ingeniería de seguridad y cripto aplicada (cruza a nexus).
    ("trail-of-bits", "https://blog.trailofbits.com/feed/"),
    // Matthew Green — Cryptographic Engineering: el porqué de los diseños cripto.
    ("cryptography-engineering", "https://blog.cryptographyengineering.com/feed/"),
    // IACR ePrint: papers de cripto recién salidos (denso y de alto volumen; es la
    // fuente primaria de PQC y primitivas para quipu).
    ("iacr-eprint", "https://eprint.iacr.org/rss/rss.xml"),

    // -- IA / seguridad de LLM (→ nexus): el frente de red-team IA ------------
    // Embrace The Red (Johann Rehberger): prompt injection y ataques a agentes, con
    // PoC. Es el «cómo» del red-team de IA, justo el eje del olfateador/razonador.
    ("embrace-the-red", "https://embracethered.com/blog/index.xml"),
    // Simon Willison: LLMs aplicados, herramientas y sus fallos, práctico.
    ("simon-willison", "https://simonwillison.net/atom/everything/"),
];

// --- Parseo (PURO: XML de feed → Vec<ItemSaber>) -----------------------------

/// Extrae los ítems de un feed RSS (`<item>`) o Atom (`<entry>`). Tolerante: toma el
/// primer `<title>` y el enlace (atributo `href` de Atom, o texto de `<link>` en RSS)
/// de cada bloque; deduplica por URL conservando el orden. PURO: no toca red (D33).
#[must_use]
pub fn extraer_items(xml: &str) -> Vec<ItemSaber> {
    let mut salida = Vec::new();
    let mut vistos = std::collections::BTreeSet::new();
    // Un feed usa `<item>` (RSS) o `<entry>` (Atom); recorrer ambos cubre los dos.
    for tag in ["item", "entry"] {
        for bloque in bloques(xml, tag) {
            let Some(titulo) = campo(bloque, "title") else {
                continue;
            };
            let Some(url) = enlace(bloque) else { continue };
            if titulo.is_empty() || url.is_empty() || !vistos.insert(url.clone()) {
                continue;
            }
            let fecha = campo(bloque, "published")
                .or_else(|| campo(bloque, "updated"))
                .or_else(|| campo(bloque, "pubDate"))
                .unwrap_or_default();
            // Resumen/cuerpo: Atom `<summary>`/`<content>`, RSS `<description>`. Acotado a
            // 2000 chars (categorizar sobre un artículo entero es ruido, no señal). No se
            // almacena; alimenta la categorización por texto completo (D16).
            let resumen = campo(bloque, "summary")
                .or_else(|| campo(bloque, "description"))
                .or_else(|| campo(bloque, "content"))
                .map(|s| s.chars().take(2000).collect::<String>())
                .unwrap_or_default();
            salida.push(ItemSaber { titulo, url, fecha, resumen });
        }
    }
    salida
}

/// Todos los interiores de `<tag>…</tag>` en orden de aparición.
fn bloques<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let abre = format!("<{tag}>");
    let cierra = format!("</{tag}>");
    let mut out = Vec::new();
    let mut resto = xml;
    while let Some(i) = resto.find(&abre) {
        let desde = &resto[i + abre.len()..];
        match desde.find(&cierra) {
            Some(j) => {
                out.push(&desde[..j]);
                resto = &desde[j + cierra.len()..];
            }
            None => break,
        }
    }
    out
}

/// El texto del primer `<tag>…</tag>` (o `<tag ...>…</tag>`) dentro de `bloque`, ya
/// des-CDATA y des-escapado; `None` si no está. Solo abre-tag simple, no anidado.
fn campo(bloque: &str, tag: &str) -> Option<String> {
    // Casa tanto `<title>` como `<title xml:lang="en">` buscando el prefijo y el `>`.
    let abre = format!("<{tag}");
    let i = bloque.find(&abre)?;
    let tras_nombre = &bloque[i + abre.len()..];
    // El siguiente char debe cerrar la etiqueta de apertura (`>` o un espacio/atributo).
    let inicio_gt = tras_nombre.find('>')?;
    let contenido = &tras_nombre[inicio_gt + 1..];
    let cierra = format!("</{tag}>");
    let fin = contenido.find(&cierra)?;
    Some(limpiar(&contenido[..fin]))
}

/// El enlace del ítem: el PRIMER `href="…"` que sea http(s) (Atom `<link href=…/>`), y
/// si no el texto de `<link>…</link>` de RSS cuando sea http(s). Se EXIGE http(s) y se
/// SALTAN anclas/relativos (`#fn:1`, `/ruta`): un bloque puede traer un `<a href="#…">`
/// de nota al pie en el contenido, y tomar el primer href a ciegas guardaba esa ancla
/// como URL (bug real de trail-of-bits, 2026-10-30) — inservible para navegar y dedup.
fn enlace(bloque: &str) -> Option<String> {
    // Recorre TODOS los href del bloque; devuelve el primero http(s).
    let mut resto = bloque;
    while let Some(h) = resto.find("href=\"") {
        let desde = &resto[h + "href=\"".len()..];
        if let Some(fin) = desde.find('"') {
            let u = limpiar(&desde[..fin]);
            if es_http(&u) {
                return Some(u);
            }
            resto = &desde[fin + 1..];
        } else {
            break;
        }
    }
    // RSS: el texto de <link>…</link>, solo si es http(s).
    campo(bloque, "link").filter(|s| es_http(s))
}

/// ¿Es una URL http(s) absoluta? Barandilla de ingesta: se rechazan anclas, rutas
/// relativas y esquemas raros (javascript:, data:…) que no sirven para navegar ni dedup.
fn es_http(u: &str) -> bool {
    u.starts_with("http://") || u.starts_with("https://")
}

/// Quita CDATA y des-escapa las entidades XML básicas; recorta espacios.
fn limpiar(s: &str) -> String {
    let s = s.trim();
    let s = s
        .strip_prefix("<![CDATA[")
        .and_then(|x| x.strip_suffix("]]>"))
        .unwrap_or(s);
    s.trim()
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
}

/// Extrae el nombre del crate de un título de advisory de RustSec, con formato
/// `RUSTSEC-AAAA-NNNN: <descripción> in <crate>`. Devuelve el crate (lo que sigue al
/// último ` in `), o `None` si el título no tiene esa forma. Es el puente de la
/// síntesis R5×R6: ese crate se cruza con `crates_consumidos` para saber si un aviso
/// del feed toca algo que consumimos.
#[must_use]
pub fn crate_de_titulo(titulo: &str) -> Option<String> {
    // Solo los títulos de RustSec ("RUSTSEC-…: … in <crate>") llevan el crate así.
    if !titulo.trim_start().starts_with("RUSTSEC-") {
        return None;
    }
    let crate_ = titulo.rsplit_once(" in ")?.1.trim();
    // Un crate es un identificador simple; si quedó una frase, no es fiable.
    if crate_.is_empty() || crate_.contains(' ') {
        None
    } else {
        Some(crate_.to_string())
    }
}

// --- Fetch (keyless) ---------------------------------------------------------

/// Descarga el XML de un feed. Keyless (regla 1). El parseo va aparte, así que esto
/// es lo único que toca la red.
pub async fn traer_feed(url: &str) -> Result<String> {
    let cli = cliente()?;
    // Reintento ante fallos de transporte (como github/kev), sin reintentar HTTP no-2xx.
    let resp = crate::github::enviar(cli.get(url))
        .await
        .with_context(|| format!("no se pudo pedir el feed {url}"))?
        .error_for_status()
        .with_context(|| format!("el feed {url} respondió con error"))?;
    resp.text()
        .await
        .context("no se pudo leer el cuerpo del feed")
}

#[cfg(test)]
mod pruebas {
    use super::*;

    // Fixtures REALES recortados (2 ítems cada uno, 2026-09-27): la aguja se valida
    // contra el artefacto que producen los feeds de verdad (D33), no uno inventado.
    const RUSTSEC: &str = include_str!("../tests/fixtures/feed_rustsec.xml");
    const TWIR: &str = include_str!("../tests/fixtures/feed_twir.xml");

    // AGUJA (D33): del Atom de RustSec salen los 2 advisories con su enlace `href`.
    #[test]
    fn aguja_atom_rustsec() {
        let items = extraer_items(RUSTSEC);
        assert_eq!(items.len(), 2, "{items:?}");
        assert!(
            items[0].titulo.contains("RUSTSEC-2026-0309"),
            "{:?}",
            items[0]
        );
        assert_eq!(
            items[0].url,
            "https://rustsec.org/advisories/RUSTSEC-2026-0309.html"
        );
        assert!(!items[0].fecha.is_empty(), "Atom trae fecha");
    }

    // AGUJA (D33): del RSS de TWiR salen los 2 números con su enlace de TEXTO `<link>`.
    #[test]
    fn aguja_rss_twir() {
        let items = extraer_items(TWIR);
        assert_eq!(items.len(), 2, "{items:?}");
        assert!(
            items[0].titulo.contains("This Week in Rust 670"),
            "{:?}",
            items[0]
        );
        assert!(
            items[0].url.starts_with("https://this-week-in-rust.org/"),
            "{:?}",
            items[0]
        );
    }

    // AGUJA (D33, texto completo): el parser captura el RESUMEN del cuerpo (summary/
    // description/content), por la vía real del artefacto. Sin esto, la categorización
    // de advisories por título genérico perdía la señal del cuerpo (D16).
    #[test]
    fn extrae_el_resumen_del_cuerpo() {
        let rustsec = extraer_items(RUSTSEC);
        assert!(
            rustsec.iter().any(|i| !i.resumen.is_empty()),
            "el Atom de RustSec trae cuerpo y debe capturarse: {rustsec:?}"
        );
        let twir = extraer_items(TWIR);
        assert!(
            twir.iter().any(|i| !i.resumen.is_empty()),
            "el RSS de TWiR trae <description> y debe capturarse: {twir:?}"
        );
    }

    // CONTROL (D33): un feed SIN ítems da cero. Con solo las agujas, un extractor que
    // "encontrara algo siempre" pasaría; este caso lo descarta, por la misma vía real.
    #[test]
    fn control_feed_vacio_da_cero() {
        let vacio = r#"<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
            <title>Vacío</title><updated>2026-01-01</updated></feed>"#;
        assert!(extraer_items(vacio).is_empty());
        assert!(extraer_items("").is_empty());
    }

    // Un ítem sin enlace se descarta (no se inventa una URL; D20). Y dedup por URL.
    #[test]
    fn descarta_sin_enlace_y_deduplica() {
        let xml = r#"
            <item><title>sin enlace</title></item>
            <item><title>uno</title><link>https://x.test/a</link></item>
            <item><title>otro (misma url)</title><link>https://x.test/a</link></item>
        "#;
        let items = extraer_items(xml);
        assert_eq!(
            items.len(),
            1,
            "sin-enlace fuera y url duplicada colapsa: {items:?}"
        );
        assert_eq!(items[0].titulo, "uno");
    }

    // AGUJA (D33): un ítem cuyo bloque trae un href de NOTA AL PIE (`#fn:1`) ANTES del
    // enlace real del artículo toma el primer href HTTP, no el ancla. MUTANTE = tomar el
    // primer href a ciegas (el código anterior): guardaba `#fn:1` (bug real trail-of-bits).
    #[test]
    fn enlace_salta_ancla_y_toma_el_http() {
        let xml = r##"
            <entry><title>Package managers have an integrity problem</title>
              <summary>&lt;a href="#fn:1"&gt;footnote&lt;/a&gt;</summary>
              <link href="#fn:1"/>
              <link href="https://blog.trailofbits.com/post"/>
            </entry>
        "##;
        let items = extraer_items(xml);
        assert_eq!(items.len(), 1, "{items:?}");
        assert_eq!(items[0].url, "https://blog.trailofbits.com/post");
    }

    // CONTROL (D33): un ítem cuyo ÚNICO enlace es un ancla/relativo se DESCARTA (no se
    // guarda una URL inservible). Si `enlace` aceptara no-http, esto daría 1 ítem.
    #[test]
    fn enlace_solo_ancla_se_descarta() {
        let xml = r##"<item><title>roto</title><link>#fn:1</link></item>"##;
        assert!(extraer_items(xml).is_empty(), "url no-http se descarta");
    }

    #[test]
    fn limpiar_cdata_y_entidades() {
        assert_eq!(limpiar("  <![CDATA[hola & chao]]> "), "hola & chao");
        assert_eq!(limpiar("A &amp; B &lt;x&gt;"), "A & B <x>");
    }

    // Síntesis R5×R6: el crate se extrae del título de RustSec; un título que no es
    // de RustSec (control) no da crate, para no inventar cruces (D20).
    #[test]
    fn crate_de_titulo_rustsec_si_otros_no() {
        assert_eq!(
            crate_de_titulo("RUSTSEC-2026-0286: Out-of-bounds read in cryptoki").as_deref(),
            Some("cryptoki")
        );
        assert_eq!(
            crate_de_titulo("RUSTSEC-2026-0285: TLS 1.3 handshake messages ... in rustls")
                .as_deref(),
            Some("rustls")
        );
        // Control: una novedad de TWiR no lleva crate → None (no se inventa cruce).
        assert_eq!(crate_de_titulo("This Week in Rust 670"), None);
        // Título raro sin crate limpio.
        assert_eq!(crate_de_titulo("RUSTSEC-2026-0001: algo sin patrón"), None);
    }
}
