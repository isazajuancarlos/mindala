// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: MIT

//! R3 · fuentes extra. Además del `buscar` por topic de GitHub, mindalá pesca
//! repositorios mencionados en Hacker News, lobste.rs y awesome-lists. Cada fuente
//! entrega URLs; de ellas se extraen las coordenadas `owner/repo` de GitHub, que
//! luego `github::resolver_repo` convierte en candidatos completos.
//!
//! El PARSEO es puro (texto → coordenadas) y se prueba sin red; solo `traer_*`
//! toca la red, keyless igual que `github` (regla 1).

use crate::github::cliente;
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::BTreeSet;

/// Segmentos de ruta de github.com que NO son un `owner`: páginas del propio sitio.
/// Enumerar lo que se descarta y mandar el resto a "es un repo" es la dirección
/// segura (D20/D23): una página nueva de GitHub, como mucho, resuelve a un 404 y
/// se salta; un repo real nunca se pierde por no estar en una lista de permitidos.
const NO_SON_OWNER: &[&str] = &[
    "sponsors",
    "topics",
    "features",
    "about",
    "pricing",
    "marketplace",
    "collections",
    "trending",
    "orgs",
    "settings",
    "notifications",
    "login",
    "join",
    "explore",
    "search",
    "apps",
    "customer-stories",
    "readme",
    "site",
    "security",
    "enterprise",
    "team",
    "contact",
    "blog",
    "events",
];

/// Extrae la coordenada `(owner, repo)` de una URL de GitHub, o `None` si la URL no
/// apunta a un repositorio. Limpia el sufijo `.git` y descarta las páginas del sitio.
#[must_use]
pub fn extraer_repo_github(url: &str) -> Option<(String, String)> {
    // Normaliza el esquema y aísla host + ruta.
    let sin_esquema = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let (host, resto) = sin_esquema.split_once('/')?;
    let host = host.trim_start_matches("www.");
    if !host.eq_ignore_ascii_case("github.com") {
        return None;
    }
    // Corta query/fragmento y parte en segmentos.
    let ruta = resto.split(['?', '#']).next().unwrap_or(resto);
    let mut segs = ruta.split('/').filter(|s| !s.is_empty());
    let owner = segs.next()?;
    let repo = segs.next()?;
    if NO_SON_OWNER.iter().any(|p| p.eq_ignore_ascii_case(owner)) {
        return None;
    }
    let repo = repo.trim_end_matches(".git");
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some((owner.to_string(), repo.to_string()))
}

/// Extrae todas las coordenadas `owner/repo` de GitHub que aparezcan en un texto
/// (el README de una awesome-list, por ejemplo). Deduplica conservando orden por
/// `owner/repo` en minúsculas. Escanea texto plano — NO es edición de código, así
/// que buscar la subcadena `github.com/` es legítimo (D17 aplica a código).
#[must_use]
pub fn extraer_repos_de_texto(texto: &str) -> Vec<(String, String)> {
    // Delimitadores donde termina una URL dentro de markdown/prosa.
    const FIN: &[char] = &[
        ' ', ')', ']', '>', '"', '\'', '\n', '\r', '\t', ',', '`', '|',
    ];
    let mut vistos: BTreeSet<String> = BTreeSet::new();
    let mut salida = Vec::new();
    let mut resto = texto;
    while let Some(pos) = resto.find("github.com/") {
        let desde = &resto[pos..];
        let fin = desde.find(FIN).unwrap_or(desde.len());
        let candidato = &desde[..fin];
        // `extraer_repo_github` espera esquema o host; le anteponemos https:// si
        // el match empezó en el host desnudo.
        let url = if candidato.starts_with("http") {
            candidato.to_string()
        } else {
            format!("https://{candidato}")
        };
        if let Some((o, r)) = extraer_repo_github(&url) {
            let clave = format!("{}/{}", o.to_lowercase(), r.to_lowercase());
            if vistos.insert(clave) {
                salida.push((o, r));
            }
        }
        resto = &resto[pos + "github.com/".len()..];
    }
    salida
}

// --- Hacker News (Algolia Search API, keyless) -----------------------------

#[derive(Debug, Deserialize)]
struct RespuestaHn {
    hits: Vec<HitHn>,
}
#[derive(Debug, Deserialize)]
struct HitHn {
    url: Option<String>,
}

/// Parsea la respuesta de la API de HN y devuelve las URLs de las historias.
///
/// # Errores
/// Falla si el JSON no tiene la forma esperada (D30).
pub fn parsear_hn(json: &str) -> Result<Vec<String>> {
    let r: RespuestaHn = serde_json::from_str(json)?;
    Ok(r.hits.into_iter().filter_map(|h| h.url).collect())
}

// --- lobste.rs (JSON público, keyless) -------------------------------------

#[derive(Debug, Deserialize)]
struct HistoriaLobsters {
    url: String,
}

/// Parsea la respuesta JSON de lobste.rs (un array de historias) y devuelve sus URLs.
///
/// # Errores
/// Falla si el JSON no tiene la forma esperada (D30).
pub fn parsear_lobsters(json: &str) -> Result<Vec<String>> {
    let v: Vec<HistoriaLobsters> = serde_json::from_str(json)?;
    Ok(v.into_iter()
        .map(|h| h.url)
        .filter(|u| !u.is_empty())
        .collect())
}

// --- Fetch (la única parte con red) ----------------------------------------

/// Trae de HN las historias que casan `query` y devuelve las coordenadas de GitHub.
pub async fn traer_hn(query: &str, hits: u32) -> Result<Vec<(String, String)>> {
    let url = "https://hn.algolia.com/api/v1/search";
    let resp = cliente()?
        .get(url)
        .query(&[
            ("query", query),
            ("tags", "story"),
            ("hitsPerPage", &hits.to_string()),
        ])
        .send()
        .await
        .context("falló la petición a Hacker News")?;
    let cuerpo = exigir_cuerpo(resp, "Hacker News").await?;
    Ok(coordenadas(&parsear_hn(&cuerpo)?))
}

/// Trae de lobste.rs las historias más votadas (o de una etiqueta) y devuelve las
/// coordenadas de GitHub.
pub async fn traer_lobsters(tag: Option<&str>) -> Result<Vec<(String, String)>> {
    let url = match tag {
        Some(t) => format!("https://lobste.rs/t/{t}.json"),
        None => "https://lobste.rs/hottest.json".to_string(),
    };
    let resp = cliente()?
        .get(&url)
        .send()
        .await
        .with_context(|| format!("falló la petición a {url}"))?;
    let cuerpo = exigir_cuerpo(resp, "lobste.rs").await?;
    Ok(coordenadas(&parsear_lobsters(&cuerpo)?))
}

/// Trae el README de una awesome-list (`owner/repo`) y extrae los repos enlazados.
pub async fn traer_awesome(
    owner: &str,
    repo: &str,
    token: Option<&str>,
) -> Result<Vec<(String, String)>> {
    let url = format!("https://api.github.com/repos/{owner}/{repo}/readme");
    let mut req = cliente()?
        .get(&url)
        // `raw` devuelve el markdown directamente, no un JSON con base64.
        .header("Accept", "application/vnd.github.raw+json")
        .header("X-GitHub-Api-Version", "2022-11-28");
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = req
        .send()
        .await
        .with_context(|| format!("falló GET {url}"))?;
    let cuerpo = exigir_cuerpo(resp, "GitHub (readme)").await?;
    let mut coords = extraer_repos_de_texto(&cuerpo);
    // La propia awesome-list no es un candidato de sí misma.
    coords.retain(|(o, r)| !(o.eq_ignore_ascii_case(owner) && r.eq_ignore_ascii_case(repo)));
    Ok(coords)
}

async fn exigir_cuerpo(resp: reqwest::Response, fuente: &str) -> Result<String> {
    let estado = resp.status();
    let cuerpo = resp.text().await.context("no se pudo leer el cuerpo")?;
    if !estado.is_success() {
        bail!(
            "{fuente} devolvió {estado}: {}",
            cuerpo.chars().take(200).collect::<String>()
        );
    }
    Ok(cuerpo)
}

fn coordenadas(urls: &[String]) -> Vec<(String, String)> {
    let mut vistos: BTreeSet<String> = BTreeSet::new();
    let mut salida = Vec::new();
    for u in urls {
        if let Some((o, r)) = extraer_repo_github(u) {
            let clave = format!("{}/{}", o.to_lowercase(), r.to_lowercase());
            if vistos.insert(clave) {
                salida.push((o, r));
            }
        }
    }
    salida
}

#[cfg(test)]
mod pruebas {
    use super::*;

    // AGUJA (D33): varias formas de URL de repo resuelven a la coordenada.
    #[test]
    fn extrae_repo_de_urls_validas() {
        assert_eq!(
            extraer_repo_github("https://github.com/kanidm/webauthn-rs"),
            Some(("kanidm".into(), "webauthn-rs".into()))
        );
        assert_eq!(
            extraer_repo_github("https://github.com/kanidm/webauthn-rs.git"),
            Some(("kanidm".into(), "webauthn-rs".into()))
        );
        assert_eq!(
            extraer_repo_github("http://www.github.com/a/b/tree/main/src?x=1#l2"),
            Some(("a".into(), "b".into()))
        );
    }

    // CONTROL (D33): lo que NO es un repo devuelve None por la vía real, no por
    // un default. Si el extractor se cegara y aceptara todo, estas se pondrían rojas.
    #[test]
    fn descarta_no_repos() {
        assert_eq!(extraer_repo_github("https://example.com/a/b"), None);
        assert_eq!(
            extraer_repo_github("https://github.com/sponsors/torvalds"),
            None
        );
        assert_eq!(extraer_repo_github("https://github.com/topics/rust"), None);
        assert_eq!(extraer_repo_github("https://github.com/soloowner"), None);
        assert_eq!(extraer_repo_github("https://gitlab.com/a/b"), None);
    }

    #[test]
    fn extrae_y_deduplica_de_texto() {
        let md = "Ver [foo](https://github.com/org/foo) y `github.com/org/bar`.\n\
                  Repetido: https://github.com/org/foo again, y https://github.com/topics/x.";
        let r = extraer_repos_de_texto(md);
        assert_eq!(
            r,
            vec![("org".into(), "foo".into()), ("org".into(), "bar".into())]
        );
    }

    #[test]
    fn parsea_hn_saltando_historias_sin_url() {
        let json =
            r#"{"hits":[{"url":"https://github.com/a/b"},{"url":null},{"url":"https://x.com"}]}"#;
        assert_eq!(
            parsear_hn(json).unwrap(),
            vec!["https://github.com/a/b", "https://x.com"]
        );
    }

    #[test]
    fn parsea_lobsters() {
        let json = r#"[{"url":"https://github.com/a/b"},{"url":"https://y.com/z"}]"#;
        assert_eq!(
            parsear_lobsters(json).unwrap(),
            vec!["https://github.com/a/b", "https://y.com/z"]
        );
    }

    #[test]
    fn coordenadas_filtra_solo_github() {
        let urls = vec![
            "https://github.com/a/b".to_string(),
            "https://noticias.com/x".to_string(),
            "https://github.com/a/b".to_string(), // dup
        ];
        assert_eq!(coordenadas(&urls), vec![("a".into(), "b".into())]);
    }
}
