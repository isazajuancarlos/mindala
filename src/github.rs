// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: MIT

//! El único módulo que toca la red: la GitHub Search API, keyless por defecto
//! (regla 1 del diseño). Con `GITHUB_TOKEN` en el entorno sube de 60 a 5000
//! req/h, pero funciona sin él. El parseo NO vive aquí: es `modelo::parsear_respuesta`,
//! la misma costura que ejercen las pruebas y `buscar --desde-archivo` (D33).

use crate::modelo::{Candidato, parsear_repo, parsear_respuesta};
use anyhow::{Context, Result, bail};

const API: &str = "https://api.github.com/search/repositories";
/// GitHub exige un User-Agent propio o rechaza la petición con 403.
pub(crate) const UA: &str = "mindala/0.1 (+https://xiliux.com; herramienta interna de estudio)";

/// Cliente HTTP compartido, con el User-Agent que GitHub exige.
pub(crate) fn cliente() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(UA)
        .build()
        .context("no se pudo construir el cliente HTTP")
}

/// Envía con REINTENTOS ante fallos de TRANSPORTE (reset de conexión, `InvalidContentType`
/// de TLS, timeout) — intermitentes en la red keyless bajo pacing, y que hacían perder
/// topics/feeds sueltos por corrida. NO reintenta ante un HTTP no-2xx: eso NO es un error
/// de `send()` (lo decide el llamante con el status), así que un 403/404/5xx pasa tal cual
/// una sola vez. Hasta 2 reintentos con backoff (400/800 ms). Una petición GET sin cuerpo
/// es clonable, así que se reemite sin reconstruirla. Lo comparten github, kev y los feeds.
pub(crate) async fn enviar(req: reqwest::RequestBuilder) -> reqwest::Result<reqwest::Response> {
    let mut intento = 0u32;
    loop {
        let clon = req
            .try_clone()
            .expect("una petición GET sin cuerpo siempre es clonable");
        match clon.send().await {
            Ok(resp) => return Ok(resp),
            Err(_) if intento < 2 => {
                intento += 1;
                tokio::time::sleep(std::time::Duration::from_millis(400 * u64::from(intento)))
                    .await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Filtros de una búsqueda. Se traducen a la sintaxis `q=` de GitHub.
#[derive(Debug, Clone)]
pub struct Filtros {
    pub topic: String,
    pub min_estrellas: Option<i64>,
    pub lenguaje: Option<String>,
    /// `pushed:>=YYYY-MM-DD` — actividad reciente.
    pub pushed_desde: Option<String>,
    pub por_pagina: u32,
}

impl Filtros {
    /// Construye el valor de `q`. Ejemplo: `topic:webauthn stars:>=50 language:rust`.
    #[must_use]
    pub fn consulta(&self) -> String {
        let mut q = format!("topic:{}", self.topic);
        if let Some(s) = self.min_estrellas {
            q.push_str(&format!(" stars:>={s}"));
        }
        if let Some(l) = &self.lenguaje {
            q.push_str(&format!(" language:{l}"));
        }
        if let Some(p) = &self.pushed_desde {
            q.push_str(&format!(" pushed:>={p}"));
        }
        q
    }
}

/// Consulta la GitHub Search API y devuelve los candidatos normalizados.
///
/// El token, si lo hay, se lee de `GITHUB_TOKEN` (bajo privilegio, solo lectura).
///
/// # Errores
/// Falla ruidosamente ante un HTTP no-2xx (incluye el 403 de rate-limit sin token),
/// para que una tanda estrangulada no se confunda con "no hubo resultados" (D30).
pub async fn buscar(filtros: &Filtros, token: Option<&str>) -> Result<Vec<Candidato>> {
    let cliente = cliente()?;

    let mut req = cliente
        .get(API)
        .query(&[
            ("q", filtros.consulta().as_str()),
            ("sort", "stars"),
            ("order", "desc"),
            ("per_page", &filtros.por_pagina.to_string()),
        ])
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28");
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }

    let resp = enviar(req).await.context("falló la petición a GitHub")?;
    let estado = resp.status();
    let cuerpo = resp.text().await.context("no se pudo leer el cuerpo")?;
    if !estado.is_success() {
        // El 403 sin token suele ser rate-limit; se dice, no se traga.
        bail!(
            "GitHub devolvió {estado}: {}",
            cuerpo.chars().take(300).collect::<String>()
        );
    }
    parsear_respuesta(&cuerpo).context("no se pudo parsear la respuesta de GitHub")
}

/// Resuelve `owner/name` a un candidato completo vía `GET /repos/{owner}/{name}`.
/// Lo usa R3: una fuente externa da la coordenada, aquí se trae la metadata.
///
/// # Errores
/// Falla ante un HTTP no-2xx (404 si el repo no existe, 403 si hay rate-limit),
/// para no confundir un fallo con "el repo no sirve" (D30).
pub async fn resolver_repo(owner: &str, name: &str, token: Option<&str>) -> Result<Candidato> {
    let url = format!("https://api.github.com/repos/{owner}/{name}");
    let mut req = cliente()?
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28");
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = enviar(req)
        .await
        .with_context(|| format!("falló GET {url}"))?;
    let estado = resp.status();
    let cuerpo = resp.text().await.context("no se pudo leer el cuerpo")?;
    if !estado.is_success() {
        bail!(
            "GitHub devolvió {estado} para {owner}/{name}: {}",
            cuerpo.chars().take(200).collect::<String>()
        );
    }
    parsear_repo(&cuerpo).with_context(|| format!("no se pudo parsear el repo {owner}/{name}"))
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn consulta_completa() {
        let f = Filtros {
            topic: "webauthn".into(),
            min_estrellas: Some(50),
            lenguaje: Some("rust".into()),
            pushed_desde: Some("2026-01-01".into()),
            por_pagina: 30,
        };
        assert_eq!(
            f.consulta(),
            "topic:webauthn stars:>=50 language:rust pushed:>=2026-01-01"
        );
    }

    #[test]
    fn consulta_minima_solo_topic() {
        let f = Filtros {
            topic: "recon".into(),
            min_estrellas: None,
            lenguaje: None,
            pushed_desde: None,
            por_pagina: 30,
        };
        assert_eq!(f.consulta(), "topic:recon");
    }
}
