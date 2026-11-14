// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: MIT

//! Los tipos del dominio: un candidato (repositorio traído de la fuente) y su
//! veredicto. El candidato es lo que el 80% descubre; el veredicto es lo que el
//! 20% (el criterio) decide, y que la BD recuerda para no re-estudiar (D5).

use serde::Deserialize;

/// Un repositorio candidato ya normalizado, listo para categorizar y encolar.
///
/// `id_github` es el identificador estable del repositorio en GitHub: es la clave
/// de deduplicación (regla 4 del diseño — lo ya visto no se re-descubre).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidato {
    pub id_github: i64,
    pub nombre_completo: String,
    pub url: String,
    pub descripcion: String,
    pub lenguaje: String,
    /// Temas (topics) del repo, en minúsculas.
    pub topics: Vec<String>,
    pub estrellas: i64,
    /// Última actividad, ISO-8601 tal como la da GitHub (`pushed_at`). Es la señal
    /// de caducidad: si un candidato pendiente cambió, se vuelve a evaluar.
    pub pushed_at: String,
    /// Identificador SPDX de la licencia (`MIT`, `AGPL-3.0`…), o `NOASSERTION`.
    /// La licencia MANDA (regla 3): AGPL/GPL contaminan, se reimplementa sin copiar.
    pub licencia: String,
}

/// El veredicto del criterio sobre un candidato. `Pendiente` es el estado inicial:
/// descubierto pero aún no estudiado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Veredicto {
    Pendiente,
    Adoptar,
    Descartar,
}

impl Veredicto {
    /// Serialización estable para la columna de la BD. `Pendiente` es `NULL`, no
    /// una cadena: un pendiente es la AUSENCIA de veredicto, no un veredicto más
    /// (D20 — no rellenar un dato ausente con un valor de relleno).
    #[must_use]
    pub fn a_bd(self) -> Option<&'static str> {
        match self {
            Veredicto::Pendiente => None,
            Veredicto::Adoptar => Some("adoptar"),
            Veredicto::Descartar => Some("descartar"),
        }
    }

    /// Inverso de [`Veredicto::a_bd`]. Una cadena desconocida es un error de datos,
    /// no un `Pendiente` silencioso (D20 — fallar ruidoso ante lo inesperado).
    #[must_use]
    pub fn desde_bd(s: Option<&str>) -> Option<Self> {
        match s {
            None => Some(Veredicto::Pendiente),
            Some("adoptar") => Some(Veredicto::Adoptar),
            Some("descartar") => Some(Veredicto::Descartar),
            Some(_) => None,
        }
    }
}

// --- R8: la CARACTERÍSTICA, la unidad de valor -----------------------------
// mindalá caza CARACTERÍSTICAS (técnicas), no repos ni programas: se reimplementan
// propias en el estándar (D9/D38). Una característica es transversal a las fuentes
// —la aporta un repo o una noticia— y separa lo que el `veredicto` del repo
// colapsaba: «este repo sirve» vs «esta técnica sirve» (D32).

/// El estado de una característica en su ciclo de vida. A diferencia del
/// `Veredicto` de un repo, NO tiene variante «ausente»: una característica nace
/// cuando el criterio la registra, así que siempre tiene estado explícito (D20).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstadoCaracteristica {
    /// El criterio la halló y registró; aún no decide si vale implementarla.
    Propuesta,
    /// Vale la pena: su desenlace es una tarea de implementar-en-el-estándar.
    Sirve,
    /// Ya está construida propia en el estándar.
    Implementada,
    /// Mirada y no vale (fuera de stack, ya la tenemos, licencia imposible…).
    Descartada,
}

impl EstadoCaracteristica {
    /// Serialización estable para la columna (NOT NULL, default `propuesta`).
    #[must_use]
    pub fn a_bd(self) -> &'static str {
        match self {
            EstadoCaracteristica::Propuesta => "propuesta",
            EstadoCaracteristica::Sirve => "sirve",
            EstadoCaracteristica::Implementada => "implementada",
            EstadoCaracteristica::Descartada => "descartada",
        }
    }

    /// Inverso de [`EstadoCaracteristica::a_bd`]. Una cadena desconocida es un
    /// error de datos, no un estado por defecto silencioso (D20).
    #[must_use]
    pub fn desde_bd(s: &str) -> Option<Self> {
        match s {
            "propuesta" => Some(EstadoCaracteristica::Propuesta),
            "sirve" => Some(EstadoCaracteristica::Sirve),
            "implementada" => Some(EstadoCaracteristica::Implementada),
            "descartada" => Some(EstadoCaracteristica::Descartada),
            _ => None,
        }
    }
}

/// De qué tabla de fuentes viene la procedencia de una característica. El puente
/// `caracteristica_fuente` no es FK dura: una fuente puede caducar de su tabla y
/// la característica sobrevive con su procedencia registrada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipoFuente {
    /// Un repo de `candidatos`; `ref_fuente` es su `id_github` como texto.
    Candidato,
    /// Un ítem de `conocimiento` (feed); `ref_fuente` es su `url`.
    Conocimiento,
}

impl TipoFuente {
    #[must_use]
    pub fn a_bd(self) -> &'static str {
        match self {
            TipoFuente::Candidato => "candidato",
            TipoFuente::Conocimiento => "conocimiento",
        }
    }

    #[must_use]
    pub fn desde_bd(s: &str) -> Option<Self> {
        match s {
            "candidato" => Some(TipoFuente::Candidato),
            "conocimiento" => Some(TipoFuente::Conocimiento),
            _ => None,
        }
    }
}

/// El contenido de una característica al CAZARLA (antes de tener id/estado). Se
/// agrupa en un struct para no arrastrar seis argumentos sueltos por la firma
/// (D1: la firma dice «una característica y su fuente», no una lista de campos).
#[derive(Debug, Clone, Copy)]
pub struct NuevaCaracteristica<'a> {
    pub que_hace: &'a str,
    pub destino: &'a str,
    pub como: &'a str,
    pub licencia_origen: &'a str,
}

/// Una característica ya registrada, tal como vive en la BD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caracteristica {
    pub id: i64,
    /// La técnica, en una frase.
    pub que_hace: String,
    /// Proyecto Xiliux destino, o `sin_clasificar`.
    pub destino: String,
    /// El «cómo» implementarla en el estándar (lo más importante, R7/R8).
    pub como: String,
    /// SPDX de la fuente: la licencia manda (regla 3). Se reimplementa, no se copia.
    pub licencia_origen: String,
    pub estado: EstadoCaracteristica,
    pub nota: String,
}

// --- Deserialización de la respuesta de la GitHub Search API ---------------
// Estas structs reciben el JSON crudo. Se separan del `Candidato` del dominio
// a propósito: la forma de la API no es la forma de nuestro modelo, y
// `normalizar` es la única costura entre las dos (D33 — la misma costura de
// texto la usan el camino real y las pruebas).

#[derive(Debug, Deserialize)]
pub struct RespuestaBusqueda {
    pub total_count: i64,
    pub items: Vec<RepoApi>,
}

#[derive(Debug, Deserialize)]
pub struct RepoApi {
    pub id: i64,
    pub full_name: String,
    pub html_url: String,
    pub description: Option<String>,
    pub language: Option<String>,
    #[serde(default)]
    pub topics: Vec<String>,
    pub stargazers_count: i64,
    pub pushed_at: String,
    pub license: Option<LicenciaApi>,
}

#[derive(Debug, Deserialize)]
pub struct LicenciaApi {
    pub spdx_id: Option<String>,
}

impl RepoApi {
    /// Convierte la forma cruda de la API en un `Candidato` del dominio. Los
    /// campos ausentes se hacen explícitos (`""`, `NOASSERTION`), nunca se
    /// inventan (D20).
    #[must_use]
    pub fn normalizar(self) -> Candidato {
        Candidato {
            id_github: self.id,
            nombre_completo: self.full_name,
            url: self.html_url,
            descripcion: self.description.unwrap_or_default(),
            lenguaje: self.language.unwrap_or_default(),
            topics: self.topics.into_iter().map(|t| t.to_lowercase()).collect(),
            estrellas: self.stargazers_count,
            pushed_at: self.pushed_at,
            licencia: self
                .license
                .and_then(|l| l.spdx_id)
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "NOASSERTION".to_string()),
        }
    }
}

/// Parsea la respuesta JSON de la GitHub Search API y devuelve los candidatos
/// normalizados. Es la costura única (recibe TEXTO) que comparten el fetch de
/// red y las pruebas / `buscar --desde-archivo` (D33).
///
/// # Errores
/// Falla si el JSON no tiene la forma esperada — ruidosamente, no con una lista
/// vacía que se confunda con "no hubo resultados" (D30).
pub fn parsear_respuesta(json: &str) -> anyhow::Result<Vec<Candidato>> {
    let r: RespuestaBusqueda = serde_json::from_str(json)?;
    Ok(r.items.into_iter().map(RepoApi::normalizar).collect())
}

/// Parsea la respuesta del endpoint `GET /repos/{owner}/{name}` (un objeto, no un
/// array). Lo usa R3 para resolver un repo descubierto por una fuente externa
/// (HN, lobste.rs, awesome-list) a un candidato completo.
///
/// # Errores
/// Falla si el JSON no tiene la forma de un repositorio (D30).
pub fn parsear_repo(json: &str) -> anyhow::Result<Candidato> {
    let r: RepoApi = serde_json::from_str(json)?;
    Ok(r.normalizar())
}

/// ¿Es `url` un origen de clonado LEGÍTIMO que se le puede entregar a `git clone`?
///
/// El único origen válido es GitHub por HTTPS. Importa porque la URL de un
/// candidato no siempre viene del feed de GitHub (`html_url`, siempre
/// `https://github.com/…`): `buscar --desde-archivo <json>` persiste una URL
/// ARBITRARIA leída de un JSON de disco. Una URL como `--upload-pack=sh -c …` o
/// `ext::sh -c …` la trataría git como OPCIÓN (ejecución de comando) y no como
/// repositorio → RCE. Exigir el prefijo exacto `https://github.com/` cierra la
/// clase en origen (D20: ante un dato con forma inesperada se falla ruidoso, no se
/// acepta por defecto). Es la primera de dos defensas; la segunda es el `--` que
/// `estudiar` inserta antes de la URL para que git nunca la lea como opción.
pub fn url_de_clon_valida(url: &str) -> bool {
    url.starts_with("https://github.com/")
}

#[cfg(test)]
mod tests {
    use super::url_de_clon_valida;

    #[test]
    fn url_de_clon_solo_acepta_github_https() {
        // Caso verde: el origen legítimo pasa.
        assert!(url_de_clon_valida("https://github.com/o/r"));

        // Caso ROJO (la clase de RCE): sin esta allowlist, una URL que empieza por
        // `-` llegaría a git como opción. Debe rechazarse.
        assert!(!url_de_clon_valida("--upload-pack=x"));
        // Esquema transporte-de-comando de git: también opción encubierta.
        assert!(!url_de_clon_valida("ext::sh -c x"));
        // Otro host: no es el origen legítimo.
        assert!(!url_de_clon_valida("https://evil.com/x"));
        // Sin TLS: se rechaza aunque el host sea github.com.
        assert!(!url_de_clon_valida("http://github.com/o/r"));
        // Sub-dominio engañoso: el `.` tras github.com no es `/`, no casa el prefijo.
        assert!(!url_de_clon_valida("https://github.com.evil.com/x"));
    }
}
