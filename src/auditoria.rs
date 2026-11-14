// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: MIT

//! R6 · lazo dep→CVE (contrainteligencia). Mientras las fuentes R1-R3 miran HACIA
//! AFUERA (traer técnicas del mundo), esta capa mira HACIA ADENTRO: ¿alguna
//! dependencia que NUESTROS repos consumen de verdad tiene un aviso de seguridad?
//!
//! El agujero que cierra (medido 2026-09-27): `deny.toml` está disperso en 9 de 19
//! repos Rust y falta justo en los sensibles (quipu, bachue, iraca-*); y el CI que
//! lo correría está apagado (solo-local permanente). Así, cuando salió
//! RUSTSEC-2026-0285 (rustls) se cazó A MANO. Este lazo lo sistematiza en local.
//!
//! Reparto 80/20 igual que el resto de mindalá: el PROGRAMA descubre repos, corre
//! `cargo audit` y agrega; el CRITERIO tría cada aviso (¿parcheable ya? ¿toca repo
//! sensible → D25/concilio?). NO reimplementa el emparejamiento de RustSec: orquesta
//! `cargo audit` (D1/D37, mismo precedente que `estudiar` con `git clone`). La
//! costura de parseo es PURA y se prueba con `--desde-archivo` sin cargo-audit ni
//! red (D33).

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Un aviso de seguridad sobre una dependencia que consumimos: una vulnerabilidad
/// (RUSTSEC con CVE) o un warning (unsound / yanked / unmaintained). Es el artefacto
/// que se guarda en `bd` y se destaca en el digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aviso {
    /// `RUSTSEC-2026-0285`, o el tipo en mayúsculas cuando no hay advisory (`YANKED`).
    pub advisory_id: String,
    pub paquete: String,
    pub version: String,
    pub titulo: String,
    pub url: String,
    /// `vulnerabilidad` | `unsound` | `yanked` | `unmaintained` | `notice` | `aviso`.
    pub tipo: String,
    /// CVSS si lo hay, o `—`.
    pub severidad: String,
    /// Versiones que corrigen (`versions.patched`), unidas por `, `, o `—`.
    pub parcheado: String,
}

/// Directorios que NO se auditan al descubrir bajo la raíz: datos PERSONALES de Juan
/// (`documentos`, prohibido por `MAPA.md` y el guardián de barrido) e infraestructura
/// que no es un repo propio. Enumerar lo que se DESCARTA y auditar el resto es la
/// dirección segura (D20/D23): un repo Rust nuevo se audita solo; nunca se cuela lo
/// personal por no estar en una lista de permitidos.
const NO_AUDITAR: &[&str] = &[
    "documentos",
    "analisis",
    "target",
    "vendor",
    "toolchains",
    "node_modules",
    "conversaciones",
    "espejos",
    "colca",
    "respaldos",
];

// --- Parseo (PURO: JSON de `cargo audit --json` → Vec<Aviso>) ----------------

#[derive(Debug, Deserialize)]
struct SalidaAudit {
    #[serde(default)]
    vulnerabilities: Vulnerabilidades,
    /// `warnings` es un mapa tipo→lista (`unsound`, `yanked`, `unmaintained`…).
    #[serde(default)]
    warnings: BTreeMap<String, Vec<Warning>>,
}

#[derive(Debug, Default, Deserialize)]
struct Vulnerabilidades {
    #[serde(default)]
    list: Vec<Vulnerabilidad>,
}

#[derive(Debug, Deserialize)]
struct Vulnerabilidad {
    advisory: Advisory,
    #[serde(default)]
    versions: Option<Versiones>,
    package: Paquete,
}

#[derive(Debug, Deserialize)]
struct Warning {
    #[serde(default)]
    kind: Option<String>,
    package: Paquete,
    #[serde(default)]
    advisory: Option<Advisory>,
    #[serde(default)]
    versions: Option<Versiones>,
}

#[derive(Debug, Deserialize)]
struct Advisory {
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    url: Option<String>,
    /// El CVSS de RustSec se serializa como cadena; ausente en muchos avisos.
    #[serde(default)]
    cvss: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Versiones {
    #[serde(default)]
    patched: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Paquete {
    name: String,
    version: String,
}

fn parcheado_de(v: &Option<Versiones>) -> String {
    match v {
        Some(x) if !x.patched.is_empty() => x.patched.join(", "),
        _ => "—".to_string(),
    }
}

/// Convierte la salida JSON de `cargo audit --json` en avisos. PURO: no toca red ni
/// procesos, así que es la costura que ejercen las pruebas (D33). Vulnerabilidades y
/// warnings se unifican en `Aviso`; un warning sin `advisory` (p. ej. `yanked`) lleva
/// su tipo en mayúsculas como id sintético.
pub fn parsear_cargo_audit(json: &str) -> Result<Vec<Aviso>> {
    let salida: SalidaAudit =
        serde_json::from_str(json).context("JSON de cargo-audit con forma inesperada")?;
    let mut avisos = Vec::new();

    for v in &salida.vulnerabilities.list {
        avisos.push(Aviso {
            advisory_id: v.advisory.id.clone(),
            paquete: v.package.name.clone(),
            version: v.package.version.clone(),
            titulo: v.advisory.title.clone(),
            url: v.advisory.url.clone().unwrap_or_default(),
            tipo: "vulnerabilidad".to_string(),
            severidad: v.advisory.cvss.clone().unwrap_or_else(|| "—".to_string()),
            parcheado: parcheado_de(&v.versions),
        });
    }

    for (kind, lista) in &salida.warnings {
        for w in lista {
            let tipo = w.kind.clone().unwrap_or_else(|| kind.clone());
            let (advisory_id, titulo, url, severidad) = match &w.advisory {
                Some(a) => (
                    a.id.clone(),
                    a.title.clone(),
                    a.url.clone().unwrap_or_default(),
                    a.cvss.clone().unwrap_or_else(|| "—".to_string()),
                ),
                None => (
                    tipo.to_uppercase(),
                    format!("{tipo}: {} {}", w.package.name, w.package.version),
                    String::new(),
                    "—".to_string(),
                ),
            };
            avisos.push(Aviso {
                advisory_id,
                paquete: w.package.name.clone(),
                version: w.package.version.clone(),
                titulo,
                url,
                tipo,
                severidad,
                parcheado: parcheado_de(&w.versions),
            });
        }
    }

    Ok(avisos)
}

// --- Descubrimiento de repos (dirs con Cargo.lock, sin tocar lo personal) -----

/// Descubre los repos auditables bajo `raiz`: un directorio con `Cargo.lock`, sea en
/// su raíz o un nivel más abajo (p. ej. `informes/rust/Cargo.lock`). Devuelve
/// `(nombre_repo, dir_del_Cargo.lock)`. Salta lo de `NO_AUDITAR` y lo oculto (D18):
/// nunca desciende a los datos personales de Juan. Máximo dos niveles.
pub fn descubrir_repos(raiz: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut repos = Vec::new();
    let entradas =
        std::fs::read_dir(raiz).with_context(|| format!("no se pudo leer {}", raiz.display()))?;
    for e in entradas.flatten() {
        let ruta = e.path();
        if !ruta.is_dir() {
            continue;
        }
        // Dirección SEGURA (D20/D23): se AUDITA por defecto y solo se excluye lo
        // probadamente-no-proyecto —lo personal/infra de `NO_AUDITAR`, lo oculto, y
        // los backups CONGELADOS `*.descifrador` (los nombra así `respaldo-cifrado`;
        // son árboles vendorizados donde una CVE es inaccionable)—. Un proyecto vivo
        // que aún no está bajo git (p. ej. `iraca`) NO se pierde por no estar listado.
        let nombre = match ruta.file_name().and_then(|s| s.to_str()) {
            Some(n)
                if !n.starts_with('.')
                    && !n.ends_with(".descifrador")
                    && !NO_AUDITAR.contains(&n) =>
            {
                n.to_string()
            }
            _ => continue,
        };
        // Nivel 1: Cargo.lock en la raíz del repo.
        if ruta.join("Cargo.lock").is_file() {
            repos.push((nombre, ruta));
            continue;
        }
        // Nivel 2: un subdirectorio con Cargo.lock (crate dentro del repo).
        if let Ok(subs) = std::fs::read_dir(&ruta) {
            for s in subs.flatten() {
                let sruta = s.path();
                if !sruta.is_dir() {
                    continue;
                }
                if let Some(sn) = sruta.file_name().and_then(|x| x.to_str())
                    && !sn.starts_with('.')
                    && !sn.ends_with(".descifrador")
                    && !NO_AUDITAR.contains(&sn)
                    && sruta.join("Cargo.lock").is_file()
                {
                    repos.push((nombre.clone(), sruta));
                }
            }
        }
    }
    repos.sort();
    Ok(repos)
}

// --- Ejecución (`cargo audit --json` en el dir del repo) ---------------------

/// Corre `cargo audit --json` en `dir` y devuelve su stdout (el JSON). `cargo audit`
/// sale con código 1 cuando HALLA avisos —eso NO es un error—: el criterio es que
/// haya JSON en stdout. Solo es fallo real si stdout viene vacío (sin `Cargo.lock`,
/// o cargo-audit no instalado), y entonces se propaga el stderr (D20: falla ruidoso).
pub fn correr_cargo_audit(dir: &Path) -> Result<String> {
    let salida = std::process::Command::new("cargo")
        .args(["audit", "--json"])
        .current_dir(dir)
        .output()
        .context("no se pudo ejecutar `cargo audit` (¿está cargo-audit instalado? `cargo install cargo-audit`)")?;
    let stdout = String::from_utf8_lossy(&salida.stdout).into_owned();
    if stdout.trim().is_empty() {
        let stderr = String::from_utf8_lossy(&salida.stderr);
        anyhow::bail!(
            "cargo audit no produjo JSON en {}: {}",
            dir.display(),
            stderr.trim()
        );
    }
    Ok(stdout)
}

// --- Síntesis R5×R6: qué crates consumimos, y en qué repos ------------------

/// El conjunto de crates que NUESTROS repos consumen, mapeado a los repos que lo
/// consumen. Lee el `Cargo.lock` de cada repo descubierto bajo `raiz` (mismos filtros
/// de descubrimiento: sin lo personal ni los backups) y recoge cada `[[package]]`.
/// Es el insumo de la lente de exposición: cruzar el flujo de advisories (R5) contra
/// esto dice "este aviso toca un crate que consumo, en estos repos".
pub fn crates_consumidos(raiz: &Path) -> Result<std::collections::BTreeMap<String, Vec<String>>> {
    let mut mapa: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for (repo, dir) in descubrir_repos(raiz)? {
        let lock = dir.join("Cargo.lock");
        let Ok(texto) = std::fs::read_to_string(&lock) else {
            continue;
        };
        for crate_ in nombres_de_lock(&texto) {
            let repos = mapa.entry(crate_).or_default();
            if !repos.contains(&repo) {
                repos.push(repo.clone());
            }
        }
    }
    Ok(mapa)
}

/// Las versiones de `crate_` presentes en un `Cargo.lock` (puede haber varias: un crate
/// aparece más de una vez si el grafo no las unifica). Parsea los bloques `[[package]]`:
/// dentro del que tenga ese `name`, toma su `version`.
pub fn versiones_en_lock(texto: &str, crate_: &str) -> Vec<String> {
    let mut out = Vec::new();
    for bloque in texto.split("[[package]]") {
        let mut nombre = None;
        let mut version = None;
        for l in bloque.lines() {
            let l = l.trim();
            if let Some(r) = l.strip_prefix("name = \"").and_then(|r| r.strip_suffix('"')) {
                nombre = Some(r);
            } else if let Some(r) = l.strip_prefix("version = \"").and_then(|r| r.strip_suffix('"')) {
                version = Some(r.to_string());
            }
        }
        if nombre == Some(crate_)
            && let Some(v) = version
        {
            out.push(v);
        }
    }
    out
}

/// Dónde y en qué versión se consume `crate_` en todos los repos bajo `raiz`: una
/// entrada `(repo, versión)` por cada aparición. Es la consulta puntual que `audit`
/// (barrido completo) no da: "¿este crate está en alguno de mis proyectos, y en qué
/// versión?". Reusa `descubrir_repos` (D9).
pub fn consumo_de(raiz: &Path, crate_: &str) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for (repo, dir) in descubrir_repos(raiz)? {
        let Ok(texto) = std::fs::read_to_string(dir.join("Cargo.lock")) else {
            continue;
        };
        for v in versiones_en_lock(&texto, crate_) {
            out.push((repo.clone(), v));
        }
    }
    out.sort();
    Ok(out)
}

/// Extrae los nombres de paquete de un `Cargo.lock` (líneas `name = "…"`). Escaneo de
/// texto: el `Cargo.lock` es formato estable y esto NO es editar código (D17 aplica a
/// edición). No importa capturar de más (un superset de "lo que consumimos" no daña).
fn nombres_de_lock(texto: &str) -> Vec<String> {
    texto
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let resto = l.strip_prefix("name = \"")?;
            resto.strip_suffix('"').map(str::to_string)
        })
        .collect()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// El JSON REAL capturado de quipu (2026-09-27). La aguja se valida contra el
    /// ARTEFACTO que el código produce, no contra uno inventado (D33).
    const FIXTURE_QUIPU: &str = include_str!("../tests/fixtures/audit_quipu.json");

    // AGUJA (D33): del fixture real DEBEN salir la vulnerabilidad de cryptoki, el
    // unsound de lru y los dos yanked. Si el parser se rompe (mutante que devuelve
    // vacío), este caso se pone ROJO.
    #[test]
    fn aguja_extrae_vuln_y_warnings_del_fixture_real() {
        let avisos = parsear_cargo_audit(FIXTURE_QUIPU).unwrap();

        let cryptoki = avisos
            .iter()
            .find(|a| a.advisory_id == "RUSTSEC-2026-0286")
            .expect("debe hallar la vuln de cryptoki");
        assert_eq!(cryptoki.paquete, "cryptoki");
        assert_eq!(cryptoki.version, "0.12.0");
        assert_eq!(cryptoki.tipo, "vulnerabilidad");
        assert!(
            cryptoki.parcheado.contains("0.12.1"),
            "parcheado: {}",
            cryptoki.parcheado
        );

        let unsound = avisos
            .iter()
            .find(|a| a.advisory_id == "RUSTSEC-2026-0253")
            .expect("debe hallar el unsound de lru");
        assert_eq!(unsound.tipo, "unsound");
        assert_eq!(unsound.paquete, "lru");

        // Warning sin advisory (yanked): id sintético en mayúsculas.
        let yanked: Vec<_> = avisos.iter().filter(|a| a.tipo == "yanked").collect();
        assert_eq!(yanked.len(), 2, "el fixture tiene 2 yanked");
        assert!(yanked.iter().all(|a| a.advisory_id == "YANKED"));
        assert!(yanked.iter().any(|a| a.paquete == "chacha20"));
    }

    // CONTROL (D33): una salida LIMPIA (sin vulns, sin warnings) DEBE dar cero. Con
    // solo la aguja, un parser que dijera "sí" a todo pasaría igual; este caso lo
    // descarta. Falla por la MISMA vía real (el mismo `parsear_cargo_audit`).
    #[test]
    fn control_salida_limpia_da_cero() {
        let limpio = r#"{"vulnerabilities":{"found":false,"count":0,"list":[]},"warnings":{}}"#;
        let avisos = parsear_cargo_audit(limpio).unwrap();
        assert!(
            avisos.is_empty(),
            "una salida limpia no produce avisos: {avisos:?}"
        );
    }

    // Un warning yanked SIN campo `warnings` con advisory nulo no debe reventar el
    // parseo (D20: forma inesperada se maneja, no se cae).
    #[test]
    fn json_vacio_no_revienta() {
        assert!(parsear_cargo_audit("{}").unwrap().is_empty());
    }

    #[test]
    fn descubrir_salta_lo_personal_y_lo_oculto() {
        let dir = tempfile::tempdir().unwrap();
        let raiz = dir.path();
        // Un repo real con Cargo.lock.
        std::fs::create_dir_all(raiz.join("quipu")).unwrap();
        std::fs::write(raiz.join("quipu/Cargo.lock"), "").unwrap();
        // Un crate un nivel abajo (como informes/rust).
        std::fs::create_dir_all(raiz.join("informes/rust")).unwrap();
        std::fs::write(raiz.join("informes/rust/Cargo.lock"), "").unwrap();
        // Proyecto VIVO que NO está bajo git (como `iraca`): DEBE auditarse igual
        // (guardián del falso negativo, D23: la dirección segura es incluir).
        std::fs::create_dir_all(raiz.join("iraca")).unwrap();
        std::fs::write(raiz.join("iraca/Cargo.lock"), "").unwrap();
        // Backup CONGELADO `*.descifrador`: tiene Cargo.lock y AUN ASÍ no se audita
        // (árbol vendorizado, una CVE ahí es inaccionable).
        std::fs::create_dir_all(raiz.join("respaldo-fuera-de-casa.descifrador")).unwrap();
        std::fs::write(
            raiz.join("respaldo-fuera-de-casa.descifrador/Cargo.lock"),
            "",
        )
        .unwrap();
        // Backup CONGELADO con el `.descifrador` UN NIVEL ABAJO (la forma real:
        // `respaldo-fuera-de-casa/<blob>.descifrador/Cargo.lock`). El padre NO está en
        // NO_AUDITAR, así que se procesa; el subdir `.descifrador` NO debe auditarse en
        // el nivel 2 tampoco (si no, su árbol vendorizado cuela un aviso inaccionable).
        std::fs::create_dir_all(raiz.join("respaldo-fuera-de-casa/blob-20260811.descifrador"))
            .unwrap();
        std::fs::write(
            raiz.join("respaldo-fuera-de-casa/blob-20260811.descifrador/Cargo.lock"),
            "",
        )
        .unwrap();
        // Datos personales: TIENE un Cargo.lock señuelo y AUN ASÍ no debe auditarse.
        std::fs::create_dir_all(raiz.join("documentos")).unwrap();
        std::fs::write(raiz.join("documentos/Cargo.lock"), "").unwrap();
        // Oculto: se salta.
        std::fs::create_dir_all(raiz.join(".git")).unwrap();
        std::fs::write(raiz.join(".git/Cargo.lock"), "").unwrap();

        let repos = descubrir_repos(raiz).unwrap();
        let nombres: Vec<&str> = repos.iter().map(|(n, _)| n.as_str()).collect();
        assert!(nombres.contains(&"quipu"), "{nombres:?}");
        assert!(
            nombres.contains(&"informes"),
            "crate a un nivel: {nombres:?}"
        );
        assert!(
            nombres.contains(&"iraca"),
            "un proyecto vivo sin git NO se pierde (D23): {nombres:?}"
        );
        assert!(
            !nombres.contains(&"documentos"),
            "NUNCA lo personal: {nombres:?}"
        );
        assert!(
            !nombres.iter().any(|n| n.starts_with('.')),
            "nada oculto: {nombres:?}"
        );
        assert!(
            !nombres.iter().any(|n| n.ends_with(".descifrador")),
            "backup congelado no se audita: {nombres:?}"
        );
        // El `.descifrador` UN NIVEL ABAJO tampoco entra (atribuido a su padre).
        assert!(
            !nombres.contains(&"respaldo-fuera-de-casa"),
            "backup congelado anidado no se audita (nivel 2): {nombres:?}"
        );
    }

    #[test]
    fn nombres_de_lock_extrae_paquetes() {
        let lock = "\
[[package]]\nname = \"rustls\"\nversion = \"0.23.43\"\n\n\
[[package]]\nname = \"tokio\"\nversion = \"1.53.0\"\n";
        let n = nombres_de_lock(lock);
        assert_eq!(n, vec!["rustls".to_string(), "tokio".to_string()]);
    }

    // El mapa crate→repos: un crate consumido por DOS repos los lista a ambos.
    #[test]
    fn crates_consumidos_mapea_crate_a_repos() {
        let dir = tempfile::tempdir().unwrap();
        let raiz = dir.path();
        for repo in ["bachue", "nexus"] {
            std::fs::create_dir_all(raiz.join(repo)).unwrap();
            std::fs::write(
                raiz.join(repo).join("Cargo.lock"),
                "[[package]]\nname = \"rustls\"\nversion = \"0.23.43\"\n",
            )
            .unwrap();
        }
        let mapa = crates_consumidos(raiz).unwrap();
        let repos = mapa.get("rustls").expect("rustls está");
        assert!(
            repos.contains(&"bachue".to_string()) && repos.contains(&"nexus".to_string()),
            "{repos:?}"
        );
    }

    // versiones_en_lock: aguja (el crate a DOS versiones aparece las dos) + control
    // (un crate ausente devuelve vacío). Pareja D33.
    #[test]
    fn versiones_en_lock_encuentra_todas_y_calla_lo_ausente() {
        let lock = "[[package]]\nname = \"chacha20\"\nversion = \"0.10.1\"\n\n\
                    [[package]]\nname = \"rustls\"\nversion = \"0.23.43\"\n\n\
                    [[package]]\nname = \"chacha20\"\nversion = \"0.10.0\"\n";
        let mut vs = versiones_en_lock(lock, "chacha20");
        vs.sort();
        assert_eq!(vs, vec!["0.10.0".to_string(), "0.10.1".to_string()], "las dos versiones");
        // Control: un crate que no está devuelve vacío (no un falso positivo).
        assert!(versiones_en_lock(lock, "openssl").is_empty(), "ausente = vacío");
    }

    #[test]
    fn consumo_de_agrupa_repo_y_version() {
        let dir = tempfile::tempdir().unwrap();
        let raiz = dir.path();
        std::fs::create_dir_all(raiz.join("quipu")).unwrap();
        std::fs::write(
            raiz.join("quipu").join("Cargo.lock"),
            "[[package]]\nname = \"lru\"\nversion = \"0.16.4\"\n",
        )
        .unwrap();
        let filas = consumo_de(raiz, "lru").unwrap();
        assert_eq!(filas, vec![("quipu".to_string(), "0.16.4".to_string())]);
        assert!(consumo_de(raiz, "no-existe").unwrap().is_empty());
    }
}
