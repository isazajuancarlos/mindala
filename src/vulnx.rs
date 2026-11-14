// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Juan Carlos Isaza
//
//! [R5] Sensor **vulnx** (ProjectDiscovery): inteligencia de vulnerabilidades RICA —EPSS,
//! exploits/POCs, prioridad de plantilla nuclei, estado KEV— que cubre a la vez productos
//! (p. ej. EDK2 BIOS) y crates (rustls). Es la fuente más completa que feed/kev para el eje
//! "virus → destino": cada CVE se categoriza por TEXTO COMPLETO al proyecto Xiliux que
//! informa/defiende y cae en `conocimiento` (→ `saber --destino`, → el hook `(mindala <p>)`).
//!
//! Dos mitades, como el resto de mindalá: `parsear` es PURO (JSON → ItemSaber, D33) y
//! `traer` hace SHELL-OUT a `vulnx search … --json` (precedente: `auditoria`↔cargo-audit,
//! `estudiar`↔git). El E2E usa `--desde-archivo` por la MISMA costura de parseo, sin red.
//!
//! Requiere el binario `vulnx` (`go install github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest`);
//! keyless con rate-limit (API key gratis `vulnx auth` sube el límite).

use crate::conocimiento::ItemSaber;
use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Deserialize)]
struct Salida {
    results: Vec<Entrada>,
}

#[derive(Deserialize)]
struct Entrada {
    cve_id: String,
    // `Option` (no `String` a secas): vulnx emite `null` en campos ausentes, y `null` no
    // deserializa a `String`. Default None cubre además la clave ausente.
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    cve_created_at: Option<String>,
}

/// Parse PURO (D33): el JSON de `vulnx search --json` → `ItemSaber`. Falla ruidoso si no
/// trae `results` (p. ej. se olvidó `--json`): no inventa un lote vacío (D20/D30).
pub fn parsear(json: &str) -> Result<Vec<ItemSaber>> {
    let s: Salida = serde_json::from_str(json)
        .context("vulnx: JSON inesperado (¿falta --json, o la forma cambió?)")?;
    Ok(s.results
        .into_iter()
        .map(|e| {
            let name = e.name.unwrap_or_default();
            let desc = e.description.unwrap_or_default();
            let sev = e.severity.unwrap_or_default();
            ItemSaber {
                titulo: if name.is_empty() {
                    e.cve_id.clone()
                } else {
                    format!("{}: {name}", e.cve_id)
                },
                url: format!("https://nvd.nist.gov/vuln/detail/{}", e.cve_id),
                fecha: e.cve_created_at.unwrap_or_default(),
                // name + severidad + descripción llevan el dominio (producto, crate, clase)
                // que la categorización por texto completo usa para asignar destino.
                resumen: format!("{name} {sev} {desc}"),
            }
        })
        .collect())
}

/// Shell-out a `vulnx search <consulta> --json --limit <n>`. Busca el binario en PATH y,
/// si no está, en `~/go/bin/vulnx` (donde lo deja `go install`). El banner/logs de vulnx
/// van a stderr; el JSON a stdout.
pub fn traer(consulta: &str, limite: u32) -> Result<String> {
    let lim = limite.to_string();
    let args = ["search", consulta, "--json", "--limit", lim.as_str()];
    let salida = match std::process::Command::new("vulnx").args(args).output() {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let home = std::env::var_os("HOME")
                .context("`vulnx` no está en PATH y no hay $HOME para probar ~/go/bin")?;
            let bin = std::path::Path::new(&home).join("go/bin/vulnx");
            std::process::Command::new(&bin).args(args).output().with_context(|| {
                format!(
                    "no se pudo ejecutar vulnx (ni en PATH ni en {}); instala con \
                     `go install github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest`",
                    bin.display()
                )
            })?
        }
        Err(e) => return Err(e).context("no se pudo ejecutar `vulnx`"),
    };
    if !salida.status.success() {
        anyhow::bail!(
            "vulnx salió con error: {}",
            String::from_utf8_lossy(&salida.stderr).chars().take(300).collect::<String>()
        );
    }
    String::from_utf8(salida.stdout).context("vulnx: la salida no es UTF-8")
}

#[cfg(test)]
mod pruebas {
    use super::*;

    // Fixture REAL (recortado) de `vulnx search --json` (D33): la aguja se valida contra
    // el artefacto que produce la herramienta de verdad, no uno inventado.
    const MUESTRA: &str = include_str!("../tests/fixtures/vulnx_sample.json");

    // AGUJA (D33): el parser mapea cada result a ItemSaber con el DOMINIO en el resumen
    // (name+severidad+descripción) — lo que el categorizador por texto completo necesita.
    #[test]
    fn parsea_salida_de_vulnx() {
        let items = parsear(MUESTRA).unwrap();
        assert!(!items.is_empty(), "el fixture trae results");
        let primero = &items[0];
        assert!(primero.titulo.starts_with("CVE-"), "titulo con CVE: {}", primero.titulo);
        assert!(
            primero.url.starts_with("https://nvd.nist.gov/vuln/detail/CVE-"),
            "url NVD: {}",
            primero.url
        );
        assert!(!primero.resumen.trim().is_empty(), "el resumen lleva el dominio");
    }

    // CONTROL (D20/D30): JSON sin `results` (p. ej. sin --json) falla ruidoso, no devuelve
    // un lote vacío en silencio.
    #[test]
    fn json_sin_results_falla() {
        assert!(parsear("no soy json").is_err());
        assert!(parsear(r#"{"otra":1}"#).is_err());
    }

    // Robustez: un result con campos `null` (vulnx los emite) NO revienta el parseo.
    #[test]
    fn campos_null_no_revientan() {
        let json = r#"{"count":1,"total":1,"results":[{"cve_id":"CVE-2026-1","name":null,"description":null,"severity":null,"cve_created_at":null}]}"#;
        let items = parsear(json).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].titulo, "CVE-2026-1", "sin name usa el cve_id solo");
    }
}
