// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Juan Carlos Isaza
//
//! [R5] Sensor del catálogo **CISA KEV** (Known Exploited Vulnerabilities): los CVE que
//! SE EXPLOTAN de verdad en el mundo (no todo el ruido de CVEs). Cada entrada se vuelve
//! un `ItemSaber` y se guarda en `conocimiento`, categorizada por TEXTO COMPLETO al
//! proyecto Xiliux que informa/defiende —igual que un advisory de feed—. Le da casa a los
//! CVE NO-Rust (p. ej. un fallo de UEFI → zaque) que RustSec/`audit` no ven, cerrando el
//! punto ciego que el propio CVE-2026-97631 expuso.
//!
//! Dos mitades, como el resto de mindalá: `parsear` es PURO (JSON → ItemSaber, D33) y
//! `traer` toca la red. El E2E usa `--desde-archivo` por la MISMA costura de parseo.

use crate::conocimiento::ItemSaber;
use anyhow::{Context, Result};
use serde::Deserialize;

/// El catálogo KEV, JSON público y estable.
pub const URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

#[derive(Deserialize)]
struct Catalogo {
    vulnerabilities: Vec<EntradaKev>,
}

#[derive(Deserialize)]
struct EntradaKev {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(rename = "vendorProject", default)]
    vendor: String,
    #[serde(default)]
    product: String,
    #[serde(rename = "vulnerabilityName", default)]
    nombre: String,
    #[serde(rename = "shortDescription", default)]
    descripcion: String,
    #[serde(rename = "dateAdded", default)]
    fecha: String,
}

/// Parse PURO (D33): el JSON del catálogo KEV → `ItemSaber`. Falla ruidoso ante JSON
/// inválido o sin la clave `vulnerabilities` (D20/D30: no inventa un catálogo vacío).
pub fn parsear(json: &str) -> Result<Vec<ItemSaber>> {
    let cat: Catalogo = serde_json::from_str(json).context("KEV: JSON inválido o sin `vulnerabilities`")?;
    Ok(cat
        .vulnerabilities
        .into_iter()
        .map(|e| ItemSaber {
            titulo: format!("{}: {}", e.cve_id, e.nombre),
            url: format!("https://nvd.nist.gov/vuln/detail/{}", e.cve_id),
            fecha: e.fecha,
            // vendor + product + descripción llevan el DOMINIO (UEFI, Chrome, TLS…) que el
            // categorizador por texto completo usa para asignar destino. Es la razón de ser
            // de este sensor: un título `CVE-xxxx` genérico no bastaría.
            resumen: format!("{} {} {}", e.vendor, e.product, e.descripcion),
        })
        .collect())
}

/// Trae el catálogo KEV por red (reusa el cliente con User-Agent de `github`).
pub async fn traer() -> Result<String> {
    let cli = crate::github::cliente()?;
    // Reintento ante fallos de transporte (como github/feeds), sin reintentar HTTP no-2xx.
    let resp = crate::github::enviar(cli.get(URL))
        .await
        .context("falló la petición a CISA KEV")?;
    let resp = resp.error_for_status().context("CISA KEV devolvió error HTTP")?;
    resp.text().await.context("no se pudo leer el cuerpo de KEV")
}

#[cfg(test)]
mod pruebas {
    use super::*;

    // Muestra con la MISMA forma del catálogo real (una entrada de arranque, una web).
    const MUESTRA: &str = r#"{"title":"CISA KEV","vulnerabilities":[
      {"cveID":"CVE-2026-97631","vendorProject":"TianoCore","product":"EDK II",
       "vulnerabilityName":"Pre-boot RCE in PXE driver",
       "shortDescription":"secure-boot / measured-boot integrity bypass; bootkit before the OS loads",
       "dateAdded":"2026-10-28"},
      {"cveID":"CVE-2026-00001","vendorProject":"Acme","product":"WebApp",
       "vulnerabilityName":"SQL injection","shortDescription":"a generic web sql injection",
       "dateAdded":"2026-10-29"}
    ]}"#;

    // AGUJA (D33): el parser mapea cada entrada a ItemSaber con el DOMINIO en el resumen
    // (lo que el categorizador por texto completo necesita para dar destino).
    #[test]
    fn parsea_catalogo_kev() {
        let items = parsear(MUESTRA).unwrap();
        assert_eq!(items.len(), 2, "{items:?}");
        assert!(items[0].titulo.starts_with("CVE-2026-97631:"));
        assert_eq!(items[0].url, "https://nvd.nist.gov/vuln/detail/CVE-2026-97631");
        assert!(
            items[0].resumen.contains("secure-boot") && items[0].resumen.contains("bootkit"),
            "el resumen lleva el dominio: {:?}",
            items[0].resumen
        );
        assert_eq!(items[0].fecha, "2026-10-28");
    }

    // CONTROL (D20/D30): JSON inválido o sin la clave esperada falla ruidoso, no devuelve
    // un catálogo vacío en silencio.
    #[test]
    fn json_invalido_o_sin_clave_falla() {
        assert!(parsear("no soy json").is_err());
        assert!(parsear(r#"{"otra_cosa":1}"#).is_err());
    }
}
