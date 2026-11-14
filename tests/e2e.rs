// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: MIT

//! Prueba de extremo a extremo (D28): arranca el BINARIO real y le habla como el
//! mundo —argumentos y un archivo—, sin red. Ejerce el pipeline completo:
//! parsear la respuesta de la API → categorizar → encolar en SQLite → leer la cola
//! → sentar un veredicto → verlo salir de la cola.
//!
//! El fixture pasa por la MISMA costura de parseo del camino real (`--desde-archivo`
//! usa `parsear_respuesta`, igual que el fetch de red), así que esto mide el
//! producto, no un códec de juguete (D33).

use std::path::PathBuf;
use std::process::Command;

fn bin() -> PathBuf {
    // Cargo expone la ruta del binario compilado a las pruebas de integración.
    PathBuf::from(env!("CARGO_BIN_EXE_mindala"))
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/busqueda_webauthn.json")
}

fn correr(bd: &str, args: &[&str]) -> (String, String, bool) {
    let salida = Command::new(bin())
        .arg("--bd")
        .arg(bd)
        .args(args)
        .output()
        .expect("no se pudo ejecutar mindala");
    (
        String::from_utf8_lossy(&salida.stdout).into_owned(),
        String::from_utf8_lossy(&salida.stderr).into_owned(),
        salida.status.success(),
    )
}

#[test]
fn pipeline_completo_sin_red() {
    let dir = tempfile::tempdir().unwrap();
    let bd = dir.path().join("mindala.db");
    let bd = format!("sqlite://{}", bd.display());
    let fx = fixture();
    let fx = fx.to_str().unwrap();

    // 1) buscar --desde-archivo: 3 traídos, 3 nuevos.
    let (out, err, ok) = correr(
        &bd,
        &["buscar", "--topic", "webauthn", "--desde-archivo", fx],
    );
    assert!(ok, "buscar falló: {err}");
    assert!(out.contains("3 traídos"), "stdout: {out}");
    assert!(out.contains("3 nuevos"), "stdout: {out}");

    // 2) cola: los 3 pendientes, cada uno con su destino categorizado.
    let (out, _e, ok) = correr(&bd, &["cola"]);
    assert!(ok);
    assert!(out.contains("3 pendientes"), "stdout: {out}");
    assert!(out.contains("kanidm/webauthn-rs"), "stdout: {out}");
    assert!(
        out.contains("bachue") || out.contains("chuspa"),
        "webauthn debe ir a auth: {out}"
    );
    assert!(out.contains("quipu"), "el repo pqc debe ir a quipu: {out}");
    assert!(
        out.contains("sin_clasificar"),
        "el juego no casa nada: {out}"
    );
    // La licencia AGPL del candidato de cripto debe verse (la licencia manda).
    assert!(out.contains("AGPL-3.0"), "debe mostrar la licencia: {out}");

    // 3) filtrar la cola por destino quipu: solo el candidato 222.
    let (out, _e, ok) = correr(&bd, &["cola", "--destino", "quipu"]);
    assert!(ok);
    assert!(out.contains("1 pendientes"), "stdout: {out}");
    assert!(out.contains("[222]"), "stdout: {out}");

    // 4) sentar veredicto: descartar el 333 (el juego).
    let (out, err, ok) = correr(
        &bd,
        &[
            "veredicto",
            "333",
            "--descartar",
            "--nota",
            "fuera de dominio",
        ],
    );
    assert!(ok, "veredicto falló: {err}");
    assert!(out.contains("Descartar"), "stdout: {out}");

    // 5) la cola baja a 2 (el descartado sale).
    let (out, _e, ok) = correr(&bd, &["cola"]);
    assert!(ok);
    assert!(out.contains("2 pendientes"), "stdout: {out}");
    assert!(
        !out.contains("retro-fun"),
        "el descartado no debe seguir en la cola: {out}"
    );

    // 6) re-buscar el mismo archivo: dedup — 0 nuevos, y el congelado (333) intacto.
    let (out, _e, ok) = correr(
        &bd,
        &["buscar", "--topic", "webauthn", "--desde-archivo", fx],
    );
    assert!(ok);
    assert!(out.contains("0 nuevos"), "dedup: {out}");
    assert!(
        out.contains("1 congelados"),
        "el 333 tiene veredicto → congelado: {out}"
    );
}

// CASO ROJO por la vía real (D33): un veredicto sobre un id inexistente hace que
// el binario salga con código != 0 y lo diga por stderr, no un éxito silencioso.
#[test]
fn veredicto_fantasma_sale_con_error() {
    let dir = tempfile::tempdir().unwrap();
    let bd = format!("sqlite://{}", dir.path().join("m.db").display());
    let (_o, err, ok) = correr(&bd, &["veredicto", "999999", "--adoptar"]);
    assert!(!ok, "debe fallar");
    assert!(err.contains("no existe el candidato"), "stderr: {err}");
}

// R2 + R4 de extremo a extremo por el binario real (D28), sin red: sembrar con el
// fixture, ver la ficha, adoptar, ver la tarea emitida, cerrar el enganche.
#[test]
fn r2_r4_ficha_adopcion_y_tarea() {
    let dir = tempfile::tempdir().unwrap();
    let bd = format!("sqlite://{}", dir.path().join("mindala.db").display());
    let fx = fixture();
    let fx = fx.to_str().unwrap();

    correr(
        &bd,
        &["buscar", "--topic", "webauthn", "--desde-archivo", fx],
    );

    // R2 `ver`: la ficha del candidato de cripto (222) trae destino quipu y su
    // licencia AGPL marcada como copyleft (reimplementar, no copiar).
    let (out, _e, ok) = correr(&bd, &["ver", "222"]);
    assert!(ok, "ver falló: {out}");
    assert!(out.contains("quipu"), "destino: {out}");
    assert!(out.contains("AGPL-3.0"), "licencia: {out}");
    assert!(out.contains("copyleft"), "debe avisar del copyleft: {out}");
    assert!(out.contains("pendiente"), "veredicto inicial: {out}");

    // Sin adopciones, `tareas` no emite nada.
    let (out, _e, ok) = correr(&bd, &["tareas"]);
    assert!(ok);
    assert!(out.contains("no hay adopciones"), "stdout: {out}");

    // R4: adoptar el 111 (webauthn-rs) → aparece su ficha de tarea para bachue/chuspa.
    let (out, err, ok) = correr(
        &bd,
        &["veredicto", "111", "--adoptar", "--nota", "flujo webauthn"],
    );
    assert!(ok, "adoptar falló: {err}");
    assert!(
        out.contains("tareas"),
        "debe sugerir generar la tarea: {out}"
    );

    let (out, _e, ok) = correr(&bd, &["tareas"]);
    assert!(ok);
    assert!(out.contains("TAREA para"), "debe emitir la ficha: {out}");
    assert!(out.contains("kanidm/webauthn-rs"), "stdout: {out}");
    assert!(out.contains("flujo webauthn"), "debe llevar la nota: {out}");
    assert!(
        out.contains("tarea-lista 111"),
        "debe indicar cómo cerrar: {out}"
    );

    // Cerrar el enganche: la tarea sale de la lista.
    let (out, err, ok) = correr(&bd, &["tarea-lista", "111"]);
    assert!(ok, "tarea-lista falló: {err}");
    assert!(out.contains("registrada"), "stdout: {out}");
    let (out, _e, ok) = correr(&bd, &["tareas"]);
    assert!(ok);
    assert!(
        out.contains("no hay adopciones"),
        "la tarea cerrada sale de la lista: {out}"
    );
}

// CASO ROJO (D33): tarea-lista sobre un candidato NO adoptado sale con error.
#[test]
fn tarea_lista_de_no_adoptado_sale_con_error() {
    let dir = tempfile::tempdir().unwrap();
    let bd = format!("sqlite://{}", dir.path().join("m.db").display());
    let fx = fixture();
    correr(
        &bd,
        &[
            "buscar",
            "--topic",
            "x",
            "--desde-archivo",
            fx.to_str().unwrap(),
        ],
    );
    // 333 está pendiente, no adoptado.
    let (_o, err, ok) = correr(&bd, &["tarea-lista", "333"]);
    assert!(!ok, "debe fallar");
    assert!(err.contains("ADOPTADO"), "stderr: {err}");
}

fn fixture_audit() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/audit_quipu.json")
}

// E2E del lazo dep→CVE (R6, D28): arranca el binario real y le da el JSON REAL de
// `cargo audit` de quipu por la MISMA costura del camino real (`--desde-archivo` usa
// `parsear_cargo_audit`, igual que el shell-out). Ejerce audit → avisos → dedup → triar.
#[test]
fn audit_pipeline_sin_red() {
    let dir = tempfile::tempdir().unwrap();
    let bd = format!("sqlite://{}", dir.path().join("m.db").display());
    let fx = fixture_audit();
    let fx = fx.to_str().unwrap();

    // 1) audit --desde-archivo: registra los avisos del fixture como de 'quipu'.
    let (out, err, ok) = correr(
        &bd,
        &["audit", "--desde-archivo", fx, "--etiqueta", "quipu"],
    );
    assert!(ok, "audit falló: {err}");
    assert!(out.contains("nuevos"), "stdout: {out}");

    // 2) avisos: el digest muestra la vuln de cryptoki marcada VULN, y el yanked.
    let (out, _e, ok) = correr(&bd, &["avisos"]);
    assert!(ok);
    assert!(out.contains("=== quipu ==="), "stdout: {out}");
    assert!(
        out.contains("RUSTSEC-2026-0286"),
        "la vuln de cryptoki: {out}"
    );
    assert!(out.contains("VULN"), "debe marcar la vulnerabilidad: {out}");
    assert!(out.contains("chacha20"), "el yanked también: {out}");

    // 3) re-correr: 0 nuevos (dedup por memoria, D5).
    let (out, _e, ok) = correr(
        &bd,
        &["audit", "--desde-archivo", fx, "--etiqueta", "quipu"],
    );
    assert!(ok);
    assert!(
        out.contains("0 nuevos"),
        "la re-corrida no destaca nada: {out}"
    );

    // 4) triar la vuln: sale del digest.
    let (out, err, ok) = correr(
        &bd,
        &[
            "triar-aviso",
            "quipu",
            "RUSTSEC-2026-0286",
            "cryptoki",
            "--estado",
            "resuelto",
        ],
    );
    assert!(ok, "triar falló: {err}");
    assert!(out.contains("resuelto"), "stdout: {out}");
    let (out, _e, ok) = correr(&bd, &["avisos", "--repo", "quipu"]);
    assert!(ok);
    assert!(
        !out.contains("RUSTSEC-2026-0286"),
        "la resuelta ya no aparece: {out}"
    );
}

// E2E de las fuentes de conocimiento (R5, D28): arranca el binario y le da un feed
// Atom REAL de RustSec por la MISMA costura (`--desde-archivo` usa `extraer_items`).
// Ejerce feed → saber (digest) → triar-saber.
#[test]
fn feed_digest_sin_red() {
    let dir = tempfile::tempdir().unwrap();
    let bd = format!("sqlite://{}", dir.path().join("m.db").display());
    let fx = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/feed_rustsec.xml");
    let fx = fx.to_str().unwrap();

    // 1) feed --desde-archivo: registra los ítems del Atom de RustSec.
    let (out, err, ok) = correr(&bd, &["feed", "--desde-archivo", fx, "--fuente", "rustsec"]);
    assert!(ok, "feed falló: {err}");
    assert!(out.contains("2 ítems"), "stdout: {out}");
    assert!(out.contains("2 nuevos"), "stdout: {out}");

    // 2) saber: el digest muestra los advisories con su fuente.
    let (out, _e, ok) = correr(&bd, &["saber"]);
    assert!(ok);
    assert!(out.contains("RUSTSEC-2026-0309"), "stdout: {out}");
    assert!(out.contains("[rustsec]"), "debe mostrar la fuente: {out}");

    // 3) re-correr feed: 0 nuevos (dedup por URL).
    let (out, _e, ok) = correr(&bd, &["feed", "--desde-archivo", fx, "--fuente", "rustsec"]);
    assert!(ok);
    assert!(
        out.contains("0 nuevos"),
        "la re-corrida no destaca nada: {out}"
    );

    // 4) triar por URL: sale del digest.
    let u = "https://rustsec.org/advisories/RUSTSEC-2026-0309.html";
    let (out, err, ok) = correr(&bd, &["triar-saber", u, "--estado", "visto"]);
    assert!(ok, "triar-saber falló: {err}");
    assert!(out.contains("visto"), "stdout: {out}");
    let (out, _e, ok) = correr(&bd, &["saber"]);
    assert!(ok);
    assert!(
        !out.contains("RUSTSEC-2026-0309"),
        "el triado ya no aparece: {out}"
    );
}

// B del eje unificado: vulnerabilidades EXTERNAS (CISA KEV) categorizadas por destino,
// igual que repos y noticias. Le da casa al CVE no-Rust que RustSec no ve.
#[test]
fn kev_categoriza_vulnerabilidades_por_destino() {
    let dir = tempfile::tempdir().unwrap();
    let bd = format!("sqlite://{}", dir.path().join("m.db").display());
    let fx = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kev_sample.json");
    let fx = fx.to_str().unwrap();

    // 1) kev --desde-archivo: registra los CVE explotados del catálogo.
    let (out, err, ok) = correr(&bd, &["kev", "--desde-archivo", fx]);
    assert!(ok, "kev falló: {err}");
    assert!(out.contains("2 nuevos"), "stdout: {out}");

    // 2) AGUJA: el CVE de ARRANQUE cae en zaque por TEXTO COMPLETO (vendor/product/desc).
    let (out, _e, ok) = correr(&bd, &["saber", "--destino", "zaque"]);
    assert!(ok);
    assert!(out.contains("CVE-2026-97631"), "el CVE de arranque va a zaque: {out}");

    // 3) CONTROL: el SQLi web genérico NO cae en zaque.
    assert!(!out.contains("CVE-2026-55123"), "el SQLi no es de zaque: {out}");

    // 4) dedup por URL: re-correr no destaca nada.
    let (out, _e, ok) = correr(&bd, &["kev", "--desde-archivo", fx]);
    assert!(ok);
    assert!(out.contains("0 nuevos"), "dedup: {out}");
}

// Sensor vulnx (ProjectDiscovery) por --desde-archivo: ingiere la inteligencia de vulns y
// la categoriza por destino, como cualquier conocimiento. Prueba el flujo completo (D28)
// sin ejecutar el binario `vulnx` ni red.
#[test]
fn vulnx_ingiere_y_categoriza() {
    let dir = tempfile::tempdir().unwrap();
    let bd = format!("sqlite://{}", dir.path().join("m.db").display());
    let fx = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vulnx_sample.json");
    let fx = fx.to_str().unwrap();

    // 1) vulnx --desde-archivo: parsea el JSON real y registra los CVE.
    let (out, err, ok) = correr(&bd, &["vulnx", "--desde-archivo", fx]);
    assert!(ok, "vulnx falló: {err}");
    assert!(out.contains("3 CVE"), "stdout: {out}");
    assert!(out.contains("3 nuevos"), "stdout: {out}");

    // 2) el digest los muestra (con su fuente), prueba de que se categorizaron y guardaron.
    let (out, _e, ok) = correr(&bd, &["saber"]);
    assert!(ok);
    assert!(out.contains("CVE-2026-63377"), "el CVE del fixture aparece en saber: {out}");
    assert!(out.contains("[vulnx]"), "la fuente es vulnx: {out}");

    // 3) dedup: re-correr no destaca nada.
    let (out, _e, ok) = correr(&bd, &["vulnx", "--desde-archivo", fx]);
    assert!(ok);
    assert!(out.contains("0 nuevos"), "dedup por URL: {out}");
}
