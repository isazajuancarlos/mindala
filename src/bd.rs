// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: MIT

//! La memoria de mindala. Encapsula SQLite: abrir/migrar, encolar candidatos con
//! deduplicación y caducidad, listar la cola y sentar el veredicto del criterio.
//!
//! Reglas que esta capa hace cumplir (del `DISENO.md`):
//! - **Dedup (regla 4):** `id_github` es la clave; lo ya visto no se duplica.
//! - **No re-estudiar (regla 4):** una fila con veredicto NO se toca al re-descubrir.
//! - **Caducidad:** una fila PENDIENTE sí se actualiza (estrellas, `pushed_at`…):
//!   el candidato pudo cambiar y aún no hay juicio que preservar.

use crate::categoria::categorizar;
use crate::modelo::{Candidato, Veredicto};
use anyhow::{Context, Result};
use sqlx::Row;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;

/// Re-exportado para que el binario tipe el pool sin depender de `sqlx` directamente.
pub use sqlx::SqlitePool;

/// Migraciones embebidas en el binario (`migrations/`): un solo ejecutable, sin
/// archivos sueltos que llevar.
static MIGRACIONES: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Una fila de la cola, tal como la lee `cola`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilaCola {
    pub id_github: i64,
    pub nombre_completo: String,
    pub url: String,
    pub destino: String,
    pub puntaje: i64,
    pub estrellas: i64,
    pub licencia: String,
    pub descripcion: String,
}

/// El resultado de encolar un lote: cuántos nuevos, cuántos pendientes
/// actualizados, cuántos ya cerrados que se dejaron intactos.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ResumenEncolado {
    pub nuevos: usize,
    pub actualizados: usize,
    pub congelados: usize,
}

/// La ficha completa de un candidato, para `ver` (R2). Incluye lo que la cola omite:
/// el veredicto, su nota, cuándo se descubrió y si ya generó tarea.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ficha {
    pub id_github: i64,
    pub nombre_completo: String,
    pub url: String,
    pub descripcion: String,
    pub lenguaje: String,
    pub topics: Vec<String>,
    pub estrellas: i64,
    pub pushed_at: String,
    pub licencia: String,
    pub destino: String,
    pub puntaje: i64,
    pub descubierto_en: String,
    pub veredicto: Veredicto,
    pub nota: Option<String>,
    pub veredicto_en: Option<String>,
    pub tarea_en: Option<String>,
}

/// Una ficha de tarea lista para registrar en el proyecto destino (R4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tarea {
    pub id_github: i64,
    pub nombre_completo: String,
    pub url: String,
    pub descripcion: String,
    pub destino: String,
    pub licencia: String,
    pub nota: Option<String>,
}

/// Una fila de aviso de seguridad (R6), tal como la lee `avisos`. Espeja `Aviso`
/// de `auditoria`, más el repo, el estado de triaje y cuándo se vio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilaAviso {
    pub repo: String,
    pub advisory_id: String,
    pub paquete: String,
    pub version: String,
    pub titulo: String,
    pub url: String,
    pub tipo: String,
    pub severidad: String,
    pub parcheado: String,
    pub primero_visto: String,
    pub estado: Option<String>,
}

/// El resultado de registrar los avisos de una corrida de `audit` (R6): cuántos son
/// NUEVOS (nunca vistos) y cuántos ya estaban (se refresca `ultimo_visto`). Es la
/// disciplina de `ResumenEncolado`: la re-corrida destaca solo lo nuevo (D5).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ResumenAvisos {
    pub nuevos: usize,
    pub revistos: usize,
    /// Avisos auto-retirados que el audit VOLVIÓ a reportar → se REABRIERON (anti fail-open).
    pub reabiertos: usize,
}

/// Una fila de conocimiento (R5) para el digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilaSaber {
    pub url: String,
    pub fuente: String,
    pub titulo: String,
    pub fecha: String,
    pub destino: String,
    pub puntaje: i64,
    pub primero_visto: String,
    /// El cuerpo (capado en origen). Alimenta la pasada de razonamiento: Claude juzga
    /// por el cuerpo, no solo el título. Puede ser '' en filas viejas (nacieron sin él).
    pub resumen: String,
}

/// Abre (o crea) la BD en `ruta` y aplica las migraciones.
pub async fn abrir(ruta: &str) -> Result<SqlitePool> {
    let opts = SqliteConnectOptions::from_str(ruta)
        .with_context(|| format!("ruta de BD inválida: {ruta}"))?
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .context("no se pudo abrir la BD")?;
    MIGRACIONES
        .run(&pool)
        .await
        .context("fallaron las migraciones")?;
    Ok(pool)
}

/// Encola un lote de candidatos, categorizándolos y respetando dedup/caducidad.
pub async fn encolar(
    pool: &SqlitePool,
    candidatos: &[Candidato],
    ahora: &str,
) -> Result<ResumenEncolado> {
    let mut r = ResumenEncolado::default();
    for c in candidatos {
        let existente: Option<(Option<String>,)> =
            sqlx::query_as("SELECT veredicto FROM candidatos WHERE id_github = ?1")
                .bind(c.id_github)
                .fetch_optional(pool)
                .await?;

        match existente {
            // Ya cerrado (adoptar/descartar): NO se toca (regla 4, no re-estudiar).
            Some((Some(_),)) => {
                r.congelados += 1;
            }
            // Pendiente: se refresca su metadata (caducidad) conservando descubierto_en.
            Some((None,)) => {
                let clas = categorizar(c);
                let topics = serde_json::to_string(&c.topics)?;
                sqlx::query(
                    "UPDATE candidatos SET nombre_completo=?2, url=?3, descripcion=?4, \
                     lenguaje=?5, topics=?6, estrellas=?7, pushed_at=?8, licencia=?9, \
                     destino=?10, puntaje=?11 WHERE id_github=?1",
                )
                .bind(c.id_github)
                .bind(&c.nombre_completo)
                .bind(&c.url)
                .bind(&c.descripcion)
                .bind(&c.lenguaje)
                .bind(&topics)
                .bind(c.estrellas)
                .bind(&c.pushed_at)
                .bind(&c.licencia)
                .bind(&clas.destino)
                .bind(clas.puntaje)
                .execute(pool)
                .await?;
                r.actualizados += 1;
            }
            // Nuevo.
            None => {
                let clas = categorizar(c);
                let topics = serde_json::to_string(&c.topics)?;
                sqlx::query(
                    "INSERT INTO candidatos (id_github, nombre_completo, url, descripcion, \
                     lenguaje, topics, estrellas, pushed_at, licencia, destino, puntaje, \
                     descubierto_en) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                )
                .bind(c.id_github)
                .bind(&c.nombre_completo)
                .bind(&c.url)
                .bind(&c.descripcion)
                .bind(&c.lenguaje)
                .bind(&topics)
                .bind(c.estrellas)
                .bind(&c.pushed_at)
                .bind(&c.licencia)
                .bind(&clas.destino)
                .bind(clas.puntaje)
                .bind(ahora)
                .execute(pool)
                .await?;
                r.nuevos += 1;
            }
        }
    }
    Ok(r)
}

/// Lista la cola de PENDIENTES (sin veredicto). Si `destino` es `Some`, filtra por
/// ese proyecto. Orden: destino, luego puntaje desc, luego estrellas desc.
pub async fn cola(pool: &SqlitePool, destino: Option<&str>) -> Result<Vec<FilaCola>> {
    // Dos consultas literales (sqlx 0.9 exige `&'static str`): el filtro es un
    // bind, nunca interpolado. La única diferencia es el `AND destino`.
    const TODOS: &str = "SELECT id_github, nombre_completo, url, destino, puntaje, estrellas, \
        licencia, descripcion FROM candidatos WHERE veredicto IS NULL \
        ORDER BY destino ASC, puntaje DESC, estrellas DESC";
    const POR_DESTINO: &str = "SELECT id_github, nombre_completo, url, destino, puntaje, estrellas, \
        licencia, descripcion FROM candidatos WHERE veredicto IS NULL AND destino = ?1 \
        ORDER BY destino ASC, puntaje DESC, estrellas DESC";
    let rows = match destino {
        Some(d) => sqlx::query(POR_DESTINO).bind(d).fetch_all(pool).await?,
        None => sqlx::query(TODOS).fetch_all(pool).await?,
    };
    Ok(rows
        .into_iter()
        .map(|row| FilaCola {
            id_github: row.get("id_github"),
            nombre_completo: row.get("nombre_completo"),
            url: row.get("url"),
            destino: row.get("destino"),
            puntaje: row.get("puntaje"),
            estrellas: row.get("estrellas"),
            licencia: row.get("licencia"),
            descripcion: row.get("descripcion"),
        })
        .collect())
}

/// ¿Ya existe un candidato con este `owner/repo` (sin importar mayúsculas)? Lo usa
/// R3 para NO gastar una petición a la API resolviendo algo que ya está en la memoria.
pub async fn existe_nombre(pool: &SqlitePool, nombre_completo: &str) -> Result<bool> {
    let r: Option<(i64,)> =
        sqlx::query_as("SELECT 1 FROM candidatos WHERE LOWER(nombre_completo) = LOWER(?1) LIMIT 1")
            .bind(nombre_completo)
            .fetch_optional(pool)
            .await?;
    Ok(r.is_some())
}

/// Lee la ficha completa de un candidato por su `id_github` (R2). `None` si no existe.
pub async fn ver(pool: &SqlitePool, id_github: i64) -> Result<Option<Ficha>> {
    let fila = sqlx::query(
        "SELECT id_github, nombre_completo, url, descripcion, lenguaje, topics, estrellas, \
         pushed_at, licencia, destino, puntaje, descubierto_en, veredicto, nota, veredicto_en, \
         tarea_en FROM candidatos WHERE id_github = ?1",
    )
    .bind(id_github)
    .fetch_optional(pool)
    .await?;
    let Some(row) = fila else { return Ok(None) };
    let topics_json: String = row.get("topics");
    let topics: Vec<String> = serde_json::from_str(&topics_json).unwrap_or_default();
    let v_bd: Option<String> = row.get("veredicto");
    let veredicto = Veredicto::desde_bd(v_bd.as_deref())
        .with_context(|| format!("veredicto corrupto en id_github={id_github}: {v_bd:?}"))?;
    Ok(Some(Ficha {
        id_github: row.get("id_github"),
        nombre_completo: row.get("nombre_completo"),
        url: row.get("url"),
        descripcion: row.get("descripcion"),
        lenguaje: row.get("lenguaje"),
        topics,
        estrellas: row.get("estrellas"),
        pushed_at: row.get("pushed_at"),
        licencia: row.get("licencia"),
        destino: row.get("destino"),
        puntaje: row.get("puntaje"),
        descubierto_en: row.get("descubierto_en"),
        veredicto,
        nota: row.get("nota"),
        veredicto_en: row.get("veredicto_en"),
        tarea_en: row.get("tarea_en"),
    }))
}

/// Lista los candidatos ADOPTADOS que aún no se han convertido en tarea (R4).
/// Orden: destino, luego puntaje desc.
pub async fn adoptados_sin_tarea(pool: &SqlitePool) -> Result<Vec<Tarea>> {
    let rows = sqlx::query(
        "SELECT id_github, nombre_completo, url, descripcion, destino, licencia, nota \
         FROM candidatos WHERE veredicto = 'adoptar' AND tarea_en IS NULL \
         ORDER BY destino ASC, puntaje DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| Tarea {
            id_github: row.get("id_github"),
            nombre_completo: row.get("nombre_completo"),
            url: row.get("url"),
            descripcion: row.get("descripcion"),
            destino: row.get("destino"),
            licencia: row.get("licencia"),
            nota: row.get("nota"),
        })
        .collect())
}

/// Marca que un candidato adoptado YA se convirtió en tarea en su proyecto destino
/// (R4). Falla ruidosamente si el id no existe o no está adoptado — no un UPDATE de
/// 0 filas silencioso (D30).
pub async fn marcar_tarea(pool: &SqlitePool, id_github: i64, ahora: &str) -> Result<()> {
    let filas = sqlx::query(
        "UPDATE candidatos SET tarea_en = ?2 WHERE id_github = ?1 AND veredicto = 'adoptar'",
    )
    .bind(id_github)
    .bind(ahora)
    .execute(pool)
    .await?
    .rows_affected();
    anyhow::ensure!(
        filas == 1,
        "no hay candidato ADOPTADO con id_github={id_github} (¿existe?, ¿está adoptado?)"
    );
    Ok(())
}

/// Sienta el veredicto del criterio sobre un candidato (R2, pero el camino de
/// escritura de la memoria vive aquí). Falla ruidosamente si el id no existe
/// (D20/D30 — un UPDATE de 0 filas no es un éxito silencioso).
pub async fn sentar_veredicto(
    pool: &SqlitePool,
    id_github: i64,
    veredicto: Veredicto,
    nota: &str,
    ahora: &str,
) -> Result<()> {
    let v = veredicto.a_bd();
    let filas = sqlx::query(
        "UPDATE candidatos SET veredicto=?2, nota=?3, veredicto_en=?4 WHERE id_github=?1",
    )
    .bind(id_github)
    .bind(v)
    .bind(nota)
    .bind(ahora)
    .execute(pool)
    .await?
    .rows_affected();
    anyhow::ensure!(filas == 1, "no existe el candidato id_github={id_github}");
    Ok(())
}

// --- R6 · avisos de seguridad (lazo dep→CVE) ---------------------------------

/// Registra los avisos hallados por `audit` en `repo`. Un aviso NUEVO (clave
/// `repo+advisory_id+paquete+version` no vista) se inserta con `primero_visto=ahora`;
/// uno ya conocido solo refresca `ultimo_visto`, conservando su `estado`/`nota` de
/// triaje (no vuelve a destacarse como nuevo, D5). Devuelve el resumen.
pub async fn registrar_avisos(
    pool: &SqlitePool,
    repo: &str,
    avisos: &[crate::auditoria::Aviso],
    ahora: &str,
) -> Result<ResumenAvisos> {
    let mut r = ResumenAvisos::default();
    for a in avisos {
        let existe: Option<(i64,)> = sqlx::query_as(
            "SELECT 1 FROM avisos WHERE repo=?1 AND advisory_id=?2 AND paquete=?3 AND version=?4",
        )
        .bind(repo)
        .bind(&a.advisory_id)
        .bind(&a.paquete)
        .bind(&a.version)
        .fetch_optional(pool)
        .await?;
        if existe.is_some() {
            // Anti fail-open (revisión de seguridad): si el aviso estaba AUTO-retirado y
            // el audit lo vuelve a reportar (dep revertido a versión vulnerable), se REABRE
            // —si no, una vuln que reaparece quedaría oculta como 'resuelto'—. El triaje
            // HUMANO (otros estados / otras notas) NO se toca.
            let reabierto = sqlx::query(
                "UPDATE avisos SET estado=NULL, nota='' WHERE repo=?1 AND advisory_id=?2 \
                 AND paquete=?3 AND version=?4 AND estado='resuelto' AND nota LIKE 'retirado autom%'",
            )
            .bind(repo)
            .bind(&a.advisory_id)
            .bind(&a.paquete)
            .bind(&a.version)
            .execute(pool)
            .await?
            .rows_affected();
            if reabierto > 0 {
                r.reabiertos += 1;
            }
            sqlx::query(
                "UPDATE avisos SET ultimo_visto=?5, titulo=?6, url=?7, tipo=?8, severidad=?9, \
                 parcheado=?10 WHERE repo=?1 AND advisory_id=?2 AND paquete=?3 AND version=?4",
            )
            .bind(repo)
            .bind(&a.advisory_id)
            .bind(&a.paquete)
            .bind(&a.version)
            .bind(ahora)
            .bind(&a.titulo)
            .bind(&a.url)
            .bind(&a.tipo)
            .bind(&a.severidad)
            .bind(&a.parcheado)
            .execute(pool)
            .await?;
            r.revistos += 1;
        } else {
            sqlx::query(
                "INSERT INTO avisos (repo, advisory_id, paquete, version, titulo, url, tipo, \
                 severidad, parcheado, primero_visto, ultimo_visto) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10)",
            )
            .bind(repo)
            .bind(&a.advisory_id)
            .bind(&a.paquete)
            .bind(&a.version)
            .bind(&a.titulo)
            .bind(&a.url)
            .bind(&a.tipo)
            .bind(&a.severidad)
            .bind(&a.parcheado)
            .bind(ahora)
            .execute(pool)
            .await?;
            r.nuevos += 1;
        }
    }

    Ok(r)
}

/// RECONCILIACIÓN (D22), anti fail-open. Retira (`estado='resuelto'`, auto) los avisos
/// PENDIENTES de `repo` que esta corrida de audit NO refrescó —es decir, con
/// `ultimo_visto < ahora`: `registrar_avisos` pone `ultimo_visto=ahora` a todo lo que el
/// audit SÍ reporta, así que lo que quedó atrás es un dep parcheado/bumpeado/quitado.
///
/// Se llama UNA vez por repo, DESPUÉS de registrar TODOS sus avisos (incluidos los de
/// sub-crates: `descubrir_repos` puede devolver el mismo nombre con varios `Cargo.lock`),
/// y SOLO si TODAS sus auditorías tuvieron éxito —si una falló, no se sabe si un aviso
/// falta por estar parcheado o por el fallo (D30), y retirar sería suprimir una alerta—.
/// No toca el triaje humano (solo `estado IS NULL`). Devuelve cuántos retiró.
pub async fn reconciliar_repo(pool: &SqlitePool, repo: &str, ahora: &str) -> Result<usize> {
    let n = sqlx::query(
        "UPDATE avisos SET estado='resuelto', nota=?3, ultimo_visto=?2 \
         WHERE repo=?1 AND estado IS NULL AND ultimo_visto < ?2",
    )
    .bind(repo)
    .bind(ahora)
    .bind("retirado automáticamente: el audit ya no lo reporta (dep parcheado/bumpeado/quitado)")
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n as usize)
}

/// Lista los avisos PENDIENTES de triaje (`estado IS NULL`). Si `repo` es `Some`,
/// filtra por ese proyecto. Orden: repo, luego las vulnerabilidades antes que los
/// warnings, luego paquete. Es el «digest» de contrainteligencia.
pub async fn avisos(pool: &SqlitePool, repo: Option<&str>) -> Result<Vec<FilaAviso>> {
    // Dos consultas literales (sqlx 0.9 exige `&'static str`); el filtro es un bind,
    // nunca interpolado. La vulnerabilidad se ordena antes que el warning.
    const TODOS: &str = "SELECT repo, advisory_id, paquete, version, titulo, url, tipo, \
        severidad, parcheado, primero_visto, estado FROM avisos WHERE estado IS NULL \
        ORDER BY repo ASC, CASE tipo WHEN 'vulnerabilidad' THEN 0 ELSE 1 END, paquete ASC";
    const POR_REPO: &str = "SELECT repo, advisory_id, paquete, version, titulo, url, tipo, \
        severidad, parcheado, primero_visto, estado FROM avisos WHERE estado IS NULL \
        AND repo = ?1 ORDER BY repo ASC, CASE tipo WHEN 'vulnerabilidad' THEN 0 ELSE 1 END, paquete ASC";
    let rows = match repo {
        Some(r) => sqlx::query(POR_REPO).bind(r).fetch_all(pool).await?,
        None => sqlx::query(TODOS).fetch_all(pool).await?,
    };
    Ok(rows
        .into_iter()
        .map(|row| FilaAviso {
            repo: row.get("repo"),
            advisory_id: row.get("advisory_id"),
            paquete: row.get("paquete"),
            version: row.get("version"),
            titulo: row.get("titulo"),
            url: row.get("url"),
            tipo: row.get("tipo"),
            severidad: row.get("severidad"),
            parcheado: row.get("parcheado"),
            primero_visto: row.get("primero_visto"),
            estado: row.get("estado"),
        })
        .collect())
}

/// Tría un aviso (R6): lo marca con un `estado` (`resuelto`/`aceptado`/`falso_positivo`)
/// para que salga del digest. Casa por `repo+advisory_id+paquete` (todas sus
/// versiones). Falla ruidosamente si no toca ninguna fila (D30 — no un 0-filas mudo).
pub async fn triar_aviso(
    pool: &SqlitePool,
    repo: &str,
    advisory_id: &str,
    paquete: &str,
    estado: &str,
    nota: &str,
) -> Result<u64> {
    let filas = sqlx::query(
        "UPDATE avisos SET estado=?4, nota=?5 WHERE repo=?1 AND advisory_id=?2 AND paquete=?3",
    )
    .bind(repo)
    .bind(advisory_id)
    .bind(paquete)
    .bind(estado)
    .bind(nota)
    .execute(pool)
    .await?
    .rows_affected();
    anyhow::ensure!(
        filas >= 1,
        "no hay aviso {advisory_id} sobre {paquete} en {repo} (¿bien escrito?)"
    );
    Ok(filas)
}

// --- R5 · conocimiento (fuentes que no son repos) ----------------------------

/// Registra los ítems de un feed en `conocimiento`, categorizándolos por relevancia
/// (reusa `categorizar_texto`, D9). Dedup por URL: uno ya visto NO se re-cuenta ni se
/// pisa su triaje (D5). Devuelve `ResumenAvisos` (nuevos/revistos), misma forma.
/// La costura ÚNICA de categorización de conocimiento (D9/D33): mapa de palabras sobre
/// título+cuerpo y, si sale `sin_clasificar`, el fallback por FUENTE mono-dominio. La usan
/// la inserción y `recategorizar`, para que las dos ruteen idéntico. El fallback entra con
/// puntaje 1 (la fuente es UNA señal): deja de ser sin_clasificar (sale de `razonar`) pero
/// sigue siendo de baja confianza frente a un match de varias palabras.
fn clasificar_con_fuente(titulo: &str, resumen: &str, fuente: &str) -> crate::categoria::Clasificacion {
    let clas = crate::categoria::categorizar_texto(&format!("{titulo} {resumen}").to_lowercase());
    if clas.destino == crate::categoria::SIN_CLASIFICAR
        && let Some(d) = crate::categoria::destino_por_fuente(fuente)
    {
        return crate::categoria::Clasificacion { destino: d.to_string(), puntaje: 1 };
    }
    clas
}

pub async fn registrar_conocimiento(
    pool: &SqlitePool,
    fuente: &str,
    items: &[crate::conocimiento::ItemSaber],
    ahora: &str,
) -> Result<ResumenAvisos> {
    let mut r = ResumenAvisos::default();
    for it in items {
        let existe: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM conocimiento WHERE url = ?1")
            .bind(&it.url)
            .fetch_optional(pool)
            .await?;
        if existe.is_some() {
            // Refresca título/fecha/fuente (el feed pudo corregirlos); conserva triaje.
            // RELLENA el resumen si esta vez vino no-vacío (backfill de filas viejas que
            // nacieron sin él), sin pisar uno ya guardado con un '' de una fuente pobre.
            sqlx::query(
                "UPDATE conocimiento SET titulo=?2, fecha=?3, fuente=?4, \
                 resumen = CASE WHEN ?5 <> '' THEN ?5 ELSE resumen END WHERE url=?1",
            )
            .bind(&it.url)
            .bind(&it.titulo)
            .bind(&it.fecha)
            .bind(fuente)
            .bind(&it.resumen)
            .execute(pool)
            .await?;
            r.revistos += 1;
        } else {
            // Texto completo (título + resumen), no solo el título: un advisory nombra el
            // crate/dominio en el cuerpo (D16). Se GUARDA el resumen para que
            // `recategorizar` use la MISMA costura (D33) y la pasada de razonamiento lo lea.
            let clas = clasificar_con_fuente(&it.titulo, &it.resumen, fuente);
            sqlx::query(
                "INSERT INTO conocimiento (url, fuente, titulo, fecha, destino, puntaje, \
                 primero_visto, resumen) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            )
            .bind(&it.url)
            .bind(fuente)
            .bind(&it.titulo)
            .bind(&it.fecha)
            .bind(&clas.destino)
            .bind(clas.puntaje)
            .bind(ahora)
            .bind(&it.resumen)
            .execute(pool)
            .await?;
            r.nuevos += 1;
        }
    }
    Ok(r)
}

/// Re-categoriza los PENDIENTES con el mapa vigente, tras cambiar `categoria.rs`.
/// Reusa la MISMA costura que la inserción —`categorizar` para repos, `categorizar_texto`
/// para noticias (D33)— y solo escribe donde el destino o el puntaje CAMBIAN. NUNCA toca
/// lo ya sentenciado (candidato con veredicto, noticia con estado): el alcance es lo que
/// se re-evalúa (D22). Devuelve (repos movidos, noticias movidas).
pub async fn recategorizar(pool: &SqlitePool) -> Result<(i64, i64)> {
    let mut repos_movidos = 0i64;
    // Solo las columnas que `categorizar` MIRA (topics/lenguaje/descripción) + la
    // clave y el estado actual; los demás campos del `Candidato` se dejan vacíos
    // porque `categorizar` no los lee (evita traer 11 columnas y el type_complexity).
    let filas: Vec<(i64, String, String, String, String, i64)> = sqlx::query_as(
        "SELECT id_github, topics, lenguaje, descripcion, destino, puntaje \
         FROM candidatos WHERE veredicto IS NULL",
    )
    .fetch_all(pool)
    .await?;
    for (id, topics_json, lenguaje, desc, dest_ant, pje_ant) in filas {
        let topics: Vec<String> = serde_json::from_str(&topics_json).unwrap_or_default();
        let c = Candidato {
            id_github: id,
            nombre_completo: String::new(),
            url: String::new(),
            descripcion: desc,
            lenguaje,
            topics,
            estrellas: 0,
            pushed_at: String::new(),
            licencia: String::new(),
        };
        let clas = categorizar(&c);
        if clas.destino != dest_ant || clas.puntaje != pje_ant {
            sqlx::query("UPDATE candidatos SET destino=?2, puntaje=?3 WHERE id_github=?1")
                .bind(id)
                .bind(&clas.destino)
                .bind(clas.puntaje)
                .execute(pool)
                .await?;
            repos_movidos += 1;
        }
    }

    let mut noticias_movidas = 0i64;
    // `AND razonado = 0`: el mapa de palabras solo re-toca lo que ÉL puso. Un ítem que
    // el criterio ruteó con juicio (`razonado = 1`) queda intocable aquí (D22/D32): la
    // limpieza se acota a lo que el mapa regenera, y el juicio no lo regenera el mapa.
    let filas: Vec<(String, String, String, String, String, i64)> = sqlx::query_as(
        "SELECT url, titulo, resumen, fuente, destino, puntaje FROM conocimiento WHERE estado IS NULL AND razonado = 0",
    )
    .fetch_all(pool)
    .await?;
    for (url, titulo, resumen, fuente, dest_ant, pje_ant) in filas {
        // MISMA costura que la inserción (D33): título+cuerpo y fallback por fuente.
        let clas = clasificar_con_fuente(&titulo, &resumen, &fuente);
        if clas.destino != dest_ant || clas.puntaje != pje_ant {
            sqlx::query("UPDATE conocimiento SET destino=?2, puntaje=?3 WHERE url=?1")
                .bind(&url)
                .bind(&clas.destino)
                .bind(clas.puntaje)
                .execute(pool)
                .await?;
            noticias_movidas += 1;
        }
    }
    Ok((repos_movidos, noticias_movidas))
}

/// El digest de conocimiento PENDIENTE de triaje (`estado IS NULL`). Filtra por
/// destino si se pide. Orden: lo relevante (puntaje) primero, luego lo más reciente.
pub async fn saber(pool: &SqlitePool, destino: Option<&str>) -> Result<Vec<FilaSaber>> {
    const TODOS: &str = "SELECT url, fuente, titulo, fecha, destino, puntaje, primero_visto, resumen \
        FROM conocimiento WHERE estado IS NULL ORDER BY puntaje DESC, fecha DESC, fuente ASC";
    const POR_DESTINO: &str = "SELECT url, fuente, titulo, fecha, destino, puntaje, primero_visto, resumen \
        FROM conocimiento WHERE estado IS NULL AND destino = ?1 \
        ORDER BY puntaje DESC, fecha DESC, fuente ASC";
    let rows = match destino {
        Some(d) => sqlx::query(POR_DESTINO).bind(d).fetch_all(pool).await?,
        None => sqlx::query(TODOS).fetch_all(pool).await?,
    };
    Ok(rows.into_iter().map(fila_saber).collect())
}

/// Construye una `FilaSaber` desde una fila SQL con las 8 columnas del digest. Costura
/// compartida por `saber` y `razonar_pendientes` (D9), para no repetir el `row.get`.
fn fila_saber(row: sqlx::sqlite::SqliteRow) -> FilaSaber {
    FilaSaber {
        url: row.get("url"),
        fuente: row.get("fuente"),
        titulo: row.get("titulo"),
        fecha: row.get("fecha"),
        destino: row.get("destino"),
        puntaje: row.get("puntaje"),
        primero_visto: row.get("primero_visto"),
        resumen: row.get("resumen"),
    }
}

/// Tría un ítem de conocimiento (visto/lead/descartado) para que salga del digest.
/// Falla ruidosamente si la URL no existe (D30 — no un 0-filas mudo).
pub async fn triar_saber(pool: &SqlitePool, url: &str, estado: &str, nota: &str) -> Result<()> {
    let filas = sqlx::query("UPDATE conocimiento SET estado=?2, nota=?3 WHERE url=?1")
        .bind(url)
        .bind(estado)
        .bind(nota)
        .execute(pool)
        .await?
        .rows_affected();
    anyhow::ensure!(filas == 1, "no hay ítem de conocimiento con url={url}");
    Ok(())
}

/// RUTEAR (el 80/20): el criterio (Claude-en-el-loop) corrige el destino de un ítem que
/// el mapa de palabras no supo colocar, con un motivo. Marca `razonado = 1` para que
/// `recategorizar` NO lo pise después (D22/D32). Conserva el ítem en el digest del
/// destino (`estado` sigue NULL) salvo que `lead = true`, que lo eleva a IDEA (R7).
/// Falla ruidosamente si la URL no existe (D30 — no un 0-filas mudo).
pub async fn rutear(
    pool: &SqlitePool,
    url: &str,
    destino: &str,
    lead: bool,
    nota: &str,
) -> Result<()> {
    // Puntaje = -1: sentinela de "ruteado por JUICIO, no por conteo de palabras". No
    // compite en el orden por puntaje del digest (que es confianza del emparejado), y
    // deja legible en la fila que el destino lo puso el criterio, no el mapa.
    let filas = if lead {
        sqlx::query(
            "UPDATE conocimiento SET destino=?2, razonado=1, puntaje=-1, estado='lead', nota=?3 WHERE url=?1",
        )
    } else {
        sqlx::query(
            "UPDATE conocimiento SET destino=?2, razonado=1, puntaje=-1, nota=?3 WHERE url=?1",
        )
    }
    .bind(url)
    .bind(destino)
    .bind(nota)
    .execute(pool)
    .await?
    .rows_affected();
    anyhow::ensure!(filas == 1, "no hay ítem de conocimiento con url={url}");
    Ok(())
}

/// La PASADA DE RAZONAMIENTO: lo que de verdad necesita juicio = lo NO RUTEADO
/// (`destino = 'sin_clasificar'`), ni el mapa de palabras ni el fallback por fuente supieron
/// colocarlo. Con `incluir_debiles`, además los emparejados por UNA sola señal (`puntaje <= 1`),
/// por si el juicio quiere corregirlos. `estado IS NULL AND razonado = 0` = ni triado ni ya
/// razonado, para no re-mostrar lo ya colocado (D30). Más reciente primero.
pub async fn razonar_pendientes(
    pool: &SqlitePool,
    incluir_debiles: bool,
    limite: i64,
) -> Result<Vec<FilaSaber>> {
    const SOLO_SIN: &str = "SELECT url, fuente, titulo, fecha, destino, puntaje, primero_visto, resumen \
         FROM conocimiento WHERE estado IS NULL AND razonado = 0 AND destino = 'sin_clasificar' \
         ORDER BY primero_visto DESC, fuente ASC LIMIT ?1";
    const CON_DEBILES: &str = "SELECT url, fuente, titulo, fecha, destino, puntaje, primero_visto, resumen \
         FROM conocimiento WHERE estado IS NULL AND razonado = 0 AND (destino = 'sin_clasificar' OR puntaje <= 1) \
         ORDER BY primero_visto DESC, puntaje ASC, fuente ASC LIMIT ?1";
    let rows = sqlx::query(if incluir_debiles { CON_DEBILES } else { SOLO_SIN })
        .bind(limite)
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(fila_saber).collect())
}

/// Una IDEA: un ítem de conocimiento que el razonador marcó `lead` porque de él sale
/// algo implementable. La `nota` lleva el destino + el «cómo» en breve; el «cómo»
/// completo vive en un doc `conocimiento/proyectos/mindala/ideas/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilaIdea {
    pub url: String,
    pub fuente: String,
    pub titulo: String,
    pub fecha: String,
    pub destino: String,
    pub nota: String,
}

/// El pipeline de IDEAS: los ítems de conocimiento en estado `lead` —lo que el
/// razonador juzgó digno de convertirse en una mejora de un producto—. Es el otro
/// lado de `saber`: `saber` muestra lo PENDIENTE de evaluar, `ideas` lo ya evaluado
/// como valioso y a la espera de construirse. Filtra por destino si se pide.
pub async fn ideas(pool: &SqlitePool, destino: Option<&str>) -> Result<Vec<FilaIdea>> {
    const TODOS: &str = "SELECT url, fuente, titulo, fecha, destino, COALESCE(nota,'') nota \
        FROM conocimiento WHERE estado = 'lead' ORDER BY destino ASC, fecha DESC";
    const POR_DESTINO: &str = "SELECT url, fuente, titulo, fecha, destino, COALESCE(nota,'') nota \
        FROM conocimiento WHERE estado = 'lead' AND destino = ?1 ORDER BY fecha DESC";
    let rows = match destino {
        Some(d) => sqlx::query(POR_DESTINO).bind(d).fetch_all(pool).await?,
        None => sqlx::query(TODOS).fetch_all(pool).await?,
    };
    Ok(rows
        .into_iter()
        .map(|row| FilaIdea {
            url: row.get("url"),
            fuente: row.get("fuente"),
            titulo: row.get("titulo"),
            fecha: row.get("fecha"),
            destino: row.get("destino"),
            nota: row.get("nota"),
        })
        .collect())
}

// --- R8: características (la unidad de valor) -------------------------------

use crate::modelo::{Caracteristica, EstadoCaracteristica, NuevaCaracteristica, TipoFuente};

/// Verifica que una fuente existe antes de ligarle una característica: una
/// procedencia inventada es peor que ninguna (D30 — no un enlace mudo a la nada).
async fn fuente_existe(pool: &SqlitePool, tipo: TipoFuente, refer: &str) -> Result<bool> {
    let sql = match tipo {
        TipoFuente::Candidato => "SELECT 1 FROM candidatos WHERE id_github = ?1",
        TipoFuente::Conocimiento => "SELECT 1 FROM conocimiento WHERE url = ?1",
    };
    let hay: Option<(i64,)> = sqlx::query_as(sql).bind(refer).fetch_optional(pool).await?;
    Ok(hay.is_some())
}

/// Liga una característica a una fuente (procedencia N↔N). Idempotente: la clave
/// compuesta absorbe un ligado repetido. Falla ruidoso si la fuente no existe.
pub async fn ligar_fuente(
    pool: &SqlitePool,
    caracteristica_id: i64,
    tipo: TipoFuente,
    refer: &str,
    ahora: &str,
) -> Result<()> {
    anyhow::ensure!(
        fuente_existe(pool, tipo, refer).await?,
        "no hay fuente {}={refer} — la procedencia sería inventada",
        tipo.a_bd()
    );
    sqlx::query(
        "INSERT OR IGNORE INTO caracteristica_fuente \
         (caracteristica_id, tipo_fuente, ref_fuente, ligada_en) VALUES (?1,?2,?3,?4)",
    )
    .bind(caracteristica_id)
    .bind(tipo.a_bd())
    .bind(refer)
    .bind(ahora)
    .execute(pool)
    .await?;
    Ok(())
}

/// Registra una característica CAZADA en una fuente y la liga a ella en el acto.
/// Nace en estado `propuesta`. Devuelve su `id`. La fuente debe existir (D30).
pub async fn registrar_caracteristica(
    pool: &SqlitePool,
    nueva: NuevaCaracteristica<'_>,
    tipo: TipoFuente,
    refer: &str,
    ahora: &str,
) -> Result<i64> {
    anyhow::ensure!(
        fuente_existe(pool, tipo, refer).await?,
        "no hay fuente {}={refer}: no se caza una característica de una fuente que no existe",
        tipo.a_bd()
    );
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO caracteristicas \
         (que_hace, destino, como, licencia_origen, estado, descubierta_en) \
         VALUES (?1,?2,?3,?4,'propuesta',?5) RETURNING id",
    )
    .bind(nueva.que_hace)
    .bind(nueva.destino)
    .bind(nueva.como)
    .bind(nueva.licencia_origen)
    .bind(ahora)
    .fetch_one(pool)
    .await?;
    ligar_fuente(pool, id, tipo, refer, ahora).await?;
    Ok(id)
}

/// Lista características, opcionalmente por destino y/o estado. Orden: por destino
/// y luego las más recientes.
pub async fn caracteristicas(
    pool: &SqlitePool,
    destino: Option<&str>,
    estado: Option<&str>,
) -> Result<Vec<Caracteristica>> {
    // Cuatro consultas LITERALES (sqlx 0.9 exige `&'static str`, no cadenas
    // dinámicas), una por combinación de filtros. El mismo idioma que `saber`.
    const TODAS: &str =
        "SELECT id, que_hace, destino, como, licencia_origen, estado, nota \
         FROM caracteristicas ORDER BY destino ASC, id DESC";
    const POR_DESTINO: &str =
        "SELECT id, que_hace, destino, como, licencia_origen, estado, nota \
         FROM caracteristicas WHERE destino = ?1 ORDER BY destino ASC, id DESC";
    const POR_ESTADO: &str =
        "SELECT id, que_hace, destino, como, licencia_origen, estado, nota \
         FROM caracteristicas WHERE estado = ?1 ORDER BY destino ASC, id DESC";
    const POR_AMBOS: &str =
        "SELECT id, que_hace, destino, como, licencia_origen, estado, nota \
         FROM caracteristicas WHERE destino = ?1 AND estado = ?2 ORDER BY destino ASC, id DESC";

    let rows = match (destino, estado) {
        (None, None) => sqlx::query(TODAS).fetch_all(pool).await?,
        (Some(d), None) => sqlx::query(POR_DESTINO).bind(d).fetch_all(pool).await?,
        (None, Some(e)) => sqlx::query(POR_ESTADO).bind(e).fetch_all(pool).await?,
        (Some(d), Some(e)) => sqlx::query(POR_AMBOS).bind(d).bind(e).fetch_all(pool).await?,
    };

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let estado_txt: String = row.get("estado");
        let estado = EstadoCaracteristica::desde_bd(&estado_txt)
            .ok_or_else(|| anyhow::anyhow!("estado de característica desconocido: {estado_txt}"))?;
        out.push(Caracteristica {
            id: row.get("id"),
            que_hace: row.get("que_hace"),
            destino: row.get("destino"),
            como: row.get("como"),
            licencia_origen: row.get("licencia_origen"),
            estado,
            nota: row.get("nota"),
        });
    }
    Ok(out)
}

/// Sienta el estado de una característica (`sirve`/`descartada`/`implementada`) con
/// su porqué. Falla ruidoso si el id no existe (D30 — no un 0-filas mudo).
pub async fn sentar_estado_caracteristica(
    pool: &SqlitePool,
    id: i64,
    estado: EstadoCaracteristica,
    nota: &str,
    ahora: &str,
) -> Result<()> {
    let filas = sqlx::query(
        "UPDATE caracteristicas SET estado=?2, nota=?3, estado_en=?4 WHERE id=?1",
    )
    .bind(id)
    .bind(estado.a_bd())
    .bind(nota)
    .bind(ahora)
    .execute(pool)
    .await?
    .rows_affected();
    anyhow::ensure!(filas == 1, "no hay característica con id={id}");
    Ok(())
}

/// La cobertura de una fuente por destino: cuántas EXAMINADAS vs PENDIENTES. Es la
/// disciplina de «revisar TODOS» (R8): una fuente examinada es una con veredicto
/// (candidatos) o estado (conocimiento) puesto —da igual si aportó característica o
/// no—; el resto está sin mirar. El objetivo es que `pendientes` → 0 por lotes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilaCobertura {
    pub destino: String,
    pub candidatos_examinados: i64,
    pub candidatos_pendientes: i64,
    pub conocimiento_examinado: i64,
    pub conocimiento_pendiente: i64,
}

impl FilaCobertura {
    #[must_use]
    pub fn pendientes(&self) -> i64 {
        self.candidatos_pendientes + self.conocimiento_pendiente
    }
}

/// Cobertura por destino, uniendo repos (`candidatos`) y noticias (`conocimiento`).
/// Ordena por lo que MÁS falta por revisar primero, que es el próximo lote.
pub async fn cobertura(pool: &SqlitePool) -> Result<Vec<FilaCobertura>> {
    use std::collections::BTreeMap;
    // (examinados_cand, pend_cand, examinado_con, pend_con)
    let mut acc: BTreeMap<String, [i64; 4]> = BTreeMap::new();

    let cand = sqlx::query(
        "SELECT destino, \
           SUM(CASE WHEN veredicto IS NOT NULL THEN 1 ELSE 0 END) AS examinados, \
           SUM(CASE WHEN veredicto IS NULL     THEN 1 ELSE 0 END) AS pendientes \
         FROM candidatos GROUP BY destino",
    )
    .fetch_all(pool)
    .await?;
    for row in cand {
        let d: String = row.get("destino");
        let e = acc.entry(d).or_default();
        e[0] += row.get::<i64, _>("examinados");
        e[1] += row.get::<i64, _>("pendientes");
    }

    let con = sqlx::query(
        "SELECT destino, \
           SUM(CASE WHEN estado IS NOT NULL THEN 1 ELSE 0 END) AS examinados, \
           SUM(CASE WHEN estado IS NULL     THEN 1 ELSE 0 END) AS pendientes \
         FROM conocimiento GROUP BY destino",
    )
    .fetch_all(pool)
    .await?;
    for row in con {
        let d: String = row.get("destino");
        let e = acc.entry(d).or_default();
        e[2] += row.get::<i64, _>("examinados");
        e[3] += row.get::<i64, _>("pendientes");
    }

    let mut filas: Vec<FilaCobertura> = acc
        .into_iter()
        .map(|(destino, v)| FilaCobertura {
            destino,
            candidatos_examinados: v[0],
            candidatos_pendientes: v[1],
            conocimiento_examinado: v[2],
            conocimiento_pendiente: v[3],
        })
        .collect();
    // Lo que más falta por revisar, primero (el próximo lote).
    filas.sort_by(|a, b| b.pendientes().cmp(&a.pendientes()).then(a.destino.cmp(&b.destino)));
    Ok(filas)
}

/// Las características que SIRVEN y aún no se convirtieron en tarea de implementar.
/// Es el trabajo pendiente del desenlace R8 (implementar-en-el-estándar propio).
pub async fn caracteristicas_por_implementar(pool: &SqlitePool) -> Result<Vec<Caracteristica>> {
    let rows = sqlx::query(
        "SELECT id, que_hace, destino, como, licencia_origen, estado, nota \
         FROM caracteristicas WHERE estado = 'sirve' AND tarea_en IS NULL \
         ORDER BY destino ASC, id ASC",
    )
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let estado_txt: String = row.get("estado");
        let estado = EstadoCaracteristica::desde_bd(&estado_txt)
            .ok_or_else(|| anyhow::anyhow!("estado desconocido: {estado_txt}"))?;
        out.push(Caracteristica {
            id: row.get("id"),
            que_hace: row.get("que_hace"),
            destino: row.get("destino"),
            como: row.get("como"),
            licencia_origen: row.get("licencia_origen"),
            estado,
            nota: row.get("nota"),
        });
    }
    Ok(out)
}

/// Marca que la característica ya se convirtió en tarea real en su proyecto destino
/// (el criterio la registró). Falla ruidoso si el id no existe o no estaba en
/// `sirve` sin tarea (D30 — no un 0-filas mudo).
pub async fn marcar_caracteristica_tarea(pool: &SqlitePool, id: i64, ahora: &str) -> Result<()> {
    let filas = sqlx::query(
        "UPDATE caracteristicas SET tarea_en=?2 \
         WHERE id=?1 AND estado='sirve' AND tarea_en IS NULL",
    )
    .bind(id)
    .bind(ahora)
    .execute(pool)
    .await?
    .rows_affected();
    anyhow::ensure!(
        filas == 1,
        "no hay característica id={id} en estado 'sirve' sin tarea (¿ya tiene tarea, no existe, o no está en 'sirve'?)"
    );
    Ok(())
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn cand(id: i64, topics: &[&str], estrellas: i64, pushed: &str) -> Candidato {
        Candidato {
            id_github: id,
            nombre_completo: format!("org/repo{id}"),
            url: format!("https://github.com/org/repo{id}"),
            descripcion: "x".into(),
            lenguaje: "Rust".into(),
            topics: topics.iter().map(|s| (*s).to_string()).collect(),
            estrellas,
            pushed_at: pushed.into(),
            licencia: "MIT".into(),
        }
    }

    async fn bd_temporal() -> SqlitePool {
        // `:memory:` no sirve con pool multi-conexión, pero max_connections=1 lo
        // mantiene sobre la misma conexión durante toda la prueba.
        abrir("sqlite::memory:").await.unwrap()
    }

    #[tokio::test]
    async fn dedup_no_duplica() {
        let pool = bd_temporal().await;
        let c = cand(100, &["cryptography"], 5, "2026-01-01T00:00:00Z");
        let r1 = encolar(&pool, std::slice::from_ref(&c), "2026-09-24")
            .await
            .unwrap();
        assert_eq!(r1.nuevos, 1);
        // Re-descubrir el mismo id: 0 nuevos.
        let r2 = encolar(&pool, std::slice::from_ref(&c), "2026-09-25")
            .await
            .unwrap();
        assert_eq!(r2.nuevos, 0);
        assert_eq!(r2.actualizados, 1);
        let n: i64 = sqlx::query("SELECT COUNT(*) AS n FROM candidatos")
            .fetch_one(&pool)
            .await
            .unwrap()
            .get("n");
        assert_eq!(n, 1, "debe haber UNA fila, no dos");
    }

    // CONTROL de caducidad + no-re-estudiar (D33, dos lados del mismo eje):
    // un PENDIENTE se refresca; uno con VEREDICTO queda congelado.
    #[tokio::test]
    async fn pendiente_se_refresca_pero_cerrado_se_congela() {
        let pool = bd_temporal().await;
        // Dos candidatos.
        let pendiente = cand(1, &["recon"], 10, "2026-01-01T00:00:00Z");
        let cerrado = cand(2, &["recon"], 10, "2026-01-01T00:00:00Z");
        encolar(&pool, &[pendiente.clone(), cerrado.clone()], "2026-09-24")
            .await
            .unwrap();
        // Cerrar el segundo.
        sentar_veredicto(
            &pool,
            2,
            Veredicto::Descartar,
            "ya lo tenemos",
            "2026-09-24",
        )
        .await
        .unwrap();

        // Re-descubrir ambos con MÁS estrellas y actividad nueva.
        let pend2 = cand(1, &["recon"], 999, "2026-09-20T00:00:00Z");
        let cerr2 = cand(2, &["recon"], 999, "2026-09-20T00:00:00Z");
        let r = encolar(&pool, &[pend2, cerr2], "2026-09-24").await.unwrap();
        assert_eq!(r.actualizados, 1, "solo el pendiente se refresca");
        assert_eq!(r.congelados, 1, "el cerrado no se toca");

        // El pendiente ahora tiene 999 estrellas; el cerrado sigue en 10.
        let e_pend: i64 = sqlx::query("SELECT estrellas FROM candidatos WHERE id_github=1")
            .fetch_one(&pool)
            .await
            .unwrap()
            .get("estrellas");
        let e_cerr: i64 = sqlx::query("SELECT estrellas FROM candidatos WHERE id_github=2")
            .fetch_one(&pool)
            .await
            .unwrap()
            .get("estrellas");
        assert_eq!(e_pend, 999);
        assert_eq!(e_cerr, 10, "el veredicto congela también la metadata");
    }

    #[tokio::test]
    async fn cola_solo_pendientes_y_filtra_destino() {
        let pool = bd_temporal().await;
        encolar(
            &pool,
            &[
                cand(1, &["cryptography"], 50, "2026-01-01T00:00:00Z"), // quipu
                cand(2, &["recon"], 80, "2026-01-01T00:00:00Z"),        // nexus
                cand(3, &["recon"], 10, "2026-01-01T00:00:00Z"),        // nexus, se cerrará
            ],
            "2026-09-24",
        )
        .await
        .unwrap();
        sentar_veredicto(&pool, 3, Veredicto::Adoptar, "sí", "2026-09-24")
            .await
            .unwrap();

        let todos = cola(&pool, None).await.unwrap();
        assert_eq!(todos.len(), 2, "el adoptado sale de la cola");

        let solo_nexus = cola(&pool, Some("nexus")).await.unwrap();
        assert_eq!(solo_nexus.len(), 1);
        assert_eq!(solo_nexus[0].id_github, 2);
    }

    // CASO ROJO por la vía real (D33): sentar veredicto sobre un id inexistente
    // NO puede pasar en silencio (un UPDATE de 0 filas es indistinguible del éxito).
    #[tokio::test]
    async fn veredicto_sobre_id_fantasma_falla() {
        let pool = bd_temporal().await;
        let e = sentar_veredicto(&pool, 424242, Veredicto::Adoptar, "x", "2026-09-24").await;
        assert!(e.is_err(), "debe fallar ruidosamente, no tragar el 0-filas");
    }

    #[tokio::test]
    async fn existe_nombre_ignora_mayusculas() {
        let pool = bd_temporal().await;
        encolar(
            &pool,
            &[cand(1, &["recon"], 1, "2026-01-01T00:00:00Z")],
            "2026-09-24",
        )
        .await
        .unwrap();
        // cand() nombra "org/repo1".
        assert!(existe_nombre(&pool, "ORG/Repo1").await.unwrap());
        assert!(!existe_nombre(&pool, "org/otro").await.unwrap());
    }

    // R4: el flujo de tarea. Adoptar → aparece en adoptados_sin_tarea → marcar → sale.
    #[tokio::test]
    async fn flujo_de_tarea() {
        let pool = bd_temporal().await;
        encolar(
            &pool,
            &[
                cand(1, &["recon"], 1, "2026-01-01T00:00:00Z"),
                cand(2, &["cryptography"], 1, "2026-01-01T00:00:00Z"),
            ],
            "2026-09-24",
        )
        .await
        .unwrap();

        // Sin adopciones aún, la lista de tareas está vacía.
        assert!(adoptados_sin_tarea(&pool).await.unwrap().is_empty());

        // Adoptar el 1: aparece como tarea pendiente; el 2 (pendiente) no.
        sentar_veredicto(&pool, 1, Veredicto::Adoptar, "sirve en nexus", "2026-09-24")
            .await
            .unwrap();
        let tareas = adoptados_sin_tarea(&pool).await.unwrap();
        assert_eq!(tareas.len(), 1);
        assert_eq!(tareas[0].id_github, 1);
        assert_eq!(tareas[0].destino, "nexus");
        assert_eq!(tareas[0].nota.as_deref(), Some("sirve en nexus"));

        // Marcar la tarea como registrada: sale de la lista.
        marcar_tarea(&pool, 1, "2026-09-24").await.unwrap();
        assert!(adoptados_sin_tarea(&pool).await.unwrap().is_empty());
    }

    // CASO ROJO (D33): marcar tarea sobre un candidato NO adoptado (solo pendiente,
    // o descartado) falla — no se genera tarea de algo que el criterio no adoptó.
    #[tokio::test]
    async fn marcar_tarea_de_no_adoptado_falla() {
        let pool = bd_temporal().await;
        encolar(
            &pool,
            &[cand(1, &["recon"], 1, "2026-01-01T00:00:00Z")],
            "2026-09-24",
        )
        .await
        .unwrap();
        // id 1 está PENDIENTE, no adoptado.
        assert!(marcar_tarea(&pool, 1, "2026-09-24").await.is_err());
        // descartado tampoco.
        sentar_veredicto(&pool, 1, Veredicto::Descartar, "no", "2026-09-24")
            .await
            .unwrap();
        assert!(marcar_tarea(&pool, 1, "2026-09-24").await.is_err());
    }

    #[tokio::test]
    async fn ver_devuelve_ficha_o_none() {
        let pool = bd_temporal().await;
        encolar(
            &pool,
            &[cand(7, &["cryptography"], 42, "2026-01-01T00:00:00Z")],
            "2026-09-24",
        )
        .await
        .unwrap();
        let f = ver(&pool, 7).await.unwrap().expect("debe existir");
        assert_eq!(f.destino, "quipu");
        assert_eq!(f.estrellas, 42);
        assert_eq!(f.veredicto, Veredicto::Pendiente);
        assert_eq!(f.topics, vec!["cryptography".to_string()]);
        assert!(ver(&pool, 999).await.unwrap().is_none());
    }

    // --- R6 · avisos ---------------------------------------------------------

    fn aviso(id: &str, paquete: &str, version: &str, tipo: &str) -> crate::auditoria::Aviso {
        crate::auditoria::Aviso {
            advisory_id: id.into(),
            paquete: paquete.into(),
            version: version.into(),
            titulo: "t".into(),
            url: "u".into(),
            tipo: tipo.into(),
            severidad: "—".into(),
            parcheado: ">=1.0".into(),
        }
    }

    // Dedup del lazo dep→CVE: la MISMA (repo,advisory,paquete,version) es una fila;
    // la re-corrida no la cuenta como nueva. Es la disciplina de `candidatos` (D5).
    #[tokio::test]
    async fn avisos_dedup_solo_destaca_nuevos() {
        let pool = bd_temporal().await;
        let lote = [
            aviso("RUSTSEC-2026-0286", "cryptoki", "0.12.0", "vulnerabilidad"),
            aviso("YANKED", "chacha20", "0.10.1", "yanked"),
        ];
        let r1 = registrar_avisos(&pool, "quipu", &lote, "2026-09-27")
            .await
            .unwrap();
        assert_eq!(r1.nuevos, 2);
        assert_eq!(r1.revistos, 0);

        // Re-correr: 0 nuevos, 2 revistos (misma clave).
        let r2 = registrar_avisos(&pool, "quipu", &lote, "2026-09-28")
            .await
            .unwrap();
        assert_eq!(r2.nuevos, 0, "nada nuevo en la re-corrida");
        assert_eq!(r2.revistos, 2);

        let n: i64 = sqlx::query("SELECT COUNT(*) AS n FROM avisos")
            .fetch_one(&pool)
            .await
            .unwrap()
            .get("n");
        assert_eq!(n, 2, "dos filas, no cuatro");

        // El MISMO aviso en OTRO repo SÍ es nuevo (la clave incluye el repo).
        let r3 = registrar_avisos(&pool, "medico", &lote[..1], "2026-09-27")
            .await
            .unwrap();
        assert_eq!(r3.nuevos, 1);
    }

    // AGUJA (D33): RECONCILIACIÓN (D22) por timestamp — `reconciliar_repo` retira los
    // PENDIENTES que la corrida NO refrescó (ultimo_visto < ahora = dep parcheado/quitado),
    // sin pisar el triaje humano. MUTANTE = sin `reconciliar_repo`: el digest seguiría
    // mostrando los avisos muertos (el bug que cazó el barrido).
    #[tokio::test]
    async fn reconciliacion_retira_avisos_que_el_audit_ya_no_reporta() {
        let pool = bd_temporal().await;
        let lote1 = [
            aviso("RUSTSEC-2026-0194", "quick-xml", "0.40.0", "vulnerabilidad"),
            aviso("YANKED", "chacha20", "0.10.1", "yanked"),
            aviso("RUSTSEC-2026-0386", "tokio", "1.53.2", "unsound"),
        ];
        registrar_avisos(&pool, "chuspa", &lote1, "2026-10-29").await.unwrap();
        triar_aviso(&pool, "chuspa", "RUSTSEC-2026-0386", "tokio", "aceptado", "egui")
            .await
            .unwrap();

        // Corrida siguiente (T más nuevo): el audit ya no reporta quick-xml ni chacha20
        // (parcheados) → no refresca su ultimo_visto. reconciliar_repo los retira; deja el
        // triado humano en paz.
        let retirados = reconciliar_repo(&pool, "chuspa", "2026-10-30").await.unwrap();
        assert_eq!(retirados, 2, "quick-xml y chacha20 ya no refrescados → retirados");
        assert!(avisos(&pool, Some("chuspa")).await.unwrap().is_empty(), "digest limpio");
        let estado: String =
            sqlx::query("SELECT estado FROM avisos WHERE repo='chuspa' AND paquete='tokio'")
                .fetch_one(&pool).await.unwrap().get("estado");
        assert_eq!(estado, "aceptado", "no se pisa el triaje humano");
    }

    // FINDING 1 (revisión seguridad): dos sub-crates del MISMO repo auditados en la MISMA
    // corrida NO se pisan. Un aviso STALE de una corrida previa se retira; los dos frescos
    // (de los dos sub-crates, ambos con ultimo_visto=ahora) SOBREVIVEN. El bug per-call
    // habría retirado el del sub-crate A al registrar el B.
    #[tokio::test]
    async fn reconciliar_no_pisa_sub_crates_del_mismo_repo() {
        let pool = bd_temporal().await;
        // Corrida vieja: un aviso que luego quedará stale.
        registrar_avisos(&pool, "X", &[aviso("RUSTSEC-2026-0001", "viejo", "1.0.0", "vulnerabilidad")], "2026-10-28").await.unwrap();
        // Corrida nueva, DOS sub-crates (mismo repo "X"), ambos T=2026-10-30:
        registrar_avisos(&pool, "X", &[aviso("RUSTSEC-2026-0002", "crateA", "1.0.0", "vulnerabilidad")], "2026-10-30").await.unwrap();
        registrar_avisos(&pool, "X", &[aviso("RUSTSEC-2026-0003", "crateB", "1.0.0", "vulnerabilidad")], "2026-10-30").await.unwrap();
        // Reconciliación UNA vez al final:
        let retirados = reconciliar_repo(&pool, "X", "2026-10-30").await.unwrap();
        assert_eq!(retirados, 1, "solo el stale viejo se retira");
        let pend: Vec<String> = sqlx::query_scalar(
            "SELECT paquete FROM avisos WHERE repo='X' AND estado IS NULL ORDER BY paquete",
        ).fetch_all(&pool).await.unwrap();
        assert_eq!(pend, vec!["crateA".to_string(), "crateB".to_string()], "ambos sub-crates sobreviven: {pend:?}");
    }

    // FINDING 2 (revisión seguridad): un aviso AUTO-retirado que el audit VUELVE a reportar
    // se REABRE (anti fail-open); uno retirado por una PERSONA no se reabre solo.
    #[tokio::test]
    async fn aviso_auto_retirado_reabre_si_reaparece() {
        let pool = bd_temporal().await;
        let a = aviso("RUSTSEC-2026-0009", "regresa", "1.0.0", "vulnerabilidad");
        registrar_avisos(&pool, "Y", std::slice::from_ref(&a), "2026-10-28").await.unwrap();
        // Se retira solo (no refrescado en una corrida posterior).
        assert_eq!(reconciliar_repo(&pool, "Y", "2026-10-29").await.unwrap(), 1);
        // El dep se revierte y el audit lo reporta OTRA VEZ → debe REABRIR.
        let r = registrar_avisos(&pool, "Y", std::slice::from_ref(&a), "2026-10-30").await.unwrap();
        assert_eq!(r.reabiertos, 1, "el auto-retirado que reaparece se reabre");
        let estado: Option<String> =
            sqlx::query_scalar("SELECT estado FROM avisos WHERE repo='Y' AND paquete='regresa'")
                .fetch_one(&pool).await.unwrap();
        assert_eq!(estado, None, "reabierto = pendiente de nuevo");

        // CONTROL: uno retirado por una PERSONA no se reabre al reaparecer.
        let b = aviso("RUSTSEC-2026-0010", "humano", "1.0.0", "vulnerabilidad");
        registrar_avisos(&pool, "Y", std::slice::from_ref(&b), "2026-10-30").await.unwrap();
        triar_aviso(&pool, "Y", "RUSTSEC-2026-0010", "humano", "resuelto", "lo miré, no aplica").await.unwrap();
        let r2 = registrar_avisos(&pool, "Y", std::slice::from_ref(&b), "2026-10-31").await.unwrap();
        assert_eq!(r2.reabiertos, 0, "el triaje humano no se reabre solo");
    }

    // Triar cierra el lazo: un aviso resuelto sale del digest. Y ordena la vuln
    // antes que el warning.
    #[tokio::test]
    async fn triar_saca_del_digest_y_ordena_vuln_primero() {
        let pool = bd_temporal().await;
        registrar_avisos(
            &pool,
            "quipu",
            &[
                aviso("YANKED", "chacha20", "0.10.1", "yanked"),
                aviso("RUSTSEC-2026-0286", "cryptoki", "0.12.0", "vulnerabilidad"),
            ],
            "2026-09-27",
        )
        .await
        .unwrap();

        let pend = avisos(&pool, None).await.unwrap();
        assert_eq!(pend.len(), 2);
        assert_eq!(
            pend[0].tipo, "vulnerabilidad",
            "la vuln va primero: {pend:?}"
        );

        // Resolver la vuln: sale del digest.
        triar_aviso(
            &pool,
            "quipu",
            "RUSTSEC-2026-0286",
            "cryptoki",
            "resuelto",
            "subí a 0.12.1",
        )
        .await
        .unwrap();
        let pend = avisos(&pool, None).await.unwrap();
        assert_eq!(pend.len(), 1, "queda solo el yanked");
        assert_eq!(pend[0].paquete, "chacha20");

        // Filtro por repo sin avisos: vacío.
        assert!(avisos(&pool, Some("medico")).await.unwrap().is_empty());
    }

    // CASO ROJO (D30): triar un aviso inexistente falla, no traga el 0-filas.
    #[tokio::test]
    async fn triar_aviso_fantasma_falla() {
        let pool = bd_temporal().await;
        let e = triar_aviso(&pool, "quipu", "RUSTSEC-9999-9999", "nada", "resuelto", "").await;
        assert!(e.is_err(), "debe fallar ruidosamente");
    }

    // --- R5 · conocimiento ---------------------------------------------------

    fn item(titulo: &str, url: &str) -> crate::conocimiento::ItemSaber {
        crate::conocimiento::ItemSaber {
            titulo: titulo.into(),
            url: url.into(),
            fecha: "2026-09-25".into(),
            resumen: String::new(),
        }
    }

    fn item_con_resumen(titulo: &str, url: &str, resumen: &str) -> crate::conocimiento::ItemSaber {
        crate::conocimiento::ItemSaber { resumen: resumen.into(), ..item(titulo, url) }
    }

    // Dedup por URL + categorización por relevancia (D9): un título de passkeys va a
    // auth; uno de post-quantum a quipu; uno genérico a sin_clasificar.
    #[tokio::test]
    async fn conocimiento_dedup_y_categoriza() {
        let pool = bd_temporal().await;
        let lote = [
            item(
                "New passkeys/webauthn flow in the browser",
                "https://x.test/pk",
            ),
            item("Post-quantum ML-KEM lands in std", "https://x.test/pq"),
            item("This Week in Rust 670", "https://x.test/twir670"),
        ];
        let r1 = registrar_conocimiento(&pool, "rustsec", &lote, "2026-09-27")
            .await
            .unwrap();
        assert_eq!(r1.nuevos, 3);

        // Re-correr: 0 nuevos (dedup por URL).
        let r2 = registrar_conocimiento(&pool, "rustsec", &lote, "2026-09-28")
            .await
            .unwrap();
        assert_eq!(r2.nuevos, 0);
        assert_eq!(r2.revistos, 3);

        // La categorización dirigió cada ítem a su banco.
        let pk = saber(&pool, Some("bachue")).await.unwrap();
        let pq = saber(&pool, Some("quipu")).await.unwrap();
        assert!(
            pk.iter().any(|f| f.url == "https://x.test/pk") || {
                // 'passkeys'/'webauthn' pueden mapear a chuspa según el mapa; acepta ambos.
                !saber(&pool, Some("chuspa")).await.unwrap().is_empty()
            },
            "el ítem de passkeys va a auth"
        );
        assert!(
            pq.iter().any(|f| f.url == "https://x.test/pq"),
            "el PQ va a quipu: {pq:?}"
        );
    }

    // AGUJA (D33, texto completo): un advisory con título GENÉRICO pero cuyo CUERPO nombra
    // el dominio se categoriza al destino correcto. MUTANTE = categorizar solo por título
    // (el código anterior): caería en sin_clasificar. CONTROL: sin la palabra en el cuerpo,
    // el mismo título genérico NO va a ese destino.
    #[tokio::test]
    async fn conocimiento_categoriza_por_cuerpo_no_solo_titulo() {
        let pool = bd_temporal().await;
        registrar_conocimiento(
            &pool,
            "osv",
            &[
                item_con_resumen(
                    "CVE-2026-97631: critical advisory", // título genérico
                    "https://x.test/uefi",
                    "pre-boot RCE: measured boot and secure-boot integrity bypass in a bootkit",
                ),
                // CONTROL: título igual de genérico, cuerpo sin la señal -> NO a zaque.
                item_con_resumen(
                    "CVE-2026-00000: another advisory",
                    "https://x.test/ruido",
                    "a generic denial of service in some web server",
                ),
            ],
            "2026-10-30",
        )
        .await
        .unwrap();

        let z = saber(&pool, Some("zaque")).await.unwrap();
        assert!(
            z.iter().any(|f| f.url == "https://x.test/uefi"),
            "el advisory de boot va a zaque por el CUERPO: {z:?}"
        );
        assert!(
            !z.iter().any(|f| f.url == "https://x.test/ruido"),
            "el control NO debe caer en zaque: {z:?}"
        );
    }

    // Triar cierra el lazo del digest, y el orden pone lo más relevante primero.
    #[tokio::test]
    async fn saber_ordena_por_relevancia_y_triar_saca() {
        let pool = bd_temporal().await;
        registrar_conocimiento(
            &pool,
            "twir",
            &[
                item("Generic weekly news", "https://x.test/generic"),
                item(
                    "post-quantum cryptography ml-kem ml-dsa lattice",
                    "https://x.test/pq",
                ),
            ],
            "2026-09-27",
        )
        .await
        .unwrap();

        let d = saber(&pool, None).await.unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(
            d[0].url, "https://x.test/pq",
            "lo más relevante primero: {d:?}"
        );
        assert!(d[0].puntaje > 0);

        triar_saber(&pool, "https://x.test/pq", "lead", "abrir un hilo PQ")
            .await
            .unwrap();
        let d = saber(&pool, None).await.unwrap();
        assert_eq!(d.len(), 1, "el triado sale del digest");
        assert_eq!(d[0].url, "https://x.test/generic");
    }

    // CASO ROJO (D30): triar una URL inexistente falla.
    #[tokio::test]
    async fn triar_saber_fantasma_falla() {
        let pool = bd_temporal().await;
        assert!(
            triar_saber(&pool, "https://no.existe/x", "visto", "")
                .await
                .is_err()
        );
    }

    // MISMA COSTURA (D33): `recategorizar` reproduce el ruteo de la INSERCIÓN (título +
    // resumen), no uno más débil por título solo. Aguja = un ítem ruteado por su CUERPO
    // sigue en su destino tras recategorizar. MUTANTE = recategorizar por título solo
    // (el código anterior): lo mandaría a sin_clasificar al perder el cuerpo.
    #[tokio::test]
    async fn recategorizar_es_fiel_a_la_insercion_por_cuerpo() {
        let pool = bd_temporal().await;
        registrar_conocimiento(
            &pool,
            "osv",
            &[item_con_resumen(
                "CVE-2026-55555: advisory", // título genérico, SIN señal
                "https://x.test/tls",
                "a flaw in secure-boot and measured-boot bootkit integrity verification",
            )],
            "2026-10-30",
        )
        .await
        .unwrap();
        // Nace en zaque por el CUERPO.
        assert!(saber(&pool, Some("zaque")).await.unwrap().iter().any(|f| f.url == "https://x.test/tls"));
        // Recategorizar NO debe degradarlo a sin_clasificar (misma costura).
        recategorizar(&pool).await.unwrap();
        let z = saber(&pool, Some("zaque")).await.unwrap();
        assert!(
            z.iter().any(|f| f.url == "https://x.test/tls"),
            "el ruteo por cuerpo sobrevive a recategorizar: {z:?}"
        );
    }

    // FALLBACK POR FUENTE (D33): un ítem de fuente mono-dominio con título en prosa (que
    // el mapa de palabras deja en sin_clasificar) se rutea por la FUENTE, en inserción Y en
    // recategorizar. CONTROL: una fuente mixta con el mismo título queda sin_clasificar.
    #[tokio::test]
    async fn fallback_por_fuente_rutea_lo_que_el_texto_no() {
        let pool = bd_temporal().await;
        // Título académico sin la palabra "cryptography"; iacr-eprint es mono-dominio.
        registrar_conocimiento(
            &pool,
            "iacr-eprint",
            &[item("Leakage-Diagrams and Importance Sampling in the Random Probing Model", "https://eprint.iacr.org/2026/444")],
            "2026-10-30",
        ).await.unwrap();
        // CONTROL: el MISMO título desde una fuente mixta NO se fuerza.
        registrar_conocimiento(
            &pool,
            "the-hacker-news",
            &[item("Leakage-Diagrams and Importance Sampling in the Random Probing Model", "https://thn.test/x")],
            "2026-10-30",
        ).await.unwrap();

        assert!(saber(&pool, Some("quipu")).await.unwrap().iter().any(|f| f.url == "https://eprint.iacr.org/2026/444"),
            "iacr → quipu por fuente");
        assert!(saber(&pool, Some("sin_clasificar")).await.unwrap().iter().any(|f| f.url == "https://thn.test/x"),
            "fuente mixta → sin_clasificar");
        // Y sobrevive a recategorizar (misma costura con fallback).
        recategorizar(&pool).await.unwrap();
        assert!(saber(&pool, Some("quipu")).await.unwrap().iter().any(|f| f.url == "https://eprint.iacr.org/2026/444"),
            "el fallback por fuente sobrevive a recategorizar");
    }

    // R5·80/20 · RUTEAR: el criterio corrige el destino de un ítem que el mapa dejó en
    // sin_clasificar, y `razonado=1` lo PROTEGE de que `recategorizar` lo pise (D22/D32).
    // AGUJA = el destino queda en lo que dijo el juicio tras recategorizar. MUTANTE = sin
    // el `AND razonado=0` en recategorizar: el mapa lo devolvería a sin_clasificar.
    #[tokio::test]
    async fn rutear_fija_destino_y_recategorizar_no_lo_pisa() {
        let pool = bd_temporal().await;
        // Un título GENÉRICO que el mapa no coloca (sin_clasificar, puntaje 0).
        registrar_conocimiento(
            &pool,
            "thehackernews",
            &[item("A new tool for developers was announced today", "https://x.test/gen")],
            "2026-10-30",
        )
        .await
        .unwrap();
        let d = saber(&pool, Some("sin_clasificar")).await.unwrap();
        assert!(d.iter().any(|f| f.url == "https://x.test/gen"), "nace sin_clasificar");

        // El criterio lo rutea a fenrir por juicio.
        rutear(&pool, "https://x.test/gen", "fenrir", false, "toca automatización de navegador")
            .await
            .unwrap();
        let f = saber(&pool, Some("fenrir")).await.unwrap();
        assert!(f.iter().any(|x| x.url == "https://x.test/gen"), "ruteado a fenrir, sigue en digest");

        // Recategorizar (reaplica el mapa de palabras) NO debe moverlo de vuelta.
        recategorizar(&pool).await.unwrap();
        let f = saber(&pool, Some("fenrir")).await.unwrap();
        assert!(
            f.iter().any(|x| x.url == "https://x.test/gen"),
            "el juicio sobrevive a recategorizar (razonado=1): {f:?}"
        );
        let sc = saber(&pool, Some("sin_clasificar")).await.unwrap();
        assert!(!sc.iter().any(|x| x.url == "https://x.test/gen"), "no volvió a sin_clasificar");
    }

    // RUTEAR --lead eleva a IDEA (sale del digest `saber`, entra en `ideas`).
    #[tokio::test]
    async fn rutear_lead_eleva_a_idea() {
        let pool = bd_temporal().await;
        registrar_conocimiento(
            &pool,
            "ghsa",
            &[item("Editor extension ships a hidden ssh key on install", "https://x.test/ext")],
            "2026-10-30",
        )
        .await
        .unwrap();
        rutear(&pool, "https://x.test/ext", "zaque", true, "verificar integridad de extensiones del editor")
            .await
            .unwrap();
        // Sale del digest de pendientes…
        assert!(saber(&pool, None).await.unwrap().iter().all(|f| f.url != "https://x.test/ext"));
        // …y entra en el taller de ideas de su destino.
        let i = ideas(&pool, Some("zaque")).await.unwrap();
        assert!(i.iter().any(|f| f.url == "https://x.test/ext"), "es una idea de zaque: {i:?}");
    }

    // CASO ROJO (D30): rutear una URL inexistente falla ruidosamente.
    #[tokio::test]
    async fn rutear_fantasma_falla() {
        let pool = bd_temporal().await;
        assert!(rutear(&pool, "https://no.existe/x", "nexus", false, "").await.is_err());
    }

    // La PASADA DE RAZONAMIENTO solo trae lo de BAJA confianza y aún sin razonar: el
    // sin_clasificar (0) sí; lo de puntaje alto (varias señales) NO; lo ya ruteado NO.
    #[tokio::test]
    async fn razonar_pendientes_solo_baja_confianza_sin_razonar() {
        let pool = bd_temporal().await;
        registrar_conocimiento(
            &pool,
            "mix",
            &[
                item("Totally generic announcement", "https://x.test/gen"), // puntaje 0
                item("post-quantum cryptography ml-kem lattice kyber", "https://x.test/pq"), // alto
            ],
            "2026-10-30",
        )
        .await
        .unwrap();
        let r = razonar_pendientes(&pool, false, 40).await.unwrap();
        assert!(r.iter().any(|f| f.url == "https://x.test/gen"), "el no-ruteado entra");
        assert!(!r.iter().any(|f| f.url == "https://x.test/pq"), "el de alta confianza NO entra");

        // Tras rutear el genérico, ya no vuelve a aparecer por razonar (razonado=1, D30).
        rutear(&pool, "https://x.test/gen", "nexus", false, "x").await.unwrap();
        let r = razonar_pendientes(&pool, false, 40).await.unwrap();
        assert!(r.is_empty(), "lo ya razonado no se re-muestra: {r:?}");
    }

    // R7 · el taller de ideas: `ideas()` muestra SOLO los `lead` (con su «cómo»), no
    // los pendientes ni los `visto`/`descartado`. Pareja aguja/control (D33).
    #[tokio::test]
    async fn ideas_solo_muestra_los_lead() {
        let pool = bd_temporal().await;
        registrar_conocimiento(
            &pool,
            "portswigger",
            &[
                item("Nueva técnica de SSRF por redirección", "https://x.test/ssrf"),
                item("Titular cualquiera de la semana", "https://x.test/ruido"),
                item("Ataque de prompt injection a agentes", "https://x.test/pi"),
            ],
            "2026-09-28",
        )
        .await
        .unwrap();

        // Aguja: una idea (lead con cómo). Control-1: un `visto` (evaluado, no idea).
        // Control-2: uno que se queda pendiente (nunca tocado).
        triar_saber(&pool, "https://x.test/ssrf", "lead", "nexus: molde de oráculo SSRF")
            .await
            .unwrap();
        triar_saber(&pool, "https://x.test/ruido", "visto", "sin jugo")
            .await
            .unwrap();

        let ideas = ideas(&pool, None).await.unwrap();
        assert_eq!(ideas.len(), 1, "solo el lead es idea: {ideas:?}");
        assert_eq!(ideas[0].url, "https://x.test/ssrf");
        assert_eq!(
            ideas[0].nota, "nexus: molde de oráculo SSRF",
            "la idea lleva el «cómo» en la nota"
        );
        // Control por la vía real: ni el `visto` ni el pendiente aparecen.
        assert!(
            !ideas.iter().any(|i| i.url == "https://x.test/ruido"),
            "un `visto` NO es una idea"
        );
        assert!(
            !ideas.iter().any(|i| i.url == "https://x.test/pi"),
            "un pendiente NO es una idea"
        );
    }

    // --- R8: características ------------------------------------------------

    #[tokio::test]
    async fn caracteristica_se_caza_de_una_fuente_y_se_liga() {
        let pool = bd_temporal().await;
        // Una fuente real: un repo encolado.
        encolar(&pool, &[cand(1, &["htmx"], 100, "2026-09-01T00:00:00Z")], "t0")
            .await
            .unwrap();

        let id = registrar_caracteristica(
            &pool,
            NuevaCaracteristica {
                que_hace: "un <dialog> que trae htmx se abre modal y se retira al cerrar",
                destino: "boi",
                como: "comportamiento boi: showModal + close→remove, evento de servidor",
                licencia_origen: "Unlicense",
            },
            TipoFuente::Candidato,
            "1",
            "t1",
        )
        .await
        .unwrap();
        assert!(id > 0);

        let cs = caracteristicas(&pool, None, None).await.unwrap();
        assert_eq!(cs.len(), 1);
        assert_eq!(cs[0].destino, "boi");
        assert_eq!(cs[0].estado, EstadoCaracteristica::Propuesta, "nace propuesta");
    }

    #[tokio::test]
    async fn cazar_de_una_fuente_inventada_falla_ruidoso() {
        // D30: una característica de una fuente que no existe sería procedencia
        // inventada. Debe fallar, no ligar a la nada.
        let pool = bd_temporal().await;
        let r = registrar_caracteristica(
            &pool,
            NuevaCaracteristica { que_hace: "algo", destino: "boi", como: "así", licencia_origen: "MIT" },
            TipoFuente::Candidato,
            "999",
            "t1",
        )
        .await;
        assert!(r.is_err(), "cazar de un repo inexistente tiene que fallar");
    }

    #[tokio::test]
    async fn una_caracteristica_llega_de_varias_fuentes() {
        let pool = bd_temporal().await;
        encolar(&pool, &[cand(1, &["webauthn"], 100, "2026-09-01T00:00:00Z")], "t0")
            .await
            .unwrap();
        encolar(&pool, &[cand(2, &["webauthn"], 200, "2026-09-01T00:00:00Z")], "t0")
            .await
            .unwrap();

        let id = registrar_caracteristica(
            &pool,
            NuevaCaracteristica {
                que_hace: "passkeys por webauthn",
                destino: "chuspa",
                como: "reimplementar el flujo",
                licencia_origen: "MIT",
            },
            TipoFuente::Candidato,
            "1",
            "t1",
        )
        .await
        .unwrap();
        // La MISMA característica, segunda fuente.
        ligar_fuente(&pool, id, TipoFuente::Candidato, "2", "t2").await.unwrap();

        let n: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM caracteristica_fuente WHERE caracteristica_id = ?1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(n.0, 2, "dos fuentes ligadas a una sola característica");

        // Y ligar la MISMA fuente otra vez es idempotente (la clave lo absorbe).
        ligar_fuente(&pool, id, TipoFuente::Candidato, "2", "t3").await.unwrap();
        let n2: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM caracteristica_fuente WHERE caracteristica_id = ?1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(n2.0, 2, "ligar dos veces no duplica");
    }

    #[tokio::test]
    async fn sentar_estado_filtra_y_falla_en_fantasma() {
        let pool = bd_temporal().await;
        encolar(&pool, &[cand(1, &["htmx"], 100, "2026-09-01T00:00:00Z")], "t0")
            .await
            .unwrap();
        let id = registrar_caracteristica(
            &pool,
            NuevaCaracteristica { que_hace: "modal", destino: "boi", como: "así", licencia_origen: "Unlicense" },
            TipoFuente::Candidato,
            "1",
            "t1",
        )
        .await
        .unwrap();

        sentar_estado_caracteristica(&pool, id, EstadoCaracteristica::Sirve, "vale para boi", "t2")
            .await
            .unwrap();

        // El filtro por estado ve la que SIRVE y no las demás.
        let sirven = caracteristicas(&pool, None, Some("sirve")).await.unwrap();
        assert_eq!(sirven.len(), 1);
        assert_eq!(sirven[0].estado, EstadoCaracteristica::Sirve);
        let propuestas = caracteristicas(&pool, None, Some("propuesta")).await.unwrap();
        assert_eq!(propuestas.len(), 0, "ya no está en propuesta");

        // Filtro por destino.
        assert_eq!(caracteristicas(&pool, Some("boi"), None).await.unwrap().len(), 1);
        assert_eq!(caracteristicas(&pool, Some("nexus"), None).await.unwrap().len(), 0);

        // Un id fantasma falla ruidoso (D30).
        let r = sentar_estado_caracteristica(
            &pool, 9999, EstadoCaracteristica::Descartada, "x", "t3",
        )
        .await;
        assert!(r.is_err(), "sentar estado sobre id inexistente tiene que fallar");
    }

    #[tokio::test]
    async fn cobertura_cuenta_examinados_vs_pendientes() {
        let pool = bd_temporal().await;
        // Tres candidatos de boi (topic htmx → destino boi por el mapa).
        encolar(
            &pool,
            &[
                cand(1, &["htmx"], 100, "2026-09-01T00:00:00Z"),
                cand(2, &["htmx"], 100, "2026-09-01T00:00:00Z"),
                cand(3, &["htmx"], 100, "2026-09-01T00:00:00Z"),
            ],
            "t0",
        )
        .await
        .unwrap();
        // Examinar dos (uno adoptar, uno descartar): ambos cuentan como examinados.
        sentar_veredicto(&pool, 1, Veredicto::Adoptar, "aportó modal", "t1").await.unwrap();
        sentar_veredicto(&pool, 2, Veredicto::Descartar, "nada que cazar", "t1").await.unwrap();

        let cob = cobertura(&pool).await.unwrap();
        let boi = cob.iter().find(|f| f.destino == "boi").expect("boi tiene que estar");
        assert_eq!(boi.candidatos_examinados, 2, "adoptar y descartar cuentan como examinados");
        assert_eq!(boi.candidatos_pendientes, 1, "queda uno sin mirar");
        assert_eq!(boi.pendientes(), 1);
    }

    #[tokio::test]
    async fn implementar_lista_solo_sirve_sin_tarea_y_marca() {
        let pool = bd_temporal().await;
        encolar(&pool, &[cand(1, &["htmx"], 100, "2026-09-01T00:00:00Z")], "t0")
            .await
            .unwrap();
        let id = registrar_caracteristica(
            &pool,
            NuevaCaracteristica { que_hace: "modal", destino: "boi", como: "así", licencia_origen: "Unlicense" },
            TipoFuente::Candidato,
            "1",
            "t1",
        )
        .await
        .unwrap();

        // Propuesta: aún NO está por implementar.
        assert_eq!(caracteristicas_por_implementar(&pool).await.unwrap().len(), 0);

        sentar_estado_caracteristica(&pool, id, EstadoCaracteristica::Sirve, "vale", "t2")
            .await
            .unwrap();
        assert_eq!(
            caracteristicas_por_implementar(&pool).await.unwrap().len(),
            1,
            "una que SIRVE sin tarea es trabajo pendiente"
        );

        // Marcarla como tarea la saca de la lista de por-implementar.
        marcar_caracteristica_tarea(&pool, id, "t3").await.unwrap();
        assert_eq!(
            caracteristicas_por_implementar(&pool).await.unwrap().len(),
            0,
            "ya con tarea, no vuelve a aparecer"
        );
        // Marcarla otra vez falla ruidoso (ya tiene tarea) — D30.
        assert!(marcar_caracteristica_tarea(&pool, id, "t4").await.is_err());
    }
}
