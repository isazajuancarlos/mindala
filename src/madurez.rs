// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: MIT

//! El eje de MADUREZ de un candidato — SEPARADO de la relevancia (D32).
//!
//! `categoria` responde *¿a QUIÉN le sirve?* (relevancia). Este módulo responde una
//! pregunta ortogonal: *¿está lo bastante PROBADO para cosechar su técnica?* Son dos
//! ejes distintos y colapsarlos ciega a uno — un repo ⭐0 puede ser perfectamente
//! relevante a quipu (es cripto) y a la vez no valer como fuente de técnica (D35: no
//! se copia criptografía de código sin adopción ni auditoría).
//!
//! **Por qué existe (medido 2026-10-29):** la cola de quipu tenía 136 candidatos, 99
//! con ⭐<10 — PQC "engines" recién nacidos que el scoring por keyword premiaba, y que
//! ahogaban a los 6 maduros de verdad. mindalá es un scout de TÉCNICAS (alimenta
//! proyectos con «lo probado»), así que su piso natural es la MADUREZ. (El scout de
//! BLANCOS —código joven y poco auditado, piso OPUESTO— es otra herramienta: `nexus
//! candidatos`. No confundir las dos venas.)
//!
//! **Demota, no borra (D20):** un incipiente NO se descarta ni se oculta en silencio —
//! sigue en la BD y `cola --todo` lo muestra. La `cola` solo lo baja de la vista por
//! defecto, y dice cuántos ocultó (D30: un filtro mudo es indistinguible de una cola
//! vacía). Y es heurística, no veredicto: a ⭐<10 no AFIRMAMOS «slop» (no se puede
//! saber, D20/D23), solo «adopción no probada» → fuera de la vista por defecto.

/// Nivel de madurez por ADOPCIÓN (estrellas). Heurístico y conservador: el umbral
/// mide cuánta gente se apoya en el repo, que es la señal barata de «probado» que la
/// Search API ya nos da sin otra petición.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Madurez {
    /// Adopción amplia (≥100 ⭐): fuente de técnica fiable.
    Maduro,
    /// Con tracción (10–99 ⭐): se muestra, pero ya no es «lo probado».
    Emergente,
    /// Sin adopción probada (<10 ⭐): fuera de la vista por defecto en la cola.
    Incipiente,
}

/// Umbral de «probado» (adopción amplia). Encima → `Maduro`.
pub const UMBRAL_MADURO: i64 = 100;
/// Umbral de tracción mínima para salir en la cola por defecto. Debajo → `Incipiente`.
pub const UMBRAL_VISIBLE: i64 = 10;

impl Madurez {
    /// Clasifica por estrellas. Puro. Es el único insumo del gate v1 (adopción), la
    /// señal que la Search API ya persiste; enriquecer con edad/forks/releases es una
    /// rebanada aparte (requiere deserializar y migrar), no este piso.
    #[must_use]
    pub fn clasificar(estrellas: i64) -> Self {
        if estrellas >= UMBRAL_MADURO {
            Madurez::Maduro
        } else if estrellas >= UMBRAL_VISIBLE {
            Madurez::Emergente
        } else {
            Madurez::Incipiente
        }
    }

    /// ¿La `cola` lo oculta por defecto? Solo el incipiente. Demota, no borra (D20):
    /// sigue en la BD y `--todo` lo trae.
    #[must_use]
    pub fn oculto_por_defecto(self) -> bool {
        matches!(self, Madurez::Incipiente)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    // AGUJA (D33): una fuente de técnica MADURA (orion ⭐722, el caso real de la cola
    // de quipu) se clasifica Maduro y NO se oculta. Si el gate cegara y todo cayera a
    // Incipiente, esto se pondría rojo.
    #[test]
    fn madura_se_ve() {
        let m = Madurez::clasificar(722);
        assert_eq!(m, Madurez::Maduro);
        assert!(!m.oculto_por_defecto());
    }

    // PAREJA (D33, el caso que JUSTIFICA el módulo): un incipiente ⭐2 (ml-dsa-rs, real
    // de la cola de quipu) se oculta por defecto. MUTANTE = sin gate (todo visible):
    // `oculto_por_defecto` daría false y esto fallaría. Discrimina por la vía real.
    #[test]
    fn incipiente_se_oculta() {
        let m = Madurez::clasificar(2);
        assert_eq!(m, Madurez::Incipiente);
        assert!(m.oculto_por_defecto());
    }

    // CONTROL del emergente: 44 ⭐ (kyberlib, real) tiene tracción → se ve, pero no es
    // Maduro. Separa las dos fronteras (no es un gate de dos estados disfrazado).
    #[test]
    fn emergente_se_ve_pero_no_es_maduro() {
        let m = Madurez::clasificar(44);
        assert_eq!(m, Madurez::Emergente);
        assert!(!m.oculto_por_defecto());
    }

    // FRONTERAS exactas (el off-by-one que un umbral siempre esconde): el umbral es
    // inclusivo abajo. 10 se ve (Emergente), 9 se oculta; 100 es Maduro, 99 Emergente.
    #[test]
    fn fronteras_de_los_umbrales() {
        assert_eq!(Madurez::clasificar(10), Madurez::Emergente);
        assert!(Madurez::clasificar(9).oculto_por_defecto());
        assert_eq!(Madurez::clasificar(100), Madurez::Maduro);
        assert_eq!(Madurez::clasificar(99), Madurez::Emergente);
        // 0 ⭐ (el PQC-slop que motivó el módulo) se oculta.
        assert!(Madurez::clasificar(0).oculto_por_defecto());
    }
}
