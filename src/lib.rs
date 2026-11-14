// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: MIT

//! mindala — el mercader de ideas del universo Xiliux.
//!
//! Sale a GitHub (y otras fuentes), encuentra técnicas de software valiosas y las
//! trae, categorizadas, para mejorar los proyectos de Xiliux. Reparto 80/20: el
//! PROGRAMA descubre/categoriza/encola (aquí); el CRITERIO (Claude-en-el-loop)
//! estudia y decide. Ver `conocimiento/proyectos/mindala/DISENO.md`.

pub mod auditoria;
pub mod bd;
pub mod categoria;
pub mod conocimiento;
pub mod fuentes;
pub mod github;
pub mod kev;
pub mod vulnx;
pub mod madurez;
pub mod modelo;
