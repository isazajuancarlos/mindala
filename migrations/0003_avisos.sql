-- SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
-- SPDX-License-Identifier: MIT
--
-- R6 · lazo dep→CVE (contrainteligencia). `mindala audit` cruza el Cargo.lock REAL
-- de cada repo Xiliux contra la base de avisos de RustSec (vía `cargo audit`), en
-- LOCAL (el CI está apagado), y recuerda aquí lo hallado para que las re-corridas
-- solo destaquen lo NUEVO (D5, memoria; misma disciplina que `candidatos`).
--
-- La clave compuesta ES la deduplicación: el MISMO aviso sobre el MISMO paquete a
-- la MISMA versión en el MISMO repo es una sola fila. `estado` NULL = pendiente de
-- triaje (ausencia, no relleno; D20): con valor lo puso el criterio ('resuelto',
-- 'aceptado', 'falso_positivo') y NO vuelve a destacarse como nuevo.

CREATE TABLE IF NOT EXISTS avisos (
    repo          TEXT NOT NULL,          -- proyecto Xiliux (ej. 'quipu')
    advisory_id   TEXT NOT NULL,          -- 'RUSTSEC-2026-0285'
    paquete       TEXT NOT NULL,          -- crate afectado (ej. 'rustls')
    version       TEXT NOT NULL,          -- versión que consumimos (ej. '0.23.43')
    titulo        TEXT NOT NULL,
    url           TEXT NOT NULL,
    -- 'vulnerabilidad' (RUSTSEC con CVE) | 'aviso' (unmaintained/yanked/notice).
    tipo          TEXT NOT NULL,
    severidad     TEXT NOT NULL,          -- CVSS/etiqueta, o '—' si no hay
    parcheado     TEXT NOT NULL,          -- versiones que corrigen, o '—'
    primero_visto TEXT NOT NULL,          -- ISO-8601: primera corrida que lo halló
    ultimo_visto  TEXT NOT NULL,          -- ISO-8601: corrida más reciente que lo vio
    estado        TEXT,                   -- NULL = pendiente de triaje (D20)
    nota          TEXT,                   -- porqué del triaje (D5)

    PRIMARY KEY (repo, advisory_id, paquete, version)
);

CREATE INDEX IF NOT EXISTS idx_avisos_repo      ON avisos (repo);
CREATE INDEX IF NOT EXISTS idx_avisos_pendiente ON avisos (estado) WHERE estado IS NULL;
