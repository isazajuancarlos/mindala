-- SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
-- SPDX-License-Identifier: MIT
--
-- La memoria de mindala (D5/D20): lo descubierto, categorizado y —cuando el
-- criterio lo estudia— su veredicto. `id_github` es PRIMARY KEY: la
-- deduplicación es la propia clave (regla 4 del diseño).

CREATE TABLE IF NOT EXISTS candidatos (
    id_github        INTEGER PRIMARY KEY,
    nombre_completo  TEXT    NOT NULL,
    url              TEXT    NOT NULL,
    descripcion      TEXT    NOT NULL,
    lenguaje         TEXT    NOT NULL,
    topics           TEXT    NOT NULL,          -- JSON: ["topic", ...]
    estrellas        INTEGER NOT NULL,
    pushed_at        TEXT    NOT NULL,          -- señal de caducidad
    licencia         TEXT    NOT NULL,          -- SPDX; la licencia manda (regla 3)
    destino          TEXT    NOT NULL,          -- proyecto Xiliux o 'sin_clasificar'
    puntaje          INTEGER NOT NULL,
    descubierto_en   TEXT    NOT NULL,          -- ISO-8601, primera vez que se vio
    -- veredicto: NULL = pendiente (ausencia, no un valor de relleno; D20).
    veredicto        TEXT,                       -- 'adoptar' | 'descartar' | NULL
    nota             TEXT,                       -- porqué del veredicto (D5)
    veredicto_en     TEXT
);

CREATE INDEX IF NOT EXISTS idx_candidatos_destino  ON candidatos (destino);
CREATE INDEX IF NOT EXISTS idx_candidatos_pendiente ON candidatos (veredicto)
    WHERE veredicto IS NULL;
