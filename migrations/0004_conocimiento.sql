-- SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
-- SPDX-License-Identifier: MIT
--
-- R5 · fuentes de CONOCIMIENTO (eje inteligencia, no-repo). Un ítem de feed —una
-- novedad, un advisory, un incidente— categorizado por relevancia a un proyecto
-- Xiliux y recordado para que el digest destaque solo lo NUEVO (D5). Misma disciplina
-- que `candidatos` y `avisos`: la URL es la clave (dedup), `estado` NULL = pendiente
-- de triaje (ausencia, no relleno; D20).

CREATE TABLE IF NOT EXISTS conocimiento (
    url           TEXT PRIMARY KEY,       -- enlace del ítem (la dedup ES la clave)
    fuente        TEXT NOT NULL,          -- 'rustsec' | 'this-week-in-rust' | …
    titulo        TEXT NOT NULL,
    fecha         TEXT NOT NULL,          -- fecha del feed, o '' si no la da
    destino       TEXT NOT NULL,          -- proyecto Xiliux o 'sin_clasificar'
    puntaje       INTEGER NOT NULL,       -- palabras clave que casaron (relevancia)
    primero_visto TEXT NOT NULL,          -- ISO-8601, primera corrida que lo trajo
    estado        TEXT,                   -- NULL = pendiente de triaje (D20)
    nota          TEXT                    -- porqué del triaje (D5)
);

CREATE INDEX IF NOT EXISTS idx_conocimiento_pendiente ON conocimiento (estado)
    WHERE estado IS NULL;
CREATE INDEX IF NOT EXISTS idx_conocimiento_destino   ON conocimiento (destino);
