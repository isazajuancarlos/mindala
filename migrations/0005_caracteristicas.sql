-- SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
-- SPDX-License-Identifier: MIT
--
-- R8 · la CARACTERÍSTICA como unidad de valor. Hasta aquí el valor vivía en el
-- `veredicto` de un repo (`candidatos`) — «adoptar/descartar» el REPO—, y eso
-- colapsaba dos cosas distintas (D32): «este repo sirve» y «esta técnica sirve».
-- mindalá caza CARACTERÍSTICAS (técnicas), no librerías ni programas: se
-- reimplementan propias en el estándar (D9/D38), no se adopta el repo.
--
-- La característica es TRANSVERSAL a las fuentes: la aporta un repo (`candidatos`)
-- o una noticia (`conocimiento`); llega de VARIAS fuentes; y puede existir sin
-- destino aún. Por eso va en su tabla, con un puente N↔N a las fuentes.

CREATE TABLE IF NOT EXISTS caracteristicas (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    que_hace        TEXT    NOT NULL,          -- la técnica, en una frase
    destino         TEXT    NOT NULL,          -- proyecto Xiliux, o 'sin_clasificar'
    como            TEXT    NOT NULL,          -- el «cómo» implementarla en el estándar
    licencia_origen TEXT    NOT NULL,          -- SPDX de la fuente (la licencia manda, regla 3)
    -- 'propuesta' (el criterio la registró) | 'sirve' (vale implementarla) |
    -- 'implementada' (ya está en el estándar) | 'descartada'. Sin NULL: una
    -- característica nace con estado explícito, no ausente (D20).
    estado          TEXT    NOT NULL DEFAULT 'propuesta',
    nota            TEXT    NOT NULL DEFAULT '',
    descubierta_en  TEXT    NOT NULL,          -- ISO-8601
    estado_en       TEXT,                       -- cuándo cambió de estado por última vez
    -- enganche a IMPLEMENTAR (como el `tarea_en` de candidatos): NULL = 'sirve'
    -- pero sin tarea registrada aún; con fecha = ya se emitió/registró la tarea.
    tarea_en        TEXT
);

CREATE INDEX IF NOT EXISTS idx_caracteristicas_destino ON caracteristicas (destino);
CREATE INDEX IF NOT EXISTS idx_caracteristicas_estado  ON caracteristicas (estado);
-- Las que SIRVEN y aún no son tarea: el trabajo pendiente de implementar.
CREATE INDEX IF NOT EXISTS idx_caracteristicas_por_implementar ON caracteristicas (estado)
    WHERE estado = 'sirve' AND tarea_en IS NULL;

-- El puente característica ↔ fuente. Una característica sale de N fuentes; una
-- fuente aporta N características. `tipo_fuente` dice de qué tabla es `ref_fuente`
-- ('candidato' → `candidatos.id_github` como texto; 'conocimiento' →
-- `conocimiento.url`). No es FK dura a propósito: una fuente puede caducar de su
-- tabla y la característica sobrevive con su procedencia registrada.
CREATE TABLE IF NOT EXISTS caracteristica_fuente (
    caracteristica_id INTEGER NOT NULL,
    tipo_fuente       TEXT    NOT NULL,        -- 'candidato' | 'conocimiento'
    ref_fuente        TEXT    NOT NULL,        -- id_github (texto) o url
    ligada_en         TEXT    NOT NULL,        -- ISO-8601

    PRIMARY KEY (caracteristica_id, tipo_fuente, ref_fuente)
);

CREATE INDEX IF NOT EXISTS idx_carfuente_fuente ON caracteristica_fuente (tipo_fuente, ref_fuente);
