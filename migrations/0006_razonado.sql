-- SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
-- SPDX-License-Identifier: MIT
--
-- El seam 80/20 del clasificador (2026-10-30). El mapa de palabras de `categoria.rs`
-- es la VÍA RÁPIDA barata: acierta los casos claros (cryptography→quipu, oidc→bachue)
-- y sale seco en la prosa ambigua (un CVE/una noticia en lenguaje natural). Lo que
-- "captura adecuadamente lo que sirve" NO es más palabras en la tabla —un emparejador
-- empareja, no razona (lección medida de nexus)— sino una PASADA DE RAZONAMIENTO:
-- Claude-en-el-loop lee lo que el emparejado no supo colocar y lo rutea con JUICIO.
--
-- `razonado` distingue las dos procedencias (D32: «ruteado por palabra» y «ruteado por
-- juicio» son dos cosas distintas): 0 = lo puso el mapa de palabras; 1 = lo ruteó el
-- criterio. Sin esta marca, `recategorizar` —que reaplica el mapa de palabras— pisaría
-- el juicio de Claude y lo devolvería al destino del emparejado SIN avisar (D22: la
-- limpieza se acota a lo que el mapa regenera, y el juicio NO lo regenera el mapa).
ALTER TABLE conocimiento ADD COLUMN razonado INTEGER NOT NULL DEFAULT 0;

-- La pasada de razonamiento consulta lo de baja confianza (puntaje bajo) aún sin
-- razonar: este índice la sirve sin recorrer toda la tabla.
CREATE INDEX IF NOT EXISTS idx_conocimiento_por_razonar ON conocimiento (razonado, puntaje)
    WHERE estado IS NULL AND razonado = 0;
