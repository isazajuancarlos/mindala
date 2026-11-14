-- SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
-- SPDX-License-Identifier: MIT
--
-- R4 · enganche a implementar. Un candidato ADOPTADO por el criterio debe volverse
-- una tarea en su proyecto destino. `tarea_en` rastrea ese enganche sin duplicar el
-- sistema de tareas de Xiliux (D1): NULL = adoptado pero aún sin tarea registrada;
-- con fecha = ya se convirtió en tarea real. mindala solo EMITE la ficha; el
-- criterio (el 20%) registra la tarea en el proyecto destino.

ALTER TABLE candidatos ADD COLUMN tarea_en TEXT;

CREATE INDEX IF NOT EXISTS idx_candidatos_adoptado_sin_tarea ON candidatos (veredicto)
    WHERE veredicto = 'adoptar' AND tarea_en IS NULL;
