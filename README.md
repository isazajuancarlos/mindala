<!--
SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
SPDX-License-Identifier: MIT
-->
# mindala — el mercader de ideas del universo Xiliux

Los **mindalá** eran los mercaderes muiscas de larga distancia: traían materiales
valiosos de mercados lejanos para enriquecer a toda la sociedad. Esta herramienta
hace lo mismo con TÉCNICAS de software — sale a GitHub, encuentra lo valioso, lo
**categoriza** hacia el proyecto de Xiliux que lo aprovecha, y lo encola para que
el criterio lo estudie.

Reparto **80/20** (patrón de nexus): el programa descubre / categoriza / encola
(el 80% mecánico); el criterio (Claude-en-el-loop) estudia el fuente, respeta la
licencia y decide adoptar o descartar (el 20% que juzga). El juicio no se automatiza.

Diseño completo: `conocimiento/proyectos/mindala/DISENO.md`.

## Uso

```sh
# R1 · descubrir por topic, categorizar y encolar (keyless: 60 req/h sin token).
mindala buscar --topic webauthn --min-estrellas 100
mindala buscar --topic post-quantum --lenguaje rust --pushed-desde 2026-01-01
GITHUB_TOKEN=ghp_xxx mindala buscar --topic recon   # PAT opcional: 5000 req/h

# R2 · triaje: listar, ver la ficha, clonar para estudiar, y sentar el veredicto.
mindala cola                       # todos los pendientes
mindala cola --destino quipu       # solo los de un proyecto
mindala ver 306366900              # ficha completa (avisa si la licencia es copyleft)
mindala estudiar 306366900         # clona a analisis/<repo> para leer el fuente
mindala veredicto 306366900 --adoptar   --nota "su flujo OIDC nos sirve en bachue"
mindala veredicto 148706208 --descartar --nota "firmware C, fuera de stack"

# R3 · fuentes extra: pescar repos de GitHub mencionados fuera de GitHub.
mindala hn --query "post-quantum rust"        # Hacker News (Algolia)
mindala lobsters --tag rust                     # lobste.rs (o sin --tag: los top)
mindala awesome rust-unofficial/awesome-rust    # repos enlazados en una awesome-list

# R4 · enganche: de lo ADOPTADO nace la ficha de tarea para el proyecto destino.
mindala tareas                     # emite cada ficha (asunto, proyecto, contexto)
mindala tarea-lista 306366900      # marca que ya la registraste en el destino

# R5 · inteligencia: noticias de seguridad, cripto e IA (11 fuentes, keyless).
mindala feed                       # trae los feeds curados (dep-free RSS/Atom)
mindala kev                        # catálogo CISA KEV: los CVE EXPLOTADOS de verdad en el
                                   # mundo → categoriza por destino (le da casa al CVE
                                   # no-Rust, p.ej. UEFI→zaque, que RustSec no ve)
mindala vulnx "post-quantum"       # inteligencia de vulns de ProjectDiscovery (EPSS,
mindala vulnx "rustls" --limite 20 #   exploits/POCs, prioridad nuclei; productos Y crates)
                                   #   → categoriza por destino. Requiere `vulnx` (go install)
mindala saber                      # el digest, lo relevante primero
mindala saber --destino nexus      # solo lo que toca un producto
mindala saber --destino zaque      # p.ej. los CVE de arranque/integridad
mindala saber --destino seguridad  # intel de seguridad-LLM (prompt injection, exfiltración,
                                   # jailbreak) para la defensa viva: olfateador/razonador
mindala triar-saber <url> --estado visto       # sacarlo del digest

# R5·80/20 · la PASADA DE RAZONAMIENTO. El mapa de palabras (categoria.rs) es la vía
# rápida: acierta lo claro y sale seco en la prosa de un CVE/noticia. Para «capturar lo
# que sirve» a nivel razonador, el criterio (Claude-en-el-loop) lee lo de BAJA confianza
# y lo rutea por JUICIO — el mismo 80/20 de nexus: el código empareja, Claude razona.
mindala razonar                    # lista lo NO ruteado (sin_clasificar) con su cuerpo
mindala razonar --incluir-debiles --limite 60   # además los de 1 sola señal (puntaje≤1)
mindala rutear <url> --destino bachue --nota "es un bypass de OIDC"   # fijar por juicio
mindala rutear <url> --destino zaque --lead --nota "idea: verificar integridad de extensiones"
                                   # --lead lo eleva a IDEA (R7). `rutear` marca el ítem
                                   # como razonado: `recategorizar` ya no lo pisa.

# R6 · contrainteligencia: dep→CVE con `cargo audit` en local sobre cada repo.
mindala audit --raiz /mnt/data     # audita los Cargo.lock reales; recuerda avisos
mindala avisos                     # el digest de avisos pendientes de triaje
mindala triar-aviso quipu YANKED chacha20 --estado aceptado --nota "vendored-moot"
mindala expuesto                   # R5×R6: qué advisory del feed toca crates que consumes
mindala consume chacha20           # consulta puntual: qué repos lo usan, y en qué versión

# R7 · taller de IDEAS: de una noticia sale el «cómo» para un producto.
mindala triar-saber <url> --estado lead --nota "nexus: detector de exfil por imagen"
mindala ideas                      # las ideas vivas (el «cómo» completo va a docs)

# R8 · CARACTERÍSTICAS: la unidad de valor es la TÉCNICA, no el repo.
# El criterio caza la característica de una fuente (repo o noticia) y la reimplementa
# propia en el estándar (D9/D38) — nunca adopta el repo.
mindala cobertura                  # «revisar TODOS»: examinadas vs pendientes por destino
mindala recategorizar              # re-aplica el mapa vigente a los PENDIENTES (tras
                                   # cambiar categoria.rs); no toca lo ya sentenciado
mindala caracteristica --que "un <dialog> que trae htmx se abre modal" \
    --destino boi --como "comportamiento boi: showModal + close→remove" \
    --licencia Unlicense --de-repo 532074755        # cazar de un repo…
mindala caracteristica --que "…" --destino nexus --como "…" --de-noticia <url>  # …o de una noticia
mindala ligar-fuente 3 --de-repo 12345             # la misma característica llega de otra fuente
mindala caracteristicas --destino boi --estado sirve
mindala veredicto8 3 --sirve       # vale implementarla (o --descartar / --implementada)
mindala implementar                # emite la ficha de IMPLEMENTAR-en-el-estándar de lo que sirve
mindala caracteristica-lista 3     # marca que ya la registraste como tarea en su destino
```

La memoria vive en `mindala.db` (SQLite, `--bd` para cambiar la ruta). Es memoria
de verdad: lo ya visto no se re-descubre (dedup por `id_github`), un candidato
pendiente se refresca si el repo tuvo actividad nueva, y uno con veredicto queda
**congelado** — no se re-estudia.

## Reglas de nacimiento

- **Keyless/soberano.** GitHub API pública; el PAT es opcional y de bajo privilegio.
- **Estatuto.** Solo estudio y divulgación responsable: mindalá clona y lee, nunca ataca.
- **La licencia manda.** Cada candidato guarda su SPDX; AGPL/GPL se reimplementan sin copiar.
- **Rust** (D38), estándar de nacimiento de Xiliux (bagué), MIT.

## Estado

Todas las rebanadas del `DISENO.md` están **HECHAS**:

- **R1 · descubrir** — `buscar` por topic de GitHub.
- **R2 · triaje** — `cola`, `ver`, `estudiar` (clona a `analisis/`), `veredicto`.
- **R3 · fuentes extra** — `hn`, `lobsters`, `awesome` (resuelven repos vía la API,
  con dedup para no gastar peticiones).
- **R4 · enganche** — `tareas` emite la ficha de tarea de lo adoptado (sin auto-código);
  `tarea-lista` cierra el enganche.
- **R5 · inteligencia** (2026-09-27, fuentes ampliadas 2026-09-28) — `feed`/`saber`/
  `triar-saber`: 11 fuentes de noticias (seguridad, cripto, IA, Rust), dep-free/keyless.
  **El seam 80/20 del clasificador** (2026-10-30) — `razonar`/`rutear`: el mapa de
  palabras es la vía rápida (acierta lo claro, sale seco en la prosa); el criterio
  razona sobre lo de baja confianza y lo rutea por juicio (`razonado=1`, que
  `recategorizar` respeta). El resumen se guarda para que inserción y recategorización
  usen la MISMA costura (título+cuerpo, D33) y Claude juzgue por el cuerpo.
  **Fallback por FUENTE**: una fuente mono-dominio (iacr-eprint, cryptography-engineering,
  embrace-the-red, portswigger) fija el destino cuando el texto sale sin_clasificar — el
  dominio lo da la fuente, no el título en prosa (294+ noticias rescatadas, 2026-10-30).
- **R6 · contrainteligencia** (2026-09-27) — `audit`/`avisos`/`triar-aviso`: lazo
  dep→CVE con `cargo audit` local; `expuesto` cruza advisories del feed × crates consumidos.
- **R7 · taller de ideas** (2026-09-28) — `ideas`: de una noticia (`lead`) sale el
  «cómo» para un producto; el detalle vive en `conocimiento/proyectos/mindala/ideas/`.
- **R8 · características** (2026-09-28) — la unidad de valor pasa del REPO a la
  CARACTERÍSTICA (técnica): `caracteristica`/`caracteristicas`/`ligar-fuente`/
  `veredicto8`/`implementar`/`caracteristica-lista`, y `cobertura` como disciplina de
  «revisar TODOS». Una característica es transversal a las fuentes (repo o noticia) y
  su desenlace es reimplementarla propia en el estándar, no adoptar el repo (D9/D38/D32).

  **El `veredicto` sobre un REPO se reorienta**: `--adoptar` ya no significa «tomar el
  repo» sino «examinado, aportó característica(s)» (que se registran con
  `caracteristica`); `--descartar` es «examinado, nada que cazar». El repo es una
  FUENTE que se examina; el valor vive en las características.

104 pruebas en verde (96 unitarias con parejas aguja/control + 8 E2E que arrancan el
binario real) + clippy `-D warnings`. Verificado contra la red real (GitHub, HN,
lobste.rs, awesome-rust, los 11 feeds, CISA KEV y vulnx) y con un clon real.
