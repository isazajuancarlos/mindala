# mindala

Technical intelligence aggregator: discovers, categorizes, and queues findings from public sources for human review and adoption. MIT. Rust.

**English** · [Español](#español)

---

## The code is not hosted here

Since August 2026 the source of this project **is not hosted on GitHub**, and it is not distributed through any package registry.

This is not abandonment, not an incident, and there was no breach. It is a decision: through 2026 the package registries and code-hosting platforms were hit by sustained, chained supply-chain attacks — the Shai-Hulud worm, ChainDrop in August, malicious extensions that exfiltrated thousands of private repositories. Hosting the source there stopped being a neutral decision.

**The licence has not changed and the code is still available to anyone who asks** — delivered with a signature and a checksum, at no cost, with no NDA, no restriction on what you publish about it, and no expiry. Request it at **xiliux.com**.

---

## What it does

The *mindalá* were the long-distance Muisca traders of pre-Columbian Colombia: they brought valuable materials from distant markets to enrich the whole society. This tool does the same for software techniques — it goes out to public sources, finds what is valuable, categorizes it toward the projects that can use it, and queues it for expert review.

**80/20 design**: the program discovers, categorizes, and queues (80% mechanical); the expert (Claude-in-the-loop) reads the source, respects the licence, and decides whether to adopt or discard (20% that judges). Judgement is not automated.

### Intelligence sources

- **GitHub** — search by topic, language, stars, and recent activity; dedup by repository id so already-seen items are never re-surfaced
- **Hacker News**, **lobste.rs** — keyword search over stories and comments
- **Awesome lists** — repositories linked in curated awesome-\* lists
- **crates.io** — recently published crates and their upstream source repositories
- **13 curated news feeds** — security, cryptography, AI safety, Rust ecosystem; dep-free RSS/Atom, no API key required
- **CISA KEV** — exploited-in-the-wild CVEs, categorized by project area
- **OSV** — open-source vulnerability advisories by package (all ecosystems, keyless)
- **ProjectDiscovery vulnx** — vulnerability intelligence with EPSS scores and PoC availability

### What it produces

For each source, `mindala` stores findings in a local SQLite database (`mindala.db`), categorizes them toward the relevant project area, and surfaces them in a digest. Already-seen items are not re-discovered. Items with a verdict are frozen and not re-studied.

The **characteristics layer** (R8) shifts the unit of value from the repository to the **technique**: a characteristic is a concrete capability worth reimplementing in-house, independent of the source repo. The workflow is: find → study → extract technique → reimplement own (not copy). `--adopt` on a repository means "examined, contributed characteristic(s)"; the value lives in the extracted technique, not the repo itself.

Dependency intelligence (R6) cross-references the advisory feeds with the crates your projects actually consume, so you see only the advisories that apply to your stack.

The **reasoning layer** (R5 80/20) handles low-confidence categorizations: the keyword map handles clear cases automatically; the expert routes ambiguous or low-score items by judgement (`rutear`), and those manual routings are preserved across re-categorization runs.

### Measured quality

104 tests (96 unit with paired probe/control per detector + 8 end-to-end tests that launch the real binary) · `cargo clippy -D warnings` green · verified against live sources (GitHub, HN, lobste.rs, crates.io, all 13 feeds, CISA KEV, OSV).

---

## Español

Agregador de inteligencia técnica: descubre, categoriza y encola hallazgos de fuentes públicas para revisión y adopción humana. MIT. Rust.

---

## El código no se publica aquí

Desde agosto de 2026, el código de este proyecto **no se aloja en GitHub**, ni se distribuye por ningún registro de paquetes.

No es abandono ni un incidente: es una decisión. A lo largo de 2026 los registros de paquetes y las plataformas de código han sufrido ataques encadenados de cadena de suministro —Shai-Hulud, ChainDrop en agosto, extensiones maliciosas que se llevaron miles de repositorios privados—. Alojar aquí el código dejó de ser una decisión neutra.

**La licencia no cambia y el código se entrega a quien lo pida**, con su firma y su suma de verificación, sin coste, sin NDA, sin restricción sobre lo que publique y sin caducidad. Solicítalo en **xiliux.com**.

---

## Qué hace

Los *mindalá* eran los mercaderes muiscas de larga distancia: traían materiales valiosos de mercados lejanos para enriquecer a toda la sociedad. Esta herramienta hace lo mismo con técnicas de software: sale a fuentes públicas, encuentra lo valioso, lo categoriza hacia los proyectos que lo aprovechan y lo encola para que el criterio lo estudie.

**Diseño 80/20**: el programa descubre, categoriza y encola (el 80% mecánico); el criterio (Claude-en-el-loop) estudia el fuente, respeta la licencia y decide adoptar o descartar (el 20% que juzga). El juicio no se automatiza.

### Fuentes de inteligencia

- **GitHub** — búsqueda por topic, lenguaje, estrellas y actividad reciente; dedup por id de repositorio para no re-descubrir lo ya visto
- **Hacker News**, **lobste.rs** — búsqueda por palabras clave
- **Awesome lists** — repositorios enlazados en listas awesome-\* curadas
- **crates.io** — crates publicados recientemente y sus repositorios de origen
- **13 feeds curados** — seguridad, criptografía, IA, ecosistema Rust; RSS/Atom dep-free, sin API key
- **CISA KEV** — CVEs explotados en el mundo real, categorizados por área de proyecto
- **OSV** — advisories de vulnerabilidades en código abierto por paquete (todos los ecosistemas, sin API key)
- **ProjectDiscovery vulnx** — inteligencia de vulnerabilidades con puntuación EPSS y disponibilidad de PoC

### Qué produce

Por cada fuente, `mindala` almacena hallazgos en una base de datos SQLite local (`mindala.db`), los categoriza hacia el área de proyecto correspondiente y los muestra en un digest. Los ítems ya vistos no se re-descubren; los que tienen veredicto quedan congelados y no se vuelven a estudiar.

La **capa de características** (R8) desplaza la unidad de valor del repositorio a la **técnica**: una característica es una capacidad concreta que vale reimplementar propia, independientemente del repo de origen. El flujo es: encontrar → estudiar → extraer técnica → reimplementar propio (no copiar). `--adoptar` sobre un repositorio significa "examinado, aportó características"; el valor vive en la técnica extraída, no en el repo.

La inteligencia de dependencias (R6) cruza los feeds de advisories con los crates que tus proyectos consumen, mostrando solo los advisories que aplican a tu stack.

La **capa de razonamiento** (R5 80/20) maneja las categorizaciones de baja confianza: el mapa de palabras resuelve los casos claros automáticamente; el criterio rutea por juicio los ítems ambiguos (`rutear`), y esos enrutamientos manuales se preservan en las re-categorizaciones.

### Calidad medida

104 pruebas (96 unitarias con parejas sonda/control por detector + 8 E2E que arrancan el binario real) · `cargo clippy -D warnings` verde · verificado contra fuentes reales (GitHub, HN, lobste.rs, crates.io, los 13 feeds, CISA KEV, OSV).

---

*mindala* — © 2026 Juan Carlos Isaza. Licencia **MIT**.
