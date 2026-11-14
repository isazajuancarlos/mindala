// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: MIT

//! El 80% que CATEGORIZA: dado un candidato, ¿a qué proyecto de Xiliux le sirve?
//!
//! Es una función PURA (candidato → destino + puntaje), sin red ni BD, para que
//! su par de pruebas la ejerza sin depender del mundo. El juicio de si la técnica
//! vale sigue siendo del criterio (el 20%); esto solo dirige el candidato al
//! banco de trabajo correcto.

use crate::modelo::Candidato;

/// Una regla del mapa de relevancia: un proyecto destino y las palabras clave que
/// lo señalan. El mapa es semilla y se amplía (ver `DISENO.md`).
struct Regla {
    destino: &'static str,
    claves: &'static [&'static str],
}

/// Cuando ninguna regla casa, el destino es este — y es honesto, no un relleno:
/// "no sé a quién le sirve" es información, no un default arbitrario (D20).
pub const SIN_CLASIFICAR: &str = "sin_clasificar";

/// El mapa de relevancia (semilla del `DISENO.md`). El orden fija el desempate:
/// ante puntaje igual, gana la regla declarada primero (determinista).
const MAPA: &[Regla] = &[
    // DESTINO `seguridad` — la intel de SEGURIDAD (sobre todo LLM: prompt injection,
    // exfiltración, jailbreak) para la DEFENSA VIVA: el hook `olfateador_ofuscacion`,
    // la skill `razonador` y el plugin `security-guidance`. NO es una carpeta de
    // proyecto: es un bucket de conocimiento. Va PRIMERO para ganar el desempate a
    // nexus (un escáner-LLM como garak es seguridad-LLM, no cazador de bounties).
    //
    // DISCIPLINA (por qué existe, para no volverlo una manguera): su digest existe para
    // CAZAR UNA CLASE NUEVA de ataque que el olfateador deba detectar —como pasó con
    // exfil-imagen (embrace-the-red → mindalá idea 01 → detector, 2026-09-28)—, NO para
    // leerse cada noticia. Es defensivo y con consumidor vivo; por eso pasa la prueba
    // "¿de qué entregable es parte?" (D37) que nexus/brain no pasaban.
    Regla {
        destino: "seguridad",
        claves: &[
            "llm-security",
            "ai-security",
            "prompt-injection",
            "jailbreak",
            "ai-red-team",
            "llm-red-team",
            "adversarial-attacks",
            // Formas EN PROSA (el heno de una noticia es su título en lenguaje natural,
            // no topics con guion): sin esto la intel de feeds caía en sin_clasificar
            // pese a estar mapeado el concepto (recall, medido 2026-09-29). Específicas
            // de ataque; se dejan fuera "prompt"/"llm"/"chatgpt" solas (IA general ≠ seguridad).
            "prompt injection",
            "data exfiltration",
            "exfiltration",
            "red teaming",
            "remote code execution",
            "privilege escalation",
            "waf bypass",
            "exploit",
            "malware",
            // Clase CADENA DE SUMINISTRO / backdoor / paquete malicioso: intel
            // defensiva que alimenta al olfateador/razonador (es el caso medido de
            // "Claude Code troyanizada con backdoor SSH" y "npm Firewall / Malicious
            // Packages", que caían en sin_clasificar, run 2026-10-30). Formas inequívocas
            // de ATAQUE (D23): se deja fuera "supply chain" a secas (prosa de logística);
            // se exige "supply chain attack". "package(s)" en plural por el titular real.
            "backdoor",
            "trojanized",
            "typosquat",
            "typosquatting",
            "supply chain attack",
            "malicious package",
            "malicious packages",
        ],
    },
    Regla {
        destino: "nexus",
        claves: &[
            "recon",
            "api-testing",
            "oracle",
            "fuzzing",
            "fuzzer",
            "bugbounty",
            "bug-bounty",
            "pentest",
            "pentesting",
            "scanner",
            "vulnerability",
            "idor",
            "bola",
            "ssrf",
            "authz",
            "broken-access-control",
            "offensive-security",
            // La seguridad de LLM y la intel de ataques (prosa) YA NO viven aquí: se
            // movieron al destino `seguridad` (declarado antes que nexus), porque nexus
            // es el CAZADOR ofensivo (apagado) y esa intel alimenta la defensa viva
            // (olfateador/razonador). nexus se queda con su vocabulario de recon/hunting.
        ],
    },
    Regla {
        destino: "quipu",
        claves: &[
            "cryptography",
            // "crypto" QUITADA: es polisémica (cryptoGRAPHY vs cryptoCURRENCY). Un bot
            // de trading casa quipu("crypto")=1 Y polymarket("trading")=1, empata, y
            // quipu gana por declararse antes → 13 repos de trading (pycryptobot/
            // StockSharp/barter-rs/lumibot…) cayeron en la cola de quipu, run
            // `(mindala quipu)` 2026-10-29. La criptografía real dice cryptography/
            // post-quantum/cipher/aead/kyber… (D23: enumerar lo que SÍ señala, lo
            // ambiguo a sin_clasificar; mismo criterio que "identity"/"game"/"zk-snark").
            "post-quantum",
            "pqc",
            "kyber",
            "dilithium",
            "signature",
            "kdf",
            "argon2",
            "encryption",
            "cipher",
            "aead",
            "zero-knowledge",
            "zk",
            // "zk-snark" QUITADA: "zk" ya la casa por frontera ("zk-snark" → zk + "-"),
            // así que tenerla contaba doble el mismo concepto (ver conteo por claves
            // DISTINTAS abajo). Igual criterio con toda pareja subconjunto.
            "lattice",
            "ml-kem",
            "ml-dsa",
        ],
    },
    Regla {
        destino: "bachue",
        claves: &[
            "authentication",
            "authorization",
            "oidc",
            "oauth",
            "oauth2",
            "sso",
            // "identity" QUITADA: es polisémica (identidad VISUAL de un design-system,
            // función identidad, etc.) y ruteaba repos de diseño a bachue. Un IdP real
            // dice oidc/oauth/sso/identity-provider (D23: enumerar lo que SÍ señala,
            // mandar lo ambiguo a sin_clasificar).
            "identity-provider",
            "idp",
            "jwt",
            "saml",
        ],
    },
    Regla {
        destino: "chuspa",
        claves: &[
            "passkey",
            "passkeys",
            "webauthn",
            "fido2",
            "password-manager",
            "credentials",
        ],
    },
    Regla {
        // boza se define por su FUNCIÓN (copiar/clonar/verificar/respaldar entre DOS
        // unidades), NO por su caja: tenía claves de toolkit (gtk/gnome/libadwaita) y
        // acaparaba cualquier app GNOME —Parabolic (yt-dlp) y varia (aria2) cayeron
        // aquí en vez de mirador porque el toolkit daba 3 claves y el dominio 1 (D23:
        // el falso positivo se arregla en la regla; 2026-10-31).
        destino: "boza",
        claves: &[
            "backup",
            "file-sync",
            "rsync",
            "disk-cloning",
            "file-copy",
            "data-integrity",
            "checksum",
            "reflink",
        ],
    },
    Regla {
        destino: "boi",
        claves: &[
            "htmx",
            "maud",
            "hypermedia",
            "server-rendered",
            "server-side-rendering",
            "html-over-the-wire",
            // Vocabulario de SISTEMA DE DISEÑO: boi ES el sistema de diseño de Xiliux
            // (boi.css, tokens muisca). Sin estas claves, los repos de design-system
            // se fugaban a bachue ("identity" visual) o tequendama ("dataset"/"scraping"
            // de tokens) — el falso negativo hermano del falso positivo (D23).
            "design-system",
            "design-systems",
            "design-tokens",
            "design-to-code",
            "dtcg",
        ],
    },
    Regla {
        destino: "tequendama",
        claves: &[
            "etl",
            "ingestion",
            "open-data",
            "opendata",
            "dataset",
            "scraping",
            // "web-scraping" QUITADA: "scraping" ya la casa por frontera; tenerla
            // hacía que el topic `web-scraping` contara 2 por un solo concepto.
            "data-pipeline",
        ],
    },
    Regla {
        destino: "validador-rips",
        claves: &[
            "healthcare",
            "hl7",
            "fhir",
            "compliance",
            "medical-records",
            "ehr",
            "emr",
        ],
    },
    Regla {
        destino: "polymarket",
        claves: &[
            "prediction-market",
            "trading",
            "arbitrage",
            "market-maker",
            "defi",
            "orderbook",
        ],
    },
    // DESTINO `chimini` — el juego/laboratorio de alquimia computacional (fusión de
    // elementos de la tabla periódica sobre datos reales). Lo que le sirve: datos y
    // visualización de QUÍMICA, tablas periódicas interactivas, cheminformática,
    // física nuclear, y el ángulo EDUCATIVO/divulgativo que es su propósito.
    //
    // DISCIPLINA (D23, enumerar lo que SÍ señala): se dejan fuera "game"/"elements"/
    // "physics"/"stem" SOLAS por polisémicas — "game" rutearía cualquier emulador
    // (ver control `nada_relevante_no_se_clasifica`), "elements" casa componentes de
    // UI, "stem" casa raíces de palabra. El dominio distintivo de chimini es la
    // QUÍMICA con datos reales, no "un juego" cualquiera.
    Regla {
        destino: "chimini",
        claves: &[
            "chemistry",
            "cheminformatics",
            "periodic-table",
            "molecule",
            "molecular",
            "chemical",
            "pubchem",
            "nuclear-physics",
            "science-education",
            "educational-games",
            "edtech",
        ],
    },
    // ─── Portafolio completo (directiva 2026-10-29: TODO proyecto de Xiliux debe ser
    // mejorable por mindalá). Rebanada 1: proyectos de dominio DISTINTO, hoy
    // incuberturables. Claves derivadas de su descripción en `conocimiento/MAPA.md`
    // (D20 — no inventadas), inequívocas (D23 — nada polisémico que colisione con un
    // destino de arriba). Los de dominio COMPARTIDO (medico/informes↔salud,
    // iraca/mohan/guaca↔quipu, proteo↔seguridad, autz↔nexus) esperan la rebanada 2
    // (ruteo multi-destino): darles fila ahora solo crea empates que pierden.
    Regla {
        destino: "tunjo",
        claves: &["chain-of-custody", "timestamping", "rfc3161", "tamper-evident", "digital-forensics", "notarization"],
    },
    Regla {
        destino: "chunsua",
        // "threshold-signature" NO: contiene "signature" (quipu) → pierde el empate (es
        // dominio cripto compartido; su ruteo fino espera la rebanada 2).
        claves: &["secret-sharing", "shamir", "key-escrow", "mpc"],
    },
    Regla {
        destino: "inventario",
        claves: &["invoicing", "e-invoicing", "billing", "point-of-sale", "erp", "accounting"],
    },
    Regla {
        destino: "chasqui",
        claves: &["whatsapp", "chatbot", "messaging-api", "omnichannel", "telephony"],
    },
    Regla {
        destino: "autocm",
        claves: &["social-media", "marketing-automation", "social-media-automation", "content-scheduling"],
    },
    Regla {
        destino: "agua",
        claves: &["hydrology", "hydrological", "geospatial", "gis", "remote-sensing"],
    },
    Regla {
        destino: "fenrir",
        claves: &["browser-automation", "web-automation", "browser-extension", "webdriver", "accessibility-tree"],
    },
    // mirilla es el ARNÉS DE PRUEBAS de navegador (Chromium sin cabeza por CDP sobre
    // tubería), NO el agente que automatiza (eso es fenrir, declarado antes). Por eso
    // sus claves son el vocabulario de TESTING E2E + CDP headless, DISJUNTO de las de
    // fenrir (automation/extension/webdriver/accessibility-tree): un repo de técnica
    // de pruebas de navegador va a mirilla; uno de automatización-agente, a fenrir. Se
    // deja fuera "accessibility-tree" (clave de fenrir, aunque mirilla también lo
    // produzca) y "cdp"/"e2e" SOLAS por polisémicas (D23: cdp=customer-data-platform,
    // e2e⊂end-to-end-encryption → quipu). Puppeteer/Playwright SON el dominio (los
    // análogos canónicos del CDP-sobre-tubería), no relleno (D20).
    Regla {
        destino: "mirilla",
        claves: &[
            "headless-chrome",
            "headless-browser",
            "chrome-devtools-protocol",
            "browser-testing",
            "end-to-end-testing",
            "e2e-testing",
            "puppeteer",
            "playwright",
        ],
    },
    Regla {
        destino: "bague",
        claves: &["scaffolding", "project-template", "boilerplate", "project-generator"],
    },
    Regla {
        destino: "huitaca",
        claves: &["egui", "immediate-mode-gui"],
    },
    Regla {
        destino: "mirador",
        claves: &["youtube", "video-player", "media-player", "yt-dlp"],
    },
    // boveda FOLDED (no es dominio distinto): "disk-encryption" contiene "encryption"
    // (quipu) → dominio cripto compartido; espera la rebanada 2 (multi-destino).
    Regla {
        destino: "cuchavira",
        claves: &["filesystem", "fuse", "ext4", "btrfs", "mount"],
    },
    // DESTINO `nemcatacoa` — el banco de pruebas en producción del vertical
    // alto-riesgo/adulto (Veluria): integra CUMPLIMIENTO + SEGURIDAD + la
    // plataforma tube/streaming sobre sistema propio. ABSORBIÓ a `chia` (2026-10-29):
    // chia era solo el cumplimiento de contenido (age-gate/CSAM), que es una PARTE
    // de nemcatacoa, no un dominio aparte — tenerlos separados partía el vertical en
    // dos destinos que compiten. Se conservan las claves de cumplimiento de chia y se
    // añade el dominio técnico propio: tube/streaming de video, pagos cripto y
    // geofencing. Claves inequívocas (D23): nada de "adult" o "crypto" solas; las de
    // streaming (`video-streaming`/`live-streaming`) no colisionan con las de mirador
    // (`video-player`/`media-player`) por palabra completa.
    Regla {
        destino: "nemcatacoa",
        claves: &[
            // cumplimiento de contenido (heredado de chia)
            "age-verification",
            "content-moderation",
            "csam-detection",
            "age-gate",
            // plataforma tube/streaming
            "adult-content",
            "video-streaming",
            "live-streaming",
            "hls",
            // pagos cripto del vertical
            "crypto-payments",
            // geofence de jurisdicción
            "geofencing",
        ],
    },
    Regla {
        destino: "guatavita",
        claves: &["igaming", "provably-fair", "slot-machine", "casino"],
    },
    Regla {
        destino: "bochica",
        claves: &["gdpr", "data-protection", "privacy-policy", "pdpa"],
    },
    Regla {
        destino: "escaner-seguridad",
        claves: &["stalkerware", "spyware", "endpoint-security", "mobile-security", "host-hardening"],
    },
    // script11 — endurecimiento/debloat/privacidad del SO WINDOWS (el script .ps1 de Win 11 Pro).
    // Claves ACOTADAS al SO Windows (D23: nada de `windows`/`security`/`hardening` sueltos, que
    // emparejarían ruido): `windows-hardening` ≠ `host-hardening` de escaner-seguridad (equipo
    // propio, no auditor). Dominio que mindalá NO cubría por su mapa (determinación de
    // win11ltsc/MEJORAS-SEGURIDAD §0); se abre como VETA DIRIGIDA, no automática.
    Regla {
        destino: "script11",
        claves: &["debloat", "windows-debloat", "windows-hardening", "windows-privacy", "appx", "ltsc", "cis-benchmark", "antispy"],
    },
    // Folded CON nicho limpio (distinguibles sin colisión): entran directo. El resto de
    // dominio compartido queda servido por su ANCHOR, que NO es un hueco sino lo correcto
    // (D21): autz⊂nexus (se extrajo de él), guaca⊂quipu (fachada), proteo⊂seguridad
    // (red-team-IA), mohan/iraca-2/3/4 ⊂ el nicho de verificación diferencial de `iraca`.
    Regla {
        destino: "informes",
        claves: &["regulatory-reporting", "tax-reporting", "xbrl", "edgar", "sec-filings", "10-k"],
    },
    // medico — la PLATAFORMA de historia clínica (registro clínico, imagen médica,
    // IHCE/RDA). Enlazado el 2026-11-03 por decisión de Juan, levantando la postergación
    // de "rebanada 2" SOLO para su nicho DISTINTIVO: las claves de abajo están LIBRES (no
    // las tiene validador-rips ni nadie) y son de REGISTRO/IMAGEN clínica, no de reporte.
    // Por eso NO crean el "empate que pierde" que temía el comentario de arriba: el eje
    // COMPARTIDO (healthcare/hl7/fhir/ehr/emr/medical-records/compliance) sigue siendo de
    // validador-rips —el validador RIPS/948, dominio de REPORTE/interoperabilidad—, y como
    // medico se declara DESPUÉS, un repo que case ambos lados (p. ej. dicom+fhir) empata y
    // lo gana validador-rips (regla declarada primero), que es lo correcto. medico solo se
    // lleva lo que es clínico-de-plataforma y NO de reporte. D20 (claves del dominio, no
    // inventadas), D23 (nada polisémico: fuera "health"/"clinical" a secas).
    Regla {
        destino: "medico",
        claves: &["dicom", "openehr", "health-records", "hospital-information-system"],
    },
    Regla {
        destino: "chaquen",
        claves: &["secret-scanning", "secret-detection", "credential-scanning", "gitleaks"],
    },
    // zaque — integridad de ARRANQUE y de archivos: sellar/verificar la cadena de arranque
    // (boot/firmware integrity, measured/secure boot, detección de bootkit) y monitoreo de
    // integridad de archivos (estilo tripwire/AIDE). Distinto de escaner-seguridad
    // (endpoint/mobile/stalkerware) y de chaquen (secretos). Claves inequívocas (D23): nada
    // de "uefi"/"tpm"/"integrity"/"boot" a secas (polisémicas) — solo las compuestas.
    Regla {
        destino: "zaque",
        claves: &[
            "boot-integrity",
            "secure-boot",
            "measured-boot",
            "bootkit",
            "file-integrity-monitoring",
            "integrity-monitoring",
            "tripwire",
            "firmware-integrity",
        ],
    },
    // iraca (y mohan dentro) = verificación diferencial de PRIMITIVAS CRIPTOGRÁFICAS. Sin
    // `differential-testing`: es un topic GENÉRICO de GitHub (HTTP, DNS, ORM, compiladores,
    // Minecraft…) y el 2026-11-06 la cola de iraca era 25/25 falsos positivos por él, ninguno
    // cripto (QDiff incluso por «quantum» ≠ post-cuántico). D23: la clave polisémica fuera;
    // un repo de diferencial genérico cae a `sin_clasificar` → `razonar`, que es lo correcto.
    // Solo claves que únicamente existen en el diferencial de cripto (D21).
    // Empate conocido: «cryptofuzz» + «fuzzing» empata con nexus y gana nexus (ver la prueba).
    Regla {
        destino: "iraca",
        claves: &["test-vectors", "acvp", "cavp", "known-answer-tests", "wycheproof", "cryptofuzz"],
    },
];

/// FALLBACK por FUENTE: algunas fuentes de R5 son MONO-DOMINIO —su dominio no está en
/// el título en prosa, pero la fuente entera lo fija—. Cuando el mapa de palabras sale
/// `sin_clasificar`, la fuente desempata: un preprint de IACR es criptografía aunque su
/// título sea «Leakage-Diagrams, Importance Sampling…». NO es relleno (D20): el dominio
/// es un DATO conocido (la fuente), no un defecto inventado. Enumera SOLO las fuentes
/// inequívocamente mono-dominio (D21/D23); una fuente mixta (the-hacker-news, simon-
/// willison, cisa-kev, trail-of-bits) NO entra aquí y sigue su curso a `razonar`.
#[must_use]
pub fn destino_por_fuente(fuente: &str) -> Option<&'static str> {
    match fuente {
        // Servidor de preprints de criptología: todo su contenido es cripto.
        "iacr-eprint" => Some("quipu"),
        // Blog de criptografía de Matthew Green: cripto.
        "cryptography-engineering" => Some("quipu"),
        // Blog de red-team de LLM (Johann Rehberger): intel de seguridad-LLM para la
        // defensa viva (olfateador/razonador) — de aquí nació la idea exfil-imagen.
        "embrace-the-red" => Some("seguridad"),
        // PortSwigger Research: técnica de seguridad WEB (SSRF, smuggling, XSS…) = el
        // dominio de nexus (el cazador), que consume esas técnicas para sus detectores.
        "portswigger" => Some("nexus"),
        _ => None,
    }
}

/// El resultado de categorizar: a dónde va el candidato y con cuánta fuerza.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clasificacion {
    pub destino: String,
    /// Número de palabras clave que casaron. 0 ⇒ `SIN_CLASIFICAR`.
    pub puntaje: i64,
}

/// Cuenta cuántas veces aparece `clave` como palabra completa dentro de `heno`.
/// Palabra completa: los bordes deben ser no-alfanuméricos, para que `zk` no case
/// dentro de `zksync-fork` como falso... — al revés: `zk` es topic propio; lo que
/// se evita es que `zk` case dentro de `blackbox`. Comparación en minúsculas.
fn cuenta_palabra(heno: &str, clave: &str) -> i64 {
    let mut n = 0;
    let heno = heno.as_bytes();
    let aguja = clave.as_bytes();
    if aguja.is_empty() {
        return 0;
    }
    let mut i = 0;
    while let Some(pos) = buscar_desde(heno, aguja, i) {
        let antes_ok = pos == 0 || !es_palabra(heno[pos - 1]);
        let fin = pos + aguja.len();
        let despues_ok = fin >= heno.len() || !es_palabra(heno[fin]);
        if antes_ok && despues_ok {
            n += 1;
        }
        i = pos + 1;
    }
    n
}

fn buscar_desde(heno: &[u8], aguja: &[u8], desde: usize) -> Option<usize> {
    if desde > heno.len() || aguja.len() > heno.len() {
        return None;
    }
    (desde..=heno.len().saturating_sub(aguja.len())).find(|&i| &heno[i..i + aguja.len()] == aguja)
}

fn es_palabra(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// ¿El repo es provablemente NO una fuente de técnica —una colección (awesome-list),
/// un tutorial, un roadmap, un cheatsheet—? Devuelve el motivo, o `None` si parece una
/// fuente real. Es la puerta de TIPO (como `nexus::tipo_no_app`): el eje ortogonal a la
/// madurez y a la relevancia —un awesome-list ⭐5000 es maduro y "cripto" y aun así no
/// se cosecha técnica de él (no hay implementación, solo enlaces)—.
///
/// Conservador (D21/D23): mira SOLO el nombre del repo y sus topics, NO la descripción
/// libre, porque "awesome"/"tutorial" en prosa ("an awesome crypto lib", "with a
/// tutorial") son del lenguaje natural y demotarían una fuente real. Estos repos SE
/// AUTO-IDENTIFICAN en el nombre (`awesome-x`, `x-tutorials`) o el topic, no en la
/// prosa. Enumera lo provablemente-no-fuente; lo dudoso sigue su curso (D23).
#[must_use]
pub fn es_no_fuente(c: &Candidato) -> Option<&'static str> {
    let nombre = c.nombre_completo.to_lowercase();
    let repo = nombre.rsplit('/').next().unwrap_or(&nombre);
    // nombre-del-repo + topics (NO la descripción, D21). Palabra completa.
    let heno = format!("{} {}", repo, c.topics.join(" ").to_lowercase());
    // (señal, motivo). El `-` de `awesome-x`/`x-tutorials` es frontera, así que casa
    // como palabra completa.
    const NO_FUENTE: &[(&str, &str)] = &[
        ("awesome", "lista curada (awesome-list), no una implementación"),
        ("tutorial", "material de tutorial, no una fuente de técnica"),
        ("tutorials", "material de tutorial, no una fuente de técnica"),
        ("roadmap", "roadmap de aprendizaje, no código de técnica"),
        ("cheatsheet", "cheatsheet, no una implementación"),
        // "awesome-list" NO va: "awesome" ya la casa por frontera (D23, subconjunto).
    ];
    NO_FUENTE
        .iter()
        .find(|(s, _)| cuenta_palabra(&heno, s) > 0)
        .map(|(_, m)| *m)
}

/// Categoriza un candidato contra el mapa de relevancia. Suma, por cada regla, las
/// palabras clave que aparecen en sus topics + lenguaje + descripción; el mayor
/// puntaje gana. Empate ⇒ la regla declarada primero. Cero ⇒ `SIN_CLASIFICAR`.
#[must_use]
pub fn categorizar(c: &Candidato) -> Clasificacion {
    // Puerta de TIPO antes del scoring: una colección/tutorial NO es fuente de técnica
    // aunque sus keywords casen (awesome-systematic-trading, lammps-tutorials caían en
    // quipu, run 2026-10-29). Demota a sin_clasificar — honesto, no un hallazgo (D20).
    if es_no_fuente(c).is_some() {
        return Clasificacion {
            destino: SIN_CLASIFICAR.to_string(),
            puntaje: 0,
        };
    }
    // El "heno" donde se buscan las agujas: topics (señal fuerte), lenguaje y
    // descripción, todo en minúsculas y separado por espacios.
    let mut heno = c.topics.join(" ");
    heno.push(' ');
    heno.push_str(&c.lenguaje.to_lowercase());
    heno.push(' ');
    heno.push_str(&c.descripcion.to_lowercase());
    categorizar_texto(&heno)
}

/// Categoriza cualquier TEXTO contra el mapa de relevancia (el núcleo compartido:
/// lo usan `categorizar` para un repo y R5 para un ítem de conocimiento, D9). Suma,
/// por regla, las palabras clave presentes; el mayor puntaje gana, empate ⇒ la
/// primera regla declarada, cero ⇒ `SIN_CLASIFICAR`. El `heno` debe venir en minúsculas.
#[must_use]
pub fn categorizar_texto(heno: &str) -> Clasificacion {
    let mut mejor = Clasificacion {
        destino: SIN_CLASIFICAR.to_string(),
        puntaje: 0,
    };
    for regla in MAPA {
        // Puntaje = número de claves DISTINTAS de la regla presentes en el heno, no la
        // suma de ocurrencias. Una misma clave que aparece en el topic Y en la
        // descripción (o dos claves que son subconjunto una de otra) señalaban UN
        // concepto y contaban 2+, produciendo falsos puntaje-2. La AMPLITUD del match
        // (cuántas señales distintas) mide relevancia mejor que la FRECUENCIA.
        let puntaje: i64 = regla
            .claves
            .iter()
            .filter(|k| cuenta_palabra(heno, k) > 0)
            .count() as i64;
        // `>` y no `>=`: el primer empate declarado se conserva (determinista).
        if puntaje > mejor.puntaje {
            mejor = Clasificacion {
                destino: regla.destino.to_string(),
                puntaje,
            };
        }
    }
    mejor
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_diferencial_generico_no_va_a_iraca_pero_el_cripto_si() {
        // Pareja D33 con TEXTO REAL de la cola del 2026-11-06 (25/25 falsos positivos).
        // Rojo con la regla vieja (`differential-testing` como clave de iraca).
        for heno in [
            "differential-testing Differential testing framework for HTTP implementations",
            "differential-testing QDiff: Differential Testing of Quantum Software Stacks",
            "differential-testing Automatic Test generator and Differential Tester for DNS",
        ] {
            assert_ne!(categorizar_texto(heno).destino, "iraca", "«{heno}» no es cripto");
        }
        for heno in [
            "cryptofuzz differential-testing",
            "wycheproof Project Wycheproof tests crypto libraries against known attacks",
            "acvp known-answer-tests ML-KEM",
        ] {
            assert_eq!(categorizar_texto(heno).destino, "iraca", "«{heno}» SÍ es diferencial cripto");
        }
        // LÍMITE CONOCIDO, fijado aquí para que se vea y no se esconda: con «fuzzing» en el
        // texto, nexus (clave `fuzzing`) EMPATA 1–1 con iraca (`cryptofuzz`) y gana nexus por
        // declararse antes. Un fuzzer diferencial de cripto así cae en la cola de nexus y se
        // re-rutea con `rutear` (el 20 % que razona), no se pierde.
        assert_eq!(categorizar_texto("cryptofuzz fuzzing cryptographic libraries").destino, "nexus");
    }

    fn candidato(topics: &[&str], lenguaje: &str, desc: &str) -> Candidato {
        Candidato {
            id_github: 1,
            nombre_completo: "org/repo".into(),
            url: "https://github.com/org/repo".into(),
            descripcion: desc.into(),
            lenguaje: lenguaje.into(),
            topics: topics.iter().map(|s| (*s).to_string()).collect(),
            estrellas: 10,
            pushed_at: "2026-09-01T00:00:00Z".into(),
            licencia: "MIT".into(),
        }
    }

    // Como `candidato` pero variando el NOMBRE (la puerta de tipo mira nombre+topics).
    fn candidato_nombrado(nombre: &str, topics: &[&str], desc: &str) -> Candidato {
        Candidato {
            nombre_completo: nombre.into(),
            ..candidato(topics, "", desc)
        }
    }

    // AGUJA (D33): una COLECCIÓN/tutorial de "crypto" NO es fuente de técnica →
    // sin_clasificar, aunque sus keywords casen quipu. MUTANTE = sin puerta de tipo:
    // daba quipu. Casos reales de la cola de quipu (run 2026-10-29): awesome-systematic-
    // trading (⭐5325) y lammps-tutorials (⭐503, "lattice"→cripto). La madurez NO los
    // caza (son de muchas estrellas); esta puerta sí.
    #[test]
    fn coleccion_o_tutorial_no_es_fuente() {
        let awesome = candidato_nombrado("x/awesome-cryptography", &["cryptography"], "a curated list");
        assert_eq!(categorizar(&awesome).destino, SIN_CLASIFICAR);
        let tut = candidato_nombrado("x/lammps-tutorials", &["lattice"], "molecular dynamics tutorials");
        assert_eq!(categorizar(&tut).destino, SIN_CLASIFICAR);
    }

    // CONTROL (D21, no sobre-demotar): "awesome"/"tutorial" en la DESCRIPCIÓN de una
    // librería real NO la demota — la puerta mira nombre+topics, NO prosa. Si mirara la
    // descripción, esto se pondría rojo (y demotaría fuentes reales).
    #[test]
    fn libreria_real_con_awesome_en_prosa_sigue_siendo_fuente() {
        let c = candidato_nombrado(
            "orion-rs/orion",
            &["cryptography", "post-quantum"],
            "an awesome, easy pure-Rust crypto library with a tutorial",
        );
        assert!(es_no_fuente(&c).is_none(), "no debe demotar por prosa: {:?}", es_no_fuente(&c));
        assert_eq!(categorizar(&c).destino, "quipu");
    }

    // AGUJA (D33): un candidato de cripto DEBE ir a quipu.
    #[test]
    fn cripto_va_a_quipu() {
        let c = candidato(&["cryptography", "post-quantum"], "Rust", "A KDF library");
        let r = categorizar(&c);
        assert_eq!(r.destino, "quipu");
        assert!(r.puntaje >= 2, "puntaje={}", r.puntaje);
    }

    // AGUJA: un candidato de recon DEBE ir a nexus.
    #[test]
    fn recon_va_a_nexus() {
        let c = candidato(&["recon", "bug-bounty"], "Go", "IDOR scanner");
        assert_eq!(categorizar(&c).destino, "nexus");
    }

    // AGUJA: seguridad de LLM va al destino `seguridad` (no a nexus, el cazador
    // apagado). MUTANTE (mapa con LLM en nexus): daba nexus. Discrimina.
    #[test]
    fn seguridad_llm_va_a_seguridad() {
        let c = candidato(
            &["llm-security", "prompt-injection"],
            "Python",
            "genAI red team",
        );
        assert_eq!(categorizar(&c).destino, "seguridad");
    }

    // CONTROL de la frontera nexus/seguridad: un escáner-LLM (garak) casa "scanner"
    // (nexus) Y "llm-security"/"jailbreak" (seguridad); `seguridad` va primero y con
    // más señales ⇒ gana seguridad, no el cazador.
    #[test]
    fn escaner_llm_gana_seguridad_no_nexus() {
        let c = candidato(&["scanner", "llm-security", "jailbreak"], "Python", "LLM red team scanner");
        assert_eq!(categorizar(&c).destino, "seguridad");
    }

    // CONTROL inverso: un recon puro (sin nada de LLM) sigue yendo a nexus.
    #[test]
    fn recon_puro_sigue_en_nexus() {
        let c = candidato(&["recon", "scanner", "ssrf"], "Go", "subdomain recon and ssrf");
        assert_eq!(categorizar(&c).destino, "nexus");
    }

    // CONTROL (D33): un candidato que no casa NADA cae en sin_clasificar por la vía
    // real (puntaje 0), no por un default silencioso. Si el mapa se cegara y todo
    // cayera aquí, la aguja de arriba se pondría roja — discriminan.
    #[test]
    fn nada_relevante_no_se_clasifica() {
        let c = candidato(&["game", "gameboy"], "C", "A retro emulator for fun");
        let r = categorizar(&c);
        assert_eq!(r.destino, SIN_CLASIFICAR);
        assert_eq!(r.puntaje, 0);
    }

    // AGUJA (D33): un repo de PLATAFORMA clínica (imagen/registro) va a medico. MUTANTE =
    // versión anterior (sin regla medico, `dicom`/`openehr` libres): daba sin_clasificar.
    // Discrimina — enlazado 2026-11-03.
    #[test]
    fn plataforma_clinica_va_a_medico() {
        let c = candidato(
            &["dicom", "openehr", "health-records"],
            "Rust",
            "A hospital-information-system for electronic patient records",
        );
        assert_eq!(categorizar(&c).destino, "medico");
    }

    // CONTROL PAREADO (D23/D33): medico NO le roba a validador-rips el dominio de REPORTE.
    // Un repo de interoperabilidad fhir/hl7 sigue en validador-rips; y un repo que case
    // AMBOS lados (dicom + fhir) empata y lo gana validador-rips por declararse primero.
    // Si medico tuviera por error una clave del eje compartido, esto saldría rojo.
    #[test]
    fn reporte_salud_sigue_en_validador_rips_no_lo_roba_medico() {
        let reporte = candidato(&["fhir", "hl7", "healthcare"], "", "RIPS/948 validator");
        assert_eq!(categorizar(&reporte).destino, "validador-rips");
        // empate dicom(medico) + fhir(validador-rips): gana el declarado primero.
        let ambos = candidato(&["dicom", "fhir"], "", "imaging gateway with fhir export");
        assert_eq!(categorizar(&ambos).destino, "validador-rips");
    }

    // CONTROL de frontera de palabra: `zk` NO debe casar dentro de otra palabra.
    #[test]
    fn palabra_completa_no_subcadena() {
        // "blackbox" contiene "bo"/"ck" pero ninguna clave completa; "workzone"
        // contiene "zk"... no: "workzone" -> w-o-r-k-z-o-n-e, sí contiene "kz" no "zk".
        // Uso un caso claro: "gtkzk" NO debe dar ni gtk ni zk como palabra completa.
        assert_eq!(cuenta_palabra("gtkzk something", "gtk"), 0);
        assert_eq!(cuenta_palabra("gtkzk something", "zk"), 0);
        // pero como topic propio sí:
        assert_eq!(cuenta_palabra("gtk something", "gtk"), 1);
    }

    // AGUJA (D23/D33): un repo de SISTEMA DE DISEÑO va a boi, aunque su descripción
    // diga "identity" (visual) o use scraping. Es el caso real `tinte`/`design-extract`
    // que antes se fugaba a bachue/tequendama. MUTANTE = versión anterior (sin claves
    // design en boi, con "identity" en bachue): daba bachue. Discrimina.
    #[test]
    fn design_system_va_a_boi_no_a_auth() {
        let c = candidato(
            &["design-system", "design-tokens", "dtcg"],
            "TypeScript",
            "Compile your design system. Extract an identity from any reference.",
        );
        assert_eq!(categorizar(&c).destino, "boi");
    }

    // CONTROL de la clave polisémica: "identity" SOLA ya no rutea a bachue (cae en
    // sin_clasificar). MUTANTE (con "identity" en bachue): daba bachue puntaje 1.
    #[test]
    fn identity_visual_sola_no_es_auth() {
        let c = candidato(&["branding"], "", "extract the brand identity");
        assert_eq!(categorizar(&c).destino, SIN_CLASIFICAR);
    }

    // AGUJA del CONTEO POR CLAVES DISTINTAS: una misma clave en topic Y descripción
    // cuenta 1, no 2. MUTANTE (suma de ocurrencias): daba puntaje 2. Discrimina.
    #[test]
    fn clave_repetida_cuenta_una_vez() {
        let c = candidato(&["dataset"], "", "a public dataset for an open-data data-pipeline");
        let r = categorizar(&c);
        assert_eq!(r.destino, "tequendama");
        // dataset(topic+desc) + open-data + data-pipeline... "open-data" y "data-pipeline"
        // son claves distintas presentes; "dataset" cuenta UNA. Sin el arreglo, "dataset"
        // contaría 2 y el puntaje sería mayor. Verificamos que "dataset" no infla:
        // 3 claves distintas presentes (dataset, open-data, data-pipeline) = 3, no 4.
        assert_eq!(r.puntaje, 3, "puntaje={} (con doble conteo daría 4)", r.puntaje);
    }

    // CONTROL del subconjunto: el topic `web-scraping` cuenta como UNA señal ("scraping"),
    // no dos. MUTANTE (con "web-scraping" en el mapa): daba 2 para tequendama.
    #[test]
    fn web_scraping_no_cuenta_doble() {
        let c = candidato(&["web-scraping"], "", "scrapes sites");
        // solo "scraping" casa (una clave distinta); el diseño no aplica aquí.
        assert_eq!(categorizar(&c).puntaje, 1);
    }

    // AGUJA (recall en PROSA): un título de noticia en lenguaje natural sobre un
    // ataque ya mapeado va a nexus. Antes caía en sin_clasificar porque el mapa solo
    // tenía la forma con guion. MUTANTE (sin claves-prosa): sin_clasificar. Discrimina.
    #[test]
    fn noticia_en_prosa_va_a_seguridad() {
        // categorizar_texto es la MISMA costura que usa el feed (título en minúsculas).
        let r = categorizar_texto("new prompt injection technique exfiltrates chat data");
        assert_eq!(r.destino, "seguridad");
    }

    // CONTROL: una noticia de IA GENERAL (sin vocabulario de ataque) NO se fuerza a
    // nexus — "prompt"/"llm" solas quedaron fuera a propósito. Cae en sin_clasificar.
    #[test]
    fn noticia_ia_general_no_es_seguridad() {
        let r = categorizar_texto("a new llm prompt engineering guide for chatgpt");
        assert_eq!(r.destino, SIN_CLASIFICAR);
    }

    // AGUJA (D33): una noticia de ataque a la CADENA DE SUMINISTRO va a `seguridad`
    // (intel defensiva). Es el caso real medido (run 2026-10-30): "Official Claude Code
    // Extension on Cursor Marketplace Trojanized with Persistent SSH Backdoor" caía en
    // sin_clasificar. MUTANTE = la versión anterior (sin la clase, `git show HEAD`):
    // sin_clasificar. Por la MISMA costura del feed (categorizar_texto, minúsculas).
    #[test]
    fn noticia_cadena_de_suministro_va_a_seguridad() {
        let r = categorizar_texto(
            "official claude code extension trojanized with persistent ssh backdoor",
        );
        assert_eq!(r.destino, "seguridad", "{r:?}");
        // el titular de npm (plural): "block malicious packages before installation"
        assert_eq!(
            categorizar_texto("github launches npm firewall to block malicious packages").destino,
            "seguridad",
        );
    }

    // CONTROL (D21/D23, no sobre-disparar): "supply chain" en prosa de LOGÍSTICA NO
    // es seguridad — se exige "supply chain attack". Si hubiéramos metido "supply chain"
    // a secas, esto se pondría rojo (y rutearía artículos de ERP/logística a seguridad).
    #[test]
    fn supply_chain_logistico_no_es_seguridad() {
        let r = categorizar_texto("a new supply chain management tool for warehouse logistics");
        assert_eq!(r.destino, SIN_CLASIFICAR, "{r:?}");
    }

    // AGUJA (D33): un repo de QUÍMICA/tabla periódica va a chimini.
    #[test]
    fn quimica_va_a_chimini() {
        let c = candidato(
            &["chemistry", "periodic-table"],
            "Rust",
            "An interactive periodic table for science education",
        );
        let r = categorizar(&c);
        assert_eq!(r.destino, "chimini");
        assert!(r.puntaje >= 2, "puntaje={}", r.puntaje);
    }

    // CONTROL (D33): "game" SOLA no basta para chimini — un emulador retro sigue en
    // sin_clasificar (es el mismo candidato del control `nada_relevante...`). MUTANTE
    // (añadir "game" a las claves de chimini): este pasaría a chimini. Discrimina:
    // chimini se gana por el DOMINIO químico, no por ser "un juego".
    #[test]
    fn juego_sin_quimica_no_es_chimini() {
        let c = candidato(&["game", "gameboy"], "C", "A retro emulator for fun");
        assert_eq!(categorizar(&c).destino, SIN_CLASIFICAR);
    }

    // AGUJA (D33): un bot de cripto-MONEDA (trading) NO debe ir a quipu. La clave
    // polisémica "crypto" (cryptocurrency) lo llevaba ahí: casa quipu("crypto")=1 Y
    // polymarket("trading")=1, empata a 1, y quipu gana por declararse antes. Es el
    // caso real del run `(mindala quipu)` 2026-10-29 (pycryptobot/StockSharp/barter-rs/
    // lumibot en la cola de quipu). MUTANTE = la versión CON "crypto" en quipu: daba
    // quipu. Discrimina por la vía real (categorizar).
    #[test]
    fn cripto_moneda_trading_no_va_a_quipu() {
        let c = candidato(&["crypto", "trading", "bitcoin"], "Python", "A cryptocurrency trading bot");
        let r = categorizar(&c);
        assert_ne!(r.destino, "quipu", "un trading bot NO es quipu: {r:?}");
        assert_eq!(r.destino, "polymarket", "trading es su casa real: {r:?}");
    }

    // CONTROL (la aguja de quipu sigue viva): la criptografía REAL sigue yendo a quipu
    // por sus claves inequívocas (cryptography/post-quantum/kyber/cipher/aead/ml-kem…),
    // NO por "crypto". Si quitar "crypto" cegara quipu, esto se pondría rojo.
    #[test]
    fn criptografia_real_sigue_en_quipu_sin_la_clave_crypto() {
        let c = candidato(&["post-quantum", "kyber"], "Rust", "ML-KEM encryption and cipher library");
        assert_eq!(categorizar(&c).destino, "quipu");
    }

    // COLISIÓN inventario↔informes (D23): un repo de análisis de informes SEC/EDGAR
    // (edgar_analytics real) casa "accounting" (inventario, declarada antes) con puntaje 1
    // y "xbrl" (informes) con puntaje 1 → el empate lo ganaba inventario, que es el destino
    // EQUIVOCADO. Las claves SEC-específicas (edgar/sec-filings/10-k) suben informes a 3 y lo
    // llevan a su casa. MUTANTE = el mapa sin esas claves (lo ruteaba a inventario).
    #[test]
    fn analisis_edgar_sec_va_a_informes_no_a_inventario() {
        let c = candidato(
            &["accounting", "edgar", "sec-filings", "10-k", "xbrl", "gaap"],
            "Python",
            "Extracting, Analyzing, and Forecasting SEC EDGAR Filings",
        );
        assert_eq!(categorizar(&c).destino, "informes");
    }

    // COLISIÓN script11↔escaner-seguridad (D23): el debloat/privacidad del SO Windows va a
    // script11, pero un repo de auditoría/anti-stalkerware (host-hardening) sigue en
    // escaner-seguridad. `windows-hardening` ≠ `host-hardening`: la distinción es a propósito.
    #[test]
    fn debloat_windows_va_a_script11_no_a_escaner() {
        let deb = candidato(&["debloat", "windows-privacy", "appx"], "PowerShell", "Debloat and harden Windows 11");
        assert_eq!(categorizar(&deb).destino, "script11");
        let aud = candidato(&["stalkerware", "host-hardening", "endpoint-security"], "Python", "Detect stalkerware on a host");
        assert_eq!(categorizar(&aud).destino, "escaner-seguridad", "el auditor de host NO lo roba script11");
    }

    // AGUJA (D33, directiva "todo proyecto mejorable"): cada destino nuevo se ALCANZA
    // por su clave firma, y por la vía real (categorizar_texto). Es además el control
    // de COLISIÓN: si una clave nueva casara un destino declarado antes, su fila
    // perdería el empate y esto saldría rojo nombrando el destino equivocado.
    #[test]
    fn cada_destino_nuevo_se_alcanza() {
        let casos: &[(&str, &str)] = &[
            ("chain-of-custody", "tunjo"),
            ("secret-sharing", "chunsua"),
            ("e-invoicing", "inventario"),
            ("whatsapp", "chasqui"),
            ("marketing-automation", "autocm"),
            ("hydrology", "agua"),
            ("browser-automation", "fenrir"),
            ("chrome-devtools-protocol", "mirilla"),
            ("scaffolding", "bague"),
            ("egui", "huitaca"),
            ("backup", "boza"),
            ("yt-dlp", "mirador"),
            ("fuse", "cuchavira"),
            ("age-verification", "nemcatacoa"),
            ("hls", "nemcatacoa"),
            ("provably-fair", "guatavita"),
            ("gdpr", "bochica"),
            ("stalkerware", "escaner-seguridad"),
            ("debloat", "script11"),
            ("regulatory-reporting", "informes"),
            ("secret-scanning", "chaquen"),
            ("boot-integrity", "zaque"),
            ("wycheproof", "iraca"),
        ];
        for (clave, destino) in casos {
            assert_eq!(
                categorizar_texto(clave).destino,
                *destino,
                "la clave «{clave}» debe rutear a {destino}",
            );
        }
    }

    // AGUJA (D33): un repo de integridad de ARRANQUE va a zaque. MUTANTE = sin la regla
    // zaque (git show HEAD), cae en sin_clasificar (ninguna de sus claves es de otro
    // destino). CONTROL (D23): los dominios vecinos NO se los traga zaque.
    #[test]
    fn integridad_de_arranque_va_a_zaque() {
        let c = candidato(
            &["secure-boot", "measured-boot", "bootkit"],
            "Rust",
            "detect boot chain tampering: measured boot and secure boot integrity verification",
        );
        let r = categorizar(&c);
        assert_eq!(r.destino, "zaque", "{r:?}");
        assert!(r.puntaje >= 2, "puntaje={}", r.puntaje);
        // CONTROL: secreto→chaquen, endpoint/stalkerware→escaner-seguridad, NO zaque.
        assert_eq!(
            categorizar(&candidato(&["secret-scanning", "gitleaks"], "Go", "find leaked secrets")).destino,
            "chaquen"
        );
        assert_eq!(
            categorizar(&candidato(&["stalkerware", "endpoint-security"], "Kotlin", "spyware scanner")).destino,
            "escaner-seguridad"
        );
    }

    // AGUJA (D33): boza se define por su FUNCIÓN (copiar/verificar entre unidades), no
    // por el toolkit. Un repo de respaldo/clonado va a boza. MUTANTE = la regla vieja
    // (git show HEAD, claves gtk/gnome/libadwaita): con ella la app de copia SIN topics
    // GTK caía en sin_clasificar, y Parabolic/varia (GTK + yt-dlp) caían en boza en vez
    // de mirador. CONTROL (D23, el falso positivo que compartía causa): una app GTK que
    // baja vídeo va a mirador, y una app GNOME sin dominio Xiliux cae en sin_clasificar
    // —boza ya NO acapara por la caja—.
    #[test]
    fn boza_se_define_por_la_funcion_no_por_gtk() {
        // AGUJA: copia/verificación entre unidades, SIN una sola clave de toolkit.
        let copia = candidato(
            &["backup", "rsync", "file-sync", "data-integrity"],
            "Rust",
            "fast verified copy and clone between two drives, reflink and checksum",
        );
        let r = categorizar(&copia);
        assert_eq!(r.destino, "boza", "{r:?}");
        assert!(r.puntaje >= 2, "puntaje={}", r.puntaje);
        // CONTROL: Parabolic (GTK + yt-dlp) ahora va a mirador, NO a boza.
        let parabolic = candidato(
            &["gtk4", "gnome", "libadwaita", "yt-dlp", "youtube"],
            "C#",
            "Download web video and audio",
        );
        assert_eq!(categorizar(&parabolic).destino, "mirador", "Parabolic debe ir a mirador");
        // CONTROL: una app GNOME sin dominio Xiliux ya no cae en boza por la caja.
        let gtk_generica = candidato(
            &["gtk4", "gnome", "libadwaita", "desktop"],
            "Rust",
            "a simple GNOME text editor",
        );
        assert_eq!(
            categorizar(&gtk_generica).destino,
            SIN_CLASIFICAR,
            "una app GTK genérica no tiene por qué caer en boza"
        );
    }

    // AGUJA (D33): un arnés de pruebas de navegador headless va a mirilla, NO a fenrir.
    // MUTANTE = sin la regla mirilla (git show HEAD): el mismo candidato caía en
    // sin_clasificar (ninguna de sus claves es de fenrir). Discrimina por la vía real.
    #[test]
    fn arnes_e2e_headless_va_a_mirilla() {
        let c = candidato(
            &["end-to-end-testing", "headless-chrome", "puppeteer"],
            "Rust",
            "A tiny headless Chrome driver over the Chrome DevTools Protocol for e2e tests",
        );
        let r = categorizar(&c);
        assert_eq!(r.destino, "mirilla", "arnés E2E es mirilla: {r:?}");
        assert!(r.puntaje >= 2, "puntaje={}", r.puntaje);
    }

    // CONTROL (D23, no robarle el dominio a fenrir): un repo de AUTOMATIZACIÓN-agente
    // (el dominio de fenrir) sin vocabulario de TESTING sigue en fenrir, no en mirilla.
    // Si mirilla hubiera tomado claves de automatización, esto se pondría rojo.
    #[test]
    fn automatizacion_agente_sigue_en_fenrir_no_mirilla() {
        let c = candidato(
            &["browser-automation", "web-automation", "webdriver"],
            "TypeScript",
            "drive the browser as an agent",
        );
        assert_eq!(categorizar(&c).destino, "fenrir");
    }

    // AGUJA (D33): un tube/streaming de video adulto va a nemcatacoa, que absorbió
    // a chia. MUTANTE = la versión anterior (regla `chia` con solo las 4 claves de
    // cumplimiento): "video-streaming"/"hls" no casaban nada → sin_clasificar.
    #[test]
    fn plataforma_adulta_va_a_nemcatacoa() {
        let c = candidato(
            &["adult-content", "video-streaming", "hls"],
            "Rust",
            "self-hosted adult tube with HLS live-streaming and age-gate",
        );
        let r = categorizar(&c);
        assert_eq!(r.destino, "nemcatacoa", "{r:?}");
        assert!(r.puntaje >= 2, "puntaje={}", r.puntaje);
    }

    // CONTROL (D23, no robar dominios): nemcatacoa NO se traga un reproductor de
    // vídeo normal (mirador: `video-player`/`media-player`/`yt-dlp`) ni la
    // criptografía real (quipu). Si sus claves de streaming colisionaran con esas,
    // esto saldría rojo nombrando el destino equivocado.
    #[test]
    fn nemcatacoa_no_roba_mirador_ni_quipu() {
        let reproductor = candidato(&["video-player", "media-player", "yt-dlp"], "Rust", "a YouTube player");
        assert_eq!(categorizar(&reproductor).destino, "mirador");
        let cripto = candidato(&["post-quantum", "kyber"], "Rust", "ML-KEM cipher");
        assert_eq!(categorizar(&cripto).destino, "quipu");
    }

    // AGUJA (D33): el fallback por FUENTE rutea una fuente mono-dominio. CONTROL: una
    // fuente MIXTA no se fuerza (sigue a razonar). Es el desempate que el título en prosa
    // no da: un preprint de IACR es cripto aunque su título no diga "cryptography".
    #[test]
    fn fallback_por_fuente_solo_mono_dominio() {
        assert_eq!(destino_por_fuente("iacr-eprint"), Some("quipu"));
        assert_eq!(destino_por_fuente("embrace-the-red"), Some("seguridad"));
        assert_eq!(destino_por_fuente("portswigger"), Some("nexus"));
        // Mixtas: NO se fuerzan.
        assert_eq!(destino_por_fuente("the-hacker-news"), None);
        assert_eq!(destino_por_fuente("simon-willison"), None);
        assert_eq!(destino_por_fuente("cisa-kev"), None);
    }

    // Desempate determinista: ante igual puntaje gana la regla declarada primero.
    #[test]
    fn empate_gana_el_primero() {
        // "oauth" (bachue) y "webauthn" (chuspa): un topic de cada uno = 1 y 1.
        // bachue se declara antes que chuspa ⇒ gana bachue.
        let c = candidato(&["oauth", "webauthn"], "", "");
        assert_eq!(categorizar(&c).destino, "bachue");
    }
}
