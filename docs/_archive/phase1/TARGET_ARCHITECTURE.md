# TARGET_ARCHITECTURE — arquitectura propuesta (Fase 1)

> Read-only document. No se toca código todavía. Producto de Fase 1.
> Decisiones base tomadas con el usuario:
> - WIP (M4 agentic, M5 DLQ, M6 invariants, local_llm, etc.) → **integrar al rediseño como baseline**.
> - DSL → **Plataforma** (clientes pueden pedir features/mejoras).
> - MCP → **Plataforma** (clientes pueden pedir tools/mejoras).
> - GNN v2 → **feature flag `gnn-v2-experimental`** + gate al carga del modelo.

---

## 1. Modelo de capas (shearing layers)

Tres capas, cada una con su paradigma. El rediseño **no unifica SOLID**; cada capa aplica lo que le corresponde.

```
┌───────────────────────────────────────────────────────────────────┐
│                           GLUE                                    │
│  Paradigma: procedural. YAGNI agresivo. Código obvio.             │
│  ├─ apps/tauri/            (ex app/src-tauri)                     │
│  │    · commands: shims 1:1 a plataforma                          │
│  │    · http_api: router Axum split por dominio                   │
│  │    · frontend (React + Cytoscape)                              │
│  ├─ apps/cli/              (ex graph_hunter_cli)                  │
│  │    · stdin/stdout JSON protocol                                │
│  └─ scripts/, demo_data/, configs/                                │
└────────────▲──────────────────────────────────────────────────────┘
             │ sólo llama a PLATAFORMA (nunca directo a NÚCLEO)
             │
┌────────────┴──────────────────────────────────────────────────────┐
│                         PLATAFORMA                                │
│  Paradigma: OOP/trait-oriented. SOLID (OCP, ISP). Extensibilidad │
│  de primera clase. API pública versionada (semver).               │
│                                                                   │
│  · platform/api/          (ex graph_hunter_api)                   │
│       GraphHunterApi façade + 23+ operations + DTOs              │
│                                                                   │
│  · platform/canonical/    (OCSF projection, provenance)           │
│  · platform/vrl/          (FieldConfig → VRL compiler)            │
│  · platform/constrained-decode/ (LLM safety guardrail)            │
│                                                                   │
│  · platform/parsers/      (nuevo crate: LogParser trait + 7 impl)│
│  · platform/sources/      (nuevo crate: LogSource trait + conn.) │
│  · platform/siem/         (Sentinel streaming — rompe ciclo CLI↔API) │
│                                                                   │
│  · platform/dsl/          (nuevo crate: parser + grammar v1 +     │
│                            extension registry)                    │
│                                                                   │
│  · platform/mcp/          (TS server, Tool trait, versioning)     │
│                                                                   │
│  · platform/local-llm/    (trait LocalLlm + Mock + Candle)        │
│                                                                   │
│  Extension points (traits públicos documentados):                 │
│    LogParser · LogSource · IngestAdapter (P2-E)                   │
│    Tool (MCP) · ScoreComponent · LocalLlm · EventEmitter          │
│    DslExtension (nuevo) · ExportFormat (nuevo)                    │
└────────────▲──────────────────────────────────────────────────────┘
             │ llama a núcleo via fachada estrecha
             │
┌────────────┴──────────────────────────────────────────────────────┐
│                   NÚCLEO ALGORÍTMICO                              │
│  Paradigma: funcional/algebraico. Tipos codifican invariantes.   │
│  Property-based testing. Benchmarks como tests. SIN traits salvo  │
│  variación real documentada.                                      │
│                                                                   │
│  · core/graph-engine/      (ex graph_hunter_core núcleo puro)     │
│       graph + DFS + anomaly + hypothesis runtime + invariants    │
│                                                                   │
│  · core/matcher-ffi/       (ex simd_matcher.rs — crate dedicado)  │
│       Typestate GmGraph<Building|Finalized>                       │
│       RAII GmGraph · GmMatcher · GmResults                        │
│       ABI version check en load                                   │
│                                                                   │
│  · core/libgraphmatch/     (C++20 SIMD — intacto)                 │
│                                                                   │
│  · core/gnn/               (ex gnn_bridge + npu_scorer)           │
│       · gnn_v1: estable, cargado por defecto                      │
│       · gnn_v2: feature flag `gnn-v2-experimental`, gate al load │
└───────────────────────────────────────────────────────────────────┘
```

---

## 2. Crates Rust (destino)

```
core/
  graph-engine/              ← graph_hunter_core núcleo puro (graph, anomaly, invariants, hypothesis)
  matcher-ffi/               ← simd_matcher.rs + typestate + RAII completo
  libgraphmatch/             ← sin cambios (C++)
  gnn/                       ← gnn_bridge + npu_scorer + gnn_v2 (feature-gated)

platform/
  api/                       ← graph_hunter_api (façade)
  canonical/                 ← graph_hunter_canonical (OCSF + Provenance)
  vrl/                       ← graph_hunter_vrl
  constrained-decode/        ← graph_hunter_constrained_decode
  parsers/                   ← NUEVO: LogParser + impls (extraídos de core)
  sources/                   ← NUEVO: LogSource + conectores (extraídos de core)
  siem/                      ← NUEVO: rompe ciclo CLI↔API (Sentinel streaming)
  dsl/                       ← NUEVO: parser + grammar v1 + DslExtension trait
  local-llm/                 ← extraído de api/src/local_llm/
  mcp/                       ← graph-hunter-mcp (TS; queda separado pero se versionará)

apps/
  tauri/                     ← app/src-tauri + app/src
  cli/                       ← graph_hunter_cli

legacy/
  gateway/                   ← Go, archivado (no eliminado en Fase 1; decisión en Fase 5)
```

---

## 3. Contratos entre capas

### Núcleo → Plataforma

Una **fachada angosta**, no exposición de tipos internos:

```rust
// core/graph-engine: expone
pub struct GraphHunter { /* opaque */ }
impl GraphHunter {
    pub fn new(config: EngineConfig) -> Self;
    pub fn ingest_events(&mut self, events: EventStream) -> IngestReport;
    pub fn run_hunt(&self, query: &Hypothesis, limits: Limits) -> HuntResult;
    pub fn score_paths(&self, paths: &[Path]) -> Vec<ScoredPath>;
    pub fn snapshot(&self) -> GraphSnapshot;  // para export/analytics
}
```

Plataforma **nunca** toca structs internos del engine (`CompactNode`, `CompactRelation`, etc.). Si necesita algo, el engine expone un método.

### Plataforma → Glue

Los crates de plataforma exponen **APIs y traits**. Glue consume, no extiende:

- `apps/tauri` usa `platform/api`, punto.
- `apps/cli` usa `platform/api` (fix del ciclo — ver ADR-001).

### Extension points (lo que clientes pueden extender)

| Trait | Crate | Para qué |
|---|---|---|
| `LogParser` | `platform/parsers` | nuevos formatos de log |
| `LogSource` | `platform/sources` | nuevos conectores (Okta, Crowdstrike, etc.) |
| `IngestAdapter` | `platform/sources` | pipeline completo (P2-E del TODO) |
| `Tool` (MCP) | `platform/mcp` | nuevas herramientas para clientes IA |
| `DslExtension` | `platform/dsl` | nuevos predicados/entity-types (clientes) |
| `ExportFormat` | `platform/canonical` | nuevos destinos de export (STIX, MISP, …) |
| `ScoreComponent` | `core/graph-engine` | nuevo scorer (raro — se queda en núcleo por invariantes) |
| `LocalLlm` | `platform/local-llm` | backends alternativos de LLM local |
| `EventEmitter` | `platform/api` | hooks de progreso (Tauri, CLI, tests) |

---

## 4. Feature flags (estado objetivo)

```toml
# core/graph-engine
default = []
simd = ["dep:libgraphmatch-sys"]                  # C++ matcher
ml-scoring = ["dep:ort", "dep:ndarray"]           # ONNX inference base
gnn-v2-experimental = ["ml-scoring"]              # NUEVO — gate GNN v2 model load
directml = ["ml-scoring", "ort/directml"]         # Windows NPU/GPU
geoip = ["dep:maxminddb"]

# platform/api
default = []
ml-scoring = ["graph-engine/ml-scoring"]
simd = ["graph-engine/simd"]
local-llm-candle = ["dep:candle-core"]

# platform/dsl
default = []                                       # grammar v1 siempre disponible
dsl-v2-experimental = []                           # reservado para v2 cuando clientes pidan
```

**Regla**: todo feature con `-experimental` debe:
1. Producir warning en docs.rs (`#[cfg_attr(docsrs, doc(cfg(feature = "...")))]`).
2. Tener gate de runtime (carga de modelo, validación de schema) que falla si no cumple precondiciones.
3. Vivir en módulo aparte, no mezclado con código estable.

---

## 5. Grafo de dependencias (destino, sin ciclos)

```
      ┌──────────────────────────────────────────────┐
      │                  apps                        │
      │        tauri · cli                           │
      └────────────────┬─────────────────────────────┘
                       │
                       ▼
      ┌──────────────────────────────────────────────┐
      │                platform                      │
      │                                              │
      │  api ────┐                                   │
      │          ├─> canonical ─> (core/*)           │
      │          ├─> parsers  ──> core/graph-engine  │
      │          ├─> sources  ──> core/graph-engine  │
      │          ├─> siem     ──> core/graph-engine  │
      │          ├─> dsl      ──> core/graph-engine  │
      │          ├─> vrl                             │
      │          ├─> constrained-decode ─> vrl       │
      │          ├─> local-llm                       │
      │          └─> mcp (TS, via HTTP a api)        │
      └────────────────┬─────────────────────────────┘
                       │
                       ▼
      ┌──────────────────────────────────────────────┐
      │                   core                       │
      │                                              │
      │  graph-engine ──┬──> matcher-ffi ──> libgraphmatch
      │                 └──> gnn (v1, v2*)           │
      └──────────────────────────────────────────────┘
```

**Ciclos eliminados**:
- `api → cli` ❌ → `siem` crate consumido por ambos ✓
- `core::parsers` ya no mezcla con DFS ✓

---

## 6. Integración del WIP al rediseño

El `git status` muestra un bloque coherente de cambios WIP que corresponden a iteraciones M4 (agentic) + M5 (DLQ) + M6 (invariants). **No es deuda, es trabajo en curso.** El rediseño lo absorbe así:

| WIP actual | Destino en la nueva arquitectura |
|---|---|
| `graph_hunter_api/src/local_llm/` | `platform/local-llm/` (crate propio) |
| `graph_hunter_api/src/operations/agentic*.rs` | `platform/api/operations/agentic/` (módulo interno, API pública) |
| `graph_hunter_api/src/operations/dlq.rs` | `platform/api/operations/dlq.rs` |
| `graph_hunter_api/src/operations/invariants.rs` | `platform/api/operations/invariants.rs` |
| `graph_hunter_api/src/operations/mapping_library.rs` | `platform/api/operations/mapping_library.rs` |
| `graph_hunter_api/src/dto/{agentic,dlq,invariants,mapping_library}.rs` | `platform/api/dto/` (respectivos) |
| `app/src-tauri/src/commands/invariants.rs` | `apps/tauri/commands/invariants.rs` (sin cambio) |
| Modif en `commands/ingestion.rs` (727 LOC) | **acción**: auditar en Fase 2, mover lógica a `platform/api/operations/ingestion` |
| Modif en `gateway/` | **acción**: revisar si alinea con decisión de archivar (ADR-006) |
| Modif en `graph_hunter_cli/src/commands.rs` | se reescribe cuando `siem` crate se extrae (ADR-001) |

ADR-006 formaliza el proceso de absorción. **La pieza clave**: Fase 2 comienza con un commit "snapshot del WIP como baseline" antes de cualquier reorganización.

---

## 7. DSL como ciudadano de Plataforma

Hoy el DSL parser es hand-rolled, ~767 LOC, en `graph_hunter_core/src/dsl.rs`. Decisión: mover a `platform/dsl/` crate con los siguientes agregados (ADR-005):

```rust
// platform/dsl/src/lib.rs
pub trait DslExtension {
    fn name(&self) -> &str;
    fn version(&self) -> u32;
    fn register_entity_types(&self, reg: &mut EntityTypeRegistry);
    fn register_relation_types(&self, reg: &mut RelationTypeRegistry);
    fn register_predicates(&self, reg: &mut PredicateRegistry);
}

pub struct DslParser {
    grammar_version: GrammarVersion,  // v1 | v2 (flagged)
    extensions: Vec<Box<dyn DslExtension>>,
}

impl DslParser {
    pub fn new_v1() -> Self { /* grammar v1 estable */ }
    pub fn with_extension(mut self, ext: impl DslExtension + 'static) -> Self;
    pub fn parse(&self, source: &str) -> Result<Hypothesis, DslError>;
}
```

Rationale:
- Clientes pueden registrar entity types custom (ej. "Container", "ServiceAccount") vía extension trait.
- Nuevos predicados (`matches_regex`, `in_subnet`, ...) pueden añadirse sin tocar el core del parser.
- `grammar_version` permite evolucionar sin romper DSL escrito por usuarios existentes.

---

## 8. MCP como ciudadano de Plataforma

Hoy `graph-hunter-mcp/src/index.ts` es un archivo de 1 670 LOC con 54 tools hardcoded. Decisión: introducir estructura de "tool module" (ADR-004):

```ts
// platform/mcp/src/tools/types.ts
export interface Tool {
  readonly name: string;
  readonly version: number;
  readonly category: ToolCategory;
  readonly inputSchema: ZodSchema;
  readonly outputSchema: ZodSchema;
  readonly stability: 'stable' | 'experimental' | 'deprecated';
  execute(ctx: ToolContext, input: unknown): Promise<unknown>;
}

// platform/mcp/src/tools/index.ts
export const registry: Tool[] = [
  ...navigationTools,      // 8 tools (search, expand, get_node_details, ...)
  ...huntingTools,         // 7 tools (run_hunt, get_hunt_results, ...)
  ...scoringTools,         // ...
  ...agenticTools,         // 9 tools M4
  ...dlqTools,             // 3 tools M5
  ...invariantsTools,      // 2 tools M6
  ...exportTools,          // 4 tools
  ...dataQualityTools,     // 2 tools
  ...notesTools,           // 2 tools
  ...integrationTools,     // 4 tools (Jira, Sentinel, Sigma, tagging)
];
```

Rationale:
- Nuevos tools = nuevo archivo que implementa `Tool`, registrado en `registry`.
- `stability` marcado explícitamente (experimental/deprecated) para señalizar compatibilidad a clientes IA.
- `version` por tool permite evolucionar contratos sin romper clientes existentes.
- Tests contractuales: cada tool tiene test que verifica inputSchema + outputSchema contra respuesta real del API.

---

## 9. Matriz de paradigma por capa

| Aspecto | Núcleo | Plataforma | Glue |
|---|---|---|---|
| Paradigma | funcional/algebraico | OOP + traits | procedural |
| Patrones SOLID | no forzado | sí (OCP, ISP) | YAGNI |
| Abstracciones (traits) | sólo si hay variación real | sí, como API pública | evitar |
| Testing | property-based (Fase 3) | integration + contract | smoke + UI crítico |
| Benchmarks | criterion, CI gate | smoke de integración | - |
| Versioning | interno (no semver público) | semver público por crate | seguir plataforma |
| Docs | `cargo doc` + `docs/algorithms/` | `cargo doc` + `docs/extending/` cookbook | README |

---

## 10. Lo que NO cambia

- **Algoritmos núcleo**: DFS, anomaly scoring matemática, hypothesis runtime — **intacto**.
- **libgraphmatch C++**: no se toca.
- **OCSF v1.4 + Provenance 0.1**: contrato estable, se preserva.
- **DSL v1 grammar**: retrocompatible. Queries existentes siguen funcionando.
- **HTTP API endpoints del Tauri**: retrocompatibles (MCP clients existentes no se rompen).
- **54 MCP tools**: todos se preservan; sólo cambia su organización interna.
- **Feature flags existentes** (`simd`, `ml-scoring`, `directml`, `geoip`): sin cambio; `gnn-v2-experimental` se suma.

---

## 11. Entregables de Fase 1 (check antes de Fase 2)

- [x] `TARGET_ARCHITECTURE.md` (este doc)
- [x] ADR-001 — Canonical API Layer (consolidación, ruptura de ciclo CLI↔API)
- [x] ADR-002 — FFI Isolation (typestate + RAII + ABI version)
- [x] ADR-003 — GNN v2 Experimental (feature flag + load gate)
- [x] ADR-004 — MCP Tools Architecture (Tool trait, registry, stability)
- [x] ADR-005 — DSL Extensibility (grammar versioning, extension registry)
- [x] ADR-006 — WIP Absorption (snapshot baseline antes de reorganizar)
- [x] `MIGRATION_PLAN.md` (pasos reversibles, tests verdes por commit)
- [x] `RISKS.md`

Fase 1 completa. Fase 2 (mecánica) ejecutada F2.0-F2.19 (F2.20 smoke pendiente manual).
Ver `MIGRATION_PLAN.md` §"Ejecución registrada" para mapeo step→commit.
