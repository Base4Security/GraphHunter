# SHEARING_MAP — propuesta de clasificación por capa (Fase 0)

> Mapa propuesto aplicando los criterios del plan del usuario. Decisiones ambiguas marcadas `CONFIRMAR`.
> **No ejecutable hasta que el usuario apruebe en Fase 1.**

---

## Criterios (citados del plan del usuario)

> **Núcleo algorítmico** (libgraphmatch, matcher, GNN): tipos fuertes que codifiquen invariantes, property-based testing, contratos formales, FFI aislado detrás de fachada segura, benchmarks como tests. NO sobre-abstraer con traits aquí salvo que haya variación real. Paradigma: funcional/algebraico con énfasis en corrección.
>
> **Plataforma** (DSL, runtime, MCP server, conectores): aquí sí aplica SOLID clásico (especialmente OCP e ISP), traits bien definidos como API pública de facto, extensibilidad como feature de primera clase. Paradigma: OOP/trait-oriented con extension points explícitos.
>
> **Glue** (UI Tauri, CLI, configs): YAGNI agresivo, código pragmático y obvio, mínima abstracción. Paradigma: procedural/directo.

---

## 1. Núcleo algorítmico

Criterio: corrección formal, hot paths, contratos matemáticos, property-based testing futuro.

| Módulo | Path | Justificación |
|---|---|---|
| `libgraphmatch` | `libgraphmatch/` | motor SIMD C++20, algoritmos graph-matching canónicos |
| `graph_hunter_core::graph` | `graph.rs` | temporal multigraph, DFS iterativo, invariante causal |
| `graph_hunter_core::simd_matcher` | `simd_matcher.rs` | FFI façade hacia libgraphmatch (1 único `extern "C"`, RAII) |
| `graph_hunter_core::anomaly` | `anomaly.rs` | 5-component scorer (definición matemática explícita) |
| `graph_hunter_core::scoring::composite` | `scoring/composite.rs` | composición vía trait `ScoreComponent` |
| `graph_hunter_core::gnn_bridge` | `gnn_bridge.rs` | extracción de features determinística para GNN |
| `graph_hunter_core::npu_scorer` | `npu_scorer.rs` | ONNX inference, contrato 6-class |
| `graph_hunter_core::hypothesis` | `hypothesis.rs` | runtime de pattern steps + k-simplicity |
| `graph_hunter_core::invariants` | `invariants/` | predicados formales (treewidth, shape catalog) |
| `graph_hunter_core::interner` | `interner.rs` | estructura de datos intern; trait pero 1 impl |
| `graph_hunter_core::simd_rust` | `simd_rust.rs` | AVX2 intrinsics puros (sin libgraphmatch) |
| `graph_hunter_core::relation` | `relation.rs` | tipos fundamentales Entity/Relation |

### CONFIRMAR — candidatos ambiguos

- `graph_hunter_core::dsl` (767 LOC) — parser hand-rolled de la DSL de hipótesis. **Razón de ambigüedad**: la DSL es una API pública (usuarios escriben hipótesis), lo que sugiere **plataforma** (extensibilidad, versionado). Por otro lado, la gramática es fija y el parser es algorítmico puro, lo que sugiere **núcleo**. Pregunta: ¿se espera que terceros agreguen nuevas construcciones de DSL?

- `graph_hunter_core::sentinel` (23K LOC archivo — antiguo) y `forti_analyzer` (1 642 LOC) — parsers de formato, trait `LogParser`. Deberían estar en plataforma (§2) pero **conviven en el mismo crate** que el núcleo por razones históricas. Proponer: extraerlos a `graph_hunter_parsers` crate en Fase 2.

---

## 2. Plataforma

Criterio: extension points explícitos, traits bien definidos, OCP/ISP, API pública versionada.

| Módulo | Path | Justificación |
|---|---|---|
| `graph_hunter_api` (façade) | `graph_hunter_api/src/lib.rs` | `GraphHunterApi` struct central de la plataforma |
| `graph_hunter_api::operations::*` | `src/operations/` | 23 módulos: hunt, anomaly, ingest, export, agentic, dlq, etc. |
| `graph_hunter_api::dto::*` | `src/dto/` | contratos públicos versionables |
| `graph_hunter_api::events` | `events.rs` | trait `EventEmitter` con 2+ impl |
| `graph_hunter_api::local_llm` | `local_llm/` | trait `LocalLlm`, backends mock/candle |
| `graph_hunter_api::ai` | `ai.rs` | provider routing (OpenAI/Anthropic/Google) |
| `graph_hunter_api::sentinel_connector` | `sentinel_connector.rs` | conector real-time con backoff |
| `graph_hunter_api::format_registry` | `format_registry.rs` | dispatcher de detección de formato |
| `graph_hunter_core::parser` (trait + impl) | `parser.rs` + subsidiarios | `LogParser` con 7 impl; API de extensión |
| `graph_hunter_core::sources::*` | `sources/mod.rs` | `LogSource` trait, Sentinel/DefenderXDR/DataLake |
| `graph_hunter_core::mapping_library` | `mapping_library/` | catálogo cross-session, API pública |
| `graph_hunter_core::catalog` | `catalog/` | shape catalog, carga declarativa |
| `graph_hunter_core::drift` | `drift/` | schema drift detection |
| `graph_hunter_core::dlq` | `dlq/` | dead-letter queue |
| `graph_hunter_core::ingest::*` | `ingest/` | pipeline: coverage, metrics, cancellation, enrichment |
| `graph_hunter_core::ingest_adapter` | `ingest_adapter.rs` | seam para IngestAdapter (P2-E, pendiente, ver TODO.md:34) |
| `graph_hunter_canonical` | crate | proyección OCSF v1.4; contrato externo estable |
| `graph_hunter_vrl` | crate | compilador FieldConfig → VRL; contrato estable |
| `graph_hunter_constrained_decode` | crate | guardrail LLM; validador gramatical |

### CONFIRMAR — candidatos ambiguos

- `graph-hunter-mcp` — **todas las 54 tools delegan via HTTP a `graph_hunter_api`**. No tiene lógica propia, pero es **surface pública** para IA (Claude, Cursor). Opciones:
  - (a) Plataforma: el MCP es la API pública para AI clients, merece SOLID estricto.
  - (b) Glue: es un shim HTTP; el verdadero surface público es `graph_hunter_api`.
  - **Recomendación Fase 1**: (a), porque el MCP define contratos de tools que son estables de cara al usuario, y el versionado importa.

- `graph_hunter_core::graph_pattern`/`analytics`/`field_preview`/`export` viven en el core pero tienen características de plataforma (API abierta al exterior). Proponer: mover `export` a `graph_hunter_canonical` (ya existe parcialmente allí); `analytics` se queda pero refactorizar; `field_preview` a plataforma.

---

## 3. Glue

Criterio: YAGNI agresivo, procedural/directo, mínima abstracción, 1:1 a plataforma.

| Módulo | Path | Justificación |
|---|---|---|
| `app/src-tauri` (commands/*) | `app/src-tauri/src/commands/` | 91 commands, la mayoría pass-through 1:1 |
| `app/src-tauri::http_api` | `http_api.rs` | 1 662 LOC de rutas Axum; necesita partir en routers por dominio (pero **sigue siendo glue**) |
| `app/src-tauri::lib` + `state` + `helpers` | `lib.rs`, `state.rs`, `helpers.rs` | setup Tauri, session lifecycle |
| `app/src` (React frontend) | `app/src/` | UI Cytoscape, 40 componentes, Context only |
| `graph_hunter_cli` | `graph_hunter_cli/` | CLI stdin/stdout, reusa core. Ver PAIN_POINTS §2 para inconsistencia |
| `scripts/` | `scripts/` | automatización local, training Python |
| `demo_data/` | `demo_data/` | fixtures |

### CONFIRMAR — candidato

- `gateway/` (Go, 885 LOC, no referenciado) — técnicamente es glue (HTTP shim spawning CLI), pero está **inactivo**. Decisión Fase 1: archivar como "glue deprecado" o eliminar (requiere pregunta explícita al usuario).

---

## 4. Candidatos a **reubicar** en Fase 2 (fundacional)

Estos módulos hoy viven en un crate pero por capa pertenecen a otro:

| Actual | Propuesto | Capa destino | Por qué |
|---|---|---|---|
| `graph_hunter_core::parser` (+ 7 impl parsers) | nuevo crate `graph_hunter_parsers` | plataforma | es el primer trait de extensión, no debería convivir con DFS |
| `graph_hunter_core::export` | `graph_hunter_canonical::export` | plataforma | OCSF ya vive allí |
| `graph_hunter_core::sentinel` (archivo legacy 23K LOC) | decidir: mover o borrar | — | revisar si aún está vivo |
| `graph_hunter_cli::siem::sentinel_streaming` | nuevo crate `graph_hunter_siem` | plataforma | rompe ciclo CLI↔API (ver PAIN_POINTS §2) |
| `app/src-tauri::commands::ingestion` (727 LOC) | `graph_hunter_api::operations::ingestion` | plataforma | lógica no debería vivir en el Tauri command |

---

## 5. Estructura de carpeta ideal (propuesta) — sujeta a Fase 1

```
GraphHunter/
├── core/                    ← (núcleo)
│   ├── graph-engine/        ← ex graph_hunter_core (solo núcleo)
│   ├── libgraphmatch/       ← C++
│   └── matcher-ffi/         ← ex simd_matcher.rs como crate
├── platform/
│   ├── api/                 ← ex graph_hunter_api
│   ├── canonical/           ← graph_hunter_canonical
│   ├── vrl/                 ← graph_hunter_vrl
│   ├── constrained-decode/  ← graph_hunter_constrained_decode
│   ├── parsers/             ← parsers extraídos
│   └── mcp/                 ← graph-hunter-mcp (TS)
├── apps/
│   ├── tauri/               ← ex app/
│   └── cli/                 ← ex graph_hunter_cli
├── legacy/
│   └── gateway/             ← (Go, archivado si se confirma §5 PAIN_POINTS)
├── scripts/
└── docs/
```

**Esto es propuesta**, no plan de migración. El plan de migración va en Fase 1 (`MIGRATION_PLAN.md`).

---

## 6. Qué NO cambia de capa

Estos módulos están en su capa correcta hoy y **no deben moverse**:

- `libgraphmatch` — núcleo, ya aislado.
- `graph_hunter_canonical`/`vrl`/`constrained_decode` — plataforma, ya son crates separados.
- `app/src-tauri/src/commands/sigma_save.rs` y similares pequeños (<100 LOC) — glue correcto.
- `app/src` React — glue correcto.

---

## Checklist de verificación para el usuario

- [ ] ¿Confirmás la clasificación de `dsl` (Núcleo o Plataforma)?
- [ ] ¿Confirmás `graph-hunter-mcp` como Plataforma (no Glue)?
- [ ] ¿OK mover `parser` a plataforma en Fase 2?
- [ ] ¿OK con el plan de archivar/eliminar `gateway/` en Fase 2 (previa aprobación explícita en ese momento)?
- [ ] ¿La estructura de carpeta en §5 es aceptable como **horizonte**, o preferís otra?
