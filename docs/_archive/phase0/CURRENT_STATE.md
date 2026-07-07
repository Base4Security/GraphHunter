# CURRENT_STATE — mapa de módulos (Fase 0)

> Read-only diagnostic snapshot. Generado 2026-04-23. No modifica código.

## 1. Inventario de crates / paquetes

### Rust (7 crates, sin workspace raíz)

| Crate | Path | LOC src/ top-level | Rol | Lang |
|---|---|---:|---|---|
| `graph_hunter_core` | `graph_hunter_core/` | ~24 325 | motor: graph, matcher, scoring, parsers, ingestión, FFI-SIMD | Rust |
| `graph_hunter_api` | `graph_hunter_api/` | ~13 623 | fachada transport-agnóstica (`GraphHunterApi` + `ApiState`), 23 módulos de operaciones | Rust |
| `graph_hunter_canonical` | `graph_hunter_canonical/` | ~600 (incl. `project/`) | proyección pura `(E,R,E)` → OCSF v1.4 + Provenance 0.1 | Rust |
| `graph_hunter_vrl` | `graph_hunter_vrl/` | ~550 | compilador determinístico `FieldConfig → VRL` (M3 wedge) | Rust |
| `graph_hunter_constrained_decode` | `graph_hunter_constrained_decode/` | ~400 | validador gramatical post-hoc para salida LLM (M6) | Rust |
| `graph_hunter_cli` | `graph_hunter_cli/` | ~8 700 | CLI stdin/stdout JSON, reusa `core` directo (no usa `api`) | Rust |
| `app/src-tauri` | `app/src-tauri/` | ~5 554 | app Tauri v2: 91 `#[tauri::command]` + `http_api.rs` (Axum) | Rust |

### No-Rust

| Paquete | Path | LOC | Rol |
|---|---|---:|---|
| `graph-hunter-mcp` | `graph-hunter-mcp/src/` | ~1 670 (index.ts) | MCP server TS, **54 tools** (confirmado: `grep server.tool(` = 54) |
| `libgraphmatch` | `libgraphmatch/` | ~13 000 | motor C++20 (no-exceptions, no-rtti) con dispatch SIMD (AVX2/AVX-512/NEON/scalar) |
| `gateway` | `gateway/` | 885 (Go) | Fiber HTTP server + WebSocket hub; **no referenciado por ningún Rust ni TS activo** |
| `app/src` | `app/src/` | ~40 `.tsx` | frontend React 19 + Cytoscape; Context API (sin Redux/Zustand) |

### Python / scripts

- `scripts/train_gnn_v2.py` — training skeleton GNN v2 (6 clases, **sin entrenar en data real**, ver PAIN_POINTS §4.)
- Otros: `scripts/*.ps1|sh|py` para automatización local.

---

## 2. Grafo de dependencias (dirección: A → B significa "A usa B")

```
                           ┌─────────────────────────┐
                           │       libgraphmatch     │  (C++20, FFI C ABI)
                           │  AVX2/AVX-512/NEON/scalar│
                           └────────────▲────────────┘
                                        │ FFI (1 extern "C" block)
                                        │
                           ┌────────────┴────────────┐
                           │    graph_hunter_core    │◀───┐
                           │  graph, anomaly, parsers│    │
                           │   GNN bridge, DSL, etc. │    │
                           └──────▲────────▲─────────┘    │
                                  │        │              │
                ┌─────────────────┤        ├──────────┐   │
                │                 │        │          │   │
    ┌───────────┴────┐  ┌─────────┴──┐  ┌──┴──────┐  ┌┴───┴──────────────────┐
    │ graph_hunter_  │  │ graph_hunter│ │ graph_  │  │ graph_hunter_cli       │
    │ canonical      │  │ _vrl        │ │ hunter_ │  │ (stdin/stdout JSON)    │
    │ (OCSF project)│   │ (VRL compl.)│ │constr._ │  └──────▲─────────────────┘
    └───────▲────────┘  └─────▲───────┘ │decode   │         │
            │                 │         └────▲────┘         │ subprocess
            │                 │              │              │ spawn
            └──────┬──────────┴──────────────┘              │
                   │                                        │
           ┌───────┴──────────────┐                ┌────────┴──────────┐
           │   graph_hunter_api   │                │   gateway (Go)    │
           │  (transport-agnost.) │                │  (LEGACY, inactivo│
           └──────▲────────▲──────┘                │   ver §4)         │
                  │        │                       └───────────────────┘
                  │        │
        ┌─────────┘        └──────────┐
        │                             │
   ┌────┴─────────────┐         ┌─────┴─────────────┐
   │ app/src-tauri    │         │ graph-hunter-mcp  │
   │ (91 commands +   │         │ (54 tools, todos  │
   │  HTTP Axum)      │         │  delegan via HTTP)│
   └──────▲───────────┘         └───────────▲───────┘
          │                                 │
          │ IPC Tauri                       │ HTTP → :37891 (o equiv)
          │                                 │
   ┌──────┴──────────┐                ┌─────┴──────────┐
   │  app/src (React)│                │ Claude/Cursor  │
   │  Cytoscape+dagre│                │ (MCP clients)  │
   └─────────────────┘                └────────────────┘
```

Observaciones:
- **Acoplamiento FFI aislado**: un solo `extern "C"` en todo el repo, en `graph_hunter_core/src/simd_matcher.rs:23`. Bueno.
- **`graph_hunter_cli` no usa `graph_hunter_api`**: va directo a `core`. Esto bifurca el "camino de ingesta" (ver PAIN_POINTS §2).
- **`gateway` Go**: sin referencias entrantes de Rust ni TS. Candidato a archivar (ver PAIN_POINTS §5).
- **`graph_hunter_api` depende de TODOS los demás crates Rust**, incluyendo `graph_hunter_cli` (`Cargo.toml`): depende del CLI como lib para reusar lógica de SIEM streaming (ver PAIN_POINTS §3).

---

## 3. Clasificación provisional por capa

Clasificación aplicando los criterios del plan del usuario: núcleo = algoritmos + corrección formal, plataforma = extension points OOP/trait, glue = pragmático/procedural.

| Módulo/Crate | Capa provisional | Justificación 1-línea |
|---|---|---|
| `libgraphmatch` | **Núcleo** | motor algorítmico SIMD, corrección crítica |
| `graph_hunter_core::graph` | **Núcleo** | temporal multigraph + DFS, invariantes de causalidad |
| `graph_hunter_core::anomaly` | **Núcleo** | 5-scorer endógeno, matemática definida |
| `graph_hunter_core::gnn_bridge` + `npu_scorer` | **Núcleo** | extracción de features + ONNX inference |
| `graph_hunter_core::simd_matcher` | **Núcleo (FFI façade)** | aislamiento C ABI, candidato a módulo dedicado |
| `graph_hunter_core::dsl` | **AMBIGUO** (plataforma?) | parser hand-rolled; ¿extension point o algoritmo? → CONFIRMAR |
| `graph_hunter_core::invariants` | **Núcleo** | predicados formales (treewidth, shape catalog) |
| `graph_hunter_core::parser` + implementaciones | **Plataforma** | trait `LogParser` con 7 impl (Cognito, Csv, Generic, Forti, IIS, Sentinel, Sysmon) |
| `graph_hunter_core::ingest/*` | **Plataforma** | pipeline streaming, coverage, metrics, cancellation |
| `graph_hunter_core::sources/*` | **Plataforma** | `LogSource` trait + Sentinel/DefenderXDR/DataLake |
| `graph_hunter_core::mapping_library` | **Plataforma** | RAG + library_classifier para mapping reuse |
| `graph_hunter_core::scoring::composite` | **Núcleo** | composición de scorers |
| `graph_hunter_core::drift` / `dlq` / `catalog` | **Plataforma** | infra de calidad de datos |
| `graph_hunter_api` (todas las `operations/*`) | **Plataforma** | fachada pública, coordinación, orquestación |
| `graph_hunter_api::local_llm` | **Plataforma** | trait `LocalLlm` con backends mock/candle |
| `graph_hunter_canonical` | **Plataforma** | proyección estable OCSF; contrato externo |
| `graph_hunter_vrl` | **Plataforma** | compilador determinístico, contrato estable |
| `graph_hunter_constrained_decode` | **Plataforma** | validador post-hoc, guardrail LLM |
| `graph-hunter-mcp` | **Plataforma** | 54 tools como surface pública, pero implementación 100% delegada ⇒ **AMBIGUO** (glue con API?) → CONFIRMAR |
| `graph_hunter_cli` | **Glue** | CLI pragmático; bifurca "camino de ingesta" ⇒ marcar |
| `app/src-tauri` | **Glue** | 91 commands 1:1 delegados, sin lógica propia |
| `app/src` (React) | **Glue** | UI, Cytoscape, Context API |
| `gateway` (Go) | **Glue** (legacy) | inactivo ⇒ ver SHEARING_MAP |

**Confirmar con el usuario** (nodos marcados AMBIGUO):
- `dsl` — ¿plataforma (extensión externa esperada) o núcleo (inmutable, formal)?
- `graph-hunter-mcp` — ¿es "plataforma delgada" (shim) o "glue externo"? Cambia dónde aplica SOLID.

---

## 4. Hot paths identificados (con benches como evidencia)

**Benches Criterion existentes** (`graph_hunter_core/benches/`):

1. `hunt_latency.rs` (47 LOC) — mide `GraphHunter::search_temporal_pattern()` sobre spray graphs de 1k/10k/100k nodos.
   - Función en hot loop: `graph_hunter_core/src/graph.rs:481` (`search_temporal_pattern`)
   - Variante SIMD: `graph.rs:721` (`search_temporal_pattern_simd`, delega a FFI)
   - Dispatcher: `graph.rs:802` (`search_temporal_pattern_smart`)

2. `dedup_throughput.rs` (47 LOC) — mide `score_and_paginate_paths()` con `DedupMode::ByPath`.

**Benches C++** (`libgraphmatch/CMakeLists.txt:91-107`):
- `bench_intersect` — throughput de set intersection SIMD.
- `bench_matching` — latencia full pattern matching.

**Binarios de profiling** (`graph_hunter_core/src/bin/`):
- `bench_dfs.rs` — profiler dedicado del DFS Rust.
- `profile_graph.rs` — allocator profiler custom.
- `profile_relation_schema.rs` — schema introspection profiler.

**Hot paths confirmados**:
- `graph.rs:search_temporal_pattern` (pure Rust DFS) — principal cuando SIMD off.
- `simd_matcher.rs::run_simd_search` → FFI → `gm_matcher_run` (C++).
- `anomaly.rs::score_path` (línea 241) — invocado por cada path encontrado.
- `graph_hunter_core::ingest::parser_task::*` — parsing paralelo Rayon.
- `interner.rs::intern` (121+ call sites por TODO.md) — bottleneck potencial >10M strings.

---

## 5. Puntos de extensión existentes (traits con múltiples impl)

| Trait | Ubicación | Implementaciones | Notas |
|---|---|---|---|
| `LogParser` | `graph_hunter_core/src/parser.rs` | Cognito, Csv, Generic, FortiAnalyzerXml, IisW3c, SentinelJson, SysmonJson | núcleo de extensión de formatos |
| `LogSource` | `graph_hunter_core/src/sources/mod.rs` | Sentinel, DefenderXDR, DataLake, LogAnalytics | `poll_since` + `query_scoped` |
| `EventEmitter` | `graph_hunter_api/src/events.rs:91` | `NoopEmitter`, implementación Tauri custom | hook de progreso |
| `LocalLlm` | `graph_hunter_api/src/local_llm/mod.rs` | MockBackend, CandleBackend (feature) | backend LLM local |
| `ScoreComponent` | `graph_hunter_core::scoring` (trait) | 5 componentes (Entity Rarity, Edge Rarity, Concentration, Temporal Novelty, GNN Threat) | composición declarada en TODO.md |
| `StringInternerBackend` | `graph_hunter_core::interner` | 1 (default) | seam shipped, impl generational diferida |
| `IngestAdapter` | — | **NO existe** aún (P2-E, ver TODO.md:34) | trait objetivo para agregar sources sin tocar core |

---

## 6. Frontend (app/src) — resumen

- React 19 + Vite, Cytoscape + dagre.
- 40 `.tsx` componentes, sin state management library.
- **3 test files** (`app/src/components/__tests__/`): HuntResultsTable, NotesPanel, SessionSelector. Vitest como runner.
- Sin Redux/Zustand → Context API para estado compartido (ver PAIN_POINTS §7 para riesgo).

---

## 7. Resumen cuantitativo (chequear en verificación)

| Métrica | Valor |
|---|---:|
| Crates Rust | 7 |
| LOC Rust (aprox sumando top-level src/) | ~68 000 |
| Tauri commands | **91** (16 files) |
| MCP tools | **54** (graph-hunter-mcp/src/index.ts) |
| `extern "C"` blocks | **1** (simd_matcher.rs:23) |
| Unsafe blocks en core | 37 |
| `#[test]` + `#[tokio::test]` (Rust) | 1 007 ocurrencias / 122 files |
| `panic!`/`unwrap`/`expect` en core | 1 081 ocurrencias / 48 files |
| Tauri tests | 2 |
| Frontend tests | 3 files / ~30 asserts |
| Gateway Go tests | **0** |
| MCP TS tests | **0** |

> Las cifras arriba difieren del modelo mental del usuario en varios puntos (54 vs 37 tools, 91 commands sin declarar, etc.). Ver PAIN_POINTS §Discrepancias.

---

## 8. Archivos que sorprendieron (`git status` inicial vs ramas de trabajo)

El `git status` muestra modificaciones y archivos sin staging en todas las capas simultáneamente (core, api, app, mcp). Esto sugiere work-in-progress de un cambio cross-layer sin merged. **No auditado en Fase 0** más allá de notarlo aquí — reportado en PAIN_POINTS §10 para que el usuario decida si es relevante.
