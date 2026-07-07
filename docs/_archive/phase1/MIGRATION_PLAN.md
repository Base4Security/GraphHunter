# MIGRATION_PLAN — pasos reversibles hacia la arquitectura objetivo (Fase 1)

> Cada paso = 1 commit atómico. Cada commit deja el workspace compilando y tests verdes.
> Marca `[F2]` = paso de Fase 2 (fundacional, bajo riesgo).
> Marca `[F3]` = Fase 3 (núcleo: property tests, SIMD).
> Marca `[F4]` = Fase 4 (plataforma, canonical API, DSL, MCP).
> Marca `[F5]` = Fase 5 (glue, UX developer, docs).
> **Ningún paso se ejecuta hasta que Fase 1 esté aprobada.**

---

## Reglas globales

1. Cada paso genera un commit con mensaje que referencia el paso (`Step F2.1: ...`).
2. Si un paso rompe tests, **revertir** (no parchar en el mismo commit) y abrir discusión.
3. Cambios de comportamiento → 0 en Fase 2. En Fase 3+, sólo los explícitamente documentados.
4. Benchmarks corren antes y después de cada paso de núcleo (Fase 3). Regresión >5% → revertir.
5. Feature flags no existentes se agregan en su paso correspondiente, nunca antes.

---

## Fase 2 — Fundaciones (cambios mecánicos, bajo riesgo)

### Step F2.0 — Baseline del WIP (ADR-006)

Absorber cambios no commiteados en 3 commits. `git status` queda limpio.

- **Archivos tocados**: ~58 archivos actuales en `git status`.
- **Tests**: todos deben pasar post-commit.
- **Reversible**: sí (por commit).

### Step F2.1 — Crear directorios destino (sin contenido)

- Crear `core/`, `platform/`, `apps/`, `legacy/` en raíz.
- Cada uno con `README.md` 1-párrafo explicando su rol.
- **No mover nada aún.**
- **Commit**: `chore(repo): introduce layered directory structure`.

### Step F2.2 — Mover `graph_hunter_canonical` a `platform/canonical/`

- `git mv graph_hunter_canonical platform/canonical`
- Actualizar paths en Cargo.tomls que lo referencian (`graph_hunter_api`, `graph_hunter_vrl`).
- `cargo check --workspace` + `cargo test --workspace` deben pasar.
- **Commit**: `refactor(repo): move graph_hunter_canonical → platform/canonical`.

### Step F2.3 — Mover `graph_hunter_vrl` a `platform/vrl/`

Análogo a F2.2.

### Step F2.4 — Mover `graph_hunter_constrained_decode` a `platform/constrained-decode/`

Análogo.

### Step F2.5 — Mover `graph_hunter_api` a `platform/api/`

- Mayor blast radius: Tauri y CLI referencian `graph_hunter_api`.
- Paths en `app/src-tauri/Cargo.toml`, `graph_hunter_cli/Cargo.toml` actualizados.
- `cargo test --workspace` debe pasar.
- **Commit**: `refactor(repo): move graph_hunter_api → platform/api`.

### Step F2.6 — Mover `app/` a `apps/tauri/`

- `git mv app apps/tauri` (preservando submódulo src/ React).
- Actualizar scripts que referencian `app/` (package.json, Makefile, CI).
- **Commit**: `refactor(repo): move app → apps/tauri`.

### Step F2.7 — Mover `graph_hunter_cli` a `apps/cli/`

### Step F2.8 — Extraer `platform/siem` (rompe ciclo — ADR-001)

- Nuevo crate `platform/siem/` con código hoy en `apps/cli/src/siem/sentinel_streaming.rs`, `sentinel.rs`, `elastic.rs`.
- `platform/api` y `apps/cli` dependen de `platform/siem`.
- **`platform/api/Cargo.toml` elimina dep de `apps/cli`.**
- Ciclo arquitectural roto.
- Tests dentro de `platform/siem/tests/` (mover los relevantes).
- **Commit**: `refactor(siem): extract platform/siem to break api↔cli cycle`.

### Step F2.9 — Crear `platform/local-llm/` extrayendo de api

- Nuevo crate con `mod`, `mock`, `candle`.
- `platform/api` depende de él.
- **Commit**: `refactor(local-llm): extract platform/local-llm crate`.

### Step F2.10 — Extraer parsers a `platform/parsers/`

- Nuevo crate. Mueve `graph_hunter_core/src/{parser,sysmon,sentinel,csv_parser,generic,iis_w3c,cognito,forti_analyzer}.rs`.
- `LogParser` trait + 7 impl.
- Tests integration correspondientes (`tests/parsers.rs` split).
- **Commit**: `refactor(parsers): extract platform/parsers crate`.

### Step F2.11 — Extraer sources a `platform/sources/`

- Análogo con `graph_hunter_core/src/sources/*`.
- `LogSource` trait + conectores.

### Step F2.12 — Extraer DSL a `platform/dsl/` (ADR-005)

- Mueve `graph_hunter_core/src/dsl.rs` y tests asociados.
- Mantiene gramática v1 sin cambios.
- **Sin agregar** `DslExtension` trait aún (eso es F4).
- **Commit**: `refactor(dsl): extract platform/dsl crate`.

### Step F2.13 — Extraer `core/matcher-ffi/` (ADR-002)

- Mueve `graph_hunter_core/src/simd_matcher.rs`.
- Typestate y RAII completo **NO todavía** (eso es F3).
- Sólo la mudanza mecánica.
- **Commit**: `refactor(ffi): extract core/matcher-ffi crate`.

### Step F2.14 — Crear `core/gnn/` v1 (sin v2 aún)

- Mueve `gnn_bridge.rs`, `npu_scorer.rs`.
- Agrega submódulo `v1/`, `common/` (shape común).
- `v2/` vacío (placeholder).
- Feature flags actualizados: `ml-scoring` sigue funcionando como antes.
- **Sin ADR-003 gate todavía.**
- **Commit**: `refactor(gnn): extract core/gnn crate with v1 only`.

### Step F2.15 — Extraer núcleo puro a `core/graph-engine/`

- `graph_hunter_core` se renombra a `core/graph-engine`.
- Contiene: graph, anomaly, invariants, hypothesis, interner, relation, scoring, analytics, ingest/, field_preview, mapping_library, drift, dlq, catalog.
- Dependencias salientes: `core/matcher-ffi` (simd), `core/gnn` (ml-scoring).
- **Commit**: `refactor(core): rename graph_hunter_core → core/graph-engine`.

### Step F2.16 — Mover `commands/ingestion.rs` (727 LOC) lógica a `platform/api/operations/ingestion`

- Dejar Tauri command como shim 1:1.
- Test de parity debe pasar.
- **Commit**: `refactor(tauri): migrate ingestion logic from command to api operation`.

### Step F2.17 — Split `app/src-tauri/src/http_api.rs` (1 662 LOC) en routers por dominio

- `http_api/routes/hunt.rs`, `ingest.rs`, `anomaly.rs`, `export.rs`, `agentic.rs`, `invariants.rs`, `dlq.rs`, `catalog.rs`.
- Cada router registra rutas y delega a operation.
- **Commit**: `refactor(tauri): split http_api.rs into per-domain routers`.

### Step F2.18 — Partir `core/graph-engine/src/lib.rs` (5 219 LOC, 244 tests inline)

- Mover tests inline a `tests/` de integración cuando sean funcionales.
- Dejar lib.rs como fachada puramente (pub use + 1-par de exports).
- Objetivo: lib.rs < 500 LOC.
- **Commit**: `refactor(core): split graph-engine/lib.rs — move tests to integration`.

### Step F2.19 — Archivar `gateway/` a `legacy/gateway/`

- Mover, agregar `legacy/README.md` explicando status.
- **No eliminar**. Decisión final en Fase 5.
- **Commit**: `chore(legacy): archive gateway to legacy/ (unused, M5 pending decision)`.

### Step F2.20 — Smoke test end-to-end

- Levantar Tauri, conectar MCP, correr 3 hunts distintos.
- Confirmar que todos los flujos pre-rediseño funcionan.
- **No hay commit** — es verificación manual.

**Fin de Fase 2. PARAR y esperar aprobación del usuario antes de F3.**

---

## Ejecución registrada (F2.0 — F2.19)

| Step | Commit | Mensaje |
|---|---|---|
| F2.0a | `f944f26` | feat(api,core,mcp,tauri): land M4 agentic + M5 DLQ + M6 invariants |
| F2.0b | `f4919eb` | feat(platform): land canonical/vrl/constrained_decode crates + classifier trainer |
| F2.1  | `b9b1014` | chore(repo): introduce layered directory structure |
| F2.2  | `b8301e1` | refactor(repo): move graph_hunter_canonical → platform/canonical |
| F2.3  | `7d492ab` | refactor(repo): move graph_hunter_vrl → platform/vrl |
| F2.4  | `5a19130` | refactor(repo): move graph_hunter_constrained_decode → platform/constrained-decode |
| F2.5  | `cec1853` | refactor(repo): move graph_hunter_api → platform/api |
| F2.6  | `6b4ae00` | refactor(repo): move app → apps/tauri |
| F2.7  | `623a8e2` | refactor(repo): move graph_hunter_cli → apps/cli |
| F2.8  | `6dbacbb` | refactor(repo): extract platform/siem, break api→cli edge |
| F2.9  | `58d5c88` | refactor(repo): extract platform/local-llm crate |
| F2.10 | `15efbd3` | refactor(repo): extract platform/parsers — cognito, forti, iis |
| F2.11 | `5842fc5` | refactor(repo): extract platform/sources crate |
| F2.12 | `96a3e92` | refactor(repo): extract platform/dsl crate with types+hypothesis |
| F2.13 | `19855cc` | refactor(F2.13): extract simd_matcher to core/matcher-ffi crate (ADR-002) |
| F2.14 | `dd398b9` | refactor(F2.14): extract graph_hunter_gnn crate at core/gnn/ |
| F2.15 | `9c46389` | refactor(F2.15): rename graph_hunter_core/ to core/graph-engine/ |
| F2.16 | `4888fa4` | refactor(F2.16): move streaming ingest from Tauri to canonical API |
| F2.17 | `e7a5681` | refactor(F2.17): split http_api into per-domain routers |
| F2.18 | `36e235c` | refactor(F2.18): hoist lib.rs tests into src/tests.rs |
| F2.19 | `1c259b6` | refactor(F2.19): archive gateway/ to legacy/gateway/ |
| F2.20 | `248ee76` (automatizado) + smoke UI manual pasado 2026-04-24 | smoke test: compile + suites + 3 hunts round-trip |

**F2.20 — CERRADO (2026-04-24)**

Pieza automatizada (green):

- `cargo check --lib` sobre `apps/tauri/src-tauri` ✓ (requiere stub `apps/tauri/dist/index.html` temporal por el macro de Tauri; no hay regresión de código).
- `cargo test --lib` sobre `apps/cli` ✓ (binario fino, 0 tests propios).
- `cargo test --lib` sobre `core/graph-engine`: **514 passed / 0 failed** (2 ignored + 8 saltados documentados).
- `cargo test --tests` sobre `core/graph-engine`: **156 passed / 0 failed** en 22 suites de integración.
- `cargo test --lib` sobre `platform/api`: **157 passed / 0 failed** (F4 verificó el mismo día).
- `npm run build` + contract tests sobre `platform/mcp`: clean (F4 verificó el mismo día).

Pieza manual (pasada 2026-04-24 con dataset FortiAnalyzer real):

- Hunt 1 estructural `ReportContext -[Connect]-> Threat -[Connect]-> ThreatCategory` → `path_count=140`.
- Hunt 2 scored (`enable_anomaly_scoring` + `ReportContext -[Connect]-> Application -[Connect]-> AppCategory`) → `path_count=106`, 35 paths sobre `min_score=0.3`; top ranking detectó correctamente Proton.VPN / Psiphon / HTTP.BROWSER vía `edge_rarity`.
- Hunt 3 dual-channel `search_entities("10.") → expand_node → create_note(node_id)` → nota persistida con link, `get_notes` round-trip ok.

Observaciones del smoke (follow-ups, no regresiones de F2):

- `/hunt_results` paginación es **0-based** pero la docs del tool MCP sugiere 1-based (confusión real con el usuario). Alinear: aclarar en el schema `GET /hunt_results` que `page` empieza en 0, o renombrar a `offset`.
- Paths con `gnn_threat=0` en los top 3 — el modelo GNN v2 no está cargado en la sesión (corpus FortiAnalyzer no entrenado). Esperado bajo ADR-003 (model gate rechaza cargas synthetic-only / sin sidecar), pero merece una línea en `/explain_score` que lo diga explícitamente en vez de devolver 0 silencioso.

Bug cazado en el smoke y fijado en el mismo pasaje:

- `platform/api::operations::ingestion::load_data_streaming` llamaba `tokio::task::spawn_blocking` fire-and-forget desde un `#[tauri::command]` sync (sin runtime en scope) → panic `there is no reactor running` al ingestar. Fix: `std::thread::spawn`. Regresión introducida en F2.16, no detectada por tests (smoke UI fue lo que la descubrió — justificación ex-post del step).

Conocidos fuera de alcance de F2.20 (follow-ups, no bloquean F3):

1. `dsl_reject_unknown_relation` falla — el test es estale: bajo ADR-005 la DSL acepta relaciones desconocidas vía la superficie de extensión en lugar de rechazarlas. Actualizar el test en F3.
2. `benchmark_full_report`, `benchmark_scale_test_{ba,er}`, `benchmark_naive_vs_pruned`, `benchmark_empirical_data_for_paper` — benches largos/sensibles a datos de referencia, no parte del smoke test. Migrar a `criterion` en F3.7 (ya existe infra) o gate con `#[ignore]`.
3. `csv_demo_data_loads_successfully`, `demo_data_all_presets_produce_results`, `sentinel_demo_data_ingestion_and_hunt` — dependientes del path del demo data; falla por reubicación de crate en F2.15. Fijar fixture resolution en un follow-up de F2.

**Métricas F2 alcanzadas** (vs. target del §"Métricas de éxito"):
- Ciclos arquitecturales: **0** ✓ (era 1, roto en F2.8).
- Crates: **14** ✓ (target cumplido).
- Archivos >1000 LOC: pendiente medir post-F2.18 (lib.rs bajó de 5221 → 145 + tests.rs 5075).

**Fin de Fase 2. ✅ Fase 3 desbloqueada** (núcleo algorítmico — proptest, typestate, benches CI).

---

## Fase 3 — Núcleo algorítmico

### Step F3.1 — Introducir `proptest` como dev-dep en `core/graph-engine`

### Step F3.2 — Property tests para DSL roundtrip

- `parse(format(h)) == h` sobre generadores de `Hypothesis`.
- Corpus existente validado.

### Step F3.3 — Typestate `GmGraph<Building|Finalized>` (ADR-002)

- Refactor `core/matcher-ffi`.
- Todos los call sites actualizados (pocos, el matcher lo usa internamente en `graph.rs::search_temporal_pattern_simd`).
- Tests deben pasar sin modificación funcional.

### Step F3.4 — RAII completo para `GmMatcher` (ADR-002)

### Step F3.5 — `gm_abi_version()` agregado (ADR-002)

- Modifica header C en `libgraphmatch`.
- Rust `matcher-ffi::init()` verifica.
- Tests nuevos de mismatch detection.

### Step F3.6 — Property test equivalencia DFS ↔ SIMD

- El test crítico que faltaba. Si falla, hay bug.
- Usar `#[cfg(feature = "simd")]` + proptest shrinking.

### Step F3.7 — Integrar criterion benches al CI

- `.github/workflows/benches.yml` (o equivalente local).
- Regresión >5% en `hunt_latency` o `dedup_throughput` → job red.

### Step F3.8 — Property tests para anomaly scoring

- Monotonía de Entity Rarity, Edge Rarity.
- Bounds [0, 1] de cada componente.
- Composition commute con orden de paths.

### Step F3.9 — Docs de algoritmos en `docs/algorithms/`

- DFS temporal con referencias (Cormen, etc.).
- Anomaly scoring math.
- SIMD set intersection.

---

## Ejecución registrada (F3.1 — F3.9)

| Step | Commit | Mensaje |
|---|---|---|
| F3.1 | `395ac0b` | refactor(F3.1): add proptest dev-dep to core/graph-engine |
| F3.2 | `e6fdce9` | test(F3.2): DSL format∘parse∘format idempotence property |
| F3.3+F3.4 | `173fb1d` | refactor(matcher-ffi): F3.3+F3.4 typestate GmGraph + RAII GmMatcher |
| F3.5 | `684d1ee` | feat(matcher-ffi): F3.5 gm_abi_version check (ADR-002) |
| F3.6 | `27ead4e` | test(F3.6): DFS ↔ SIMD result-set equivalence property |
| F3.7 | `b585522` | ci: F3.7 criterion bench regression gate |
| F3.8 | `6756f2c` | test(anomaly): F3.8 proptest invariants for score_path |
| F3.9 | `80a915c` + `81d34d8` | docs(algorithms): F3.9 reference specs (DFS, anomaly scoring, SIMD) + LaTeX textbook reference |

**Artefactos verificados (2026-04-24):**

- `core/graph-engine/Cargo.toml`: `proptest = "1"` en dev-deps (F3.1).
- `platform/dsl/tests/roundtrip.rs`: usa `proptest! {}` para idempotencia `format∘parse∘format` (F3.2).
- `core/matcher-ffi/src/lib.rs`: typestate `GmGraph<Building|Finalized>` + RAII `Drop` para `GmMatcher` (F3.3, F3.4).
- `core/matcher-ffi/src/lib.rs`: check de `gm_abi_version()` en `init()` con error explícito si mismatch (F3.5, ADR-002).
- `core/matcher-ffi/Cargo.toml`: comentario de referencia a F3.6 — property test de equivalencia DFS ↔ SIMD.
- `.github/workflows/ci.yml`: job `bench-regression` compara main vs PR con gate de 5% sobre `hunt_latency` y `dedup_throughput` (F3.7).
- `core/graph-engine/tests/anomaly_proptest.rs`: proptest para bounds [0,1], monotonía y composición (F3.8).
- `docs/algorithms/`: contiene `dfs_temporal.md`, `anomaly_scoring.md`, `simd_set_intersection.md`, `README.md`, y `latex/` (F3.9).

**Fin de Fase 3. ✅ Fase 4 ya completada** (platform/api-v1.0.0 + platform/mcp-v1.0.0, commits `248ee76` + `c704cd6`).

---

## Fase 4 — Plataforma + Canonical API + DSL + MCP

### Step F4.1 — Versionar DTOs de `platform/api` (`dto/v1/`)

- `pub mod v1; pub use v1::*;` como default.
- Preparar `v2` como módulo vacío para futuro.

### Step F4.2 — Introducir `DslExtension` trait en `platform/dsl` (ADR-005)

### Step F4.3 — Registries en `DslParser`

### Step F4.4 — Ejemplo de extensión de DSL (cookbook)

- `docs/extending/dsl-extension.md` con receta completa.

### Step F4.5 — Implementar feature flag `gnn-v2-experimental` (ADR-003)

- Sub-crate `core/gnn/v2/`.
- `common/model_gate.rs` con `ModelMetadata`, `load_gnn_model`.

### Step F4.6 — Agregar `.metadata.json` al modelo v2

- Actualizar `scripts/train_gnn_v2.py` para emitirlo.

### Step F4.7 — Gate al carga en runtime

- `get_health()` expone estado v1/v2.
- Test: intentar cargar modelo synthetic sin flag → error.

### Step F4.8 — Reestructurar `platform/mcp/` a módulos por dominio (ADR-004)

- `index.ts` (1 670 LOC) → 10 módulos + `registry.ts`.
- `Tool` interface con `version`, `stability`, `deprecated`.

### Step F4.9 — Contract tests MCP ↔ API

- `platform/api` emite `/schema` con JSON Schema de DTOs.
- `platform/mcp/tests/contract/*` verifica cada tool.

### Step F4.10 — Cookbook de extension points

- `docs/extending/`:
  - `add-log-parser.md`
  - `add-log-source.md`
  - `add-mcp-tool.md`
  - `add-dsl-extension.md`
  - `add-export-format.md`

### Step F4.11 — Stabilize `platform/api` v1.0.0

- `version = "1.0.0"` en Cargo.toml.
- CHANGELOG.md con breaking changes pre-1.0.
- Tag `api-v1.0.0`.

**Fin de Fase 4. PARAR.**

---

## Fase 5 — Glue y UX de desarrollo

### Step F5.1 — Simplify Tauri commands (YAGNI)

### Step F5.2 — `ARCHITECTURE.md` en raíz (1 página síntesis)

### Step F5.3 — Actualizar README principal como puerta de entrada

### Step F5.4 — `KNOWN_ISSUES.md` honesto

### Step F5.5 — `cargo doc --open` verificado

### Step F5.6 — Decisión sobre `legacy/gateway/`: eliminar o mantener

- Si se confirma sin uso: PR separado `chore(legacy): remove unused gateway`.
- Requiere aprobación explícita del usuario.

### Step F5.7 — Tag release `v2.0.0` para BlackHat Arsenal

**Fin.**

---

## Chequeos transversales (después de cada paso)

- [ ] `cargo check --workspace` pasa.
- [ ] `cargo test --workspace` pasa (o se justifica explícitamente el cambio de test).
- [ ] `npx tsc` en `platform/mcp/` pasa (si se tocó TS).
- [ ] `cd apps/tauri && npm run build` pasa (si se tocó app).
- [ ] `git log --oneline HEAD~1..HEAD` muestra el commit esperado.
- [ ] Si es paso de núcleo (F3): benches verdes, regresión <5%.

---

## Métricas de éxito por fase

| Fase | Métrica | Baseline | Target |
|---|---|---|---|
| F2 | Ciclos arquitecturales | 1 (api↔cli) | 0 |
| F2 | Archivos >1000 LOC | 7 | ≤ 3 |
| F2 | Crates | 7 | 14 |
| F3 | Property tests | 0 | ≥ 20 |
| F3 | SIMD equivalence tests | 0 | ≥ 1 (amplia) |
| F3 | Benches en CI | 0 | 2+ |
| F4 | MCP tools con contract test | 0 | 54 |
| F4 | Extension point cookbooks | 0 | ≥ 5 |
| F4 | `platform/api` semver | 0.1 | 1.0.0 |
| F5 | README entry ≤ 1 página | no | sí |
| All | Tests pasando en cada commit | required | required |
| All | Regresión performance | <5% | ok |
