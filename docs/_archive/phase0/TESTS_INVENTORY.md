# TESTS_INVENTORY — estado de testing (Fase 0)

> Conteos derivados de grep sobre `.rs`, sin ejecutar `cargo test`.
> Fecha de corte: 2026-04-23.

---

## 1. Totales por crate / paquete

| Crate / paquete | `#[test]` + `#[tokio::test]` (grep) | Archivos con tests | Integration tests (`tests/*.rs`) | `#[cfg(test)]` modules | Benches | Property tests |
|---|---:|---:|---:|---:|---:|---:|
| `graph_hunter_core` | **718** | 67 | 22 | 51 | **2** (criterion) | 0 |
| `graph_hunter_api` | **207** | 40 | 12 | 30 | 0 | 0 |
| `graph_hunter_canonical` | ~13 | 3 | 1 | 2 | 0 | 0 |
| `graph_hunter_vrl` | ~14 | 4 | 1 | 3 | 0 | 0 |
| `graph_hunter_constrained_decode` | ~16 | 3 | 2 | 1 | 0 | 0 |
| `graph_hunter_cli` | ~5 | 3 | 0 | 3 | 0 | 0 |
| `app/src-tauri` | ~18 | 6 | 0 | 2 | 0 | 0 |
| **Total Rust** | **~991** | **126** | **38** | **92** | **2** | **0** |
| `app/src` (React, vitest) | — | 3 | — | — | — | — |
| `graph-hunter-mcp` (TS) | **0** | 0 | 0 | — | 0 | 0 |
| `gateway` (Go) | **0** | 0 | 0 | — | 0 | 0 |

> Nota sobre "94 tests" mencionado por el usuario: el conteo más cercano es **92 `#[cfg(test)]` modules** en Rust (suma de columna 5). La cifra "94" probablemente se refiere a esto o a una suma incluyendo los 2 de C++ / async. No son "tests individuales".

---

## 2. Integration tests por archivo (`tests/`)

### `graph_hunter_core/tests/` (22 archivos)

| Archivo | # tests | Propósito (inferido) |
|---|---:|---|
| `parsers.rs` | 59 | tests de parsers (probablemente Sysmon, Sentinel, IIS, Cognito, FortiAnalyzer, CSV, Generic) |
| `graph_pattern.rs` | 10 | pattern matching end-to-end |
| `dsl_predicates.rs` | 9 | DSL con predicados |
| `catalog_compatibility.rs` | 7 | compatibilidad de catálogos |
| `expand_fallback.rs` | 6 | fallback en expand_node |
| `dsl_bindings.rs` | 5 | bindings DSL → runtime |
| `hunt_diagnostic.rs` | 5 | diagnóstico de hunts |
| `path_dedup.rs` | 5 | dedup de paths |
| `search_entities.rs` | 5 | búsqueda de entidades |
| `classifier_seam.rs` | 5 | trait classifier |
| `temporal_heatmap.rs` | 5 | heatmap temporal |
| `diff_hunts.rs` | 4 | diff entre hunts |
| `aggregation.rs` | 4 | agregación |
| `relation_schema.rs` | 4 | schema de relaciones |
| `mvcc_ingested_at.rs` | 4 | MVCC timestamps (seam, no full) |
| `scoring_snapshot.rs` | 4 | snapshot scoring |
| `simd_matcher_test.rs` | **3** | FFI SIMD — muy pocos para un componente crítico |
| `hunt_diagnostic_predicates.rs` | 3 | diagnóstico con predicados |
| `backend_dual_impl.rs` | 3 | backends dual (seam test) |
| `spill_streaming.rs` | 3 | spill-to-disk |
| `hunt_provenance.rs` | 2 | provenance en hunts |
| `catalog_golden.rs` | 1 | golden file catalog |

### `graph_hunter_api/tests/` (12 archivos)

| Archivo | # tests | Propósito |
|---|---:|---|
| `parity/scenarios.rs` | 16 | parity tests Tauri commands ↔ API HTTP |
| `parity/dto_shapes.rs` | 19 | DTO shape parity |
| `export_ocsf.rs` | 4 | export OCSF |
| `invariants_api.rs` | 3 | API de invariants |
| `mapping_library_publish.rs` | 3 | publish de mapping library |
| `mapping_library_rag.rs` | 3 | RAG sobre mapping library |
| `agentic_loop.rs` | 2 | loop completo agentic |
| `dlq_smoke.rs` | 2 | DLQ smoke |
| `drift_smoke.rs` | 2 | drift smoke |
| `preview_defaults.rs` | 1 | previsualización defaults |
| `parity.rs` | — | (wrapper de parity) |

### Otros crates

- `graph_hunter_canonical/tests/schema_validation.rs` (8 tests) — valida contra `ocsf_v1_4.json`.
- `graph_hunter_vrl/tests/golden_three_formats.rs` (7 tests) — golden file tests sobre compiler.
- `graph_hunter_constrained_decode/tests/compiler_roundtrip.rs` (4 tests) + `fuzz_validator.rs` (2 tests).

---

## 3. Inline tests (`#[cfg(test)] mod tests`)

Los hot-spots por archivo con más tests inline:

| Archivo | # `#[test]` | Observación |
|---|---:|---|
| `graph_hunter_core/src/lib.rs` | **244** | excesivo; debería partirse. Ver PAIN_POINTS §1. |
| `graph_hunter_core/src/ip_utils.rs` | 30 | razonable para una utility |
| `graph_hunter_core/src/service_classifier.rs` | 30 | razonable |
| `graph_hunter_api/src/ai.rs` | 21 | razonable para un módulo crítico |
| `graph_hunter_core/src/invariants/predicates.rs` | 19 | razonable |
| `graph_hunter_core/src/iis_w3c.rs` | 14 | razonable |
| `graph_hunter_core/src/forti_analyzer.rs` | 17 | razonable |
| `graph_hunter_api/tests/parity/scenarios.rs` | 16 | integration, no inline |
| `graph_hunter_api/tests/parity/dto_shapes.rs` | 19 | integration, no inline |

---

## 4. Property-based testing

- **proptest**: 0 archivos.
- **quickcheck**: 0 archivos.
- **Estado**: ausente. Esto está **dentro del plan del usuario (Fase 3)**. No es un problema, es trabajo planeado.
- Candidatos obvios para proptest (a definir en Fase 3):
  - DSL parser (`graph_hunter_core/src/dsl.rs`): roundtrip `format(parse(x)) == x` sobre hipótesis válidas.
  - Matcher: equivalencia entre pure-Rust DFS y SIMD sobre grafos aleatorios.
  - Anomaly scorer: propiedades de monotonía, bounds.
  - Invariants/treewidth: propiedades estructurales (grafo serial-paralelo, etc.).
  - Canonical OCSF projection: `ocsf_to_triple(triple_to_ocsf(t)) == t` para triples válidos.

---

## 5. Benches (criterion)

Sólo `graph_hunter_core/Cargo.toml` declara `criterion` como dev-dep. 2 benches activos:

| Bench | Función medida | File:line |
|---|---|---|
| `hunt_latency` | `GraphHunter::search_temporal_pattern` | `graph_hunter_core/benches/hunt_latency.rs:1-47` → `graph.rs:481` |
| `dedup_throughput` | `score_and_paginate_paths` con `DedupMode::ByPath` | `graph_hunter_core/benches/dedup_throughput.rs:1-47` → `analytics.rs` |

Más 2 benches C++ (`libgraphmatch`): `bench_intersect`, `bench_matching`.

**Brecha**: los benches no están integrados al CI (no `.github/workflows/` detectado con step criterion). Plan del usuario Fase 3 pide integrar al CI.

---

## 6. Coverage gaps — módulos > 200 LOC sin tests visibles

### Tauri / src-tauri

| File | LOC | Tests | Notas |
|---|---:|---|---|
| `lib.rs` | ~580 | 0 | session state mgmt crítica |
| `http_api.rs` | 1 662 | 0 | todas las rutas Axum |
| `commands/ingestion.rs` | 727 | 0 | ver PAIN_POINTS §3 |
| `commands/graph_ops.rs` | ~240 | 0 | hunt execution |
| `sentinel_connector.rs` (api) | 354 | 0 | real-time polling |

### graph_hunter_core

- `spill.rs` (1 152 LOC, 10 `#[test]`) — coverage parcial; falta integration sobre rotación de archivos.
- `generic.rs` (1 389 LOC): no detectado conteo, revisar.
- `sysmon.rs` (881 LOC), `iis_w3c.rs` (14 tests): coverage aceptable.

### Gateway / MCP

- **Gateway Go**: 0 tests, 885 LOC. Ver PAIN_POINTS §5.
- **graph-hunter-mcp TS**: 0 tests, 1 670 LOC (index.ts). Las 54 tools delegan via HTTP → los tests de parity de `graph_hunter_api/tests/parity/` cubren el contrato, pero NO el código TS (errores de serialización, timeouts, auth).

### Frontend React

- 3 archivos test (HuntResultsTable, NotesPanel, SessionSelector).
- 40 `.tsx` → cobertura ~7.5%. Glue, aceptable bajo YAGNI, pero el Event-View freeze (TODO.md §1) amerita test de regresión.

---

## 7. SIMD coverage específica

- `graph_hunter_core/tests/simd_matcher_test.rs` — **sólo 3 tests** para toda la superficie FFI.
- `graph_hunter_core/src/simd_rust.rs` — 9 `#[test]` inline para AVX2 Rust-side.
- `libgraphmatch/tests/` — 5 executables C++ con doctest:
  - `test_simd_intersect`, `test_csr_graph`, `test_pruning`, `test_matcher`, `test_apt29_killchain`.

**Hueco crítico**: **no hay test de equivalencia SIMD ↔ pure-Rust sobre corpus común**. Los 3 tests de `simd_matcher_test.rs` presumiblemente son smoke. Si los resultados del matcher SIMD y del DFS Rust divergen, sólo se detecta en producción.

Plan del usuario Fase 3 exige property tests de equivalencia — ese es el cierre de este gap.

---

## 8. Tests async (tokio)

- `graph_hunter_core`: 2 `#[tokio::test]`.
- `graph_hunter_api`: 1 `#[tokio::test]`.

Superficie async mayormente untested. `sentinel_connector.rs`, `ingest/source_poller.rs`, `local_llm/candle.rs`, `operations/agentic*.rs` son todos async y la cobertura es mínima.

---

## 9. Recomendaciones para Fase 0 (sólo inventario; acción en Fase 1+)

Estas son **observaciones** — no acciones. Fase 0 termina aquí.

1. **Fase 3 del plan del usuario** cubre naturalmente la introducción de proptest y la equivalencia SIMD/pure-Rust.
2. **Fase 4** debería incluir tests de integración para cada "extension point" formalizado (LogParser, IngestAdapter, Tool MCP, LocalLlm backend).
3. **Fase 2 (fundacional)**: mover los 244 tests inline de `lib.rs` a `tests/` o a submódulos es un cambio de bajo riesgo con alto impacto de legibilidad.
4. **CI**: detectar si hay un `.github/workflows/ci.yml` (Fase 0 no lo auditó). Recomendación para Fase 1: un ADR sobre política de CI (benches, SIMD cross-validation, regression detection >5%).

---

## 10. Resumen ejecutivo (para el EXECUTIVE_SUMMARY.md)

- **~991 tests Rust** (suma `#[test]/#[tokio::test]`), **38 integration files**, **2 benches criterion**.
- **0 property tests, 0 SIMD equivalence tests** — huecos principales cubiertos por Fase 3 del plan.
- **0 tests Go/TS** fuera de parity tests indirectos.
- **Concentración inaceptable**: 244 tests inline en `lib.rs`.
- **Glue (Tauri/React) y MCP** están sub-testeados. YAGNI lo excusa parcialmente; solo auditar Fase 5.
