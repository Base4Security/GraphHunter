# EXECUTIVE_SUMMARY — Fase 0

> Síntesis de 1 página del diagnóstico. Todo lo afirmado aquí tiene evidencia en los 5 docs hermanos.
> Fecha: 2026-04-23.

## Estado actual en una frase

GraphHunter es un sistema maduro de ~68 000 LOC Rust + 13 000 LOC C++ + ~1 700 LOC TS MCP + 885 LOC Go (legacy), organizado en 7 crates Rust + motor C++ + server MCP. El problema no es falta de ingeniería — es **concentración excesiva en pocos archivos y fronteras borrosas entre núcleo y plataforma**.

## Las 3 capas hoy

- **Núcleo algorítmico** (bien formado): `libgraphmatch` C++ con dispatch SIMD (AVX2/AVX-512/NEON/scalar), `graph_hunter_core::{graph,anomaly,gnn_bridge,invariants}`, FFI aislado en **un único** `extern "C"` en `simd_matcher.rs:23`. RAII wrappers (`GmGraph`, `GmResults`). Falta RAII para `GmMatcher` y typestate para el ciclo build/finalized.

- **Plataforma** (existe pero mezclada): `graph_hunter_api` (façade + 23 operations modules + DTOs), 3 wedge crates (`canonical`, `vrl`, `constrained_decode`) con contratos estables, y el MCP server con 54 tools. **Problema**: trait `LogParser` y parsers conviven en `graph_hunter_core` en lugar de estar en plataforma; `graph_hunter_cli` se depende como lib desde `api` creando ciclo lógico.

- **Glue**: `app/src-tauri` (91 commands + `http_api.rs` de 1 662 LOC), `app/src` React con 40 componentes y 3 tests, CLI. Mostly thin delegation, salvo `commands/ingestion.rs` (727 LOC) que tiene lógica propia.

## Top 5 pain points

1. **GNN v2 "skeleton"** (riesgo de corrección): `scripts/train_gnn_v2.py:29-31` declara el modelo como no entrenado con data real; consumido en producción vía string literal. Falta feature-gate y validación mínima antes de cargar.
2. **Bifurcación CLI ↔ API** (ciclo lógico): `graph_hunter_api` depende de `graph_hunter_cli` como lib para reusar Sentinel streaming; CLI va directo a `core`. Rompe la intención "canonical API".
3. **Archivos gigantes**: `graph_hunter_core/src/lib.rs` con 5 219 LOC y **244 tests inline**; `http_api.rs` con 1 662 LOC; `graph_hunter_api/src/ai.rs` con 1 258 LOC.
4. **`gateway/` Go (885 LOC, 0 tests, 0 referencias)**: código legacy sin uso. Decidir: archivar o eliminar.
5. **Cero property tests y cero tests de equivalencia DFS ↔ SIMD**: gap crítico para refactors del núcleo (cubierto por Fase 3 del plan, pero el hueco es real hoy).

## Discrepancias con el diagnóstico del usuario

| Usuario dijo | Realidad |
|---|---|
| 37 MCP tools | **54 tools** (`grep server.tool(` = 54) |
| 94 tests | **~991 `#[test]`**, **92 `#[cfg(test)] mod`** (el 94 probablemente se refiere a módulos) |
| GNN v2 como módulo a aislar | **No existe un módulo Rust GNN v2**. Hay un modelo ONNX skeleton + script Python de training |
| "Canonical API layer a diseñar" | `graph_hunter_api` **ya es** esa canonical layer; Fase 4 es consolidación/versionado, no creación |
| "FFI aislado tras fachada segura" | **Ya cumplido** para aislamiento (1 único `extern "C"`); falta endurecer con typestate y RAII del matcher |

## Hallazgos fuera del diagnóstico del usuario

1. **`graph_hunter_canonical`, `graph_hunter_vrl`, `graph_hunter_constrained_decode`** — 3 crates wedge M3-M6 de data quality y LLM safety. No aparecen en el plan. Todos parecen estables y candidatos a Plataforma, pero merecen confirmación.
2. **`local_llm/` en `graph_hunter_api`** (untracked, WIP) — hay trabajo en progreso sobre LLM local (Candle). Condiciona la Fase 4.
3. **`IngestAdapter` trait marcado P2-E en TODO.md:34** — justo el tipo de extension point de Fase 4, pendiente desde antes del plan.
4. **`git status` sucio** — ~40 archivos modificados sin commitear + ~10 untracked. Antes de entrar Fase 1 necesitamos baseline limpia.

## Preguntas que bloquean Fase 1

1. ¿Qué hacer con los cambios no-commiteados actuales? ¿Se integran al rediseño o se resuelven antes?
2. Clasificación de `dsl` parser: ¿Núcleo (formal, inmutable) o Plataforma (extensible por usuarios)?
3. Clasificación de `graph-hunter-mcp`: ¿Plataforma (API pública de IA) o Glue (shim HTTP)?
4. `gateway/` Go: ¿archivar, eliminar, o reactivar para un uso futuro?
5. `GNN v2`: ¿aceptás el plan de gate al carga de modelo y feature flag `gnn-v2-experimental` hasta que se entrene en data real?
6. "94 tests" del plan: ¿te referías a módulos `#[cfg(test)]` (92-94 es match exacto) o a tests individuales (~991)? Esto afecta el umbral de "tests deben seguir pasando" en Fase 2.
7. `IngestAdapter` (P2-E): ¿parte de la Fase 4 o trabajo separado?

## Qué está listo para Fase 1

- Mapa de capas con casos ambiguos marcados.
- Inventario FFI con 5 recomendaciones concretas (typestate, RAII matcher, property tests, simplificar ABI, versionado).
- Top 5 pain points con evidencia de `archivo:línea`.
- Criterios de verificación del entregable (checklist en `SHEARING_MAP.md` §Checklist).

## Qué NO está en Fase 0 (y cuándo viene)

- Propuesta de arquitectura objetivo → Fase 1 (`TARGET_ARCHITECTURE.md`).
- ADRs (canonical API, FFI, GNN experimental, MCP tools) → Fase 1.
- Plan de migración incremental reversible → Fase 1 (`MIGRATION_PLAN.md`).
- Cambios de código → Fase 2 fundacional.
- Property tests + benches en CI → Fase 3.

---

**Recomendación**: aprobar Fase 0, discutir respuestas a las 7 preguntas arriba, y pasar a Fase 1 sin tocar código. El análisis sugiere que el rediseño es **reubicación + endurecimiento + documentación** más que re-implementación — el núcleo ya está bien, la plataforma ya existe parcialmente, y el glue es delgado.
