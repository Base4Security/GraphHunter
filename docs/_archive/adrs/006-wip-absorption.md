# ADR-006 — WIP Absorption: snapshot baseline antes de reorganizar

- **Fecha**: 2026-04-23
- **Estado**: propuesto
- **Decisión**: commitear el WIP actual en 3 commits atómicos como **baseline pre-rediseño**, integrándolo al rediseño (no descartándolo), antes de que Fase 2 empiece cualquier reorganización.

## Contexto

`git status` al arrancar Fase 0 mostraba:
- ~44 archivos modificados (core, api, app, mcp, gateway, cli).
- ~14 archivos untracked en `graph_hunter_api/src/` (local_llm, dto/{agentic,dlq,invariants,mapping_library}, operations/{agentic*, dlq, invariants, mapping_library}, state/agentic, tests/{agentic_loop, dlq_smoke}).
- 1 archivo untracked en Tauri commands (invariants.rs).

Lectura de las cabeceras confirma: no es código abandonado. Es **trabajo coherente de iteraciones M4 (agentic slow lane) + M5 (DLQ) + M6 (invariant checker)**. Los módulos tienen doc-comments explicando el diseño, referencias a otras capas, y tests asociados en `graph_hunter_api/tests/`.

Decisión del usuario: **integrar al rediseño para limpiarlo**.

## Decisión

### D1 — Commit atómico en 3 partes (antes de Fase 2)

Primer trabajo de Fase 2, commit 0: absorber el WIP como baseline.

**Commit 1**: `feat(api): land M4 agentic slow-lane + local-llm seam`
- `graph_hunter_api/src/local_llm/` (mod, mock, candle)
- `graph_hunter_api/src/dto/agentic.rs`
- `graph_hunter_api/src/operations/agentic.rs`
- `graph_hunter_api/src/operations/agentic_drift.rs`
- `graph_hunter_api/src/operations/agentic_review.rs`
- `graph_hunter_api/src/state/agentic.rs`
- `graph_hunter_api/tests/agentic_loop.rs`
- Modificaciones asociadas en `dto/mod.rs`, `operations/mod.rs`, `state/mod.rs`, `lib.rs`, `Cargo.toml`.

**Commit 2**: `feat(api): land M5 DLQ + M6 invariant checker + mapping library`
- `graph_hunter_api/src/dto/{dlq,invariants,mapping_library}.rs`
- `graph_hunter_api/src/operations/{dlq,invariants,mapping_library}.rs`
- `graph_hunter_api/tests/dlq_smoke.rs`
- `app/src-tauri/src/commands/invariants.rs`
- Modificaciones asociadas.

**Commit 3**: `chore(all): in-flight housekeeping pre-redesign`
- Modificaciones diversas (parsers touch-up, gateway jobs, UI components, cli).
- Revisión previa por archivo para asegurar que no incluye cambios experimentales o semi-hechos.
- Si algún archivo está en mal estado, se separa a su propio commit o se revierte explícitamente con justificación.

### D2 — Criterios de aceptación del baseline

Antes de hacer los commits:
1. **Compila**: `cargo check --workspace` pasa.
2. **Tests verdes**: `cargo test --workspace` pasa (baseline de tests que Fase 2 debe preservar).
3. **Sin `TODO!()` / `unimplemented!()`** nuevos.
4. **Sin prints de debug** (`dbg!`, `eprintln!` fuera de tests).
5. Cada commit documenta brevemente qué M incorporated (M4/M5/M6) y referencia el ADR-006.

### D3 — Archivos que requieren revisión especial

Algunos archivos modificados tienen riesgo:

- `app/src-tauri/src/commands/ingestion.rs` — ya tiene 727 LOC pre-WIP (ver PAIN_POINTS §3). El diff debe separarse: qué fue added en WIP (va al commit) vs qué es deuda pre-existente (se migra en Fase 2).
- `gateway/internal/jobs/*.go` — si son cambios reales y el gateway está archivado (ADR pendiente en Fase 5), son desperdicio. Recomendación: revertir o aislar en su commit propio marcado `legacy:`.
- `graph-hunter-mcp/src/index.ts` — si agrega tools nuevos (M4/M5/M6), commitearlos; si toca estructura monolítica que se va a reescribir en Fase 4, aislar.

### D4 — Después del baseline, `git status` queda limpio

Fase 2 arranca con:
- `git status` → sólo archivos de `docs/architecture/phase0/` y `docs/architecture/phase1/` untracked (docs de planificación).
- `cargo test --workspace` → todos los tests pasan.
- `cargo check --workspace` → sin warnings nuevos.

### D5 — Trazabilidad

Cada commit del WIP baseline incluye en el mensaje:

```
Land M4 agentic slow-lane + local-llm seam.

Absorbs pre-redesign WIP covering the six M4 operations
(ingest_negotiate, canonical_map, parser_generate, schema_drift_detect,
mapping_regression_test, invariant_check_hypothetical) and the
review-queue promotion gate. Introduces the LocalLlm trait with a
deterministic mock backend for CI.

Baseline for the layered redesign (ADR-006). Fase 2 reorganization
starts on top of this commit.
```

## Consecuencias positivas

- `main` queda en un estado lanzable (M4/M5/M6 features ya aterrizadas) **antes** de arrancar movimientos de crate.
- Si Fase 2 se pausa o rollback, el WIP está preservado en git.
- History clara: "primero aterrizó M4-M6, después reorganizamos".
- Tests de M4/M5/M6 se vuelven el baseline que Fase 2 debe mantener verde.

## Consecuencias negativas / costos

- Un paso extra antes de empezar la reorganización. Tiempo ~0.5 día.
- Requiere revisión cuidadosa de los archivos modificados (no todos son WIP de M4-M6).
- Si algún archivo modificado está a medio hacer, obliga a decisión: completar, revertir, o aislar.

## Alternativas consideradas

- **Stash + reorganizar primero, restaurar después**: rechazado; genera conflictos garantizados y pierde la trazabilidad.
- **Descartar WIP y recrearlo post-rediseño**: rechazado por decisión del usuario (integrar).
- **Un solo commit gigante "land WIP"**: rechazado; no es atómico ni auditable.

## Referencias

- PAIN_POINTS §10 (git status sucio)
- PAIN_POINTS §12.2 (local_llm/ nuevo)
- Decisión explícita del usuario: *"integremos al rediseño para limpiarlo"*.
