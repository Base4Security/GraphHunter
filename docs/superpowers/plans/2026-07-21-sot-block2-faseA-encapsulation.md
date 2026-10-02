# Fase A (Bloque 2): Encapsulación — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cerrar la brecha S6 añadiendo `capabilities()` a `LogSource`, y convertir el KQL crudo de analista en un escape hatch explícitamente etiquetado, auditado y desactivable por feature flag — sin cambiar el comportamiento externo por defecto.

**Architecture:** Tres frentes: (1) Rust `platform/sources` — un tipo `SourceCapabilities` y un método de trait con default, implementado por las 3 fuentes reales; (2) Rust `platform/api`/`apps/tauri` — un gate de feature flag en el borde HTTP `/kql` (donde entra el KQL libre del analista), con auditoría, que deja intactos los caminos que no son escape hatch (run_hunt, graph_*, journal expand, graph_build); (3) TypeScript `platform/mcp` — metadata de escape hatch en `sentinel_query` y etiquetado de resultados como tabulares-de-fuente. Más docs y una verificación de que la superficie de auditoría del Bloque 1 no cambia (Fase A no crea, encapsula).

**Tech Stack:** Rust (async-trait, tokio, axum handlers, `tracing`), TypeScript (zod, `node:test`), Python (el runner de auditoría del repo sot, solo para verificación no-op).

## Reconciliación de alcance (leer antes de empezar)

El spec §5 Bloque 2 Fase A dice "mover todo KQL de `platform/mcp/src/tools/graph/*` y `sentinel/query.ts` detrás del conector". El assessment del Bloque 0 (secciones S7/S8, `docs/architecture/sot-integration-assessment.md` @ b9335cf) **corrigió esa premisa**:

- Los tools `graph/{propose,build,path,neighbors}.ts` **no construyen ni envían KQL ejecutable** — el KQL aparece solo como texto de descripción/prosa; `graph_path`/`graph_neighbors` son lecturas de grafo puras, `graph_propose`/`graph_build` rutean a endpoints que generan KQL *de recolección* server-side (compliant, no escape hatch). (S7 filas 1507-1510, S8 1906-1917.)
- `sentinel/query.ts` **ya es el escape hatch** — único tool con KQL de texto libre, ya marcado "ADVANCED escape hatch" en su descripción, ya con `max_rows` y el gate §4.7 (`sentinel/query.ts:6,31,37`). (S8 1875-1888.)
- La ejecución de KQL crudo vive en `handler_run_kql` → `api.run_kql` (`operations/sentinel.rs:320`). (S7 fila 1467, "Nada calificó para eliminar" 1635.)

Por lo tanto Fase A **no mueve KQL inexistente**. Encapsula lo que existe: (a) declara capacidades de fuente (la brecha S6 real y el único código nuevo sustantivo); (b) hace del escape hatch un contrato *ejecutable* (gate por flag en el borde HTTP, auditoría, etiquetado) en vez de solo prosa; (c) documenta la separación. Esto satisface la intención del spec §2/§14 ("KQL solo dentro del conector para recolección; escape hatch marcado, no usado internamente por run_hypothesis, con límites, auditoría, resultados claramente tabulares") sobre la realidad corregida. La divergencia respecto de la letra del spec es deliberada y se documenta en el entregable de migración (Task 5).

## Global Constraints

- **Sin cambio de comportamiento externo por defecto** (spec Fase A): el flag `GRAPHHUNTER_KQL_ESCAPE_HATCH` está **habilitado por defecto**; solo desactivarlo explícitamente cambia el comportamiento. Convención de flag runtime del repo: env var booleana (`platform/api/src/operations/negotiation.rs:41-45`).
- **El gate del escape hatch aplica SOLO al KQL de texto libre del analista** (`POST /kql` vía `handler_run_kql`), nunca a callers internos de `api.run_kql` (journal expand) ni al KQL de recolección generado por el sistema (`graph_build`/`graph_propose`). Ubicar el gate en el handler HTTP, no dentro de `run_kql`.
- **`capabilities()` es aditivo con default** — no debe romper la object-safety del trait (test guard en `lib.rs:419`) ni obligar a reescribir las 3 impls de golpe; el default expresa el caso conservador.
- **Rama:** `spec/hunt-journal` en `C:\Users\lsotomayor\GraphHunter`. Hay WIP ajeno sin commitear (incl. `core/graph-engine/src/generic.rs`, tests de parsers — trabajo del usuario). **Jamás** `git add -A` / `git stash` / `git checkout --`; `git add` solo los archivos que cada tarea nombra.
- **Idioma:** código y comentarios de código en inglés (convención del repo); prosa de docs en español (convención de los docs SOT del repo).
- **Cargo build/test:** el workspace no tiene raíz Cargo única (`.cargo/config.toml:16-18`); compilar/testear por crate: `cargo test -p graph_hunter_sources`, `cargo test -p graph_hunter_api`. MCP: `cd platform/mcp && npm run build && npm run test:contract` (requiere `tsc`; contract tests gated por `GRAPHHUNTER_CONTRACT_TEST=1` contra server vivo — los tests puros de unidad no).
- **Verificación de no-op de auditoría:** al final, el runner del Bloque 1 (`sot/scripts/sot_sys/audit_graphhunter.py --check`) debe seguir "up to date" — Fase A no toca ningún canal de `ingest_surface.json` (los 11 fixes apuntan a Fase B/C/Coverage, ninguno a Fase A).
- **Disciplina de claims en docs:** cada afirmación fáctica sobre el código cita `path:line`; nada de "mínimo/suficiente" fuera de lo que el test demuestra.

---

### Task 1: `SourceCapabilities` struct + `capabilities()` en el trait (Rust, TDD)

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\sources\src\lib.rs` (añadir el struct antes del trait ~línea 273; añadir el método al trait con default ~línea 288; añadir tests al módulo `tests` ~línea 347)

**Interfaces:**
- Produces: `pub struct SourceCapabilities { pub append_only: bool, pub supports_corrections: bool, pub supports_deletions: bool, pub guarantees_order: bool, pub stable_event_ids: bool, pub supports_pagination: bool, pub supports_time_filter: bool, pub supports_field_filter: bool, pub supports_backfill: bool, pub provides_event_and_ingestion_time: bool, pub max_known_lag: Option<Duration>, pub opaque_checkpoints: bool }` con `impl Default` (todo el caso conservador) y `impl SourceCapabilities` con constructor `kql_query_source()`; `LogSource::capabilities(&self) -> SourceCapabilities` con default que retorna `SourceCapabilities::default()`. Task 2 sobreescribe `capabilities()` en las 3 fuentes.

- [ ] **Step 1: Escribir el test que falla**

Añadir al módulo `#[cfg(test)] mod tests` en `platform/sources/src/lib.rs` (después del test `dyn_logsource_is_object_safe`, dentro del mismo módulo):

```rust
    #[test]
    fn default_capabilities_are_conservative() {
        // The conservative default: assume the worst (no guarantees) so a
        // source that hasn't declared its capabilities can never be treated
        // as append-only, ordered, or stable-id'd by mistake.
        let c = SourceCapabilities::default();
        assert!(!c.append_only);
        assert!(!c.guarantees_order);
        assert!(!c.stable_event_ids);
        assert!(!c.supports_backfill);
        assert!(c.opaque_checkpoints);
        assert!(c.max_known_lag.is_none());
    }

    #[test]
    fn kql_query_source_preset_declares_pagination_and_time_filter() {
        let c = SourceCapabilities::kql_query_source();
        assert!(c.supports_pagination);
        assert!(c.supports_time_filter);
        assert!(c.supports_field_filter);
        assert!(c.supports_backfill);
        // KQL query APIs are append-only logs with no stable per-row id and
        // no correction/deletion semantics.
        assert!(c.append_only);
        assert!(!c.supports_corrections);
        assert!(!c.supports_deletions);
        assert!(!c.stable_event_ids);
    }

    #[test]
    fn trait_default_capabilities_matches_struct_default() {
        let m = MockSource { id: "cap".to_string(), tables: vec!["SecurityEvent"] };
        // MockSource does NOT override capabilities(), so it gets the default.
        assert_eq!(m.capabilities(), SourceCapabilities::default());
    }
```

Nota: `SourceCapabilities` necesita `#[derive(PartialEq)]` para `assert_eq!`. El `MockSource` está en el mismo módulo de test (`lib.rs:358`).

- [ ] **Step 2: Correr y ver fallar**

Run: `cd C:\Users\lsotomayor\GraphHunter && cargo test -p graph_hunter_sources capabilities`
Expected: FAIL de compilación — `cannot find type SourceCapabilities` / `no method named capabilities`.

- [ ] **Step 3: Implementar**

Añadir antes de `#[async_trait] pub trait LogSource` (~línea 274 de `lib.rs`):

```rust
/// What a source can and cannot promise about the data it yields. Declared,
/// not inferred: a connector states these so the upper layers never assume a
/// guarantee (append-only, ordering, stable ids, backfill) the source can't
/// actually keep. The conservative `Default` assumes no guarantees.
///
/// SOT context: this is the "capabilities" the ADR
/// (`docs/adr/ADR-SOT-source-independent-ingestion.md`, Clase de realización R)
/// and the design spec §6 require each connector to declare. It closes the
/// S6 assessment gap (`docs/architecture/sot-integration-assessment.md`): the
/// trait previously had no runtime capability surface, only `available_tables()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceCapabilities {
    /// The source only ever adds records; it never rewrites history in place.
    pub append_only: bool,
    /// The source can emit corrected versions of previously-emitted records.
    pub supports_corrections: bool,
    /// The source can signal that a previously-emitted record was deleted.
    pub supports_deletions: bool,
    /// Records arrive in a stable order (e.g. non-decreasing event time).
    pub guarantees_order: bool,
    /// Every record carries a stable, source-native unique id.
    pub stable_event_ids: bool,
    /// The source supports paged retrieval of a result set.
    pub supports_pagination: bool,
    /// The source supports server-side filtering by time range.
    pub supports_time_filter: bool,
    /// The source supports server-side filtering by field/column value.
    pub supports_field_filter: bool,
    /// The source supports fetching a bounded historical range on demand.
    pub supports_backfill: bool,
    /// The source distinguishes event time from ingestion time per record.
    pub provides_event_and_ingestion_time: bool,
    /// A known upper bound on how stale the source can be, if any.
    pub max_known_lag: Option<Duration>,
    /// The resume checkpoint is opaque (a string the upper layer must not
    /// interpret) rather than a structured, interpretable cursor.
    pub opaque_checkpoints: bool,
}

impl Default for SourceCapabilities {
    fn default() -> Self {
        // Conservative: promise nothing. An undeclared source is treated as
        // unordered, id-less, correction-less, non-backfillable.
        SourceCapabilities {
            append_only: false,
            supports_corrections: false,
            supports_deletions: false,
            guarantees_order: false,
            stable_event_ids: false,
            supports_pagination: false,
            supports_time_filter: false,
            supports_field_filter: false,
            supports_backfill: false,
            provides_event_and_ingestion_time: false,
            max_known_lag: None,
            opaque_checkpoints: true,
        }
    }
}

impl SourceCapabilities {
    /// Preset for a KQL query API (Log Analytics / Data Lake v2 / Defender
    /// XDR): an append-only log queryable with server-side time and field
    /// filters and pagination, backfillable by widening the time range, with
    /// no stable per-row id and no correction/deletion semantics.
    pub fn kql_query_source() -> Self {
        SourceCapabilities {
            append_only: true,
            supports_pagination: true,
            supports_time_filter: true,
            supports_field_filter: true,
            supports_backfill: true,
            opaque_checkpoints: true,
            ..SourceCapabilities::default()
        }
    }
}
```

Añadir al trait `LogSource`, después de `available_tables` (~línea 288), con default:

```rust
    /// What this source can and cannot promise. Declared per-connector so the
    /// upper layers never assume an unbacked guarantee. The default is the
    /// conservative "promise nothing"; real sources override it.
    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities::default()
    }
```

- [ ] **Step 4: Correr y ver pasar**

Run: `cargo test -p graph_hunter_sources capabilities`
Expected: PASS (3 tests). Luego `cargo test -p graph_hunter_sources` completo: verde (incl. `dyn_logsource_is_object_safe` — el default no rompe object-safety).

- [ ] **Step 5: Commit**

```powershell
Set-Location C:\Users\lsotomayor\GraphHunter
git add platform/sources/src/lib.rs
git commit -m "feat(sources): SourceCapabilities + LogSource::capabilities() with conservative default (S6 gap)"
```

---

### Task 2: `capabilities()` en las 3 fuentes reales (Rust, TDD)

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\sources\src\log_analytics.rs` (impl del método + test)
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\sources\src\defender_xdr.rs` (impl del método + test)
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\sources\src\data_lake.rs` (impl del método + test)

**Interfaces:**
- Consumes: `SourceCapabilities`, `SourceCapabilities::kql_query_source()`, `LogSource::capabilities()` de Task 1.
- Produces: cada una de las 3 impls de `LogSource` sobreescribe `capabilities()`.

- [ ] **Step 1: Escribir los tests que fallan**

En `log_analytics.rs`, dentro de su `#[cfg(test)] mod tests` (existe — el módulo tiene tests en `:526-796` según el assessment), añadir. Primero LEER el módulo de test para reutilizar su patrón de construcción de `LogAnalyticsSource` (probablemente hay un helper `fn test_source()` o similar; si no, construir mínimamente). Test:

```rust
    #[test]
    fn log_analytics_declares_kql_query_capabilities() {
        let src = test_source(); // reuse the module's existing constructor helper
        let c = src.capabilities();
        assert!(c.append_only);
        assert!(c.supports_time_filter);
        assert!(c.supports_pagination);
        assert!(c.supports_backfill);
        assert!(!c.stable_event_ids);
        assert!(!c.supports_deletions);
    }
```

Análogo en `defender_xdr.rs` (`defender_declares_kql_query_capabilities`) y `data_lake.rs` (`data_lake_declares_kql_query_capabilities`), usando el constructor de test de cada módulo. Si un módulo no tiene helper de construcción reutilizable, el implementador debe LEER el `mod tests` de ese archivo y replicar cómo instancia la fuente (no inventar campos).

- [ ] **Step 2: Correr y ver fallar**

Run: `cargo test -p graph_hunter_sources declares_kql_query_capabilities`
Expected: FAIL — las asserts fallan porque las 3 fuentes usan el default (`append_only == false`).

- [ ] **Step 3: Implementar**

En cada una de las 3 impls de `impl LogSource for <Source>`, añadir el override (después de `available_tables`):

```rust
    fn capabilities(&self) -> SourceCapabilities {
        // KQL query API: append-only, time/field filterable, paginated,
        // backfillable by widening the range; no stable per-row id, no
        // correction/deletion semantics, opaque ISO-8601 watermark.
        SourceCapabilities::kql_query_source()
    }
```

Para `defender_xdr.rs` y `data_lake.rs`, si el import de `SourceCapabilities` no está, añadir `use crate::SourceCapabilities;` (o al `use crate::{...}` existente). Nota data_lake es un stub (`data_lake.rs:71`) — declarar `kql_query_source()` es correcto de intención aunque la query no esté implementada; si el implementador juzga que un stub debe declarar el default conservador en su lugar, ese es un llamado defendible — documentarlo en el reporte, pero el test pide `kql_query_source()`; mantener consistencia (los tres son APIs KQL).

- [ ] **Step 4: Correr y ver pasar**

Run: `cargo test -p graph_hunter_sources`
Expected: PASS — los 3 nuevos + todos los preexistentes verdes.

- [ ] **Step 5: Commit**

```powershell
git add platform/sources/src/log_analytics.rs platform/sources/src/defender_xdr.rs platform/sources/src/data_lake.rs
git commit -m "feat(sources): declare KQL-query capabilities for LogAnalytics/Defender/DataLake"
```

---

### Task 3: Gate del escape hatch por feature flag + auditoría (Rust, TDD)

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\apps\tauri\src-tauri\src\http\siem.rs` (gate + audit log en `handler_run_kql`, ~líneas 42-71)
- Create: `C:\Users\lsotomayor\GraphHunter\apps\tauri\src-tauri\src\http\escape_hatch.rs` (helper del flag + test)
- Modify: `C:\Users\lsotomayor\GraphHunter\apps\tauri\src-tauri\src\http\mod.rs` (declarar `mod escape_hatch;`)

**Interfaces:**
- Produces: `escape_hatch::kql_escape_hatch_enabled() -> bool` (lee `GRAPHHUNTER_KQL_ESCAPE_HATCH`, default `true`); `escape_hatch::disabled_response() -> (StatusCode, Json<Value>)` (respuesta estructurada que dirige a los graph tools).
- Consumes: nada de tareas previas.

- [ ] **Step 1: Escribir el test del helper (falla)**

Crear `apps/tauri/src-tauri/src/http/escape_hatch.rs`:

```rust
//! The raw-KQL escape hatch: a feature-flagged, audited boundary for
//! analyst-supplied free-text KQL. Enabled by default (no external behavior
//! change); set GRAPHHUNTER_KQL_ESCAPE_HATCH to a falsy value to disable the
//! raw /kql path and steer callers to the graph tools. This gate lives at the
//! HTTP boundary so system-internal callers of `api.run_kql` (journal expand)
//! and system-generated collection KQL (graph_build/graph_propose) are
//! unaffected — only free-text analyst KQL entering via POST /kql is gated.

/// Whether the raw-KQL escape hatch is enabled. Default: enabled. Only an
/// explicit falsy value ("0"/"false"/"no"/"off", case-insensitive) disables it.
pub fn kql_escape_hatch_enabled() -> bool {
    match std::env::var("GRAPHHUNTER_KQL_ESCAPE_HATCH") {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ),
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests mutate a process-global env var; keep them in one test to
    // avoid cross-test races under the default multi-threaded runner.
    #[test]
    fn flag_defaults_enabled_and_respects_explicit_falsy() {
        std::env::remove_var("GRAPHHUNTER_KQL_ESCAPE_HATCH");
        assert!(kql_escape_hatch_enabled(), "default must be enabled");

        for off in ["0", "false", "FALSE", "no", "off", " off "] {
            std::env::set_var("GRAPHHUNTER_KQL_ESCAPE_HATCH", off);
            assert!(!kql_escape_hatch_enabled(), "{off:?} should disable");
        }
        for on in ["1", "true", "yes", "on", "anything"] {
            std::env::set_var("GRAPHHUNTER_KQL_ESCAPE_HATCH", on);
            assert!(kql_escape_hatch_enabled(), "{on:?} should enable");
        }
        std::env::remove_var("GRAPHHUNTER_KQL_ESCAPE_HATCH");
    }
}
```

Declarar el módulo: en `apps/tauri/src-tauri/src/http/mod.rs`, junto a los otros `mod <x>;` de submódulos http (buscar el bloque `mod siem;` etc.), añadir `mod escape_hatch;`.

- [ ] **Step 2: Correr y ver fallar/pasar el helper**

Run: `cargo test -p graph_hunter_app_lib escape_hatch` (o el nombre del crate de `apps/tauri/src-tauri`; confirmar en su `Cargo.toml` `[package] name`; el assessment lo llama `graph_hunter_app_lib`).
Expected: primero FAIL de compilación si el `mod` no está declarado; tras declararlo, PASS del test del helper. (El helper es correcto de una; el "fail" real es el gate en el handler, Step 3-4.)

- [ ] **Step 3: Escribir el test de integración del gate (falla)**

Antes de tocar el handler, LEER `apps/tauri/src-tauri/src/http/siem.rs:42-71` (`handler_run_kql`) para conocer su firma exacta (tipo de `State`, `Json<...>` de entrada, tipo de retorno — probablemente `impl IntoResponse` o `Result<Json<..>, ..>`), y cómo los otros handlers construyen respuestas de error en ese archivo. El test de integración vive donde `apps/tauri` tenga sus tests de http (buscar un `#[cfg(test)]` en `http/mod.rs` o un `tests/` del crate; si no existe infraestructura de test http, añadir un test acotado en `siem.rs` que ejerza solo la rama del gate llamando a `handler_run_kql` con el flag apagado y un `State`/request mínimos).

Test (adaptar la construcción de `State`/`Json` a las firmas reales que leas — este es el contrato a satisfacer):

```rust
    // With the escape hatch disabled, POST /kql must NOT reach api.run_kql;
    // it returns a structured "disabled" response steering to graph tools.
    #[tokio::test]
    async fn kql_gate_blocks_when_flag_disabled() {
        std::env::set_var("GRAPHHUNTER_KQL_ESCAPE_HATCH", "0");
        let resp = crate::http::escape_hatch::disabled_response();
        std::env::remove_var("GRAPHHUNTER_KQL_ESCAPE_HATCH");
        // disabled_response is (StatusCode, Json<Value>); assert its shape.
        let (status, body) = resp;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
        let v: serde_json::Value = body.0;
        assert_eq!(v["error"], "kql_escape_hatch_disabled");
        assert!(v["hint"].as_str().unwrap().contains("graph"));
    }
```

- [ ] **Step 4: Implementar el gate + auditoría + `disabled_response`**

Añadir a `escape_hatch.rs`:

```rust
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

/// Structured response returned by POST /kql when the escape hatch is
/// disabled. Names the disabled feature and steers to the graph tools.
pub fn disabled_response() -> (StatusCode, Json<Value>) {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": "kql_escape_hatch_disabled",
            "hint": "Raw KQL is disabled (GRAPHHUNTER_KQL_ESCAPE_HATCH). Use the \
                     graph tools (sentinel_seed, node_enrich, hunt_run, graph_path, \
                     graph_neighbors) — the correlated graph, not raw source rows.",
            "source_tabular": true
        })),
    )
}
```

En `handler_run_kql` (`http/siem.rs`), como PRIMERA acción del cuerpo, antes de llamar `api.run_kql(...)`:

```rust
    // Escape-hatch gate: analyst free-text KQL is a marked, audited, disable-able
    // boundary. System-internal run_kql callers (journal expand) and system-
    // generated collection KQL (graph_build) do NOT pass through this handler.
    if !crate::http::escape_hatch::kql_escape_hatch_enabled() {
        tracing::warn!(target: "kql_escape_hatch", "raw /kql blocked: escape hatch disabled");
        return crate::http::escape_hatch::disabled_response().into_response();
    }
    tracing::warn!(
        target: "kql_escape_hatch",
        kql_len = body.kql.len(),
        ingest = body.ingest,
        "raw /kql escape hatch invoked (analyst free-text KQL)"
    );
```

Ajustar: (a) el tipo de retorno del handler — si no es `impl IntoResponse`, adaptar el early-return a lo que el handler retorna (p. ej. envolver en su `Result<Json<..>, (StatusCode, ..)>`); el implementador debe hacer que compile respetando la firma real, sin cambiar el tipo de retorno del handler si otros callers dependen de él. (b) los nombres de campo del body (`body.kql`, `body.ingest`) según la struct `RunKqlRequest` real que se deserializa — LEERLA. (c) `.into_response()` requiere `use axum::response::IntoResponse;` en el scope del handler.

- [ ] **Step 5: Correr y ver pasar; probar no-regresión**

Run: `cargo test -p graph_hunter_app_lib escape_hatch kql_gate` (o el nombre real del crate).
Expected: PASS. Luego el crate completo: `cargo test -p graph_hunter_app_lib` — verde (el gate por default habilitado no cambia nada; los tests preexistentes de http/journal/hunt siguen pasando porque no entran por `handler_run_kql`).

- [ ] **Step 6: Commit**

```powershell
git add apps/tauri/src-tauri/src/http/escape_hatch.rs apps/tauri/src-tauri/src/http/siem.rs apps/tauri/src-tauri/src/http/mod.rs
git commit -m "feat(http): feature-flag + audit the raw-KQL escape hatch at the /kql boundary"
```

---

### Task 4: Etiquetado del escape hatch y resultados tabulares en el MCP (TypeScript, TDD)

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\mcp\src\tools\sentinel\query.ts` (metadata `escapeHatch` + envolver resultado con `source_tabular: true`)
- Create: `C:\Users\lsotomayor\GraphHunter\platform\mcp\tests\contract\sentinel-query-escape-hatch.test.ts`

**Interfaces:**
- Consumes: el contrato de `defineTool` (`platform/mcp/src/lib/types.js`) y `ctx.api.post` (`lib/api-client.js`).
- Produces: `sentinelQuery` con un campo booleano de metadata que lo marca como escape hatch, y su `execute` etiquetando la respuesta como tabular-de-fuente. Un test de contrato que lo verifica sin server vivo.

- [ ] **Step 1: Escribir el test que falla**

Primero LEER `platform/mcp/src/lib/types.ts` para ver si `defineTool` acepta campos de metadata arbitrarios o si hay un campo declarado para esto (p. ej. `stability`, `category` ya existen). Si `defineTool` valida un shape cerrado, añadir un campo `escapeHatch?: boolean` a su tipo/schema como parte de esta tarea (mínimo, opcional, default ausente). Test (`node:test`, patrón de `tests/contract/*.test.ts`):

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { sentinelQuery } from "../../src/tools/sentinel/query.js";

test("sentinel_query is flagged as an escape hatch", () => {
  assert.equal(sentinelQuery.escapeHatch, true);
  assert.equal(sentinelQuery.name, "sentinel_query");
});

test("sentinel_query labels its result as source-tabular, not a graph answer", async () => {
  // Stub ctx.api.post to return raw rows; execute must wrap them so the
  // caller can never mistake source rows for a causal graph result.
  const calls: Array<{ path: string; body: unknown }> = [];
  const ctx = {
    api: {
      post: async (path: string, body: unknown) => {
        calls.push({ path, body });
        return { rows: [{ a: 1 }], kql_executed: "SecurityEvent | take 1" };
      },
    },
  } as any;
  const out: any = await sentinelQuery.execute(ctx, { query: "SecurityEvent | take 1" });
  assert.equal(calls[0].path, "/kql");
  assert.equal(out.source_tabular, true);
  // The underlying rows are still present.
  assert.ok(out.result ?? out.rows ?? out.data);
});
```

- [ ] **Step 2: Correr y ver fallar**

Run: `cd platform/mcp && npm run build && node --test dist/tests/contract/sentinel-query-escape-hatch.test.js`
Expected: FAIL — `escapeHatch` undefined y el resultado no tiene `source_tabular`. (Si `npm run build` falla porque el test importa `.js` no compilado aún, el build de tsc compila ambos; el test corre sobre `dist/`.)

- [ ] **Step 3: Implementar**

En `sentinel/query.ts`, añadir el flag de metadata al objeto `defineTool` (junto a `category`, `version`, `stability`):

```ts
  // Marks this as the raw-source escape hatch (design spec §14): not a causal
  // graph search, must not be used internally by hunt/graph flows, results are
  // source-tabular. Enforced server-side by the /kql feature-flag gate.
  escapeHatch: true,
```

Y envolver el retorno de `execute` para etiquetar el resultado:

```ts
  async execute(ctx, { query, lookback, ingest, max_rows, dataset, acknowledge_fallback }) {
    const body: Record<string, unknown> = { kql: query, ingest: ingest ?? false };
    if (lookback) body.lookback = lookback;
    if (max_rows != null) body.max_rows = max_rows;
    if (dataset) body.dataset = dataset;
    if (acknowledge_fallback != null) body.acknowledge_fallback = acknowledge_fallback;
    const result = await ctx.api.post("/kql", body, HEAVY);
    // Label the payload so an agent can never present raw source rows as an
    // equivalent to a GraphHunter causal search (design spec §14).
    return { source_tabular: true, result };
  },
```

Si `defineTool`'s type no admite `escapeHatch`, extender el tipo en `lib/types.ts` con `escapeHatch?: boolean` (opcional) — cambio mínimo, no rompe otros tools.

Nota de compatibilidad de forma de salida: envolver en `{ source_tabular, result }` CAMBIA la forma que ve el agente. Verificar que ningún test de contrato existente ni el frontend dependan de la forma plana anterior de `sentinel_query` (grep `sentinel_query` en `platform/mcp/tests` y en el frontend). Si algo depende, preferir añadir `source_tabular` como campo hermano manteniendo los campos originales top-level (spread): `return { source_tabular: true, ...(typeof result === "object" && result ? result : { result }) };` — elegir esta variante si el grep encuentra dependencias de forma; documentar la elección en el reporte.

- [ ] **Step 4: Correr y ver pasar**

Run: `cd platform/mcp && npm run build && node --test dist/tests/contract/sentinel-query-escape-hatch.test.js`
Expected: PASS (2 tests). Luego `npm run test:contract` completo: verde (o, para los tests gated por server vivo, confirmar que no rompen por falta de `GRAPHHUNTER_CONTRACT_TEST=1` — corren o se saltan como antes).

- [ ] **Step 5: Commit**

```powershell
git add platform/mcp/src/tools/sentinel/query.ts platform/mcp/tests/contract/sentinel-query-escape-hatch.test.ts
# incluir platform/mcp/src/lib/types.ts SOLO si se extendió el tipo
git commit -m "feat(mcp): flag sentinel_query as escape hatch; label results source-tabular"
```

---

### Task 5: Docs de encapsulación + verificación no-op de la auditoría

**Files:**
- Create: `C:\Users\lsotomayor\GraphHunter\docs\architecture\source-independent-ingestion.md`
- Create: `C:\Users\lsotomayor\GraphHunter\docs\migration\sentinel-mcp-decoupling.md`

**Interfaces:**
- Consumes: los deliverables de Tasks 1-4 (citar sus `path:line` reales tras implementarlas) + el assessment S6/S7/S8 + el ADR.

- [ ] **Step 1: Escribir `source-independent-ingestion.md`** (spec §23 lo asigna a Fase A/B)

Secciones:
1. **Capacidades de fuente**: la matriz — tabla con las 12 capacidades de `SourceCapabilities` (columnas) × las 3 fuentes + el default conservador (filas), con los valores reales de `kql_query_source()` (citar `platform/sources/src/lib.rs:<línea del struct>` y las 3 impls de Task 2). Explicar la regla del default conservador (una fuente no declarada no promete nada).
2. **Brecha S6 cerrada**: antes solo `available_tables()`; ahora `capabilities()`. Citar el ADR (Clase de realización R) y S6.
3. **Lo que Fase A NO hizo** (honestidad, reconciliación de alcance): no se movió KQL de `graph/*` porque no había KQL ejecutable ahí (S7/S8); el KQL de recolección generado por el sistema (`graph_build`/`graph_propose`) sigue server-side y es compliant, no escape hatch. Etiqueta: `implemented` para capabilities, `descriptive` para lo demás.

- [ ] **Step 2: Escribir `sentinel-mcp-decoupling.md`** (spec §23 lo asigna a 2-A..G; esta es su sección Fase A)

Secciones:
1. **El escape hatch como contrato ejecutable**: el gate `GRAPHHUNTER_KQL_ESCAPE_HATCH` en `handler_run_kql` (citar `apps/tauri/src-tauri/src/http/escape_hatch.rs` y `siem.rs`), habilitado por defecto (sin cambio externo), desactivable; auditoría vía `tracing target:"kql_escape_hatch"`; el etiquetado `source_tabular` en el MCP (`sentinel/query.ts`). Mapear cada condición del spec §14 a dónde se cumple ahora: marcado ✓ (`escapeHatch: true`), no usado internamente por run_hypothesis ✓ (el gate está en el borde HTTP; run_hunt/graph_* no pasan por `/kql` — citar S8 1919-1925), límites ✓ (`max_rows`, §4.7 gate), auditoría ✓ (tracing), resultados tabulares claros ✓ (`source_tabular`).
2. **Qué falta para las fases siguientes**: backfill explícito y native id siguen ausentes (S6 gaps b/c) — Fase B/C. `capabilities()` existe pero aún no lo consume ningún ruteo — se conecta cuando el runtime incremental despierte (Fase C).
3. **Reconciliación de alcance**: la nota de por qué la letra del spec ("mover KQL de graph/*") no aplicaba, con las citas S7/S8.

- [ ] **Step 3: Verificar el no-op de la auditoría del Bloque 1**

Run (repo sot):
```bash
cd /c/Users/lsotomayor/sot && python scripts/sot_sys/audit_graphhunter.py --check
```
Expected: `audit_results.json up to date` — Fase A no tocó ningún canal de `ingest_surface.json` (los 11 fixes apuntan a Fase B/C/Coverage; ninguno a Fase A). Registrar este resultado en el doc de migración como evidencia de que "encapsular no cambia la superficie de suficiencia" (criterio 17 del spec: la línea base se mantiene, Fase A no debe mostrar delta de veredictos). NO regenerar ni `--refresh-catalog`; solo `--check`.

- [ ] **Step 4: Verificar (checklist)**

(a) la matriz de capacidades tiene las 12 filas y valores que coinciden con `kql_query_source()`; (b) cada condición del spec §14 mapeada a un `path:line` real de Tasks 1-4; (c) la reconciliación de alcance cita S7/S8; (d) `--check` quedó "up to date" y registrado; (e) sin afirmaciones de garantía sin etiqueta.

- [ ] **Step 5: Commit**

```powershell
Set-Location C:\Users\lsotomayor\GraphHunter
git add docs/architecture/source-independent-ingestion.md docs/migration/sentinel-mcp-decoupling.md
git commit -m "docs(sot): Fase A - source capabilities matrix + Sentinel/MCP escape-hatch decoupling"
```

---

## Self-Review (del plan, ya ejecutada)

- **Cobertura del spec Fase A:** `capabilities()` en LogSource (T1+T2 ↔ spec §6 "cada conector declara capacidades", cierra brecha S6); escape hatch marcado/auditado/desactivable/no-interno/límites/tabular (T3+T4 ↔ spec §14 y §2, "detrás de feature flag" ✓); docs source-independent-ingestion + sentinel-mcp-decoupling (T5 ↔ spec §23 entregables 2-A/B); "sin cambiar comportamiento externo" ✓ (flag default habilitado). La letra "mover KQL de graph/*" se reconcilia explícitamente contra S7/S8 en el plan y en T5 — divergencia deliberada por realidad corregida, flagged arriba.
- **Placeholders:** ninguno de código sin cuerpo; los puntos donde el implementador debe leer una firma real (handler_run_kql, RunKqlRequest, defineTool, constructores de test de las fuentes) están marcados como "LEER" con la ubicación exacta y el contrato a satisfacer expresado como test — no como "figure it out".
- **Consistencia de tipos/nombres:** `SourceCapabilities`/`kql_query_source()`/`capabilities()` definidos en T1 y usados en T2; `kql_escape_hatch_enabled()`/`disabled_response()` definidos y usados en T3; `escapeHatch`/`source_tabular` en T4; T5 cita los `path:line` de todos tras implementarlos. El flag `GRAPHHUNTER_KQL_ESCAPE_HATCH` idéntico en T3 (código), T4 (comentario), T5 (doc).
- **Riesgo señalado para pre-flight:** T3 y T4 tocan firmas que el implementador debe leer; T4 puede cambiar la forma de salida de `sentinel_query` — el plan da la variante spread como fallback si hay dependencias de forma. El gate se ubica en el handler HTTP, no en `run_kql`, para no romper journal-expand/graph_build (constraint global).
