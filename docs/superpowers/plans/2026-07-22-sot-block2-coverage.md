# Fase de Cobertura (Bloque 2): possibly_incomplete + row_completeness — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surfacear las señales de truncamiento (`stopped_early`) hasta un marcador de incompletitud a nivel de sesión y de ahí a un campo `possibly_incomplete` (+ `coverage_start/end`) en las respuestas de consulta; y contabilizar los skips en el único sitio de insert que hoy no lo hace (`ingest_siem`) más el batch-loop de streaming — cerrando `ingest_completeness`, `completeness_flag` y `row_completeness` de la auditoría.

**Architecture:** (1) `row_completeness`: `ingest_siem` pasa de `parse_raw` a `parse_raw_with_stats` (SentinelJsonParser ya lo tiene) y journalea los skips reales; el batch-loop de streaming deja de descartar skip samples. (2) `ingest_completeness`/`completeness_flag`: `stopped_early` (hoy un local que muere) se surfacea a `LoadResult`; un marcador `IngestCoverage` de sesión acumula "algún ingest quedó incompleto"; las respuestas de consulta (`RunHuntResponse` al menos) ganan `possibly_incomplete: bool` + `coverage_start/coverage_end` (de los timestamps de aristas del grafo), poblado desde el marcador — detrás de `GRAPHHUNTER_COVERAGE` (default off). Todo aditivo y reversible.

**Tech Stack:** Rust (`graph_hunter_core`, `graph_hunter_api`), Python (runner de auditoría del repo sot).

## Honestidad de alcance (leer antes de empezar)

**Esta fase NO desbloquea ningún `Sufficient`.** Tras cerrar `ingest_completeness` + `row_completeness`, el blind set de cada una de las 30 hipótesis queda en **exactamente `{source_coverage}`** — que está diferido a **Fase F** (el poller/breaker de streaming está dormido; el path live no tiene coverage accounting). `_verdict` (gh_audit.py:88) marca ciega cualquier hipótesis con algún canal requerido ≠ full, así que mientras `source_coverage` siga degraded, ninguna hipótesis llega a Sufficient. **El hito "primera hipótesis Sufficient" es de Fase F, no de esta fase.** El delta honesto de esta fase: blind set 3→1 por hipótesis, 0 Sufficient. El flip de Task 6 debe decir exactamente eso.

`completeness_flag` es transversal-only (no está en HYPOTHESIS_REQUIRES); su cierre afecta las transversales `loss_reconstruction`/`exhaustiveness_marking`, no los veredictos de hipótesis.

## Límites de honestidad por canal (definen lo que el flip puede reclamar)

- **`row_completeness`** (contexto `malformed_row`): tras el fix, los 6 sitios de insert contabilizan y journalean los skips. Boundary: el reservorio `skipped_samples` sigue acotado por lote (cap 50 nativo / 20 genérico) — el *conteo* `rows_skipped` es siempre exacto; solo el *payload crudo* del skip #N>cap no se guarda. El flip a full es honesto sobre "toda fila descartada queda contabilizada"; disclosure del cap de muestreo.
- **`ingest_completeness`** (contexto `memory_critical`): el fix surfacea `stopped_early` a la respuesta. Boundary honesto: `stopped_early` solo dispara bajo `#[cfg(windows)]` + memoria crítica real (`ingestion.rs:1624-1629`); `MAX_INGEST_LINES` está muerto (`usize::MAX`); `WHOLE_FILE_PARSE_LIMIT` ya surfacea como `Err`. El cierre es: *cuando* una condición de truncamiento-que-continúa-en-silencio ocurre, la respuesta queda marcada — que es exactamente el witness. El mecanismo de surfacing se testea inyectando la señal (no requiere presión de memoria real).
- **`completeness_flag`** (transversal): el fix añade el campo `possibly_incomplete` a las respuestas de consulta y lo puebla desde el marcador. Boundary: `coverage_start/end` provienen de los timestamps de aristas del grafo (disponibles); `source_watermarks`/`missing_sources` del spec §17 dependen del poller dormido → **Fase F** (no se prometen aquí).

## Global Constraints

- **Feature flag `GRAPHHUNTER_COVERAGE`**, default **off**. Con el flag off, `possibly_incomplete` es siempre `false` (comportamiento actual: respuestas no marcadas) y `coverage_start/end` `None` — cero cambio externo. Truthy-to-enable, idéntico a `env_flag` (`planner.rs:481-485`) y a `journal_enabled()`. Las nuevas features de cobertura solo actúan con el flag on. (El fix de conteo de skips de `row_completeness` es journal-interno, ya detrás de `GRAPHHUNTER_JOURNAL` — no necesita el flag nuevo.)
- **Aditivo/reversible:** los campos nuevos en DTOs (`stopped_early` en `LoadResult`; `possibly_incomplete`/`coverage_start`/`coverage_end` en respuestas) son opcionales/default-false — no rompen deserialización ni comportamiento existente.
- **Rama:** `spec/hunt-journal` en `C:\Users\lsotomayor\GraphHunter`. WIP ajeno presente (incl. `haproxy.rs` untracked y otros). **Jamás** `git add -A`/`stash`/`checkout --`; `git add` solo los archivos que cada tarea nombra, y ante un archivo con WIP mezclado usar `git add -p` para stagear solo los hunks propios (`git diff --cached` debe ser propio-only).
- **Compilar/testear por crate** (sin raíz Cargo): `cd <crate-dir>` primero. `graph_hunter_api` bare `cargo test` falla en tests pre-existentes sin fixture (`demo_data`) — usar `--lib`. Skip el bench lento: `cargo test -- --skip benchmark_full_report --skip benchmark`. NOTA: si al agregar un campo a un tipo construido en muchos sitios el crate no compila, aplicar el fix mecánico compiler-driven (default para el campo nuevo) a TODOS los literales, incluyendo los de otros crates trackeados (`platform/api/src/ingestors/*`), pero NUNCA a `haproxy.rs` (untracked user WIP — dejarlo con el default agregado sin stagear).
- **Idioma:** código/comentarios en inglés; docs en español; disciplina de claims.
- **Task 6 toca el repo sot** (`sot-sys/bootstrap`) — flip + re-freeze; commit aparte.

---

### Task 1: `ingest_siem` computa ParseStats y journalea skips reales (Rust api, TDD/read-verify)

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\api\src\operations\ingestion.rs` (`ingest_siem` ~:751, :766, :838)

**Interfaces:**
- Consumes: `SentinelJsonParser::parse_raw_with_stats` (`core/graph-engine/src/sentinel.rs:1204`), `journal_batch_best_effort`, `ParseStats`.
- Produces: `ingest_siem` retorna `LoadResult{ ingest_stats: Some(stats), ... }` y journalea `stats.skipped_samples` en vez de `&[]`.

- [ ] **Step 1: LEER + escribir un test si es alcanzable, sino read-verify**

LEER `ingest_siem` (`ingestion.rs:608-841`): el `parser.parse_raw(&data)` (:751), el `journal_batch_best_effort(..., &events, &[])` (:766), el `LoadResult{... ingest_stats: None}` (:838-839). `ingest_siem` es async y depende de una query Azure/Elastic — probablemente NO unit-testeable sin harness. La cobertura de esta tarea: (a) el cambio de `parse_raw` → `parse_raw_with_stats` (SentinelJsonParser ya lo implementa, `sentinel.rs:1204`, verificado en C-2/exploración); (b) pasar `stats.skipped_samples` al journal y `Some(stats)` a `LoadResult`; (c) read-verification de que las tres líneas cambiaron correctamente. Si existe un test de `ingest_siem` con un parser mockeable, añadir uno que verifique `rows_skipped` no-cero ante input con filas descartables; sino documentar read-coverage.

- [ ] **Step 2: Implementar**

En `ingest_siem` (`ingestion.rs`):
- Reemplazar `let events = parser.parse_raw(&data);` (:751) por `let (events, stats) = parser.parse_raw_with_stats(&data);`.
- En la llamada al journal (:766), reemplazar el `&[]` literal por `&stats.skipped_samples`. (Adaptar a la firma real de `journal_batch_best_effort` — leerla; también existe el gate `journal_enabled()` alrededor.)
- Si el flag `GRAPHHUNTER_GRAPHDELTA` está on, el apply idempotente ya se hace tras el journal (C-1) — no cambia.
- En el `LoadResult` de retorno (:838-839), `ingest_stats: Some(stats)` en vez de `None` (y `zero_triples` derivado de `stats.rows_with_triples == 0` si el patrón de otros sitios lo hace — LEER cómo load_data setea zero_triples ~:600 y replicar).
- Verificar que `record_parse_skips`/DLQ recibe los skips por el mismo camino que load_data (el `journal_batch_best_effort` ya no lleva `&[]`).

- [ ] **Step 3: Compilar + tests**

Run: `cd C:\Users\lsotomayor\GraphHunter\platform\api && cargo build --lib` (verde) y `cargo test --lib` (verde; el flag por default no cambia el comportamiento sync — `ingest_siem` ahora computa stats siempre, que es aditivo).
Expected: compila; sin regresión.

- [ ] **Step 4: Commit**

```powershell
Set-Location C:\Users\lsotomayor\GraphHunter
git add platform/api/src/operations/ingestion.rs
git commit -m "fix(api): ingest_siem computes ParseStats + journals real skips (row_completeness live path)"
```

---

### Task 2: El batch-loop de streaming deja de descartar skip samples (Rust api, TDD/read-verify)

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\api\src\operations\ingestion.rs` (batch-loop de `load_data_streaming` ~:1494-1531)

**Interfaces:**
- Consumes: `parse_raw_with_stats` (ya llamado ahí), `journal_batch_best_effort`.
- Produces: el batch-loop journalea `stats.skipped_samples` en vez de un slice vacío.

- [ ] **Step 1: LEER el batch-loop**

LEER `load_data_streaming` (`ingestion.rs:912+`), específicamente el batch-loop paralelo (~:1494-1531). La exploración indica que ese sitio computa `parse_raw_with_stats` por sub-chunk pero journalea `skipped_samples` vacío en `journal_batch_best_effort` (~:1525). Confirmar: ¿el `stats.skipped_samples` está disponible en scope en el punto del journal, o se descarta al mergear sub-chunks (solo se conserva `drift`)? Si se descarta antes, hay que conservarlo (acumular `skipped_samples` de los sub-chunks hasta el cap `SKIP_SAMPLE_CAP`).

- [ ] **Step 2: Implementar**

Hacer que el batch-loop acumule `skipped_samples` de los sub-chunks (hasta `graph_hunter_core::parser::SKIP_SAMPLE_CAP = 50`) y los pase a `journal_batch_best_effort` en vez de `&[]`. Adaptar al merge real de stats (hoy solo mergea `drift` — extender para mergear `skipped_samples` con el cap). Si el merge de stats está en una fn helper, extenderla; sino inline. El `rows_skipped` count debe seguir siendo la suma exacta (probablemente ya lo es).

- [ ] **Step 3: Compilar + tests**

Run: `cd platform/api && cargo build --lib` y `cargo test --lib`.
Expected: compila; sin regresión. Si hay un test del merge de stats streaming, verificar que `skipped_samples` ahora se conserva.

- [ ] **Step 4: Commit**

```powershell
git add platform/api/src/operations/ingestion.rs
git commit -m "fix(api): streaming batch-loop preserves skip samples up to cap (row_completeness)"
```

---

### Task 3: `stopped_early` surfaceado a `LoadResult` (Rust api, TDD)

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\api\src\dto\v1\ingestion.rs` (`LoadResult` struct ~:73-93)
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\api\src\operations\ingestion.rs` (poblar el campo en `load_data_streaming` desde el local `stopped_early`)

**Interfaces:**
- Produces: `LoadResult.stopped_early: bool` (nuevo, `#[serde(default)]`), poblado desde el local `stopped_early` (`ingestion.rs:1379/:1629`). Task 4 lo consume para el marcador de sesión.

- [ ] **Step 1: Escribir el test que falla**

LEER `LoadResult` (`dto/v1/ingestion.rs:73-93`). Añadir un test (en el módulo de test del DTO, o un test de round-trip):

```rust
    #[test]
    fn load_result_carries_stopped_early_default_false() {
        // Backward compatible: deserializing an old LoadResult without the field defaults false.
        let json = r#"{"new_entities":1,"new_relations":1,"total_entities":1,"total_relations":1,"zero_triples":false,"warnings":[]}"#;
        let r: LoadResult = serde_json::from_str(json).unwrap();
        assert!(!r.stopped_early);
        // and a constructed one round-trips.
        let mut r2 = r.clone();
        r2.stopped_early = true;
        let s = serde_json::to_string(&r2).unwrap();
        let back: LoadResult = serde_json::from_str(&s).unwrap();
        assert!(back.stopped_early);
    }
```
Ajustar los campos obligatorios del JSON a la firma real de `LoadResult` (leerla; puede tener más campos).

- [ ] **Step 2: Correr y ver fallar**

Run: `cd platform/api && cargo test --lib load_result_carries_stopped_early`
Expected: FAIL — `stopped_early` no es campo de `LoadResult`.

- [ ] **Step 3: Implementar**

En `LoadResult` (`dto/v1/ingestion.rs`), añadir:
```rust
    /// True if this ingest stopped before consuming all input (e.g. Windows
    /// critical-memory guard mid-file). Surfaced so a downstream answer over
    /// this data can be marked possibly_incomplete (ingest_completeness). The
    /// underlying signal was previously a dropped local (S5).
    #[serde(default)]
    pub stopped_early: bool,
```
En `load_data_streaming` (`ingestion.rs`), donde se construye el `LoadResult`/`IngestComplete` de retorno (~:1916-1924), setear `stopped_early` desde el local `stopped_early` (:1379). En los otros constructores de `LoadResult` (load_data, load_data_with_config, ingest_siem) el campo default `false` (esos paths no tienen el guard de memoria). **Compilar** — si hay literales `LoadResult { ... }` que ahora fallan, añadir `stopped_early: false,` (o usar `..Default::default()` si el tipo lo soporta) a cada uno.

- [ ] **Step 4: Correr y ver pasar**

Run: `cargo test --lib load_result_carries_stopped_early` y `cargo test --lib`.
Expected: PASS; suite verde.

- [ ] **Step 5: Commit**

```powershell
git add platform/api/src/dto/v1/ingestion.rs platform/api/src/operations/ingestion.rs
git commit -m "feat(api): surface stopped_early in LoadResult (ingest_completeness signal no longer dropped)"
```

---

### Task 4: Marcador `IngestCoverage` de sesión + helper de completitud (Rust core+api, TDD)

**Files:**
- Create: `C:\Users\lsotomayor\GraphHunter\platform\api\src\coverage.rs`
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\api\src\lib.rs` (`pub mod coverage;`)

**Interfaces:**
- Produces:
  ```rust
  pub fn coverage_enabled() -> bool   // GRAPHHUNTER_COVERAGE, default off
  #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
  pub struct IngestCoverage { pub possibly_incomplete: bool, pub incomplete_reasons: Vec<String> }
  impl IngestCoverage {
      /// Fold one ingest's completeness signals into the running coverage.
      pub fn observe(&mut self, stopped_early: bool, whole_file_rejected: bool)
  }
  /// The completeness metadata attached to a query answer.
  #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
  pub struct AnswerCoverage {
      pub possibly_incomplete: bool,
      #[serde(skip_serializing_if = "Option::is_none")] pub coverage_start: Option<i64>,
      #[serde(skip_serializing_if = "Option::is_none")] pub coverage_end: Option<i64>,
      pub incomplete_reasons: Vec<String>,
  }
  /// Build the answer coverage from the session's ingest coverage + the graph's
  /// edge-timestamp span. Returns default (all clear) when the flag is off.
  pub fn answer_coverage(ic: &IngestCoverage, edge_ts_min: Option<i64>, edge_ts_max: Option<i64>) -> AnswerCoverage
  ```
  Task 5 llama `answer_coverage` para poblar la respuesta; el sitio de ingesta llama `IngestCoverage::observe`.

- [ ] **Step 1: Escribir los tests que fallan**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_flag_defaults_off() {
        let _lock = /* reuse an env mutex if the crate has one, else a local static Mutex */;
        std::env::remove_var("GRAPHHUNTER_COVERAGE");
        assert!(!coverage_enabled());
        std::env::set_var("GRAPHHUNTER_COVERAGE", "1");
        assert!(coverage_enabled());
        std::env::remove_var("GRAPHHUNTER_COVERAGE");
    }

    #[test]
    fn observe_folds_incompleteness_signals() {
        let mut ic = IngestCoverage::default();
        assert!(!ic.possibly_incomplete);
        ic.observe(false, false);            // a clean ingest
        assert!(!ic.possibly_incomplete);
        ic.observe(true, false);             // one that stopped early
        assert!(ic.possibly_incomplete);
        assert!(ic.incomplete_reasons.iter().any(|r| r.contains("stopped_early")));
    }

    #[test]
    fn answer_coverage_off_is_all_clear() {
        std::env::remove_var("GRAPHHUNTER_COVERAGE");
        let ic = IngestCoverage { possibly_incomplete: true, incomplete_reasons: vec!["stopped_early".into()] };
        let ac = answer_coverage(&ic, Some(100), Some(200));
        // flag off: no marking, no coverage span leaked.
        assert!(!ac.possibly_incomplete);
        assert!(ac.coverage_start.is_none());
    }

    #[test]
    fn answer_coverage_on_reflects_incompleteness_and_span() {
        std::env::set_var("GRAPHHUNTER_COVERAGE", "1");
        let ic = IngestCoverage { possibly_incomplete: true, incomplete_reasons: vec!["stopped_early".into()] };
        let ac = answer_coverage(&ic, Some(100), Some(200));
        std::env::remove_var("GRAPHHUNTER_COVERAGE");
        assert!(ac.possibly_incomplete);
        assert_eq!(ac.coverage_start, Some(100));
        assert_eq!(ac.coverage_end, Some(200));
        assert!(ac.incomplete_reasons.iter().any(|r| r.contains("stopped_early")));
    }
}
```

- [ ] **Step 2: Correr y ver fallar**

Run: `cd platform/api && cargo test --lib coverage`
Expected: FAIL — símbolos inexistentes.

- [ ] **Step 3: Implementar** (`coverage.rs`)

```rust
//! Coverage/completeness metadata: surfaces ingest-time incompleteness
//! (stopped_early, whole-file rejection) up to a session marker and onto query
//! answers as possibly_incomplete + a coverage time span. Behind
//! GRAPHHUNTER_COVERAGE (default off): with the flag off, answers are never
//! marked (current behavior). Closes ingest_completeness + completeness_flag
//! (design spec §17). source_watermarks/missing_sources need the streaming
//! poller (Fase F) and are NOT produced here.

use serde::{Deserialize, Serialize};

/// GRAPHHUNTER_COVERAGE: mark query answers with completeness metadata.
/// Default off. Truthy-to-enable (env_flag convention).
pub fn coverage_enabled() -> bool {
    std::env::var("GRAPHHUNTER_COVERAGE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Running completeness state for a session: set when any ingest into it did
/// not consume all its input.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct IngestCoverage {
    pub possibly_incomplete: bool,
    pub incomplete_reasons: Vec<String>,
}

impl IngestCoverage {
    /// Fold one ingest's completeness signals in. Monotonic: once incomplete,
    /// stays incomplete (a later clean ingest doesn't make past loss recoverable).
    pub fn observe(&mut self, stopped_early: bool, whole_file_rejected: bool) {
        if stopped_early {
            self.possibly_incomplete = true;
            let r = "stopped_early: ingest cut short (memory pressure)".to_string();
            if !self.incomplete_reasons.contains(&r) { self.incomplete_reasons.push(r); }
        }
        if whole_file_rejected {
            self.possibly_incomplete = true;
            let r = "whole_file_rejected: file exceeded parse limit".to_string();
            if !self.incomplete_reasons.contains(&r) { self.incomplete_reasons.push(r); }
        }
    }
}

/// Completeness metadata attached to a query answer.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AnswerCoverage {
    pub possibly_incomplete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage_start: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage_end: Option<i64>,
    pub incomplete_reasons: Vec<String>,
}

/// Build answer coverage from the session's ingest coverage and the graph's
/// edge-timestamp span. Off ⇒ all-clear (no marking, no span leaked).
pub fn answer_coverage(
    ic: &IngestCoverage,
    edge_ts_min: Option<i64>,
    edge_ts_max: Option<i64>,
) -> AnswerCoverage {
    if !coverage_enabled() {
        return AnswerCoverage::default();
    }
    AnswerCoverage {
        possibly_incomplete: ic.possibly_incomplete,
        coverage_start: edge_ts_min,
        coverage_end: edge_ts_max,
        incomplete_reasons: ic.incomplete_reasons.clone(),
    }
}
```
Declarar `pub mod coverage;` en `lib.rs`. Reusar el mutex de env de los tests si existe (journal.rs tiene uno — pero está en otro módulo; usar un `static ENV_LOCK: Mutex<()>` local en coverage.rs para los tests de flag, mismo patrón).

- [ ] **Step 4: Correr y ver pasar**

Run: `cargo test --lib coverage` y `cargo test --lib`.
Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add platform/api/src/coverage.rs platform/api/src/lib.rs
git commit -m "feat(api): IngestCoverage session marker + answer_coverage behind GRAPHHUNTER_COVERAGE"
```

---

### Task 5: `possibly_incomplete` + `coverage_*` en `RunHuntResponse` (Rust api, TDD)

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\api\src\dto\v1\hunt.rs` (`RunHuntResponse` ~:80-88)
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\api\src\operations\hunt.rs` (poblar el campo desde `answer_coverage`)

**Interfaces:**
- Consumes: `AnswerCoverage`/`answer_coverage` (Task 4), el `IngestCoverage` de la sesión, los timestamps min/max de aristas del grafo.
- Produces: `RunHuntResponse.coverage: AnswerCoverage` (nuevo, `#[serde(default)]`).

- [ ] **Step 1: LEER + escribir el test que falla**

LEER `RunHuntResponse` (`dto/v1/hunt.rs:80-88`) y cómo `operations/hunt.rs` lo construye + de dónde obtiene la sesión/grafo (para el `IngestCoverage` de sesión y los timestamps de aristas — LEER si el grafo expone min/max timestamp; si no hay helper, usar `entity_count`/`relation_count`-style o el `edges_sorted`/timestamp range — buscar un método existente como `edge_timestamp_range` o derivarlo). Test (a nivel DTO + un test de la construcción si es alcanzable):

```rust
    #[test]
    fn run_hunt_response_carries_coverage_default_clear() {
        // backward compatible: old response without coverage → default (clear).
        let json = r#"{"paths":[],"path_count":0,"truncated":false}"#;
        let r: RunHuntResponse = serde_json::from_str(json).unwrap();
        assert!(!r.coverage.possibly_incomplete);
    }
```
Ajustar campos obligatorios a la firma real. Si hay un test de `run_hunt` con harness, añadir uno que con `GRAPHHUNTER_COVERAGE=1` y una sesión marcada incompleta, la respuesta tenga `coverage.possibly_incomplete == true`; sino read-verify la construcción.

- [ ] **Step 2: Correr y ver fallar**

Run: `cd platform/api && cargo test --lib run_hunt_response_carries_coverage`
Expected: FAIL — `coverage` no es campo.

- [ ] **Step 3: Implementar**

En `RunHuntResponse` (`dto/v1/hunt.rs`):
```rust
    /// Completeness metadata for this answer: possibly_incomplete + the covered
    /// time span, populated when GRAPHHUNTER_COVERAGE is on and the session had
    /// an incomplete ingest. Default clear (backward compatible).
    #[serde(default)]
    pub coverage: crate::coverage::AnswerCoverage,
```
En `operations/hunt.rs`, donde se construye `RunHuntResponse`: obtener el `IngestCoverage` de la sesión (LEER dónde vive el estado de sesión — si no hay un campo de sesión para `IngestCoverage`, esta tarea debe añadirlo al tipo de sesión y poblarlo desde el `stopped_early` de Task 3; si eso resulta invasivo, la ruta mínima testeable: `answer_coverage(&session_ingest_coverage, edge_min, edge_max)` donde `session_ingest_coverage` se lee del estado — documentar la ubicación real). Poblar `coverage: answer_coverage(&ic, edge_min, edge_max)`. Los timestamps de aristas: usar el helper real del grafo (LEER `graph.rs` para un rango de timestamps; si no existe, derivarlo de forma barata o pasar `None, None` y dejar `possibly_incomplete` como la señal principal — el flip de Task 6 debe reflejar qué se pobló realmente).

Nota de integración de sesión: el `IngestCoverage` de sesión necesita un hogar. Si el tipo de sesión (`platform/api/src/state/session.rs`) no tiene un campo, añadir `pub ingest_coverage: crate::coverage::IngestCoverage` (default) y que los paths de ingesta llamen `session.ingest_coverage.observe(load_result.stopped_early, whole_file_rejected)` tras cada ingesta. LEER cómo la sesión se accede en load_data/ingest_siem y en run_hunt para cablear ambos extremos. Si el cableado completo excede una tarea, la cobertura mínima honesta: el helper `answer_coverage` + el campo DTO testeados como unidades, y read-verify del cableado — Task 6 solo reclama lo cableado y verificado.

- [ ] **Step 4: Correr y ver pasar**

Run: `cargo test --lib run_hunt_response_carries_coverage` y `cargo test --lib`.
Expected: PASS; suite verde (flag off = coverage default clear, sin regresión).

- [ ] **Step 5: Commit**

```powershell
git add platform/api/src/dto/v1/hunt.rs platform/api/src/operations/hunt.rs
# + platform/api/src/state/session.rs si se añadió el campo de sesión (git add -p si tiene WIP)
git commit -m "feat(api): possibly_incomplete + coverage span on RunHuntResponse (completeness_flag)"
```

---

### Task 6: Flip row_completeness + ingest_completeness + completeness_flag + docs (repo sot + GraphHunter)

**Files:**
- Modify: `C:\Users\lsotomayor\sot\validation\graphhunter\ingest_surface.json` (3 canales)
- Modify: `C:\Users\lsotomayor\sot\validation\graphhunter\audit_results.json` (re-freeze)
- Modify: `C:\Users\lsotomayor\sot\validation\graphhunter\graphhunter_sufficiency_audit.md` (delta)
- Modify: `C:\Users\lsotomayor\sot\MANIFEST.sha256` (git-blob)
- Modify: `C:\Users\lsotomayor\GraphHunter\docs\architecture\source-independent-ingestion.md` (o un doc de cobertura — sección Cobertura)

**Interfaces:**
- Consumes: los deliverables Tasks 1-5; el runner `audit_graphhunter.py`.

- [ ] **Step 1: Flip los 3 canales, honestamente scoped**

En `ingest_surface.json`:
- **`row_completeness` → "full"**: nota — los 6 sitios de insert ahora contabilizan y journalean skips (Task 1 `ingest_siem` `parse_raw_with_stats` + skips reales; Task 2 batch-loop conserva skip samples). Boundary: `rows_skipped` siempre exacto; `skipped_samples` acotado por cap (50 nativo/20 genérico) — disclosure. Detrás de `GRAPHHUNTER_JOURNAL`.
- **`ingest_completeness` → "full"**: nota — `stopped_early` se surfacea a `LoadResult.stopped_early` (Task 3) → marcador `IngestCoverage` de sesión (Task 4) → `possibly_incomplete` en la respuesta (Task 5). Boundary honesto: `stopped_early` solo dispara bajo Windows + memoria crítica real; el mecanismo de surfacing está testeado por inyección (no por presión de memoria real); detrás de `GRAPHHUNTER_COVERAGE`. Si el cableado sesión→respuesta quedó read-verified y no integration-tested, decirlo exacto.
- **`completeness_flag` → "full"**: nota — `RunHuntResponse.coverage.possibly_incomplete` (+ `coverage_start/end`) existe y se puebla desde el marcador. Boundary: `coverage_start/end` de timestamps de aristas; `source_watermarks`/`missing_sources` del spec §17 diferidos a Fase F. Detrás de `GRAPHHUNTER_COVERAGE`.
- **NO tocar `source_coverage`** (Fase F).
Si algún canal quedó parcialmente cableado (p. ej. solo `RunHuntResponse` tiene coverage, no `graph_neighbors`/`graph_path`/`graph_anomaly`), la nota debe decir exactamente qué respuestas lo llevan. Honestidad primero — el whole-phase review lo escrutará.

- [ ] **Step 2: Re-freeze + leer el delta REAL**

```bash
cd /c/Users/lsotomayor/sot
python scripts/sot_sys/audit_graphhunter.py
python scripts/sot_sys/audit_graphhunter.py --check   # "up to date"
```
`ingest_completeness` + `row_completeness` están en HYPOTHESIS_REQUIRES. Antes de esta fase el blind set era 3 ({ingest_completeness, row_completeness, source_coverage}). Al flipear los dos → blind set **3→1** ({source_coverage}). **Ninguna hipótesis llega a Sufficient** (source_coverage sigue degraded → Fase F). La transversal `exhaustiveness_marking` (completeness_flag, ingest_completeness, source_coverage) sigue ciega por source_coverage aunque cerremos los otros dos; `loss_reconstruction` (completeness_flag, ingestion_time, provenance_stability, skip_diagnostics) — completeness_flag ahora full, skip_diagnostics ya full (Fase B), pero ingestion_time + provenance_stability siguen (¿degraded? — leer su estado actual; provenance_stability quedó degraded en la corrección de Fase B) → sigue ciega. Reportar el delta EXACTO del JSON: blind set 3→1, 0 Sufficient, y el estado de ambas transversales. NO inflar. NO reclamar Sufficient.

- [ ] **Step 3: Docs** — sección Cobertura: el marcador `IngestCoverage`, `answer_coverage`, el campo `RunHuntResponse.coverage`, el fix de `ingest_siem` skips; los flags (`GRAPHHUNTER_COVERAGE`, `GRAPHHUNTER_JOURNAL`); qué cierra y bajo qué boundaries; y **prominente**: source_coverage (Fase F) es el último bloqueante para el primer Sufficient. Etiquetas de claim.

- [ ] **Step 4: audit md + MANIFEST** — sección "Fase Cobertura delta" con los números reales (3→1, 0 Sufficient, los 3 canales cerrados con boundaries, source_coverage→F como el último bloqueante). MANIFEST vía git-blob (sha256 de `git cat-file blob :<path>` tras `git add`).

- [ ] **Step 5: Verificar (checklist)** — 3 canales full con notas honestas (boundaries + flags nombrados); `--check` up-to-date; delta = JSON (3→1, 0 Sufficient); doc con el boundary source_coverage→F; MANIFEST limpio.

- [ ] **Step 6: Commit (dos repos)**

```bash
cd /c/Users/lsotomayor/sot
git add validation/graphhunter/ingest_surface.json validation/graphhunter/audit_results.json validation/graphhunter/graphhunter_sufficiency_audit.md MANIFEST.sha256
git commit -m "GraphHunter audit: Coverage phase flips row_completeness + ingest_completeness + completeness_flag (behind flags) + re-freeze"
```
```powershell
Set-Location C:\Users\lsotomayor\GraphHunter
git add docs/architecture/source-independent-ingestion.md
git commit -m "docs(sot): Coverage phase - possibly_incomplete + row_completeness accounting"
```

---

## Self-Review (del plan, ya ejecutada)

- **Cobertura del spec §17:** `possibly_incomplete` (T4/T5), `coverage_start`/`coverage_end` (T4/T5), marcador de sesión (T4), surfacing de `stopped_early` (T3); `source_watermarks`/`missing_sources` explícitamente diferidos a Fase F (dependen del poller dormido). row_completeness (T1/T2) cierra el gap de C-2. Flip honesto (T6 ↔ criterio 17). El milestone "primer Sufficient" declarado como de Fase F, no de esta fase — blind set 3→1.
- **Placeholders:** T3/T4/T5 llevan código+tests completos; T1/T2/T5 marcan "LEER" los sitios reales (ingest_siem, el batch-loop, la construcción de RunHuntResponse + de dónde sale el IngestCoverage de sesión) con ubicación exacta y el contrato como test/read-verify. T5 declara la ruta mínima testeable (helper + campo DTO como unidades) si el cableado de sesión excede una tarea.
- **Consistencia de tipos/nombres:** `coverage_enabled`/`IngestCoverage`/`observe`/`AnswerCoverage`/`answer_coverage` (T4) consumidos por T5; `LoadResult.stopped_early` (T3) alimenta `IngestCoverage::observe` (T4); `RunHuntResponse.coverage: AnswerCoverage` (T5); `GRAPHHUNTER_COVERAGE` idéntico en T4 (código) y T6 (nota/doc); `parse_raw_with_stats`/`skipped_samples`/`SKIP_SAMPLE_CAP` reusados en T1/T2.
- **Honestidad pre-registrada:** T6 declara delta 3→1, 0 Sufficient, source_coverage→F como el último bloqueante (no fabrica un Sufficient que el modelo no da); nombra el boundary de `stopped_early` (Windows/memoria, surfacing testeado por inyección) y de `coverage_start/end` (aristas, no watermarks); exige no reclamar respuestas no cableadas. Riesgo señalado para pre-flight: el cableado sesión→respuesta (T5) puede exceder una tarea — la ruta mínima es helper+DTO testeados + read-verify; y la lección de C-2 (enumerar consumidores) aplica al campo nuevo de sesión `ingest_coverage` — pero es campo nuevo sin consumidores previos, seguro.
