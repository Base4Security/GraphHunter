# Fase F (Bloque 2): source_coverage — el hito del primer Sufficient — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cerrar `source_coverage` cableando un circuit-breaker real por-fuente + un registro de cobertura por-fuente sobre el path live one-shot `ingest_siem`, y surfaceando `source_watermarks`/`missing_sources` en las respuestas de consulta — de modo que una ventana ciega (fuente saltada por el breaker o poll errado) sea distinguible de una ventana genuinamente vacía; flipeando source_coverage a full y desbloqueando el primer `Sufficient` de las 30 hipótesis.

**Architecture:** `AnswerCoverage` gana `source_watermarks: BTreeMap<String,i64>` + `missing_sources: Vec<String>`. La `Session` gana un `SourceCoverage` (nuevo tipo en `coverage.rs`): por fuente, la última ventana cubierta (watermark) + un `CircuitBreaker` de fallas consecutivas. `ingest_siem` registra la ventana cubierta por pull; ante error de query llama `record_failure`; si el breaker de esa fuente está abierto, salta el pull y marca la ventana como faltante. `answer_coverage` puebla `source_watermarks`/`missing_sources` desde el `SourceCoverage` de la sesión. Todo detrás de `GRAPHHUNTER_SOURCE_COVERAGE` (default off). Más un accessor O(1) de rango de timestamps de aristas que completa `coverage_start/end` (carry-over de la fase de Cobertura).

**Tech Stack:** Rust (`graph_hunter_core`, `graph_hunter_api`), Python (runner de auditoría del repo sot).

## Alcance y honestidad (leer antes de empezar — el whole-phase review lo escrutará)

**Qué cierra esta fase, exactamente:** el contexto declarado de `source_coverage` es `circuit_breaker`, y su witness es "una ventana saltada por el breaker mientras ocurrían eventos que la hipótesis busca produce la MISMA respuesta observable que una ventana genuinamente vacía" (`gh_audit.py` witness `source_coverage`). Para cerrarlo **literalmente** (no solo su esencia), esta fase cablea un **circuit breaker real por-fuente sobre el path one-shot `ingest_siem`**: rastrea fallas consecutivas por fuente a través de llamadas (estado en la sesión), abre el breaker tras N fallas, salta la fuente, y registra esa ventana como un gap de cobertura → `missing_sources` en la respuesta. Así el `same_observed` del witness ("identical graph and identical answers") deja de valer: una ventana ciega ahora lleva `missing_sources`/un watermark rezagado, una vacía no.

**Qué NO hace (disclosure obligatorio):** el pipeline de streaming dormido (`SourcePoller→ParserTask→GraphWriter`, `core/graph-engine/src/ingest/`) **NO se cablea** — no es requerido por el witness y es una construcción separada mucho mayor. Esta fase usa el path one-shot existente con un breaker+coverage por-fuente, reusando los tipos `CircuitBreaker`/`DataCoverage` que ya existen. El `SourceCoverage` de la sesión es **efímero** (no se persiste en GHS1, igual que `ingest_coverage` de la fase de Cobertura) — un truncamiento/skip → guardar sesión → recargar pierde el marcador; se disclosa.

**El hito:** `source_coverage` es el **último canal degraded en `HYPOTHESIS_REQUIRES`** (los otros 6 — entity_identity, edge_multiplicity, row_completeness, field_survival, event_time, ingest_completeness — ya son full). `_verdict` (gh_audit.py) marca `Sufficient` cuando el blind set requerido queda vacío. Flipear source_coverage → **las 30 hipótesis alcanzan `Sufficient`** — el primer Sufficient del programa. Caveat honesto para Task 6: las dos transversales (`loss_reconstruction`, `exhaustiveness_marking`) NO alcanzan Sufficient — `loss_reconstruction` requiere `ingestion_time` (absent) + `provenance_stability` (degraded), ninguno en HYPOTHESIS_REQUIRES ni en el hito de 30 hipótesis. El repo conserva esos dos canales ciegos fuera del set requerido; el claim de "Sufficient para las 30 hipótesis" es honesto y no debe extenderse a las transversales.

## Global Constraints

- **Feature flag `GRAPHHUNTER_SOURCE_COVERAGE`**, default **off**. Truthy-to-enable, idéntico a `env_flag` (`planner.rs:481-485`) y a `coverage_enabled()` (`coverage.rs:13-17`). Con el flag off: `ingest_siem` no rastrea breaker ni registra cobertura por-fuente (comportamiento actual exacto), y `source_watermarks`/`missing_sources` quedan vacíos/omitidos en las respuestas. Cero cambio externo por default.
- **Aditivo/reversible:** los campos nuevos en `AnswerCoverage` (`source_watermarks`, `missing_sources`) son opcionales/default-vacíos con `skip_serializing_if` cuando vacíos (patrón de la fase de Cobertura para no romper el parity test `tests/parity/dto_shapes.rs`) — no rompen la forma del wire con el flag off. El campo nuevo de `Session` es efímero (no persistido).
- **Reusar, no reconstruir:** el `CircuitBreaker` ya existe (`source_poller.rs:76-132`, privado) y `DataCoverage` (`coverage.rs`). Task 3 decide reusar (hacer `pub(crate)` el breaker) o replicar una versión mínima en `coverage.rs` — el implementador lee el código y elige; el contrato es un breaker de fallas-consecutivas con backoff exponencial capado.
- **NO cablear el poller de streaming dormido** (`SourcePoller`/`GraphWriter`/`ParserTask`) — fuera de alcance, disclosure en Task 6.
- **Rama:** `spec/hunt-journal` en `C:\Users\lsotomayor\GraphHunter`. WIP ajeno (incl. `haproxy.rs` untracked). **Jamás** `git add -A`/`stash`/`checkout --`; `git add` solo los archivos que cada tarea nombra; `git add -p` si un archivo tiene WIP mezclado (`git diff --cached` = propio-only).
- **Compilar/testear por crate:** `cd <crate-dir>`. `graph_hunter_api` bare `cargo test` falla en tests pre-existentes sin fixture (`demo_data`) — usar `--lib`; correr **también** el binario de parity (`cargo test --test parity`) cuando se toca un DTO de respuesta. `graph_hunter_core` = `cargo test -- --skip benchmark_full_report --skip benchmark`.
- **Lección de consumidores (C-2/Cobertura):** al tocar `AnswerCoverage` o un DTO de respuesta, enumerar TODOS los consumidores — `RunHuntResponse`, `RunHuntBatchEntry` (deben mantener shape-parity), el parity test, y las notas congeladas de `ingest_surface.json` que citan código. Grep antes de commitear.
- **Idioma:** código/comentarios en inglés; docs en español; disciplina de claims.
- **Task 6 toca el repo sot** (`sot-sys/bootstrap`) — flip + re-freeze; commit aparte.

---

### Task 1: Accessor O(1) de rango de timestamps de aristas (Rust core, TDD)

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\core\graph-engine\src\graph.rs` (método nuevo en `GraphHunter`)

**Interfaces:**
- Produces: `pub fn edge_timestamp_range(&self) -> Option<(i64, i64)>` — `(min_ts, max_ts)` de las aristas, o `None` si el grafo no tiene aristas. Task 5 lo usa para `coverage_start/end`.

- [ ] **Step 1: LEER + escribir el test que falla**

LEER `graph.rs`: cómo se almacenan las aristas (el backend `streaming`), `relation_count()` (:401), `sort_edges_by_timestamp` (:918), el flag `edges_sorted` (:122), y si hay un iterador de aristas (`for_each_edge` en `streaming.rs`). El accessor debe ser barato: si `edges_sorted` está garantizado tras finalize, min = primera arista, max = última; si no, un solo pase O(E) con min/max (aceptable como fallback — documentar). Test (en el `#[cfg(test)] mod tests` de graph.rs, reusar el patrón de construcción de `RawIngestEvent`/insert de tests existentes como `tests.rs:971`):

```rust
    #[test]
    fn edge_timestamp_range_reports_min_and_max() {
        let mut g = GraphHunter::new();
        // insert 3 events with timestamps 100, 300, 200 (unsorted on purpose)
        g.insert_raw_events(vec![
            /* build RawIngestEvent with timestamp 100 — reuse the module's ev() helper */,
            /* ts 300 */,
            /* ts 200 */,
        ], None).unwrap();
        assert_eq!(g.edge_timestamp_range(), Some((100, 300)));
    }

    #[test]
    fn edge_timestamp_range_empty_graph_is_none() {
        let g = GraphHunter::new();
        assert_eq!(g.edge_timestamp_range(), None);
    }
```
Ajustar la construcción de `RawIngestEvent` a los tipos reales (`crate::types::{EntityType,RelationType}`, `raw_line: None`).

- [ ] **Step 2: Correr y ver fallar**

Run: `cd C:\Users\lsotomayor\GraphHunter\core\graph-engine && cargo test edge_timestamp_range`
Expected: FAIL — método inexistente.

- [ ] **Step 3: Implementar**

Añadir a `impl GraphHunter` (cerca de `relation_count`/`entity_count`, ~:394-401):
```rust
    /// Min and max edge timestamp across the graph, or None if there are no
    /// edges. Used to report the covered time span on query answers
    /// (coverage_start/coverage_end). Cheap: a single pass over the edge store's
    /// timestamps (edges are compact 32-byte records; this is a scan of the
    /// timestamp column, not a full materialization).
    pub fn edge_timestamp_range(&self) -> Option<(i64, i64)> {
        let mut lo: Option<i64> = None;
        let mut hi: Option<i64> = None;
        self.streaming.for_each_edge(|edge| {
            let ts = edge.timestamp;
            lo = Some(lo.map_or(ts, |v| v.min(ts)));
            hi = Some(hi.map_or(ts, |v| v.max(ts)));
        });
        match (lo, hi) { (Some(a), Some(b)) => Some((a, b)), _ => None }
    }
```
Adaptar a la firma real de `for_each_edge` (LEER `streaming.rs:995` — el closure recibe un `&StreamEdge`/`&CompactRelation` con `.timestamp`). Si `for_each_edge` no existe con esa forma, usar el iterador real de aristas. El costo O(E) es aceptable (una consulta, no por-arista); si hay una vía O(1) vía `edges_sorted`, usarla — el test es el árbitro.

- [ ] **Step 4: Correr y ver pasar**

Run: `cargo test edge_timestamp_range` y `cargo test -- --skip benchmark_full_report --skip benchmark`.
Expected: PASS; crate verde modulo los 3 fallos pre-existentes de `demo_data`.

- [ ] **Step 5: Commit**

```powershell
Set-Location C:\Users\lsotomayor\GraphHunter
git add core/graph-engine/src/graph.rs
git commit -m "feat(core): edge_timestamp_range accessor for coverage span"
```

---

### Task 2: `source_watermarks` + `missing_sources` en `AnswerCoverage` (Rust api, TDD)

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\api\src\coverage.rs` (`AnswerCoverage` struct + `answer_coverage` firma)

**Interfaces:**
- Consumes: `edge_timestamp_range` (Task 1) — vía los args de `answer_coverage`.
- Produces:
  ```rust
  // AnswerCoverage gains:
  #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
  pub source_watermarks: std::collections::BTreeMap<String, i64>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub missing_sources: Vec<String>,
  // answer_coverage gains two params:
  pub fn answer_coverage(ic: &IngestCoverage, edge_ts_min: Option<i64>, edge_ts_max: Option<i64>,
      source_watermarks: std::collections::BTreeMap<String,i64>, missing_sources: Vec<String>) -> AnswerCoverage
  ```
  Task 5 llama `answer_coverage` con los watermarks/missing de la sesión. Flag off ⇒ `AnswerCoverage::default()` (todo vacío).

- [ ] **Step 1: Escribir los tests que fallan**

En `coverage.rs` test module (reusar el `ENV_LOCK`):
```rust
    #[test]
    fn answer_coverage_off_omits_source_fields() {
        let _g = lock_env();
        std::env::remove_var("GRAPHHUNTER_SOURCE_COVERAGE");   // and COVERAGE off
        std::env::remove_var("GRAPHHUNTER_COVERAGE");
        let ic = IngestCoverage::default();
        let ac = answer_coverage(&ic, Some(1), Some(2),
            std::collections::BTreeMap::from([("la:ws".into(), 100i64)]), vec!["xdr".into()]);
        assert!(ac.source_watermarks.is_empty());
        assert!(ac.missing_sources.is_empty());
    }

    #[test]
    fn answer_coverage_on_carries_source_watermarks_and_missing() {
        let _g = lock_env();
        std::env::set_var("GRAPHHUNTER_COVERAGE", "1");
        let ic = IngestCoverage::default();
        let ac = answer_coverage(&ic, Some(1), Some(2),
            std::collections::BTreeMap::from([("la:ws".into(), 100i64)]), vec!["xdr".into()]);
        std::env::remove_var("GRAPHHUNTER_COVERAGE");
        assert_eq!(ac.source_watermarks.get("la:ws"), Some(&100));
        assert_eq!(ac.missing_sources, vec!["xdr".to_string()]);
        // a missing source makes the answer possibly_incomplete.
        assert!(ac.possibly_incomplete);
    }
```
Nota: el flag que gobierna el surfacing de source coverage — decidir en Task 3 si es `GRAPHHUNTER_COVERAGE` (reusar) o `GRAPHHUNTER_SOURCE_COVERAGE` (nuevo). El plan usa `GRAPHHUNTER_COVERAGE` para el surfacing en la respuesta (ya gobierna AnswerCoverage) y `GRAPHHUNTER_SOURCE_COVERAGE` para el rastreo en ingest (Task 3/4). Si el implementador prefiere un solo flag, documentarlo; el test de arriba usa `GRAPHHUNTER_COVERAGE` para el surfacing.

- [ ] **Step 2: Correr y ver fallar**

Run: `cd platform/api && cargo test --lib answer_coverage_off_omits_source answer_coverage_on_carries_source`
Expected: FAIL — campos/args inexistentes.

- [ ] **Step 3: Implementar**

En `AnswerCoverage` (coverage.rs:49-57), añadir los dos campos (con `skip_serializing_if` vacío). Extender `answer_coverage`:
```rust
pub fn answer_coverage(
    ic: &IngestCoverage,
    edge_ts_min: Option<i64>,
    edge_ts_max: Option<i64>,
    source_watermarks: std::collections::BTreeMap<String, i64>,
    missing_sources: Vec<String>,
) -> AnswerCoverage {
    if !coverage_enabled() {
        return AnswerCoverage::default();
    }
    let possibly_incomplete = ic.possibly_incomplete || !missing_sources.is_empty();
    let mut incomplete_reasons = ic.incomplete_reasons.clone();
    if !missing_sources.is_empty() {
        incomplete_reasons.push(format!(
            "missing_sources: {} source(s) blind in the queried window", missing_sources.len()));
    }
    AnswerCoverage {
        possibly_incomplete,
        coverage_start: edge_ts_min,
        coverage_end: edge_ts_max,
        incomplete_reasons,
        source_watermarks,
        missing_sources,
    }
}
```
Actualizar TODOS los call sites de `answer_coverage` (hoy en `hunt.rs`) para pasar los dos args nuevos — de momento `BTreeMap::new(), vec![]` (Task 5 los puebla de verdad). LEER los call sites y ajustar para que compile.

- [ ] **Step 4: Correr y ver pasar**

Run: `cargo test --lib answer_coverage` y `cargo test --lib` + `cargo test --test parity` (el DTO de respuesta cambia — el parity test debe seguir verde porque los campos nuevos tienen `skip_serializing_if` vacío ⇒ omitidos por default).
Expected: PASS; parity verde.

- [ ] **Step 5: Commit**

```powershell
git add platform/api/src/coverage.rs platform/api/src/operations/hunt.rs
git commit -m "feat(api): AnswerCoverage.source_watermarks + missing_sources (omitted when empty)"
```

---

### Task 3: `SourceCoverage` de sesión (watermark por-fuente + circuit breaker) + flag (Rust api, TDD)

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\api\src\coverage.rs` (tipo `SourceCoverage` + `source_coverage_enabled()`)

**Interfaces:**
- Consumes: la lógica de `CircuitBreaker` (`source_poller.rs:76-132` — LEER; reusar `pub(crate)` o replicar mínima).
- Produces:
  ```rust
  pub fn source_coverage_enabled() -> bool   // GRAPHHUNTER_SOURCE_COVERAGE, default off
  pub struct SourceCoverage { /* per-source: last_covered_ts + consecutive_failures + open_until */ }
  impl SourceCoverage {
      pub fn new() -> Self
      /// A successful pull covering up to `window_end_ts` for `source_id`.
      pub fn record_covered(&mut self, source_id: &str, window_end_ts: i64)
      /// A failed pull for `source_id`. Returns true if the breaker is now open.
      pub fn record_failure(&mut self, source_id: &str, max_failures: u32) -> bool
      /// Is the source's breaker currently open (skip the pull)?
      pub fn is_open(&self, source_id: &str) -> bool
      /// Mark a window as not covered (breaker-skipped or errored) for source_id.
      pub fn record_missing(&mut self, source_id: &str)
      /// Snapshot for the answer: (per-source last_covered_ts, list of sources with a gap/open breaker).
      pub fn snapshot(&self) -> (std::collections::BTreeMap<String,i64>, Vec<String>)
  }
  ```
  Task 4 llama `record_covered`/`record_failure`/`is_open`/`record_missing`; Task 5 llama `snapshot`.

- [ ] **Step 1: Escribir los tests que fallan**

```rust
    #[test]
    fn source_coverage_flag_defaults_off() {
        let _g = lock_env();
        std::env::remove_var("GRAPHHUNTER_SOURCE_COVERAGE");
        assert!(!source_coverage_enabled());
        std::env::set_var("GRAPHHUNTER_SOURCE_COVERAGE", "1");
        assert!(source_coverage_enabled());
        std::env::remove_var("GRAPHHUNTER_SOURCE_COVERAGE");
    }

    #[test]
    fn breaker_opens_after_consecutive_failures_and_marks_missing() {
        let mut sc = SourceCoverage::new();
        // a good pull records the watermark, breaker closed.
        sc.record_covered("la:ws", 1000);
        assert!(!sc.is_open("la:ws"));
        // 3 consecutive failures (max_failures = 3) opens the breaker.
        assert!(!sc.record_failure("la:ws", 3));
        assert!(!sc.record_failure("la:ws", 3));
        assert!(sc.record_failure("la:ws", 3));   // now open
        assert!(sc.is_open("la:ws"));
        // an open breaker's window is recorded missing.
        sc.record_missing("la:ws");
        let (wms, missing) = sc.snapshot();
        assert_eq!(wms.get("la:ws"), Some(&1000));   // last good watermark
        assert!(missing.contains(&"la:ws".to_string()));
    }

    #[test]
    fn success_resets_failures() {
        let mut sc = SourceCoverage::new();
        sc.record_failure("la:ws", 3);
        sc.record_failure("la:ws", 3);
        sc.record_covered("la:ws", 2000);   // success resets the counter
        assert!(!sc.record_failure("la:ws", 3)); // 1 failure again, not open
        assert!(!sc.is_open("la:ws"));
    }
```
Nota: para el breaker de tiempo, `is_open` puede usar un contador simple (open cuando `consecutive_failures >= max_failures`) o el `open_until` temporal del breaker real. Para testeabilidad sin reloj, la versión de contador (`consecutive_failures >= max_failures`) es suficiente y determinista — el implementador puede añadir el backoff temporal reusando el breaker real si el reloj es inyectable, pero el contrato mínimo del test es el contador. Documentar la elección.

- [ ] **Step 2: Correr y ver fallar**

Run: `cd platform/api && cargo test --lib source_coverage breaker_opens success_resets`
Expected: FAIL — símbolos inexistentes.

- [ ] **Step 3: Implementar**

En `coverage.rs`: el flag `source_coverage_enabled()` (mismo patrón que `coverage_enabled`, var `GRAPHHUNTER_SOURCE_COVERAGE`). El `SourceCoverage` con un `BTreeMap<String, PerSource>` donde `PerSource { last_covered_ts: Option<i64>, consecutive_failures: u32, missing: bool }`. `record_covered` setea `last_covered_ts`, resetea `consecutive_failures=0`, `missing=false`. `record_failure` incrementa `consecutive_failures`, retorna `consecutive_failures >= max_failures`. `is_open` = `consecutive_failures >= <the max used>` — pero `is_open` no conoce max_failures; guardar el estado open como bool en `PerSource` (setear en `record_failure` cuando cruza el umbral). `record_missing` setea `missing=true`. `snapshot` retorna `(map de source→last_covered_ts donde Some, vec de sources con missing==true || open)`. Reusar/replicar el backoff del `CircuitBreaker` real es opcional (el contador es el contrato). Documentar si se reusó `source_poller::CircuitBreaker` (requiere hacerlo `pub(crate)`) o se replicó mínimo en coverage.rs (preferible para no acoplar api↔core-internal).

- [ ] **Step 4: Correr y ver pasar**

Run: `cargo test --lib source_coverage breaker_opens success_resets` y `cargo test --lib`.
Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add platform/api/src/coverage.rs
git commit -m "feat(api): SourceCoverage - per-source watermark + circuit breaker (GRAPHHUNTER_SOURCE_COVERAGE)"
```

---

### Task 4: Cablear `ingest_siem` al breaker + coverage por-fuente (Rust api, TDD/read-verify)

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\api\src\state\session.rs` (campo `source_coverage`)
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\api\src\operations\ingestion.rs` (`ingest_siem` ~:609-852)

**Interfaces:**
- Consumes: `SourceCoverage`/`source_coverage_enabled` (Task 3).
- Produces: `Session.source_coverage: RwLock<crate::coverage::SourceCoverage>` (efímero, no persistido); `ingest_siem` cablea el breaker+coverage cuando el flag está on.

- [ ] **Step 1: LEER + escribir el test si es alcanzable**

LEER `ingest_siem` (`ingestion.rs:609-852`): dónde arma el `source_id` (el workspace/tenant — el breaker es por-fuente; usar `source_id = format!("{}:{}", kind, workspace_id)` o el identificador real disponible), el punto donde la query a Sentinel/Elastic tiene éxito (`L646-654`) o falla (el `Err`/`spawn_blocking` result), y de dónde sale la ventana temporal (el query string tiene el filtro `TimeGenerated` — si no hay un window_end explícito, usar el `now`/el max timestamp de los eventos como `window_end_ts`). LEER cómo `ingest_siem` accede a la sesión (para `session.source_coverage`). `ingest_siem` es async + depende de Azure/Elastic → probablemente NO unit-testeable; cobertura = build + read-verify + un test de la lógica pura si se puede extraer (p. ej. una fn `record_siem_outcome(sc, source_id, result, window_end, max_failures)` testeable).

- [ ] **Step 2: Implementar** (cuando `source_coverage_enabled()`)

En `Session` (session.rs), añadir `pub source_coverage: RwLock<crate::coverage::SourceCoverage>` (init `SourceCoverage::new()` en el constructor ~:350; actualizar los otros sitios de construcción de `Session` que el compilador marque — `operations/session.rs` reload, `dto_shapes` test si aplica). NO añadirlo al `SessionFile`/GHS1 serializer (efímero, como `ingest_coverage`).

En `ingest_siem`, guardado por `source_coverage_enabled()`:
- Antes del pull: si `session.source_coverage.read().is_open(&source_id)` → saltar el pull, `record_missing(&source_id)`, y retornar un `LoadResult` que refleje 0 eventos + una razón (o continuar según el diseño — el mínimo: registrar missing y no pullear esa fuente).
- Tras un pull exitoso: `session.source_coverage.write().record_covered(&source_id, window_end_ts)`.
- Tras un pull fallido (query error / partial): `session.source_coverage.write().record_failure(&source_id, DEFAULT_MAX_FAILURES)` (usar `5` o una const — reusar `DEFAULT_CIRCUIT_MAX_FAILURES` si es accesible), y `record_missing(&source_id)`.
Elegir `max_failures` (const local, p. ej. `SIEM_BREAKER_MAX_FAILURES: u32 = 5`). El `window_end_ts`: el max timestamp de los eventos parseados, o `now` si no hay eventos. Extraer la decisión a una fn pura `record_siem_outcome(...)` para testearla sin el harness Azure; testear esa fn (éxito→covered, error→failure+missing, breaker-open→skip). Read-verify el cableado de `ingest_siem`.

- [ ] **Step 3: Compilar + tests**

Run: `cd platform/api && cargo build --lib` (verde) y `cargo test --lib` (verde; flag off = no-op, ingest_siem no toca source_coverage) + `cargo test --lib record_siem_outcome` (la fn pura).
Expected: compila; sin regresión.

- [ ] **Step 4: WIP-safety + Commit**

`git diff --cached` de cada archivo = propio-only (git add -p si session.rs/ingestion.rs tienen WIP mezclado).
```powershell
git add platform/api/src/state/session.rs platform/api/src/operations/ingestion.rs
git commit -m "feat(api): ingest_siem records per-source coverage + breaker (source_coverage)"
```

---

### Task 5: Poblar `source_watermarks`/`missing_sources` en las respuestas (Rust api, TDD)

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\api\src\operations\hunt.rs` (poblar desde `session.source_coverage.snapshot()`)

**Interfaces:**
- Consumes: `SourceCoverage::snapshot` (Task 3), `answer_coverage` extendido (Task 2), `Session.source_coverage` (Task 4), `edge_timestamp_range` (Task 1).
- Produces: `RunHuntResponse.coverage` y `RunHuntBatchEntry.coverage` ahora incluyen source_watermarks/missing_sources + el span de timestamps.

- [ ] **Step 1: LEER + escribir el test que falla**

LEER cómo `hunt.rs` construye `answer_coverage` hoy (fase Cobertura: `answer_coverage(&ic, None, None)` + `batch_entry_coverage`). Cambiar a: leer `session.source_coverage.read().snapshot()` → `(watermarks, missing)`; leer `session.graph...edge_timestamp_range()` → `(min,max)`; llamar `answer_coverage(&ic, Some(min), Some(max), watermarks, missing)`. Test (a nivel de la construcción, reusando el patrón del test end-to-end de la fase Cobertura que marca la sesión directamente):

```rust
    #[test]
    fn run_hunt_answer_carries_missing_sources_when_breaker_open() {
        let _g = lock_env();
        std::env::set_var("GRAPHHUNTER_COVERAGE", "1");
        std::env::set_var("GRAPHHUNTER_SOURCE_COVERAGE", "1");
        // resolve a session, mark a source's breaker open + missing directly.
        let session = /* current_session() / resolve_session(None) per the Coverage-phase test */;
        {
            let mut sc = session.source_coverage.write().unwrap();
            sc.record_covered("la:ws", 500);
            for _ in 0..5 { sc.record_failure("xdr:tenant", 5); }
            sc.record_missing("xdr:tenant");
        }
        let resp = /* run_hunt with a trivial request */;
        std::env::remove_var("GRAPHHUNTER_COVERAGE");
        std::env::remove_var("GRAPHHUNTER_SOURCE_COVERAGE");
        assert!(resp.coverage.missing_sources.contains(&"xdr:tenant".to_string()));
        assert_eq!(resp.coverage.source_watermarks.get("la:ws"), Some(&500));
        assert!(resp.coverage.possibly_incomplete);
    }
```
Adaptar a cómo la fase Cobertura testeó run_hunt (mismo `Arc<Session>`, request trivial). Si run_hunt no es fácilmente invocable en test, degradar a testear la fn helper que arma la `AnswerCoverage` desde la sesión + read-verify.

- [ ] **Step 2: Correr y ver fallar**

Run: `cd platform/api && cargo test --lib run_hunt_answer_carries_missing_sources`
Expected: FAIL — hoy pasa `BTreeMap::new(), vec![]`.

- [ ] **Step 3: Implementar**

En `hunt.rs`, donde se arma `answer_coverage` para `RunHuntResponse` Y para `RunHuntBatchEntry` (los 5 sitios de la fase Cobertura — main + error + 3 fast/cache): leer `session.source_coverage.snapshot()` + `session.graph.read()...edge_timestamp_range()` y pasarlos a `answer_coverage`. Extraer un helper `fn session_answer_coverage(session: &Session) -> AnswerCoverage` que haga las 3 lecturas y la llamada, reusado en todos los sitios (evita duplicar). Con flag off, `answer_coverage` retorna default igual (no-op).

- [ ] **Step 4: Correr y ver pasar**

Run: `cargo test --lib run_hunt_answer_carries_missing_sources` y `cargo test --lib` + `cargo test --test parity`.
Expected: PASS; parity verde (campos nuevos omitidos por default con flag off).

- [ ] **Step 5: Commit**

```powershell
git add platform/api/src/operations/hunt.rs
git commit -m "feat(api): hunt answers carry source_watermarks + missing_sources + coverage span"
```

---

### Task 6: Flip source_coverage → full — EL HITO (repo sot + GraphHunter)

**Files:**
- Modify: `C:\Users\lsotomayor\sot\validation\graphhunter\ingest_surface.json` (source_coverage)
- Modify: `C:\Users\lsotomayor\sot\validation\graphhunter\audit_results.json` (re-freeze — 30 hipótesis → Sufficient)
- Modify: `C:\Users\lsotomayor\sot\validation\graphhunter\graphhunter_sufficiency_audit.md` (el delta del hito)
- Modify: `C:\Users\lsotomayor\sot\MANIFEST.sha256` (git-blob)
- Modify/Create: `C:\Users\lsotomayor\GraphHunter\docs\architecture\incremental-correctness.md` (o un doc de cobertura — sección Fase F)

**Interfaces:**
- Consumes: los deliverables Tasks 1-5; el runner `audit_graphhunter.py`.

- [ ] **Step 1: Flip source_coverage → "full", honestamente scoped**

En `ingest_surface.json`, `source_coverage` → `"fidelity": "full"`, nota reescrita:
```json
"source_coverage": {"fidelity": "full", "loss_point": "L5", "context": "circuit_breaker", "witness_type": "future_behavior", "note": "closed for the circuit_breaker context on the live one-shot ingest path: a per-source circuit breaker (SourceCoverage in platform/api coverage.rs) tracks consecutive query failures across ingest_siem calls; when it opens, that source's window is skipped and recorded as a coverage gap, surfaced as missing_sources (+ a lagging source_watermark) on the hunt answer (RunHuntResponse + RunHuntBatchEntry). So a breaker-skipped window is now DISTINGUISHABLE from a genuinely-empty one (the witness's same_observed no longer holds). Behind GRAPHHUNTER_SOURCE_COVERAGE + GRAPHHUNTER_COVERAGE (default off). BOUNDARY: the dormant streaming poller pipeline (SourcePoller/ParserTask/GraphWriter) is NOT wired - not required by the witness; the closure uses a per-source breaker+coverage on the existing one-shot ingest_siem path. The session SourceCoverage is ephemeral (not persisted to GHS1) - a reload loses the marker. graph_neighbors/path/anomaly answers do not carry coverage; only the hunt/batch surface (where hypotheses are answered) does.", "fix": "Fase F: cablear el runtime incremental de dirty-sets/watermark al path de ingesta real"}
```
NO tocar otros canales. Si algo del cableado quedó read-verified y no integration-tested (ingest_siem async), decirlo exacto.

- [ ] **Step 2: Re-freeze + leer el delta REAL — EL HITO**

```bash
cd /c/Users/lsotomayor/sot
python scripts/sot_sys/audit_graphhunter.py
python scripts/sot_sys/audit_graphhunter.py --check   # "up to date"
```
`source_coverage` es el último canal degraded en HYPOTHESIS_REQUIRES. Al flipear → el blind set de cada hipótesis queda **vacío** → `_verdict` retorna `Sufficient`. INSPECCIONAR `audit_results.json`: las **30 hipótesis** deben pasar de `InsufficientWithWitness` a **`Sufficient`**. Reportar el número EXACTO leído del JSON (30/30 Sufficient — el primer Sufficient del programa). Las dos transversales (`loss_reconstruction`, `exhaustiveness_marking`): `exhaustiveness_marking` (source_coverage + ingest_completeness + completeness_flag) ahora todos full → puede pasar a Sufficient también; `loss_reconstruction` (ingestion_time absent + provenance_stability degraded) SIGUE insuficiente. Reportar el estado EXACTO de ambas transversales del JSON. NO inflar — pero SÍ registrar el hito (30 hipótesis Sufficient) que es real.

- [ ] **Step 3: Docs** — sección Fase F: el `SourceCoverage` (breaker por-fuente + watermark), el cableado de `ingest_siem`, `source_watermarks`/`missing_sources` en las respuestas, `edge_timestamp_range` para el span; los flags; qué cierra (circuit_breaker literal en el path one-shot) y los boundaries (poller dormido no cableado, efímero, hunt/batch-only); y **prominente**: EL HITO — las 30 hipótesis alcanzan Sufficient; el estado de las transversales; los dos canales fuera del set requerido (provenance_stability, ingestion_time) que el repo conserva ciegos. Etiquetas de claim.

- [ ] **Step 4: audit md + MANIFEST** — sección "Fase F delta / MILESTONE" con los números reales (30/30 Sufficient, el estado de ambas transversales, source_coverage closed con boundaries). MANIFEST vía git-blob (sha256 de `git cat-file blob :<path>` tras `git add` — NO write_manifest.py, corrompe con CRLF).

- [ ] **Step 5: Verificar (checklist)** — source_coverage full con nota honesta (boundaries: poller dormido, efímero, hunt-only, flags); `--check` up-to-date; delta = JSON (30/30 Sufficient — verificar leyendo el JSON, no asumir); doc con el hito + boundaries; MANIFEST limpio.

- [ ] **Step 6: Commit (dos repos)**

```bash
cd /c/Users/lsotomayor/sot
git add validation/graphhunter/ingest_surface.json validation/graphhunter/audit_results.json validation/graphhunter/graphhunter_sufficiency_audit.md MANIFEST.sha256
git commit -m "GraphHunter audit: Fase F flips source_coverage to full - 30 hypotheses reach Sufficient (milestone) + re-freeze"
```
```powershell
Set-Location C:\Users\lsotomayor\GraphHunter
git add docs/architecture/incremental-correctness.md
git commit -m "docs(sot): Fase F - per-source coverage + breaker closes source_coverage (first Sufficient)"
```

---

## Self-Review (del plan, ya ejecutada)

- **Cobertura del spec §16-17:** `source_watermarks`/`missing_sources` en AnswerCoverage (T2/T5); accounting de cobertura por-fuente + breaker en el path live (T3/T4 ↔ §16 hot/cold — la cerradura usa el path live one-shot, el poller dormido queda fuera con disclosure); `coverage_start/end` completados vía T1 (carry-over de Cobertura). El flip honesto del hito (T6 ↔ criterio 17). Diferido explícitamente y disclosado: el pipeline de streaming dormido (no requerido por el witness), provenance_stability + ingestion_time (fuera de HYPOTHESIS_REQUIRES, siguen ciegos).
- **Placeholders:** T1/T2/T3 llevan código+tests completos; T4/T5 marcan "LEER" los sitios reales (ingest_siem success/error/source_id/window, la construcción de answer_coverage en hunt.rs) con ubicación exacta y el contrato como test/read-verify; T4 recomienda extraer `record_siem_outcome` como fn pura testeable sin el harness Azure.
- **Consistencia de tipos/nombres:** `edge_timestamp_range` (T1) → T5; `AnswerCoverage.source_watermarks/missing_sources` + `answer_coverage(ic,min,max,wms,missing)` (T2) → T5; `SourceCoverage`/`record_covered`/`record_failure`/`is_open`/`record_missing`/`snapshot`/`source_coverage_enabled` (T3) → T4/T5; `Session.source_coverage` (T4) → T5; `GRAPHHUNTER_SOURCE_COVERAGE` idéntico en T3 (código) y T6 (nota/doc). Shape-parity RunHuntResponse↔RunHuntBatchEntry mantenida (T5 puebla ambos vía el mismo helper).
- **Honestidad pre-registrada:** T6 declara el hito real (30/30 Sufficient) SIN extenderlo a las transversales; nombra los boundaries (breaker literal en one-shot vs poller dormido no cableado; efímero; hunt/batch-only; flags); reporta el estado exacto de ambas transversales del JSON; conserva provenance_stability/ingestion_time como ciegos fuera del set requerido. Riesgo señalado para pre-flight: la decisión context-literal (breaker real por-fuente) es lo que hace la cerradura de `circuit_breaker` defendible ante el whole-phase review — un mero registro de error one-shot cerraría la esencia pero no el contexto literal; por eso T3/T4 implementan el breaker de fallas-consecutivas. La lección de consumidores (Cobertura): T2/T5 tocan AnswerCoverage/DTOs de respuesta → correr `cargo test --test parity` + mantener RunHuntBatchEntry en shape-parity + grep de notas congeladas.
