# Sentinel Connector — Robust Incremental Cursor (ingestion_time + drain) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the Sentinel polling connector so it stops silently losing late-arriving events, by cursoring on `ingestion_time()` (monotonic w.r.t. ingestion) instead of `TimeGenerated` (event time, arrives late/out-of-order), and by draining backlog within a poll instead of one batch per interval.

**Architecture:** The real-time polling connector is `platform/api/src/sentinel_connector.rs` (`start_polling` loop over `SentinelPollingConfig`). Per table per poll it: reads a per-table watermark → `KqlQueryBuilder::build` renders KQL → transport executes → `normalize_response` extracts rows + the next watermark → parser → `insert_triples`. Today the cursor is `where TimeGenerated > datetime({wm}) | order by TimeGenerated asc | take N`, and the watermark advances to the max `TimeGenerated` of the batch. Because Log Analytics ingests logs late and out of order, any row that lands after the watermark advanced but with an earlier `TimeGenerated` falls below the `>` and is skipped forever. The fix: cursor on `coalesce(ingestion_time(), TimeGenerated)` (a row's ingestion time only ever increases, so `> wm` never skips a late arrival), advance the watermark from that column, and drain each table until caught up. The insert path has no dedup, so we use a **strict `>`** cursor (no overlap, no re-read) — correctness comes from ingestion_time's monotonicity, not from dedup.

**Tech Stack:** Rust — `graph_hunter_siem` (`platform/siem`, the query builder + normalize) and `graph_hunter_api` (`platform/api`, the connector loop). Both link ort-free → tests actually RUN here. The connector has a `SentinelTransport` trait (DIP) with mock transports in its test module, so the drain loop and cursor are unit-testable end-to-end without Azure.

## Global Constraints

- **Contained to the incremental polling path.** ONLY change: `KqlQueryBuilder::build` + `normalize_response` (in `platform/siem/src/sentinel_streaming.rs`) and the `sentinel_connector.rs` loop. Do NOT touch the sync `run_sentinel_query` path (`platform/siem/src/sentinel.rs`), `ingest_siem`, `ingest_query` (CLI), `run_kql`, or `build_hydration_kql` — those run caller-supplied one-shot queries where the cursor is the caller's responsibility.
- **Back-compat for the other `normalize_response` consumer.** `operations/sentinel.rs`'s hydration also calls `normalize_response` but IGNORES `next_query_start` (one-shot, no watermark loop) and does NOT project `_ingest_ts`. So `normalize_response` MUST fall back to `TimeGenerated` when the `_ingest_ts` column is absent — hydration keeps working unchanged.
- **The parser still needs `TimeGenerated`.** `_ingest_ts` is added purely for cursoring; every row must KEEP its original `TimeGenerated` (and all other fields) so `SentinelJsonParser` still derives the correct event-time edge timestamps. `SentinelJsonParser` ignores unknown columns, so the extra `_ingest_ts` column is harmless.
- **Strict `>` cursor, no overlap, no dedup dependency.** The live `insert_triples` path is append-only (no edge dedup), so re-reading rows would duplicate edges. Cursor with strict `>` on the monotonic ingestion timestamp — never re-read. (Document the single residual edge: >`batch_size` rows sharing one exact `ingestion_time` tick straddling a batch cut; negligible, and the drain loop makes batch cuts happen only when caught up.)
- **Drain must be bounded + cancel-aware.** The per-table drain loop must (a) check `cancel.is_cancelled()` each iteration, (b) stop if the watermark did not advance (guards against an infinite loop when `next_query_start` is `None`), and (c) have a max-iterations backstop. It must not hold the graph write lock across the whole drain.
- **No behavior change to what data lands** beyond "no longer dropping late events + catching up faster." Same tables, same parser, same session graph.

---

### Task 1: `KqlQueryBuilder::build` — cursor on `ingestion_time()`

**Files:**
- Modify: `platform/siem/src/sentinel_streaming.rs` (`KqlQueryBuilder::build` + its tests)

**Interfaces:**
- Produces: `KqlQueryBuilder::build(table, watermark: Option<&str>, batch_size, time_window_filter: Option<&str>) -> String` (signature unchanged) that now renders an `ingestion_time()`-based incremental cursor.

- [ ] **Step 1: Update the failing tests to the new query shape**

Rewrite the existing `kql_with_watermark`, `kql_without_watermark`, `kql_with_time_window_filter_overrides_default`, `kql_watermark_wins_over_time_window` to expect the new shape, and add `kql_projects_ingestion_time_and_orders_by_it`:

```rust
#[test]
fn kql_with_watermark() {
    let q = KqlQueryBuilder::build("SecurityEvent", Some("2024-01-15T14:30:00Z"), 10000, None);
    assert_eq!(
        q,
        "SecurityEvent | extend _ingest_ts = coalesce(ingestion_time(), TimeGenerated) \
         | where _ingest_ts > datetime(2024-01-15T14:30:00Z) \
         | order by _ingest_ts asc | take 10000"
    );
}

#[test]
fn kql_without_watermark_uses_ingestion_time_default() {
    let q = KqlQueryBuilder::build("SigninLogs", None, 5000, None);
    assert_eq!(
        q,
        "SigninLogs | extend _ingest_ts = coalesce(ingestion_time(), TimeGenerated) \
         | where _ingest_ts > ago(24h) \
         | order by _ingest_ts asc | take 5000"
    );
}

#[test]
fn kql_first_poll_uses_caller_window_then_orders_by_ingest_ts() {
    // No watermark yet: use the caller's event-time backfill filter verbatim,
    // but still project + order by _ingest_ts so the first watermark captured
    // is an ingestion_time value (subsequent polls are ingestion-cursored).
    let q = KqlQueryBuilder::build("SigninLogs", None, 5000, Some("where TimeGenerated > ago(7d)"));
    assert_eq!(
        q,
        "SigninLogs | extend _ingest_ts = coalesce(ingestion_time(), TimeGenerated) \
         | where TimeGenerated > ago(7d) \
         | order by _ingest_ts asc | take 5000"
    );
}

#[test]
fn kql_watermark_wins_over_time_window() {
    let q = KqlQueryBuilder::build("SigninLogs", Some("2024-01-15T14:30:00Z"), 5000, Some("where TimeGenerated > ago(7d)"));
    assert!(q.contains("_ingest_ts > datetime(2024-01-15T14:30:00Z)"), "watermark must win: {q}");
    assert!(!q.contains("ago(7d)"), "time_window leaked despite watermark: {q}");
}
```

- [ ] **Step 2: Run — verify they fail against the current builder**

Run: `cd platform/siem && cargo test --lib kql_`
Expected: FAIL (current output uses `where TimeGenerated > ...`, no `_ingest_ts`).

- [ ] **Step 3: Implement the ingestion-time cursor**

```rust
pub fn build(
    table: &str,
    watermark: Option<&str>,
    batch_size: u32,
    time_window_filter: Option<&str>,
) -> String {
    // Cursor on ingestion_time() — monotonic w.r.t. when a row became
    // queryable — so late-arriving events (earlier TimeGenerated, later
    // ingestion) are never skipped by the `>` cursor. `coalesce(..,
    // TimeGenerated)` degrades gracefully for tables without an
    // ingestion-time policy (all rows fall back to event time for that
    // table). `_ingest_ts` is an added column; every row keeps its original
    // TimeGenerated for the parser.
    let time_filter = match (watermark, time_window_filter) {
        // Incremental: cursor strictly past the last ingestion timestamp seen.
        (Some(w), _) => format!("where _ingest_ts > datetime({})", w),
        // First poll: honor the caller's event-time backfill window verbatim.
        (None, Some(tw)) => tw.to_string(),
        // First poll, no window: last 24h by ingestion time.
        (None, None) => "where _ingest_ts > ago(24h)".to_string(),
    };
    format!(
        "{} | extend _ingest_ts = coalesce(ingestion_time(), TimeGenerated) | {} | order by _ingest_ts asc | take {}",
        table, time_filter, batch_size
    )
}
```

- [ ] **Step 4: Run — pass**

Run: `cd platform/siem && cargo test --lib kql_`
Expected: PASS (all builder tests).

- [ ] **Step 5: Commit**

```bash
git add platform/siem/src/sentinel_streaming.rs
git commit -m "fix(sentinel): cursor incremental poll on ingestion_time() not TimeGenerated (stop losing late events)"
```

---

### Task 2: `normalize_response` — advance the watermark from `_ingest_ts`

**Files:**
- Modify: `platform/siem/src/sentinel_streaming.rs` (`normalize_response` + tests)

**Interfaces:**
- Consumes: the Log Analytics response JSON; the response now includes an `_ingest_ts` column (from Task 1's query).
- Produces: `normalize_response(raw) -> Result<SentinelQueryResult, String>` where `next_query_start` is the max `_ingest_ts` value across rows, falling back to max `TimeGenerated` when no `_ingest_ts` column is present (back-compat for hydration).

- [ ] **Step 1: Write the failing tests**

Add to the tests module. Build a fake Log Analytics response with columns incl. `_ingest_ts`, assert `next_query_start` tracks the max `_ingest_ts`; and a second response WITHOUT `_ingest_ts`, assert it falls back to max `TimeGenerated`.

```rust
#[test]
fn normalize_advances_watermark_on_ingest_ts_when_present() {
    let raw = serde_json::json!({
        "tables": [{
            "columns": [
                {"name": "TimeGenerated", "type": "datetime"},
                {"name": "_ingest_ts", "type": "datetime"}
            ],
            "rows": [
                ["2024-01-15T10:00:00Z", "2024-01-15T10:05:00Z"],
                ["2024-01-15T09:00:00Z", "2024-01-15T10:07:00Z"]  // late event, later ingest
            ]
        }]
    });
    let r = normalize_response(&raw).unwrap();
    // Watermark = max ingestion time, NOT max event time.
    assert_eq!(r.next_query_start.as_deref(), Some("2024-01-15T10:07:00Z"));
}

#[test]
fn normalize_falls_back_to_timegenerated_without_ingest_ts() {
    let raw = serde_json::json!({
        "tables": [{
            "columns": [{"name": "TimeGenerated", "type": "datetime"}],
            "rows": [["2024-01-15T10:00:00Z"], ["2024-01-15T10:30:00Z"]]
        }]
    });
    let r = normalize_response(&raw).unwrap();
    assert_eq!(r.next_query_start.as_deref(), Some("2024-01-15T10:30:00Z"));
}
```

- [ ] **Step 2: Run — fail**

Run: `cd platform/siem && cargo test --lib normalize_advances_watermark_on_ingest_ts`
Expected: FAIL (current code only tracks `TimeGenerated`).

- [ ] **Step 3: Implement `_ingest_ts`-preferred watermark tracking**

In `normalize_response`, locate BOTH the `_ingest_ts` column index and the `TimeGenerated` column index. Track `last_time` from `_ingest_ts` when that column exists in this table, else from `TimeGenerated` (per-table decision, so hydration without `_ingest_ts` still tracks TimeGenerated). Keep inserting ALL cells into `obj` (including both columns) so the parser and downstream keep every field. Preserve the existing string-max comparison.

- [ ] **Step 4: Run — pass + full siem suite**

Run: `cd platform/siem && cargo test --lib`
Expected: all green (the new tests + the existing normalize/elastic tests, adjusting any existing normalize test that asserted a TimeGenerated watermark on a response that now would carry `_ingest_ts` — but the existing fixtures have no `_ingest_ts`, so they hit the fallback and stay green).

- [ ] **Step 5: Commit**

```bash
git add platform/siem/src/sentinel_streaming.rs
git commit -m "fix(sentinel): advance poll watermark from _ingest_ts with TimeGenerated fallback"
```

---

### Task 3: Drain the backlog within a poll (bounded, cancel-aware)

**Files:**
- Modify: `platform/api/src/sentinel_connector.rs` (the per-table body of the poll loop + tests)

**Interfaces:**
- Consumes: `KqlQueryBuilder::build` (Task 1), `normalize_response` (Task 2), the `SentinelTransport` mock in the test module.
- Produces: a per-table drain loop that keeps pulling+ingesting until a batch returns fewer than `batch_size` rows (caught up) or empties, cancel-checked and iteration-bounded.

- [ ] **Step 1: Write a failing mock-transport test proving drain**

In the connector's test module (it already has `test_config` + mock transports), add a test where the mock returns `batch_size` rows on the first two calls (advancing `_ingest_ts` each time) then fewer on the third, and assert the connector issued 3 queries in ONE poll and ingested all rows — proving it drains rather than stopping after the first batch. Use a mock transport that records the KQL it received and returns scripted responses keyed by call count. (Model it on the existing connector tests; if the existing tests only run a single poll iteration via cancel, structure the mock so the drain loop is exercised within one poll before cancel.)

- [ ] **Step 2: Run — fail (only one query per table today)**

Run: `cd platform/api && cargo test --lib sentinel_connector` (or the connector test module path)
Expected: FAIL — current code issues exactly one query per table per poll.

- [ ] **Step 3: Implement the bounded drain loop**

Wrap the existing per-table logic (`KqlQueryBuilder::build` → execute → normalize → parse → insert → advance watermark) in an inner loop:

```rust
const MAX_DRAIN_ITERS: u32 = 100; // backstop against a pathological non-advancing cursor
let mut drained = 0u32;
loop {
    if cancel.is_cancelled() { break; }
    let watermark = { watermarks.read().await.get(table).cloned() };
    let kql = KqlQueryBuilder::build(table, watermark.as_deref(), config.batch_size, config.initial_time_window_filter.as_deref());
    // ... execute + normalize (existing match) ...
    // On Ok(result):
    let row_count = /* existing row_count */;
    // parse + insert (existing) ...
    let mut advanced = false;
    if let Some(next) = result.next_query_start {
        let mut store = watermarks.write().await;
        let prev = store.get(table).cloned();
        if prev.as_deref() != Some(next.as_str()) {   // watermark actually moved
            store.set(table, next);
            advanced = true;
        }
    }
    drained += 1;
    // Stop draining this table when: caught up (partial batch), empty, the
    // cursor didn't advance (guards infinite loop), or the backstop hit.
    if row_count < config.batch_size as usize || row_count == 0 || !advanced || drained >= MAX_DRAIN_ITERS {
        break;
    }
}
```

Keep the existing error handling (normalize error / lock poisoned) inside the loop; a normalize error should break the drain for this table (not spin). Do NOT hold the graph write lock across iterations — acquire it per-batch as today. Preserve the `kql-executed` event emission per batch.

- [ ] **Step 4: Run — pass + connector suite**

Run: `cd platform/api && cargo test --lib sentinel_connector` and `cargo test --lib sentinel::`
Expected: green — the new drain test + the existing connector tests (paused-loop, backoff, etc.) still pass. Confirm the paused-by-default test still holds (drain must not fire while paused).

- [ ] **Step 5: Commit**

```bash
git add platform/api/src/sentinel_connector.rs
git commit -m "feat(sentinel): drain backlog within a poll (bounded, cancel-aware) so polling keeps up"
```

---

### Task 4: SOT coverage — make poll gaps observable on hunt answers (Fase F)

**Files:**
- Modify: `platform/api/src/sentinel_connector.rs` (record per-source coverage in the poll loop + tests)

**Interfaces:**
- Consumes: the session's `source_coverage` RwLock (`Session.source_coverage: RwLock<SourceCoverage>`), `SourceCoverage::record_covered(source_id, window_end_ts)` / `record_failure(source_id, max_failures) -> bool` / `record_missing(source_id)`; `graph_hunter_api::coverage::source_coverage_enabled()` (gate, default off, same as `ingest_siem`).
- Produces: the connector loop records a per-source outcome each poll so a subsequent hunt's `AnswerCoverage` reports `missing_sources` when the connector is blind/failing — the SOT discipline: never present an incomplete graph as exhaustive.

**Why (SOT framing):** the cursor fix (Tasks 1-3) stops *silent* loss, but a source can still go blind for reasons outside the cursor (auth failure, table error, transport down, a paused/lagging connector). SOT requires that a blind window be *distinguishable* from a genuinely empty one on the observer's answer. Fase F built exactly this (`SourceCoverage` breaker → `missing_sources` on hunts) but wired it only into `ingest_siem`, not the connector loop. This task closes that gap so the connector's own gaps surface to the analyst.

- [ ] **Step 1: Write a failing mock-transport test**

In the connector test module, drive the mock so one table's query FAILS (transport error) while `GRAPHHUNTER_SOURCE_COVERAGE=1`, then assert the session's `source_coverage.snapshot()` reports that source as missing (or the breaker opens after the configured failures). Add a companion test: a SUCCESSFUL poll calls `record_covered` with the batch's watermark, and the source is NOT missing. Use a stable per-source id for the Sentinel connector (e.g. `format!("sentinel:{}", workspace_id)` or the table — pick one and be consistent; document it).

- [ ] **Step 2: Run — fail**

Run: `cd platform/api && cargo test --lib sentinel_connector` (the new coverage tests)
Expected: FAIL — the loop records nothing today.

- [ ] **Step 3: Wire coverage into the loop (gated, probe-every-poll)**

Gated on `source_coverage_enabled()` (no-op when off — keep the connector byte-identical when the flag is unset). On each table poll:
- **Success** (rows ingested or a clean empty result): `session.source_coverage.write().record_covered(source_id, window_end_ts)` where `window_end_ts` is the batch's max event/ingestion timestamp (or `now` if none) — mirror `record_siem_outcome`'s success arm in `ingestion.rs`.
- **Failure** (transport error, normalize error, or the persistent-error path that currently only `emit_error`s): `record_failure(source_id, max_failures)` + `record_missing(source_id)` — mirror `record_siem_outcome`'s failure arm.
Use the same `source_id` scheme in success and failure. Do NOT change the existing `emit_error`/backoff/status behavior — coverage recording is additive. Keep it out of the hot path when the flag is off (check the flag once per poll, not per row).

- [ ] **Step 4: Run — pass + connector suite**

Run: `cd platform/api && cargo test --lib sentinel_connector` and `cargo test --lib coverage`
Expected: green; the paused-loop / backoff / drain tests still pass; the new coverage tests pass; no-op-when-off preserved (a test with the flag unset asserts `source_coverage` stays empty).

- [ ] **Step 5: Commit**

```bash
git add platform/api/src/sentinel_connector.rs
git commit -m "feat(sentinel): record per-source coverage in the poll loop so gaps surface as missing_sources (Fase F/SOT)"
```

---

### Task 5: Document the cursor semantics + the operator guidance

**Files:**
- Create: `docs/architecture/sentinel-incremental-cursor.md`

- [ ] **Step 1: Write the doc**

Cover, concisely:
- **The bug that was fixed:** `TimeGenerated > watermark` loses late-arriving / out-of-order logs (Log Analytics ingests minutes late, out of order). Why ingestion_time fixes it (monotonic w.r.t. ingestion; a new row always gets a later ingestion timestamp than any already-read row, so strict `>` never skips it).
- **The query shape:** `extend _ingest_ts = coalesce(ingestion_time(), TimeGenerated) | where _ingest_ts > datetime(wm) | order by _ingest_ts asc | take N`; `_ingest_ts` is cursor-only, `TimeGenerated` stays for the parser's edge timestamps.
- **Strict `>` + no dedup:** the insert path is append-only, so we never re-read; correctness rests on monotonicity, not dedup. The one residual edge (>`batch_size` rows at one exact ingestion tick straddling a batch cut) and why it's negligible with the drain loop.
- **Drain semantics:** each table drains until caught up (partial batch), bounded + cancel-aware.
- **Two honest limits:** (1) the watermark store is in-memory (`SentinelWatermarkStore`) — on connector restart it re-backfills from the initial window; persisting watermarks is follow-up work. (2) `ingestion_time()` needs the table's ingestion-time policy (default-on for standard tables); `coalesce` degrades that table to event-time cursoring if absent.
- **SOT coverage (Task 4):** the connector now records per-source coverage (gated by `GRAPHHUNTER_SOURCE_COVERAGE`) so a blind/failing poll window surfaces as `missing_sources` on hunt answers (Fase F) — an incomplete graph is never presented as exhaustive.
- **Operator guidance for the one-shot path** (`ingest_siem` / `ingest_query` with a caller-supplied query — the connector fix does NOT touch these): write your incremental query the same way — `extend _it = ingestion_time() | where _it > datetime(<last>) | order by _it asc | take N` — and cursor on the returned `next_query_start`, never on `TimeGenerated`.

- [ ] **Step 2: Commit**

```bash
git add docs/architecture/sentinel-incremental-cursor.md
git commit -m "docs(sentinel): incremental cursor semantics (ingestion_time, drain, operator guidance)"
```

---

## Self-Review notes

- **Root cause addressed:** the naive `TimeGenerated` cursor (Tasks 1-2) + one-batch-per-interval (Task 3) are exactly the two failure modes behind "el polling no me servía."
- **Contained + back-compat:** only the async incremental path changes; hydration (no `_ingest_ts`, ignores watermark) and the sync one-shot queries are untouched; `normalize_response` falls back to `TimeGenerated`.
- **Testable ort-free:** all changes in `platform/siem` + `platform/api` (no ort); the connector's `SentinelTransport` mock makes the drain loop + cursor unit-testable without Azure.
- **No placeholders:** every step has concrete code/queries/commands; the two "adjust existing test if needed" notes are verification instructions.
- **Type consistency:** `build` signature unchanged; `_ingest_ts` column name consistent across Task 1 (emit) and Task 2 (read); drain loop reuses the existing `KqlQueryBuilder`/`normalize_response`/watermark-store types.
