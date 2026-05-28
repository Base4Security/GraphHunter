# Track O — Azure E2E + Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the async ingest pipeline into Tauri production, close parser gaps, and harden poller/spill/DLQ paths with observable metrics.

**Architecture:** `GraphAccess` bridges `GraphWriter` to `Session`'s `RwLock<GraphHunter>`; one poller + parser per source feed a shared writer; circuit breaker lives in `SourcePoller`; spill failures surface as `GraphError` not stderr.

**Tech Stack:** Rust, tokio, `graph_hunter_core::ingest::*`, `graph_hunter_sources`, Tauri commands, optional Parquet via `arrow`/`parquet` crate (verify existing deps in `platform/sources`).

**Spec:** `docs/superpowers/specs/2026-05-28-ingest-streaming-matcher-audit-design.md` (Track O section)

**Integrates with:** Track H (`SessionPhase::LiveTail` on writer start).

---

## File map

| File | Responsibility |
|------|----------------|
| `core/graph-engine/src/ingest/graph_access.rs` | Production `GraphAccess` trait |
| `apps/tauri/src-tauri/src/ingest/graph_access.rs` | **Create** — `RwLock<GraphHunter>` impl |
| `apps/tauri/src-tauri/src/ingest/pipeline.rs` | **Create** — spawn poller/parser/writer |
| `apps/tauri/src-tauri/src/commands/azure_streaming.rs` | **Create** — start/stop/status commands |
| `core/graph-engine/src/ingest/source_poller.rs` | Circuit breaker state |
| `core/graph-engine/src/streaming.rs` | Propagate spill errors |
| `core/graph-engine/src/ingest/parser_task.rs` | Parquet + `parse_rows` |
| `core/graph-engine/src/ingest/writer.rs` | Handle spill errors, export metrics |
| `core/graph-engine/src/ingest/overflow.rs` | Integration test |
| `platform/parsers/` | `try_parse` migration (10 parsers) |
| `apps/tauri/src/components/` | Observability panel (optional Sprint 5) |

---

## Sprint 1 — Hardening (O0)

### Task 1: Circuit breaker in `SourcePoller`

**Files:**
- Modify: `core/graph-engine/src/ingest/source_poller.rs`
- Modify: `core/graph-engine/src/ingest/metrics.rs` (expose breaker state)
- Test: `core/graph-engine/src/ingest/source_poller.rs` tests

- [ ] **Step 1: Write failing test**

```rust
#[tokio::test]
async fn poller_opens_circuit_after_n_failures() {
    let source = Arc::new(FailingMockSource::new());
    let poller = SourcePoller::new(/* config with max_failures: 3 */);
    // run one cycle
    assert_eq!(poller.circuit_state(), CircuitState::Open);
}
```

- [ ] **Step 2: Run test — expect FAIL**

Run: `cargo test --manifest-path core/graph-engine/Cargo.toml poller_opens_circuit

- [ ] **Step 3: Add breaker fields to poller**

```rust
pub struct CircuitBreaker {
    consecutive_failures: AtomicU32,
    open_until: AtomicI64, // unix millis
    max_failures: u32,
    backoff_base: Duration,
}
```

On poll error: increment failures; when `>= max_failures`, set open_until with exponential backoff capped at 5 minutes. On success: reset counter.

- [ ] **Step 4: Skip poll cycle while open**

Before `poll_since`, if `Instant::now() < open_until`, sleep and emit metric.

- [ ] **Step 5: Commit**

```bash
git add core/graph-engine/src/ingest/source_poller.rs core/graph-engine/src/ingest/metrics.rs
git commit -m "feat: circuit breaker for SourcePoller table failures"
```

---

### Task 2: Propagate spill errors from streaming

**Files:**
- Modify: `core/graph-engine/src/streaming.rs` (~1058–1105, `auto_spill`)
- Modify: `core/graph-engine/src/errors.rs` (add `GraphError::Spill` if missing)
- Modify: `core/graph-engine/src/ingest/writer.rs`

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn append_edge_surfaces_spill_failure() {
    // configure backend with spill_state that forces io::Error
    let backend = InMemoryStreamingBackend::with_spill_fail(true);
    let err = backend.append_edge_checked(src, edge);
    assert!(matches!(err, Err(GraphError::Spill(_))));
}
```

- [ ] **Step 2: Replace `eprintln!` path**

Change `append_edge` to return `Result<(), GraphError>` on spill failure **or** add `append_edge_checked` used by writer path while keeping infallible `append_edge` for tests with `debug_assert`.

Recommended: internal `try_append_edge` returning `Result`; public `append_edge` logs in test builds only.

- [ ] **Step 3: Writer increments spill error metric and surfaces to metrics snapshot**

In `GraphWriter` loop, on spill error: increment `WriterMetrics.spill_errors`, optionally pause writes.

- [ ] **Step 4: Run tests**

Run: `cargo test --manifest-path core/graph-engine/Cargo.toml auto_spill append_edge_surfaces

- [ ] **Step 5: Commit**

```bash
git add core/graph-engine/src/streaming.rs core/graph-engine/src/errors.rs core/graph-engine/src/ingest/writer.rs
git commit -m "fix: propagate streaming spill failures to writer metrics"
```

---

### Task 3: Overflow replay integration test

**Files:**
- Modify: `core/graph-engine/src/ingest/overflow.rs`
- Test: new `#[tokio::test]` in same file or `core/graph-engine/tests/ingest_overflow.rs`

- [ ] **Step 1: Write test — shutdown spill then replay**

Pattern from `overflow.rs` module docs:

1. Fill `parsed_tx` channel
2. Trigger writer shutdown with pending batches
3. Assert overflow files written
4. Restart writer with `OverflowStore::drain`
5. Assert triple count idempotent

- [ ] **Step 2: Run test**

Run: `cargo test --manifest-path core/graph-engine/Cargo.toml overflow_replay

- [ ] **Step 3: Commit**

```bash
git add core/graph-engine/src/ingest/overflow.rs
git commit -m "test: overflow spill and idempotent replay integration"
```

---

## Sprint 4 — Azure pipeline E2E (O1)

### Task 4: Production `GraphAccess` for Tauri session

**Files:**
- Create: `apps/tauri/src-tauri/src/ingest/mod.rs`
- Create: `apps/tauri/src-tauri/src/ingest/graph_access.rs`
- Modify: `apps/tauri/src-tauri/src/lib.rs` (mod ingest)

- [ ] **Step 1: Implement trait**

```rust
use async_trait::async_trait;
use graph_hunter_core::ingest::graph_access::GraphAccess;
use graph_hunter_core::{GraphError, GraphHunter, ParsedTriple, RawIngestEvent};
use std::sync::{Arc, RwLock};

pub struct SessionGraphAccess {
    graph: Arc<RwLock<GraphHunter>>,
}

#[async_trait]
impl GraphAccess for SessionGraphAccess {
    async fn insert_chunk(
        &self,
        pending: &mut Vec<ParsedTriple>,
        dataset_id: Option<&str>,
        chunk_size: usize,
    ) -> Result<usize, GraphError> {
        let n = tokio::task::block_in_place(|| {
            let mut g = self.graph.write().unwrap_or_else(|e| e.into_inner());
            g.insert_triples_chunk(pending, dataset_id, chunk_size)
        })?;
        Ok(n)
    }

    async fn insert_raw_chunk(
        &self,
        pending: &mut Vec<RawIngestEvent>,
        dataset_id: Option<&str>,
        chunk_size: usize,
    ) -> Result<usize, GraphError> {
        let n = tokio::task::block_in_place(|| {
            let mut g = self.graph.write().unwrap_or_else(|e| e.into_inner());
            g.insert_raw_events_chunk(pending, dataset_id, chunk_size)
        })?;
        Ok(n)
    }
}
```

- [ ] **Step 2: Unit test with `GraphWriter`**

Copy pattern from `graph_access.rs` `InMemoryGraphAccess` tests but use `SessionGraphAccess` + `tokio::sync::Mutex` wrapper if needed.

- [ ] **Step 3: Commit**

```bash
git add apps/tauri/src-tauri/src/ingest/
git commit -m "feat: SessionGraphAccess GraphAccess impl for Tauri"
```

---

### Task 5: Pipeline supervisor

**Files:**
- Create: `apps/tauri/src-tauri/src/ingest/pipeline.rs`
- Modify: `apps/tauri/src-tauri/src/state.rs` or session wrapper to hold `PipelineHandle`

- [ ] **Step 1: Define handle**

```rust
pub struct IngestPipelineHandle {
    cancel: CancellationToken,
    metrics: Arc<WriterMetrics>,
    join: tokio::task::JoinHandle<()>,
}
```

- [ ] **Step 2: Spawn tasks**

```rust
pub async fn spawn_pipeline(
    source: Arc<dyn LogSource>,
    config: PollerConfig,
    parser: Arc<dyn LogParser>,
    graph: Arc<RwLock<GraphHunter>>,
    watermark: Arc<WatermarkStore>,
) -> Result<IngestPipelineHandle, GraphError> {
    let (raw_tx, raw_rx) = raw_channel(4);
    let (parsed_tx, parsed_rx) = parsed_channel(8);
    let access = Arc::new(SessionGraphAccess { graph });
    let metrics = WriterMetrics::new();
    let writer = GraphWriter::new(parsed_rx, access.clone(), metrics.clone());
    let parser_task = ParserTask::new(raw_rx, parsed_tx, parser);
    let poller = SourcePoller::new(source, config, watermark, raw_tx);
    // spawn join_set, return handle
}
```

- [ ] **Step 3: Stop command cancels tree and awaits drain**

Use `IngestCancelTree` from smoke test patterns.

- [ ] **Step 4: Commit**

```bash
git add apps/tauri/src-tauri/src/ingest/pipeline.rs
git commit -m "feat: ingest pipeline supervisor for poller/parser/writer"
```

---

### Task 6: Tauri commands + LiveTail phase

**Files:**
- Create: `apps/tauri/src-tauri/src/commands/azure_streaming.rs`
- Modify: `apps/tauri/src-tauri/src/commands/mod.rs`
- Modify: `platform/api/src/state/session.rs` (set `LiveTail` on start)

- [ ] **Step 1: `cmd_start_azure_streaming`**

Inputs: session id, source config (workspace, tables, poll interval). Validates session is `Ready` or `Loading→Ready`. Spawns pipeline; sets `SessionPhase::LiveTail`.

- [ ] **Step 2: `cmd_stop_azure_streaming`**

Cancels pipeline; leaves graph in LiveTail or transitions to Ready based on product choice (document: stay LiveTail until manual finalize).

- [ ] **Step 3: `cmd_azure_streaming_status`**

Returns `WriterMetricsSnapshot`, circuit breaker states, channel depths.

- [ ] **Step 4: Wire React panel (minimal)**

Extend or replace `AzureStreamingSmokeTest.tsx` with status polling.

- [ ] **Step 5: Commit**

```bash
git add apps/tauri/src-tauri/src/commands/azure_streaming.rs apps/tauri/src/components/
git commit -m "feat: Tauri commands to start/stop Azure streaming pipeline"
```

---

### Task 7: Mock pipeline integration test (no Azure)

**Files:**
- Create: `core/graph-engine/tests/ingest_pipeline_e2e.rs`

- [ ] **Step 1: Mock `LogSource` emitting JSON chunks**

Reuse mock from `source_poller.rs` tests or `azure_streaming_smoke.rs`.

- [ ] **Step 2: Run full pipeline into `InMemoryGraphAccess`**

Assert edge count > 0 and watermarks advanced.

- [ ] **Step 3: Run**

Run: `cargo test --manifest-path core/graph-engine/Cargo.toml ingest_pipeline_e2e

- [ ] **Step 4: Commit**

```bash
git add core/graph-engine/tests/ingest_pipeline_e2e.rs
git commit -m "test: mock LogSource ingest pipeline E2E"
```

---

## Sprint 4 — Parser gaps

### Task 8: Parquet support in `ParserTask`

**Files:**
- Modify: `core/graph-engine/src/ingest/parser_task.rs`
- Modify: `core/graph-engine/Cargo.toml` / `platform/sources/Cargo.toml` (parquet deps if needed)

- [ ] **Step 1: Write failing test with synthetic Parquet bytes**

Use `parquet` crate to write a single-column JSON-equivalent table in test helper.

- [ ] **Step 2: Implement `ChunkEncoding::Parquet` arm**

Decode to rows, call `parser.parse_rows(&rows)`.

- [ ] **Step 3: Run tests**

Run: `cargo test --manifest-path core/graph-engine/Cargo.toml parser_task:: parquet

- [ ] **Step 4: Commit**

```bash
git add core/graph-engine/src/ingest/parser_task.rs
git commit -m "feat: Parquet decoding in ParserTask"
```

---

### Task 9: `parse_rows` fast path

**Files:**
- Modify: `core/graph-engine/src/ingest/parser_task.rs`
- Modify: selected parsers in `platform/parsers/`

- [ ] **Step 1: For Sentinel/Defender parsers, override `parse_rows`**

Avoid re-parsing JSON strings when chunk already decoded to row structs.

- [ ] **Step 2: Benchmark ingest throughput**

Run: `cargo bench --manifest-path core/graph-engine/Cargo.toml --bench ingest_throughput`

- [ ] **Step 3: Commit**

```bash
git add core/graph-engine/src/ingest/parser_task.rs platform/parsers/
git commit -m "perf: parse_rows fast path for high-volume Azure chunks"
```

---

## Sprint 5 — DLQ + observability

### Task 10: Complete `try_parse` migration

**Files:**
- Modify: parsers listed in `CHANGELOG.md` v1.0.0 (10 remaining)
- Pattern: `platform/parsers/sentinel.rs` (reference implementation)

- [ ] **Step 1: List remaining parsers**

Run: `rg "fn parse\\(" platform/parsers --glob '*.rs' -l`

Cross-check which lack `try_parse` override.

- [ ] **Step 2: Migrate one parser per PR**

Each migration: return `ParseOutcome::Triples` or `ParseOutcome::Dlq(reason)` — no silent drop.

- [ ] **Step 3: Commit per parser or batch of 3**

---

### Task 11: Unified observability panel

**Files:**
- Modify: Tauri perf view component
- Expose: `WriterMetricsSnapshot`, poller circuit state, `SessionPhase`, tail stats (Track H)

- [ ] **Step 1: API endpoint or Tauri command aggregating metrics**

- [ ] **Step 2: UI table with channel depths and spill rounds**

- [ ] **Step 3: Document shard plan trigger (writer CPU > 80% for 5 min)

Add section to spec or runbook markdown when threshold hit — no code shard yet.

---

## Acceptance checklist (Track O)

- [ ] Mock pipeline E2E test passes in CI
- [ ] Tauri start/stop streaming commands work with mock source
- [ ] Circuit breaker opens after configured failures; status visible
- [ ] Spill failure increments metric (no silent `eprintln!` only)
- [ ] Parquet chunk parses in unit test
- [ ] Overflow replay integration test passes
