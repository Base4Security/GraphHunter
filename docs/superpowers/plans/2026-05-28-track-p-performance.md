# Track P — Performance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve hunt latency and index cost across scale tiers S/M/L without blocking hybrid live-tail work (Track H).

**Architecture:** Extend existing Criterion benches and planner cost model; parallelize streaming finalize for hub vertices; validate semijoin/AMAC defaults via regression tests before flipping defaults.

**Tech Stack:** Rust, Criterion, rayon, `graph_hunter_core` (`planner.rs`, `streaming.rs`, `graph.rs`, `nlf.rs`), GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-05-28-ingest-streaming-matcher-audit-design.md` (Track P section)

---

## File map

| File | Responsibility |
|------|----------------|
| `core/graph-engine/benches/hunt_latency.rs` | Tier S/M/L spray graphs + hub synthetic |
| `core/graph-engine/benches/matching_powerlaw.rs` | Hub-shaped graph baseline |
| `core/graph-engine/benches/matching_hops.rs` | Multi-hop path baseline |
| `core/graph-engine/src/planner.rs` | Cost model, `plan_with_hints_lazy`, default flip |
| `core/graph-engine/src/streaming.rs` | Parallel `finalize()` |
| `core/graph-engine/src/graph.rs` | Semijoin/AMAC env gates |
| `core/matcher-ffi/` | Deprecation/removal after consumer audit |
| `.github/workflows/rust-ci.yml` | Optional bench regression job |
| `docs/superpowers/calibration/planner-cost-hints.json` | Multi-host calibration constants (new) |

---

## Sprint 1 — Tier benches + planner calibration start

### Task 1: Add tier M/L sizes to `hunt_latency`

**Files:**
- Modify: `core/graph-engine/benches/hunt_latency.rs`
- Modify: `core/graph-engine/Cargo.toml` (ensure `harness = false` on bench target if missing)

- [ ] **Step 1: Add hub-synthetic builder**

Add after `build_spray_graph`:

```rust
/// Tier L — one hub with many spokes (auth spray onto single IP).
fn build_hub_spray_graph(n_spokes: usize) -> GraphHunter {
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("attacker", EntityType::User)).unwrap();
    g.add_entity(Entity::new("10.0.0.1", EntityType::IP)).unwrap();
    for i in 0..n_spokes {
        let user = format!("user_{i}");
        g.add_entity(Entity::new(&user, EntityType::User)).unwrap();
        g.add_relation(
            Relation::new(&user, "10.0.0.1", RelationType::Auth, 1000 + i as i64)
                .with_metadata("status", "Failure"),
        )
        .unwrap();
    }
    g
}
```

- [ ] **Step 2: Extend benchmark group**

Change the loop to include tier sizes and a hub group:

```rust
for n in &[1_000usize, 10_000, 100_000, 500_000, 1_000_000] {
    // existing spray bench...
}

let mut hub_group = c.benchmark_group("User-Auth-IP-hub");
for n in &[10_000usize, 100_000, 500_000] {
    let g = build_hub_spray_graph(*n);
    // same hypothesis as spray...
}
hub_group.finish();
```

- [ ] **Step 3: Run bench locally**

Run: `cargo bench --manifest-path core/graph-engine/Cargo.toml --bench hunt_latency -- User-Auth-IP/1000`

Expected: completes without panic; baseline numbers printed.

- [ ] **Step 4: Commit**

```bash
git add core/graph-engine/benches/hunt_latency.rs
git commit -m "bench: extend hunt_latency with tier M/L and hub spray"
```

---

### Task 2: Baseline snapshot for CI regression (>10%)

**Files:**
- Create: `core/graph-engine/benches/baseline/hunt_latency_baseline.json`
- Create: `.github/workflows/bench-regression.yml` (soft job, `continue-on-error: true` initially)

- [ ] **Step 1: Capture baseline on reference machine**

Run: `cargo bench --manifest-path core/graph-engine/Cargo.toml --bench hunt_latency -- --save-baseline main`

Copy `target/criterion/` summary into committed JSON or use Criterion's baseline feature documented in bench header.

- [ ] **Step 2: Add workflow job**

```yaml
bench-hunt-latency:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@stable
    - uses: Swatinem/rust-cache@v2
    - name: Bench hunt_latency vs baseline
      continue-on-error: true
      run: |
        cargo bench --manifest-path core/graph-engine/Cargo.toml --bench hunt_latency -- --baseline main
```

- [ ] **Step 3: Document regression policy in bench file header**

Add: "CI fails soft until baseline stabilizes across Windows + Linux runners."

- [ ] **Step 4: Commit**

```bash
git add core/graph-engine/benches/ .github/workflows/bench-regression.yml
git commit -m "ci: add soft hunt_latency regression bench job"
```

---

### Task 3: Planner calibration artifact

**Files:**
- Create: `docs/superpowers/calibration/planner-cost-hints.json`
- Modify: `core/graph-engine/src/planner.rs` (load optional calibration overrides)

- [ ] **Step 1: Run calibration on three hosts**

On each host (Windows 16GB, Linux CI, 32GB dev box), run:

```bash
cargo test --manifest-path core/graph-engine/Cargo.toml planner::tests::cost_model_smoke -- --nocapture
```

Record `CostHints` fields (`avg_degree`, `n_vertices`, `n_edges`, mmap spill flags) into JSON:

```json
{
  "hosts": [
    { "label": "linux-ci", "hints": { "avg_degree": 0.0, "n_vertices": 0, "n_edges": 0 } }
  ],
  "cost_constants_version": 1
}
```

- [ ] **Step 2: Add unit test that calibration JSON parses**

In `planner.rs` `#[cfg(test)]` module:

```rust
#[test]
fn calibration_json_loads_if_present() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/superpowers/calibration/planner-cost-hints.json");
    if std::path::Path::new(path).exists() {
        let _raw = std::fs::read_to_string(path).expect("read calibration");
        // parse and assert hosts.len() >= 1
    }
}
```

- [ ] **Step 3: Run test**

Run: `cargo test --manifest-path core/graph-engine/Cargo.toml calibration_json_loads -- --nocapture`

Expected: PASS (skips gracefully if file missing on old branches).

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/calibration/planner-cost-hints.json core/graph-engine/src/planner.rs
git commit -m "docs: add planner cost calibration artifact and loader test"
```

---

## Sprint 2 — Hub finalize + semijoin/AMAC gates

### Task 4: Parallel streaming `finalize()`

**Files:**
- Modify: `core/graph-engine/src/streaming.rs` (~708–723)
- Test: `core/graph-engine/src/streaming.rs` (`#[cfg(test)]` module)

- [ ] **Step 1: Write failing equivalence test**

```rust
#[test]
fn finalize_parallel_matches_sequential() {
    let mk = || {
        let b = InMemoryStreamingBackend::new();
        // append 100 edges across 10 vertices with random timestamps
        b
    };
    let a = mk();
    let c = mk();
    a.finalize();
    c.finalize_parallel(/* threshold */ 4);
    // compare sorted neighbor lists for all vertices
}
```

- [ ] **Step 2: Run test — expect FAIL** (no `finalize_parallel` yet)

Run: `cargo test --manifest-path core/graph-engine/Cargo.toml finalize_parallel_matches -- --nocapture`

- [ ] **Step 3: Implement `finalize_parallel` with rayon**

Collect `(StrId, NeighborList)` pairs needing sort; `par_iter` sort inline/vec arms; leave Mmap unchanged.

- [ ] **Step 4: Gate behind env `GRAPHHUNTER_PARALLEL_FINALIZE=1` initially**

Wire `GraphHunter::sort_edges_by_timestamp` to call parallel path when flag set.

- [ ] **Step 5: Run tests + bench tier M**

Run: `cargo test --manifest-path core/graph-engine/Cargo.toml streaming:: -- --nocapture`

Expected: PASS; note finalize wall time in bench output.

- [ ] **Step 6: Commit**

```bash
git add core/graph-engine/src/streaming.rs core/graph-engine/src/graph.rs
git commit -m "perf: optional parallel streaming finalize for hub graphs"
```

---

### Task 5: Semijoin + AMAC default validation

**Files:**
- Modify: `core/graph-engine/src/graph.rs` (env flag reads)
- Test: existing `graph_pattern`, `path_dedup`, `k4_lftj_dispatch` tests

- [ ] **Step 1: Run regression suite with flags forced on**

```bash
set GRAPHHUNTER_SEMIJOIN=1
set GRAPHHUNTER_AMAC=1
cargo test --manifest-path core/graph-engine/Cargo.toml graph_pattern path_dedup k4_lftj
```

Expected: all PASS on Windows and Linux CI matrix.

- [ ] **Step 2: If PASS, flip defaults in code**

Replace `env_flag("GRAPHHUNTER_SEMIJOIN")` default-false with default-true but keep `GRAPHHUNTER_SEMIJOIN=0` escape hatch for one release.

- [ ] **Step 3: Update CHANGELOG**

Document new defaults and escape env vars.

- [ ] **Step 4: Commit**

```bash
git add core/graph-engine/src/graph.rs CHANGELOG.md
git commit -m "perf: enable semijoin and AMAC by default with opt-out env"
```

---

## Sprint 5 — Planner auto default

### Task 6: Promote `plan_with_hints_lazy` to default

**Files:**
- Modify: `core/graph-engine/src/planner.rs`
- Modify: `core/graph-engine/src/graph.rs` (~819)
- Test: `planner.rs` existing `with_var("GRAPHHUNTER_LFTJ_AUTO", "1", ...)` tests

- [ ] **Step 1: Invert env gate**

Change `plan_with_hints_lazy` to use cost-aware path by default; `GRAPHHUNTER_LFTJ_LEGACY=1` restores old `plan()`.

- [ ] **Step 2: Run full graph-engine test suite**

Run: `cargo test --manifest-path core/graph-engine/Cargo.toml`

Expected: PASS; investigate any plan-selection drift in snapshot tests.

- [ ] **Step 3: Re-run hunt_latency tiers — no >10% regression**

- [ ] **Step 4: Commit**

```bash
git add core/graph-engine/src/planner.rs core/graph-engine/src/graph.rs CHANGELOG.md
git commit -m "perf: make cost-aware planner the default dispatch path"
```

---

## Cleanup (parallel, low priority)

### Task 7: Deprecate `matcher-ffi`

**Files:**
- Modify: `core/matcher-ffi/src/lib.rs`
- Modify: `core/matcher-ffi/Cargo.toml`
- Search: repo for `matcher-ffi` dependents

- [ ] **Step 1: Grep consumers**

Run: `rg "matcher-ffi|matcher_ffi" --glob '*.toml' --glob '*.rs'`

- [ ] **Step 2: Add `#![deprecated]` crate-level notice if still linked from CI matrix**

- [ ] **Step 3: Remove from CI matrix after one release if zero external deps**

---

## Acceptance checklist (Track P)

- [ ] Tier S p95 hunt < 2s (3-step User-Auth-IP, ≤1M edges) on reference host
- [ ] Tier M finalize < 60s at 1M edges with parallel finalize enabled
- [ ] Tier L hub spray: no >10% regression vs committed baseline
- [ ] Planner auto default with legacy escape hatch documented
