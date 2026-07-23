# Rich Incremental-vs-Rebuild Validation Mode + §20 Metrics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the spec's full incremental-vs-rebuild validation mode — rich observable equality (not just counts) between the live incremental graph and a from-scratch journal rebuild, with a readable diff report and §20 structured metrics — so Fase G's precondition ("tests AND métricas demuestran equivalencia operacional") is fully satisfied, runnable without ONNX.

**Architecture:** The comparator sits next to the existing `check_incremental_equivalence` (`platform/api/src/journal.rs:354`), which today compares only entity/relation counts. This plan extends it into a full observable comparator built on `GraphHunter::to_snapshot()` (the one-call full dump: `(Vec<Entity>, Vec<Relation>)`, `core/graph-engine/src/graph.rs:2818`) plus `search_temporal_pattern` for hypothesis-result equality. Both graphs funnel through the same `insert_raw_events`, so entities/metadata/multiplicity/timestamps/dataset-id ARE faithfully carried on both paths; provenance, anomaly/centrality scores, MVCC `ingested_at`, and envelope-only fields are NOT graph observables and must be reported as `NotComparable` (never false-diffed). The translation-validation framing (SOT-VM): the from-scratch rebuild is the trusted reference, the live incremental graph is the untrusted artifact.

**Tech Stack:** Rust (`graph_hunter_api`, `graph_hunter_core`), `tracing` for structured metrics, git-tracked parser fixtures for the real-dataset run. Runs in `platform/api` / `core/graph-engine` test context, which link ort-free by default (no `ml-scoring` feature) — so the whole thing runs without the ONNX blocker that stops `apps/tauri` tests.

## Global Constraints

- **Honesty over completeness — never false-diff.** Dimensions the graph does not carry (provenance beyond dataset-id, anomaly/centrality scores, MVCC `ingested_at`, event-vs-ingestion time, native_id, raw_source_row, canonical_hash) MUST be reported as `NotComparable { reason }`, NOT as a match and NOT as a diff. A comparator that claims equality on a dimension it cannot observe is the exact overstatement this program walks back.
- **Cross-graph identity: resolve to strings.** `StrId(u32)` is an interner-local index — the same logical id gets different `StrId`s in the live graph vs a fresh rebuild. ALL cross-graph comparison MUST go through resolved `String` keys (use `to_snapshot()`, which already resolves to `String`, or `interner.resolve(sid)`). Never compare `StrId`s across the two graphs.
- **Multiset semantics for edges.** Compare edges as a multiset keyed on `(source_id, rel_type, dest_id, timestamp, sorted metadata, dataset_id)` — never assume cross-vertex edge ordering matches. `Entity`'s derived `PartialEq` is id-only (`entity.rs:100-112`), so entity type + metadata must be compared field-by-field, not via `Vec<Entity> == Vec<Entity>`.
- **Corrections/Tombstones caveat.** `rebuild_from_journal` (`journal.rs:304`) does not yet faithfully replay Correction/Tombstone envelopes (they fall through to inserts/ignores). If the journal being validated contains any non-Insert/Skipped envelope, the report MUST flag `rebuild_faithful: false` with a reason, so equivalence is not claimed on an unreplayable journal.
- **No new always-on runtime hook.** The comparator is an explicit diagnostic API + tests, not an every-ingest hook. The spec's "production: off/sampled/small-replica" concern is satisfied by it being an explicit call; do NOT wire it into the hot ingest path. Document production auto-run as flag-gated future work.
- **Metrics house style:** `tracing::info!(target: "validation", key = value, …, "message")` (matches `journal.rs:283`, `ingestion.rs:106`). No new metrics module. Return numbers in the report struct for programmatic assertions; log them via `tracing`.
- **ort-free:** everything must compile and run under `cd platform/api && cargo test` / `cd core/graph-engine && cargo test` WITHOUT `--features ml-scoring`. Do not add any dependency that pulls `ort`.

---

### Task 1: Rich structural comparator (entities, metadata, edge multiset, temporal window)

**Files:**
- Modify: `platform/api/src/journal.rs` (extend `EquivalenceReport`; add `compare_observable_equality`)
- Test: inline `#[cfg(test)] mod tests` in `platform/api/src/journal.rs`

**Interfaces:**
- Consumes: `GraphHunter::to_snapshot() -> (Vec<Entity>, Vec<Relation>)` (`graph.rs:2818`); `Relation { source_id:String, dest_id:String, rel_type:RelationType, timestamp:i64, metadata:HashMap<String,String>, dataset_id:Option<Arc<str>> }`; `Entity` (confirm its type field — likely `entity_type: EntityType` — and `metadata: HashMap<String,String>` against `core/graph-engine/src/entity.rs` before writing the compare); `GraphHunter::edge_timestamp_range() -> Option<(i64,i64)>` (`graph.rs:432`).
- Produces: `pub enum DimensionResult { Match, Diff { detail: String }, NotComparable { reason: String } }`; extended `EquivalenceReport` with rich per-dimension fields; `pub fn compare_observable_equality(live: &GraphHunter, rebuilt: &GraphHunter) -> EquivalenceReport`.

- [ ] **Step 1: Write the failing test — identical graphs match on every structural dimension**

Add to `journal.rs` tests. Build a small live graph + its journal rebuild (mirror the existing `rebuild_from_journal_matches_live_after_idempotent_apply` harness at `journal.rs:917` to get a `(live, rebuilt)` pair from the same envelopes), then:

```rust
#[test]
fn rich_compare_identical_graphs_match_all_structural_dimensions() {
    let (live, rebuilt) = build_live_and_rebuilt_from_same_envelopes(); // helper mirrors journal.rs:917
    let report = compare_observable_equality(&live, &rebuilt);
    assert!(matches!(report.entities, DimensionResult::Match), "entities: {:?}", report.entities);
    assert!(matches!(report.entity_metadata, DimensionResult::Match), "metadata: {:?}", report.entity_metadata);
    assert!(matches!(report.edges_multiset, DimensionResult::Match), "edges: {:?}", report.edges_multiset);
    assert!(matches!(report.temporal_window, DimensionResult::Match), "window: {:?}", report.temporal_window);
    assert!(report.all_comparable_dimensions_match());
}
```

- [ ] **Step 2: Run it — verify it fails to compile (symbols absent)**

Run: `cd platform/api && cargo test --lib journal::tests::rich_compare_identical`
Expected: FAIL — `compare_observable_equality`, `DimensionResult`, and the new report fields don't exist.

- [ ] **Step 3: Implement `DimensionResult`, the extended report, and the structural comparator**

Add `DimensionResult` and extend `EquivalenceReport` (keep the existing count fields for backward-compat with the current test). Implement `compare_observable_equality`:
- `to_snapshot()` both graphs.
- Entities: build `BTreeMap<String, (EntityType, BTreeMap<String,String>)>` from each (resolve metadata `HashMap` into `BTreeMap` for order-independent equality). Compare id sets → `entities`; compare per-shared-id type+metadata → `entity_metadata` (report first ≤5 divergences in the `detail`).
- Edges: build a multiset (`BTreeMap<EdgeKey, usize>` where `EdgeKey = (String src, RelationType, String dst, i64 ts, Vec<(String,String)> sorted_meta, Option<String> dataset)`) from each `Vec<Relation>`. Compare → `edges_multiset` (detail: counts + first divergent keys).
- Temporal: compare `edge_timestamp_range()` → `temporal_window`.
- Add `all_comparable_dimensions_match()` = every `Match`-or-`NotComparable` dimension is not `Diff`.
Keep it a pure function (no I/O, no tracing yet — metrics land in Task 3).

- [ ] **Step 4: Run it — verify pass**

Run: `cd platform/api && cargo test --lib journal::tests::rich_compare_identical`
Expected: PASS.

- [ ] **Step 5: Write + pass the negative-control test (injected divergence is caught)**

```rust
#[test]
fn rich_compare_catches_injected_edge_and_metadata_divergence() {
    let (live, rebuilt) = build_live_and_rebuilt_from_same_envelopes();
    // Mutate the LIVE graph after the fact so it diverges from the rebuild.
    inject_extra_edge(&mut live_mut); // add one edge absent from the journal
    let report = compare_observable_equality(&live_mut, &rebuilt);
    assert!(matches!(report.edges_multiset, DimensionResult::Diff { .. }),
        "expected edge multiset divergence, got {:?}", report.edges_multiset);
    assert!(!report.all_comparable_dimensions_match());
}
```

Use whatever public mutation the graph exposes (e.g. `add_relation`) to inject the extra edge; if no post-hoc mutation is ergonomic, build the divergent graph from a superset envelope batch instead. Run: `cd platform/api && cargo test --lib journal::tests::rich_compare_catches`. Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add platform/api/src/journal.rs
git commit -m "feat(validation): rich structural incremental-vs-rebuild comparator (entities, metadata, edge multiset, temporal)"
```

---

### Task 2: Hypothesis-result + k-hop equivalence dimension

**Files:**
- Modify: `platform/api/src/journal.rs` (extend the comparator with a hypothesis battery)
- Test: same tests module

**Interfaces:**
- Consumes: `GraphHunter::search_temporal_pattern(&self, hypothesis: &Hypothesis, time_window: Option<(i64,i64)>, max_results: Option<usize>) -> Result<(Vec<HuntResult>, bool), GraphError>` (`graph.rs:990`), `HuntResult = Vec<Arc<str>>` (ordered string-id path); `graph_hunter_core::parse_dsl` to build the `Hypothesis` battery from DSL strings.
- Produces: `hypothesis_results: DimensionResult` field on `EquivalenceReport`; comparator runs a fixed DSL battery on both graphs and compares path multisets.

- [ ] **Step 1: Write the failing test — same hypotheses yield same paths on both graphs**

```rust
#[test]
fn rich_compare_hypothesis_results_match_across_incremental_and_rebuild() {
    let (live, rebuilt) = build_live_and_rebuilt_from_same_envelopes();
    // A battery whose entity/relation types exist in the fixture graph.
    let battery = ["User -[Auth]-> Host", "Host -[Execute]-> Process"];
    let report = compare_hypothesis_results(&live, &rebuilt, &battery);
    assert!(matches!(report, DimensionResult::Match), "hypothesis results: {:?}", report);
}
```

- [ ] **Step 2: Run it — fails (symbol absent)**

Run: `cd platform/api && cargo test --lib journal::tests::rich_compare_hypothesis`
Expected: FAIL — `compare_hypothesis_results` not defined.

- [ ] **Step 3: Implement the hypothesis-battery comparator**

`fn compare_hypothesis_results(live, rebuilt, battery: &[&str]) -> DimensionResult`:
- For each DSL string: `parse_dsl(dsl, Some("validation"))` → `Hypothesis`.
- Run `search_temporal_pattern(&h, None, Some(10_000))` on both graphs.
- Normalize each `Vec<HuntResult>` to a multiset of `Vec<String>` (resolve `Arc<str>` → `String`) — order within a path is semantic and preserved, but the set of paths is order-independent, so compare as `BTreeMap<Vec<String>, usize>`.
- If every battery hypothesis matches → `Match`; else `Diff { detail }` naming the first divergent hypothesis + path counts.
- **Honesty:** use ONLY `search_temporal_pattern` (structural). Do NOT use `search_temporal_pattern_smart` — anomaly scores are not populated on either path (both read 0), so the smart path silently degrades and would give a false "match" that says nothing about scoring. Add a `NotComparable`-documented note in code that anomaly-ranked results are excluded because scores are not an ingestion observable.
- Wire the result into `EquivalenceReport.hypothesis_results` inside `compare_observable_equality` (accept the battery as a parameter, or use a default battery constant derived from the fixture's known types — pick the parameterized form and pass a default from callers).

- [ ] **Step 4: Run it — pass**

Run: `cd platform/api && cargo test --lib journal::tests::rich_compare_hypothesis`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add platform/api/src/journal.rs
git commit -m "feat(validation): hypothesis-result equivalence dimension (structural paths, scores excluded honestly)"
```

---

### Task 3: Readable diff report + §20 tracing metrics + the tie-together entrypoint

**Files:**
- Modify: `platform/api/src/journal.rs` (`Display` for the report; metrics; `check_incremental_equivalence` enrichment)
- Test: same tests module

**Interfaces:**
- Consumes: the Task 1/2 comparator; `rebuild_from_journal` + `apply_batch_idempotent` (existing); `tracing::info!`.
- Produces: `impl std::fmt::Display for EquivalenceReport` (human-readable per-dimension PASS/DIFF/NOT-COMPARABLE summary); `check_incremental_equivalence` enriched to populate the rich fields, emit `tracing` metrics, and mark `NotComparable` dimensions + the `rebuild_faithful` guard.

- [ ] **Step 1: Write the failing test — NotComparable dimensions + rebuild_faithful guard + render**

```rust
#[test]
fn report_marks_uncomparable_dimensions_and_renders_readably() {
    let (live, store) = build_live_graph_and_its_journal(); // store may include only Insert/Skipped
    let report = check_incremental_equivalence(&live, &store).unwrap();
    // Provenance & scores are not graph observables -> must be NotComparable, never Match/Diff.
    assert!(matches!(report.provenance, DimensionResult::NotComparable { .. }));
    assert!(matches!(report.anomaly_scores, DimensionResult::NotComparable { .. }));
    assert!(report.rebuild_faithful, "journal has only Insert/Skipped -> faithful");
    let rendered = format!("{}", report);
    assert!(rendered.contains("entities"));
    assert!(rendered.contains("NOT-COMPARABLE") || rendered.contains("not comparable"));
}
```

- [ ] **Step 2: Run it — fails**

Run: `cd platform/api && cargo test --lib journal::tests::report_marks_uncomparable`
Expected: FAIL — `provenance`/`anomaly_scores` fields, `rebuild_faithful`, and `Display` absent.

- [ ] **Step 3: Implement Display, the NotComparable dimensions, the faithful guard, and metrics**

- Add `provenance`, `anomaly_scores`, `mvcc_ingested_at` (and any other spec dimension the graph cannot observe) as `DimensionResult::NotComparable { reason }` fields, each with an accurate reason (e.g. provenance: "beyond dataset-id, provenance is journal-envelope-only; not a graph observable").
- Add `rebuild_faithful: bool` + `rebuild_caveats: Vec<String>`: scan the journal's envelopes; if any is a Correction/Tombstone (non-Insert/Skipped), set `false` and push a caveat naming the count (rebuild_from_journal does not yet replay those — journal.rs:310-313).
- Enrich `check_incremental_equivalence` to: rebuild, run `compare_observable_equality` (+ the default hypothesis battery), fill the rich fields, keep the legacy count fields, set the faithful guard, then `tracing::info!(target: "validation", live_entities = report.live_entities, rebuilt_entities = report.rebuilt_entities, edges_match = report.edges_multiset.is_match(), hypotheses_match = report.hypothesis_results.is_match(), rebuild_faithful = report.rebuild_faithful, "incremental-vs-rebuild validation")`.
- `impl Display`: one line per dimension — `PASS` / `DIFF: <detail>` / `NOT-COMPARABLE: <reason>` — plus a header with entity/relation/edge counts and the `rebuild_faithful` verdict. This is the "reporte de diferencias legible" the spec names.
- Keep the existing `rebuild_from_journal_matches_live_after_idempotent_apply` test green (the legacy count fields remain).

- [ ] **Step 4: Run it — pass + full regression**

Run: `cd platform/api && cargo test --lib journal::` then `cd ../../platform/api && cargo test --test parity`
Expected: all green (24+ journal tests incl. the new ones; parity 35/35 unaffected).

- [ ] **Step 5: Commit**

```bash
git add platform/api/src/journal.rs
git commit -m "feat(validation): readable diff report + §20 tracing metrics + NotComparable honesty + rebuild-faithful guard"
```

---

### Task 4: Real-dataset end-to-end validation certificate

**Files:**
- Create: `platform/api/tests/incremental_rebuild_validation.rs` (integration test)
- Consumes real git-tracked, ort-free fixtures.

**Interfaces:**
- Consumes: the git-tracked multi-source raw-event fixtures used by `platform/canonical/tests/fixtures_three_sources.rs` (Sysmon/Sentinel/FortiAnalyzer inline strings → `LogParser::parse` → parsed triples) OR the parser corpus in `core/graph-engine/tests/parsers.rs`; the envelope + `apply_batch_idempotent` + `check_incremental_equivalence` pipeline from `journal.rs`. Reuse the exact envelope-construction path the `journal.rs:917` test uses, but feed it PARSED REAL EVENTS rather than synthetic `sample_event`s.
- Produces: an integration test that ingests a real multi-source dataset through BOTH the incremental GRAPHDELTA path and the journal rebuild, runs the rich comparator, asserts full observable equality, and prints the readable report; plus a negative control.

- [ ] **Step 1: Write the failing end-to-end equivalence test**

```rust
// platform/api/tests/incremental_rebuild_validation.rs
#[test]
fn real_multi_source_dataset_incremental_equals_rebuild() {
    // 1. Parse real events from git-tracked fixtures (sysmon + sentinel + forti).
    let envelopes = parse_real_fixtures_into_envelopes(); // reuse LogParser + envelope build
    // 2. Live incremental path.
    let mut live = GraphHunter::new();
    let store = JournalStore::open(tempdir).unwrap();
    for e in &envelopes { store.append(e).unwrap(); }
    apply_batch_idempotent(&mut live, &envelopes_as_inserted(&envelopes));
    // 3. Rebuild + rich compare (this is the certificate).
    let report = check_incremental_equivalence(&live, &store).unwrap();
    eprintln!("{}", report); // readable diff report in test output
    assert!(report.all_comparable_dimensions_match(),
        "incremental != rebuild on real dataset:\n{}", report);
    assert!(report.rebuild_faithful);
    assert!(report.live_relations > 0, "fixture must produce a non-trivial graph");
}
```

Confirm the fixture path and parser entrypoint against the actual `fixtures_three_sources.rs` / `parsers.rs` before finalizing — use their exact `LogParser::parse` call and the real inline fixture strings (or `include_str!` a git-tracked demo `.log`). Do NOT depend on the missing `demo_data/*.json` fixtures (they are absent from the main tree).

- [ ] **Step 2: Run it — fails (helper absent / until wired)**

Run: `cd platform/api && cargo test --test incremental_rebuild_validation real_multi_source`
Expected: FAIL first (compile/helper), then a real assertion once wired.

- [ ] **Step 3: Implement the fixture-parsing helper + wire the test**

Implement `parse_real_fixtures_into_envelopes` using the real parser on git-tracked fixtures, producing `CanonicalEnvelope`s the same way `journal.rs` does. Keep it small and multi-source (at least two source types) so the certificate covers the decoupling claim (heterogeneous sources → one graph → incremental=rebuild).

- [ ] **Step 4: Run it — pass, and eyeball the printed report**

Run: `cd platform/api && cargo test --test incremental_rebuild_validation -- --nocapture`
Expected: PASS; the printed report shows every comparable dimension PASS and provenance/scores NOT-COMPARABLE.

- [ ] **Step 5: Negative control — a corrupted incremental graph is caught on the real dataset**

```rust
#[test]
fn real_dataset_negative_control_divergence_is_reported() {
    let envelopes = parse_real_fixtures_into_envelopes();
    let mut live = GraphHunter::new();
    apply_batch_idempotent(&mut live, &envelopes_as_inserted(&envelopes));
    // Drop the last envelope from the journal so the rebuild is a strict subset.
    let store = JournalStore::open(tempdir).unwrap();
    for e in &envelopes[..envelopes.len()-1] { store.append(e).unwrap(); }
    let report = check_incremental_equivalence(&live, &store).unwrap();
    assert!(!report.all_comparable_dimensions_match(),
        "a missing journal record must surface as a divergence");
}
```

Run: `cd platform/api && cargo test --test incremental_rebuild_validation real_dataset_negative`. Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add platform/api/tests/incremental_rebuild_validation.rs
git commit -m "test(validation): real multi-source dataset incremental=rebuild certificate + negative control"
```

---

## Post-phase deliverables (controller, after all tasks review clean)

- **Re-run the audit runner** (sot repo): `python scripts/sot_sys/audit_graphhunter.py --check` — expect null delta (this adds a diagnostic comparator + tests; it touches no telemetry channel).
- **Doc:** append to `docs/architecture/incremental-correctness.md` a "Validation mode (rich)" section documenting what the comparator compares, what it honestly marks `NotComparable`, the `rebuild_faithful` guard, and that this satisfies the metrics half of Fase G's precondition. State plainly the remaining honest limits: provenance/scores not compared (not graph observables); Correction/Tombstone journals not yet faithfully rebuildable; production auto-run is flag-gated future work.
- **Ledger:** record that Fase G's precondition is now fully met (property-tests GREEN + rich validation-mode + real-dataset certificate GREEN), so G is spec-justifiable — and that flipping the production default still requires explicit user OK (production-default change).

## Self-Review notes

- **Spec coverage (§18 validation mode):** entities/relations/multiplicity/identities/metadata/indices/neighborhoods/hypothesis-results/k-hop/temporal-order/provenance/windows → Tasks 1–2 cover every dimension the graph observes; provenance + scores are honestly `NotComparable` (Task 3); readable diff report (Task 3); real-dataset run (Task 4). Metrics §20 → Task 3 `tracing`.
- **No placeholders:** every step has concrete code or a concrete command; the two "confirm field names / fixture path against source" notes are verification instructions, not deferred work.
- **Type consistency:** `DimensionResult` (Task 1) is used by Tasks 2–4; `EquivalenceReport` extended additively (legacy count fields kept so the existing `rebuild_from_journal_matches_live_after_idempotent_apply` test stays green); `compare_observable_equality`/`compare_hypothesis_results`/`check_incremental_equivalence` names are consistent across tasks.
- **YAGNI:** no new runtime flag, no metrics module, no differential-dataflow — an explicit diagnostic API + tests, exactly what G's evidence needs.
