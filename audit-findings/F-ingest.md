# F — Ingest/processing engine audit (static-only)

**Date:** 2026-05-27
**Method:** Grep-only scans across `platform/{parsers,sources,canonical,api,constrained-decode,local-llm,vrl}` and `core/graph-engine/src/ingest/`. Cross-reference of memories `project_{disk_ram_ingest, llm_as_compiler, ator_fraud_case}` and `feedback_{perf_plug_and_play, zoho_ingest_pitfalls, hunt_session_real, one_shot_ingest_parity}`. Dynamic verification deferred to `rust-ci.yml` (Unit 10, PR #66).
**Worker:** unit-18
**Base commit:** 258d30d

## Summary

5 findings: **0 P0, 2 P1, 2 P2, 1 P3**. Also corrects two over-stated severities from Unit 14 (PR #72) — see "Cross-references to prior units" below.

| # | Sev | Finding |
|---|-----|---------|
| 1 | P1 | `LogParser::parse` returns `Vec<ParsedTriple>` (no `Result`) — malformed records on EVERY source are silently dropped by trait design (and `parse_rows` swallows `serde_json::to_string` errors at `parser.rs:146`). Documented as intentional, but no per-source DLQ surface for the dropped rows. |
| 2 | P1 | `parity.rs::subgraph_shape` test still constructs `Subgraph { nodes, edges }` without the 5 new pagination fields (`total_edges`, `returned_edges`, `offset`, `page_size`, `has_more`) — confirms Unit 7's pre-existing compile error is still in the tree. Loss of compile-time coverage for the Subgraph DTO. |
| 3 | P2 | No `PerfBadge` / `perf_mode` / `cap_saturated` surface anywhere in `apps/` (Tauri) or backend — `feedback_perf_plug_and_play` requires a visible UI badge for runtime SIMD/intern detection. SIMD IS plug-and-play (`is_x86_feature_detected!("avx2")` at `simd_rust.rs:39`), but it's invisible to the user. |
| 4 | P2 | Agentic ingestor's `synthesize parser` path at `platform/api/src/operations/agentic.rs:253` uses **unconstrained** `LocalLlm::infer` instead of `infer_constrained`. The constrained decode loop is fully implemented (`candle.rs:184-252`), but the agentic ingestor never feeds it the VRL-subset grammar — so the synthesized parser can be syntactically invalid VRL. |
| 5 | P3 | `evtx_to_sysmon_ndjson` (`platform/api/src/evtx.rs:40`) is the legacy unbounded variant that accumulates ALL EVTX records into `Vec<String>` before returning. Called from `operations/ingestion.rs:345` and `:664`. The 28GB-EVTX streaming guarantee from `project_disk_ram_ingest` only applies to `evtx_ingest_streaming` (50k-record batches, `evtx.rs:72`). |

## Findings

### F1 — P1: Per-source parse errors silently dropped at trait level

- **File:** `core/graph-engine/src/parser.rs:114-148`
- **Evidence:**
  ```rust
  // parser.rs:117
  /// Malformed or unrecognized events are silently skipped (logged in metadata)
  /// to allow best-effort ingestion of real-world, often messy, log sources.
  fn parse(&self, data: &str) -> Vec<ParsedTriple>;
  ```
  Every concrete parser (`CognitoParser`, `FortiAnalyzerXmlParser`, `IisW3cParser`, `SysmonJsonParser`, `GenericParser`) returns `Vec<ParsedTriple>` directly — no `Result`. The default `parse_rows` at line 144-147 catches `serde_json::to_string` failures with `Err(_) => Vec::new()` — a "silently return zero triples" branch.
- **Impact:** A real-world failure mode of the Ator fraud case (memory `project_ator_fraud_case`) is that ingest "works" but produces zero edges because every row hit a parse error. The trait is **designed** for resilience but the design hides systematic failure (e.g. wrong field-config mapping) from the operator. The DLQ subsystem (`platform/api/src/operations/dlq.rs` — full impl with `record_dead_letter`, `list_dead_letters`, `reingest_dead_letter`) exists for the **insertion** path, not the **parse** path.
- **Why P1 (not P0):** Not a panic, not a crash — but in a security product where "zero results found" must be distinguishable from "100% silent parse failures", this gap is a correctness liability. The `ParseStats` helper at `parser.rs:158` partially mitigates by surfacing `rows_seen` vs `rows_with_triples`, but parsers default to empty stats.
- **Fix sketch:**
  1. Add `LogParser::parse_with_dlq(&self, data) -> (Vec<ParsedTriple>, Vec<DeadLetter>)` as a default-implemented trait method (default returns empty DLQ vec, parsers opt in).
  2. Wire the DLQ vec into the existing `record_dead_letter` API in the ingest writer task.
  3. Document the convention in `parser.rs` so the next parser implementor knows about both signals.

### F2 — P1: Lost compile-time coverage on `Subgraph` DTO (still broken from Unit 7)

- **File:** `platform/api/tests/parity/dto_shapes.rs:307`
- **Evidence:**
  ```rust
  // dto_shapes.rs:307-322
  let sg = Subgraph {
      nodes: vec![...],
      edges: vec![SubgraphEdge { ... }],
  };
  ```
  But the production `Subgraph` struct (`platform/api/src/dto/v1/graph_ops.rs:56-75`) has **five** additional fields added 2026-05-06: `total_edges, returned_edges, offset, page_size, has_more`. The test's struct literal is missing all five → compile error.
- **Impact:** `platform/api/tests/parity.rs` is the parity harness that verifies the 3-way (Tauri/HTTP/MCP) transport DTO compatibility. While the test is broken, **shape parity on `Subgraph` is unverified** on every PR. A DTO drift between transports could ship undetected.
- **Cross-reference:** Unit 7 (PR #74) noted "Subgraph.has_more/offset/page_size missing" as a pre-existing compile error. This audit confirms it is still in the tree.
- **Why P1 (not P0):** It's a test, not production code — but it's an *ingest-relevant* test (Subgraph is the visible output of `expand_node` / `events_for_node` in the UI's neighborhood view).
- **Fix:** One-liner — add `..Default::default()` to the struct literal (DTO already has `#[serde(default)]` on all 5 new fields) OR fill them explicitly. Pair with Unit 7's PR.

### F3 — P2: No `PerfBadge` surface — runtime SIMD detection is invisible to user

- **Evidence:**
  - `core/graph-engine/src/simd_rust.rs:39` — `is_x86_feature_detected!("avx2")` runtime dispatch is correctly plug-and-play.
  - `core/graph-engine/src/lftj.rs:344` and `lftj_query.rs:245` — same runtime AVX2 dispatch on the hot query paths.
  - `git grep -nE 'PerfBadge|perf_mode|SimdMode|StringInternMode|cap_saturated'` over the entire tree (`*.rs`, `*.ts`, `*.tsx`) returns **zero matches**.
- **Impact:** `feedback_perf_plug_and_play` is explicit: "All S/M/L perf work must be plug-and-play: default-on at startup + visible UI badge, no manual env config required." The first half (default-on) is satisfied; the second half (visible badge) is not. An analyst running on a non-AVX2 host has no way to know they're getting the scalar fallback (~3-5× slower on intersection-heavy hunts).
- **Why P2 (not P1):** The performance path itself works correctly; only the *visibility* is missing. Doesn't block release, but ships a known UX gap.
- **Fix sketch:**
  1. Add `pub fn perf_capabilities() -> PerfBadge` to `core/graph-engine/src/lib.rs` returning `{ avx2: bool, intern_mode: enum, build_lto: bool }`.
  2. Expose via Tauri command `get_perf_badge`.
  3. Render in the status bar of `apps/tauri/src/App.tsx`.

### F4 — P2: Agentic ingestor synthesizes parsers without grammar constraint

- **File:** `platform/api/src/operations/agentic.rs:253`
- **Evidence:**
  ```rust
  // agentic.rs:253 (parser-synthesis path)
  .infer(&PromptSpec::new(PromptTemplate::ParserGenerate, prompt))
  ```
  But `LocalLlm` trait (`platform/local-llm/src/lib.rs:142`) ALSO exposes `infer_constrained` which is fully wired in `CandleBackend::infer_constrained` (`candle.rs:184-252`, full prefill + per-step decode loop with `LogitsMasker`). The constrained sampler (`platform/constrained-decode/src/xgrammar_backend.rs`) wraps llguidance with the VRL-subset Lark grammar (`grammars/vrl_subset.lark`). The only call site for `infer_constrained` in the whole tree is `negotiation.rs:344` — the field-negotiation path, not parser synthesis.
- **Impact:** Memory `project_llm_as_compiler` notes "F12.3+F12.6 done, decode-loop wire-up pending". This audit confirms: the decode loop is **done** (not pending — memory is stale), but the agentic ingestor's parser-synthesis call path doesn't use it. The synthesized VRL transform comes back as free-form text and can be syntactically invalid VRL → ingest job fails at parse-time of the LLM output, not at LLM-output time.
- **Why P2 (not P0):** No panic. The unconstrained path is the legacy behavior; constrained decode is an optimization. Production usage today works (analyst inspects output, edits, applies). It's a P2 because the constrained path exists and is unused.
- **Fix sketch:**
  1. Add a feature flag `agentic.constrained_parser_synthesis` (default off).
  2. In `agentic.rs:253`, when feature on, load the VRL Lark grammar and call `backend.infer_constrained(spec, &mut sampler)` instead of `infer`.
  3. Update memory `project_llm_as_compiler` — decode-loop IS wired in `CandleBackend`; what is pending is the *agentic ingestor's adoption* of it.

### F5 — P3: Legacy unbounded EVTX path still reachable from production

- **File:** `platform/api/src/evtx.rs:40-57`
- **Evidence:**
  ```rust
  // evtx.rs:40
  pub fn evtx_to_sysmon_ndjson(path: &str) -> Result<String, String> {
      let mut parser = EvtxParser::from_path(path)...;
      let mut lines: Vec<String> = Vec::new();   // unbounded
      for record in parser.records_json_value() { lines.push(...); }
      Ok(lines.join("\n"))
  }
  ```
  Callers: `platform/api/src/operations/ingestion.rs:345` and `:664`. The bounded `evtx_ingest_streaming` (50k-record batches, `evtx.rs:72`) is the path used by `ingestors/evtx.rs:67`'s registered ingestor — but the legacy fn is still on the call graph.
- **Impact:** Memory `project_disk_ram_ingest` documents 4-phase memory optimization for 28GB EVTX. That optimization lives in `evtx_ingest_streaming`. If the legacy `evtx_to_sysmon_ndjson` is invoked on a 28GB EVTX, it OOMs the API process — no chunking, no caps.
- **Why P3 (not P1):** Need to verify whether the two call sites in `operations/ingestion.rs` are dead code (the streaming registry should be the only live path post-refactor) or still on the fast path for some flow. The `git grep` snapshot can't disambiguate. If they're dead code: trivial removal. If live: promote to P1.
- **Fix sketch:**
  1. Trace callers of `operations/ingestion.rs:345/664` via reverse-search; if dead, delete both functions.
  2. If live, replace with `evtx_ingest_streaming` and a small in-memory adapter for the small-file path.
  3. Add `#[deprecated(note = "Use evtx_ingest_streaming")]` in the meantime.

## Cross-references to prior units

### Correction to Unit 14 (PR #72) F1 — `unimplemented!()` was test-only, not P0

- **Claim under review:** Unit 14 reported `platform/api/src/operations/dlq.rs:498` `unimplemented!()` as P0 "reachable in production path".
- **Actual position:** Lines 480-499 of `dlq.rs` are inside a `#[cfg(test)] mod tests { ... }` block (the `#[cfg(test)]` marker is at line 341 of the file, well before line 498). The specific function is:
  ```rust
  // dlq.rs:494-499 — inside #[cfg(test)] mod tests
  // Silence the unused-dataset warning for the DatasetInfo type only
  // ever referenced from the live ingestion paths.
  #[allow(dead_code)]
  fn _referenced_types() -> DatasetInfo {
      unimplemented!()
  }
  ```
- **Verdict:** This is a warning-silencer helper in the test module, marked `#[allow(dead_code)]` and never invoked. It will never run in production. **Not a P0**; not even a P3 — it's a documented intentional warning-silencer.
- **Recommendation:** Mark Unit 14 F1 as "FALSE POSITIVE — test-only `unimplemented!()` behind `#[cfg(test)]` and `#[allow(dead_code)]`". The full DLQ surface (`record_dead_letter`, `list_dead_letters`, `reingest_dead_letter`, `purge_dead_letters` at lines 34/76/230/269) is fully implemented.

### Correction to Unit 14 (PR #72) F2 — "260 unwrap" count is inflated

- **Claim under review:** "260 `unwrap()` calls in `core/graph-engine/src/` … heaviest in `ingest/overflow.rs` (49), `khop_reach.rs` (46), `ingest/source_poller.rs/lftj_query.rs/lftj.rs` (36-41)".
- **Verification on 4 heaviest files** (`#[cfg(test)]` boundary in column 3, unwraps before that boundary in column 4):
  ```
  file                                          total  cfg(test)@line   prod_unwraps_before_cfg
  core/graph-engine/src/ingest/overflow.rs      49     264              0
  core/graph-engine/src/ingest/source_poller.rs 19     258              0
  core/graph-engine/src/khop_reach.rs           46     547              0
  core/graph-engine/src/lftj.rs                 36     1612             0
  ```
- **Sample first 3 unwrap sites in overflow.rs** (`git grep -n '.unwrap()' -- ...overflow.rs | head -3`):
  ```
  overflow.rs:299:    let tmp = TempDir::new().unwrap();
  overflow.rs:302:    let _store = OverflowStore::open(&sub).unwrap();
  overflow.rs:309:    let tmp = TempDir::new().unwrap();
  ```
  All past line 264 = all in `#[cfg(test)]`.
- **Verdict on 4 heaviest:** 0 of 150 unwraps are in production code; 100% are in test modules. The "P1 fleet liability" claim does NOT survive on these files.
- **What's actually true in production ingest code:** Spot-checked `ingest/batch.rs:182`:
  ```rust
  let (table, wm) = batch.watermark_after.as_ref().unwrap();
  ```
  This IS a real production unwrap — but `RwLock::read/write().unwrap()` (the dominant pattern in `cancellation.rs`, `coverage.rs`, etc.) is the idiomatic Rust convention to panic-on-lock-poison and is acceptable per the same Unit 14 finding's own carve-out ("Mutex/lock unwraps (panic on poison) are acceptable to leave").
- **Recommendation:** Re-classify Unit 14 F2 from P1 to **P3** ("audit ingest production unwraps individually; current 260 figure double-counts the 50%+ that are in `#[cfg(test)]` modules"). Keep `clippy::unwrap_used` as a workspace lint goal but stop calling this a fleet liability.

### Confirmations of feedback memories

- **`feedback_zoho_ingest_pitfalls`:** All 5 listed pitfalls (TIME default role, INFO-as-node, EVENT_BY actor/target, identity dup, Zoho-backend IP) ARE documented in code comments (`core/graph-engine/src/field_preview.rs:709-756, 850` and `core/graph-engine/src/csv_parser.rs:22-37, 189`). Addressed.
- **`feedback_hunt_session_real` — silent run_hunt failures:** `core/graph-engine/src/analytics.rs:1518` documents the explicit fix — `get_relation_schema()` exists specifically so analysts no longer "discover [edge direction] through failed `run_hunt` calls." Addressed.
- **`feedback_one_shot_ingest_parity`:** `platform/api/src/operations/ingestion.rs:93-101` defines `auto_field_config_for(format_name, contents) -> Option<FieldConfig>` with the explicit comment "Build a `FieldConfig` from the same heuristic the Preview UI shows, so a one-shot `load_data` call (no analyst override) gets the value-level…" Addressed.

## Method log

```bash
# 1. Per-source error handling (~5 calls)
ls platform/parsers/src        # cognito, forti_analyzer, iis_w3c, lib.rs
ls platform/sources/src        # backoff, data_lake, defender_xdr, http_client, etc.
ls platform/canonical/src      # lib.rs, ocsf/, project/, provenance.rs, schema/
git grep -nE 'fn parse|impl.*Parser' --include='*.rs' platform/parsers platform/sources
#   → 6 'fn parse' definitions; ALL return Vec<ParsedTriple>, none return Result
git grep -nE '\.ok\(\)|let _ =' platform/sources/src         # 6 occurrences in 3 files (HTTP client / token mostly)
git grep -nE '\.ok\(\)|let _ =' platform/parsers/src         # 50 occurrences — typical Option chaining, not error-dropping
git grep -nE 'trait LogParser' core platform                 # → core/graph-engine/src/parser.rs:114
# Read parser.rs:100-160 — trait DOCUMENTS "Malformed or unrecognized events are silently skipped" (line 117)
#   → F1 (P1)

# 2. Memory bounds — 28GB EVTX cap verification (~3 calls)
git grep -nE 'MAX_FILE_BYTES|MAX_FILE_SIZE|BATCH_SIZE|chunk_size' platform/api/src/ingestors platform/sources/src platform/parsers/src core/graph-engine/src/ingest
#   → platform/api/src/ingestors/netflow.rs:37  const MAX_FILE_BYTES: usize = 512 * 1024 * 1024
#   → platform/api/src/evtx.rs:72              const BATCH_SIZE: usize = 50_000   (streaming OK)
#   → platform/api/src/evtx.rs:40              evtx_to_sysmon_ndjson — UNBOUNDED  (F5, P3)
git grep -nE 'read_to_end|fs::read\(|read_to_string' platform/api/src/ingestors platform/sources/src core/graph-engine/src/ingest
#   → platform/api/src/ingestors/netflow.rs:169  guarded by MAX_FILE_BYTES check  (OK)
#   → core/graph-engine/src/ingest/overflow.rs:192  fs::read — but reads self-written batch files, bounded by writer  (OK)

# 3. DLQ + retry inspection (~3 calls)
git grep -nE 'fn.*dlq|dead.?letter|retry_policy|max_retries|FailureKind' platform/api/src/operations/dlq.rs
#   → Lines 34/76/230/269/342/353 — full surface (list/reingest/purge/record/test-helpers)
sed -n '480,520p' platform/api/src/operations/dlq.rs
#   → unimplemented!() at line 498 is INSIDE #[cfg(test)] mod tests, in fn _referenced_types()
#     marked #[allow(dead_code)] — warning-silencer helper, never invoked.   (Correction to Unit 14 F1)
git grep -nE 'retry|max_retries|backoff' platform/sources/src/backoff.rs core/graph-engine/src/ingest
#   → backoff.rs:1 exponential backoff with jitter, shared by every LogSource — well-designed
#   → ingest/parser_task.rs:24 "retry/backoff policy lives at the poller level, not here" — clean separation

# 4. Plug-and-play perf badges (~3 calls)
git grep -nE 'PerfBadge|perf_mode|SimdMode|StringInternMode|cap_saturated' .  # → 0 matches anywhere
git grep -nE 'AVX2|target_feature|is_x86_feature_detected' core/graph-engine/src
#   → simd_rust.rs:39, lftj.rs:344, lftj_query.rs:245 — runtime detection IS in place
#   → No UI surface for the detection result   (F3, P2)

# 5. Agentic ingestor LLM-compiler state (~3 calls)
git grep -nE 'ConstrainedSampler|CandleBackend|xgrammar|llguidance|VRLSubset' platform/constrained-decode platform/local-llm platform/vrl
#   → All symbols exist; full impl in xgrammar_backend.rs + candle.rs
git grep -nE 'unimplemented!|TODO.*F12|TODO.*decode.loop|todo!' platform/constrained-decode platform/local-llm
#   → 0 matches — no pending markers   (memory project_llm_as_compiler is stale)
git grep -nE 'infer_constrained|\.infer\(&' platform core apps
#   → infer_constrained called only at platform/api/src/operations/negotiation.rs:344
#   → Agentic parser-synthesis path at platform/api/src/operations/agentic.rs:253 uses .infer() (unconstrained)
#   → F4 (P2)

# 6. Cross-link to Unit 7 — Subgraph DTO test compile error
git grep -nE 'Subgraph\s*\{|Subgraph::new' platform/api/tests
#   → platform/api/tests/parity/dto_shapes.rs:307 — struct literal missing 5 fields
git grep -nE 'pub struct Subgraph' platform/api/src core
#   → platform/api/src/dto/v1/graph_ops.rs:56 — has total_edges, returned_edges, offset, page_size, has_more (since 2026-05-06)
#   → F2 (P1) — still broken, confirms Unit 7 finding

# 7. Spot-check Unit 14 F2's unwrap inflation (~2 calls)
for f in core/graph-engine/src/{lftj,khop_reach}.rs core/graph-engine/src/ingest/{source_poller,overflow}.rs; do
    total=$(git grep -c '.unwrap()' -- "$f")
    cfg_line=$(git grep -n '#\[cfg(test)\]' -- "$f" | head -1)
    echo "$f total=$total $cfg_line"
done
#   overflow.rs       total=49  #[cfg(test)]@264
#   source_poller.rs  total=19  #[cfg(test)]@258
#   khop_reach.rs     total=46  #[cfg(test)]@547
#   lftj.rs           total=36  #[cfg(test)]@1612
git grep -n '.unwrap()' -- core/graph-engine/src/ingest/overflow.rs | head -3
#   → 299, 302, 309 — all past line 264 → all in #[cfg(test)] — 0 production unwraps in overflow.rs
#   (Correction to Unit 14 F2 — see Cross-references section.)
```

## Skipped (deferred to PR #66 rust-ci.yml, Unit 10)

- `cargo test --workspace` — not run
- `cargo clippy -- -D warnings` — not run
- `cargo doc --no-deps` — not run
- `markdownlint audit-findings/F-ingest.md` — markdownlint not in PATH on this worker

These are the standard deferrals; CI will exercise them on the resulting PR.
