# Close the SOT `provenance_stability` blind channel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the audit's `provenance_stability` blind channel (`degraded → full`) — the LAST channel keeping `loss_reconstruction` InsufficientWithWitness, so closing it makes `loss_reconstruction` **Sufficient** (a program milestone: every transversal Sufficient).

**Architecture (reframed by recon — the note is a stale labeled-inference):** The witness (context `mapping_edit`): editing a mapping after ingest must NOT retroactively change an already-ingested edge's *exported* provenance. Recon found the export path already reads the FROZEN per-dataset mapping: `export_ocsf` builds `vrl_by_dataset` from `session.datasets → DatasetInfo.field_config` (the mapping captured at ingest, persisted with the session, with no post-ingest mutation site), and `provenance_for_relation` derives the mapping_hash from it. So the retroactive-contamination witness is architecturally closed for FieldConfig datasets — the note's two claimed defects (export reads *current* mapping; configurable freezes static `"builtin:configurable"`) no longer hold as written. The honest remaining gaps: (1) the frozen mapping_hash is `sha256(generated vrl_source)` — make it `sha256(serde_json(FieldConfig))` **directly** (robust, independent of the VRL generator); (2) live/`ingest_siem` and other builtin-parser datasets (`field_config: None`) fall through to `for_builtin_parser(parser_name)` where `parser_name` is usually unstamped → the useless `"builtin:unknown"` — give them a real frozen `"builtin:{parser}"` identity; (3) prove the closure with a witness test. Then re-freeze the audit to `full` with a corrected, honest note.

**Tech Stack:** Rust (`graph_hunter_api` export/ingestion, `platform/canonical` provenance, `core/graph-engine` FieldConfig — all ort-free, tests RUN), Python audit runner (sot repo).

## Global Constraints

- **Verify, do not trust the stale note.** Task 1 writes the witness test FIRST to empirically establish the current state. If it shows the FieldConfig path already frozen/distinguishable (expected), the work is hardening + builtin identity + honest re-freeze. If it reveals real contamination (a post-ingest mutation path), the plan pivots to freezing — report which.
- **`full` requires a meaningful frozen identity on EVERY edge's exported provenance**, not just FieldConfig datasets. A builtin/SIEM edge exporting `"builtin:unknown"` is not a real identity — it must carry the actual parser (`"builtin:sysmon"`, `"builtin:sentinel"`, …), frozen at ingest (the parser is code, versioned by the binary — a "mapping edit" doesn't apply to it, but the identity must still be meaningful and stable).
- **Frozen identity comes from the config CAPTURED AT INGEST**, never a current/global mapping table. FieldConfig datasets: `sha256(serde_json(DatasetInfo.field_config))`. Builtin datasets: `"builtin:{resolved_parser}"` from the format/parser resolved at ingest. Export reads these frozen per-dataset values.
- **Honest note correcting the stale one.** The re-freeze note MUST: (a) state the real mechanism (frozen `DatasetInfo.field_config` → `sha256(serde_json)`; builtin → frozen `builtin:{parser}`), (b) explicitly retract the stale claims (export no longer reads current mapping; configurable no longer collapses to a static tag), (c) disclose boundaries: builtin-parser identity is code-versioned (not a content hash of an editable artifact), and `field_config` persistence relies on the session save format. Do NOT round up.
- **loss_reconstruction becomes Sufficient — verify, don't overclaim beyond it.** After the flip, `loss_reconstruction` status must be `Sufficient` with empty blind_channels. The 30/30 catalog + `exhaustiveness_marking` must stay Sufficient. `ingestion_time` (just closed) stays `full`. Report the milestone precisely: "loss_reconstruction Sufficient — all transversals now Sufficient" — nothing broader.
- **MANIFEST via git-blob only** (sot repo). No unrelated WIP; never `git add -A`.

---

### Task 1: Witness test + robust frozen mapping identity (FieldConfig sha256-direct + real builtin identity)

**Files:**
- Modify: `platform/canonical/src/provenance.rs` (add `for_configurable`)
- Modify: `platform/api/src/operations/export.rs` (`provenance_for_relation` + the `vrl_by_dataset` build → a frozen mapping-identity table)
- Modify: `platform/api/src/operations/ingestion.rs` and/or `platform/api/src/state/session_types.rs` (ensure the resolved parser/format is captured on `DatasetInfo` for builtin datasets so export can emit `builtin:{parser}` not `builtin:unknown`)
- Test: `platform/api/tests/` (a witness test; extend `export_ocsf.rs` or a new `provenance_stability.rs`)

**Interfaces:**
- Consumes: `DatasetInfo { field_config: Option<FieldConfig>, name, path, … }` (`state/session_types.rs:52`); `provenance_for_relation` (`export.rs:376`); `ProvenanceCtx::for_builtin_parser`/`for_vrl` (`provenance.rs:59,80`); `FieldConfig` (canonically `serde_json`-serializable — Vec-only, no HashMap); `sha256_hex` helper (used by `for_vrl`).
- Produces: `ProvenanceCtx::for_configurable(field_config: &FieldConfig, dataset_id, raw_event) -> ProvenanceCtx` with `mapping_hash = "cfg:" + sha256_hex(serde_json(field_config))`; a per-dataset frozen mapping-identity table in export derived from `DatasetInfo` (not current mappings); builtin datasets carrying a real `parser`/`format` on `DatasetInfo` for a `builtin:{parser}` identity.

- [ ] **Step 1: Write the witness test FIRST (empirically establish the state)**

A test that directly exercises the `mapping_edit` witness. Ingest two datasets with DIFFERENT FieldConfigs (A, B) into a session, export OCSF, and assert:
- each edge's exported `provenance.mapping_hash` is a real content hash (starts with `cfg:` / `vrl-` — NOT the static `builtin:configurable` and NOT `builtin:unknown`);
- dataset A's edges and dataset B's edges carry DIFFERENT mapping_hashes (distinguishable — closes defect b);
- re-exporting yields the SAME mapping_hash (stable — the identity is frozen, derived from the ingest-time `DatasetInfo.field_config`, not a mutable global).
Plus a builtin-parser dataset (e.g. format `"sysmon"` with no FieldConfig): assert its exported `mapping_hash` is `builtin:sysmon` (the real parser), NOT `builtin:unknown`.

```rust
// platform/api/tests/provenance_stability.rs (sketch — confirm exact DTO/field names)
#[test]
fn provenance_mapping_hash_is_frozen_and_distinguishes_configs() {
    let api = GraphHunterApi::new_noop();
    api.create_session(/* ... */).unwrap();
    // ingest dataset A with FieldConfig A (via load_data_with_config or a csv+config path)
    // ingest dataset B with a DIFFERENT FieldConfig B
    let out1 = api.export_ocsf(/* ... */).unwrap();
    // parse the OCSF json, collect mapping_hash per dataset
    // assert A_hash != B_hash, both are real content hashes (cfg:/vrl- prefix), neither is builtin:configurable/unknown
    let out2 = api.export_ocsf(/* same */).unwrap();
    // assert A_hash/B_hash unchanged across the two exports (frozen)
}

#[test]
fn builtin_parser_dataset_gets_real_parser_identity_not_unknown() {
    // ingest a sysmon dataset (no FieldConfig) ; export ; assert mapping_hash == "builtin:sysmon"
}
```

Confirm the exact ingest entrypoints/DTOs (`load_data_with_config` for FieldConfig, `load_data` format `"sysmon"` for builtin) and the OCSF provenance json path (`prov["mapping_hash"]`, see `export_ocsf.rs:272`).

- [ ] **Step 2: Run — see what's already green vs red**

Run: `cd platform/api && cargo test --test provenance_stability`
Expected: the FieldConfig-frozen/distinguishable assertions likely PASS already (or fail only on the `cfg:` prefix if the current path emits `vrl-`); the `builtin:sysmon` assertion FAILS (currently `builtin:unknown`). Record exactly which assertions are red — that IS the honest gap.

- [ ] **Step 3: Add `for_configurable` + make export derive the frozen hash directly from FieldConfig**

- In `provenance.rs`, add `for_configurable(field_config, dataset_id, raw_event)` → `mapping_hash = format!("cfg:{}", sha256_hex(serde_json::to_vec(field_config)?))`. Update the doc comment (l.24-27) to match reality.
- In `export.rs`, change the per-dataset table build (`vrl_by_dataset`, l.206-219) to a frozen mapping-identity table keyed by dataset_id, built from `DatasetInfo.field_config` via `for_configurable` (sha256 of the config json DIRECTLY — not `field_config_to_vrl(cfg).source`, so the identity is independent of the VRL generator's output stability). `provenance_for_relation` uses this frozen table for FieldConfig datasets.

- [ ] **Step 4: Give builtin datasets a real frozen parser identity**

Ensure `DatasetInfo` records the resolved parser/format at ingest (it has `name`/`path`; if neither reliably holds the parser, add a `parser: Option<String>` or reuse the resolved format — check `ingestion.rs:471` `resolved_format` and the `DatasetInfo` construction at :478/767/949/1157). In `provenance_for_relation`, for datasets without a FieldConfig, emit `for_builtin_parser(resolved_parser)` using the frozen resolved parser from `DatasetInfo` (→ `builtin:sysmon`, `builtin:sentinel`, …) instead of the `relation.metadata["parser_name"]` → `"unknown"` fallback. If `DatasetInfo` gains a field, bump the GHS1 `BODY_FORMAT_VERSION` if it's in the bincode session body (check `session_binary.rs`; `DatasetInfo` is likely in the session metadata JSON, not the positional Relation body — verify and only bump if needed).

- [ ] **Step 5: Run — witness test green + regression**

Run: `cd platform/api && cargo test --test provenance_stability` then `cargo test --test export_ocsf` + `cargo test --lib journal::` + `cargo test --test parity` + `cargo test --test incremental_rebuild_validation`.
Expected: all green — mapping_hashes are frozen, distinguishable, real (cfg:/builtin:{parser}); the equivalence certificate + parity unaffected (provenance is not in the edge-equality key).

- [ ] **Step 6: Commit**

```bash
git add platform/canonical/src/provenance.rs platform/api/src/operations/export.rs platform/api/src/operations/ingestion.rs platform/api/src/state/session_types.rs platform/api/tests/provenance_stability.rs
git commit -m "feat(provenance): frozen per-dataset mapping identity (sha256(FieldConfig) direct + real builtin:{parser}); witness test"
```

(Stage only the files you actually changed.)

---

### Task 2: Re-freeze the audit — `provenance_stability` → full → loss_reconstruction Sufficient

**Files:**
- Modify (sot repo): `C:\Users\lsotomayor\sot\validation\graphhunter\ingest_surface.json` (the `provenance_stability` channel)
- Regenerate (sot repo): `validation/graphhunter/audit_results.json` + `MANIFEST.sha256`

**Interfaces:**
- Consumes: Task 1's committed code (cite file:line as evidence).
- Produces: `provenance_stability` `fidelity: full`; `loss_reconstruction` status `Sufficient`, empty blind_channels; 30/30 catalog + exhaustiveness_marking unchanged.

- [ ] **Step 1: Flip fidelity + write the honest, corrected note**

Set `provenance_stability` `"fidelity": "full"`. Rewrite `note` to: (a) the real mechanism — the mapping is frozen per-dataset in `DatasetInfo.field_config` at ingest (persisted with the session), export derives `mapping_hash = cfg:sha256(serde_json(FieldConfig))` from it (not a current/global mapping), and builtin datasets carry a frozen `builtin:{resolved_parser}` identity; a post-ingest mapping edit cannot change an already-ingested edge's exported provenance (verified by the witness test `provenance_mapping_hash_is_frozen_and_distinguishes_configs`); (b) EXPLICITLY retract the stale claims — "export reads current mapping" and "configurable freezes static builtin:configurable" no longer hold (the note was a labeled inference from an earlier assessment; the code evolved). (c) Boundaries: builtin-parser identity is code/binary-versioned, not a content hash of an editable artifact; the freeze relies on `DatasetInfo.field_config` surviving the session save format. Update `fix` to point at any residual future work (or "delivered").

- [ ] **Step 2: Re-run the runner + verify the milestone**

```bash
cd /c/Users/lsotomayor/sot
python scripts/sot_sys/audit_graphhunter.py
python scripts/sot_sys/audit_graphhunter.py --check
```
Inspect `audit_results.json`: `loss_reconstruction` status `Sufficient`, blind_channels `[]`; 30/30 `cat-*` Sufficient; `exhaustiveness_marking` Sufficient. If `loss_reconstruction` is still Insufficient, STOP — a required channel is still not `full`.

- [ ] **Step 3: MANIFEST (git-blob) + commit**

Stage the two files, recompute their `git cat-file blob` sha256, update `MANIFEST.sha256` (git-blob only), commit:
```bash
cd /c/Users/lsotomayor/sot
git add validation/graphhunter/ingest_surface.json validation/graphhunter/audit_results.json MANIFEST.sha256
git commit -m "GraphHunter audit: provenance_stability -> full (frozen per-dataset mapping identity); loss_reconstruction now Sufficient"
```

---

### Task 3: Document the closure + the milestone

**Files:**
- Modify: `docs/architecture/incremental-correctness.md` (a short section)

- [ ] **Step 1: Write the section**

Document: mapping identity is frozen per-dataset at ingest (`DatasetInfo.field_config` → `cfg:sha256`; builtin → `builtin:{parser}`), export reads the frozen value so a post-ingest mapping edit cannot contaminate old edges; the stale-note correction; boundaries. Then the MILESTONE: `loss_reconstruction` is now `Sufficient` → **all SOT transversals (`exhaustiveness_marking`, `loss_reconstruction`) and all 30 catalog hypotheses are Sufficient**. State it precisely — this is the audit's full Sufficient state for the declared families, with the standing flag-gating/boundary disclosures each channel's note carries.

- [ ] **Step 2: Commit**

```bash
git add docs/architecture/incremental-correctness.md
git commit -m "docs: provenance_stability closed (frozen per-dataset mapping); loss_reconstruction now Sufficient"
```

---

## Self-Review notes

- **Honest reframe:** the note was a stale labeled-inference; Task 1's witness test empirically establishes the real state before any claim. The `full` grade rests on frozen-per-dataset identity + real builtin identity + a passing witness test — not on the note's original defect framing.
- **Milestone discipline:** loss_reconstruction Sufficient is the ceiling of the claim — "all transversals + catalog Sufficient," with each channel's standing boundaries (flag-gating, receive-clock, code-versioned builtin identity) still disclosed in their notes. Do NOT inflate to "the repo is fully Sufficient unconditionally."
- **Whole-phase review must scrutinize:** is `full` honest given builtin identity is code-versioned (not a content hash) and the closure leans on the pre-existing frozen field_config? Route that to the reviewer, as with ingestion_time's receive-clock question.
