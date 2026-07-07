# Snapshot Ingest by Dataset Layer — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional `dataset` layer name to the LLM-facing ingest tools (`node_enrich`, `sentinel_query`) so that re-running with the same name REPLACES that layer (snapshot) instead of duplicating relations; omitting it keeps today's append behavior.

**Architecture:** Reuse the existing `remove_entities_and_relations_by_dataset` (core) + `insert_triples` with a stable `dataset_id`. When a `dataset` name is supplied, the op removes that layer before inserting. Threaded API op → HTTP → MCP, mirroring the enrichment feature.

**Tech Stack:** Rust (per-crate `--manifest-path`, no workspace), axum HTTP (:37891), TypeScript MCP (runs from compiled `dist/`).

**Spec:** `docs/superpowers/specs/2026-06-09-snapshot-ingest-by-dataset-design.md`

**Cross-cutting reminders:**
- No cargo workspace — always `--manifest-path <crate>/Cargo.toml`.
- The MCP server runs from `dist/`; after any `platform/mcp/src` change, `npm run build` + the user restarts the client.
- Commit trailer: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Known limitation (spec §6): `remove_*_by_dataset` removes entities owned (first-writer) by that dataset; a shared cross-source entity owned by layer X is removed when X is removed even if Y references it. Out of scope here — do NOT try to fix entity ownership.

---

## Task 1: Core snapshot-replace invariant test (contract lock)

Pin the exact guarantee the whole feature relies on: append duplicates, but `remove_by_dataset` + re-insert refreshes a layer without duplication, and distinct layers coexist. These core functions already exist; this is a characterization/contract test composing them the new way.

**Files:**
- Test: `core/graph-engine/src/graph.rs` (existing `#[cfg(test)] mod` at the bottom)

- [ ] **Step 1: Write the test**

Add to the test module in `core/graph-engine/src/graph.rs`. It uses the in-scope test imports (`Entity`, `EntityType`, `RelationType`, `Relation`) the sibling tests already use (e.g. `empty_other_rel_type_roundtrips_without_key` near line 3534).

```rust
    #[test]
    fn snapshot_replace_by_dataset_is_idempotent() {
        let mut g = GraphHunter::new();
        let edge_l = || (
            Entity::new("a", EntityType::IP),
            Relation::new("a", "b", RelationType::Connect, 1),
            Entity::new("b", EntityType::IP),
        );
        let edge_m = || (
            Entity::new("c", EntityType::IP),
            Relation::new("c", "d", RelationType::Connect, 1),
            Entity::new("d", EntityType::IP),
        );

        // First ingest into layer "L".
        g.insert_triples(vec![edge_l()], Some("L")).unwrap();
        assert_eq!(g.relation_count(), 1);

        // Append into the same layer WITHOUT replacing -> duplicates (today's behavior).
        g.insert_triples(vec![edge_l()], Some("L")).unwrap();
        assert_eq!(g.relation_count(), 2, "append without remove duplicates");

        // Snapshot replace: remove the layer, then re-insert -> back to 1 (refreshed).
        g.remove_entities_and_relations_by_dataset("L").unwrap();
        g.insert_triples(vec![edge_l()], Some("L")).unwrap();
        assert_eq!(g.relation_count(), 1, "remove + insert refreshes the layer, no duplication");

        // A distinct layer "M" coexists; refreshing "L" must leave "M" intact.
        g.insert_triples(vec![edge_m()], Some("M")).unwrap();
        assert_eq!(g.relation_count(), 2);
        g.remove_entities_and_relations_by_dataset("L").unwrap();
        g.insert_triples(vec![edge_l()], Some("L")).unwrap();
        assert_eq!(g.relation_count(), 2, "M intact while L is refreshed");
    }
```

- [ ] **Step 2: Run it**

Run: `cargo test --manifest-path core/graph-engine/Cargo.toml --lib snapshot_replace_by_dataset 2>&1 | tail -15`
Expected: PASS. (If `relation_count` or `RelationType::Connect` differs in the real code, adapt — read the sibling test at ~line 3534 for the exact in-scope names and use `g.streaming_edge_count()` if `relation_count` isn't available on `GraphHunter`.)

- [ ] **Step 3: Commit**

```bash
git add core/graph-engine/src/graph.rs
git commit -m "test(core): snapshot-replace-by-dataset idempotency invariant

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: `run_kql` — `dataset` field + replace wiring

**Files:**
- Modify: `platform/api/src/dto/v1/sentinel.rs` (`RunKqlRequest`)
- Modify: `platform/api/src/operations/sentinel.rs` (`run_kql` ingest path, ~lines 396, 414-424)

- [ ] **Step 1: Add the DTO field**

In `platform/api/src/dto/v1/sentinel.rs`, add to `RunKqlRequest` (after the `max_rows` field from the enrichment feature):

```rust
    /// Optional layer name. When set (and `ingest != false`), this query's
    /// results REPLACE the existing layer with this name (snapshot) instead
    /// of appending — re-running the same query refreshes it rather than
    /// duplicating. Omit for a one-off append (random dataset id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset: Option<String>,
```

- [ ] **Step 2: Wire the stable id + replace into `run_kql`**

In `platform/api/src/operations/sentinel.rs`, find the ingest path (after the inspect early-return). Replace the random `dataset_id` assignment (currently `let dataset_id = Uuid::new_v4().to_string();`, ~line 396) with:

```rust
        // Stable layer name when provided (enables snapshot replace);
        // otherwise a random id (one-off append, legacy behavior).
        let dataset_id = match &req.dataset {
            Some(name) => name.clone(),
            None => Uuid::new_v4().to_string(),
        };
```

Then in the parse+ingest block (currently `let (new_entities, new_relations) = { let mut graph = session.graph.write()...; let parser = ...; let triples = parser.parse(&res.data); let (e, r) = graph.insert_triples(...)?; run_full_scoring(&mut graph); (e, r) };`, ~lines 414-427), add a remove BEFORE the parse, inside the same write-lock block:

```rust
        // Parse + ingest + score.
        let (new_entities, new_relations) = {
            let mut graph = session
                .graph
                .write()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            // Snapshot replace: refresh a named layer instead of appending.
            if req.dataset.is_some() {
                graph
                    .remove_entities_and_relations_by_dataset(&dataset_id)
                    .map_err(|e| ApiError::Internal(e.to_string()))?;
            }
            let parser = make_parser_for_format("sentinel").map_err(ApiError::InvalidInput)?;
            let triples = parser.parse(&res.data);
            let (e, r) = graph
                .insert_triples(triples, Some(dataset_id.as_str()))
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            run_full_scoring(&mut graph);
            (e, r)
        };
```

The `DatasetInfo` registration above already uses `dataset_id` (now the stable name when provided) — no change needed there.

- [ ] **Step 3: Build**

Run: `cargo build --manifest-path platform/api/Cargo.toml 2>&1 | tail -5`
Expected: builds clean. (No new unit test here — `run_kql` calls `run_sentinel_query` directly and is not transport-mockable; the replace mechanism is covered by Task 1's invariant test. Confirm `run_hunting_template`'s `RunKqlRequest` literal still compiles — add `dataset: None,` to it if the compiler flags a missing field.)

- [ ] **Step 4: Run the api lib suite (no regressions)**

Run: `cargo test --manifest-path platform/api/Cargo.toml --lib 2>&1 | tail -3`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add platform/api/src/dto/v1/sentinel.rs platform/api/src/operations/sentinel.rs
git commit -m "feat(api): run_kql dataset layer with snapshot replace

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: `node_enrich` — `dataset` field + replace wiring

**Files:**
- Modify: `platform/api/src/dto/v1/sentinel.rs` (`NodeEnrichRequest`)
- Modify: `platform/api/src/operations/sentinel.rs` (`node_enrich`, ~lines 797-818)

- [ ] **Step 1: Add the DTO field**

In `platform/api/src/dto/v1/sentinel.rs`, add to `NodeEnrichRequest` (after `max_rows`):

```rust
    /// Optional layer name. When set, this enrichment REPLACES the existing
    /// layer with this name (snapshot) instead of appending — re-enriching
    /// the same node into the same layer refreshes it rather than
    /// duplicating. Omit to append under the default enrich tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset: Option<String>,
```

- [ ] **Step 2: Wire the tag + replace into `node_enrich`**

In `node_enrich` (`operations/sentinel.rs`), the filter is built (~line 799) then `match resolve_azure_creds()` calls `hydrate_node_filtered_with(..., "Sentinel Enrich (node)", Some(&filter))`. Between the filter and the match, add the layer tag + replace, and pass the tag into the hydrate call. The `session` handle is already in scope (resolved at the top of `node_enrich` for the entity-type lookup).

Replace the dataset_tag literal and add the remove:

```rust
        // Snapshot replace: a named layer is refreshed (remove then insert);
        // omitted -> the default append tag (legacy behavior).
        let dataset_tag = req.dataset.as_deref().unwrap_or("Sentinel Enrich (node)");
        if req.dataset.is_some() {
            let mut graph = session
                .graph
                .write()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            graph
                .remove_entities_and_relations_by_dataset(dataset_tag)
                .map_err(|e| ApiError::Internal(e.to_string()))?;
        }

        match resolve_azure_creds() {
            Some((ws, auth)) => {
                let transport = HttpSentinelTransport::new();
                let cache = SentinelTokenCache::new();
                self.hydrate_node_filtered_with(
                    &transport,
                    &cache,
                    &req.node_id,
                    &entity_type,
                    &time_filter,
                    &ws,
                    &auth,
                    dataset_tag,
                    Some(&filter),
                )
                .await
            }
            None => Ok(HydrationOutcome {
                skipped: true,
                reason: Some(
                    "Azure credentials not configured (set AZURE_* or connect Sentinel)".into(),
                ),
                new_entities: 0,
                new_relations: 0,
                tables_hit: 0,
                tables_attempted: 0,
            }),
        }
```

(Note: the `if req.dataset.is_some()` block acquires and drops the graph write lock before the `.await` — do NOT hold the guard across the await. The block above scopes the guard correctly: it ends before `match resolve_azure_creds()`.)

- [ ] **Step 3: Build + run api lib suite**

Run: `cargo test --manifest-path platform/api/Cargo.toml --lib 2>&1 | tail -3`
Expected: all pass (existing `node_enrich_errors_*` tests unaffected — they pass `dataset: None`... confirm: those test literals construct `NodeEnrichRequest { ... }` without `dataset`. Add `dataset: None,` to each of the two test literals so they compile).

- [ ] **Step 4: Commit**

```bash
git add platform/api/src/dto/v1/sentinel.rs platform/api/src/operations/sentinel.rs
git commit -m "feat(api): node_enrich dataset layer with snapshot replace

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: HTTP — forward `dataset` on `/kql` and `/node/enrich`

**Files:**
- Modify: `apps/tauri/src-tauri/src/http/siem.rs` (`RunKqlBody`, `handler_run_kql`, `NodeEnrichBody`, `handler_node_enrich`)

- [ ] **Step 1: Add `dataset` to both bodies**

In `apps/tauri/src-tauri/src/http/siem.rs`, add to `RunKqlBody` (after `lookback`):

```rust
    #[serde(default)]
    pub dataset: Option<String>,
```

And to `NodeEnrichBody` (after `max_rows`):

```rust
    #[serde(default)]
    pub dataset: Option<String>,
```

- [ ] **Step 2: Forward in both handlers**

In `handler_run_kql`, add to the `RunKqlRequest { ... }` construction:

```rust
            dataset: body.dataset,
```

In `handler_node_enrich`, add to the `NodeEnrichRequest { ... }` construction:

```rust
            dataset: body.dataset,
```

- [ ] **Step 3: Compile-check the Tauri app**

If the fresh worktree lacks `apps/tauri/dist`, copy it first:
```bash
[ -d apps/tauri/dist ] || cp -r C:/Users/lsotomayor/GraphHunter/apps/tauri/dist apps/tauri/
```
Run: `cargo check --manifest-path apps/tauri/src-tauri/Cargo.toml 2>&1 | tail -5`
Expected: exit 0.

- [ ] **Step 4: Commit**

```bash
git add apps/tauri/src-tauri/src/http/siem.rs
git commit -m "feat(http): forward dataset layer on /kql and /node/enrich

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: MCP — `dataset` param on `node_enrich` and `sentinel_query` + rebuild

**Files:**
- Modify: `platform/mcp/src/tools/node/enrich.ts`
- Modify: `platform/mcp/src/tools/sentinel/query.ts`

- [ ] **Step 1: Add `dataset` to `node/enrich.ts`**

Add to the `input` zod object (after `max_rows`):

```ts
  dataset: z
    .string()
    .max(200)
    .optional()
    .describe("Name this enrichment as a refreshable layer — re-enriching with the same dataset name REPLACES it instead of duplicating (snapshot). Omit for a one-off append. Use a stable per-scenario/hypothesis name."),
```

And in `execute`, add it to the forwarded body (it already conditionally appends optionals):

```ts
    if (dataset) body.dataset = dataset;
```

Make sure `dataset` is destructured in the `execute(ctx, { node_id, tables, lookback, max_rows, dataset })` signature.

- [ ] **Step 2: Add `dataset` to `sentinel/query.ts`**

Add to the `input` zod object (after `max_rows`):

```ts
  dataset: z
    .string()
    .max(200)
    .optional()
    .describe("Only with ingest=true: name this ingest as a refreshable layer — re-running with the same dataset name REPLACES it instead of duplicating (snapshot). Omit for a one-off append."),
```

And in `execute`, add to the body and destructure it:

```ts
    if (dataset) body.dataset = dataset;
```
(Update the destructure to `execute(ctx, { query, lookback, ingest, max_rows, dataset })`.)

- [ ] **Step 3: Typecheck + build + verify catalog unchanged (43)**

```bash
cd platform/mcp && npx tsc --noEmit
```
Expected: exit 0. Then:
```bash
cd platform/mcp && npm run build && grep -rhoE 'name:\s*"[a-z_]+"' dist/src/tools/ | sort -u | wc -l
```
Expected: `43` (no new tools — just new params on existing ones).

- [ ] **Step 4: Commit**

```bash
git add platform/mcp/src/tools/node/enrich.ts platform/mcp/src/tools/sentinel/query.ts
git commit -m "feat(mcp): dataset layer param on node_enrich + sentinel_query

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Final verification gate (after all tasks)

```bash
cargo test --manifest-path core/graph-engine/Cargo.toml --lib snapshot_replace_by_dataset 2>&1 | tail -3
cargo test --manifest-path platform/api/Cargo.toml --lib 2>&1 | tail -3
cargo check --manifest-path apps/tauri/src-tauri/Cargo.toml 2>&1 | tail -3
( cd platform/mcp && npx tsc --noEmit && npm run build )
```
Expected: core invariant green, api lib green, Tauri check exit 0, tsc/build exit 0.

**Operator reminder:** restart the MCP client after merge so the rebuilt `dist/` exposes the new `dataset` params.

---

## Self-Review notes

- **Spec coverage:** §4.1 DTOs → Tasks 2+3 (each adds its field); §4.2 run_kql replace → Task 2; §4.3 node_enrich replace → Task 3; §4.4 HTTP → Task 4; §4.5 MCP → Task 5; §7 testing → Task 1 (invariant) covers run_kql+node_enrich mechanism (neither op is unit-testable: run_kql hits the network, node_enrich needs AZURE_* creds), plus backward-compat preserved by `dataset: None` defaults and verified by the existing api lib suite.
- **Placeholder scan:** none — every step has concrete code/commands.
- **Type consistency:** `dataset: Option<String>` identical across `RunKqlRequest`/`NodeEnrichRequest`/`RunKqlBody`/`NodeEnrichBody`; MCP `dataset?: string` → body `dataset`. `remove_entities_and_relations_by_dataset(&str)` used consistently. `dataset_tag` (node_enrich) and `dataset_id` (run_kql) are the stable layer keys passed to `insert_triples`.
- **Known limitation carried:** cross-source entity ownership on remove (spec §6) — explicitly out of scope; no task attempts it.
- **Lock discipline:** the node_enrich remove block scopes the graph write guard so it drops before the `.await` (Task 3 Step 2 note).
