# Heavy Edges (SP-B) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use `- [ ]` for tracking.

**Goal:** A read-only `heavy_edges` projection that groups stored relations by `(source, dest, rel_type)` with volume metrics (count, bytes, duration, %resets, time span), ranked + filterable, exposed as an op + MCP tool + HTTP route — plus a prerequisite fix that preserves custom (`Other`) rel-type names in the graph (fixing a latent SP-A gap).

**Architecture:** Task 1 preserves `RelationType::Other(name)` by injecting `_rel_type` into edge metadata at insert and recovering it in `materialize_relation` (centralized via a small helper across the 6 insert sites). Task 2 adds `heavy_edges` to the core (a `for_each_edge` scan over `CompactRelation`s, read-only). Task 3 wires the API op + DTO + MCP tool + HTTP route. No storage/schema changes; per-event edges stay intact (SP-C-safe).

**Tech Stack:** Rust (`graph_hunter_core`, `graph_hunter_api`, `graph-hunter-app`), TypeScript (MCP).

## Build/test commands (no cargo workspace)
- Core: `cargo test --manifest-path core/graph-engine/Cargo.toml --lib -- --skip benchmark_ <filter>`
- API: `cargo test --manifest-path platform/api/Cargo.toml --lib <filter>` ; `cargo check --manifest-path platform/api/Cargo.toml`
- Tauri: `cargo check --manifest-path apps/tauri/src-tauri/Cargo.toml`
- MCP: from `platform/mcp/`, `npm install` (once) then `npx tsc --noEmit`

## Verified facts
- `streaming.for_each_edge<F: FnMut(StrId, &StreamEdge)>` (streaming.rs:985) iterates all edges. `StreamEdge { timestamp:i64, metadata_offset:u64, source_sid:StrId, dest_sid:StrId, ingested_at_delta:u32, dataset_tag:u16, rel_type_tag:u8 }`.
- `graph.interner.resolve(sid: StrId) -> &str` (interner.rs:75). `graph.meta_store.get(offset: u64) -> HashMap<String,String>` (graph.rs:116/603).
- `RelationType::Other(_) -> to_u8()==254`; `from_u8(254) -> Other(String::new())` (custom name lost) — platform/dsl/src/types.rs:122/140. `Display` for `Other(s)` writes `s`.
- 6 insert sites build a CompactRelation with `meta_store.append(&...metadata)` immediately followed by `rel_type_tag: <rel>.to_u8()`: graph.rs lines ~449, ~2584, ~2950, ~3079, ~3168, ~3388. Each has the rel-type value in scope at that point.
- `materialize_relation` (graph.rs:597) builds `Relation` from a `CompactRelation` using `compact.rel_type()` + `meta_store.get(offset)`.
- `RelationType` is in scope in graph.rs (used at lines 182/820). `HashMap` is already imported.

---

## Task 1: Preserve `Other(_)` rel-type names (§4.0 prerequisite)

**Files:**
- Modify: `core/graph-engine/src/graph.rs` (new helper + 6 insert sites + `materialize_relation`)
- Test: `core/graph-engine/src/graph.rs` (`#[cfg(test)]`)

- [ ] **Step 1: Write the failing test**
Add to a test module in `graph.rs` (use the crate's existing graph-test pattern — `GraphHunter::new()` or the local test constructor; grep `fn new_test_graph`/`GraphHunter::new` in this file's tests):
```rust
#[test]
fn other_rel_type_name_survives_roundtrip() {
    use crate::types::{EntityType, RelationType};
    use crate::entity::Entity;
    use crate::relation::Relation;
    let mut g = GraphHunter::new();
    let triple = (
        Entity::new("a", EntityType::IP),
        Relation::new("a", "b", RelationType::Other("SNAT".to_string()), 100),
        Entity::new("b", EntityType::IP),
    );
    g.insert_triples(vec![triple], None).unwrap();
    // Recover via materialize_relation over the stored edge.
    let rels = g.get_relations("a");
    let snat = rels.iter().find(|r| matches!(&r.rel_type, RelationType::Other(n) if n == "SNAT"))
        .expect("Other(\"SNAT\") rel-type must survive ingest");
    // The reserved key must not leak into the public metadata.
    assert!(!snat.metadata.contains_key("_rel_type"), "_rel_type must be stripped from returned metadata");
}

#[test]
fn builtin_rel_type_unaffected() {
    use crate::types::{EntityType, RelationType};
    use crate::entity::Entity;
    use crate::relation::Relation;
    let mut g = GraphHunter::new();
    g.insert_triples(vec![(
        Entity::new("a", EntityType::IP),
        Relation::new("a", "b", RelationType::Connect, 100),
        Entity::new("b", EntityType::IP),
    )], None).unwrap();
    let rels = g.get_relations("a");
    assert!(rels.iter().any(|r| r.rel_type == RelationType::Connect));
    assert!(rels.iter().all(|r| !r.metadata.contains_key("_rel_type")), "builtin types inject no _rel_type");
}
```
(`get_relations(source_id)` exists at graph.rs:621 and returns `Vec<Relation>` via `materialize_relation`. If its name differs, use the real accessor that materializes a source's edges.)
Run: `cargo test --manifest-path core/graph-engine/Cargo.toml --lib other_rel_type_name_survives_roundtrip builtin_rel_type_unaffected` → FAIL (name lost / not stripped).

- [ ] **Step 2: Add the centralizing helper**
In `impl GraphHunter` (graph.rs), add:
```rust
    /// Append edge metadata to the meta_store, injecting the reserved
    /// `_rel_type` key when the relation type is a custom `Other(name)`
    /// (whose name the 1-byte `rel_type_tag` cannot preserve). Built-in
    /// types (Connect, Auth, …) inject nothing — their tag identifies them.
    fn append_edge_metadata(
        &mut self,
        rel_type: &crate::types::RelationType,
        metadata: &std::collections::HashMap<String, String>,
    ) -> u64 {
        if let crate::types::RelationType::Other(name) = rel_type {
            if !name.is_empty() {
                let mut m = metadata.clone();
                m.insert("_rel_type".to_string(), name.clone());
                return self.meta_store.append(&m);
            }
        }
        self.meta_store.append(metadata)
    }
```

- [ ] **Step 3: Route all 6 insert sites through the helper**
At each of the 6 sites (graph.rs ~449, ~2584, ~2950, ~3079, ~3168, ~3388), replace:
```rust
let meta_offset = self.meta_store.append(&<METADATA>);
```
with:
```rust
let meta_offset = self.append_edge_metadata(&<RELTYPE>, &<METADATA>);
```
where `<METADATA>`/`<RELTYPE>` are the local names at that site (e.g. `&rel.metadata`/`&rel.rel_type`; the raw-events site at ~3168 uses `&rel_metadata`/`&rel_type`). Use the compiler to confirm each rel-type binding name. Do NOT change the `rel_type_tag: <RELTYPE>.to_u8()` lines.

- [ ] **Step 4: Recover + strip in `materialize_relation`**
In `materialize_relation` (graph.rs:597), change the body to recover the custom name and strip the reserved key:
```rust
    pub fn materialize_relation(&self, compact: &CompactRelation) -> Relation {
        let mut metadata = self.meta_store.get(compact.metadata_offset);
        let rel_type = match metadata.remove("_rel_type") {
            Some(name) => crate::types::RelationType::Other(name),
            None => compact.rel_type(),
        };
        Relation {
            source_id: self.interner.resolve(compact.source_sid).to_string(),
            dest_id: self.interner.resolve(compact.dest_sid).to_string(),
            rel_type,
            timestamp: compact.timestamp,
            metadata,
            dataset_id: self.resolve_dataset_tag(compact.dataset_tag),
        }
    }
```

- [ ] **Step 5: Run + regression**
`cargo test --manifest-path core/graph-engine/Cargo.toml --lib other_rel_type_name_survives_roundtrip builtin_rel_type_unaffected` → PASS.
`cargo test --manifest-path core/graph-engine/Cargo.toml --lib -- --skip benchmark_` → no regressions (the `_rel_type` strip in materialize keeps public metadata clean, so existing metadata assertions hold).

- [ ] **Step 6: Commit**
```bash
git add core/graph-engine/src/graph.rs
git commit -m "fix(core): preserve Other rel-type names via _rel_type metadata"
```

---

## Task 2: `heavy_edges` core projection

**Files:**
- Modify: `core/graph-engine/src/analytics.rs` (structs + `heavy_edges`)
- Test: `core/graph-engine/src/analytics.rs` (`#[cfg(test)]`)

- [ ] **Step 1: Write the failing test**
Add to `analytics.rs` tests:
```rust
#[cfg(test)]
mod heavy_edges_tests {
    use super::*;
    use crate::{GraphHunter};
    use crate::types::{EntityType, RelationType};
    use crate::entity::Entity;
    use crate::relation::Relation;
    use std::collections::HashMap;

    fn edge(s: &str, d: &str, rt: RelationType, ts: i64, sentbyte: Option<&str>, action: Option<&str>) -> crate::parser::ParsedTriple {
        let mut md = HashMap::new();
        if let Some(b) = sentbyte { md.insert("sentbyte".into(), b.into()); }
        if let Some(a) = action { md.insert("action".into(), a.into()); }
        let mut rel = Relation::new(s, d, rt, ts);
        rel.metadata = md;
        (Entity::new(s, EntityType::IP), rel, Entity::new(d, EntityType::IP))
    }

    #[test]
    fn heavy_edges_groups_and_ranks() {
        let mut g = GraphHunter::new();
        // A->B Connect x4 (one is client-rst), with bytes; A->C Connect x1
        g.insert_triples(vec![
            edge("A","B",RelationType::Connect,10,Some("100"),Some("close")),
            edge("A","B",RelationType::Connect,20,Some("200"),Some("close")),
            edge("A","B",RelationType::Connect,30,Some("300"),Some("close")),
            edge("A","B",RelationType::Connect,40,Some("400"),Some("client-rst")),
            edge("A","C",RelationType::Connect,50,Some("999"),Some("close")),
        ], None).unwrap();

        let out = g.heavy_edges(&HeavyEdgesOpts { top_n: 10, min_count: None, rel_type: None });
        let ab = out.iter().find(|e| e.source=="A" && e.target=="B").expect("A->B group");
        assert_eq!(ab.count, 4);
        assert_eq!(ab.total_bytes, 1000);
        assert_eq!(ab.rel_type, "Connect");
        assert!((ab.reset_pct - 25.0).abs() < 1e-9);
        assert_eq!(ab.first_ts, 10);
        assert_eq!(ab.last_ts, 40);
        // ranking: A->B (count 4) before A->C (count 1)
        assert_eq!(out[0].source, "A");
        assert_eq!(out[0].target, "B");

        // min_count filters out A->C
        let filtered = g.heavy_edges(&HeavyEdgesOpts { top_n: 10, min_count: Some(2), rel_type: None });
        assert!(filtered.iter().all(|e| e.count >= 2));
        assert!(filtered.iter().all(|e| !(e.source=="A" && e.target=="C")));
    }

    #[test]
    fn heavy_edges_custom_rel_type_labeled() {
        let mut g = GraphHunter::new();
        g.insert_triples(vec![ edge("X","Y",RelationType::Other("SNAT".to_string()),1,None,None) ], None).unwrap();
        let out = g.heavy_edges(&HeavyEdgesOpts { top_n: 10, min_count: None, rel_type: Some("SNAT".to_string()) });
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rel_type, "SNAT");
        assert_eq!(out[0].count, 1);
        assert_eq!(out[0].total_bytes, 0);
    }
}
```
Run: `cargo test --manifest-path core/graph-engine/Cargo.toml --lib heavy_edges` → FAIL (types/fn missing).

- [ ] **Step 2: Implement structs + `heavy_edges`**
In `analytics.rs`, add the structs:
```rust
#[derive(Debug, Clone, serde::Serialize)]
pub struct HeavyEdge {
    pub source: String,
    pub target: String,
    pub rel_type: String,
    pub count: usize,
    pub total_bytes: u64,
    pub total_duration_secs: u64,
    pub reset_pct: f64,
    pub first_ts: i64,
    pub last_ts: i64,
}

#[derive(Debug, Clone)]
pub struct HeavyEdgesOpts {
    pub top_n: usize,
    pub min_count: Option<usize>,
    pub rel_type: Option<String>,
}
```
Add to `impl GraphHunter` (in analytics.rs — confirm the impl block targets `GraphHunter`):
```rust
    /// Read-only projection: group stored edges by (source, dest, rel_type)
    /// with volume metrics, ranked by count desc (bytes desc tiebreak).
    /// Does not mutate the graph.
    pub fn heavy_edges(&self, opts: &HeavyEdgesOpts) -> Vec<HeavyEdge> {
        use std::collections::HashMap;
        #[derive(Default)]
        struct Agg { count: usize, bytes: u64, dur: u64, resets: usize, first_ts: i64, last_ts: i64 }
        // Bind disjoint field borrows as locals so the closure does not
        // borrow `self` while `self.streaming` is borrowed by for_each_edge.
        let meta_store = &self.meta_store;
        let mut groups: HashMap<(StrId, StrId, String), Agg> = HashMap::new();
        self.streaming.for_each_edge(|src, e| {
            let md = meta_store.get(e.metadata_offset);
            let rt = md.get("_rel_type").cloned()
                .unwrap_or_else(|| format!("{}", crate::types::RelationType::from_u8(e.rel_type_tag)));
            let entry = groups.entry((src, e.dest_sid, rt)).or_insert_with(|| Agg {
                count: 0, bytes: 0, dur: 0, resets: 0, first_ts: i64::MAX, last_ts: i64::MIN,
            });
            entry.count += 1;
            if let Some(b) = md.get("sentbyte").and_then(|s| s.parse::<u64>().ok()) { entry.bytes += b; }
            if let Some(d) = md.get("duration").and_then(|s| s.parse::<u64>().ok()) { entry.dur += d; }
            if matches!(md.get("action").map(|s| s.as_str()), Some("client-rst") | Some("server-rst")) {
                entry.resets += 1;
            }
            if e.timestamp < entry.first_ts { entry.first_ts = e.timestamp; }
            if e.timestamp > entry.last_ts { entry.last_ts = e.timestamp; }
        });

        let mut out: Vec<HeavyEdge> = groups.into_iter()
            .filter(|((_, _, rt), _)| opts.rel_type.as_ref().map_or(true, |want| want == rt))
            .filter(|(_, a)| opts.min_count.map_or(true, |m| a.count >= m))
            .map(|((s, d, rt), a)| HeavyEdge {
                source: self.interner.resolve(s).to_string(),
                target: self.interner.resolve(d).to_string(),
                rel_type: rt,
                count: a.count,
                total_bytes: a.bytes,
                total_duration_secs: a.dur,
                reset_pct: if a.count > 0 { 100.0 * a.resets as f64 / a.count as f64 } else { 0.0 },
                first_ts: a.first_ts,
                last_ts: a.last_ts,
            })
            .collect();
        out.sort_by(|x, y| y.count.cmp(&x.count).then(y.total_bytes.cmp(&x.total_bytes)));
        out.truncate(opts.top_n);
        out
    }
```
Adjust: confirm `StrId` is in scope in analytics.rs (import if needed: `use crate::interner::StrId;` or the real path). Confirm `self.streaming`/`self.interner`/`self.meta_store` field names match. If `for_each_edge`'s closure borrow-checks against `self.interner` too, also bind `let interner = &self.interner;` and resolve inside the closure into the key — but prefer resolving after the scan (as written) to avoid per-edge string alloc; if the borrow checker rejects the post-scan `self.interner.resolve`, it won't (the closure has ended by then).

- [ ] **Step 3: Run + regression**
`cargo test --manifest-path core/graph-engine/Cargo.toml --lib heavy_edges` → 2 tests PASS.
`cargo test --manifest-path core/graph-engine/Cargo.toml --lib -- --skip benchmark_` → no regressions.

- [ ] **Step 4: Commit**
```bash
git add core/graph-engine/src/analytics.rs
git commit -m "feat(core): heavy_edges read-only weighted-edge projection"
```

---

## Task 3: Exposure — API op + DTO + MCP tool + HTTP route

**Files:**
- Modify: `platform/api/src/dto/v1/graph_ops.rs` (`HeavyEdgesRequest`)
- Modify: `platform/api/src/operations/graph_ops.rs` (`graph_heavy_edges` op)
- Modify: `apps/tauri/src-tauri/src/http/graph.rs` + `http/mod.rs` (route)
- Create: `platform/mcp/src/tools/graph/heavy_edges.ts` ; Modify `platform/mcp/src/tools/graph/index.ts`

- [ ] **Step 1: DTO**
In `platform/api/src/dto/v1/graph_ops.rs`:
```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HeavyEdgesRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_n: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rel_type: Option<String>,
}
```

- [ ] **Step 2: API op**
In `platform/api/src/operations/graph_ops.rs`, mirror an existing read op (e.g. `expand_node` uses `self.resolve_session` + `with_graph_read` or `session.graph.read()`):
```rust
    pub fn graph_heavy_edges(
        &self,
        req: HeavyEdgesRequest,
    ) -> ApiResult<Vec<graph_hunter_core::analytics::HeavyEdge>> {
        let session = self.resolve_session(req.session.as_ref())?;
        let graph = session.graph.read()
            .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
        let opts = graph_hunter_core::analytics::HeavyEdgesOpts {
            top_n: req.top_n.unwrap_or(50),
            min_count: req.min_count,
            rel_type: req.rel_type,
        };
        Ok(graph.heavy_edges(&opts))
    }
```
(Match the real read-lock pattern this file uses — copy from `expand_node`. Import `HeavyEdgesRequest` from the dto module.)

- [ ] **Step 3: HTTP route**
In `apps/tauri/src-tauri/src/http/graph.rs`, add a handler mirroring `handler_expand` (GET with query params), and register `GET /heavy_edges` in `http/mod.rs`:
```rust
#[derive(serde::Deserialize)]
pub(super) struct HeavyEdgesQuery {
    #[serde(default)] pub top_n: Option<usize>,
    #[serde(default)] pub min_count: Option<usize>,
    #[serde(default)] pub rel_type: Option<String>,
}
pub(super) async fn handler_heavy_edges(
    State(api): State<Arc<GraphHunterApi>>,
    Query(q): Query<HeavyEdgesQuery>,
) -> Response {
    api_response(api.graph_heavy_edges(graph_hunter_api::dto::graph_ops::HeavyEdgesRequest {
        session: None, top_n: q.top_n, min_count: q.min_count, rel_type: q.rel_type,
    }))
}
```
Route (mod.rs, near `/expand`): `.route("/heavy_edges", get(graph::handler_heavy_edges))`. (Match the file's real `api_response`/error helper and imports.)

- [ ] **Step 4: MCP tool**
Create `platform/mcp/src/tools/graph/heavy_edges.ts` (mirror `tools/graph/summary.ts` / `node/expand.ts` shape):
```ts
import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  top_n: z.number().int().min(1).max(500).optional().describe("Max edge groups to return (default 50)."),
  min_count: z.number().int().min(1).optional().describe("Only groups with at least this many edges."),
  rel_type: z.string().optional().describe("Filter to one relation type (e.g. Connect, SNAT, Exposes)."),
});

export const graphHeavyEdges = defineTool({
  name: "graph_heavy_edges",
  description:
    "List the heaviest edges in the graph: groups of repeated (source -> target : rel_type) ranked by connection count, with total bytes, total duration, %resets, and time span. Use to find high-volume channels, top talkers, or noisy/aborted connections.",
  category: "graph",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { top_n, min_count, rel_type }) {
    const params: Record<string, string> = {};
    if (top_n != null) params.top_n = String(top_n);
    if (min_count != null) params.min_count = String(min_count);
    if (rel_type) params.rel_type = rel_type;
    return ctx.api.get("/heavy_edges", params, HEAVY);
  },
});
```
Register in `platform/mcp/src/tools/graph/index.ts`: import `graphHeavyEdges` and add it to the `graphTools` array.

- [ ] **Step 5: Verify + commit**
`cargo check --manifest-path platform/api/Cargo.toml` (clean) ; `cargo check --manifest-path apps/tauri/src-tauri/Cargo.toml` (clean; needs `apps/tauri/dist` present — copy from a prior build if the frontendDist macro panics) ; from `platform/mcp/`: `npm install` then `npx tsc --noEmit` (clean).
```bash
git add platform/api/src/dto/v1/graph_ops.rs platform/api/src/operations/graph_ops.rs apps/tauri/src-tauri/src/http/graph.rs apps/tauri/src-tauri/src/http/mod.rs platform/mcp/src/tools/graph/heavy_edges.ts platform/mcp/src/tools/graph/index.ts
git commit -m "feat(api,mcp,tauri): expose graph_heavy_edges"
```

---

## Task 4: Verification gate
**Files:** none.
- [ ] **Step 1:** `cargo test --manifest-path core/graph-engine/Cargo.toml --lib -- --skip benchmark_` (green incl. rel-type roundtrip + heavy_edges tests).
- [ ] **Step 2:** `cargo test --manifest-path platform/api/Cargo.toml --lib` (no regressions) ; `cargo check --manifest-path apps/tauri/src-tauri/Cargo.toml` ; mcp `npx tsc --noEmit`.
- [ ] **Step 3 (operator smoke):** ingest the FortiGate FW_VPN export, then `graph_heavy_edges(top_n=10)` → confirm the top group is `172.25.15.1 -> 192.168.53.96 : Connect` with a large count + bytes; a `rel_type="SNAT"` query returns the `172.25.15.1 -> 128.36.11.249` egress edge labeled `SNAT` (proves Task 1 preservation end-to-end).

---

## Self-review notes
- **Spec coverage:** §4.0 preservation (T1); §4.1 HeavyEdge struct (T2 Step 2); §4.2 aggregation incl. `_rel_type` recovery + sentbyte/duration/action (T2); §4.3 opts top_n/min_count/rel_type + sort (T2); §5 components (T1 graph.rs, T2 analytics.rs, T3 api/mcp/http); §6 non-destructive (heavy_edges is `&self`, only reads); §7 tests (T1 roundtrip, T2 grouping/ranking/filter/custom-label, T4 smoke).
- **Type consistency:** `HeavyEdge`/`HeavyEdgesOpts` fields identical across T2 (core) and T3 (api wrapper); `_rel_type` key string identical in T1 inject (graph.rs) and T2 recover (analytics.rs) and T1 strip (materialize); `graph_heavy_edges` op name == MCP tool path `/heavy_edges`.
- **Known soft spots:** the closure borrow (bind `meta_store` local before `for_each_edge`, T2 Step 2 note); `StrId` import in analytics.rs; the 6 insert-site rel-type binding names (T1 Step 3 — compiler-guided); the `api_response`/read-lock helpers' exact names (T3 — match existing `handler_expand`/`expand_node`); `dist` artifact for tauri check.
```
