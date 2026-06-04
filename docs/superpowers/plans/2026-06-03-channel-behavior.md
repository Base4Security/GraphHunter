# Channel Behavior (SP-C) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use `- [ ]` for tracking.

**Goal:** A read-only `channel_behavior` projection that, per `(source, dest, rel_type)` channel, computes temporal behavior — beaconing (inter-arrival CV → beacon_score), reset bursts (max in window), volume spikes (max bytes/count in window) — ranked + filterable, exposed as op + MCP tool + HTTP route.

**Architecture:** Mirrors SP-B's `heavy_edges`: a `for_each_edge` scan collecting per-channel `(timestamp, bytes, is_reset)` tuples (reusing the `_rel_type` rel-type recovery from SP-B), then per-channel post-processing for the temporal metrics. Read-only (`&self`); no storage changes. Then DTO + API op + MCP tool + HTTP route wiring.

**Tech Stack:** Rust (`graph_hunter_core`, `graph_hunter_api`, `graph-hunter-app`), TypeScript (MCP).

## Build/test commands (no cargo workspace)
- Core: `cargo test --manifest-path core/graph-engine/Cargo.toml --lib -- --skip benchmark_ <filter>`
- API: `cargo check --manifest-path platform/api/Cargo.toml`
- Tauri: `cargo check --manifest-path apps/tauri/src-tauri/Cargo.toml` (copy `apps/tauri/dist` if the frontendDist macro panics)
- MCP: from `platform/mcp/`, `npm install` (once) then `npx tsc --noEmit`

## Verified facts (from SP-B, now on main)
- `self.streaming.for_each_edge<F: FnMut(StrId, &StreamEdge)>`; `StreamEdge { timestamp:i64, metadata_offset:u64, source_sid:StrId, dest_sid:StrId, rel_type_tag:u8, ... }`.
- `self.meta_store.get(offset) -> HashMap<String,String>`; `self.interner.resolve(StrId) -> &str`.
- `self.resolve_rel_type_name_raw(rel_type_tag: u8, metadata_offset: u64) -> String` exists (added in SP-B) — recovers custom `_rel_type` names; use it for the group rel-type label. (Confirm exact name/signature in graph.rs; SP-B added both `resolve_rel_type_name(&CompactRelation)` and `resolve_rel_type_name_raw(tag, offset)`.)
- `heavy_edges` in `analytics.rs` is the structural template (same scan + grouping shape).
- `StrId` imported in analytics.rs.

---

## Task 1: `channel_behavior` core projection

**Files:**
- Modify: `core/graph-engine/src/analytics.rs` (structs + `channel_behavior`)
- Modify: `core/graph-engine/src/lib.rs` (re-export the new public types)
- Test: `core/graph-engine/src/analytics.rs` (`#[cfg(test)]`)

- [ ] **Step 1: Write the failing tests**
Add to `analytics.rs`:
```rust
#[cfg(test)]
mod channel_behavior_tests {
    use super::*;
    use crate::GraphHunter;
    use crate::types::{EntityType, RelationType};
    use crate::entity::Entity;
    use crate::relation::Relation;
    use std::collections::HashMap;

    fn e(s: &str, d: &str, ts: i64, sentbyte: Option<&str>, action: Option<&str>) -> crate::parser::ParsedTriple {
        let mut md = HashMap::new();
        if let Some(b) = sentbyte { md.insert("sentbyte".into(), b.into()); }
        if let Some(a) = action { md.insert("action".into(), a.into()); }
        let mut rel = Relation::new(s, d, RelationType::Connect, ts);
        rel.metadata = md;
        (Entity::new(s, EntityType::IP), rel, Entity::new(d, EntityType::IP))
    }

    #[test]
    fn regular_channel_scores_as_beacon() {
        let mut g = GraphHunter::new();
        g.insert_triples(vec![
            e("A","B",0,Some("10"),None), e("A","B",60,Some("10"),None),
            e("A","B",120,Some("10"),None), e("A","B",180,Some("10"),None),
        ], None).unwrap();
        let out = g.channel_behavior(&ChannelBehaviorOpts {
            top_n: 10, min_count: None, window_secs: 60, rel_type: None, sort_by: ChannelSortBy::Beacon,
        });
        let ab = out.iter().find(|c| c.source=="A" && c.target=="B").expect("A->B");
        assert_eq!(ab.count, 4);
        assert!((ab.interval_mean_secs - 60.0).abs() < 1e-6);
        assert!(ab.interval_cv < 1e-6, "regular intervals -> cv ~0, got {}", ab.interval_cv);
        assert!(ab.beacon_score > 0.99, "regular -> beacon_score ~1, got {}", ab.beacon_score);
    }

    #[test]
    fn irregular_channel_low_beacon() {
        let mut g = GraphHunter::new();
        g.insert_triples(vec![
            e("A","B",0,None,None), e("A","B",5,None,None),
            e("A","B",200,None,None), e("A","B",201,None,None),
        ], None).unwrap();
        let out = g.channel_behavior(&ChannelBehaviorOpts {
            top_n: 10, min_count: None, window_secs: 60, rel_type: None, sort_by: ChannelSortBy::Beacon,
        });
        let ab = out.iter().find(|c| c.source=="A" && c.target=="B").unwrap();
        assert!(ab.interval_cv > 0.5, "irregular -> high cv, got {}", ab.interval_cv);
        assert!(ab.beacon_score < 0.5, "irregular -> low beacon, got {}", ab.beacon_score);
    }

    #[test]
    fn too_few_events_no_beacon() {
        let mut g = GraphHunter::new();
        g.insert_triples(vec![ e("A","B",0,None,None), e("A","B",60,None,None) ], None).unwrap(); // count 2 < 3
        let out = g.channel_behavior(&ChannelBehaviorOpts {
            top_n: 10, min_count: None, window_secs: 60, rel_type: None, sort_by: ChannelSortBy::Beacon,
        });
        let ab = out.iter().find(|c| c.source=="A" && c.target=="B").unwrap();
        assert_eq!(ab.beacon_score, 0.0); // <3 events
    }

    #[test]
    fn reset_burst_and_volume_window() {
        let mut g = GraphHunter::new();
        // 3 resets within window [0,60), 1 close later; bytes spike in first window
        g.insert_triples(vec![
            e("A","B",1,Some("500"),Some("client-rst")),
            e("A","B",2,Some("500"),Some("server-rst")),
            e("A","B",3,Some("500"),Some("client-rst")),
            e("A","B",1000,Some("10"),Some("close")),
        ], None).unwrap();
        let out = g.channel_behavior(&ChannelBehaviorOpts {
            top_n: 10, min_count: None, window_secs: 60, rel_type: None, sort_by: ChannelSortBy::Resets,
        });
        let ab = out.iter().find(|c| c.source=="A" && c.target=="B").unwrap();
        assert_eq!(ab.max_resets_in_window, 3);
        assert_eq!(ab.max_bytes_in_window, 1500); // 3x500 in window 0
        assert_eq!(ab.max_count_in_window, 3);
    }
}
```
Run: `cargo test --manifest-path core/graph-engine/Cargo.toml --lib channel_behavior` → FAIL (types/fn missing).

- [ ] **Step 2: Implement structs + `channel_behavior`**
Add to `analytics.rs` (module level):
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelSortBy { Beacon, Resets, Volume }

#[derive(Debug, Clone)]
pub struct ChannelBehaviorOpts {
    pub top_n: usize,
    pub min_count: Option<usize>,
    pub window_secs: u64,
    pub rel_type: Option<String>,
    pub sort_by: ChannelSortBy,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ChannelBehavior {
    pub source: String,
    pub target: String,
    pub rel_type: String,
    pub count: usize,
    pub first_ts: i64,
    pub last_ts: i64,
    pub interval_mean_secs: f64,
    pub interval_cv: f64,
    pub beacon_score: f64,
    pub max_resets_in_window: usize,
    pub max_bytes_in_window: u64,
    pub max_count_in_window: usize,
}
```
Add to `impl GraphHunter`:
```rust
    /// Read-only per-channel temporal behavior: beaconing (inter-arrival CV),
    /// reset bursts, and volume spikes. Groups by (source, dest, rel_type).
    /// Does not mutate the graph.
    pub fn channel_behavior(&self, opts: &ChannelBehaviorOpts) -> Vec<ChannelBehavior> {
        use std::collections::HashMap;
        // Per channel: collect (timestamp, bytes, is_reset).
        // NOTE: `meta_store.get` allocates a HashMap per edge; acceptable for an
        // on-demand analytical query (cf. heavy_edges). And `for_each_edge` is
        // base-only — tail edges from a post-finalize live graph are excluded
        // (tracked follow-up).
        let window = opts.window_secs.max(1) as i64;
        let mut groups: HashMap<(StrId, StrId, String), Vec<(i64, u64, bool)>> = HashMap::new();
        self.streaming.for_each_edge(|src, ed| {
            let md = self.meta_store.get(ed.metadata_offset);
            let rt = self.resolve_rel_type_name_raw(ed.rel_type_tag, ed.metadata_offset);
            let bytes = md.get("sentbyte").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            let is_reset = matches!(md.get("action").map(|s| s.as_str()), Some("client-rst") | Some("server-rst"));
            groups.entry((src, ed.dest_sid, rt)).or_default().push((ed.timestamp, bytes, is_reset));
        });

        let mut out: Vec<ChannelBehavior> = Vec::new();
        for ((s, d, rt), mut edges) in groups {
            if let Some(m) = opts.min_count { if edges.len() < m { continue; } }
            if let Some(want) = opts.rel_type.as_ref() { if want != &rt { continue; } }
            edges.sort_by_key(|x| x.0);
            let count = edges.len();
            let first_ts = edges.first().map(|x| x.0).unwrap_or(0);
            let last_ts = edges.last().map(|x| x.0).unwrap_or(0);

            // Beaconing: inter-arrival mean + CV.
            let (mut interval_mean_secs, mut interval_cv, mut beacon_score) = (0.0_f64, 0.0_f64, 0.0_f64);
            if count >= 2 {
                let intervals: Vec<f64> = edges.windows(2).map(|w| (w[1].0 - w[0].0) as f64).collect();
                let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
                interval_mean_secs = mean;
                if count >= 3 && mean > 0.0 {
                    let var = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
                    let cv = var.sqrt() / mean;
                    interval_cv = cv;
                    beacon_score = 1.0 - cv.min(1.0);
                }
                // mean == 0 (all same instant) or count < 3 -> beacon_score stays 0.
            }

            // Window buckets: resets / bytes / count maxima.
            let mut buckets: HashMap<i64, (usize, u64, usize)> = HashMap::new();
            for (ts, bytes, is_reset) in &edges {
                let b = buckets.entry(ts / window).or_insert((0, 0, 0));
                if *is_reset { b.0 += 1; }
                b.1 += *bytes;
                b.2 += 1;
            }
            let max_resets_in_window = buckets.values().map(|b| b.0).max().unwrap_or(0);
            let max_bytes_in_window = buckets.values().map(|b| b.1).max().unwrap_or(0);
            let max_count_in_window = buckets.values().map(|b| b.2).max().unwrap_or(0);

            out.push(ChannelBehavior {
                source: self.interner.resolve(s).to_string(),
                target: self.interner.resolve(d).to_string(),
                rel_type: rt,
                count, first_ts, last_ts,
                interval_mean_secs, interval_cv, beacon_score,
                max_resets_in_window, max_bytes_in_window, max_count_in_window,
            });
        }

        out.sort_by(|x, y| {
            let (a, b) = match opts.sort_by {
                ChannelSortBy::Beacon => (y.beacon_score.partial_cmp(&x.beacon_score), None::<std::cmp::Ordering>),
                ChannelSortBy::Resets => (Some(y.max_resets_in_window.cmp(&x.max_resets_in_window)), None),
                ChannelSortBy::Volume => (Some(y.max_bytes_in_window.cmp(&x.max_bytes_in_window)), None),
            };
            let _ = b;
            a.unwrap_or(std::cmp::Ordering::Equal).then(y.count.cmp(&x.count))
        });
        out.truncate(opts.top_n);
        out
    }
```
Notes for the implementer:
- `resolve_rel_type_name_raw` is the SP-B helper taking `(tag, offset)`. If only `resolve_rel_type_name(&CompactRelation)` exists, add a `_raw` variant or inline the recovery (`if tag==254 { meta.get("_rel_type") } else { from_u8(tag) Display }`) — the `_rel_type` recovery MUST be applied so custom rel-types group/label correctly.
- The `sort_by` match for `Beacon` uses `partial_cmp` (f64); the `let (a,b)` shape above is awkward — simplify to a clean `match` that returns an `Ordering` per arm, with `.then(y.count.cmp(&x.count))` as tiebreak. Write whatever is cleanest and compiles; the REQUIRED behavior: Beacon→beacon_score desc, Resets→max_resets desc, Volume→max_bytes desc, count desc tiebreak.
- If the closure borrow-checks against `self` (it didn't for heavy_edges since `streaming` is `Arc`), keep the same form heavy_edges used.

- [ ] **Step 3: Re-export**
In `core/graph-engine/src/lib.rs`, add `ChannelBehavior`, `ChannelBehaviorOpts`, `ChannelSortBy` to the analytics re-export block (next to `HeavyEdge`/`HeavyEdgesOpts`).

- [ ] **Step 4: Run + regression**
`cargo test --manifest-path core/graph-engine/Cargo.toml --lib channel_behavior` → 4 tests PASS.
`cargo test --manifest-path core/graph-engine/Cargo.toml --lib -- --skip benchmark_` → no regressions.

- [ ] **Step 5: Commit**
```bash
git add core/graph-engine/src/analytics.rs core/graph-engine/src/lib.rs
git commit -m "feat(core): channel_behavior temporal projection (beaconing/bursts/spikes)"
```

---

## Task 2: Exposure — DTO + API op + MCP tool + HTTP route

**Files:**
- Modify: `platform/api/src/dto/v1/graph_ops.rs` (`ChannelBehaviorRequest`)
- Modify: `platform/api/src/operations/graph_ops.rs` (`graph_channel_behavior` op)
- Modify: `apps/tauri/src-tauri/src/http/graph.rs` + `http/mod.rs` (route)
- Create: `platform/mcp/src/tools/graph/channel_behavior.ts` ; Modify `platform/mcp/src/tools/graph/index.ts`

- [ ] **Step 1: DTO**
In `platform/api/src/dto/v1/graph_ops.rs` (mirror `HeavyEdgesRequest` from SP-B):
```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChannelBehaviorRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_n: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rel_type: Option<String>,
    /// "beacon" (default) | "resets" | "volume"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort_by: Option<String>,
}
```

- [ ] **Step 2: API op**
In `platform/api/src/operations/graph_ops.rs` (mirror `graph_heavy_edges` — uses `with_graph_read`):
```rust
    pub fn graph_channel_behavior(
        &self,
        req: ChannelBehaviorRequest,
    ) -> ApiResult<Vec<graph_hunter_core::analytics::ChannelBehavior>> {
        use graph_hunter_core::analytics::{ChannelBehaviorOpts, ChannelSortBy};
        let sort_by = match req.sort_by.as_deref() {
            Some("resets") => ChannelSortBy::Resets,
            Some("volume") => ChannelSortBy::Volume,
            _ => ChannelSortBy::Beacon,
        };
        let opts = ChannelBehaviorOpts {
            top_n: req.top_n.unwrap_or(50),
            min_count: req.min_count.or(Some(4)),
            window_secs: req.window_secs.unwrap_or(60),
            rel_type: req.rel_type,
            sort_by,
        };
        self.with_graph_read(req.session.as_ref(), |graph| Ok(graph.channel_behavior(&opts)))
    }
```
Import `ChannelBehaviorRequest` (match how `graph_heavy_edges` imports `HeavyEdgesRequest`). Note the `min_count` default of 4 (spec §3) applied here when the caller omits it.

- [ ] **Step 3: HTTP route**
In `apps/tauri/src-tauri/src/http/graph.rs` (mirror `handler_heavy_edges`):
```rust
#[derive(serde::Deserialize)]
pub(super) struct ChannelBehaviorQuery {
    #[serde(default)] pub top_n: Option<usize>,
    #[serde(default)] pub min_count: Option<usize>,
    #[serde(default)] pub window_secs: Option<u64>,
    #[serde(default)] pub rel_type: Option<String>,
    #[serde(default)] pub sort_by: Option<String>,
}
pub(super) async fn handler_channel_behavior(
    State(api): State<Arc<GraphHunterApi>>,
    Query(q): Query<ChannelBehaviorQuery>,
) -> Response {
    api_response(api.graph_channel_behavior(graph_hunter_api::dto::graph_ops::ChannelBehaviorRequest {
        session: None, top_n: q.top_n, min_count: q.min_count, window_secs: q.window_secs,
        rel_type: q.rel_type, sort_by: q.sort_by,
    }))
}
```
Register in `http/mod.rs` near `/heavy_edges`: `.route("/channel_behavior", get(graph::handler_channel_behavior))`.

- [ ] **Step 4: MCP tool**
Create `platform/mcp/src/tools/graph/channel_behavior.ts` (mirror `heavy_edges.ts`):
```ts
import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  top_n: z.number().int().min(1).max(500).optional().describe("Max channels (default 50)."),
  min_count: z.number().int().min(1).optional().describe("Only channels with at least this many edges (default 4)."),
  window_secs: z.number().int().min(1).optional().describe("Bucket size for reset/volume windows (default 60)."),
  rel_type: z.string().optional().describe("Filter to one relation type (e.g. Connect, SNAT)."),
  sort_by: z.enum(["beacon", "resets", "volume"]).optional().describe("Ranking signal (default beacon)."),
});

export const graphChannelBehavior = defineTool({
  name: "graph_channel_behavior",
  description:
    "Per-channel temporal behavior: detect beaconing (regular inter-arrival intervals -> beacon_score), reset bursts, and volume spikes for each (source -> target : rel_type). Use to find C2-like periodic channels, error storms, or exfil bursts that pure volume (graph_heavy_edges) misses.",
  category: "graph",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { top_n, min_count, window_secs, rel_type, sort_by }) {
    const params: Record<string, string> = {};
    if (top_n != null) params.top_n = String(top_n);
    if (min_count != null) params.min_count = String(min_count);
    if (window_secs != null) params.window_secs = String(window_secs);
    if (rel_type) params.rel_type = rel_type;
    if (sort_by) params.sort_by = sort_by;
    return ctx.api.get("/channel_behavior", params, HEAVY);
  },
});
```
Register in `platform/mcp/src/tools/graph/index.ts`: import `graphChannelBehavior` + add to `graphTools`.

- [ ] **Step 5: Verify + commit**
`cargo check --manifest-path platform/api/Cargo.toml` (clean) ; `cargo check --manifest-path apps/tauri/src-tauri/Cargo.toml` (clean) ; from `platform/mcp/`: `npx tsc --noEmit` (clean).
```bash
git add platform/api/src/dto/v1/graph_ops.rs platform/api/src/operations/graph_ops.rs apps/tauri/src-tauri/src/http/graph.rs apps/tauri/src-tauri/src/http/mod.rs platform/mcp/src/tools/graph/channel_behavior.ts platform/mcp/src/tools/graph/index.ts
git commit -m "feat(api,mcp,tauri): expose graph_channel_behavior"
```

---

## Task 3: Verification gate
**Files:** none.
- [ ] **Step 1:** `cargo test --manifest-path core/graph-engine/Cargo.toml --lib -- --skip benchmark_` (green incl. 4 channel_behavior tests).
- [ ] **Step 2:** `cargo test --manifest-path platform/api/Cargo.toml --lib` (no regressions) ; `cargo check --manifest-path apps/tauri/src-tauri/Cargo.toml` ; mcp `npx tsc --noEmit`.
- [ ] **Step 3 (operator smoke):** ingest FortiGate FW_VPN; `graph_channel_behavior(sort_by="beacon")` → the Telecarga channel should show LOW beacon_score (irregular 9h bursts, not periodic) — proving the feature distinguishes real migration from C2. `sort_by="resets"` surfaces the highest reset-burst window.

---

## Self-review notes
- **Spec coverage:** §4 struct fields (T1 Step 2); §4.1 computation (intervals/CV/beacon_score with count>=3 & mean>0 guards; fixed buckets) — T1 Step 2 + tests; §4.2 opts incl. defaults (top_n=50/min_count=4/window_secs=60/sort_by=beacon — note min_count default applied in the API op T2 Step 2, core treats min_count as Option) ; §5 components (T1 core, T2 api/mcp/http) ; §6 read-only (&self) + tail NOTE (T1 Step 2 comment) ; §7 tests (T1: regular/irregular/too-few/burst+volume).
- **Type consistency:** `ChannelBehavior`/`ChannelBehaviorOpts`/`ChannelSortBy` identical across T1 (core) ↔ T2 (api maps string→enum); DTO field names ↔ HTTP query ↔ MCP params (top_n/min_count/window_secs/rel_type/sort_by); op name `graph_channel_behavior` == HTTP `/channel_behavior` == MCP tool path.
- **Known soft spots:** `resolve_rel_type_name_raw` exact name (SP-B added it; confirm — else inline recovery); the `sort_by` f64 partial_cmp closure (write a clean match); `min_count` default lives in the API op (core leaves it Option, tests pass min_count: None); `with_graph_read` signature (match `graph_heavy_edges`).
