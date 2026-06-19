# Graph-Visible Sentinel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop GraphHunter from acting as a thin proxy in front of Sentinel KQL by making graph state continuously visible to Claude (via three MCP resources + a per-tool-response footer) and by computing overlap nudges on `sentinel_query` results.

**Architecture:** Two new HTTP endpoints in `platform/api` (`/graph/summary`, `/graph/overlap`) feed a TypeScript `ContextEnricher` middleware that wraps every tool handler in `platform/mcp` and exposes three `graph://` MCP resources. All four payloads carry `schema_version: 1` matching the `BODY_FORMAT_VERSION` discipline. Enrichment is best-effort: backend timeouts produce an `(unavailable)` footer but never break the tool call.

**Tech Stack:** Rust (axum, serde) on the backend; TypeScript with `@modelcontextprotocol/sdk` and `zod` on the MCP server; `node --test` for MCP contract tests; `cargo test` for backend tests.

**Spec:** [docs/superpowers/specs/2026-06-19-graph-visible-sentinel-design.md](../specs/2026-06-19-graph-visible-sentinel-design.md)

**File map (created or modified):**

| File | Status | Responsibility |
|------|--------|----------------|
| `platform/api/src/dto/v1/graph_meta.rs` | NEW | Request/response DTOs for `/graph/summary` and `/graph/overlap` |
| `platform/api/src/dto/v1/mod.rs` | MODIFY | Declare `graph_meta` |
| `platform/api/src/operations/graph_meta.rs` | NEW | Endpoint handlers, ring buffer, cache |
| `platform/api/src/operations/mod.rs` | MODIFY | Declare `graph_meta` |
| `platform/api/src/operations/sentinel.rs` | MODIFY | Push to `recent_pivots` on successful seed |
| `platform/api/src/operations/entity.rs` | MODIFY | Push to `recent_pivots` on successful node_expand |
| `platform/api/src/lib.rs` or routing module | MODIFY | Register two new routes |
| `core/graph-engine/src/ingest/metrics.rs` | MODIFY | Add per-type incremental counters if absent |
| `platform/mcp/src/lib/graph-state-client.ts` | NEW | Typed HTTP client for `/graph/*` |
| `platform/mcp/src/lib/entity-extractor.ts` | NEW | Regex extractors for IP/User/Domain/Hostname |
| `platform/mcp/src/lib/footer-composer.ts` | NEW | Compose the base graph-context footer |
| `platform/mcp/src/lib/nudge-composer.ts` | NEW | Per-tool nudge rules |
| `platform/mcp/src/lib/context-enricher.ts` | NEW | Orchestrator that wires extractor + footer + nudge |
| `platform/mcp/src/resources/graph-summary.ts` | NEW | Resource handler |
| `platform/mcp/src/resources/graph-active-hunts.ts` | NEW | Resource handler |
| `platform/mcp/src/resources/graph-recent-pivots.ts` | NEW | Resource handler |
| `platform/mcp/src/resources/index.ts` | NEW | Resource registry + `registerResources(server, …)` |
| `platform/mcp/src/server.ts` | MODIFY | Wrap tool handler with `ContextEnricher` |
| `platform/mcp/src/index.ts` | MODIFY | Call `registerResources` |
| `platform/mcp/tests/contract/*.test.ts` | NEW | Per-component contract tests |
| `platform/api/tests/graph_meta_integration.rs` | NEW | Backend integration tests |

---

## Phase A — Backend

### Task 1: DTO skeleton + `/graph/summary` returning hardcoded payload

**Files:**
- Create: `platform/api/src/dto/v1/graph_meta.rs`
- Modify: `platform/api/src/dto/v1/mod.rs`
- Create: `platform/api/src/operations/graph_meta.rs`
- Modify: `platform/api/src/operations/mod.rs`
- Modify: wherever routes are registered (likely `platform/api/src/lib.rs` — verify with `git grep -n "/kql" platform/api/src/`)
- Test: `platform/api/tests/graph_meta_integration.rs`

- [ ] **Step 1: Write the failing integration test**

```rust
// platform/api/tests/graph_meta_integration.rs
use graph_hunter_api::test_harness::spawn_test_api;
use serde_json::Value;

#[tokio::test]
async fn graph_summary_returns_schema_v1_shape() {
    let api = spawn_test_api().await;
    let resp: Value = api.get("/graph/summary").await.json().await.unwrap();
    assert_eq!(resp["schema_version"], 1);
    assert!(resp["as_of"].is_string());
    assert!(resp["totals"]["nodes"].is_u64());
    assert!(resp["totals"]["edges"].is_u64());
    assert!(resp["totals"]["by_type"].is_object());
    assert!(resp["sources"].is_array());
    assert!(resp["active_datasets"].is_array());
    assert!(resp["graph_empty"].is_boolean());
}
```

- [ ] **Step 2: Run test — expect FAIL (route does not exist)**

```
cargo test --package graph-hunter-api --test graph_meta_integration -- graph_summary_returns_schema_v1_shape
```

Expected: 404 or routing error.

- [ ] **Step 3: Add the DTO**

```rust
// platform/api/src/dto/v1/graph_meta.rs
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const GRAPH_META_SCHEMA_VERSION: u32 = 1;

#[derive(Serialize, Deserialize, Debug)]
pub struct GraphSummary {
    pub schema_version: u32,
    pub as_of: String,
    pub totals: GraphTotals,
    pub sources: Vec<SourceState>,
    pub active_datasets: Vec<String>,
    pub active_hunts: Vec<ActiveHunt>,
    pub recent_pivots: Vec<RecentPivot>,
    pub graph_empty: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GraphTotals {
    pub nodes: u64,
    pub edges: u64,
    pub by_type: BTreeMap<String, u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SourceState {
    pub name: String,
    pub last_ingest: Option<String>,
    pub rows_lifetime: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ActiveHunt {
    pub cache_key: String,
    pub params_summary: String,
    pub result_size: u64,
    pub computed_at: String,
    pub ttl_seconds_remaining: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RecentPivot {
    pub entity: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub added_at: String,
    pub expanded: bool,
    pub degree: u32,
}
```

Register in `platform/api/src/dto/v1/mod.rs`:
```rust
pub mod graph_meta;
```

- [ ] **Step 4: Add the operation with hardcoded data**

```rust
// platform/api/src/operations/graph_meta.rs
use std::sync::Arc;
use crate::dto::v1::graph_meta::{
    GraphSummary, GraphTotals, GRAPH_META_SCHEMA_VERSION,
};
use crate::{ApiResult, GraphHunterApi};
use std::collections::BTreeMap;

pub async fn get_graph_summary(_api: Arc<GraphHunterApi>) -> ApiResult<GraphSummary> {
    Ok(GraphSummary {
        schema_version: GRAPH_META_SCHEMA_VERSION,
        as_of: chrono::Utc::now().to_rfc3339(),
        totals: GraphTotals { nodes: 0, edges: 0, by_type: BTreeMap::new() },
        sources: vec![],
        active_datasets: vec![],
        active_hunts: vec![],
        recent_pivots: vec![],
        graph_empty: true,
    })
}
```

Register in `platform/api/src/operations/mod.rs`:
```rust
pub mod graph_meta;
```

- [ ] **Step 5: Wire the route**

Find the route registration (likely `platform/api/src/lib.rs`). Add next to existing routes:
```rust
.route("/graph/summary", get(|State(api): State<Arc<GraphHunterApi>>| async move {
    operations::graph_meta::get_graph_summary(api).await.map(Json)
}))
```

- [ ] **Step 6: Run test — expect PASS**

```
cargo test --package graph-hunter-api --test graph_meta_integration -- graph_summary_returns_schema_v1_shape
```

- [ ] **Step 7: Commit**

```
git add platform/api/src/dto/v1/graph_meta.rs platform/api/src/dto/v1/mod.rs \
        platform/api/src/operations/graph_meta.rs platform/api/src/operations/mod.rs \
        platform/api/src/lib.rs \
        platform/api/tests/graph_meta_integration.rs
git commit -m "feat(api): /graph/summary skeleton with schema_version=1 (hardcoded data)"
```

---

### Task 2: Wire `/graph/summary` to real data sources

**Files:**
- Modify: `platform/api/src/operations/graph_meta.rs`
- Test: `platform/api/tests/graph_meta_integration.rs` (add tests)

- [ ] **Step 1: Add a failing test for real sources population**

```rust
#[tokio::test]
async fn graph_summary_lists_active_datasets() {
    let api = spawn_test_api().await;
    api.register_dataset("ator-evtx-snapshot").await;
    let resp: GraphSummary = api.get("/graph/summary").await.json().await.unwrap();
    assert!(resp.active_datasets.contains(&"ator-evtx-snapshot".to_string()));
}

#[tokio::test]
async fn graph_summary_lists_active_hunts_from_cache() {
    let api = spawn_test_api().await;
    api.run_hunt_seed("203.0.113.42").await;
    let resp: GraphSummary = api.get("/graph/summary").await.json().await.unwrap();
    assert!(!resp.active_hunts.is_empty(), "hunt cache should expose entries");
}
```

- [ ] **Step 2: Run test — expect FAIL (still returns empty arrays)**

```
cargo test --package graph-hunter-api --test graph_meta_integration
```

- [ ] **Step 3: Read existing state in the handler**

Replace the hardcoded body in `get_graph_summary`:

```rust
pub async fn get_graph_summary(api: Arc<GraphHunterApi>) -> ApiResult<GraphSummary> {
    let (nodes, edges, by_type) = api.graph_handle.read().await.totals_by_type();
    let active_datasets = api.dataset_registry.list_active().await;
    let active_hunts = api
        .hunt_cache_handle
        .read()
        .await
        .iter()
        .map(|(key, entry)| ActiveHunt {
            cache_key: key.clone(),
            params_summary: entry.params.summary_string(),
            result_size: entry.result_size as u64,
            computed_at: entry.computed_at.to_rfc3339(),
            ttl_seconds_remaining: entry.ttl_remaining().as_secs(),
        })
        .collect::<Vec<_>>();
    let sources = api.source_registry.snapshot().await;

    Ok(GraphSummary {
        schema_version: GRAPH_META_SCHEMA_VERSION,
        as_of: chrono::Utc::now().to_rfc3339(),
        totals: GraphTotals { nodes, edges, by_type },
        sources,
        active_datasets,
        active_hunts,
        recent_pivots: vec![],  // Filled in Task 6
        graph_empty: nodes == 0,
    })
}
```

NOTE: `totals_by_type`, `source_registry.snapshot`, and `params.summary_string()` are placeholders for the actual existing APIs. The implementer should map each to whatever already exists; if a piece is missing, prefer extending the existing struct over adding a parallel one.

- [ ] **Step 4: Run tests — expect PASS**

```
cargo test --package graph-hunter-api --test graph_meta_integration
```

- [ ] **Step 5: Commit**

```
git add platform/api/src/operations/graph_meta.rs platform/api/tests/graph_meta_integration.rs
git commit -m "feat(api): /graph/summary wires datasets, hunts, sources from existing state"
```

---

### Task 3: Per-type incremental counters in graph engine

**Files:**
- Modify: `core/graph-engine/src/ingest/metrics.rs`
- Modify: `core/graph-engine/src/graph.rs` (insertion paths)
- Test: inline `#[cfg(test)] mod tests` in `metrics.rs`

**Pre-step: verify what exists.** Run `git grep -n "fn record_node\|fn add_node\|node_count" core/graph-engine/src/`. If per-type counters already exist (e.g., `nodes_by_type: DashMap<NodeType, u64>`), skip to Step 5 and just wire them into Task 2's `totals_by_type()`. Otherwise:

- [ ] **Step 1: Write the failing unit test**

```rust
// core/graph-engine/src/ingest/metrics.rs (in the tests module)
#[test]
fn counters_increment_per_type() {
    let m = IngestMetrics::default();
    m.record_node_inserted("IP");
    m.record_node_inserted("IP");
    m.record_node_inserted("User");
    m.record_edge_inserted();
    assert_eq!(m.nodes_total(), 3);
    assert_eq!(m.edges_total(), 1);
    assert_eq!(m.nodes_by_type().get("IP").copied(), Some(2));
    assert_eq!(m.nodes_by_type().get("User").copied(), Some(1));
}
```

- [ ] **Step 2: Run test — expect FAIL**

```
cargo test --package graph-hunter-core counters_increment_per_type
```

- [ ] **Step 3: Add the counter struct**

```rust
// in metrics.rs
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct IngestMetrics {
    nodes_total: AtomicU64,
    edges_total: AtomicU64,
    nodes_by_type: DashMap<String, AtomicU64>,
}

impl IngestMetrics {
    pub fn record_node_inserted(&self, ty: &str) {
        self.nodes_total.fetch_add(1, Ordering::Relaxed);
        self.nodes_by_type
            .entry(ty.to_string())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_edge_inserted(&self) {
        self.edges_total.fetch_add(1, Ordering::Relaxed);
    }
    pub fn nodes_total(&self) -> u64 { self.nodes_total.load(Ordering::Relaxed) }
    pub fn edges_total(&self) -> u64 { self.edges_total.load(Ordering::Relaxed) }
    pub fn nodes_by_type(&self) -> std::collections::BTreeMap<String, u64> {
        self.nodes_by_type
            .iter()
            .map(|e| (e.key().clone(), e.value().load(Ordering::Relaxed)))
            .collect()
    }
}
```

- [ ] **Step 4: Hook insertion sites**

Find the two-three places where nodes and edges enter the graph (likely in `core/graph-engine/src/graph.rs` and `core/graph-engine/src/ingest/writer.rs`). At each, call `metrics.record_node_inserted(type_name)` or `record_edge_inserted()`. Keep the change minimal — single-line per insertion site.

- [ ] **Step 5: Expose `totals_by_type()` on the graph handle**

```rust
// in graph.rs (or wherever GraphHandle is defined)
pub fn totals_by_type(&self) -> (u64, u64, BTreeMap<String, u64>) {
    let m = &self.metrics;
    (m.nodes_total(), m.edges_total(), m.nodes_by_type())
}
```

- [ ] **Step 6: Run test — expect PASS**

```
cargo test --package graph-hunter-core counters_increment_per_type
```

- [ ] **Step 7: Run the Task 2 integration test to confirm wiring**

```
cargo test --package graph-hunter-api --test graph_meta_integration
```

- [ ] **Step 8: Commit**

```
git add core/graph-engine/src/ingest/metrics.rs core/graph-engine/src/graph.rs \
        core/graph-engine/src/ingest/writer.rs
git commit -m "feat(graph-engine): per-type incremental node/edge counters"
```

---

### Task 4: 30s TTL cache on `/graph/summary`

**Files:**
- Modify: `platform/api/src/operations/graph_meta.rs`
- Test: `platform/api/tests/graph_meta_integration.rs`

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn graph_summary_caches_30s() {
    let api = spawn_test_api().await;
    let t1: GraphSummary = api.get("/graph/summary").await.json().await.unwrap();
    api.ingest_one_node("IP", "10.0.0.1").await;
    let t2: GraphSummary = api.get("/graph/summary").await.json().await.unwrap();
    assert_eq!(t1.totals.nodes, t2.totals.nodes, "cache hit should mask the new node");
    assert_eq!(t1.as_of, t2.as_of, "cached responses share as_of");
}
```

- [ ] **Step 2: Run test — expect FAIL (no cache yet)**

- [ ] **Step 3: Add the cache**

```rust
// in operations/graph_meta.rs
use std::sync::Mutex;
use std::time::{Duration, Instant};
use once_cell::sync::Lazy;

const SUMMARY_TTL: Duration = Duration::from_secs(30);

static SUMMARY_CACHE: Lazy<Mutex<Option<(Instant, GraphSummary)>>> =
    Lazy::new(|| Mutex::new(None));

pub async fn get_graph_summary(api: Arc<GraphHunterApi>) -> ApiResult<GraphSummary> {
    {
        let guard = SUMMARY_CACHE.lock().unwrap();
        if let Some((t, ref cached)) = *guard {
            if t.elapsed() < SUMMARY_TTL {
                return Ok(cached.clone_for_response());
            }
        }
    }
    let fresh = compute_summary(api).await?;
    *SUMMARY_CACHE.lock().unwrap() = Some((Instant::now(), fresh.clone_for_response()));
    Ok(fresh)
}
```

`clone_for_response()` is a small helper that clones the struct (add `Clone` to all DTO structs in Task 1's file if not already present).

- [ ] **Step 4: Run test — expect PASS**

- [ ] **Step 5: Commit**

```
git commit -am "feat(api): 30s TTL cache on /graph/summary"
```

---

### Task 5: `recent_pivots` ring buffer

**Files:**
- Modify: `platform/api/src/operations/graph_meta.rs`
- Test: inline `#[cfg(test)] mod tests`

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ring_buffer_drops_oldest_at_capacity() {
        let buf = RecentPivotsBuffer::with_capacity(3);
        for i in 0..5 {
            buf.push(RecentPivot {
                entity: format!("ip-{}", i), kind: "IP".into(),
                added_at: chrono::Utc::now().to_rfc3339(),
                expanded: false, degree: 0,
            });
        }
        let snap = buf.snapshot();
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0].entity, "ip-4");  // newest first
        assert_eq!(snap[2].entity, "ip-2");
    }
}
```

- [ ] **Step 2: Run test — expect FAIL**

- [ ] **Step 3: Implement the buffer**

```rust
// in operations/graph_meta.rs
use std::collections::VecDeque;
use std::sync::Mutex;

pub struct RecentPivotsBuffer {
    inner: Mutex<VecDeque<RecentPivot>>,
    capacity: usize,
}

impl RecentPivotsBuffer {
    pub fn with_capacity(cap: usize) -> Self {
        Self { inner: Mutex::new(VecDeque::with_capacity(cap)), capacity: cap }
    }
    pub fn push(&self, p: RecentPivot) {
        let mut q = self.inner.lock().unwrap();
        if q.len() == self.capacity { q.pop_back(); }
        q.push_front(p);
    }
    pub fn snapshot(&self) -> Vec<RecentPivot> {
        self.inner.lock().unwrap().iter().cloned().collect()
    }
}

pub static RECENT_PIVOTS: Lazy<RecentPivotsBuffer> =
    Lazy::new(|| RecentPivotsBuffer::with_capacity(20));
```

(Add `Clone` to `RecentPivot` in Task 1's DTO file.)

- [ ] **Step 4: Wire snapshot into `compute_summary`**

In the body that becomes `compute_summary`, set `recent_pivots: RECENT_PIVOTS.snapshot()`.

- [ ] **Step 5: Run test — expect PASS**

- [ ] **Step 6: Commit**

```
git commit -am "feat(api): recent_pivots ring buffer (size 20) in graph_meta"
```

---

### Task 6: Push to `recent_pivots` on seed and node_expand

**Files:**
- Modify: `platform/api/src/operations/sentinel.rs`
- Modify: `platform/api/src/operations/entity.rs`
- Test: `platform/api/tests/graph_meta_integration.rs`

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn seed_pushes_recent_pivot() {
    let api = spawn_test_api().await;
    api.sentinel_seed("203.0.113.42", "IP").await.unwrap();
    let resp: GraphSummary = api.get("/graph/summary").await.json().await.unwrap();
    // bypass cache:
    std::thread::sleep(std::time::Duration::from_secs(31));
    let resp: GraphSummary = api.get("/graph/summary").await.json().await.unwrap();
    let pivot = resp.recent_pivots.iter().find(|p| p.entity == "203.0.113.42");
    assert!(pivot.is_some(), "seeded entity should appear in recent_pivots");
    assert_eq!(pivot.unwrap().expanded, false);
}

#[tokio::test]
async fn expand_marks_pivot_expanded() {
    let api = spawn_test_api().await;
    api.sentinel_seed("203.0.113.42", "IP").await.unwrap();
    api.node_expand("203.0.113.42").await.unwrap();
    let resp: GraphSummary = api.get_uncached("/graph/summary").await.json().await.unwrap();
    let pivot = resp.recent_pivots.iter().find(|p| p.entity == "203.0.113.42").unwrap();
    assert_eq!(pivot.expanded, true);
}
```

Add `get_uncached` to the test harness — it bypasses the SUMMARY_CACHE by invalidating it before the call (test-only API behind `#[cfg(test)]`).

- [ ] **Step 2: Run tests — expect FAIL**

- [ ] **Step 3: Add the push in `sentinel_seed`**

At the success branch (just before returning from the seed operation in `operations/sentinel.rs`):

```rust
use crate::operations::graph_meta::{RECENT_PIVOTS, RecentPivot};

// after the seed succeeds and the node is in the graph:
RECENT_PIVOTS.push(RecentPivot {
    entity: ioc.value.clone(),
    kind: ioc.kind.to_string(),
    added_at: chrono::Utc::now().to_rfc3339(),
    expanded: false,
    degree: 0,
});
```

- [ ] **Step 4: Add a `mark_expanded` helper and call from node_expand**

In `operations/graph_meta.rs`:

```rust
impl RecentPivotsBuffer {
    pub fn mark_expanded(&self, entity: &str, degree: u32) {
        let mut q = self.inner.lock().unwrap();
        if let Some(p) = q.iter_mut().find(|p| p.entity == entity) {
            p.expanded = true;
            p.degree = degree;
        }
    }
}
```

In `operations/entity.rs` at the success branch of `node_expand`:

```rust
RECENT_PIVOTS.mark_expanded(&request.entity, neighbors.len() as u32);
```

- [ ] **Step 5: Run tests — expect PASS**

- [ ] **Step 6: Commit**

```
git commit -am "feat(api): push to recent_pivots on sentinel_seed; mark expanded on node_expand"
```

---

### Task 7: `POST /graph/overlap` endpoint

**Files:**
- Modify: `platform/api/src/dto/v1/graph_meta.rs`
- Modify: `platform/api/src/operations/graph_meta.rs`
- Modify: route registration site
- Test: `platform/api/tests/graph_meta_integration.rs`

- [ ] **Step 1: Add the request/response DTOs**

```rust
// in dto/v1/graph_meta.rs
#[derive(Serialize, Deserialize, Debug)]
pub struct OverlapRequest {
    pub schema_version: u32,
    pub entities: Vec<EntityRef>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EntityRef {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OverlapResponse {
    pub schema_version: u32,
    pub found: Vec<FoundEntity>,
    pub missing: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FoundEntity {
    pub entity: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub degree: u32,
    pub top_neighbor: Option<TopNeighbor>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TopNeighbor {
    pub entity: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub edge_count: u32,
}
```

- [ ] **Step 2: Write the failing tests**

```rust
#[tokio::test]
async fn overlap_returns_found_for_present_entity() {
    let api = spawn_test_api().await;
    api.sentinel_seed("203.0.113.42", "IP").await.unwrap();
    let body = serde_json::json!({
        "schema_version": 1,
        "entities": [{"type": "IP", "value": "203.0.113.42"}, {"type": "IP", "value": "8.8.8.8"}]
    });
    let resp: OverlapResponse = api.post("/graph/overlap", &body).await.json().await.unwrap();
    assert_eq!(resp.found.len(), 1);
    assert_eq!(resp.found[0].entity, "203.0.113.42");
    assert_eq!(resp.missing, vec!["8.8.8.8".to_string()]);
}

#[tokio::test]
async fn overlap_413_above_500_entities() {
    let api = spawn_test_api().await;
    let entities: Vec<_> = (0..501).map(|i| serde_json::json!({
        "type": "IP", "value": format!("10.0.{}.{}", i / 256, i % 256)
    })).collect();
    let body = serde_json::json!({"schema_version": 1, "entities": entities});
    let status = api.post_raw("/graph/overlap", &body).await.status();
    assert_eq!(status, 413);
}
```

- [ ] **Step 3: Run tests — expect FAIL**

- [ ] **Step 4: Implement the handler**

```rust
// in operations/graph_meta.rs
const OVERLAP_MAX_ENTITIES: usize = 500;

pub async fn post_graph_overlap(
    api: Arc<GraphHunterApi>,
    req: OverlapRequest,
) -> ApiResult<OverlapResponse> {
    if req.entities.len() > OVERLAP_MAX_ENTITIES {
        return Err(ApiError::PayloadTooLarge(format!(
            "entities ({} > {})", req.entities.len(), OVERLAP_MAX_ENTITIES
        )));
    }
    let graph = api.graph_handle.read().await;
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for e in &req.entities {
        match graph.lookup_typed(&e.kind, &e.value) {
            Some(node_ref) => {
                let degree = graph.degree(node_ref);
                let top_neighbor = graph
                    .neighbors_sorted_by_edge_count(node_ref, 1)
                    .into_iter()
                    .next()
                    .map(|(n, edges)| TopNeighbor {
                        entity: graph.entity_value(n).to_string(),
                        kind: graph.entity_kind(n).to_string(),
                        edge_count: edges,
                    });
                found.push(FoundEntity {
                    entity: e.value.clone(), kind: e.kind.clone(),
                    degree, top_neighbor,
                });
            }
            None => missing.push(e.value.clone()),
        }
    }
    Ok(OverlapResponse {
        schema_version: GRAPH_META_SCHEMA_VERSION,
        found, missing,
    })
}
```

NOTE: `lookup_typed`, `degree`, `neighbors_sorted_by_edge_count`, `entity_value`, `entity_kind` may or may not exist on the graph handle. If missing, add thin wrappers around the actual underlying APIs — do not invent new graph operations. Read `core/graph-engine/src/graph.rs` to find the right method names.

- [ ] **Step 5: Register the route**

```rust
.route("/graph/overlap", post(|State(api): State<Arc<GraphHunterApi>>, Json(req): Json<OverlapRequest>| async move {
    operations::graph_meta::post_graph_overlap(api, req).await.map(Json)
}))
```

Ensure `ApiError::PayloadTooLarge` maps to HTTP 413 (add a variant if needed).

- [ ] **Step 6: Run tests — expect PASS**

- [ ] **Step 7: Commit**

```
git commit -am "feat(api): /graph/overlap endpoint with 500-entity cap (413)"
```

---

### Task 8: Backend schema_version golden test

**Files:**
- Test: `platform/api/tests/graph_meta_integration.rs`

- [ ] **Step 1: Add the golden test**

```rust
#[tokio::test]
async fn graph_meta_schema_version_is_1() {
    let api = spawn_test_api().await;
    let summary: serde_json::Value = api.get("/graph/summary").await.json().await.unwrap();
    assert_eq!(summary["schema_version"], 1,
        "BUMPING schema_version requires coordinated zod + serde + golden test changes");
    let body = serde_json::json!({"schema_version": 1, "entities": []});
    let overlap: serde_json::Value = api.post("/graph/overlap", &body).await.json().await.unwrap();
    assert_eq!(overlap["schema_version"], 1);
}
```

- [ ] **Step 2: Run — expect PASS** (this just locks the invariant)

- [ ] **Step 3: Commit**

```
git commit -am "test(api): schema_version=1 golden test for graph_meta endpoints"
```

---

## Phase B — MCP server

### Task 9: `graph-state-client.ts`

**Files:**
- Create: `platform/mcp/src/lib/graph-state-client.ts`
- Create: `platform/mcp/tests/contract/graph-state-client.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// platform/mcp/tests/contract/graph-state-client.test.ts
import test from "node:test";
import assert from "node:assert/strict";
import { GraphStateClient } from "../../src/lib/graph-state-client.js";

test("getSummary parses a v1 payload", async () => {
  const fakeFetch = async (url: string) => ({
    ok: true,
    json: async () => ({
      schema_version: 1, as_of: "2026-06-19T00:00:00Z",
      totals: { nodes: 0, edges: 0, by_type: {} },
      sources: [], active_datasets: [], active_hunts: [], recent_pivots: [],
      graph_empty: true,
    }),
  });
  const c = new GraphStateClient("http://x", { fetchImpl: fakeFetch as any });
  const r = await c.getSummary({ timeoutMs: 800 });
  assert.equal(r.schema_version, 1);
  assert.equal(r.graph_empty, true);
});

test("getSummary returns null on timeout", async () => {
  const fakeFetch = (_: string, init: any) =>
    new Promise<any>((_, rej) => init.signal.addEventListener("abort", () => rej(new Error("aborted"))));
  const c = new GraphStateClient("http://x", { fetchImpl: fakeFetch as any });
  const r = await c.getSummary({ timeoutMs: 10 });
  assert.equal(r, null);
});

test("postOverlap rejects > 500 entities client-side", async () => {
  const c = new GraphStateClient("http://x");
  const entities = Array.from({ length: 501 }, (_, i) => ({ type: "IP", value: `10.0.0.${i}` }));
  await assert.rejects(() => c.postOverlap(entities), /500/);
});
```

- [ ] **Step 2: Build + run — expect FAIL**

```
cd platform/mcp && npm run build && npm run test:contract
```

- [ ] **Step 3: Implement the client**

```typescript
// platform/mcp/src/lib/graph-state-client.ts
import { z } from "zod";

const FoundEntity = z.object({
  entity: z.string(),
  type: z.string(),
  degree: z.number(),
  top_neighbor: z.object({
    entity: z.string(), type: z.string(), edge_count: z.number(),
  }).optional().nullable(),
});

export const SummarySchema = z.object({
  schema_version: z.literal(1),
  as_of: z.string(),
  totals: z.object({
    nodes: z.number(), edges: z.number(),
    by_type: z.record(z.string(), z.number()),
  }),
  sources: z.array(z.object({
    name: z.string(), last_ingest: z.string().nullable(), rows_lifetime: z.number(),
  })),
  active_datasets: z.array(z.string()),
  active_hunts: z.array(z.object({
    cache_key: z.string(), params_summary: z.string(),
    result_size: z.number(), computed_at: z.string(),
    ttl_seconds_remaining: z.number(),
  })),
  recent_pivots: z.array(z.object({
    entity: z.string(), type: z.string(), added_at: z.string(),
    expanded: z.boolean(), degree: z.number(),
  })),
  graph_empty: z.boolean(),
});
export type Summary = z.infer<typeof SummarySchema>;

export const OverlapResponseSchema = z.object({
  schema_version: z.literal(1),
  found: z.array(FoundEntity),
  missing: z.array(z.string()),
});
export type OverlapResponse = z.infer<typeof OverlapResponseSchema>;

export interface EntityRef { type: string; value: string; }
export interface ClientOpts { fetchImpl?: typeof fetch; }

export class GraphStateClient {
  constructor(private baseUrl: string, private opts: ClientOpts = {}) {}

  async getSummary(o: { timeoutMs: number }): Promise<Summary | null> {
    return this.callJson(`${this.baseUrl}/graph/summary`, "GET", undefined, o.timeoutMs, SummarySchema);
  }

  async postOverlap(entities: EntityRef[], o: { timeoutMs?: number } = {}): Promise<OverlapResponse | null> {
    if (entities.length > 500) throw new Error("overlap: max 500 entities per request");
    return this.callJson(
      `${this.baseUrl}/graph/overlap`, "POST",
      { schema_version: 1, entities }, o.timeoutMs ?? 800, OverlapResponseSchema,
    );
  }

  private async callJson<T>(
    url: string, method: "GET" | "POST", body: unknown, timeoutMs: number, schema: z.ZodType<T>,
  ): Promise<T | null> {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeoutMs);
    const f = this.opts.fetchImpl ?? fetch;
    try {
      const resp = await f(url, {
        method, signal: ctl.signal,
        headers: body ? { "content-type": "application/json" } : undefined,
        body: body ? JSON.stringify(body) : undefined,
      } as any);
      if (!resp.ok) return null;
      return schema.parse(await resp.json());
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }
}
```

- [ ] **Step 4: Build + run tests — expect PASS**

```
cd platform/mcp && npm run build && npm run test:contract
```

- [ ] **Step 5: Commit**

```
git add platform/mcp/src/lib/graph-state-client.ts platform/mcp/tests/contract/graph-state-client.test.ts
git commit -m "feat(mcp): GraphStateClient with zod-validated summary/overlap"
```

---

### Task 10: Three `graph://` resources

**Files:**
- Create: `platform/mcp/src/resources/graph-summary.ts`
- Create: `platform/mcp/src/resources/graph-active-hunts.ts`
- Create: `platform/mcp/src/resources/graph-recent-pivots.ts`
- Create: `platform/mcp/src/resources/index.ts`
- Modify: `platform/mcp/src/index.ts` (call `registerResources`)
- Create: `platform/mcp/tests/contract/resources.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// resources.test.ts
import test from "node:test";
import assert from "node:assert/strict";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerResources } from "../../src/resources/index.js";
import { GraphStateClient } from "../../src/lib/graph-state-client.js";

test("registers three graph:// resources", () => {
  const server = new McpServer({ name: "test", version: "0" });
  const stub = new GraphStateClient("http://stub");
  const registered = registerResources(server, stub);
  assert.deepEqual(registered.sort(), [
    "graph://active-hunts", "graph://recent-pivots", "graph://summary",
  ]);
});

test("graph://summary description nudges seed when empty", () => {
  const server = new McpServer({ name: "test", version: "0" });
  const stub = new GraphStateClient("http://stub");
  registerResources(server, stub);
  const meta = (server as any)._registeredResources["graph://summary"];
  assert.match(meta.description, /sentinel_seed/);
  assert.match(meta.description, /graph_empty/);
});
```

NOTE: the `_registeredResources` internal property name may differ; adjust to the SDK's actual introspection API or use a wrapper.

- [ ] **Step 2: Build + run — expect FAIL**

- [ ] **Step 3: Implement each resource**

```typescript
// platform/mcp/src/resources/graph-summary.ts
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { GraphStateClient } from "../lib/graph-state-client.js";

export const URI = "graph://summary";
export const DESC =
  "Current graph state: totals by type, sources ingested with freshness, " +
  "active datasets, active hunts, and recent pivots. Read this at the start " +
  "of any hunting conversation. If graph_empty is true, prefer sentinel_seed " +
  "before sentinel_query.";

export function register(server: McpServer, client: GraphStateClient) {
  server.resource(URI, DESC, async () => {
    const s = await client.getSummary({ timeoutMs: 800 });
    const text = s
      ? JSON.stringify(s, null, 2)
      : JSON.stringify({ error: "graph_summary unavailable" });
    return { contents: [{ uri: URI, mimeType: "application/json", text }] };
  });
}
```

```typescript
// platform/mcp/src/resources/graph-active-hunts.ts
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { GraphStateClient } from "../lib/graph-state-client.js";

export const URI = "graph://active-hunts";
export const DESC =
  "Currently cached hunts (execution-scoped DFS results). When the user " +
  "mentions an ongoing investigation, check here before launching a new hunt.";

export function register(server: McpServer, client: GraphStateClient) {
  server.resource(URI, DESC, async () => {
    const s = await client.getSummary({ timeoutMs: 800 });
    const hunts = s ? s.active_hunts : [];
    return {
      contents: [{
        uri: URI, mimeType: "application/json",
        text: JSON.stringify({ schema_version: 1, hunts }, null, 2),
      }],
    };
  });
}
```

```typescript
// platform/mcp/src/resources/graph-recent-pivots.ts
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { GraphStateClient } from "../lib/graph-state-client.js";

export const URI = "graph://recent-pivots";
export const DESC =
  "Last 20 entities added via sentinel_seed or expanded via node_expand. " +
  "Entries with expanded=false are open invitations for node_expand — prefer " +
  "expanding them over generating a fresh KQL.";

export function register(server: McpServer, client: GraphStateClient) {
  server.resource(URI, DESC, async () => {
    const s = await client.getSummary({ timeoutMs: 800 });
    const pivots = s ? s.recent_pivots : [];
    return {
      contents: [{
        uri: URI, mimeType: "application/json",
        text: JSON.stringify({ schema_version: 1, pivots }, null, 2),
      }],
    };
  });
}
```

```typescript
// platform/mcp/src/resources/index.ts
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { GraphStateClient } from "../lib/graph-state-client.js";
import * as summary from "./graph-summary.js";
import * as hunts from "./graph-active-hunts.js";
import * as pivots from "./graph-recent-pivots.js";

export function registerResources(server: McpServer, client: GraphStateClient): string[] {
  summary.register(server, client);
  hunts.register(server, client);
  pivots.register(server, client);
  return [summary.URI, hunts.URI, pivots.URI];
}
```

In `platform/mcp/src/index.ts`, after registering tools:

```typescript
import { registerResources } from "./resources/index.js";
import { GraphStateClient } from "./lib/graph-state-client.js";

const graphClient = new GraphStateClient(process.env.GH_API_URL ?? "http://localhost:3000");
registerResources(server, graphClient);
```

- [ ] **Step 4: Build + run tests — expect PASS**

- [ ] **Step 5: Commit**

```
git add platform/mcp/src/resources/ platform/mcp/src/index.ts \
        platform/mcp/tests/contract/resources.test.ts
git commit -m "feat(mcp): three graph:// resources (summary, active-hunts, recent-pivots)"
```

---

### Task 11: Entity extractor

**Files:**
- Create: `platform/mcp/src/lib/entity-extractor.ts`
- Create: `platform/mcp/tests/contract/entity-extractor.test.ts`

- [ ] **Step 1: Write the failing tests**

```typescript
import test from "node:test";
import assert from "node:assert/strict";
import { extractEntities } from "../../src/lib/entity-extractor.js";

test("extracts IPs from arbitrary string columns", () => {
  const rows = [{ Message: "src=203.0.113.42 dst=8.8.8.8" }];
  const out = extractEntities(rows);
  const ips = out.filter(e => e.type === "IP").map(e => e.value).sort();
  assert.deepEqual(ips, ["203.0.113.42", "8.8.8.8"]);
});

test("extracts emails as User", () => {
  const rows = [{ Account: "lasoto@telecarga.cl" }, { who: "x@y.zw" }];
  const out = extractEntities(rows);
  const users = out.filter(e => e.type === "User").map(e => e.value).sort();
  assert.deepEqual(users, ["lasoto@telecarga.cl", "x@y.zw"]);
});

test("extracts Hostname only from named columns", () => {
  const rows = [{ Computer: "fw01.telecarga.cl", Note: "fw02.telecarga.cl" }];
  const out = extractEntities(rows);
  const hosts = out.filter(e => e.type === "Hostname").map(e => e.value);
  assert.deepEqual(hosts, ["fw01.telecarga.cl"]);
  // fw02 from a non-host column should be Domain, not Hostname
  const domains = out.filter(e => e.type === "Domain").map(e => e.value);
  assert.ok(domains.includes("fw02.telecarga.cl"));
});

test("dedupes across rows and caps at 500", () => {
  const rows = Array.from({ length: 1200 }, (_, i) => ({
    Message: `src=10.0.${Math.floor(i / 256)}.${i % 256}`,
  }));
  const out = extractEntities(rows);
  assert.ok(out.length <= 500);
});

test("first-N row cap is respected", () => {
  const rows = Array.from({ length: 1000 }, (_, i) => ({ Message: `203.0.113.${i % 256}` }));
  const out = extractEntities(rows, { maxRows: 50 });
  // 50 rows * up to 256 unique IPs/row but capped → much less than 500
  assert.ok(out.length <= 50);
});
```

- [ ] **Step 2: Build + run — expect FAIL**

- [ ] **Step 3: Implement**

```typescript
// platform/mcp/src/lib/entity-extractor.ts
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const FQDN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b/gi;
const HOST_FIELD_NAMES = new Set(["Computer", "Hostname", "DeviceName"]);

export interface ExtractedEntity { type: "IP" | "User" | "Domain" | "Hostname"; value: string; }
export interface ExtractOpts { maxRows?: number; maxEntities?: number; }

export function extractEntities(
  rows: Array<Record<string, unknown>>,
  opts: ExtractOpts = {},
): ExtractedEntity[] {
  const maxRows = opts.maxRows ?? 100;
  const maxEntities = opts.maxEntities ?? 500;
  const out = new Map<string, ExtractedEntity>(); // key = `${type}:${value}`

  for (const row of rows.slice(0, maxRows)) {
    for (const [field, raw] of Object.entries(row)) {
      if (raw == null) continue;
      const s = String(raw);

      // Emails first (consume @-containing tokens before generic FQDN)
      for (const m of s.matchAll(EMAIL_RE)) {
        push(out, "User", m[0], maxEntities);
        if (out.size >= maxEntities) return [...out.values()];
      }

      for (const m of s.matchAll(IP_RE)) {
        push(out, "IP", m[0], maxEntities);
        if (out.size >= maxEntities) return [...out.values()];
      }

      const isHostField = HOST_FIELD_NAMES.has(field);
      const seenInThisField = new Set<string>();
      for (const m of s.matchAll(FQDN_RE)) {
        if (m[0].includes("@")) continue;       // already classified
        if (seenInThisField.has(m[0])) continue;
        seenInThisField.add(m[0]);
        push(out, isHostField ? "Hostname" : "Domain", m[0], maxEntities);
        if (out.size >= maxEntities) return [...out.values()];
      }
    }
  }
  return [...out.values()];
}

function push(out: Map<string, ExtractedEntity>, type: ExtractedEntity["type"], value: string, max: number) {
  const key = `${type}:${value}`;
  if (out.has(key) || out.size >= max) return;
  out.set(key, { type, value });
}
```

- [ ] **Step 4: Build + run tests — expect PASS**

- [ ] **Step 5: Commit**

```
git add platform/mcp/src/lib/entity-extractor.ts platform/mcp/tests/contract/entity-extractor.test.ts
git commit -m "feat(mcp): entity extractor (IP/User/Domain/Hostname) with field-name heuristic"
```

---

### Task 12: Footer composer

**Files:**
- Create: `platform/mcp/src/lib/footer-composer.ts`
- Create: `platform/mcp/tests/contract/footer-composer.test.ts`

- [ ] **Step 1: Write the failing tests**

```typescript
import test from "node:test";
import assert from "node:assert/strict";
import { composeFooter } from "../../src/lib/footer-composer.js";
import type { Summary } from "../../src/lib/graph-state-client.js";

const fullSummary: Summary = {
  schema_version: 1, as_of: new Date().toISOString(),
  totals: { nodes: 2_412_588, edges: 18_402_117, by_type: {} },
  sources: [
    { name: "Sentinel",  last_ingest: minutesAgo(30),  rows_lifetime: 18_000_000 },
    { name: "FortiGate", last_ingest: minutesAgo(180), rows_lifetime: 220_000_000 },
  ],
  active_datasets: [], active_hunts: [], recent_pivots: [],
  graph_empty: false,
};

test("base footer has totals and source freshness", () => {
  const f = composeFooter(fullSummary);
  assert.match(f, /---graph-context---/);
  assert.match(f, /2\.4M nodes/);
  assert.match(f, /Sentinel\(30m\)/);
  assert.match(f, /FortiGate\(3h\)/);
});

test("collapses second line when no hunts and no pivots", () => {
  const f = composeFooter(fullSummary);
  assert.equal(f.split("\n").length, 2); // header + totals line only
});

test("unavailable when summary is null", () => {
  assert.match(composeFooter(null), /\(unavailable\)/);
});

function minutesAgo(m: number) {
  return new Date(Date.now() - m * 60_000).toISOString();
}
```

- [ ] **Step 2: Build + run — expect FAIL**

- [ ] **Step 3: Implement**

```typescript
// platform/mcp/src/lib/footer-composer.ts
import type { Summary } from "./graph-state-client.js";

const HEADER = "---graph-context---";

export function composeFooter(summary: Summary | null): string {
  if (!summary) return `${HEADER}\n(unavailable)`;
  const lines: string[] = [HEADER];

  const nodes = compact(summary.totals.nodes);
  const edges = compact(summary.totals.edges);
  const sources = summary.sources
    .map(s => `${s.name}(${freshness(s.last_ingest)})`)
    .join(", ");
  lines.push(`graph: ${nodes} nodes / ${edges} edges  |  sources: ${sources}`);

  const secondParts: string[] = [];
  if (summary.active_hunts.length > 0) {
    const h = summary.active_hunts[0];
    secondParts.push(`active hunt: ${h.cache_key.slice(0, 12)} (${h.params_summary})`);
  }
  if (summary.recent_pivots.length > 0) {
    const p = summary.recent_pivots[0];
    secondParts.push(`recent pivot: ${p.entity} (${p.expanded ? "expanded" : "unexpanded"})`);
  }
  if (secondParts.length > 0) lines.push(secondParts.join(" | "));

  return lines.join("\n");
}

function compact(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000)     return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

function freshness(iso: string | null): string {
  if (!iso) return "unknown";
  const ms = Date.now() - new Date(iso).getTime();
  if (ms < 60_000)            return `${Math.floor(ms / 1000)}s`;
  if (ms < 3_600_000)         return `${Math.floor(ms / 60_000)}m`;
  if (ms < 86_400_000)        return `${Math.floor(ms / 3_600_000)}h`;
  return `${Math.floor(ms / 86_400_000)}d`;
}
```

- [ ] **Step 4: Build + run — expect PASS**

- [ ] **Step 5: Commit**

```
git add platform/mcp/src/lib/footer-composer.ts platform/mcp/tests/contract/footer-composer.test.ts
git commit -m "feat(mcp): base graph-context footer composer with freshness compaction"
```

---

### Task 13: Nudge composer

**Files:**
- Create: `platform/mcp/src/lib/nudge-composer.ts`
- Create: `platform/mcp/tests/contract/nudge-composer.test.ts`

- [ ] **Step 1: Write the failing tests**

```typescript
import test from "node:test";
import assert from "node:assert/strict";
import { composeNudge } from "../../src/lib/nudge-composer.js";

test("sentinel_query with overlap > 0 suggests node_expand on top entity", () => {
  const n = composeNudge("sentinel_query", { ingest: false }, {
    schema_version: 1, found: [
      { entity: "203.0.113.42", type: "IP", degree: 47,
        top_neighbor: { entity: "lasoto@telecarga.cl", type: "User", edge_count: 12 } },
    ], missing: ["8.8.8.8"],
  });
  assert.match(n!, /1 entit/);
  assert.match(n!, /203\.0\.113\.42/);
  assert.match(n!, /node_expand/);
  assert.match(n!, /lasoto@telecarga\.cl/);
});

test("sentinel_query with overlap=0 suggests ingest=true", () => {
  const n = composeNudge("sentinel_query", { ingest: false }, {
    schema_version: 1, found: [], missing: ["8.8.8.8"],
  });
  assert.match(n!, /ingest=true/);
});

test("sentinel_query with ingest=true emits no nudge", () => {
  assert.equal(composeNudge("sentinel_query", { ingest: true }, {
    schema_version: 1, found: [], missing: [],
  }), null);
});

test("sentinel_seed always suggests next step", () => {
  const n = composeNudge("sentinel_seed", { value: "X" }, null);
  assert.match(n!, /node_expand/);
});

test("node_expand with neighbors > 0 suggests channel_behavior", () => {
  const n = composeNudge("node_expand", { neighbors_found: 47 }, null);
  assert.match(n!, /channel_behavior/);
});

test("unknown tool: no nudge", () => {
  assert.equal(composeNudge("export", {}, null), null);
});
```

- [ ] **Step 2: Build + run — expect FAIL**

- [ ] **Step 3: Implement**

```typescript
// platform/mcp/src/lib/nudge-composer.ts
import type { OverlapResponse } from "./graph-state-client.js";

export function composeNudge(
  tool: string,
  args: Record<string, unknown>,
  overlap: OverlapResponse | null,
): string | null {
  switch (tool) {
    case "sentinel_query": {
      if (args.ingest === true) return null;
      if (!overlap) return null;
      if (overlap.found.length > 0) {
        const top = [...overlap.found].sort((a, b) => b.degree - a.degree)[0];
        const tail = top.top_neighbor
          ? `, connected to ${top.top_neighbor.entity}`
          : "";
        return `${overlap.found.length} entit${overlap.found.length === 1 ? "y" : "ies"} ` +
          `of this result already in the graph. Top: ${top.entity} (degree ${top.degree}${tail}). ` +
          `Consider node_expand before another KQL.`;
      }
      return `None of this KQL's entities are in the graph. ` +
        `To explore these rows, re-run with ingest=true.`;
    }
    case "sentinel_seed":
      return `Node added. Next: node_expand for neighbors, ` +
        `or hunt_run if a playbook scenario fits.`;
    case "node_expand": {
      const n = Number(args.neighbors_found ?? 0);
      if (n <= 0) return null;
      return `Found ${n} neighbors. For channel anomalies: ` +
        `channel_behavior on this node.`;
    }
    default:
      return null;
  }
}
```

- [ ] **Step 4: Build + run — expect PASS**

- [ ] **Step 5: Commit**

```
git add platform/mcp/src/lib/nudge-composer.ts platform/mcp/tests/contract/nudge-composer.test.ts
git commit -m "feat(mcp): nudge composer with per-tool rules table"
```

---

### Task 14: `ContextEnricher` orchestrator

**Files:**
- Create: `platform/mcp/src/lib/context-enricher.ts`
- Create: `platform/mcp/tests/contract/context-enricher.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
import test from "node:test";
import assert from "node:assert/strict";
import { ContextEnricher } from "../../src/lib/context-enricher.js";
import { GraphStateClient } from "../../src/lib/graph-state-client.js";

const fakeFetch = (mode: "ok" | "down") => async (url: string, init?: any) => {
  if (mode === "down") throw new Error("backend down");
  if (url.endsWith("/graph/summary")) {
    return { ok: true, json: async () => ({
      schema_version: 1, as_of: new Date().toISOString(),
      totals: { nodes: 100, edges: 200, by_type: {} },
      sources: [{ name: "Sentinel", last_ingest: new Date().toISOString(), rows_lifetime: 1000 }],
      active_datasets: [], active_hunts: [], recent_pivots: [], graph_empty: false,
    }) };
  }
  return { ok: true, json: async () => ({ schema_version: 1, found: [], missing: [] }) };
};

test("enriches sentinel_query response with footer and nudge", async () => {
  const client = new GraphStateClient("http://x", { fetchImpl: fakeFetch("ok") as any });
  const enricher = new ContextEnricher(client);
  const enriched = await enricher.enrich(
    "sentinel_query",
    { ingest: false },
    [{ type: "text" as const, text: JSON.stringify([{ src: "203.0.113.42" }]) }],
  );
  assert.equal(enriched.length, 2);
  assert.match(enriched[1].text, /graph-context/);
});

test("returns original when env GH_MCP_ENRICH=off", async () => {
  process.env.GH_MCP_ENRICH = "off";
  const enricher = new ContextEnricher(new GraphStateClient("http://x"));
  const orig = [{ type: "text" as const, text: "x" }];
  const out = await enricher.enrich("sentinel_query", { ingest: false }, orig);
  assert.deepEqual(out, orig);
  delete process.env.GH_MCP_ENRICH;
});

test("backend down: footer says unavailable, tool output preserved", async () => {
  const client = new GraphStateClient("http://x", { fetchImpl: fakeFetch("down") as any });
  const enricher = new ContextEnricher(client);
  const orig = [{ type: "text" as const, text: "rows" }];
  const out = await enricher.enrich("sentinel_query", { ingest: false }, orig);
  assert.equal(out[0].text, "rows");
  assert.match(out[1].text, /\(unavailable\)/);
});
```

- [ ] **Step 2: Build + run — expect FAIL**

- [ ] **Step 3: Implement**

```typescript
// platform/mcp/src/lib/context-enricher.ts
import type { GraphStateClient, EntityRef } from "./graph-state-client.js";
import { extractEntities } from "./entity-extractor.js";
import { composeFooter } from "./footer-composer.js";
import { composeNudge } from "./nudge-composer.js";

export interface TextContent { type: "text"; text: string; }

export class ContextEnricher {
  constructor(private client: GraphStateClient) {}

  async enrich(
    tool: string,
    args: Record<string, unknown>,
    original: TextContent[],
  ): Promise<TextContent[]> {
    if (process.env.GH_MCP_ENRICH === "off") return original;
    if ((args as any)?._meta?.enrich === false) return original;

    const wantsOverlap =
      tool === "sentinel_query" && args.ingest !== true;

    const [summary, overlap] = await Promise.all([
      this.client.getSummary({ timeoutMs: 800 }),
      wantsOverlap ? this.runOverlap(original) : Promise.resolve(null),
    ]);

    const footer = composeFooter(summary);
    const nudge = composeNudge(tool, args, overlap);
    const text = nudge ? `${footer}\n${nudge}` : footer;
    return [...original, { type: "text", text }];
  }

  private async runOverlap(content: TextContent[]) {
    try {
      const rows = this.parseRows(content);
      const entities = extractEntities(rows);
      const cast: EntityRef[] = entities.map(e => ({ type: e.type, value: e.value }));
      if (cast.length === 0) return null;
      return await this.client.postOverlap(cast, { timeoutMs: 800 });
    } catch {
      return null;
    }
  }

  private parseRows(content: TextContent[]): Array<Record<string, unknown>> {
    // Tool results in this server are safeJsonContent — first text block is JSON
    const first = content[0]?.text;
    if (!first) return [];
    try {
      const parsed = JSON.parse(first);
      if (Array.isArray(parsed)) return parsed as Array<Record<string, unknown>>;
      if (parsed && typeof parsed === "object" && Array.isArray((parsed as any).rows)) {
        return (parsed as any).rows;
      }
    } catch { /* ignore */ }
    return [];
  }
}
```

- [ ] **Step 4: Build + run — expect PASS**

- [ ] **Step 5: Commit**

```
git add platform/mcp/src/lib/context-enricher.ts platform/mcp/tests/contract/context-enricher.test.ts
git commit -m "feat(mcp): ContextEnricher orchestrating extractor + footer + nudge"
```

---

### Task 15: Wire `ContextEnricher` into `registerTools`

**Files:**
- Modify: `platform/mcp/src/server.ts`
- Modify: `platform/mcp/src/index.ts` (construct and pass the enricher)
- Create: `platform/mcp/tests/contract/server-enrichment.test.ts`

- [ ] **Step 1: Write the failing E2E test**

```typescript
import test from "node:test";
import assert from "node:assert/strict";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerTools } from "../../src/server.js";
import { ContextEnricher } from "../../src/lib/context-enricher.js";
import { GraphStateClient } from "../../src/lib/graph-state-client.js";

test("tool response gets a second content block with the footer", async () => {
  const fakeFetch = async (url: string) => ({
    ok: true,
    json: async () => url.endsWith("/graph/summary") ? {
      schema_version: 1, as_of: new Date().toISOString(),
      totals: { nodes: 1, edges: 0, by_type: {} },
      sources: [], active_datasets: [], active_hunts: [], recent_pivots: [],
      graph_empty: false,
    } : { schema_version: 1, found: [], missing: [] },
  });
  const client = new GraphStateClient("http://x", { fetchImpl: fakeFetch as any });
  const enricher = new ContextEnricher(client);

  const server = new McpServer({ name: "t", version: "0" });
  const fakeTool = {
    name: "demo", description: "", category: "test", version: 1, stability: "stable",
    inputSchema: (await import("zod")).z.object({}),
    outputSchema: (await import("zod")).z.unknown(),
    execute: async () => ({ ok: true }),
  };
  registerTools(server, [fakeTool as any], () => ({} as any), enricher);

  const handler = (server as any)._tools.get("demo");
  const result = await handler({});
  assert.equal(result.content.length, 2);
  assert.match(result.content[1].text, /graph-context/);
});
```

NOTE: internal property names like `_tools` will vary; adapt to whatever the SDK exposes for the test.

- [ ] **Step 2: Build + run — expect FAIL**

- [ ] **Step 3: Thread the enricher through `registerTools`**

In `platform/mcp/src/server.ts`, change the signature and body:

```typescript
export function registerTools(
  server: McpServer,
  tools: Tool[],
  makeContext: (requestId: string) => ToolContext,
  enricher?: ContextEnricher,             // NEW
): void {
  for (const tool of tools) {
    const handler = async (rawInput: unknown) => {
      const requestId = nextRequestId();
      const ctx = makeContext(requestId);
      const start = Date.now();
      ctx.logger.tool(tool.name, { request_id: requestId });
      // … existing experimental/deprecated warnings …
      try {
        const parsed = tool.inputSchema.parse(rawInput ?? {});
        const result = await tool.execute(ctx, parsed);
        ctx.logger.tool(tool.name + " done", { duration_ms: Date.now() - start });
        const raw = tool.resultFormat === "text"
          ? textContent(typeof result === "string" ? result : String(result))
          : safeJsonContent(result);
        if (!enricher) return raw;
        const enriched = await enricher.enrich(
          tool.name,
          (parsed ?? {}) as Record<string, unknown>,
          raw.content as any,
        );
        return { ...raw, content: enriched };
      } catch (e) {
        // … unchanged …
      }
    };
    // … existing schema-empty branching …
  }
}
```

Import `ContextEnricher` at the top of `server.ts`.

In `platform/mcp/src/index.ts`, construct and pass:

```typescript
const enricher = new ContextEnricher(graphClient);
registerTools(server, tools, makeContext, enricher);
```

- [ ] **Step 4: Build + run — expect PASS**

- [ ] **Step 5: Commit**

```
git add platform/mcp/src/server.ts platform/mcp/src/index.ts \
        platform/mcp/tests/contract/server-enrichment.test.ts
git commit -m "feat(mcp): wire ContextEnricher into registerTools (default on)"
```

---

## Phase C — Cross-side guarantees

### Task 16: Schema-version drift guard (cross-side golden snapshot)

**Files:**
- Create: `platform/mcp/tests/contract/schema-version-sync.test.ts`
- Create: `platform/api/tests/schema_snapshot.rs`
- Create: `platform/mcp/tests/fixtures/summary.v1.golden.json` (shared fixture)

- [ ] **Step 1: Author a single shared fixture**

```json
{
  "schema_version": 1,
  "as_of": "2026-06-19T00:00:00Z",
  "totals": { "nodes": 0, "edges": 0, "by_type": {} },
  "sources": [],
  "active_datasets": [],
  "active_hunts": [],
  "recent_pivots": [],
  "graph_empty": true
}
```

- [ ] **Step 2: MCP-side test that the zod schema accepts it**

```typescript
// platform/mcp/tests/contract/schema-version-sync.test.ts
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { SummarySchema } from "../../src/lib/graph-state-client.js";

test("zod schema accepts the shared v1 golden fixture", () => {
  const golden = JSON.parse(
    fs.readFileSync(path.join(__dirname, "../fixtures/summary.v1.golden.json"), "utf-8"),
  );
  const parsed = SummarySchema.parse(golden);
  assert.equal(parsed.schema_version, 1);
});
```

- [ ] **Step 3: Rust-side test that serde accepts the same fixture**

```rust
// platform/api/tests/schema_snapshot.rs
use graph_hunter_api::dto::v1::graph_meta::GraphSummary;

#[test]
fn serde_accepts_the_shared_v1_golden_fixture() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../mcp/tests/fixtures/summary.v1.golden.json");
    let raw = std::fs::read_to_string(path).expect("fixture must exist");
    let parsed: GraphSummary = serde_json::from_str(&raw).expect("serde must accept v1");
    assert_eq!(parsed.schema_version, 1);
}
```

- [ ] **Step 4: Build + run both — expect PASS**

```
cd platform/mcp && npm run build && npm run test:contract
cargo test --package graph-hunter-api --test schema_snapshot
```

- [ ] **Step 5: Commit**

```
git add platform/mcp/tests/fixtures/summary.v1.golden.json \
        platform/mcp/tests/contract/schema-version-sync.test.ts \
        platform/api/tests/schema_snapshot.rs
git commit -m "test: cross-side schema_version=1 drift guard (shared golden fixture)"
```

---

### Task 17: Metrics instrumentation

**Files:**
- Modify: `platform/mcp/src/server.ts` (add counters around handler)
- Create: `platform/mcp/src/lib/metrics.ts`
- Test: `platform/mcp/tests/contract/metrics.test.ts`

The metrics that prove "not middleware":
- `gh_mcp_tool_calls_total{tool}` — call ratio per tool
- `gh_mcp_nudge_displayed_total{tool}`, `gh_mcp_nudge_followed_total{tool}` — follow-through (followed = same session sees a graph-side tool call within 2 turns after a nudge)
- `gh_mcp_graph_resource_reads_total{uri}` — orientation reads
- `gh_mcp_pivot_followthrough_total` — incremented when a `recent_pivot` with `expanded=false` is later expanded in the same session

- [ ] **Step 1: Write the failing test**

```typescript
import test from "node:test";
import assert from "node:assert/strict";
import { Metrics } from "../../src/lib/metrics.js";

test("counters increment and snapshot reports them", () => {
  const m = new Metrics();
  m.incToolCall("sentinel_query");
  m.incToolCall("sentinel_query");
  m.incToolCall("node_expand");
  m.incNudgeDisplayed("sentinel_query");
  m.incNudgeFollowed("sentinel_query");
  m.incResourceRead("graph://summary");

  const snap = m.snapshot();
  assert.equal(snap.tool_calls.sentinel_query, 2);
  assert.equal(snap.tool_calls.node_expand, 1);
  assert.equal(snap.nudges_displayed.sentinel_query, 1);
  assert.equal(snap.nudges_followed.sentinel_query, 1);
  assert.equal(snap.resource_reads["graph://summary"], 1);
});
```

- [ ] **Step 2: Build + run — expect FAIL**

- [ ] **Step 3: Implement**

```typescript
// platform/mcp/src/lib/metrics.ts
export class Metrics {
  private toolCalls = new Map<string, number>();
  private nudgesDisplayed = new Map<string, number>();
  private nudgesFollowed = new Map<string, number>();
  private resourceReads = new Map<string, number>();

  incToolCall(tool: string) { this.bump(this.toolCalls, tool); }
  incNudgeDisplayed(tool: string) { this.bump(this.nudgesDisplayed, tool); }
  incNudgeFollowed(tool: string) { this.bump(this.nudgesFollowed, tool); }
  incResourceRead(uri: string) { this.bump(this.resourceReads, uri); }

  snapshot() {
    return {
      tool_calls: Object.fromEntries(this.toolCalls),
      nudges_displayed: Object.fromEntries(this.nudgesDisplayed),
      nudges_followed: Object.fromEntries(this.nudgesFollowed),
      resource_reads: Object.fromEntries(this.resourceReads),
    };
  }

  private bump(m: Map<string, number>, k: string) {
    m.set(k, (m.get(k) ?? 0) + 1);
  }
}
```

- [ ] **Step 4: Hook into `registerTools` and resources**

In `server.ts` `registerTools`, accept a `Metrics` instance, call `metrics.incToolCall(tool.name)` at the start of the handler, and after enrichment if a nudge was added (the enricher returns a small `meta` flag) call `metrics.incNudgeDisplayed(tool.name)`.

Update `ContextEnricher.enrich` to return both content and a `{ nudged: boolean }` indicator (small change to the signature; update tests).

In each resource's `register` function, accept `metrics` and call `incResourceRead(URI)` inside the handler.

Follow-through detection (`incNudgeFollowed`): track per-session the last tool that received a nudge; when the next tool call is a graph-side tool (`node_expand`, `hunt_run`, etc.) within the same `ToolContext`, increment.

- [ ] **Step 5: Build + run — expect PASS**

- [ ] **Step 6: Commit**

```
git add platform/mcp/src/lib/metrics.ts platform/mcp/src/server.ts platform/mcp/src/resources/ \
        platform/mcp/src/lib/context-enricher.ts platform/mcp/tests/contract/metrics.test.ts
git commit -m "feat(mcp): metrics counters for tool calls, nudges, resource reads, followthrough"
```

---

### Task 18: Performance bisection harness

**Files:**
- Create: `platform/mcp/tests/perf/bisection.test.ts`
- Create: `scripts/perf-bisect.sh`

- [ ] **Step 1: Record a sample session script**

```typescript
// platform/mcp/tests/perf/bisection.test.ts
import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";

const SCENARIO = [
  { tool: "sentinel_seed", args: { ioc: "203.0.113.42", type: "IP" } },
  { tool: "node_expand",   args: { entity: "203.0.113.42" } },
  { tool: "sentinel_query", args: { query: "SecurityAlert | take 10", ingest: false } },
  { tool: "hunt_run",      args: { seed: "203.0.113.42", depth: 3 } },
];

test.skip("bisection: enrich on vs off — manual gate (300ms p95, 15% tokens)", async () => {
  // This test is opt-in: run with PERF_BISECT=1 npm run test:contract
  if (!process.env.PERF_BISECT) return;
  const off = await runScenario({ enrich: false });
  const on  = await runScenario({ enrich: true });
  const overhead = on.p95LatencyMs - off.p95LatencyMs;
  const tokenDelta = (on.totalTokens - off.totalTokens) / off.totalTokens;
  console.log("overhead p95 (ms):", overhead, "token delta (%):", tokenDelta * 100);
  assert.ok(overhead < 300, `enrich p95 overhead ${overhead}ms exceeds 300ms gate`);
  assert.ok(tokenDelta < 0.15, `enrich token delta ${tokenDelta * 100}% exceeds 15% gate`);
});

async function runScenario(opts: { enrich: boolean }) {
  // Spawn the MCP server with the right env, drive it via stdio with SCENARIO,
  // collect per-call durations and total response token estimate, return stats.
  // Implementation left to the executor — keep it under 100 lines, no heavy deps.
  return { p95LatencyMs: 0, totalTokens: 0 }; // placeholder shape; real impl in this task
}
```

NOTE: The full `runScenario` body is the engineer's job in this task — drive the MCP server via stdio using `@modelcontextprotocol/sdk/client/stdio.js`, time each tool call, sum the size (chars) of response content as a token proxy. Keep under 100 lines.

- [ ] **Step 2: Add the convenience script**

```bash
#!/usr/bin/env bash
# scripts/perf-bisect.sh
set -euo pipefail
cd platform/mcp
echo "=== baseline (GH_MCP_ENRICH=off) ==="
PERF_BISECT=1 GH_MCP_ENRICH=off npm run test:contract -- --test-name-pattern bisection
echo "=== treatment (GH_MCP_ENRICH=on) ==="
PERF_BISECT=1 GH_MCP_ENRICH=on  npm run test:contract -- --test-name-pattern bisection
```

`chmod +x scripts/perf-bisect.sh`.

- [ ] **Step 3: Document the merge gate in the spec doc**

Add a "How to run the perf gate" subsection under "Testing strategy" in the design spec pointing to `scripts/perf-bisect.sh`. (Edit the spec file.)

- [ ] **Step 4: Commit**

```
git add platform/mcp/tests/perf/bisection.test.ts scripts/perf-bisect.sh docs/superpowers/specs/2026-06-19-graph-visible-sentinel-design.md
git commit -m "test: perf bisection harness (300ms p95 / 15% tokens merge gate)"
```

---

## Wrap-up: full-suite check

- [ ] **Step 1: Run the entire backend suite**

```
cargo test --package graph-hunter-api
cargo test --package graph-hunter-core
```

Expected: all pass.

- [ ] **Step 2: Run the full MCP contract suite**

```
cd platform/mcp && npm run build && npm run test:contract
```

Expected: all pass.

- [ ] **Step 3: Run the perf gate**

```
bash scripts/perf-bisect.sh
```

Expected: enrich p95 overhead < 300 ms; token delta < 15%.

- [ ] **Step 4: Final commit (if any cleanup)**

```
git status   # confirm clean
```

---

## Self-review notes (executed at plan-writing time)

- **Spec coverage:** every section of the spec maps to at least one task:
  - "Component 1 — MCP Resources" → Task 10
  - "Component 2 — ContextEnricher" → Tasks 11–14, wired in Task 15
  - "Component 3 — Backend endpoints" → Tasks 1, 2, 4, 5, 6, 7
  - "Schema versioning" → Tasks 8, 16
  - "Testing strategy" → in-task tests + Task 18 (perf bisection)
  - "Metrics of success" → Task 17 (instrumentation; the targets themselves are evaluated at rollout)
  - "Per-type counters" → Task 3
  - Rollout (dogfood → beta → default-on) is operational, not implemented in code; not a task.
- **Placeholder scan:** the only "fill in" zones are flagged with NOTE blocks pointing to existing-API discovery — they are decisions the engineer takes when they reach the code, not vague gaps:
  - Task 1 Step 5: route registration site to be found via `git grep`.
  - Task 2 Step 3: graph handle's `totals_by_type` and source registry method names must match existing APIs.
  - Task 3 Pre-step: counters may already exist; the task degrades gracefully if so.
  - Task 7 Step 4: graph-handle lookup methods to be matched against existing names.
  - Task 18 Step 1: `runScenario` body left to the executor with a clear contract.
- **Type consistency:** all DTO names match between Rust (`GraphSummary`, `OverlapResponse`, `RecentPivot`, etc.) and the zod schemas in `graph-state-client.ts`. `RecentPivot` uses `kind` (Rust) ↔ `type` (JSON) via `#[serde(rename = "type")]` — consistent with what the zod schema expects.
