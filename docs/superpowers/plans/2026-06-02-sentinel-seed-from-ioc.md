# Sentinel Seed from IoC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An MCP cold-start primitive `sentinel_seed(entity_type, value, lookback)` that pulls everything Sentinel knows about a known IoC, ingests it into the graph (auto-creating a session if none), and returns the seeded neighborhood + top anomalies — so an LLM can START a hunt against an empty GraphHunter.

**Architecture:** Composition over the existing hydration engine. A new `seed_from_ioc` operation validates the entity type, ensures a session, calls the existing `hydrate_node_with` (parametrized with a "Sentinel Seed" dataset tag), then `expand_node` on the seeded node, then sorts the neighborhood by score for top anomalies. Exposed via `POST /sentinel/seed` and the MCP tool `sentinel_seed`. One engine, two doors (this + live-expand both end in `hydrate_node_with`).

**Tech Stack:** Rust (platform/api), Tauri (axum HTTP), TypeScript (MCP, zod).

---

## Spec reconciliation (one refinement over `2026-06-02-sentinel-seed-from-ioc-design.md`)

- **§5 type validation:** `parse_entity_type` returns `Other(s)` (never `None`) for non-empty unknown strings, so the spec's two cases (unknown→InvalidInput, unmapped-valid→skip) collapse cleanly: any `entity_type` whose `sentinel_entity_targets(ty)` is empty (Domain/URL/Registry/Service/Other) → **`InvalidInput`** with the 5-type list. The MCP zod enum already prevents anything but the 5 seedable types reaching this, so this only hardens the raw HTTP route.

## File Structure

| File | Responsibility | Change |
|------|----------------|--------|
| `platform/api/src/operations/sentinel.rs` | `hydrate_node_with` gains `dataset_tag`; new `seed_from_ioc_with` (generic) + `seed_from_ioc` (public) | Modify |
| `platform/api/src/operations/graph_ops.rs` | update `hydrate_node_with` call site (pass tag) | Modify |
| `platform/api/src/dto/v1/sentinel.rs` | `SeedFromIocRequest` + `SeedResult` DTOs | Modify |
| `apps/tauri/src-tauri/src/http/siem.rs` | `handler_seed_from_ioc` | Modify |
| `apps/tauri/src-tauri/src/http/mod.rs` | route `POST /sentinel/seed` | Modify |
| `platform/mcp/src/tools/sentinel/seed.ts` | MCP tool `sentinel_seed` | Create |
| `platform/mcp/src/tools/sentinel/index.ts` | `sentinelTools` export | Create |
| `platform/mcp/src/registry.ts` | register `sentinelTools` | Modify |

## Build/test commands (no cargo workspace)
- API tests: `cargo test --manifest-path platform/api/Cargo.toml --lib seed`
- API full lib: `cargo test --manifest-path platform/api/Cargo.toml --lib`
- Tauri check: `cargo check --manifest-path apps/tauri/src-tauri/Cargo.toml`
- MCP typecheck: from `platform/mcp/`, `npx tsc --noEmit`

---

## Task 1: Parametrize `hydrate_node_with` with a `dataset_tag`

**Files:**
- Modify: `platform/api/src/operations/sentinel.rs` (`hydrate_node_with`)
- Modify: `platform/api/src/operations/graph_ops.rs` (the `expand_node_live` call site)

Pure refactor, no behavior change — existing tests must stay green.

- [ ] **Step 1: Change the signature + use the param**

In `hydrate_node_with`, remove the line `const HYDRATION_DATASET: &str = "Sentinel Hydration (live)";` and add a parameter. New signature (add `dataset_tag: &str` as the LAST param):
```rust
    #[allow(clippy::too_many_arguments)]
    pub async fn hydrate_node_with<T: SentinelTransport>(
        &self,
        transport: &T,
        token_cache: &SentinelTokenCache,
        value: &str,
        entity_type: &EntityType,
        time_filter: &str,
        workspace_id: &str,
        auth: &SentinelAuth,
        dataset_tag: &str,
    ) -> ApiResult<graph_hunter_core::analytics::HydrationOutcome> {
```
Replace the `insert_triples(triples, Some(HYDRATION_DATASET))` call with `insert_triples(triples, Some(dataset_tag))`.

- [ ] **Step 2: Update the production call site**

In `platform/api/src/operations/graph_ops.rs`, `expand_node_live` calls `self.hydrate_node_with(&transport, &cache, &req.node_id, &ty, &time_filter, &ws, &auth)`. Add the tag arg:
```rust
                self.hydrate_node_with(&transport, &cache, &req.node_id, &ty, &time_filter, &ws, &auth, "Sentinel Hydration (live)")
```

- [ ] **Step 3: Update the two existing hydrate tests**

In `platform/api/src/operations/sentinel.rs` `hydrate_tests`, both `.hydrate_node_with(...)` calls gain a final arg `, "Sentinel Hydration (live)"`. (There are exactly two — the IP test and the Domain/unmapped test.)

- [ ] **Step 4: Verify no behavior change**

Run: `cargo test --manifest-path platform/api/Cargo.toml --lib hydrate`
Expected: the existing hydrate tests still PASS (now passing the tag explicitly).
Run: `cargo test --manifest-path platform/api/Cargo.toml --lib expand_live`
Expected: still PASS.

- [ ] **Step 5: Commit**
```bash
git add platform/api/src/operations/sentinel.rs platform/api/src/operations/graph_ops.rs
git commit -m "refactor(api): hydrate_node_with takes explicit dataset_tag"
```

---

## Task 2: `SeedFromIocRequest` + `SeedResult` DTOs

**Files:**
- Modify: `platform/api/src/dto/v1/sentinel.rs`

- [ ] **Step 1: Add the DTOs**

Append to `platform/api/src/dto/v1/sentinel.rs` (it already imports `SessionHandle` and `serde`; `TimeWindow` is defined in this same file):
```rust
// ── Cold-start seed from a known IoC (MCP-first) ───────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SeedFromIocRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    /// One of: "IP" | "User" | "Host" | "Process" | "File".
    pub entity_type: String,
    /// The IoC value (e.g. "10.0.0.9", "alice@corp.com").
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_window: Option<TimeWindow>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SeedResult {
    pub hydration: graph_hunter_core::analytics::HydrationOutcome,
    pub neighborhood: graph_hunter_core::analytics::Neighborhood,
    /// Top-N seeded neighborhood nodes by anomaly score (descending).
    pub top_anomalies: Vec<graph_hunter_core::analytics::NeighborNode>,
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check --manifest-path platform/api/Cargo.toml`
Expected: clean (the referenced core types are public; confirm the `graph_hunter_core` crate is already a dependency — it is, used elsewhere in this crate).

- [ ] **Step 3: Commit**
```bash
git add platform/api/src/dto/v1/sentinel.rs
git commit -m "feat(api): SeedFromIocRequest + SeedResult DTOs"
```

---

## Task 3: `seed_from_ioc` operation (generic + public) with tests

**Files:**
- Modify: `platform/api/src/operations/sentinel.rs`
- Test: same file, `#[cfg(test)] mod seed_tests`

The generic `seed_from_ioc_with<T>` is mock-testable; the public `seed_from_ioc` resolves creds/session and builds the real transport.

- [ ] **Step 1: Write the failing tests**

Add to `platform/api/src/operations/sentinel.rs`. Reuse the `MockTransport` + `one_signin_row()` helpers from `hydrate_tests` (move them to a shared `#[cfg(test)]` location in the file if they are private to `hydrate_tests` — e.g. lift `MockTransport`, `one_signin_row` to a `#[cfg(test)] mod test_support` and `use super::test_support::*;` in both modules. If lifting is awkward, redefine a minimal copy in `seed_tests`.):
```rust
#[cfg(test)]
mod seed_tests {
    use super::*;
    use crate::dto::v1::sentinel::SeedFromIocRequest;
    use crate::dto::session::CreateSessionRequest;

    // Minimal local mock (or reuse the one from hydrate_tests).
    struct MockTransport { response: serde_json::Value }
    impl graph_hunter_siem::SentinelTransport for MockTransport {
        async fn acquire_token(&self, _t: &str, _c: &str, _s: &str)
            -> Result<graph_hunter_siem::TokenResponse, String> {
            Ok(graph_hunter_siem::TokenResponse { access_token: "tok".into(), expires_in: 3600 })
        }
        async fn execute_query(&self, _ws: &str, _q: &str, _b: &str)
            -> Result<serde_json::Value, String> { Ok(self.response.clone()) }
    }
    fn one_signin_row() -> serde_json::Value {
        serde_json::json!({ "tables": [{ "name": "PrimaryResult",
            "columns": [{"name":"TimeGenerated"},{"name":"Type"},{"name":"UserPrincipalName"},{"name":"IPAddress"},{"name":"ResultType"}],
            "rows": [["2026-06-02T10:00:00Z","SigninLogs","alice@corp.com","10.0.0.9","0"]] }] })
    }

    #[tokio::test]
    async fn seed_ip_populates_neighborhood_and_ranks_anomalies() {
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest { name: Some("seed-test".into()) }).expect("session");
        let transport = MockTransport { response: one_signin_row() };
        let cache = graph_hunter_siem::SentinelTokenCache::new();
        let auth = SentinelAuth { tenant_id:"t".into(), client_id:"c".into(), client_secret:"s".into() };

        let result = api.seed_from_ioc_with(
            &transport, &cache,
            "10.0.0.9", &graph_hunter_core::types::EntityType::IP,
            "where TimeGenerated > ago(24h)", "ws-1", &auth,
        ).await.expect("seed");

        assert!(!result.hydration.skipped);
        assert!(result.hydration.new_relations >= 1);
        assert_eq!(result.neighborhood.center, "10.0.0.9");
        assert!(!result.neighborhood.nodes.is_empty(), "expected a populated neighborhood");
        // top_anomalies is sorted descending by score and capped at 5.
        assert!(result.top_anomalies.len() <= 5);
        for w in result.top_anomalies.windows(2) {
            assert!(w[0].score >= w[1].score, "top_anomalies must be score-descending");
        }
    }

    #[tokio::test]
    async fn seed_without_session_auto_creates_one() {
        // No AZURE_* creds and no session: public path auto-creates a session,
        // hydration soft-skips, neighborhood is empty — but the session exists.
        for k in ["AZURE_WORKSPACE_ID","AZURE_TENANT_ID","AZURE_CLIENT_ID","AZURE_CLIENT_SECRET"] {
            // SAFETY: no other test in this binary reads AZURE_* from the env.
            unsafe { std::env::remove_var(k); }
        }
        let api = GraphHunterApi::new_noop();
        // deliberately DO NOT create a session
        let result = api.seed_from_ioc(SeedFromIocRequest {
            session: None, entity_type: "IP".into(), value: "10.0.0.9".into(), time_window: None,
        }).await.expect("seed");
        assert!(result.hydration.skipped, "no creds → skipped");
        let session = api.sessions().current_session().expect("a session was auto-created");
        assert!(session.name.contains("Sentinel Seed"), "auto-created session named for the seed");
    }

    #[tokio::test]
    async fn seed_rejects_unseedable_type() {
        let api = GraphHunterApi::new_noop();
        let err = api.seed_from_ioc(SeedFromIocRequest {
            session: None, entity_type: "Domain".into(), value: "evil.com".into(), time_window: None,
        }).await.unwrap_err();
        match err { ApiError::InvalidInput(_) => {}, other => panic!("expected InvalidInput, got {other:?}") }
    }
}
```
Note: confirm the `Session` struct exposes `name` (used in the auto-create assertion). If the field is named differently (e.g. `session.info().name`), adjust the assertion to read the real accessor. Run → expect FAIL (`seed_from_ioc_with` / `seed_from_ioc` not found).

- [ ] **Step 2: Run tests to confirm they fail**

Run: `cargo test --manifest-path platform/api/Cargo.toml --lib seed`
Expected: FAIL (methods not found).

- [ ] **Step 3: Implement both methods**

Ensure imports at the top of `operations/sentinel.rs` include `use crate::util::parse_entity_type;` and `use crate::dto::v1::sentinel::{SeedFromIocRequest, SeedResult};` (and `CreateSessionRequest`, `ExpandNodeRequest` as needed). Add inside `impl GraphHunterApi`:
```rust
    /// Generic seed engine (mockable). Assumes the entity type is valid
    /// and a session is current. Hydrates the IoC, expands its node, and
    /// ranks the neighborhood by anomaly score.
    #[allow(clippy::too_many_arguments)]
    pub async fn seed_from_ioc_with<T: SentinelTransport>(
        &self,
        transport: &T,
        token_cache: &SentinelTokenCache,
        value: &str,
        entity_type: &EntityType,
        time_filter: &str,
        workspace_id: &str,
        auth: &SentinelAuth,
    ) -> ApiResult<SeedResult> {
        let hydration = self
            .hydrate_node_with(transport, token_cache, value, entity_type, time_filter, workspace_id, auth, "Sentinel Seed")
            .await?;
        let neighborhood = self.seeded_neighborhood(value)?;
        let top_anomalies = Self::rank_top_anomalies(&neighborhood, 5);
        Ok(SeedResult { hydration, neighborhood, top_anomalies })
    }

    /// Public cold-start entry: validate type → ensure session →
    /// resolve creds (skip if absent) → hydrate+expand+rank.
    pub async fn seed_from_ioc(&self, req: SeedFromIocRequest) -> ApiResult<SeedResult> {
        use graph_hunter_core::analytics::HydrationOutcome;
        use graph_hunter_core::sentinel::sentinel_entity_targets;

        // 1. Validate the type is one of the 5 Sentinel-seedable types.
        let ty = parse_entity_type(&req.entity_type)
            .filter(|t| !sentinel_entity_targets(t).is_empty())
            .ok_or_else(|| ApiError::InvalidInput(format!(
                "entity_type must be one of IP, User, Host, Process, File (got '{}')",
                req.entity_type
            )))?;

        // 2. Ensure a session (auto-create for cold-start).
        if self.sessions().current_session().is_none() {
            self.create_session(crate::dto::session::CreateSessionRequest {
                name: Some(format!("Sentinel Seed: {}", req.value)),
            })?;
        }

        let time_filter = req.time_window.as_ref().map(|w| w.kql_filter())
            .unwrap_or_else(|| "where TimeGenerated > ago(24h)".to_string());

        // 3. Resolve creds from env; skip hydration if any is missing.
        let creds = (
            std::env::var("AZURE_WORKSPACE_ID").ok(),
            std::env::var("AZURE_TENANT_ID").ok(),
            std::env::var("AZURE_CLIENT_ID").ok(),
            std::env::var("AZURE_CLIENT_SECRET").ok(),
        );
        match creds {
            (Some(ws), Some(tenant), Some(client), Some(secret)) => {
                let transport = graph_hunter_siem::HttpSentinelTransport::new();
                let cache = graph_hunter_siem::SentinelTokenCache::new();
                let auth = SentinelAuth { tenant_id: tenant, client_id: client, client_secret: secret };
                self.seed_from_ioc_with(&transport, &cache, &req.value, &ty, &time_filter, &ws, &auth).await
            }
            _ => {
                let neighborhood = self.seeded_neighborhood(&req.value)?;
                let top_anomalies = Self::rank_top_anomalies(&neighborhood, 5);
                Ok(SeedResult {
                    hydration: HydrationOutcome {
                        skipped: true,
                        reason: Some("Azure credentials not configured (set AZURE_* or connect Sentinel)".into()),
                        new_entities: 0, new_relations: 0, tables_hit: 0, tables_attempted: 0,
                    },
                    neighborhood,
                    top_anomalies,
                })
            }
        }
    }

    /// Build the neighborhood of the seeded node, or an empty centered
    /// neighborhood if the node was not created (empty/failed hydration).
    fn seeded_neighborhood(&self, value: &str) -> ApiResult<graph_hunter_core::analytics::Neighborhood> {
        let exists = {
            let session = self.sessions().current_session()
                .ok_or_else(|| ApiError::InvalidState("no session".into()))?;
            let g = session.graph.read()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            g.get_entity(value).is_some()
        };
        if exists {
            self.expand_node(crate::dto::v1::graph_ops::ExpandNodeRequest {
                session: None, node_id: value.to_string(),
                max_hops: Some(1), max_nodes: Some(50), filter: None,
                live: false, time_window: None,
            })
        } else {
            Ok(graph_hunter_core::analytics::Neighborhood {
                center: value.to_string(), nodes: vec![], edges: vec![],
                truncated: false, auto_grouped: false, auto_group_reason: None, hydration: None,
            })
        }
    }

    fn rank_top_anomalies(
        hood: &graph_hunter_core::analytics::Neighborhood, n: usize,
    ) -> Vec<graph_hunter_core::analytics::NeighborNode> {
        let mut nodes = hood.nodes.clone();
        nodes.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        nodes.truncate(n);
        nodes
    }
```
Adjust import paths to whatever compiles (`ExpandNodeRequest` path, `parse_entity_type`). If `expand_node` lives in a different `impl` block, that's fine — it's the same type.

- [ ] **Step 4: Run tests to confirm they pass**

Run: `cargo test --manifest-path platform/api/Cargo.toml --lib seed`
Expected: all 3 PASS.
Run: `cargo test --manifest-path platform/api/Cargo.toml --lib`
Expected: no regressions.

- [ ] **Step 5: Commit**
```bash
git add platform/api/src/operations/sentinel.rs
git commit -m "feat(api): seed_from_ioc — MCP cold-start from a known IoC"
```

---

## Task 4: HTTP route `POST /sentinel/seed`

**Files:**
- Modify: `apps/tauri/src-tauri/src/http/siem.rs`
- Modify: `apps/tauri/src-tauri/src/http/mod.rs`

- [ ] **Step 1: Add the handler**

In `apps/tauri/src-tauri/src/http/siem.rs`, mirror `handler_run_kql`. Add a body struct + handler:
```rust
#[derive(serde::Deserialize)]
pub(super) struct SeedBody {
    pub entity_type: String,
    pub value: String,
    #[serde(default)]
    pub lookback: Option<String>,
}

/// Cold-start the graph from a known Sentinel IoC. Pulls the IoC's
/// events, ingests them, returns the seeded neighborhood + anomalies.
pub(super) async fn handler_seed_from_ioc(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<SeedBody>,
) -> Response {
    let time_window = lookback_to_window(body.lookback.as_deref());
    let result = tokio::time::timeout(
        Duration::from_secs(120),
        api.seed_from_ioc(graph_hunter_api::dto::sentinel::SeedFromIocRequest {
            session: None,
            entity_type: body.entity_type,
            value: body.value,
            time_window,
        }),
    )
    .await;
    match result {
        Ok(Ok(v)) => ok_json(v),
        Ok(Err(e)) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
        Err(_) => err_json("Sentinel seed timed out (120s)"),
    }
}

/// Lookback preset → TimeWindow. Mirrors the helper in http/graph.rs.
fn lookback_to_window(lookback: Option<&str>) -> Option<graph_hunter_api::dto::sentinel::TimeWindow> {
    use graph_hunter_api::dto::sentinel::{LookbackPreset, TimeWindow};
    let preset = match lookback? {
        "1h" => LookbackPreset::H1, "6h" => LookbackPreset::H6, "24h" => LookbackPreset::H24,
        "7d" => LookbackPreset::D7, "30d" => LookbackPreset::D30, _ => return None,
    };
    Some(TimeWindow::Preset { lookback: preset })
}
```
(If `lookback_to_window` is already `pub(super)` in `http/graph.rs`, import and reuse it instead of redefining — check; DRY. If it's private to graph.rs, the small redefinition here is acceptable.)

- [ ] **Step 2: Register the route**

In `apps/tauri/src-tauri/src/http/mod.rs`, near the `/kql` routes (~line 168), add:
```rust
        .route("/sentinel/seed", post(siem::handler_seed_from_ioc))
```
(Confirm `post` is imported — it is, used by `/kql`.)

- [ ] **Step 3: Verify**

Run: `cargo check --manifest-path apps/tauri/src-tauri/Cargo.toml`
Expected: clean. (The frontend `dist/` must exist in the workspace for the tauri build macro — if `cargo check` fails ONLY with a `frontendDist`/`../dist` macro panic, copy the built `dist` into `apps/tauri/dist/` from a prior build and re-run; that is an environment artifact, not a code error.)

- [ ] **Step 4: Commit**
```bash
git add apps/tauri/src-tauri/src/http/siem.rs apps/tauri/src-tauri/src/http/mod.rs
git commit -m "feat(tauri): POST /sentinel/seed cold-start route"
```

---

## Task 5: MCP tool `sentinel_seed`

**Files:**
- Create: `platform/mcp/src/tools/sentinel/seed.ts`
- Create: `platform/mcp/src/tools/sentinel/index.ts`
- Modify: `platform/mcp/src/registry.ts`

- [ ] **Step 1: Create the tool**

`platform/mcp/src/tools/sentinel/seed.ts` (mirror the `defineTool` shape used in `tools/node/expand.ts`; POST to `/sentinel/seed`):
```ts
import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  entity_type: z
    .enum(["IP", "User", "Host", "Process", "File"])
    .describe("Type of the IoC you are seeding from."),
  value: z.string().max(1000).describe("The IoC value, e.g. an IP, UPN, hostname, or path."),
  lookback: z
    .enum(["1h", "6h", "24h", "7d", "30d"])
    .optional()
    .describe("Time window to pull from Sentinel (default 24h)."),
});

export const sentinelSeed = defineTool({
  name: "sentinel_seed",
  description:
    "Cold-start a hunt from a known Sentinel IoC. Pulls every event touching the IoC (IP/User/Host/Process/File) in the lookback window, ingests it into the graph (auto-creating a session if needed), and returns the seeded neighborhood + top anomalies. Use this FIRST when the graph is empty, then hunt_run / node_expand from the seeded nodes.",
  category: "sentinel",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { entity_type, value, lookback }) {
    const body: Record<string, unknown> = { entity_type, value };
    if (lookback) body.lookback = lookback;
    return ctx.api.post("/sentinel/seed", body, HEAVY);
  },
});
```
Confirm the api-client exposes `post(path, body, HEAVY)` — check `platform/mcp/src/lib/api-client.js`/`.ts`. If the signature differs (e.g. `ctx.api.post(path, body)` without the HEAVY arg, or a different method), match the existing POST-using tool (e.g. an ingest tool that POSTs) verbatim.

- [ ] **Step 2: Create the category index**

`platform/mcp/src/tools/sentinel/index.ts`:
```ts
import type { Tool } from "../../lib/types.js";
import { sentinelSeed } from "./seed.js";

export const sentinelTools: Tool[] = [sentinelSeed];
```

- [ ] **Step 3: Register in the catalog**

In `platform/mcp/src/registry.ts`, add the import alongside the others:
```ts
import { sentinelTools } from "./tools/sentinel/index.js";
```
and add `...sentinelTools,` to the `registry` array (after `...ingestTools,` is a sensible stable position).

- [ ] **Step 4: Verify**

Run: from `platform/mcp/`, `npx tsc --noEmit`
Expected: no TypeScript errors. (Run `npm install` first if `tsc` is not present in the workspace.)

- [ ] **Step 5: Commit**
```bash
git add platform/mcp/src/tools/sentinel/ platform/mcp/src/registry.ts
git commit -m "feat(mcp): sentinel_seed cold-start tool"
```

---

## Task 6: Verification gate

**Files:** none (verification only)

- [ ] **Step 1: API suite**

Run: `cargo test --manifest-path platform/api/Cargo.toml --lib`
Expected: all green incl. `seed_tests` (3) and the unchanged `hydrate_tests`/`expand_live_tests`.

- [ ] **Step 2: Tauri + MCP**

Run: `cargo check --manifest-path apps/tauri/src-tauri/Cargo.toml` (clean) and `npx tsc --noEmit` in `platform/mcp/` (clean).

- [ ] **Step 3: Real Azure smoke (operator, with creds + Sentinel access)**

From an MCP client with `AZURE_*` set: `sentinel_seed(entity_type="IP", value="<a real IP from your workspace>", lookback="24h")`. Confirm the response has `hydration.skipped=false` with non-zero `tables_attempted`, a populated `neighborhood`, and `top_anomalies` sorted by score. Then `node_expand` / `hunt_run` from a returned node to confirm the seed → hunt → expand loop works end-to-end over MCP.

- [ ] **Step 4: Empty-graph cold-start check**

With no session loaded, call `sentinel_seed` and confirm a session named `"Sentinel Seed: <value>"` is created and the seeded data is queryable via `graph_summary`.

---

## Self-review notes

- **Spec coverage:** §2 objective (T3 + T4 + T5 = the MCP loop entry); §3 decisions — IoC/explicit-type (T3 validation + T5 enum), retorno outcome+vecindario+anomalías (T3 `SeedResult`), composición (T3 reuses `hydrate_node_with`+`expand_node`), auto-create session (T3 + test), dataset tag (T1 + T3 passes "Sentinel Seed"), top-5 NeighborNode (T3 `rank_top_anomalies`), exposure (T4 route + T5 tool); §5 gating (T3: InvalidInput for unseedable, skip for no-creds; refinement documented); §6 testing (T3 tests + T6).
- **Type consistency:** `seed_from_ioc_with` arg order matches its call in `seed_from_ioc`; `SeedResult` fields identical across DTO (T2) and construction (T3); `hydrate_node_with`'s new `dataset_tag` param (T1) is passed by every caller (expand_node_live, both hydrate tests, seed_from_ioc_with).
- **Known soft spots flagged for the engineer:** lift-or-copy of `MockTransport`/`one_signin_row` test helpers (T3 Step 1); `Session.name` accessor name (T3 test assertion); `ctx.api.post` signature (T5 Step 1); `lookback_to_window` DRY vs redefine (T4); the `frontendDist`/`dist` env artifact for the tauri check (T4 Step 3).
