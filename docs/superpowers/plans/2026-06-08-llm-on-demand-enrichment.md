# LLM On-Demand Enrichment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give an LLM (Claude Desktop / any MCP client) three new tools to enrich the graph on demand from Azure Sentinel without polling: `node_enrich` (selective pull for one node), `sentinel_query` (free KQL, dual inspect/ingest), and `sentinel_status` (read-only connection state).

**Architecture:** Reuse the existing hydration machinery (`hydrate_node_with` + `sentinel_entity_targets` + `build_hydration_kql`) behind a new `HydrationFilter` (no new query-builder). `run_kql` grows a non-destructive inspect mode. All three are exposed as API ops → HTTP routes → MCP tools, mirroring the shipped `sentinel_seed` plumbing.

**Tech Stack:** Rust (per-crate `--manifest-path`, no workspace), axum HTTP server (127.0.0.1:37891), TypeScript MCP server (`platform/mcp`, runs from compiled `dist/`).

**Spec:** `docs/superpowers/specs/2026-06-05-llm-on-demand-enrichment-design.md`

**Cross-cutting reminders:**
- No cargo workspace — always pass `--manifest-path <crate>/Cargo.toml`.
- The MCP server runs from `dist/`. After any `platform/mcp/src` change you MUST `npm run build` (in `platform/mcp`) and the user must restart the MCP client; the tool won't appear otherwise.
- Commit message trailer on every commit: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

---

## Task 1: `HydrationFilter` + filtered hydration (core of `node_enrich`)

Add a filter that restricts which Sentinel tables are queried and caps rows per table, threaded through the hydration path **without changing the existing public signature** (so the live-expand and seed call sites and their tests are untouched).

**Files:**
- Modify: `platform/api/src/operations/sentinel.rs` (add `HydrationFilter`, refactor `hydrate_node_with` to delegate to a new `hydrate_node_filtered_with`)
- Test: `platform/api/src/operations/sentinel.rs` (test module, mirrors `hydrate_ip_issues_three_table_queries_and_ingests` at ~line 997)

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod` in `sentinel.rs` (near the other hydrate tests). Reuses the existing `MockTransport` and `one_signin_row()` helpers already in that module.

```rust
    #[tokio::test]
    async fn hydrate_filter_restricts_tables_and_caps_rows() {
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("enrich-test".into()),
        })
        .expect("create_session");
        let transport = MockTransport {
            queries: Mutex::new(vec![]),
            response: one_signin_row(),
        };
        let cache = graph_hunter_siem::SentinelTokenCache::new();

        let filter = HydrationFilter {
            tables: Some(vec!["SigninLogs".to_string()]),
            max_rows: Some(100),
        };
        let outcome = api
            .hydrate_node_filtered_with(
                &transport,
                &cache,
                "10.0.0.9",
                &graph_hunter_core::types::EntityType::IP,
                "where TimeGenerated > ago(24h)",
                "ws-1",
                &SentinelAuth {
                    tenant_id: "t".into(),
                    client_id: "c".into(),
                    client_secret: "s".into(),
                },
                "Sentinel Enrich",
                Some(&filter),
            )
            .await
            .expect("hydrate filtered");

        let queries = transport.queries.lock().unwrap();
        // IP maps to 3 tables; the filter narrows to SigninLogs only -> 1 query.
        assert_eq!(queries.len(), 1, "filter must restrict to one table");
        assert!(queries[0].contains("SigninLogs"), "query: {}", queries[0]);
        assert!(queries[0].contains("take 100"), "max_rows must cap take: {}", queries[0]);
        assert_eq!(outcome.tables_attempted, 1);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --manifest-path platform/api/Cargo.toml --lib hydrate_filter_restricts 2>&1 | tail -20`
Expected: FAIL to compile — `HydrationFilter` and `hydrate_node_filtered_with` don't exist yet.

- [ ] **Step 3: Add the `HydrationFilter` struct**

Add near the top of `sentinel.rs` (after the `use` block, before `impl GraphHunterApi` or alongside other public types):

```rust
/// Narrows a node hydration to a subset of its mapped Sentinel tables
/// and caps the rows pulled per table. `None` fields mean "no
/// restriction" — a fully-`None` filter behaves exactly like the
/// unfiltered hydration.
#[derive(Debug, Clone, Default)]
pub struct HydrationFilter {
    /// Restrict to these tables (case-insensitive match against the
    /// type's mapped tables). `None` = all mapped tables.
    pub tables: Option<Vec<String>>,
    /// Cap rows per table (`| take N`). `None` = the default
    /// `HYDRATION_TAKE`.
    pub max_rows: Option<u32>,
}
```

- [ ] **Step 4: Refactor `hydrate_node_with` to delegate, and move the body into `hydrate_node_filtered_with`**

Find `pub async fn hydrate_node_with` (~line 452). Replace the whole method with a thin delegate plus the new filtered method holding the (modified) body:

```rust
    /// Unfiltered node hydration (live-expand + seed call this).
    /// Delegates to [`Self::hydrate_node_filtered_with`] with no filter,
    /// preserving the exact prior behavior.
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
        self.hydrate_node_filtered_with(
            transport, token_cache, value, entity_type, time_filter, workspace_id, auth,
            dataset_tag, None,
        )
        .await
    }

    /// Node hydration with an optional [`HydrationFilter`] that narrows
    /// the tables queried and caps rows per table. `filter = None` is
    /// identical to the unfiltered path.
    #[allow(clippy::too_many_arguments)]
    pub async fn hydrate_node_filtered_with<T: SentinelTransport>(
        &self,
        transport: &T,
        token_cache: &SentinelTokenCache,
        value: &str,
        entity_type: &EntityType,
        time_filter: &str,
        workspace_id: &str,
        auth: &SentinelAuth,
        dataset_tag: &str,
        filter: Option<&HydrationFilter>,
    ) -> ApiResult<graph_hunter_core::analytics::HydrationOutcome> {
        use graph_hunter_core::analytics::HydrationOutcome;

        let all_targets = sentinel_entity_targets(entity_type);
        if all_targets.is_empty() {
            return Ok(HydrationOutcome {
                skipped: true,
                reason: Some(format!("no Sentinel column mapping for type {entity_type}")),
                new_entities: 0,
                new_relations: 0,
                tables_hit: 0,
                tables_attempted: 0,
            });
        }

        // Apply the table filter (case-insensitive). Requested tables that
        // aren't mapped for this type are simply not queried (no error).
        let requested: Option<Vec<String>> = filter.and_then(|f| f.tables.clone());
        let targets: Vec<(&'static str, &'static [&'static str])> = all_targets
            .iter()
            .copied()
            .filter(|(table, _)| match &requested {
                Some(list) => list.iter().any(|t| t.eq_ignore_ascii_case(table)),
                None => true,
            })
            .collect();

        let take: u32 = filter.and_then(|f| f.max_rows).unwrap_or(5000);

        let token = token_cache
            .get_or_refresh(transport, auth)
            .await
            .map_err(|e| ApiError::Upstream {
                service: "sentinel-auth".into(),
                message: e,
            })?;

        let parser = make_parser_for_format("sentinel").map_err(ApiError::InvalidInput)?;
        let session = self
            .sessions()
            .current_session()
            .ok_or_else(|| ApiError::InvalidState("No current session.".into()))?;

        let mut tables_hit = 0usize;
        let mut new_e = 0usize;
        let mut new_r = 0usize;
        let tables_attempted = targets.len();

        for (table, columns) in &targets {
            let kql = build_hydration_kql(table, columns, value, time_filter, take);
            match transport.execute_query(workspace_id, &kql, &token).await {
                Ok(raw) => match normalize_response(&raw) {
                    Ok(result) if result.data != "[]" => {
                        let triples = parser.parse(&result.data);
                        if !triples.is_empty() {
                            match session.graph.write() {
                                Ok(mut graph) => match graph.insert_triples(triples, Some(dataset_tag)) {
                                    Ok((e, r)) => {
                                        new_e += e;
                                        new_r += r;
                                        tables_hit += 1;
                                    }
                                    Err(e) => tracing::warn!("hydration insert {table}: {e}"),
                                },
                                Err(e) => tracing::warn!("hydration graph lock poisoned {table}: {e}"),
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!("hydration normalize {table}: {e}"),
                },
                Err(e) => tracing::warn!("hydration query {table}: {e}"),
            }
        }

        if new_e > 0 || new_r > 0 {
            if let Ok(mut graph) = session.graph.write() {
                run_scoring_incremental(&mut graph);
            }
        }

        Ok(HydrationOutcome {
            skipped: false,
            reason: None,
            new_entities: new_e,
            new_relations: new_r,
            tables_hit,
            tables_attempted,
        })
    }
```

Note: this preserves the original `HYDRATION_TAKE = 5000` as the default `take`. The only behavioral change vs. the original is (a) targets are filtered, (b) `take` comes from the filter. With `filter = None`, `requested = None` (all tables) and `take = 5000` — identical to before.

- [ ] **Step 5: Run the filter test + the pre-existing hydrate tests**

Run: `cargo test --manifest-path platform/api/Cargo.toml --lib hydrate 2>&1 | tail -20`
Expected: PASS — `hydrate_filter_restricts_tables_and_caps_rows` plus the existing `hydrate_ip_issues_three_table_queries_and_ingests` and any sibling hydrate tests all green (the delegate keeps them working unchanged).

- [ ] **Step 6: Commit**

```bash
git add platform/api/src/operations/sentinel.rs
git commit -m "feat(api): HydrationFilter + hydrate_node_filtered_with

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: `node_enrich` API op + DTO

The op resolves the node's entity type from the current graph, builds a `HydrationFilter`, and calls the filtered hydration with env-derived credentials (same pattern as `seed_from_ioc`).

**Files:**
- Modify: `platform/api/src/dto/v1/sentinel.rs` (add `NodeEnrichRequest`)
- Modify: `platform/api/src/operations/sentinel.rs` (add `node_enrich` op)
- Test: `platform/api/src/operations/sentinel.rs` (test module)

- [ ] **Step 1: Add the `NodeEnrichRequest` DTO**

In `platform/api/src/dto/v1/sentinel.rs`, after `SeedFromIocRequest` (~line 246). The result reuses the existing `HydrationOutcome` (already serializable and returned by seed), so no new result struct.

```rust
/// Pull a specific slice of a node's Sentinel events into the graph on
/// demand (no polling). The node must already exist in the current
/// session graph; its entity type selects the Sentinel tables to query.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NodeEnrichRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    /// Existing node id (also the value searched in Sentinel, e.g. an IP
    /// or UPN).
    pub node_id: String,
    /// Restrict to these Sentinel tables (default: all tables mapped for
    /// the node's type).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tables: Option<Vec<String>>,
    /// Time window (soft-sugar). Default `ago(24h)` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_window: Option<TimeWindow>,
    /// Cap rows pulled per table. Default 1000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_rows: Option<u32>,
}
```

- [ ] **Step 2: Write the failing tests**

Add to the test module in `sentinel.rs`. The "node not found" case needs no network (it errors before touching the transport), so it's a clean unit test. The happy path is covered by Task 1's filtered-hydration test, so here we test the op's resolution/guard logic.

```rust
    #[tokio::test]
    async fn node_enrich_errors_when_node_absent() {
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("enrich-absent".into()),
        })
        .unwrap();
        let err = api
            .node_enrich(crate::dto::sentinel::NodeEnrichRequest {
                session: None,
                node_id: "does-not-exist".into(),
                tables: None,
                time_window: None,
                max_rows: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ApiError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn node_enrich_errors_without_session() {
        let api = GraphHunterApi::new_noop();
        let err = api
            .node_enrich(crate::dto::sentinel::NodeEnrichRequest {
                session: None,
                node_id: "10.0.0.9".into(),
                tables: None,
                time_window: None,
                max_rows: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ApiError::InvalidState(_)));
    }
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test --manifest-path platform/api/Cargo.toml --lib node_enrich 2>&1 | tail -20`
Expected: FAIL to compile — `node_enrich` and `NodeEnrichRequest` don't exist.

- [ ] **Step 4: Implement `node_enrich`**

Add to `impl GraphHunterApi` in `sentinel.rs` (near `seed_from_ioc`). Imports `sentinel_entity_targets` (already imported in this file), `HttpSentinelTransport`, `SentinelTokenCache`, `SentinelAuth` (already in scope per seed).

```rust
    /// Enrich an existing node by pulling a chosen slice of its Sentinel
    /// events into the current session graph. Returns the
    /// `HydrationOutcome` describing what was added.
    pub async fn node_enrich(
        &self,
        req: NodeEnrichRequest,
    ) -> ApiResult<graph_hunter_core::analytics::HydrationOutcome> {
        use graph_hunter_core::analytics::HydrationOutcome;

        let session = self.sessions().current_session().ok_or_else(|| {
            ApiError::InvalidState("No current session. Seed or load a session first.".into())
        })?;

        // Resolve the node's entity type from the graph.
        let entity_type = {
            let graph = session
                .graph
                .read()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            graph
                .get_entity(&req.node_id)
                .map(|e| e.entity_type.clone())
                .ok_or_else(|| {
                    ApiError::InvalidInput(format!(
                        "node '{}' not found in the current session graph",
                        req.node_id
                    ))
                })?
        };

        if sentinel_entity_targets(&entity_type).is_empty() {
            return Ok(HydrationOutcome {
                skipped: true,
                reason: Some(format!(
                    "node type {entity_type} has no Sentinel table mapping; nothing to enrich"
                )),
                new_entities: 0,
                new_relations: 0,
                tables_hit: 0,
                tables_attempted: 0,
            });
        }

        let time_filter = req
            .time_window
            .as_ref()
            .map(|w| w.kql_filter())
            .unwrap_or_else(|| "where TimeGenerated > ago(24h)".to_string());

        let filter = HydrationFilter {
            tables: req.tables.clone(),
            max_rows: Some(req.max_rows.unwrap_or(1000)),
        };

        let creds = (
            std::env::var("AZURE_WORKSPACE_ID").ok(),
            std::env::var("AZURE_TENANT_ID").ok(),
            std::env::var("AZURE_CLIENT_ID").ok(),
            std::env::var("AZURE_CLIENT_SECRET").ok(),
        );
        match creds {
            (Some(ws), Some(tenant), Some(client), Some(secret)) => {
                let transport = HttpSentinelTransport::new();
                let cache = SentinelTokenCache::new();
                let auth = SentinelAuth {
                    tenant_id: tenant,
                    client_id: client,
                    client_secret: secret,
                };
                self.hydrate_node_filtered_with(
                    &transport,
                    &cache,
                    &req.node_id,
                    &entity_type,
                    &time_filter,
                    &ws,
                    &auth,
                    "Sentinel Enrich (node)",
                    Some(&filter),
                )
                .await
            }
            _ => Ok(HydrationOutcome {
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
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --manifest-path platform/api/Cargo.toml --lib node_enrich 2>&1 | tail -20`
Expected: PASS — both `node_enrich_errors_when_node_absent` and `node_enrich_errors_without_session`.

- [ ] **Step 6: Commit**

```bash
git add platform/api/src/dto/v1/sentinel.rs platform/api/src/operations/sentinel.rs
git commit -m "feat(api): node_enrich op + NodeEnrichRequest

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: `run_kql` dual mode (inspect vs ingest)

Add a non-destructive inspect mode to `run_kql`. Default stays "ingest" so the existing UI `/kql` route is unchanged.

**Files:**
- Modify: `platform/api/src/dto/v1/sentinel.rs` (`RunKqlRequest` + `KqlResult`)
- Modify: `platform/api/src/operations/sentinel.rs` (`run_kql` + a pure `cap_kql_rows` helper)
- Test: `platform/api/src/operations/sentinel.rs` (unit-test `cap_kql_rows`)

- [ ] **Step 1: Add fields to `RunKqlRequest` and `KqlResult`**

In `platform/api/src/dto/v1/sentinel.rs`, add to `RunKqlRequest` (after `time_window`, ~line 146):

```rust
    /// When `Some(false)`, the query runs but results are NOT ingested
    /// into the graph — rows are returned for inspection instead. `None`
    /// is treated as `true` (ingest), preserving the legacy behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingest: Option<bool>,
    /// Cap on rows returned in inspect mode (`ingest=false`). Default 200.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_rows: Option<u32>,
```

And add to `KqlResult` (find `pub struct KqlResult`; add as a new last field):

```rust
    /// Populated only in inspect mode (`ingest=false`): the (capped) raw
    /// rows. `None` when the query was ingested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<serde_json::Value>>,
```

- [ ] **Step 2: Write the failing test for the pure helper**

Add to the test module in `sentinel.rs`:

```rust
    #[test]
    fn cap_kql_rows_parses_and_truncates() {
        let data = r#"[{"a":1},{"a":2},{"a":3}]"#;
        let rows = cap_kql_rows(data, 2);
        assert_eq!(rows.len(), 2, "must truncate to max_rows");
        assert_eq!(rows[0]["a"], serde_json::json!(1));
    }

    #[test]
    fn cap_kql_rows_handles_non_array() {
        // Malformed / non-array data yields an empty vec, never panics.
        assert!(cap_kql_rows("not json", 10).is_empty());
        assert!(cap_kql_rows("{}", 10).is_empty());
    }
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test --manifest-path platform/api/Cargo.toml --lib cap_kql_rows 2>&1 | tail -15`
Expected: FAIL to compile — `cap_kql_rows` doesn't exist.

- [ ] **Step 4: Implement the helper**

Add as a free function in `sentinel.rs` (near the other free helpers like `apply_time_window_sugar`):

```rust
/// Parse a normalized KQL response (a JSON array of row objects) and
/// return at most `max_rows` rows. Non-array or malformed input yields
/// an empty vec rather than erroring — inspect mode is best-effort.
fn cap_kql_rows(data: &str, max_rows: usize) -> Vec<serde_json::Value> {
    match serde_json::from_str::<Vec<serde_json::Value>>(data) {
        Ok(mut rows) => {
            rows.truncate(max_rows);
            rows
        }
        Err(_) => Vec::new(),
    }
}
```

- [ ] **Step 5: Wire inspect mode into `run_kql`**

In `run_kql`, after `let took_ms = started.elapsed().as_millis() as u64;` and the `row_count`/`take_limit`/`truncated` lines, branch BEFORE the session/dataset/ingest block:

```rust
        // Inspect mode: return rows without touching the graph. Default
        // (ingest absent or true) falls through to the ingest path below.
        if req.ingest == Some(false) {
            let cap = req.max_rows.unwrap_or(200) as usize;
            let rows = cap_kql_rows(&res.data, cap);
            self.emitter_arc().emit(
                "kql-executed",
                serde_json::json!({
                    "kql": kql,
                    "source": "adhoc",
                    "target": "inspect",
                    "row_count": row_count,
                    "entities_created": 0,
                    "relations_created": 0,
                }),
            );
            return Ok(KqlResult {
                new_entities: 0,
                new_relations: 0,
                total_entities: 0,
                total_relations: 0,
                kql_executed: kql,
                row_count,
                took_ms,
                take_limit,
                truncated,
                rows: Some(rows),
            });
        }
```

Then update the existing ingest-path `Ok(KqlResult { ... })` at the end of `run_kql` to add `rows: None,` as its last field.

- [ ] **Step 6: Run tests + confirm the crate compiles**

Run: `cargo test --manifest-path platform/api/Cargo.toml --lib cap_kql_rows 2>&1 | tail -15`
Expected: PASS.
Run: `cargo build --manifest-path platform/api/Cargo.toml 2>&1 | tail -5`
Expected: builds clean (the new `rows` field is wired into both `KqlResult` constructors).

- [ ] **Step 7: Commit**

```bash
git add platform/api/src/dto/v1/sentinel.rs platform/api/src/operations/sentinel.rs
git commit -m "feat(api): run_kql dual inspect/ingest mode

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: HTTP routes (`POST /node/enrich`, extend `/kql`)

Expose `node_enrich` over HTTP and let `/kql` carry the new `ingest`/`max_rows`/`lookback` fields. `/sentinel_status` already exists — no change.

**Files:**
- Modify: `apps/tauri/src-tauri/src/http/siem.rs` (new `handler_node_enrich` + `NodeEnrichBody`; extend `RunKqlBody`)
- Modify: `apps/tauri/src-tauri/src/http/mod.rs` (add `/node/enrich` route)

- [ ] **Step 1: Extend `RunKqlBody` and map the new fields**

In `apps/tauri/src-tauri/src/http/siem.rs`, find `struct RunKqlBody` and add fields:

```rust
    #[serde(default)]
    pub ingest: Option<bool>,
    #[serde(default)]
    pub max_rows: Option<u32>,
    #[serde(default)]
    pub lookback: Option<String>,
```

Then in `handler_run_kql`, change the `RunKqlRequest { ... }` construction so it forwards them (replace the `time_window: None,` line):

```rust
            time_window: super::graph::lookback_to_window(body.lookback.as_deref()),
            ingest: body.ingest,
            max_rows: body.max_rows,
```

- [ ] **Step 2: Add `NodeEnrichBody` + `handler_node_enrich`**

In `siem.rs`, mirror `handler_seed_from_ioc`:

```rust
#[derive(serde::Deserialize)]
pub(super) struct NodeEnrichBody {
    pub node_id: String,
    #[serde(default)]
    pub tables: Option<Vec<String>>,
    #[serde(default)]
    pub lookback: Option<String>,
    #[serde(default)]
    pub max_rows: Option<u32>,
}

pub(super) async fn handler_node_enrich(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<NodeEnrichBody>,
) -> Response {
    let time_window = super::graph::lookback_to_window(body.lookback.as_deref());
    let result = tokio::time::timeout(
        Duration::from_secs(120),
        api.node_enrich(graph_hunter_api::dto::sentinel::NodeEnrichRequest {
            session: None,
            node_id: body.node_id,
            tables: body.tables,
            time_window,
            max_rows: body.max_rows,
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
        Err(_) => err_json("node enrich timed out (120s)"),
    }
}
```

(If `NodeEnrichBody` needs `serde::Deserialize` in scope, the file already derives Deserialize on `SeedBody`/`RunKqlBody` the same way — match that import style.)

- [ ] **Step 3: Register the route**

In `apps/tauri/src-tauri/src/http/mod.rs`, next to the `/sentinel/seed` route (~line 172), add:

```rust
        .route("/node/enrich", post(siem::handler_node_enrich))
```

- [ ] **Step 4: Compile-check the Tauri app**

The fresh worktree may lack the gitignored `apps/tauri/dist`; copy it from the main checkout if the frontendDist macro panics:
```bash
[ -d apps/tauri/dist ] || cp -r /c/Users/lsotomayor/GraphHunter/apps/tauri/dist apps/tauri/
```
Run: `cargo check --manifest-path apps/tauri/src-tauri/Cargo.toml 2>&1 | tail -8`
Expected: exit 0 (no errors).

- [ ] **Step 5: Commit**

```bash
git add apps/tauri/src-tauri/src/http/siem.rs apps/tauri/src-tauri/src/http/mod.rs
git commit -m "feat(http): POST /node/enrich + /kql ingest/lookback fields

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: MCP tools (`node_enrich`, `sentinel_query`, `sentinel_status`) + registration

Three thin tools mirroring `sentinel_seed`/`node_expand`. Catalog goes 40 → 43.

**Files:**
- Create: `platform/mcp/src/tools/node/enrich.ts`
- Create: `platform/mcp/src/tools/sentinel/query.ts`
- Create: `platform/mcp/src/tools/sentinel/status.ts`
- Modify: `platform/mcp/src/tools/sentinel/index.ts` (register query + status)
- Modify: `platform/mcp/src/tools/node/index.ts` (register enrich)

- [ ] **Step 1: Write `node/enrich.ts`**

```ts
import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  node_id: z.string().max(500).describe("Existing graph node to enrich (also the value searched in Sentinel)."),
  tables: z
    .array(z.string().max(120))
    .max(20)
    .optional()
    .describe("Restrict to these Sentinel tables (default: all tables mapped for the node's type)."),
  lookback: z
    .enum(["1h", "6h", "24h", "7d", "30d"])
    .optional()
    .describe("Time window to pull from Sentinel (default 24h)."),
  max_rows: z
    .number()
    .int()
    .min(1)
    .max(5000)
    .optional()
    .describe("Cap rows pulled per table (default 1000)."),
});

export const nodeEnrich = defineTool({
  name: "node_enrich",
  description:
    "Pull a specific slice of an existing node's Sentinel events into the graph on demand (no polling). Use when you need a particular data point to enrich the graph — e.g. just this user's SigninLogs for the last 7d. Narrower than node_expand(live), which hydrates everything. Returns what was added (new entities/relations, tables hit).",
  category: "node",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { node_id, tables, lookback, max_rows }) {
    const body: Record<string, unknown> = { node_id };
    if (tables) body.tables = tables;
    if (lookback) body.lookback = lookback;
    if (max_rows != null) body.max_rows = max_rows;
    return ctx.api.post("/node/enrich", body, HEAVY);
  },
});
```

- [ ] **Step 2: Write `sentinel/query.ts`**

```ts
import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  query: z.string().max(10000).describe("The KQL query to run against the connected Sentinel workspace."),
  lookback: z
    .enum(["1h", "6h", "24h", "7d", "30d"])
    .optional()
    .describe("Soft-sugar time window; ignored if your query already filters TimeGenerated."),
  ingest: z
    .boolean()
    .optional()
    .describe("false (default): return rows for inspection without touching the graph. true: parse + ingest into the graph."),
  max_rows: z
    .number()
    .int()
    .min(1)
    .max(1000)
    .optional()
    .describe("Cap rows returned in inspect mode (default 200)."),
});

export const sentinelQuery = defineTool({
  name: "sentinel_query",
  description:
    "Run a free-form KQL query against the connected Sentinel workspace. Dual mode: ingest=false (default) returns rows so you can inspect/verify a hypothesis without polluting the graph; ingest=true parses and ingests the results. Use node_enrich for targeted per-node pulls; use this for arbitrary KQL.",
  category: "sentinel",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { query, lookback, ingest, max_rows }) {
    const body: Record<string, unknown> = { kql: query, ingest: ingest ?? false };
    if (lookback) body.lookback = lookback;
    if (max_rows != null) body.max_rows = max_rows;
    return ctx.api.post("/kql", body, HEAVY);
  },
});
```

- [ ] **Step 3: Write `sentinel/status.ts`**

```ts
import { z } from "zod";
import { defineTool } from "../../lib/types.js";

const input = z.object({});

export const sentinelStatus = defineTool({
  name: "sentinel_status",
  description:
    "Read-only Sentinel connection state: whether a connector is registered, its status (Paused/Polling/...), and connector id. Check this before running sentinel_query / node_enrich so you know a workspace is reachable.",
  category: "sentinel",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx) {
    return ctx.api.get("/sentinel_status", {});
  },
});
```

- [ ] **Step 4: Register the tools**

Replace `platform/mcp/src/tools/sentinel/index.ts` entirely:

```ts
import type { Tool } from "../../lib/types.js";
import { sentinelSeed } from "./seed.js";
import { sentinelQuery } from "./query.js";
import { sentinelStatus } from "./status.js";

export const sentinelTools: Tool[] = [sentinelSeed, sentinelQuery, sentinelStatus];
```

In `platform/mcp/src/tools/node/index.ts`, import and append `nodeEnrich` to the `nodeTools` array. Open the file first to match its exact existing shape; the change is: add `import { nodeEnrich } from "./enrich.js";` at the top and add `nodeEnrich` to the exported `nodeTools: Tool[]` array.

- [ ] **Step 5: Build + verify the catalog**

```bash
cd platform/mcp && npx tsc --noEmit
```
Expected: exit 0 (no type errors). Then build the dist and count tools:
```bash
cd platform/mcp && npm run build && grep -rhoE 'name:\s*"[a-z_]+"' dist/src/tools/ | sort -u | wc -l
```
Expected: `43` unique tool names, including `node_enrich`, `sentinel_query`, `sentinel_status`.

- [ ] **Step 6: Commit**

```bash
git add platform/mcp/src/tools/node/enrich.ts platform/mcp/src/tools/sentinel/query.ts platform/mcp/src/tools/sentinel/status.ts platform/mcp/src/tools/sentinel/index.ts platform/mcp/src/tools/node/index.ts
git commit -m "feat(mcp): node_enrich + sentinel_query + sentinel_status tools

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Final verification gate (after all tasks)

```bash
cargo test --manifest-path platform/api/Cargo.toml --lib 2>&1 | tail -3
cargo check --manifest-path apps/tauri/src-tauri/Cargo.toml 2>&1 | tail -3
( cd platform/mcp && npx tsc --noEmit && npm run build )
```
Expected: api lib all green (incl. the new HydrationFilter / node_enrich / cap_kql_rows tests), Tauri check exit 0, tsc/build exit 0.

**Reminder for the operator:** after merge, the MCP client must be restarted so it picks up the rebuilt `dist/` — otherwise `node_enrich`/`sentinel_query`/`sentinel_status` won't appear in `tools/list` (same gotcha that hid `sentinel_seed`).

---

## Self-Review notes

- **Spec coverage:** §4.1 node_enrich → Tasks 1+2+4(route)+5(tool); §4.2 sentinel_query dual mode → Tasks 3+4(/kql fields)+5(tool); §4.3 sentinel_status → Task 5 (op + HTTP route already exist). §3 decisions: dual `ingest` default (DTO `None`→true, MCP `ingest ?? false`) → Task 3 + Task 5 query.ts; HydrationFilter reuse, no new query-builder → Task 1; pause/resume excluded → not in plan (status only). §6 caps: `max_rows` enforced server-side in both paths → Tasks 1 (take) + 3 (cap_kql_rows). §7 testing: filter restricts tables + take (T1), ingest=false no graph mutation via pure helper (T3), node-not-found (T2), catalog 43 (T5).
- **Type consistency:** `HydrationFilter { tables: Option<Vec<String>>, max_rows: Option<u32> }` defined T1, consumed T2/T1 body. `NodeEnrichRequest` fields match between DTO (T2), HTTP body mapping (T4), and MCP tool body (T5: node_id/tables/lookback/max_rows). `RunKqlRequest.ingest/max_rows` (T3) match `RunKqlBody` (T4) and query.ts (T5). `KqlResult.rows` added once (T3) and set in both constructors.
- **Known limitation (carry-over):** `run_kql` is not transport-generic (calls `run_sentinel_query` directly), so its live path has no unit test — the testable seam is the pure `cap_kql_rows` helper (T3). Same as the pre-existing code, which also has no run_kql unit test.
- **Inherited limitation:** hydration reads via `for_each_edge` base-only (tail edges excluded post-finalize) — documented follow-up, unchanged here.
