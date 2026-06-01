# Sentinel Live Node Hydration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When the analyst expands a graph node with `live:true`, GraphHunter pulls every Sentinel event touching that entity (in the hunt window) and ingests it before expanding, so the neighborhood is complete with respect to the source.

**Architecture:** A pure entity→columns map (co-located with `SentinelJsonParser`) drives per-table KQL scoped to the node. A new async `hydrate_node` op fetches via the existing `SentinelTransport` trait (mockable, same as polling), parses with `SentinelJsonParser`, inserts into the session graph, then scores incrementally. `expand_node_live` wires hydration before the existing synchronous `expand_node`. Polling keeps running in parallel; the graph `RwLock` serializes writes.

**Tech Stack:** Rust (core graph-engine, platform/api, platform/siem), Tauri (axum HTTP + commands), TypeScript (MCP tool, zod).

---

## Spec reconciliation (refinements over `2026-06-01-sentinel-live-node-hydration-design.md`)

- **Response shape:** `Neighborhood` is a **core** type (`core/graph-engine/src/analytics.rs`). The `hydration` block is added there as an optional field, not as an api-layer wrapper.
- **Fetch seam:** `hydrate_node` uses the `SentinelTransport` trait (exported from `graph_hunter_siem`), not the blocking `run_sentinel_query`. This is async and mockable, matching the spec's §8 testing intent and mirroring the polling loop.
- **Time window over MCP/HTTP:** preset lookback string (`"24h"` etc.) via query param → `TimeWindow::Preset`. Absolute windows remain available through the Tauri command's full `Option<TimeWindow>`. Absolute-over-MCP is out of scope (YAGNI).

## File Structure

| File | Responsibility | Change |
|------|----------------|--------|
| `core/graph-engine/src/sentinel.rs` | entity→columns map, KQL escape, hydration KQL builder, parser↔map sync test | Modify |
| `core/graph-engine/src/analytics.rs` | `HydrationOutcome` struct + `Neighborhood.hydration` field | Modify |
| `platform/api/src/dto/v1/graph_ops.rs` | `ExpandNodeRequest`: add `live`, `time_window` | Modify |
| `platform/api/src/operations/sentinel.rs` | `hydrate_node` async op (generic over transport) | Modify |
| `platform/api/src/operations/graph_ops.rs` | `expand_node_live` async wrapper + gating | Modify |
| `apps/tauri/src-tauri/src/http/graph.rs` | `ExpandQuery` live params + `handler_expand` live path | Modify |
| `apps/tauri/src-tauri/src/commands/graph_ops.rs` | `cmd_expand_node` live params | Modify |
| `platform/mcp/src/tools/node/expand.ts` | `live` + `lookback` input params | Modify |

---

## Task 1: Entity→columns map (`sentinel_entity_targets`)

**Files:**
- Modify: `core/graph-engine/src/sentinel.rs` (append near the end of the `impl`/module)
- Test: same file, `#[cfg(test)]` module

- [ ] **Step 1: Write the failing test**

Append to the existing test module in `core/graph-engine/src/sentinel.rs` (create a `#[cfg(test)] mod hydration_tests { ... }` if none exists for this):

```rust
#[cfg(test)]
mod hydration_tests {
    use super::*;
    use crate::types::EntityType;

    #[test]
    fn targets_for_ip_cover_three_tables() {
        let targets = sentinel_entity_targets(&EntityType::IP);
        let tables: Vec<&str> = targets.iter().map(|(t, _)| *t).collect();
        assert!(tables.contains(&"SigninLogs"));
        assert!(tables.contains(&"DeviceNetworkEvents"));
        assert!(tables.contains(&"CommonSecurityLog"));
    }

    #[test]
    fn targets_for_user_include_signin_upn() {
        let targets = sentinel_entity_targets(&EntityType::User);
        let signin = targets.iter().find(|(t, _)| *t == "SigninLogs").unwrap();
        assert!(signin.1.contains(&"UserPrincipalName"));
    }

    #[test]
    fn targets_for_unmapped_type_are_empty() {
        assert!(sentinel_entity_targets(&EntityType::Domain).is_empty());
        assert!(sentinel_entity_targets(&EntityType::Any).is_empty());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p graph-hunter-core hydration_tests`
Expected: FAIL — `cannot find function sentinel_entity_targets`.

(If the crate name differs, use the name from `core/graph-engine/Cargo.toml` `[package] name`.)

- [ ] **Step 3: Write minimal implementation**

Add to `core/graph-engine/src/sentinel.rs` (module level, after the `SentinelJsonParser` impls):

```rust
/// Inverse of the parser's column→entity mapping: for an entity type,
/// the `(Sentinel table name, columns)` pairs where a value of that type
/// can appear. Used to build entity-scoped hydration KQL.
///
/// MUST stay in sync with what the table parsers above read — the
/// `parser_map_sync` test enforces this. TODO(owner): tune columns to
/// your tenant (e.g. add `LocalIP` for IP, `SHA256` for Process) — these
/// lines define how complete each hydration is.
pub fn sentinel_entity_targets(
    ty: &crate::types::EntityType,
) -> &'static [(&'static str, &'static [&'static str])] {
    use crate::types::EntityType;
    match ty {
        EntityType::User => &[
            ("SecurityEvent", &["TargetUserName", "Account", "SubjectUserName"]),
            ("SigninLogs", &["UserPrincipalName", "UserDisplayName"]),
            ("DeviceProcessEvents", &["AccountName", "InitiatingProcessAccountName"]),
        ],
        EntityType::IP => &[
            ("SigninLogs", &["IPAddress"]),
            ("DeviceNetworkEvents", &["RemoteIP"]),
            ("CommonSecurityLog", &["SourceIP", "DestinationIP"]),
        ],
        EntityType::Host => &[
            ("SecurityEvent", &["Computer"]),
            ("DeviceNetworkEvents", &["DeviceName"]),
        ],
        EntityType::Process => &[
            ("SecurityEvent", &["NewProcessName", "ParentProcessName", "ProcessName"]),
            ("DeviceProcessEvents", &["FolderPath", "FileName", "InitiatingProcessFolderPath"]),
            ("DeviceFileEvents", &["InitiatingProcessFolderPath", "InitiatingProcessFileName"]),
        ],
        EntityType::File => &[
            ("SecurityEvent", &["ObjectName"]),
            ("DeviceFileEvents", &["FolderPath", "FileName"]),
        ],
        _ => &[],
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p graph-hunter-core hydration_tests`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add core/graph-engine/src/sentinel.rs
git commit -m "feat(core): sentinel_entity_targets inverse map for node hydration

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: Parser↔map synchronization guardrail test

**Files:**
- Test: `core/graph-engine/src/sentinel.rs` (`hydration_tests` module)

This test fails if the parser reads a column for an entity role that the
map omits. It is the load-bearing guardrail against silent incomplete
hydration. The shared source of truth is a declarative table; both the map
and (by review) the parser must agree with it.

- [ ] **Step 1: Write the failing test**

Add to `hydration_tests`:

```rust
/// Declarative source of truth: every (table, column) the parsers read as
/// an entity *identifier* (not metadata), grouped by entity type. When a
/// parser starts reading a new identifier column, add it here AND to
/// `sentinel_entity_targets` — this test fails until both match.
fn parser_identifier_columns() -> &'static [(crate::types::EntityType, &'static str, &'static str)]
{
    use crate::types::EntityType as E;
    &[
        (E::User, "SecurityEvent", "TargetUserName"),
        (E::User, "SecurityEvent", "Account"),
        (E::User, "SecurityEvent", "SubjectUserName"),
        (E::User, "SigninLogs", "UserPrincipalName"),
        (E::User, "SigninLogs", "UserDisplayName"),
        (E::User, "DeviceProcessEvents", "AccountName"),
        (E::User, "DeviceProcessEvents", "InitiatingProcessAccountName"),
        (E::IP, "SigninLogs", "IPAddress"),
        (E::IP, "DeviceNetworkEvents", "RemoteIP"),
        (E::IP, "CommonSecurityLog", "SourceIP"),
        (E::IP, "CommonSecurityLog", "DestinationIP"),
        (E::Host, "SecurityEvent", "Computer"),
        (E::Host, "DeviceNetworkEvents", "DeviceName"),
        (E::Process, "SecurityEvent", "NewProcessName"),
        (E::Process, "SecurityEvent", "ParentProcessName"),
        (E::Process, "SecurityEvent", "ProcessName"),
        (E::Process, "DeviceProcessEvents", "FolderPath"),
        (E::Process, "DeviceProcessEvents", "FileName"),
        (E::Process, "DeviceProcessEvents", "InitiatingProcessFolderPath"),
        (E::Process, "DeviceFileEvents", "InitiatingProcessFolderPath"),
        (E::Process, "DeviceFileEvents", "InitiatingProcessFileName"),
        (E::File, "SecurityEvent", "ObjectName"),
        (E::File, "DeviceFileEvents", "FolderPath"),
        (E::File, "DeviceFileEvents", "FileName"),
    ]
}

#[test]
fn map_covers_every_parser_identifier_column() {
    for (ty, table, column) in parser_identifier_columns() {
        let targets = sentinel_entity_targets(ty);
        let covered = targets
            .iter()
            .any(|(t, cols)| t == table && cols.contains(column));
        assert!(
            covered,
            "parser reads {column} in {table} as {ty:?}, but sentinel_entity_targets omits it",
        );
    }
}
```

- [ ] **Step 2: Run test to verify it passes immediately**

Run: `cargo test -p graph-hunter-core map_covers_every_parser_identifier_column`
Expected: PASS — the map from Task 1 already covers the declared columns.

(This test "fails first" only when the map and declaration drift; verify the guardrail bites by temporarily deleting one column from `sentinel_entity_targets`, re-running to see RED, then restoring.)

- [ ] **Step 3: Verify the guardrail bites (manual)**

Temporarily remove `"IPAddress"` from the IP→SigninLogs entry, run the test, confirm it FAILS with the assert message, then restore it. Re-run: PASS.

- [ ] **Step 4: Commit**

```bash
git add core/graph-engine/src/sentinel.rs
git commit -m "test(core): parser↔hydration-map sync guardrail

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: KQL escape + hydration KQL builder

**Files:**
- Modify: `core/graph-engine/src/sentinel.rs`
- Test: `core/graph-engine/src/sentinel.rs` (`hydration_tests`)

- [ ] **Step 1: Write the failing test**

Add to `hydration_tests`:

```rust
#[test]
fn kql_escape_neutralizes_quotes_and_backslashes() {
    assert_eq!(kql_escape(r#"a"b\c"#), r#"a\"b\\c"#);
    assert_eq!(kql_escape("plain"), "plain");
}

#[test]
fn hydration_kql_builds_or_clause_across_columns() {
    let kql = build_hydration_kql(
        "CommonSecurityLog",
        &["SourceIP", "DestinationIP"],
        "10.0.0.1",
        "where TimeGenerated > ago(24h)",
        5000,
    );
    assert_eq!(
        kql,
        r#"CommonSecurityLog | where TimeGenerated > ago(24h) | where SourceIP == "10.0.0.1" or DestinationIP == "10.0.0.1" | take 5000"#
    );
}

#[test]
fn hydration_kql_escapes_value() {
    let kql = build_hydration_kql(
        "SigninLogs",
        &["UserPrincipalName"],
        r#"ev"il"#,
        "where TimeGenerated > ago(1h)",
        100,
    );
    assert!(kql.contains(r#"UserPrincipalName == "ev\"il""#), "value not escaped: {kql}");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p graph-hunter-core hydration_tests`
Expected: FAIL — `cannot find function kql_escape` / `build_hydration_kql`.

- [ ] **Step 3: Write minimal implementation**

Add to `core/graph-engine/src/sentinel.rs` (module level):

```rust
/// Escapes a value for embedding in a KQL double-quoted string literal.
/// KQL string literals escape `"` and `\` with a backslash.
pub fn kql_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Builds an entity-scoped hydration query for one Sentinel table.
///
/// Shape: `<table> | <time_filter> | where C1 == "v" or C2 == "v" | take N`.
/// `time_filter` is a pre-rendered clause beginning with `where`
/// (e.g. from `TimeWindow::kql_filter`). `value` is escaped internally.
pub fn build_hydration_kql(
    table: &str,
    columns: &[&str],
    value: &str,
    time_filter: &str,
    take: u32,
) -> String {
    let escaped = kql_escape(value);
    let predicate = columns
        .iter()
        .map(|c| format!("{c} == \"{escaped}\""))
        .collect::<Vec<_>>()
        .join(" or ");
    format!("{table} | {time_filter} | where {predicate} | take {take}")
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p graph-hunter-core hydration_tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/graph-engine/src/sentinel.rs
git commit -m "feat(core): kql_escape + build_hydration_kql

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: `HydrationOutcome` + `Neighborhood.hydration` field

**Files:**
- Modify: `core/graph-engine/src/analytics.rs` (near `Neighborhood`, line ~47)
- Test: `core/graph-engine/src/analytics.rs` (`#[cfg(test)]`)

- [ ] **Step 1: Write the failing test**

Add a test in `analytics.rs`:

```rust
#[cfg(test)]
mod hydration_outcome_tests {
    use super::*;

    #[test]
    fn neighborhood_default_omits_hydration_in_json() {
        let hood = Neighborhood {
            center: "x".into(),
            nodes: vec![],
            edges: vec![],
            truncated: false,
            auto_grouped: false,
            auto_group_reason: None,
            hydration: None,
        };
        let json = serde_json::to_string(&hood).unwrap();
        assert!(!json.contains("hydration"), "None hydration must be skipped: {json}");
    }

    #[test]
    fn hydration_outcome_serializes_counts() {
        let o = HydrationOutcome {
            skipped: false,
            reason: None,
            new_entities: 3,
            new_relations: 7,
            tables_hit: 2,
            tables_attempted: 3,
        };
        let json = serde_json::to_string(&o).unwrap();
        assert!(json.contains("\"new_relations\":7"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p graph-hunter-core hydration_outcome_tests`
Expected: FAIL — `Neighborhood` has no field `hydration`; `HydrationOutcome` undefined.

- [ ] **Step 3: Write minimal implementation**

In `core/graph-engine/src/analytics.rs`, add the struct (near `Neighborhood`):

```rust
/// Reports the result of live-source hydration performed before an
/// expansion. Attached to `Neighborhood` when an expand ran with the
/// live flag. `skipped=true` with a `reason` means hydration could not
/// run (non-Sentinel session, missing creds, unmapped entity type).
#[derive(Serialize, Clone, Debug)]
pub struct HydrationOutcome {
    pub skipped: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub new_entities: usize,
    pub new_relations: usize,
    pub tables_hit: usize,
    pub tables_attempted: usize,
}
```

Then add the field to `Neighborhood` (after `auto_group_reason`):

```rust
    /// Present when this expansion ran with live hydration (Enfoque A).
    /// See `HydrationOutcome`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hydration: Option<HydrationOutcome>,
```

- [ ] **Step 4: Fix all `Neighborhood { .. }` constructors**

Compiling will fail at every struct-literal site (no field `hydration`). Find them:

Run: `cargo build -p graph-hunter-core 2>&1 | grep "missing field"`

For each site (notably `core/graph-engine/src/analytics.rs` in `get_neighborhood` / `get_neighborhood_grouped` and `platform/api/src/operations/graph_ops.rs:351`), add `hydration: None,` to the literal. The api-layer site already builds `Neighborhood { center, nodes, edges, truncated, auto_grouped, auto_group_reason }` — add `hydration: None,`.

- [ ] **Step 5: Run test + full build to verify**

Run: `cargo test -p graph-hunter-core hydration_outcome_tests && cargo build -p graph-hunter-api`
Expected: tests PASS, build OK.

- [ ] **Step 6: Commit**

```bash
git add core/graph-engine/src/analytics.rs platform/api/src/operations/graph_ops.rs
git commit -m "feat(core): HydrationOutcome + Neighborhood.hydration field

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: `ExpandNodeRequest` gains `live` + `time_window`

**Files:**
- Modify: `platform/api/src/dto/v1/graph_ops.rs:166-176`

- [ ] **Step 1: Add the fields**

In `ExpandNodeRequest`, add (import `TimeWindow` at top: `use crate::dto::v1::sentinel::TimeWindow;`):

```rust
    /// When true, hydrate the target node from Sentinel before expanding
    /// (Enfoque A). Ignored on non-Sentinel sessions (soft no-op).
    #[serde(default)]
    pub live: bool,
    /// Time window for the hydration KQL. Defaults to 24h when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_window: Option<TimeWindow>,
```

- [ ] **Step 2: Fix all `ExpandNodeRequest { .. }` constructors**

Run: `cargo build -p graph-hunter-api 2>&1 | grep "missing field"`

`#[serde(default)]` + `Option` default means deserialization is fine, but struct literals in Rust still need the fields. Add `live: false,` and `time_window: None,` to each literal (in `commands/graph_ops.rs`, `http/graph.rs`, `operations/graph_ops.rs` `expand_node_grouped`, test fixtures). These get overwritten by the live wiring in later tasks.

- [ ] **Step 3: Build to verify**

Run: `cargo build -p graph-hunter-api`
Expected: OK.

- [ ] **Step 4: Commit**

```bash
git add platform/api/src/dto/v1/graph_ops.rs platform/api/src/operations/graph_ops.rs
git commit -m "feat(api): ExpandNodeRequest live + time_window fields

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: `hydrate_node` async operation

**Files:**
- Modify: `platform/api/src/operations/sentinel.rs`
- Test: `platform/api/src/operations/sentinel.rs` (`#[cfg(test)]`)

The op is generic over `SentinelTransport` for mockability. A thin public
method constructs the real `HttpSentinelTransport`.

- [ ] **Step 1: Write the failing test (mock transport)**

Add to `operations/sentinel.rs`:

```rust
#[cfg(test)]
mod hydrate_tests {
    use super::*;
    use graph_hunter_siem::{SentinelTransport, TokenResponse};
    use std::sync::Mutex;

    struct MockTransport {
        queries: Mutex<Vec<String>>,
        response: serde_json::Value,
    }

    impl SentinelTransport for MockTransport {
        async fn acquire_token(&self, _t: &str, _c: &str, _s: &str) -> Result<TokenResponse, String> {
            Ok(TokenResponse { access_token: "tok".into(), expires_in: 3600 })
        }
        async fn execute_query(&self, _ws: &str, query: &str, _b: &str) -> Result<serde_json::Value, String> {
            self.queries.lock().unwrap().push(query.to_string());
            Ok(self.response.clone())
        }
    }

    fn one_signin_row() -> serde_json::Value {
        // Log Analytics response shape: tables[].columns[].name + rows[][]
        serde_json::json!({
            "tables": [{
                "name": "PrimaryResult",
                "columns": [
                    {"name": "TimeGenerated"}, {"name": "Type"},
                    {"name": "UserPrincipalName"}, {"name": "IPAddress"}, {"name": "ResultType"}
                ],
                "rows": [[
                    "2026-06-01T10:00:00Z", "SigninLogs",
                    "alice@corp.com", "10.0.0.9", "0"
                ]]
            }]
        })
    }

    #[tokio::test]
    async fn hydrate_ip_issues_three_table_queries_and_ingests() {
        let api = GraphHunterApi::new_in_memory_for_test(); // see note in Step 3
        api.create_session_for_test("s1");
        let transport = MockTransport { queries: Mutex::new(vec![]), response: one_signin_row() };
        let cache = graph_hunter_siem::SentinelTokenCache::new();

        let outcome = api
            .hydrate_node_with(
                &transport, &cache,
                "10.0.0.9", &graph_hunter_core::types::EntityType::IP,
                "where TimeGenerated > ago(24h)", "ws-1",
                &SentinelAuth { tenant_id: "t".into(), client_id: "c".into(), client_secret: "s".into() },
            )
            .await
            .unwrap();

        // IP maps to 3 tables → 3 queries issued.
        assert_eq!(transport.queries.lock().unwrap().len(), 3);
        assert_eq!(outcome.tables_attempted, 3);
        assert!(!outcome.skipped);
    }
}
```

> **Note:** if `GraphHunterApi` has no in-memory test constructor, use the
> existing test-session helper pattern from other `operations/*` tests in
> this crate (grep `mod tests` in `operations/`). Adapt the two helper
> calls to whatever the crate already uses to build an API + session.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p graph-hunter-api hydrate_tests`
Expected: FAIL — `hydrate_node_with` not found.

- [ ] **Step 3: Write the implementation**

Ensure imports at top of `operations/sentinel.rs` include:

```rust
use graph_hunter_siem::{
    normalize_response, HttpSentinelTransport, SentinelAuth, SentinelTokenCache,
    SentinelTransport,
};
use graph_hunter_core::sentinel::{build_hydration_kql, sentinel_entity_targets};
use graph_hunter_core::types::EntityType;
```

Add inside `impl GraphHunterApi`:

```rust
    /// Hydrate a single node from Sentinel: for each (table, columns)
    /// where its type can appear, run an entity-scoped KQL, parse, and
    /// ingest into the current session graph. Generic over transport for
    /// mockability; `hydrate_node` builds the real HTTP transport.
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
    ) -> ApiResult<graph_hunter_core::analytics::HydrationOutcome> {
        use graph_hunter_core::analytics::HydrationOutcome;

        let targets = sentinel_entity_targets(entity_type);
        if targets.is_empty() {
            return Ok(HydrationOutcome {
                skipped: true,
                reason: Some(format!("no Sentinel column mapping for type {entity_type}")),
                new_entities: 0,
                new_relations: 0,
                tables_hit: 0,
                tables_attempted: 0,
            });
        }

        let token = token_cache
            .get_or_refresh(transport, auth)
            .await
            .map_err(|e| ApiError::Upstream { service: "sentinel-auth".into(), message: e })?;

        const HYDRATION_TAKE: u32 = 5000;
        const HYDRATION_DATASET: &str = "Sentinel Hydration (live)";

        let parser = make_parser_for_format("sentinel").map_err(ApiError::InvalidInput)?;
        let session = self.sessions().current_session().ok_or_else(|| {
            ApiError::InvalidState("No current session.".into())
        })?;

        let mut tables_hit = 0usize;
        let mut new_e = 0usize;
        let mut new_r = 0usize;
        let tables_attempted = targets.len();

        for (table, columns) in targets {
            let kql = build_hydration_kql(table, columns, value, time_filter, HYDRATION_TAKE);
            match transport.execute_query(workspace_id, &kql, &token).await {
                Ok(raw) => match normalize_response(&raw) {
                    Ok(result) if !result.data.is_empty() && result.data != "[]" => {
                        let triples = parser.parse(&result.data);
                        if !triples.is_empty() {
                            let mut graph = session.graph.write().map_err(|e| {
                                ApiError::Internal(format!("graph lock poisoned: {e}"))
                            })?;
                            if let Ok((e, r)) =
                                graph.insert_triples(triples, Some(HYDRATION_DATASET))
                            {
                                new_e += e;
                                new_r += r;
                                tables_hit += 1;
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

Add the `run_scoring_incremental` import to the file's `use crate::scoring::...` line (it currently imports `run_full_scoring, run_scoring_adaptive`).

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p graph-hunter-api hydrate_tests`
Expected: PASS — 3 queries issued, outcome not skipped.

- [ ] **Step 5: Commit**

```bash
git add platform/api/src/operations/sentinel.rs
git commit -m "feat(api): hydrate_node_with — entity-scoped Sentinel hydration

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: `expand_node_live` async wrapper + gating

**Files:**
- Modify: `platform/api/src/operations/graph_ops.rs` (near `expand_node`, line ~304)
- Test: `platform/api/src/operations/graph_ops.rs` (`#[cfg(test)]`)

- [ ] **Step 1: Write the failing test (gating: no creds → soft skip)**

Add to `graph_ops.rs` tests:

```rust
#[tokio::test]
async fn expand_live_without_creds_soft_skips_and_still_expands() {
    // Build an API + session with a couple of nodes, no AZURE_* env set.
    let api = GraphHunterApi::new_in_memory_for_test();
    api.create_session_for_test("s1");
    // Insert a tiny graph with node "10.0.0.9" of type IP via the test helper
    // used elsewhere in this module (grep insert_triples in tests).
    seed_ip_node(&api, "10.0.0.9");

    // Ensure no creds.
    std::env::remove_var("AZURE_WORKSPACE_ID");
    std::env::remove_var("AZURE_TENANT_ID");

    let hood = api
        .expand_node_live(ExpandNodeRequest {
            session: None,
            node_id: "10.0.0.9".into(),
            max_hops: Some(1),
            max_nodes: Some(50),
            filter: None,
            live: true,
            time_window: None,
        })
        .await
        .unwrap();

    let h = hood.hydration.expect("hydration block present on live expand");
    assert!(h.skipped, "should soft-skip without creds");
    assert_eq!(hood.center, "10.0.0.9");
}
```

> Use the module's existing seed/test-API helpers; `seed_ip_node` stands in
> for whatever helper inserts a single typed node in this test module.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p graph-hunter-api expand_live_without_creds`
Expected: FAIL — `expand_node_live` not found.

- [ ] **Step 3: Write the implementation**

Add to `impl GraphHunterApi` in `graph_ops.rs`:

```rust
    /// Live-backed expansion (Enfoque A): hydrate the target node from
    /// Sentinel (when possible), then run the synchronous `expand_node`
    /// and attach the hydration outcome. Soft no-op (skipped outcome) when
    /// the session is not Sentinel-capable or the type is unmapped.
    pub async fn expand_node_live(
        &self,
        req: ExpandNodeRequest,
    ) -> ApiResult<graph_hunter_core::analytics::Neighborhood> {
        use graph_hunter_core::analytics::HydrationOutcome;

        if !req.live {
            return self.expand_node(req);
        }

        // Resolve the node's entity type (brief read lock).
        let entity_type = {
            let session = self.resolve_session(req.session.as_ref())?;
            let graph = session
                .graph
                .read()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            graph.get_entity(&req.node_id).map(|e| e.entity_type.clone())
        };

        let time_filter = req
            .time_window
            .as_ref()
            .map(|w| w.kql_filter())
            .unwrap_or_else(|| "where TimeGenerated > ago(24h)".to_string());

        // Resolve creds from env (the connector sets these); empty → skip.
        let creds = (
            std::env::var("AZURE_WORKSPACE_ID").ok(),
            std::env::var("AZURE_TENANT_ID").ok(),
            std::env::var("AZURE_CLIENT_ID").ok(),
            std::env::var("AZURE_CLIENT_SECRET").ok(),
        );

        let outcome = match (entity_type, creds) {
            (None, _) => HydrationOutcome {
                skipped: true,
                reason: Some("node not in graph; cannot infer entity type".into()),
                new_entities: 0, new_relations: 0, tables_hit: 0, tables_attempted: 0,
            },
            (Some(_), (None, ..)) | (Some(_), (_, None, ..))
            | (Some(_), (_, _, None, _)) | (Some(_), (_, _, _, None)) => HydrationOutcome {
                skipped: true,
                reason: Some("Azure credentials not configured (set AZURE_* or connect Sentinel)".into()),
                new_entities: 0, new_relations: 0, tables_hit: 0, tables_attempted: 0,
            },
            (Some(ty), (Some(ws), Some(tenant), Some(client), Some(secret))) => {
                let transport = graph_hunter_siem::HttpSentinelTransport::new();
                let cache = graph_hunter_siem::SentinelTokenCache::new();
                let auth = graph_hunter_siem::SentinelAuth {
                    tenant_id: tenant, client_id: client, client_secret: secret,
                };
                self.hydrate_node_with(
                    &transport, &cache, &req.node_id, &ty, &time_filter, &ws, &auth,
                )
                .await
                .unwrap_or_else(|e| HydrationOutcome {
                    skipped: true,
                    reason: Some(format!("hydration error: {e}")),
                    new_entities: 0, new_relations: 0, tables_hit: 0, tables_attempted: 0,
                })
            }
        };

        // Run the existing synchronous expansion, then attach the outcome.
        let mut hood = self.expand_node(req)?;
        hood.hydration = Some(outcome);
        Ok(hood)
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p graph-hunter-api expand_live_without_creds`
Expected: PASS — hydration present, skipped, expand still returns the center.

- [ ] **Step 5: Commit**

```bash
git add platform/api/src/operations/graph_ops.rs
git commit -m "feat(api): expand_node_live — hydrate-then-expand with gating

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 8: Tauri HTTP `handler_expand` live path

**Files:**
- Modify: `apps/tauri/src-tauri/src/http/graph.rs` (`ExpandQuery`, `handler_expand` ~106)

- [ ] **Step 1: Add query fields + route the live path**

Find the `ExpandQuery` struct in `http/graph.rs` and add:

```rust
    #[serde(default)]
    pub live: bool,
    /// Lookback preset for hydration window: "1h" | "6h" | "24h" | "7d" | "30d".
    #[serde(default)]
    pub lookback: Option<String>,
```

Add a helper in the same file:

```rust
fn lookback_to_window(
    lookback: Option<&str>,
) -> Option<graph_hunter_api::dto::sentinel::TimeWindow> {
    use graph_hunter_api::dto::sentinel::{LookbackPreset, TimeWindow};
    let preset = match lookback? {
        "1h" => LookbackPreset::H1,
        "6h" => LookbackPreset::H6,
        "24h" => LookbackPreset::H24,
        "7d" => LookbackPreset::D7,
        "30d" => LookbackPreset::D30,
        _ => return None,
    };
    Some(TimeWindow::Preset { lookback: preset })
}
```

Modify `handler_expand` so that when `q.live` is true it awaits the async
`expand_node_live` (no `spawn_blocking` — the op manages its own blocking),
otherwise it keeps the existing `spawn_blocking(expand_node)` path:

```rust
    if q.live {
        let req = graph_hunter_api::dto::graph_ops::ExpandNodeRequest {
            session: None,
            node_id: q.node_id.clone(),
            max_hops: q.max_hops,
            max_nodes: q.max_nodes,
            filter: None,
            live: true,
            time_window: lookback_to_window(q.lookback.as_deref()),
        };
        return api_response(
            tokio::time::timeout(Duration::from_secs(90), api.expand_node_live(req))
                .await
                .unwrap_or_else(|_| Err(graph_hunter_api::ApiError::Internal(
                    "expand (live) timed out".into(),
                ))),
        );
    }
    // ... existing non-live spawn_blocking path unchanged ...
```

> The live timeout is 90s (vs 60s offline) because hydration adds network
> round-trips. Confirm `api_response` and `ApiError` import paths match the
> file's existing usage.

- [ ] **Step 2: Build the Tauri crate**

Run: `cargo build -p graph-hunter-tauri` (use the crate name from `apps/tauri/src-tauri/Cargo.toml`)
Expected: OK.

- [ ] **Step 3: Manual smoke (documented, run later in T-final)**

With `AZURE_*` set and a Sentinel session, `GET /expand?node_id=<ip>&live=true&lookback=24h` returns a `Neighborhood` JSON containing a `hydration` block with non-zero `tables_attempted`.

- [ ] **Step 4: Commit**

```bash
git add apps/tauri/src-tauri/src/http/graph.rs
git commit -m "feat(tauri): /expand live path with lookback window

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 9: Tauri `cmd_expand_node` live params

**Files:**
- Modify: `apps/tauri/src-tauri/src/commands/graph_ops.rs:222-238`

- [ ] **Step 1: Extend the command**

Make `cmd_expand_node` async and add params. New signature + body:

```rust
#[tauri::command]
pub async fn cmd_expand_node(
    api: State<'_, Arc<GraphHunterApi>>,
    node_id: String,
    max_hops: Option<usize>,
    max_nodes: Option<usize>,
    filter: Option<ExpandFilter>,
    live: Option<bool>,
    time_window: Option<graph_hunter_api::dto::sentinel::TimeWindow>,
) -> Result<Neighborhood, CommandError> {
    let req = ExpandNodeRequest {
        session: None,
        node_id,
        max_hops,
        max_nodes,
        filter,
        live: live.unwrap_or(false),
        time_window,
    };
    if req.live {
        api.expand_node_live(req).await.map_err(CommandError::from)
    } else {
        api.expand_node(req).map_err(CommandError::from)
    }
}
```

> Tauri async commands require `State<'_, ...>`. Adjust the `State` lifetime
> as shown. The frontend `invoke("cmd_expand_node", { nodeId, ... })` keeps
> working; `live`/`timeWindow` are optional and default off.

- [ ] **Step 2: Build**

Run: `cargo build -p graph-hunter-tauri`
Expected: OK. If other call sites pass positional args, update them; the
frontend uses named invoke args so no TS change is required for the offline
path.

- [ ] **Step 3: Commit**

```bash
git add apps/tauri/src-tauri/src/commands/graph_ops.rs
git commit -m "feat(tauri): cmd_expand_node live + time_window (async)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 10: MCP `node_expand` tool — `live` + `lookback`

**Files:**
- Modify: `platform/mcp/src/tools/node/expand.ts`

- [ ] **Step 1: Extend the input schema + query params**

Edit `expand.ts`:

```ts
const input = z.object({
  node_id: z.string().max(500).describe("Entity ID to expand from"),
  mode: z
    .enum(["raw", "grouped"])
    .optional()
    .default("raw")
    .describe(
      "raw: individual edges. grouped: per-type summaries with counts + first/last timestamps. Use grouped for hubs.",
    ),
  max_hops: z.number().int().min(1).max(5).optional().describe("Max hops (default 1)"),
  max_nodes: z.number().int().min(1).max(500).optional().describe("Max nodes (default 50)"),
  live: z
    .boolean()
    .optional()
    .describe(
      "When true, hydrate this node from Sentinel (pull all of its events in the lookback window) before expanding, so the neighborhood is complete w.r.t. the SIEM. No-op on non-Sentinel sessions. Only valid with mode=raw.",
    ),
  lookback: z
    .enum(["1h", "6h", "24h", "7d", "30d"])
    .optional()
    .describe("Hydration window when live=true (default 24h)."),
});
```

Update `execute` to pass the params (live only applies to the raw `/expand`
route):

```ts
  async execute(ctx, { node_id, mode, max_hops, max_nodes, live, lookback }) {
    const params: Record<string, string> = { node_id };
    if (max_hops != null) params.max_hops = String(max_hops);
    if (max_nodes != null) params.max_nodes = String(max_nodes);
    if (mode !== "grouped" && live) {
      params.live = "true";
      if (lookback) params.lookback = lookback;
    }
    const path = mode === "grouped" ? "/expand_grouped" : "/expand";
    return ctx.api.get(path, params, HEAVY);
  },
```

- [ ] **Step 2: Typecheck / build the MCP package**

Run: `npm run -w platform/mcp build` (or the repo's MCP build script; check `platform/mcp/package.json`)
Expected: no TS errors.

- [ ] **Step 3: Commit**

```bash
git add platform/mcp/src/tools/node/expand.ts
git commit -m "feat(mcp): node_expand live + lookback params

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 11: Full verification gate

**Files:** none (verification only)

- [ ] **Step 1: Workspace test suite**

Run: `cargo test -p graph-hunter-core -p graph-hunter-api`
Expected: all green, including `hydration_tests`, `map_covers_every_parser_identifier_column`, `hydrate_tests`, `expand_live_without_creds...`.

- [ ] **Step 2: Tauri + MCP build**

Run: `cargo build -p graph-hunter-tauri` and the MCP build script.
Expected: OK.

- [ ] **Step 3: Real Azure smoke (operator, with creds + Sentinel session)**

1. Connect Sentinel (polling running).
2. Find an IP node in the graph.
3. From the UI/MCP, `node_expand(node_id=<ip>, live=true, lookback="24h")`.
4. Confirm response has `hydration: { skipped:false, tables_attempted:3, ... }` and that new edges around the IP appeared (compare neighbor count before/after).
5. Confirm polling kept running concurrently (Activity Log shows both `polling` and the hydration ingest under "Sentinel Hydration (live)").

- [ ] **Step 4: Non-Sentinel session check**

Load a file/PCAP dataset, expand a node with `live=true`. Confirm the
expand still returns and `hydration.skipped == true` with a clear reason.

---

## Self-review notes

- **Spec coverage:** §2 map (T1), §3 sync test (T2), §6 KQL/escape/gating/errors (T3, T6, T7), §4 architecture (T4–T10), §7 parallel polling (T6 uses incremental scoring, no auto-pause; verified T11.3), §8 testing (T2, T6, T7, T11).
- **Type consistency:** `HydrationOutcome` fields identical across T4/T6/T7; `sentinel_entity_targets` returns `&[(&str, &[&str])]` consumed verbatim in T6; `build_hydration_kql` signature matches T3↔T6.
- **Known soft spots flagged for the engineer:** in-memory test-API/seed helpers (T6, T7) must be adapted to whatever this crate already uses; crate names in `cargo` commands come from the respective `Cargo.toml`.
