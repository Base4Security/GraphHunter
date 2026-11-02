//! Hunt journal read/write endpoints (Task A5).
//!
//! Thin wrappers around `JournalStore` (Task A2). All paths under
//! `/journal` are exempt from the mandatory capture middleware (see
//! `journal_capture_skips` in `mod.rs`) — reading/exporting past hunts
//! must never journal itself.

use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

use crate::AppState;
use graph_hunter_api::GraphHunterApi;

use super::helpers::ok_json;

#[derive(Debug, Default, Deserialize)]
pub(super) struct StartBody {
    label: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ExportBody {
    id: String,
}

fn not_found(id: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "unknown hunt id", "id": id })),
    )
        .into_response()
}

/// `POST /journal/start` — body `{label?: String}`. Accepts a missing or
/// empty body (the label is optional) rather than requiring callers to
/// send `{}`.
pub(super) async fn handler_start(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let label = if body.is_empty() {
        None
    } else {
        serde_json::from_slice::<StartBody>(&body)
            .ok()
            .and_then(|b| b.label)
    };
    let hunt_id = state.journal.start_hunt(label);
    ok_json(serde_json::json!({ "hunt_id": hunt_id }))
}

/// `POST /journal/close` — closes the current hunt (if any).
pub(super) async fn handler_close(State(state): State<Arc<AppState>>) -> Response {
    let hunt_id = state.journal.close_hunt();
    ok_json(serde_json::json!({ "hunt_id": hunt_id }))
}

/// `GET /journal/list` — summaries of every known hunt.
pub(super) async fn handler_list(State(state): State<Arc<AppState>>) -> Response {
    ok_json(state.journal.list())
}

/// `GET /journal/:id` — full route/topology of one hunt: `{meta, events}`.
pub(super) async fn handler_get(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    match state.journal.read(&id) {
        Some((meta, events)) => ok_json(serde_json::json!({ "meta": meta, "events": events })),
        None => not_found(&id),
    }
}

/// `GET /journal/:id/stats` — per-hunt token accounting (Task B2):
/// `{hunt_id, cumulative_est_tokens, event_count, by_kind}`. Additive —
/// does not alter `GET /journal/:id`'s response shape.
pub(super) async fn handler_stats(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    match state.journal.stats(&id) {
        Some(stats) => ok_json(stats),
        None => not_found(&id),
    }
}

/// `POST /journal/export` — body `{id: String}`. Streams the hunt's events
/// back as NDJSON (one `HuntEvent` per line), mirroring the on-disk
/// `events.jsonl` byte-for-byte in structure.
pub(super) async fn handler_export(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ExportBody>,
) -> Response {
    match state.journal.read(&body.id) {
        Some((_meta, events)) => {
            let lines: Vec<String> = events
                .iter()
                .map(|ev| {
                    serde_json::to_string(ev).unwrap_or_else(|e| {
                        tracing::error!("journal export: failed to serialize event: {e}");
                        format!("{{\"__journal_export_error\":\"{}\"}}", e)
                    })
                })
                .collect();
            let text = lines.join("\n");
            ([(header::CONTENT_TYPE, "application/x-ndjson")], text).into_response()
        }
        None => not_found(&body.id),
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct ExpandBody {
    value: String,
    #[serde(default)]
    column: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

/// Default cap on how many matched rows `handler_expand` returns when the
/// caller doesn't specify a `limit`. Keeps the "cheap" guarantee of the L2
/// reconstruct layer even against a value that matches most of the result.
const DEFAULT_EXPAND_LIMIT: usize = 50;

/// Stringify a `Value` for comparison the same way the summarizer does:
/// strings compare as-is, everything else via `Value::to_string()`.
fn stringify(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Returns the rows matching `value`: if `column` is `Some`, rows whose
/// `row[column]` stringified equals `value` (case-insensitive); else rows
/// where ANY field's stringified value contains `value` (case-insensitive).
/// Capped at `limit`.
fn filter_rows(rows: &[Value], column: Option<&str>, value: &str, limit: usize) -> Vec<Value> {
    let needle = value.to_lowercase();
    let matches = |row: &Value| -> bool {
        match column {
            Some(col) => row
                .get(col)
                .map(|v| stringify(v).to_lowercase() == needle)
                .unwrap_or(false),
            None => match row.as_object() {
                Some(obj) => obj
                    .values()
                    .any(|v| stringify(v).to_lowercase().contains(&needle)),
                None => stringify(row).to_lowercase().contains(&needle),
            },
        }
    };
    rows.iter()
        .filter(|r| matches(r))
        .take(limit)
        .cloned()
        .collect()
}

/// `POST /journal/:id/expand` — the L2 "reconstruct" layer (Task expand).
/// Given a hunt id and a value seen in its (compact) summary, re-runs the
/// hunt's stored KQL and returns ONLY the full rows matching that value —
/// so an LLM can resolve a row-level correlation the per-column aggregates
/// can't convey, without re-dumping the whole result.
pub(super) async fn handler_expand(
    State(app): State<Arc<AppState>>,
    State(api): State<Arc<GraphHunterApi>>,
    Path(id): Path<String>,
    Json(body): Json<ExpandBody>,
) -> Response {
    let (_meta, events) = match app.journal.read(&id) {
        Some(v) => v,
        None => return not_found(&id),
    };

    let kql = events
        .iter()
        .rev()
        .find_map(|ev| ev.params.get("kql").and_then(|v| v.as_str()))
        .map(|s| s.to_string());

    let kql = match kql {
        Some(k) => k,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "hunt has no KQL event to expand" })),
            )
                .into_response();
        }
    };

    let result = tokio::time::timeout(
        Duration::from_secs(120),
        api.run_kql(graph_hunter_api::dto::sentinel::RunKqlRequest {
            kql: kql.clone(),
            workspace_id: String::new(),
            azure_tenant_id: String::new(),
            azure_client_id: String::new(),
            azure_client_secret: String::new(),
            time_window: None,
            ingest: Some(false),
            max_rows: None,
            dataset: None,
            acknowledge_fallback: Some(true),
        }),
    )
    .await;

    let kql_result = match result {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            let code =
                StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            return (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response();
        }
        Err(_) => {
            return (
                StatusCode::GATEWAY_TIMEOUT,
                Json(serde_json::json!({ "error": "KQL execution timed out (120s)" })),
            )
                .into_response();
        }
    };

    let limit = body.limit.unwrap_or(DEFAULT_EXPAND_LIMIT);
    let rows = kql_result.rows.unwrap_or_default();
    let matched_rows = filter_rows(&rows, body.column.as_deref(), &body.value, limit);
    let redacted_rows: Vec<Value> = matched_rows
        .iter()
        .map(crate::journal::redact::redact_secrets)
        .collect();

    ok_json(serde_json::json!({
        "hunt_id": id,
        "kql": kql,
        "match": { "column": body.column, "value": body.value },
        "matched": redacted_rows.len(),
        "total_rows": kql_result.row_count,
        "rows": redacted_rows,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_rows_column_match_exact_and_case_insensitive() {
        let rows = vec![
            serde_json::json!({"user": "Alice", "ip": "1.2.3.4"}),
            serde_json::json!({"user": "bob", "ip": "5.6.7.8"}),
        ];
        let out = filter_rows(&rows, Some("user"), "alice", 10);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["user"], "Alice");

        let out = filter_rows(&rows, Some("user"), "BOB", 10);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["user"], "bob");
    }

    #[test]
    fn filter_rows_no_column_any_field_contains() {
        let rows = vec![
            serde_json::json!({"user": "alice", "note": "seen from 10.0.0.5 twice"}),
            serde_json::json!({"user": "bob", "note": "clean"}),
        ];
        let out = filter_rows(&rows, None, "10.0.0.5", 10);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["user"], "alice");
    }

    #[test]
    fn filter_rows_limit_cap() {
        let rows: Vec<Value> = (0..10)
            .map(|i| serde_json::json!({"user": "alice", "seq": i}))
            .collect();
        let out = filter_rows(&rows, Some("user"), "alice", 3);
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn filter_rows_non_string_field_stringified() {
        let rows = vec![
            serde_json::json!({"user": "alice", "count": 42}),
            serde_json::json!({"user": "bob", "count": 7}),
        ];
        let out = filter_rows(&rows, Some("count"), "42", 10);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["user"], "alice");

        let out = filter_rows(&rows, None, "42", 10);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["user"], "alice");
    }

    #[test]
    fn filter_rows_no_match_empty() {
        let rows = vec![serde_json::json!({"user": "alice"})];
        let out = filter_rows(&rows, Some("user"), "carol", 10);
        assert!(out.is_empty());

        let out = filter_rows(&rows, None, "carol", 10);
        assert!(out.is_empty());
    }
}
