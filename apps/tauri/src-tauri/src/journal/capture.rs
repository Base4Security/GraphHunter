//! Pure event-assembly helper for the mandatory capture middleware (Task A4).
//!
//! `build_event` has no I/O and no axum types in its signature so it can be
//! unit-tested directly; the axum-facing `capture` middleware
//! (`http::mod::capture`) does the request/response buffering and graph
//! count lookups, then hands the raw parts to this function.

use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

use super::event::{EventResult, GraphCounts, HuntEvent, Topology};
use super::interpret::{classify_kind, extract_result_meta, extract_touched};
use super::redact::redact_secrets;

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Assembles a redacted `HuntEvent` from the captured parts of one HTTP
/// request/response pair. `seq` is left at its default (0); `JournalStore`
/// assigns the real per-hunt sequence number on append.
#[allow(clippy::too_many_arguments)]
pub fn build_event(
    path: &str,
    method: &str,
    status: u16,
    dur_ms: u64,
    req_body: &Value,
    resp_body: &Value,
    before: GraphCounts,
    after: GraphCounts,
) -> HuntEvent {
    let kind = classify_kind(path).to_string();
    let params = redact_secrets(req_body);
    let (row_count, new_entities, new_relations) = extract_result_meta(resp_body);
    let touched = extract_touched(path, resp_body);

    let resp_serialized = serde_json::to_string(resp_body).unwrap_or_default();
    let body_bytes = resp_serialized.len() as u64;
    let est_tokens = body_bytes / 4;

    HuntEvent {
        seq: 0,
        ts: now_millis(),
        kind,
        endpoint: format!("{method} {path}"),
        params,
        result: EventResult {
            status,
            duration_ms: dur_ms,
            row_count,
            new_entities,
            new_relations,
            body_bytes,
            est_tokens,
        },
        topology: Topology {
            graph_before: before,
            graph_after: after,
            touched,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_event_redacts_and_classifies() {
        let req = json!({"kql":"X","azure_client_secret":"s"});
        let resp = json!({"row_count": 3});
        let ev = build_event(
            "/kql",
            "POST",
            200,
            12,
            &req,
            &resp,
            GraphCounts { entities: 0, relations: 0 },
            GraphCounts { entities: 0, relations: 0 },
        );
        assert_eq!(ev.kind, "query");
        assert_eq!(ev.params["azure_client_secret"], "[REDACTED]");
        assert_eq!(ev.params["kql"], "X");
        assert_eq!(ev.result.row_count, Some(3));
        assert_eq!(ev.result.status, 200);
        assert_eq!(ev.result.duration_ms, 12);
        assert!(ev.result.est_tokens > 0);
        assert_eq!(ev.endpoint, "POST /kql");
    }

    #[test]
    fn build_event_fills_topology_from_before_after() {
        let ev = build_event(
            "/graph/build",
            "POST",
            200,
            5,
            &Value::Null,
            &json!({"new_entities": 8, "new_relations": 227}),
            GraphCounts { entities: 10, relations: 20 },
            GraphCounts { entities: 18, relations: 247 },
        );
        assert_eq!(ev.kind, "build");
        assert_eq!(ev.result.new_entities, Some(8));
        assert_eq!(ev.result.new_relations, Some(227));
        assert_eq!(ev.topology.graph_before.entities, 10);
        assert_eq!(ev.topology.graph_after.entities, 18);
    }
}
