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
use super::summarize;

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
    detail_ref: &str,
) -> HuntEvent {
    let kind = classify_kind(path).to_string();
    let params = redact_secrets(req_body);
    let (row_count, new_entities, new_relations) = extract_result_meta(resp_body);

    let resp_serialized = serde_json::to_string(resp_body).unwrap_or_default();
    let body_bytes = resp_serialized.len() as u64;

    // CRITICAL fix: never let raw secret-bearing response rows reach the
    // persisted summary. `summarize` copies up to TOP_N raw rows into
    // `top`, and that summary is written to disk (events.jsonl) and served
    // back via GET /journal/:id, /journal/export, and the MCP get/export
    // ops — so redact the response the same way `params` (the request) is
    // above, before it can ever be summarized. `body_bytes` stays keyed to
    // the ORIGINAL (unredacted) serialization since it records real wire
    // size, not persisted content; `redact_secrets` only replaces values in
    // place, so row_count and other counts derived from the redacted copy
    // still match.
    let safe_resp = redact_secrets(resp_body);

    // I-2 fix: `Touched.nodes` clones whole node objects into the event
    // written to events.jsonl, so it must be built from the redacted
    // `safe_resp`, not the raw `resp_body` — otherwise a secret-keyed field
    // on a touched node (e.g. a token column returned inline by
    // /graph/neighbors) is persisted unredacted. `redact_secrets` only
    // replaces secret-keyed values in place and preserves structure, so
    // neighbor/path extraction still works correctly on the redacted copy.
    let touched = extract_touched(path, &safe_resp);

    // Task B2: record what an LLM would actually pay to read this event —
    // the compact summary's token cost when one was produced (the measured
    // saving), otherwise the full response's cost (today's body_bytes/4,
    // reusing the serialization already computed above for body_bytes
    // instead of re-serializing the body a second time).
    let summary = summarize::summarize(path, &safe_resp, detail_ref);
    let est_tokens = match &summary {
        Some(s) => summarize::est_tokens(s),
        None => resp_serialized.len() as u64 / 4,
    };

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
            summary,
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
            "h#0",
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
            "h#0",
        );
        assert_eq!(ev.kind, "build");
        assert_eq!(ev.result.new_entities, Some(8));
        assert_eq!(ev.result.new_relations, Some(227));
        assert_eq!(ev.topology.graph_before.entities, 10);
        assert_eq!(ev.topology.graph_after.entities, 18);
    }

    fn big_kql_response(row_count: usize) -> Value {
        let rows: Vec<Value> = (0..row_count)
            .map(|i| {
                json!({
                    "TimeGenerated": format!("2026-07-14T12:{:02}:00Z", i % 60),
                    "Account": format!("user{i}@contoso.com"),
                    "IPAddress": format!("10.0.{}.{}", i % 256, (i * 7) % 256),
                    "ResultType": if i % 3 == 0 { "50126" } else { "0" },
                    "AppDisplayName": "Azure Portal",
                })
            })
            .collect();
        json!({ "rows": rows, "row_count": row_count })
    }

    #[test]
    fn build_event_summarizes_large_kql_response_and_lowers_est_tokens() {
        let resp = big_kql_response(100);
        let ev = build_event(
            "/kql",
            "POST",
            200,
            10,
            &Value::Null,
            &resp,
            GraphCounts { entities: 0, relations: 0 },
            GraphCounts { entities: 0, relations: 0 },
            "h#1",
        );
        assert!(ev.result.summary.is_some(), "large response should be summarized");
        let summary = ev.result.summary.as_ref().unwrap();
        assert_eq!(summary["_summary"], json!(true));
        assert_eq!(summary["detail_ref"], json!("h#1"));
        // The summary's token cost must be strictly cheaper than the full
        // body's — this is the measured saving the journal exists to prove.
        assert!(ev.result.est_tokens < ev.result.body_bytes / 4);
    }

    #[test]
    fn build_event_redacts_secret_fields_inside_summarized_response_rows() {
        // A /kql response whose rows carry a secret-keyed field (mirrors a
        // real Sentinel result column like RefreshToken/ClientSecret). Large
        // enough (row_count well past summarize's THRESHOLD=400 est_tokens)
        // that `summarize` copies raw rows into `top` — this is exactly the
        // path CRITICAL-1 found leaking secrets into the persisted journal.
        let row_count = 100;
        let rows: Vec<Value> = (0..row_count)
            .map(|i| {
                json!({
                    "TimeGenerated": format!("2026-07-14T12:{:02}:00Z", i % 60),
                    "Account": format!("user{i}@contoso.com"),
                    "IPAddress": format!("10.0.{}.{}", i % 256, (i * 7) % 256),
                    "AppDisplayName": "Azure Portal",
                    "RefreshToken": "SECRET-XYZ",
                })
            })
            .collect();
        let resp = json!({ "rows": rows, "row_count": row_count });

        let ev = build_event(
            "/kql",
            "POST",
            200,
            10,
            &Value::Null,
            &resp,
            GraphCounts { entities: 0, relations: 0 },
            GraphCounts { entities: 0, relations: 0 },
            "h#secret",
        );

        assert!(ev.result.summary.is_some(), "large response should be summarized");
        let serialized = serde_json::to_string(&ev.result.summary).unwrap();
        assert!(
            !serialized.contains("SECRET-XYZ"),
            "secret leaked into persisted journal summary: {serialized}"
        );
        assert!(
            serialized.contains("[REDACTED]"),
            "expected redact_secrets marker in persisted summary: {serialized}"
        );
    }

    #[test]
    fn build_event_small_response_is_not_summarized() {
        let resp = big_kql_response(2);
        let ev = build_event(
            "/kql",
            "POST",
            200,
            10,
            &Value::Null,
            &resp,
            GraphCounts { entities: 0, relations: 0 },
            GraphCounts { entities: 0, relations: 0 },
            "h#2",
        );
        assert!(ev.result.summary.is_none());
        assert_eq!(ev.result.est_tokens, ev.result.body_bytes / 4);
    }

    #[test]
    fn build_event_redacts_secret_fields_inside_touched_nodes() {
        // I-2: `topology.touched` was built from the RAW response, so a
        // secret-keyed field on a touched node (e.g. a token column
        // returned inline by /graph/neighbors) was persisted unredacted
        // into events.jsonl even though `result.summary` was already
        // redacted. Assert the fix: touched nodes go through the same
        // `redact_secrets` pass as the summary.
        let resp = json!({
            "entity": {"class": "User", "value": "a@b.com"},
            "neighbors": [{
                "edge": "Connect",
                "node": {"class": "IP", "value": "1.1.1.1", "token": "LEAK-123"}
            }]
        });
        let ev = build_event(
            "/graph/neighbors",
            "POST",
            200,
            10,
            &Value::Null,
            &resp,
            GraphCounts { entities: 0, relations: 0 },
            GraphCounts { entities: 0, relations: 0 },
            "h#touched",
        );

        let touched = ev.topology.touched.as_ref().expect("touched present");
        assert_eq!(touched.nodes.len(), 1);
        let serialized = serde_json::to_string(&touched).unwrap();
        assert!(
            !serialized.contains("LEAK-123"),
            "secret leaked into persisted touched.nodes: {serialized}"
        );
        assert!(
            serialized.contains("[REDACTED]"),
            "expected redact_secrets marker in persisted touched.nodes: {serialized}"
        );
    }
}
