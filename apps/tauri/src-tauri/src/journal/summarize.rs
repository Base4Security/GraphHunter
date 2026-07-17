use serde_json::{json, Map, Value};

use super::interpret::classify_kind;

/// Soft-cap (in estimated tokens) above which a response is worth summarizing.
/// Anything at or below this is already small enough to hand back as-is.
const THRESHOLD: u64 = 400;

/// Max number of representative rows/items kept in `top`.
const TOP_N: usize = 5;

/// Serialized-length / 4 heuristic for estimating LLM token cost of a JSON value.
pub fn est_tokens(v: &Value) -> u64 {
    serde_json::to_string(v).unwrap_or_default().len() as u64 / 4
}

/// Builds a compact semantic summary for a large, known-shape endpoint response.
///
/// Returns `None` when the response is already small (`est_tokens(resp) <= THRESHOLD`)
/// or when `classify_kind(path)` can't be summarized meaningfully ("other") — in both
/// cases the caller should keep the original response.
pub fn summarize(path: &str, resp: &Value, detail_ref: &str) -> Option<Value> {
    if est_tokens(resp) <= THRESHOLD {
        return None;
    }

    let kind = classify_kind(path);
    if kind == "other" {
        return None;
    }

    let (counts, top) = match kind {
        "query" => summarize_query(resp),
        "traverse" => summarize_traverse(resp),
        _ => (generic_counts(resp), Vec::new()),
    };

    let mut obj = Map::new();
    obj.insert("_summary".to_string(), Value::Bool(true));
    obj.insert("kind".to_string(), Value::String(kind.to_string()));
    obj.insert("counts".to_string(), counts);
    obj.insert("top".to_string(), Value::Array(top));
    obj.insert("detail_ref".to_string(), Value::String(detail_ref.to_string()));
    Some(Value::Object(obj))
}

fn summarize_query(resp: &Value) -> (Value, Vec<Value>) {
    let rows = resp.get("rows").and_then(|v| v.as_array());
    let row_count = rows.map(|r| r.len()).unwrap_or(0);
    let top = rows
        .map(|r| r.iter().take(TOP_N).cloned().collect())
        .unwrap_or_default();
    (json!({ "row_count": row_count }), top)
}

fn summarize_traverse(resp: &Value) -> (Value, Vec<Value>) {
    let counts = if let Some(arr) = resp.get("neighbors").and_then(|v| v.as_array()) {
        json!({ "neighbor_count": arr.len() })
    } else if let Some(arr) = resp.get("paths").and_then(|v| v.as_array()) {
        json!({ "path_count": arr.len() })
    } else {
        generic_counts(resp)
    };
    (counts, Vec::new())
}

fn generic_counts(resp: &Value) -> Value {
    match resp {
        Value::Object(map) => json!({ "keys": map.len() }),
        Value::Array(arr) => json!({ "len": arr.len() }),
        _ => json!({}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn est_tokens_orders_small_below_large() {
        let small = json!({"a": 1});
        let large = big_kql_response(100);
        assert!(est_tokens(&small) < est_tokens(&large));
        // A tiny value should be a handful of tokens, not hundreds.
        assert!(est_tokens(&small) < 10);
    }

    #[test]
    fn summarizes_large_kql_response() {
        let resp = big_kql_response(100);
        assert!(est_tokens(&resp) > THRESHOLD, "fixture must exceed THRESHOLD");

        let summary = summarize("/kql", &resp, "hunt-x#3").expect("should summarize");

        assert_eq!(summary["_summary"], json!(true));
        assert_eq!(summary["kind"], json!("query"));
        assert_eq!(summary["detail_ref"], json!("hunt-x#3"));
        assert_eq!(summary["counts"]["row_count"], json!(100));

        let top = summary["top"].as_array().expect("top is an array");
        assert!(top.len() <= TOP_N);

        assert!(est_tokens(&summary) < est_tokens(&resp));
    }

    #[test]
    fn small_kql_response_is_not_summarized() {
        let resp = big_kql_response(2);
        assert!(est_tokens(&resp) <= THRESHOLD, "fixture must be small");
        assert_eq!(summarize("/kql", &resp, "hunt-x#1"), None);
    }

    #[test]
    fn unknown_kind_is_not_summarized_even_if_large() {
        let mut padding = Map::new();
        for i in 0..200 {
            padding.insert(format!("field_{i}"), json!("some moderately sized filler value"));
        }
        let resp = Value::Object(padding);
        assert!(est_tokens(&resp) > THRESHOLD, "fixture must exceed THRESHOLD");
        assert_eq!(summarize("/something_new", &resp, "hunt-x#9"), None);
    }

    #[test]
    fn summarizes_traverse_neighbors_with_light_count() {
        let neighbors: Vec<Value> = (0..50)
            .map(|i| json!({"edge": "Connect", "node": {"class": "IP", "value": format!("10.0.0.{i}")}}))
            .collect();
        let resp = json!({ "entity": {"class": "User", "value": "a@b.com"}, "neighbors": neighbors });
        assert!(est_tokens(&resp) > THRESHOLD, "fixture must exceed THRESHOLD");

        let summary = summarize("/graph/neighbors", &resp, "hunt-x#2").expect("should summarize");
        assert_eq!(summary["_summary"], json!(true));
        assert_eq!(summary["kind"], json!("traverse"));
        assert_eq!(summary["counts"]["neighbor_count"], json!(50));
        assert_eq!(summary["detail_ref"], json!("hunt-x#2"));
    }
}
