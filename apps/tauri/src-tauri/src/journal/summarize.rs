use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use super::interpret::classify_kind;

/// Soft-cap (in estimated tokens) above which a response is worth summarizing.
/// Anything at or below this is already small enough to hand back as-is.
const THRESHOLD: u64 = 400;

/// Max number of representative rows/items kept in `top`.
const TOP_N: usize = 5;

/// Max characters kept for a single string field value in a `top` row before truncation.
const MAX_FIELD_CHARS: usize = 200;

/// Max distinct values reported per column in the aggregates.
const AGG_TOP_N: usize = 3;

/// Max singleton (count == 1) values surfaced per column in the aggregates'
/// `rare` list — the long tail that `top`-by-frequency hides.
const AGG_RARE_N: usize = 6;

/// Wide rows (Sentinel/AAD logs carry ~74 columns, mostly Azure metadata)
/// are projected to hunt-relevant columns before storage. A row with more
/// than this many keys gets projected; narrower rows keep all (non-empty) keys.
const WIDE_ROW_KEYS: usize = 20;

/// Minimum projected keys; if the signal match yields fewer, fall back to the
/// first N original keys so we never emit a near-empty row.
const MIN_PROJECTED_KEYS: usize = 8;

/// Hard cap on projected columns for a wide row — a hunter needs a handful of
/// high-signal fields, not every column that loosely matched a signal substring.
const MAX_PROJECTED_KEYS: usize = 12;

/// Ordered highest-value hunt columns for a table. When projecting a wide
/// row, these are kept FIRST (in this order, and even if they don't match
/// `is_signal_key`), then remaining slots are filled with generic signal
/// matches in original column order, capped at MAX_PROJECTED_KEYS. Matched
/// case-insensitively against the FULL key name (exact, lowercased).
///
/// Real Sentinel/AWS tables carry wildly different columns (SecurityEvent
/// ~234, DeviceProcessEvents ~73, AWSCloudTrail ~53, ...) — a single
/// identity-tuned list misses each table's real signal columns (e.g.
/// SecurityEvent's `EventID` matches no generic signal substring).
/// `priority_for_table` selects the right list per-row via the `Type` field.
const IDENTITY_PRIORITY: &[&str] = &[
    "timegenerated", "userprincipalname", "userdisplayname", "ipaddress",
    "location", "resulttype", "resultdescription", "appdisplayname",
    "clientappused", "devicedetail", "riskstate", "status",
    "conditionalaccessstatus", "category", "identity", "operationname",
];

const SECURITYEVENT_PRIORITY: &[&str] = &[
    "timegenerated", "computer", "account", "accountdomain", "eventid",
    "activity", "ipaddress", "clientipaddress", "logontype", "commandline",
    "callerprocessname", "newprocessname", "targetusername", "subjectusername",
];

const CLOUDTRAIL_PRIORITY: &[&str] = &[
    "timegenerated", "eventname", "eventsource", "eventtypename",
    "useridentitytype", "useridentityarn", "useridentityusername",
    "useridentityaccountid", "sourceipaddress", "awsregion", "errorcode",
    "useragent",
];

const DEVICE_PRIORITY: &[&str] = &[
    "timegenerated", "devicename", "accountname", "actiontype", "filename",
    "processcommandline", "initiatingprocessfilename", "initiatingprocesscommandline",
    "initiatingprocesssignaturestatus", "initiatingprocesssignertype", "sha256", "folderpath",
    "initiatingprocessaccountname", "processid",
];

const NETFLOW_PRIORITY: &[&str] = &[
    "timegenerated", "firewallname", "srcip", "srcport", "destip",
    "destport", "proto", "appproto", "eventtype", "action",
];

const SYSLOG_PRIORITY: &[&str] = &[
    "timegenerated", "computer", "hostname", "hostip", "facility",
    "severitylevel", "processname", "syslogmessage",
];

/// Selects the priority column list for `table` (matched case-insensitively,
/// full-name, against the row's `Type` field). Tables without a dedicated
/// list fall back to `IDENTITY_PRIORITY`.
fn priority_for_table(table: &str) -> &'static [&'static str] {
    match table.to_lowercase().as_str() {
        "signinlogs" | "aadnoninteractiveusersigninlogs" | "aadsignineventslogs" => IDENTITY_PRIORITY,
        "securityevent" => SECURITYEVENT_PRIORITY,
        "awscloudtrail" | "awscloudtrail_cl" => CLOUDTRAIL_PRIORITY,
        "deviceprocessevents" | "deviceevents" | "devicenetworkevents" | "devicefileevents" => DEVICE_PRIORITY,
        "awsnetworkfirewallflow" | "awsnetworkfirewallalert" => NETFLOW_PRIORITY,
        "syslog" => SYSLOG_PRIORITY,
        _ => IDENTITY_PRIORITY, // sensible default (same as the previous single generic list)
    }
}

/// Key-name substrings (case-insensitive) that mark a column as hunt-relevant.
const SIGNAL_KEY_SUBSTRINGS: &[&str] = &[
    "time",
    "user",
    "account",
    "principal",
    "identity",
    "ipaddress",
    "address",
    "location",
    "city",
    "country",
    "result",
    "status",
    "app",
    "operation",
    "client",
    "device",
    "browser",
    "agent",
    "risk",
    "conditional",
    "category",
    "action",
    "target",
    "actor",
    "sign",
    "logon",
    "auth",
    "error",
    "reason",
    "name",
];

/// Key-name substrings (case-insensitive) that mark a column as pure Azure
/// plumbing — excluded even if it also matches a signal substring.
const NOISE_KEY_SUBSTRINGS: &[&str] = &[
    "tenant",
    "resourceid",
    "correlation",
    "originalrequest",
    "operationversion",
    "sourcesystem",
    "subscription",
    "aadtenant",
];

/// True when `key` names a hunt-relevant column: it contains a signal
/// substring and does not contain a noise substring (case-insensitive).
fn is_signal_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    if NOISE_KEY_SUBSTRINGS.iter().any(|n| lower.contains(n)) {
        return false;
    }
    SIGNAL_KEY_SUBSTRINGS.iter().any(|s| lower.contains(s))
}

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

    let (counts, top, aggregates) = match kind {
        "query" => summarize_query(resp),
        "traverse" => {
            let (counts, top) = summarize_traverse(resp);
            (counts, top, Value::Object(Map::new()))
        }
        _ => (generic_counts(resp), Vec::new(), Value::Object(Map::new())),
    };

    let mut obj = Map::new();
    obj.insert("_summary".to_string(), Value::Bool(true));
    obj.insert("kind".to_string(), Value::String(kind.to_string()));
    obj.insert("counts".to_string(), counts);
    let has_aggregates = matches!(&aggregates, Value::Object(map) if !map.is_empty());
    if has_aggregates {
        obj.insert("aggregates".to_string(), aggregates);
    }
    obj.insert("top".to_string(), Value::Array(top));
    obj.insert("detail_ref".to_string(), Value::String(detail_ref.to_string()));
    Some(Value::Object(obj))
}

/// Builds the `query`-kind summary: `row_count`, the `top` sample rows, and
/// (for responses with more than `TOP_N` rows) distribution `aggregates`
/// over ALL rows for the columns `top[0]` was projected down to.
fn summarize_query(resp: &Value) -> (Value, Vec<Value>, Value) {
    let rows = resp.get("rows").and_then(|v| v.as_array());
    let row_count = rows.map(|r| r.len()).unwrap_or(0);
    // Log Analytics rows carry a `Type` field equal to the table name
    // (e.g. "SecurityEvent", "AWSCloudTrail"). Detect it from the first row
    // to pick the right per-table priority list for the whole batch.
    let table = rows
        .and_then(|r| r.first())
        .and_then(|row| row.get("Type"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let priority = priority_for_table(table);
    let top: Vec<Value> = rows
        .map(|r| r.iter().take(TOP_N).map(|row| trim_row(row, priority)).collect())
        .unwrap_or_default();

    // Only worth aggregating when `top` doesn't already show every row (the
    // whole point of aggregates is to convey distribution across rows that
    // didn't make it into the sample).
    let aggregates = if row_count > TOP_N {
        let columns: Vec<String> = top
            .first()
            .and_then(|v| v.as_object())
            .map(|obj| obj.keys().cloned().collect())
            .unwrap_or_default();
        match rows {
            Some(r) if !columns.is_empty() => aggregate_columns(r, &columns),
            _ => Value::Object(Map::new()),
        }
    } else {
        Value::Object(Map::new())
    };

    (json!({ "row_count": row_count }), top, aggregates)
}

/// Computes per-column value-frequency distribution over ALL of `rows` for
/// each of `columns`, returning
/// `{ "<col>": { "distinct": <n>, "total": <m>, "top": [ {"value": <v>, "count": <c>}, ... ], "rare": [<v>, ...] } }`.
///
/// For each column: `Null` and empty-string values are skipped; other values
/// are stringified (`Value::String(s)` as-is, everything else via
/// `to_string()`) and truncated to `MAX_FIELD_CHARS` characters. `distinct`
/// is the number of distinct (post-truncation) values seen; `total` is the
/// count of non-null/non-empty values seen for the column (so a consumer can
/// compute exact proportions, e.g. top value 17 of total 25 = 68%); `top`
/// holds the `AGG_TOP_N` most frequent, sorted by count descending then
/// value ascending (a deterministic tiebreak — never relies on hashmap
/// iteration order); `rare` holds up to `AGG_RARE_N` distinct values that
/// appear EXACTLY ONCE (singletons — the long tail top-N-by-frequency
/// hides), sorted value ascending, and is OMITTED entirely when there are no
/// singletons. A column with zero non-null/non-empty values across all rows
/// is omitted from the result entirely.
fn aggregate_columns(rows: &[Value], columns: &[String]) -> Value {
    let mut result = Map::new();
    for col in columns {
        let mut counts: BTreeMap<String, u64> = BTreeMap::new();
        let mut total: u64 = 0;
        for row in rows {
            let value = match row.get(col) {
                None | Some(Value::Null) => continue,
                Some(Value::String(s)) if s.is_empty() => continue,
                Some(Value::String(s)) => s.clone(),
                Some(other) => other.to_string(),
            };
            let truncated = if value.chars().count() > MAX_FIELD_CHARS {
                let head: String = value.chars().take(MAX_FIELD_CHARS).collect();
                format!("{head}…")
            } else {
                value
            };
            total += 1;
            *counts.entry(truncated).or_insert(0) += 1;
        }

        if counts.is_empty() {
            continue;
        }

        let distinct = counts.len();
        let mut entries: Vec<(String, u64)> = counts.into_iter().collect();
        // Deterministic ordering: count descending, then value ascending to
        // break ties (BTreeMap iteration is already value-ascending, but
        // sort explicitly so the ordering doesn't silently depend on that).
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        // Singleton (count == 1) values are the long tail `top` hides.
        // Collected before truncating `entries` to AGG_TOP_N, sorted value
        // ascending, capped at AGG_RARE_N.
        let mut rare: Vec<String> = entries
            .iter()
            .filter(|(_, count)| *count == 1)
            .map(|(value, _)| value.clone())
            .collect();
        rare.sort();
        rare.truncate(AGG_RARE_N);

        let top: Vec<Value> = entries
            .into_iter()
            .take(AGG_TOP_N)
            .map(|(value, count)| json!({ "value": value, "count": count }))
            .collect();

        let mut col_agg = Map::new();
        col_agg.insert("distinct".to_string(), json!(distinct));
        col_agg.insert("total".to_string(), json!(total));
        col_agg.insert("top".to_string(), Value::Array(top));
        if !rare.is_empty() {
            col_agg.insert("rare".to_string(), json!(rare));
        }

        result.insert(col.clone(), Value::Object(col_agg));
    }
    Value::Object(result)
}

/// Compacts one representative row for `top`: drops fields whose value is
/// null or an empty string (Sentinel rows carry many empty columns that add
/// bytes but no signal), and truncates over-long string values. Non-object
/// rows (arrays, scalars) are returned unchanged.
///
/// Wide rows (Sentinel/AAD/AWS tables carry anywhere from ~50 to ~230
/// columns, mostly Azure/AWS metadata such as TenantId, ResourceId,
/// CorrelationId) often have zero empty values, so the drop-empty step
/// alone doesn't touch them — the real token cost is column COUNT. If the
/// surviving object still has more than `WIDE_ROW_KEYS` keys, it is
/// projected down to at most `MAX_PROJECTED_KEYS` columns:
///
/// 1. `priority` columns present in the row are kept first, in priority
///    order — even if they don't match the generic `is_signal_key` filter
///    (e.g. SecurityEvent's `EventID` is vital but matches no signal
///    substring).
/// 2. Remaining slots are filled with generic signal-matching columns, in
///    original column order.
/// 3. If that still yields fewer than `MIN_PROJECTED_KEYS` columns, an
///    order-preserving fallback fills up to `MIN_PROJECTED_KEYS` from any
///    remaining original columns, so a row is never emitted near-empty.
fn trim_row(row: &Value, priority: &[&str]) -> Value {
    let map = match row {
        Value::Object(map) => map,
        other => return other.clone(),
    };

    let mut trimmed = Map::new();
    for (key, value) in map {
        match value {
            Value::Null => continue,
            Value::String(s) if s.is_empty() => continue,
            Value::String(s) if s.chars().count() > MAX_FIELD_CHARS => {
                let truncated: String = s.chars().take(MAX_FIELD_CHARS).collect();
                trimmed.insert(key.clone(), Value::String(format!("{truncated}…")));
            }
            other => {
                trimmed.insert(key.clone(), other.clone());
            }
        }
    }

    if trimmed.len() <= WIDE_ROW_KEYS {
        return Value::Object(trimmed);
    }

    let mut selection: Vec<String> = Vec::new();

    // (a) Priority columns, in priority order, kept regardless of is_signal_key.
    for p in priority {
        if selection.len() >= MAX_PROJECTED_KEYS {
            break;
        }
        if let Some(key) = trimmed.keys().find(|k| k.to_lowercase() == *p) {
            if !selection.iter().any(|s| s == key) {
                selection.push(key.clone());
            }
        }
    }

    // (b) Generic signal fill, in original column order.
    if selection.len() < MAX_PROJECTED_KEYS {
        for key in trimmed.keys() {
            if selection.len() >= MAX_PROJECTED_KEYS {
                break;
            }
            if is_signal_key(key) && !selection.iter().any(|s| s == key) {
                selection.push(key.clone());
            }
        }
    }

    // (c) Never emit a near-empty row: fall back to the first original
    // columns (in order) until MIN_PROJECTED_KEYS is reached.
    if selection.len() < MIN_PROJECTED_KEYS {
        for key in trimmed.keys() {
            if selection.len() >= MIN_PROJECTED_KEYS {
                break;
            }
            if !selection.iter().any(|s| s == key) {
                selection.push(key.clone());
            }
        }
    }

    selection.truncate(MAX_PROJECTED_KEYS);

    let mut result = Map::new();
    for key in &selection {
        if let Some(value) = trimmed.get(key) {
            result.insert(key.clone(), value.clone());
        }
    }
    Value::Object(result)
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
    fn trim_row_drops_empty_and_null_fields() {
        let row = json!({"a": "x", "empty": "", "nothing": null, "n": 42});
        let trimmed = trim_row(&row, IDENTITY_PRIORITY);
        assert_eq!(trimmed, json!({"a": "x", "n": 42}));
    }

    #[test]
    fn trim_row_truncates_long_strings() {
        let long_value = "z".repeat(500);
        let row = json!({"field": long_value});
        let trimmed = trim_row(&row, IDENTITY_PRIORITY);
        let kept = trimmed["field"].as_str().expect("field is a string");
        assert_eq!(kept.chars().count(), MAX_FIELD_CHARS + 1);
        assert!(kept.ends_with('…'));
    }

    fn wide_sentinel_like_response(row_count: usize) -> Value {
        let long_value = "x".repeat(500);
        let rows: Vec<Value> = (0..row_count)
            .map(|i| {
                json!({
                    "TimeGenerated": format!("2026-07-14T12:{:02}:00Z", i % 60),
                    "Account": format!("user{i}@contoso.com"),
                    "IPAddress": format!("10.0.{}.{}", i % 256, (i * 7) % 256),
                    "ResultType": if i % 3 == 0 { "50126" } else { "0" },
                    "AppDisplayName": "Azure Portal",
                    "RawEventData": long_value.clone(),
                    "empty1": "",
                    "empty2": "",
                    "empty3": "",
                    "empty4": "",
                    "empty5": "",
                    "empty6": "",
                    "empty7": "",
                    "empty8": "",
                    "empty9": "",
                    "empty10": Value::Null,
                })
            })
            .collect();
        json!({ "rows": rows, "row_count": row_count })
    }

    #[test]
    fn summarize_query_compresses_wide_column_rows() {
        let resp = wide_sentinel_like_response(25);
        assert!(est_tokens(&resp) > THRESHOLD, "fixture must exceed THRESHOLD");

        let summary = summarize("/kql", &resp, "h#1").expect("should summarize");

        let top = summary["top"].as_array().expect("top is an array");
        assert!(!top.is_empty());
        for row in top {
            let obj = row.as_object().expect("row is an object");
            for key in obj.keys() {
                assert!(
                    !key.starts_with("empty"),
                    "trimmed row should not contain empty-valued keys, found {key}"
                );
            }
        }

        // Build the same envelope but with untrimmed (full) top rows for comparison.
        let untrimmed_top: Vec<Value> = resp["rows"]
            .as_array()
            .unwrap()
            .iter()
            .take(TOP_N)
            .cloned()
            .collect();
        let untrimmed_summary = json!({
            "_summary": true,
            "kind": "query",
            "counts": summary["counts"].clone(),
            "top": untrimmed_top,
            "detail_ref": "h#1",
        });

        let trimmed_tokens = est_tokens(&summary);
        let untrimmed_tokens = est_tokens(&untrimmed_summary);
        assert!(
            // Threshold loosened from 60% (40% smaller) to 75%, to 80%, then
            // to 85%: distribution aggregates over all 25 rows now ride
            // along in the summary — and, per Fix B, each aggregated column
            // also carries a "total" count plus an optional "rare" singleton
            // list, widened from 3 to 6 entries — so the margin over the
            // untrimmed 5-row comparison is a bit narrower still, though
            // still meaningfully smaller.
            trimmed_tokens <= untrimmed_tokens * 85 / 100,
            "trimmed ({trimmed_tokens}) should be meaningfully smaller than untrimmed ({untrimmed_tokens})"
        );
    }

    /// Builds a wide (~30-key) row mixing Azure-noise columns with
    /// hunt-signal columns, mirroring a real SigninLogs row shape.
    fn wide_signin_row(i: usize) -> Value {
        json!({
            "Type": "SigninLogs",
            "TenantId": "11111111-2222-3333-4444-555555555555",
            "ResourceId": format!("/tenants/t{i}/providers/Microsoft.aadiam"),
            "CorrelationId": format!("corr-{i}"),
            "SourceSystem": "Azure AD",
            "OperationVersion": "1.0",
            "TimeGenerated": format!("2026-07-14T12:{:02}:00Z", i % 60),
            "UserPrincipalName": format!("user{i}@contoso.com"),
            "IPAddress": format!("10.0.{}.{}", i % 256, (i * 7) % 256),
            "ResultType": if i % 3 == 0 { "50126" } else { "0" },
            "AppDisplayName": "Azure Portal",
            "Location": "US",
            "ClientAppUsed": "Browser",
            "RiskLevel": "none",
            "Status": "Success",
            "OriginalRequestIds": format!("req-{i}"),
            "SubscriptionId": "sub-abc",
            "AadTenantId": "aad-xyz",
            "col_noise_1": "n1",
            "col_noise_2": "n2",
            "col_noise_3": "n3",
            "col_noise_4": "n4",
            "col_noise_5": "n5",
            "col_noise_6": "n6",
            "col_noise_7": "n7",
            "col_noise_8": "n8",
            "col_noise_9": "n9",
            "col_noise_10": "n10",
            "col_noise_11": "n11",
            "col_noise_12": "n12",
            "col_noise_13": "n13",
        })
    }

    #[test]
    fn trim_row_projects_wide_row_to_signal_columns() {
        let row = wide_signin_row(1);
        let obj = row.as_object().unwrap();
        assert!(obj.len() > WIDE_ROW_KEYS, "fixture must exceed WIDE_ROW_KEYS");

        let trimmed = trim_row(&row, IDENTITY_PRIORITY);
        let trimmed_obj = trimmed.as_object().expect("trimmed row is an object");

        let signal_keys = [
            "TimeGenerated",
            "UserPrincipalName",
            "IPAddress",
            "ResultType",
            "AppDisplayName",
            "Location",
            "ClientAppUsed",
            "RiskLevel",
            "Status",
        ];
        for key in signal_keys {
            assert!(trimmed_obj.contains_key(key), "missing signal key {key}");
        }

        let noise_keys = ["TenantId", "ResourceId", "CorrelationId", "SourceSystem", "OperationVersion"];
        for key in noise_keys {
            assert!(!trimmed_obj.contains_key(key), "noise key {key} should be projected out");
        }

        assert!(trimmed_obj.len() <= signal_keys.len() + 2);
    }

    #[test]
    fn trim_row_leaves_narrow_row_untouched() {
        let row = json!({
            "TimeGenerated": "2026-07-14T12:00:00Z",
            "UserPrincipalName": "user@contoso.com",
            "IPAddress": "10.0.0.1",
            "ResultType": "0",
            "AppDisplayName": "Azure Portal",
            "Location": "US",
        });
        let obj = row.as_object().unwrap();
        assert!(obj.len() <= WIDE_ROW_KEYS, "fixture must be narrow");

        let trimmed = trim_row(&row, IDENTITY_PRIORITY);
        let trimmed_obj = trimmed.as_object().expect("trimmed row is an object");
        assert_eq!(trimmed_obj.len(), 6);
        for key in obj.keys() {
            assert!(trimmed_obj.contains_key(key));
        }
    }

    /// No priority or signal matches at all: the projection should fall back
    /// to the first MIN_PROJECTED_KEYS original keys rather than emit a
    /// near-empty row.
    #[test]
    fn trim_row_falls_back_to_first_n_keys_when_no_signal_matches() {
        let mut map = Map::new();
        for i in 1..=25 {
            map.insert(format!("col{i}"), json!(format!("v{i}")));
        }
        let row = Value::Object(map.clone());
        assert!(map.len() > WIDE_ROW_KEYS, "fixture must exceed WIDE_ROW_KEYS");

        let trimmed = trim_row(&row, IDENTITY_PRIORITY);
        let trimmed_obj = trimmed.as_object().expect("trimmed row is an object");
        assert_eq!(trimmed_obj.len(), MIN_PROJECTED_KEYS);

        let expected_first_keys: Vec<String> =
            map.keys().take(MIN_PROJECTED_KEYS).cloned().collect();
        for key in &expected_first_keys {
            assert!(
                trimmed_obj.contains_key(key),
                "fallback should keep first {MIN_PROJECTED_KEYS} original keys, missing {key}"
            );
        }
    }

    #[test]
    fn summarize_query_compresses_realistic_wide_sentinel_payload() {
        let rows: Vec<Value> = (0..25).map(wide_signin_row).collect();
        let resp = json!({ "rows": rows, "row_count": rows.len() });
        assert!(est_tokens(&resp) > THRESHOLD, "fixture must exceed THRESHOLD");

        let summary = summarize("/kql", &resp, "h#1").expect("should summarize");

        let untrimmed_top: Vec<Value> = resp["rows"]
            .as_array()
            .unwrap()
            .iter()
            .take(TOP_N)
            .cloned()
            .collect();
        let untrimmed_summary = json!({
            "_summary": true,
            "kind": "query",
            "counts": summary["counts"].clone(),
            "top": untrimmed_top,
            "detail_ref": "h#1",
        });

        let projected_tokens = est_tokens(&summary);
        let untrimmed_tokens = est_tokens(&untrimmed_summary);
        assert!(
            // Threshold loosened from 40% (60% smaller) to 60%, to 65%, then
            // to 70%: see the comment on the analogous assertion above —
            // aggregates add a bounded amount of distribution data over all
            // 25 rows, now including a per-column "total" and an optional
            // "rare" list widened (Fix B) from 3 to 6 entries.
            projected_tokens <= untrimmed_tokens * 70 / 100,
            "projected ({projected_tokens}) should be meaningfully smaller than untrimmed ({untrimmed_tokens})"
        );
    }

    /// Builds a wide (~40-key) row containing ALL 16 `HUNT_PRIORITY_KEYS`
    /// (realistic casing/values) plus ~24 Azure-noise/extra-signal columns
    /// that loosely match a signal substring (Authentication*, Risk*,
    /// ConditionalAccess*, *Name) but are not in the priority allowlist.
    fn all_priority_plus_noise_row() -> Value {
        json!({
            // 16 HUNT_PRIORITY_KEYS, in order, realistic casing.
            "TimeGenerated": "2026-07-14T12:00:00Z",
            "UserPrincipalName": "user@contoso.com",
            "UserDisplayName": "Contoso User",
            "IPAddress": "10.0.0.5",
            "Location": "US",
            "ResultType": "50126",
            "ResultDescription": "Invalid password",
            "AppDisplayName": "Azure Portal",
            "ClientAppUsed": "Browser",
            "DeviceDetail": "{\"deviceId\":\"abc\"}",
            "RiskState": "atRisk",
            "Status": "Failure",
            "ConditionalAccessStatus": "success",
            "Category": "SignInLogs",
            "Identity": "user@contoso.com",
            "OperationName": "Sign-in activity",
            // ~24 Azure-noise / extra-signal columns (not in the allowlist).
            "AuthenticationDetails": "[{\"authenticationStepDateTime\":\"2026-07-14T12:00:00Z\"}]",
            "AuthenticationRequirement": "singleFactorAuthentication",
            "AuthenticationMethodsUsed": "Password",
            "AuthenticationProcessingDetails": "[{\"key\":\"value\"}]",
            "RiskLevelAggregated": "none",
            "RiskLevelDuringSignIn": "none",
            "RiskDetail": "none",
            "RiskEventTypes": "[]",
            "ConditionalAccessPolicies": "[]",
            "ConditionalAccessStatusDetail": "notApplied",
            "TokenIssuerName": "contoso.onmicrosoft.com",
            "ServicePrincipalName": "graph-api",
            "ServicePrincipalId": "sp-0001",
            "ManagedIdentityName": "mi-0001",
            "AppliedConditionalAccessPolicies": "[]",
            "AuthenticationContextClassReferences": "[]",
            "ClientCredentialType": "none",
            "UserAgentDetail": "Mozilla/5.0",
            "UserTypeDetail": "Member",
            "AccountDisplayName": "Contoso User",
            "ActorUserPrincipalName": "actor@contoso.com",
            "TargetUserName": "target@contoso.com",
            "SignInIdentifier": "sid-0001",
            "ErrorReasonDetail": "none",
        })
    }

    #[test]
    fn trim_row_caps_wide_row_to_priority_columns() {
        let row = all_priority_plus_noise_row();
        let obj = row.as_object().unwrap();
        assert!(obj.len() > WIDE_ROW_KEYS, "fixture must exceed WIDE_ROW_KEYS");

        let trimmed = trim_row(&row, IDENTITY_PRIORITY);
        let trimmed_obj = trimmed.as_object().expect("trimmed row is an object");

        assert_eq!(
            trimmed_obj.len(),
            MAX_PROJECTED_KEYS,
            "wide row with many signal matches should compress to exactly MAX_PROJECTED_KEYS columns"
        );

        for key in ["IPAddress", "ResultType", "UserPrincipalName"] {
            assert!(trimmed_obj.contains_key(key), "expected priority key {key} to survive the cap");
        }

        for key in ["AuthenticationDetails", "TokenIssuerName"] {
            assert!(
                !trimmed_obj.contains_key(key),
                "lower-priority noise key {key} should be dropped by the cap"
            );
        }
    }

    #[test]
    fn trim_row_priority_beats_original_key_order() {
        let mut map = Map::new();
        // 20 early, non-priority signal columns (all match "auth").
        for n in 1..=20 {
            map.insert(
                format!("AuthenticationDetail{n:02}"),
                json!(format!("auth-detail-{n}")),
            );
        }
        // A priority column placed LAST in original key order.
        map.insert("IPAddress".to_string(), json!("10.0.0.9"));
        let row = Value::Object(map);
        let obj = row.as_object().unwrap();
        assert!(obj.len() > WIDE_ROW_KEYS, "fixture must exceed WIDE_ROW_KEYS");

        let trimmed = trim_row(&row, IDENTITY_PRIORITY);
        let trimmed_obj = trimmed.as_object().expect("trimmed row is an object");

        assert_eq!(trimmed_obj.len(), MAX_PROJECTED_KEYS);
        assert!(
            trimmed_obj.contains_key("IPAddress"),
            "priority key IPAddress must survive the cap despite sitting late in original key order"
        );
        assert!(
            !trimmed_obj.contains_key("AuthenticationDetail20"),
            "a late (in original order) non-priority signal field should be dropped by the cap"
        );
    }

    #[test]
    fn trim_row_under_cap_projection_is_unchanged() {
        let mut map = Map::new();
        // Exactly 10 signal-matching columns (< MAX_PROJECTED_KEYS).
        let signal_keys = [
            "TimeGenerated",
            "UserPrincipalName",
            "IPAddress",
            "ResultType",
            "AppDisplayName",
            "Location",
            "ClientAppUsed",
            "RiskState",
            "Status",
            "Category",
        ];
        for key in signal_keys {
            map.insert(key.to_string(), json!(format!("{key}-value")));
        }
        // Filler columns that match no signal substring, pushing the row wide.
        for n in 1..=15 {
            map.insert(format!("col_noise_{n}"), json!(format!("n{n}")));
        }
        let row = Value::Object(map);
        let obj = row.as_object().unwrap();
        assert!(obj.len() > WIDE_ROW_KEYS, "fixture must exceed WIDE_ROW_KEYS");
        assert!(signal_keys.len() < MAX_PROJECTED_KEYS);

        let trimmed = trim_row(&row, IDENTITY_PRIORITY);
        let trimmed_obj = trimmed.as_object().expect("trimmed row is an object");

        assert_eq!(
            trimmed_obj.len(),
            signal_keys.len(),
            "projection under the cap should be returned unchanged"
        );
        for key in signal_keys {
            assert!(trimmed_obj.contains_key(key), "missing signal key {key}");
        }
    }

    /// Builds a wide (~45-key) SigninLogs-like row: 10 priority hunt columns
    /// plus 35 Azure-noise / extra-signal columns, mirroring realistic wide
    /// telemetry width.
    fn wide_signin_row_45(i: usize) -> Value {
        let mut map = Map::new();
        map.insert("Type".to_string(), json!("SigninLogs"));
        // 10 priority hunt columns.
        map.insert("TimeGenerated".to_string(), json!(format!("2026-07-14T12:{:02}:00Z", i % 60)));
        map.insert("UserPrincipalName".to_string(), json!(format!("user{i}@contoso.com")));
        map.insert("IPAddress".to_string(), json!(format!("10.0.{}.{}", i % 256, (i * 7) % 256)));
        map.insert("ResultType".to_string(), json!(if i % 3 == 0 { "50126" } else { "0" }));
        map.insert("AppDisplayName".to_string(), json!("Azure Portal"));
        map.insert("Location".to_string(), json!("US"));
        map.insert("ClientAppUsed".to_string(), json!("Browser"));
        map.insert("RiskState".to_string(), json!("none"));
        map.insert("Status".to_string(), json!("Success"));
        map.insert("Category".to_string(), json!("SignInLogs"));

        // 35 Azure-noise / extra-signal columns.
        let noise_fields: [(&str, &str); 35] = [
            ("TenantId", "11111111-2222-3333-4444-555555555555"),
            ("ResourceId", "/tenants/t/providers/Microsoft.aadiam"),
            ("CorrelationId", "corr-id-0001"),
            ("SourceSystem", "Azure AD"),
            ("OperationVersion", "1.0"),
            ("OriginalRequestIds", "req-0001"),
            ("SubscriptionId", "sub-abc"),
            ("AadTenantId", "aad-xyz"),
            ("AuthenticationDetails", "[{\"authenticationStepDateTime\":\"2026-07-14T12:00:00Z\",\"authenticationMethod\":\"Password\",\"authenticationStepResultDetail\":\"First factor requirement satisfied by password\",\"succeeded\":true}]"),
            ("AuthenticationRequirement", "singleFactorAuthentication"),
            ("AuthenticationMethodsUsed", "Password"),
            ("AuthenticationProcessingDetails", "[{\"key\":\"Root Key Type\",\"value\":\"Unknown\"},{\"key\":\"Is CA Compliant\",\"value\":\"False\"},{\"key\":\"ProcessingTimeInMilliseconds\",\"value\":\"37\"},{\"key\":\"Legacy TLS (TLS 1.0, 1.1, 3DES)\",\"value\":\"False\"},{\"key\":\"Autologon Type\",\"value\":\"None\"}]"),
            ("AuthenticationAppDeviceDetails", "[]"),
            ("AuthenticationContextClassReferences", "[{\"id\":\"c1\",\"detail\":\"Multifactor authentication\"}]"),
            ("RiskLevelAggregated", "none"),
            ("RiskLevelDuringSignIn", "none"),
            ("RiskDetail", "none"),
            ("RiskEventTypes", "[\"unfamiliarFeatures\",\"anonymizedIPAddress\"]"),
            ("RiskEventTypesV2", "[\"unfamiliarFeatures\",\"anonymizedIPAddress\"]"),
            ("ConditionalAccessPolicies", "[{\"id\":\"p1\",\"displayName\":\"Require MFA for all users\",\"enforcedGrantControls\":[\"Mfa\"],\"result\":\"success\"},{\"id\":\"p2\",\"displayName\":\"Block legacy authentication\",\"enforcedGrantControls\":[\"Block\"],\"result\":\"notApplied\"}]"),
            ("ConditionalAccessStatusDetail", "notApplied"),
            ("AppliedConditionalAccessPolicies", "[{\"id\":\"p1\",\"displayName\":\"Require MFA for all users\",\"result\":\"success\",\"enforcedGrantControls\":[\"Mfa\"],\"enforcedSessionControls\":[]},{\"id\":\"p2\",\"displayName\":\"Block legacy authentication\",\"result\":\"notApplied\",\"enforcedGrantControls\":[\"Block\"],\"enforcedSessionControls\":[]}]"),
            ("TokenIssuerName", "contoso.onmicrosoft.com"),
            ("TokenIssuerType", "AzureAD"),
            ("ServicePrincipalName", "graph-api"),
            ("ServicePrincipalId", "sp-0001"),
            ("ManagedIdentityName", "mi-0001"),
            ("ClientCredentialType", "none"),
            ("UserAgentDetail", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0"),
            ("UserTypeDetail", "Member"),
            ("AccountDisplayName", "Contoso User Account Display Name"),
            ("ActorUserPrincipalName", "actor@contoso.com"),
            ("TargetUserName", "target@contoso.com"),
            ("SignInIdentifier", "sid-0001"),
            ("ErrorReasonDetail", "The user could not be authenticated due to an invalid password or expired credential state on the account"),
        ];
        for (key, value) in noise_fields {
            map.insert(key.to_string(), json!(value));
        }
        Value::Object(map)
    }

    #[test]
    fn summarize_query_compresses_realistic_45_column_signin_payload() {
        let rows: Vec<Value> = (0..25).map(wide_signin_row_45).collect();
        let resp = json!({ "rows": rows, "row_count": rows.len() });
        assert!(est_tokens(&resp) > THRESHOLD, "fixture must exceed THRESHOLD");

        let summary = summarize("/kql", &resp, "h#1").expect("should summarize");

        let top = summary["top"].as_array().expect("top is an array");
        for row in top {
            let obj = row.as_object().expect("row is an object");
            assert!(
                obj.len() <= MAX_PROJECTED_KEYS,
                "projected row should have at most MAX_PROJECTED_KEYS columns, got {}",
                obj.len()
            );
        }

        let untrimmed_top: Vec<Value> = resp["rows"]
            .as_array()
            .unwrap()
            .iter()
            .take(5)
            .cloned()
            .collect();
        let untrimmed = json!({
            "_summary": true,
            "kind": "query",
            "counts": summary["counts"].clone(),
            "top": untrimmed_top,
            "detail_ref": "h#1",
        });

        let projected_tokens = est_tokens(&summary);
        let untrimmed_tokens = est_tokens(&untrimmed);
        assert!(
            // Threshold loosened from 20% (80% smaller) to 35%: see the
            // comment on the analogous assertion above — aggregates add a
            // bounded amount of distribution data over all 25 rows.
            projected_tokens <= untrimmed_tokens * 35 / 100,
            "projected ({projected_tokens}) should be at least 65% smaller than untrimmed ({untrimmed_tokens})"
        );
    }

    /// Builds a wide (~40-key) SecurityEvent-shaped row: the SECURITYEVENT_PRIORITY
    /// columns (incl. `EventID`, which matches no generic signal substring)
    /// plus Azure-plumbing noise columns.
    fn security_event_row(i: usize) -> Value {
        json!({
            "Type": "SecurityEvent",
            "TimeGenerated": format!("2026-07-14T12:{:02}:00Z", i % 60),
            "Computer": format!("WKSTN-{i:03}.contoso.com"),
            "Account": format!("CONTOSO\\user{i}"),
            "AccountDomain": "CONTOSO",
            "EventID": 4688,
            "Activity": "4688 - A new process has been created.",
            "IPAddress": format!("10.0.{}.{}", i % 256, (i * 7) % 256),
            "ClientIPAddress": format!("10.0.{}.{}", i % 256, (i * 3) % 256),
            "LogonType": 3,
            "CommandLine": format!("cmd.exe /c whoami-{i}"),
            "CallerProcessName": "C:\\Windows\\explorer.exe",
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "TargetUserName": format!("user{i}"),
            "SubjectUserName": format!("user{i}"),
            "TenantId": "11111111-2222-3333-4444-555555555555",
            "ResourceId": "/subscriptions/x/resourceGroups/y",
            "CorrelationId": format!("corr-{i}"),
            "SourceSystem": "OpsManager",
            "OperationVersion": "1.0",
            "SubscriptionId": "sub-abc",
            "AadTenantId": "aad-xyz",
            "col_noise_1": "n1",
            "col_noise_2": "n2",
            "col_noise_3": "n3",
            "col_noise_4": "n4",
            "col_noise_5": "n5",
            "col_noise_6": "n6",
            "col_noise_7": "n7",
            "col_noise_8": "n8",
            "col_noise_9": "n9",
            "col_noise_10": "n10",
            "col_noise_11": "n11",
            "col_noise_12": "n12",
            "col_noise_13": "n13",
            "col_noise_14": "n14",
            "col_noise_15": "n15",
            "col_noise_16": "n16",
            "col_noise_17": "n17",
            "col_noise_18": "n18",
        })
    }

    /// Builds a wide AWSCloudTrail-shaped row: the CLOUDTRAIL_PRIORITY
    /// columns plus Azure/AWS-plumbing noise columns.
    fn cloudtrail_row(i: usize) -> Value {
        json!({
            "Type": "AWSCloudTrail",
            "TimeGenerated": format!("2026-07-14T12:{:02}:00Z", i % 60),
            "EventName": "AssumeRole",
            "EventSource": "sts.amazonaws.com",
            "EventTypeName": "AwsApiCall",
            "UserIdentityType": "IAMUser",
            "UserIdentityArn": format!("arn:aws:iam::123456789012:user/user{i}"),
            "UserIdentityUserName": format!("user{i}"),
            "UserIdentityAccountId": "123456789012",
            "SourceIpAddress": format!("10.0.{}.{}", i % 256, (i * 7) % 256),
            "AwsRegion": "us-east-1",
            "ErrorCode": if i % 3 == 0 { "AccessDenied" } else { "" },
            "UserAgent": "aws-cli/2.15.0",
            "TenantId": "11111111-2222-3333-4444-555555555555",
            "ResourceId": "/subscriptions/x/resourceGroups/y",
            "CorrelationId": format!("corr-{i}"),
            "SourceSystem": "AmazonWebServices",
            "OperationVersion": "1.0",
            "SubscriptionId": "sub-abc",
            "AadTenantId": "aad-xyz",
            "col_noise_1": "n1",
            "col_noise_2": "n2",
            "col_noise_3": "n3",
            "col_noise_4": "n4",
            "col_noise_5": "n5",
            "col_noise_6": "n6",
            "col_noise_7": "n7",
            "col_noise_8": "n8",
        })
    }

    #[test]
    fn summarize_detects_securityevent_table_and_keeps_eventid_and_computer() {
        let rows: Vec<Value> = (0..25).map(security_event_row).collect();
        let resp = json!({ "rows": rows, "row_count": rows.len() });
        assert!(est_tokens(&resp) > THRESHOLD, "fixture must exceed THRESHOLD");

        let summary = summarize("/kql", &resp, "h#se").expect("should summarize");
        let top = summary["top"].as_array().expect("top is an array");
        let first = top[0].as_object().expect("row is an object");

        assert!(first.contains_key("EventID"), "SecurityEvent priority list should keep EventID");
        assert!(first.contains_key("Computer"), "SecurityEvent priority list should keep Computer");
        assert!(!is_signal_key("EventID"), "EventID must not match the generic signal filter");

        for noise_key in ["TenantId", "ResourceId", "CorrelationId", "col_noise_1"] {
            assert!(!first.contains_key(noise_key), "noise key {noise_key} should be projected out");
        }
        assert!(first.len() <= MAX_PROJECTED_KEYS);
    }

    #[test]
    fn summarize_detects_cloudtrail_table_with_its_own_columns() {
        let rows: Vec<Value> = (0..25).map(cloudtrail_row).collect();
        let resp = json!({ "rows": rows, "row_count": rows.len() });
        assert!(est_tokens(&resp) > THRESHOLD, "fixture must exceed THRESHOLD");

        let summary = summarize("/kql", &resp, "h#ct").expect("should summarize");
        let top = summary["top"].as_array().expect("top is an array");
        let first = top[0].as_object().expect("row is an object");

        assert!(first.contains_key("EventName"), "CloudTrail priority list should keep EventName");
        assert!(first.contains_key("SourceIpAddress"), "CloudTrail priority list should keep SourceIpAddress");

        for signin_only_key in ["UserPrincipalName", "AppDisplayName", "ConditionalAccessStatus"] {
            assert!(
                !first.contains_key(signin_only_key),
                "SigninLogs-only key {signin_only_key} should not appear in a CloudTrail projection"
            );
        }
        assert!(first.len() <= MAX_PROJECTED_KEYS);
    }

    #[test]
    fn summarize_unknown_table_falls_back_to_identity_default() {
        let mut row = wide_signin_row(1);
        row.as_object_mut()
            .unwrap()
            .insert("Type".to_string(), json!("SomethingElse"));
        let rows: Vec<Value> = (0..25).map(|_| row.clone()).collect();
        let resp = json!({ "rows": rows, "row_count": rows.len() });
        assert!(est_tokens(&resp) > THRESHOLD, "fixture must exceed THRESHOLD");

        let summary = summarize("/kql", &resp, "h#unk").expect("should summarize");
        let top = summary["top"].as_array().expect("top is an array");
        let first = top[0].as_object().expect("row is an object");

        assert!(!first.is_empty(), "unknown-table row should still project a non-empty result");
        assert!(first.len() <= MAX_PROJECTED_KEYS);
    }

    #[test]
    fn trim_row_keeps_eventid_via_priority_bypass_of_signal_filter() {
        let row = security_event_row(1);
        assert!(!is_signal_key("EventID"), "EventID must not match is_signal_key");

        let trimmed = trim_row(&row, SECURITYEVENT_PRIORITY);
        let trimmed_obj = trimmed.as_object().expect("trimmed row is an object");
        assert!(
            trimmed_obj.contains_key("EventID"),
            "priority list must keep EventID even though it fails the generic signal filter"
        );
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
        // Traverse kind never computes aggregates: they're a `query`-kind concept.
        assert!(summary.get("aggregates").is_none());
    }

    /// 25-row SigninLogs-shaped fixture with a controlled distribution:
    /// `ResultType` is "50126" in 12 rows, "50097" in 8, "0" in 5 (12+8+5=25);
    /// `UserPrincipalName` cycles through 7 distinct values.
    fn signin_distribution_response() -> Value {
        let rows: Vec<Value> = (0..25)
            .map(|i| {
                let result_type = if i < 12 {
                    "50126"
                } else if i < 20 {
                    "50097"
                } else {
                    "0"
                };
                json!({
                    "Type": "SigninLogs",
                    "TimeGenerated": format!("2026-07-14T12:{:02}:00Z", i % 60),
                    "UserPrincipalName": format!("user{}@contoso.com", i % 7),
                    "IPAddress": format!("10.0.0.{i}"),
                    "ResultType": result_type,
                    "AppDisplayName": "Azure Portal",
                })
            })
            .collect();
        json!({ "rows": rows, "row_count": rows.len() })
    }

    #[test]
    fn aggregates_report_distinct_counts_and_top_n_for_key_columns() {
        let resp = signin_distribution_response();
        assert!(est_tokens(&resp) > THRESHOLD, "fixture must exceed THRESHOLD");

        let summary = summarize("/kql", &resp, "h#agg1").expect("should summarize");

        assert_eq!(summary["aggregates"]["ResultType"]["distinct"], json!(3));
        assert_eq!(
            summary["aggregates"]["ResultType"]["top"][0],
            json!({"value": "50126", "count": 12})
        );
        assert_eq!(summary["aggregates"]["UserPrincipalName"]["distinct"], json!(7));
    }

    #[test]
    fn aggregates_surface_dominant_actor_frequency() {
        // 25-row AWSCloudTrail-shaped fixture where one UserIdentityArn value
        // dominates 17/25 rows (68%) — the "dominant actor" needle.
        let rows: Vec<Value> = (0..25)
            .map(|i| {
                let arn = if i < 17 {
                    "arn:aws:iam::123456789012:user/dominant-actor".to_string()
                } else {
                    format!("arn:aws:iam::123456789012:user/user{i}")
                };
                json!({
                    "Type": "AWSCloudTrail",
                    "TimeGenerated": format!("2026-07-14T12:{:02}:00Z", i % 60),
                    "EventName": "AssumeRole",
                    "UserIdentityArn": arn,
                    "SourceIpAddress": format!("10.0.0.{i}"),
                })
            })
            .collect();
        let resp = json!({ "rows": rows, "row_count": rows.len() });
        assert!(est_tokens(&resp) > THRESHOLD, "fixture must exceed THRESHOLD");

        let summary = summarize("/kql", &resp, "h#agg2").expect("should summarize");

        assert_eq!(summary["aggregates"]["UserIdentityArn"]["top"][0]["count"], json!(17));
        assert_eq!(
            summary["aggregates"]["UserIdentityArn"]["top"][0]["value"],
            json!("arn:aws:iam::123456789012:user/dominant-actor")
        );
    }

    #[test]
    fn aggregate_columns_breaks_count_ties_by_value_ascending() {
        let rows: Vec<Value> = vec![
            json!({"col": "b"}),
            json!({"col": "b"}),
            json!({"col": "a"}),
            json!({"col": "a"}),
            json!({"col": "c"}),
        ];
        let agg = aggregate_columns(&rows, &["col".to_string()]);
        let top = agg["col"]["top"].as_array().expect("top is an array");

        // "a" and "b" tie at count=2; deterministic tiebreak is value ascending.
        assert_eq!(top[0], json!({"value": "a", "count": 2}));
        assert_eq!(top[1], json!({"value": "b", "count": 2}));
        assert_eq!(top[2], json!({"value": "c", "count": 1}));
    }

    #[test]
    fn aggregates_are_skipped_when_row_count_is_at_or_below_top_n() {
        // Individually large rows so the fixture exceeds THRESHOLD even
        // with only 4 rows (row_count <= TOP_N), so `top` alone should
        // already show every row and aggregates would add nothing.
        let long_value = "y".repeat(2000);
        let rows: Vec<Value> = (0..4)
            .map(|i| {
                json!({
                    "Type": "SigninLogs",
                    "TimeGenerated": format!("2026-07-14T12:{:02}:00Z", i),
                    "UserPrincipalName": format!("user{i}@contoso.com"),
                    "ResultType": "0",
                    "Filler": long_value.clone(),
                })
            })
            .collect();
        let resp = json!({ "rows": rows, "row_count": rows.len() });
        assert!(est_tokens(&resp) > THRESHOLD, "fixture must exceed THRESHOLD");
        assert!(rows.len() <= TOP_N, "fixture row_count must be <= TOP_N");

        let summary = summarize("/kql", &resp, "h#small").expect("should summarize");

        assert!(summary.get("aggregates").is_none(), "small responses should have no aggregates field");
        let top = summary["top"].as_array().expect("top is an array");
        assert_eq!(top.len(), 4, "top should still show every row");
    }

    #[test]
    fn aggregate_columns_truncates_long_values() {
        let long_value = "z".repeat(500);
        let rows = vec![json!({"col": long_value})];
        let agg = aggregate_columns(&rows, &["col".to_string()]);
        let top = agg["col"]["top"].as_array().expect("top is an array");

        assert_eq!(top.len(), 1);
        let kept = top[0]["value"].as_str().expect("value is a string");
        assert_eq!(kept.chars().count(), MAX_FIELD_CHARS + 1);
        assert!(kept.ends_with('…'));
        assert_eq!(top[0]["count"], json!(1));
    }

    // --- Fix A: signature-status columns in DEVICE_PRIORITY ---------------

    /// Builds a wide (~27-key) DeviceProcessEvents-shaped row: a subset of
    /// DEVICE_PRIORITY columns (omitting FolderPath/ProcessCommandLine/
    /// Sha256/ProcessId), including `InitiatingProcessSignatureStatus`, plus
    /// Azure-plumbing noise columns. Row 0 carries an unsigned binary. With
    /// DEVICE_PRIORITY reordered (Fix A), the signer columns survive
    /// projection both in this narrower shape and in a realistic FULL
    /// 14-priority-column row — see `realistic_full_device_row` below,
    /// which is the fixture that actually exercised the old append-at-end
    /// bug (that bug required all 12 higher-priority columns present, which
    /// this narrower fixture deliberately avoided).
    fn device_process_event_row(i: usize) -> Value {
        json!({
            "Type": "DeviceProcessEvents",
            "TimeGenerated": format!("2026-07-14T12:{:02}:00Z", i % 60),
            "DeviceName": format!("WKSTN-{i:03}.contoso.com"),
            "AccountName": format!("user{i}"),
            "ActionType": "ProcessCreated",
            "FileName": "powershell.exe",
            "InitiatingProcessFileName": "explorer.exe",
            "InitiatingProcessCommandLine": format!("powershell.exe -enc payload{i}"),
            "InitiatingProcessAccountName": format!("user{i}"),
            "InitiatingProcessSignerType": if i == 0 { "NotSigned" } else { "OsVendor" },
            "InitiatingProcessSignatureStatus": if i == 0 { "Unsigned" } else { "Valid" },
            "TenantId": "11111111-2222-3333-4444-555555555555",
            "ResourceId": "/subscriptions/x/resourceGroups/y",
            "CorrelationId": format!("corr-{i}"),
            "SourceSystem": "OpsManager",
            "OperationVersion": "1.0",
            "SubscriptionId": "sub-abc",
            "AadTenantId": "aad-xyz",
            "col_noise_1": "n1",
            "col_noise_2": "n2",
            "col_noise_3": "n3",
            "col_noise_4": "n4",
            "col_noise_5": "n5",
            "col_noise_6": "n6",
            "col_noise_7": "n7",
            "col_noise_8": "n8",
            "col_noise_9": "n9",
        })
    }

    #[test]
    fn summarize_projects_and_aggregates_signature_status_for_device_rows() {
        let rows: Vec<Value> = (0..25).map(device_process_event_row).collect();
        let resp = json!({ "rows": rows, "row_count": rows.len() });
        assert!(est_tokens(&resp) > THRESHOLD, "fixture must exceed THRESHOLD");

        let summary = summarize("/kql", &resp, "h#sig").expect("should summarize");
        let top = summary["top"].as_array().expect("top is an array");
        let first = top[0].as_object().expect("row is an object");

        assert!(
            first.contains_key("InitiatingProcessSignatureStatus"),
            "DEVICE_PRIORITY projection should keep InitiatingProcessSignatureStatus, got keys: {:?}",
            first.keys().collect::<Vec<_>>()
        );
        assert_eq!(first["InitiatingProcessSignatureStatus"], json!("Unsigned"));

        assert!(
            summary["aggregates"].get("InitiatingProcessSignatureStatus").is_some(),
            "signer status column should be aggregated across all rows"
        );
    }

    /// Builds a realistic ~27-key DeviceProcessEvents row carrying ALL 12
    /// non-signer DEVICE_PRIORITY columns (as real 73-column telemetry
    /// does) PLUS the two signer columns PLUS Azure-plumbing noise. Under
    /// the OLD append-at-end DEVICE_PRIORITY order, those 12 non-signer
    /// columns alone fill MAX_PROJECTED_KEYS before the priority scan ever
    /// reaches the signer entries at (old) positions 13-14 — cutting them
    /// entirely. This is the fixture that actually exercised the bug Fix A
    /// closes; `device_process_event_row` above was a narrower shape that
    /// happened to dodge it.
    fn realistic_full_device_row(i: usize) -> Value {
        json!({
            "Type": "DeviceProcessEvents",
            "TimeGenerated": format!("2026-07-14T12:{:02}:00Z", i % 60),
            "DeviceName": format!("WKSTN-{i:03}.contoso.com"),
            "AccountName": format!("user{i}"),
            "ActionType": "ProcessCreated",
            "FileName": "powershell.exe",
            "ProcessCommandLine": format!("powershell.exe -enc payload{i}"),
            "InitiatingProcessFileName": "explorer.exe",
            "InitiatingProcessCommandLine": "explorer.exe /startup",
            "Sha256": format!("{:064x}", i),
            "FolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "InitiatingProcessAccountName": format!("user{i}"),
            "ProcessId": 1000 + i,
            "InitiatingProcessSignerType": if i == 0 { "NotSigned" } else { "OsVendor" },
            "InitiatingProcessSignatureStatus": if i == 0 { "Unsigned" } else { "Valid" },
            "TenantId": "11111111-2222-3333-4444-555555555555",
            "ResourceId": "/subscriptions/x/resourceGroups/y",
            "CorrelationId": format!("corr-{i}"),
            "SourceSystem": "OpsManager",
            "OperationVersion": "1.0",
            "SubscriptionId": "sub-abc",
            "AadTenantId": "aad-xyz",
            "col_noise_1": "n1",
            "col_noise_2": "n2",
            "col_noise_3": "n3",
            "col_noise_4": "n4",
            "col_noise_5": "n5",
        })
    }

    #[test]
    fn summarize_promotes_signer_columns_into_full_device_row_projection() {
        let rows: Vec<Value> = (0..25).map(realistic_full_device_row).collect();
        let resp = json!({ "rows": rows, "row_count": rows.len() });
        assert!(est_tokens(&resp) > THRESHOLD, "fixture must exceed THRESHOLD");
        assert!(
            rows[0].as_object().unwrap().len() > WIDE_ROW_KEYS,
            "fixture must exceed WIDE_ROW_KEYS to trigger projection"
        );

        let summary = summarize("/kql", &resp, "h#sig-full").expect("should summarize");
        let top = summary["top"].as_array().expect("top is an array");
        let first = top[0].as_object().expect("row is an object");

        assert!(
            first.contains_key("InitiatingProcessSignatureStatus"),
            "signer status must survive projection even in a full 14-priority-column row, got keys: {:?}",
            first.keys().collect::<Vec<_>>()
        );
        assert!(
            first.contains_key("InitiatingProcessSignerType"),
            "signer type must survive projection even in a full 14-priority-column row, got keys: {:?}",
            first.keys().collect::<Vec<_>>()
        );

        let agg = summary["aggregates"]
            .get("InitiatingProcessSignatureStatus")
            .expect("signer status column should be aggregated");
        let top_values: Vec<&str> = agg["top"]
            .as_array()
            .expect("top is an array")
            .iter()
            .map(|v| v["value"].as_str().unwrap())
            .collect();
        assert!(
            top_values.contains(&"Unsigned"),
            "Unsigned value should appear in aggregates top, got {top_values:?}"
        );
    }

    // --- Fix B: total + rare (singleton) values in aggregates -------------

    #[test]
    fn aggregates_expose_total_for_exact_proportions() {
        // 25-row AWSCloudTrail-shaped fixture: EventSource is "ec2.amazonaws.com"
        // in 20/25 rows (80%) — total must make that proportion computable.
        let rows: Vec<Value> = (0..25)
            .map(|i| {
                let source = if i < 20 { "ec2.amazonaws.com" } else { "s3.amazonaws.com" };
                json!({
                    "Type": "AWSCloudTrail",
                    "TimeGenerated": format!("2026-07-14T12:{:02}:00Z", i % 60),
                    "EventName": "AssumeRole",
                    "EventSource": source,
                    "SourceIpAddress": format!("10.0.0.{i}"),
                })
            })
            .collect();
        let resp = json!({ "rows": rows, "row_count": rows.len() });
        assert!(est_tokens(&resp) > THRESHOLD, "fixture must exceed THRESHOLD");

        let summary = summarize("/kql", &resp, "h#total").expect("should summarize");

        assert_eq!(summary["aggregates"]["EventSource"]["total"], json!(25));
        assert_eq!(
            summary["aggregates"]["EventSource"]["top"][0],
            json!({"value": "ec2.amazonaws.com", "count": 20})
        );
    }

    #[test]
    fn aggregates_surface_singleton_value_hidden_by_top_n() {
        // 25-row fixture: EventName is "AssumeRole" x12 and "ListBuckets" x12
        // (both repeated), plus a single "GetBucketPublicAccessBlock" row —
        // the "rare successful action among failures" needle top-N hides.
        let rows: Vec<Value> = (0..25)
            .map(|i| {
                let name = if i == 24 {
                    "GetBucketPublicAccessBlock"
                } else if i % 2 == 0 {
                    "AssumeRole"
                } else {
                    "ListBuckets"
                };
                json!({
                    "Type": "AWSCloudTrail",
                    "TimeGenerated": format!("2026-07-14T12:{:02}:00Z", i % 60),
                    "EventName": name,
                    "SourceIpAddress": format!("10.0.0.{i}"),
                })
            })
            .collect();
        let resp = json!({ "rows": rows, "row_count": rows.len() });
        assert!(est_tokens(&resp) > THRESHOLD, "fixture must exceed THRESHOLD");

        let summary = summarize("/kql", &resp, "h#rare").expect("should summarize");

        let rare = summary["aggregates"]["EventName"]["rare"]
            .as_array()
            .expect("rare is an array");
        let rare_values: Vec<&str> = rare.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(
            rare_values.contains(&"GetBucketPublicAccessBlock"),
            "singleton value should be in rare, got {rare_values:?}"
        );
        assert!(
            !rare_values.contains(&"AssumeRole"),
            "repeated value must not be in rare"
        );
        assert!(
            !rare_values.contains(&"ListBuckets"),
            "repeated value must not be in rare"
        );
    }

    #[test]
    fn aggregates_omit_rare_key_when_no_singletons_exist() {
        // Reuses the ResultType distribution (12/8/5 — every value repeats,
        // minimum count is 5) from signin_distribution_response: no
        // singletons anywhere, so `rare` must be entirely absent.
        let resp = signin_distribution_response();
        let summary = summarize("/kql", &resp, "h#norare").expect("should summarize");

        assert!(
            summary["aggregates"]["ResultType"].get("rare").is_none(),
            "column with no singleton values should have no rare key"
        );
    }

    #[test]
    fn aggregate_columns_rare_values_are_sorted_ascending_and_capped() {
        let mut rows: Vec<Value> = Vec::new();
        // A non-singleton value (count = 3) that must never appear in rare.
        for _ in 0..3 {
            rows.push(json!({"col": "common"}));
        }
        // More singleton values than AGG_RARE_N (6), inserted out of
        // alphabetical order; only the first AGG_RARE_N (ascending) survive.
        for v in ["h", "d", "f", "b", "a", "g", "c", "e"] {
            rows.push(json!({"col": v}));
        }

        let agg = aggregate_columns(&rows, &["col".to_string()]);
        let rare = agg["col"]["rare"].as_array().expect("rare is an array");
        let rare_values: Vec<&str> = rare.iter().map(|v| v.as_str().unwrap()).collect();

        assert_eq!(rare_values, vec!["a", "b", "c", "d", "e", "f"]);
        assert_eq!(rare_values.len(), AGG_RARE_N);
    }

    /// Fix B regression: a real CloudTrail sample had 7 singleton EventName
    /// values where the hunt-relevant success event (`GetBucketPublicAccessBlock`)
    /// was the 5th alphabetically — invisible under the old AGG_RARE_N=3 cap.
    #[test]
    fn aggregates_rare_widened_to_six_surfaces_fifth_alphabetical_singleton() {
        let singleton_names = [
            "CreateBucket",
            "DeleteBucket",
            "DescribeInstances",
            "GetBucketAcl",
            "GetBucketPublicAccessBlock",
            "ListRoles",
            "PutBucketPolicy",
        ];
        let mut rows: Vec<Value> = (0..18)
            .map(|i| {
                json!({
                    "Type": "AWSCloudTrail",
                    "TimeGenerated": format!("2026-07-14T12:{:02}:00Z", i % 60),
                    "EventName": "AssumeRole",
                    "SourceIpAddress": format!("10.0.0.{i}"),
                })
            })
            .collect();
        for (i, name) in singleton_names.iter().enumerate() {
            rows.push(json!({
                "Type": "AWSCloudTrail",
                "TimeGenerated": format!("2026-07-14T13:{:02}:00Z", i),
                "EventName": name,
                "SourceIpAddress": format!("10.0.1.{i}"),
            }));
        }
        let resp = json!({ "rows": rows, "row_count": rows.len() });
        assert!(est_tokens(&resp) > THRESHOLD, "fixture must exceed THRESHOLD");

        let summary = summarize("/kql", &resp, "h#rare6").expect("should summarize");

        let rare = summary["aggregates"]["EventName"]["rare"]
            .as_array()
            .expect("rare is an array");
        let rare_values: Vec<&str> = rare.iter().map(|v| v.as_str().unwrap()).collect();

        assert!(
            rare_values.contains(&"GetBucketPublicAccessBlock"),
            "5th-alphabetical singleton must surface with AGG_RARE_N=6, got {rare_values:?}"
        );
        assert!(rare.len() <= AGG_RARE_N);
        assert!(rare.len() <= 6);
    }
}
