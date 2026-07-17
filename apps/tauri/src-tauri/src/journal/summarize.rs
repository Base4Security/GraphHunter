use serde_json::{json, Map, Value};

use super::interpret::classify_kind;

/// Soft-cap (in estimated tokens) above which a response is worth summarizing.
/// Anything at or below this is already small enough to hand back as-is.
const THRESHOLD: u64 = 400;

/// Max number of representative rows/items kept in `top`.
const TOP_N: usize = 5;

/// Max characters kept for a single string field value in a `top` row before truncation.
const MAX_FIELD_CHARS: usize = 200;

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

/// Ordered highest-value hunt columns. When a wide row's signal projection
/// still exceeds MAX_PROJECTED_KEYS, these are kept FIRST (in this order),
/// then remaining signal keys in original order, capped at MAX_PROJECTED_KEYS.
/// Matched case-insensitively against the FULL key name (exact, lowercased).
const HUNT_PRIORITY_KEYS: &[&str] = &[
    "timegenerated", "userprincipalname", "userdisplayname", "ipaddress",
    "location", "resulttype", "resultdescription", "appdisplayname",
    "clientappused", "devicedetail", "riskstate", "status",
    "conditionalaccessstatus", "category", "identity", "operationname",
];

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
        .map(|r| r.iter().take(TOP_N).map(trim_row).collect())
        .unwrap_or_default();
    (json!({ "row_count": row_count }), top)
}

/// Compacts one representative row for `top`: drops fields whose value is
/// null or an empty string (Sentinel rows carry many empty columns that add
/// bytes but no signal), and truncates over-long string values. Non-object
/// rows (arrays, scalars) are returned unchanged.
///
/// Wide rows (Sentinel/AAD logs carry ~74 columns, mostly Azure metadata
/// such as TenantId, ResourceId, CorrelationId) often have zero empty
/// values, so the drop-empty step alone doesn't touch them — the real
/// token cost is column COUNT. If the surviving object still has more than
/// `WIDE_ROW_KEYS` keys, it is projected down to hunt-relevant ("signal")
/// columns; if that projection yields too few keys to be useful, an
/// order-preserving fallback keeps the first `WIDE_ROW_KEYS` surviving keys.
fn trim_row(row: &Value) -> Value {
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

    let projected: Map<String, Value> = trimmed
        .iter()
        .filter(|(key, _)| is_signal_key(key))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    if projected.len() >= MIN_PROJECTED_KEYS {
        if projected.len() > MAX_PROJECTED_KEYS {
            Value::Object(cap_to_priority_keys(projected))
        } else {
            Value::Object(projected)
        }
    } else {
        let fallback: Map<String, Value> = trimmed
            .into_iter()
            .take(WIDE_ROW_KEYS)
            .collect();
        Value::Object(fallback)
    }
}

/// Reduces an already signal-projected row down to at most `MAX_PROJECTED_KEYS`
/// columns: `HUNT_PRIORITY_KEYS` present in `projected` are kept first (in
/// priority order, matched case-insensitively against the full key name),
/// then remaining projected keys are appended in their original order until
/// the cap is reached. Values are preserved unchanged.
fn cap_to_priority_keys(projected: Map<String, Value>) -> Map<String, Value> {
    let mut result = Map::new();

    for priority in HUNT_PRIORITY_KEYS {
        if result.len() >= MAX_PROJECTED_KEYS {
            break;
        }
        if let Some((key, value)) = projected
            .iter()
            .find(|(key, _)| key.to_lowercase() == *priority)
        {
            result.insert(key.clone(), value.clone());
        }
    }

    for (key, value) in &projected {
        if result.len() >= MAX_PROJECTED_KEYS {
            break;
        }
        if !result.contains_key(key) {
            result.insert(key.clone(), value.clone());
        }
    }

    result
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
        let trimmed = trim_row(&row);
        assert_eq!(trimmed, json!({"a": "x", "n": 42}));
    }

    #[test]
    fn trim_row_truncates_long_strings() {
        let long_value = "z".repeat(500);
        let row = json!({"field": long_value});
        let trimmed = trim_row(&row);
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
            trimmed_tokens <= untrimmed_tokens * 60 / 100,
            "trimmed ({trimmed_tokens}) should be at least 40% smaller than untrimmed ({untrimmed_tokens})"
        );
    }

    /// Builds a wide (~30-key) row mixing Azure-noise columns with
    /// hunt-signal columns, mirroring a real SigninLogs row shape.
    fn wide_signin_row(i: usize) -> Value {
        json!({
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

        let trimmed = trim_row(&row);
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

        let trimmed = trim_row(&row);
        let trimmed_obj = trimmed.as_object().expect("trimmed row is an object");
        assert_eq!(trimmed_obj.len(), 6);
        for key in obj.keys() {
            assert!(trimmed_obj.contains_key(key));
        }
    }

    #[test]
    fn trim_row_falls_back_to_first_n_keys_when_no_signal_matches() {
        let mut map = Map::new();
        for i in 1..=25 {
            map.insert(format!("col{i}"), json!(format!("v{i}")));
        }
        let row = Value::Object(map.clone());
        assert!(map.len() > WIDE_ROW_KEYS, "fixture must exceed WIDE_ROW_KEYS");

        let trimmed = trim_row(&row);
        let trimmed_obj = trimmed.as_object().expect("trimmed row is an object");
        assert_eq!(trimmed_obj.len(), WIDE_ROW_KEYS);

        let expected_first_keys: Vec<String> =
            map.keys().take(WIDE_ROW_KEYS).cloned().collect();
        for key in &expected_first_keys {
            assert!(
                trimmed_obj.contains_key(key),
                "fallback should keep first {WIDE_ROW_KEYS} original keys, missing {key}"
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
            projected_tokens <= untrimmed_tokens * 40 / 100,
            "projected ({projected_tokens}) should be at least 60% smaller than untrimmed ({untrimmed_tokens})"
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

        let trimmed = trim_row(&row);
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

        let trimmed = trim_row(&row);
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

        let trimmed = trim_row(&row);
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
            projected_tokens <= untrimmed_tokens * 20 / 100,
            "projected ({projected_tokens}) should be at least 80% smaller than untrimmed ({untrimmed_tokens})"
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
    }
}
