//! Azure Sentinel (Log Analytics) query runner.
//!
//! Uses Azure AD client credentials and Log Analytics Query REST API.
//! Auth via env: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET.

use serde_json::{Map, Value};

/// Result of a Sentinel query: parser-ready JSON string and optional pagination state.
#[derive(Debug)]
pub struct SentinelQueryResult {
    /// JSON array or NDJSON string suitable for SentinelJsonParser.
    pub data: String,
    /// Last TimeGenerated seen (ISO8601 or epoch string) for next query_start.
    pub next_query_start: Option<String>,
    /// Query cost reported by Log Analytics when `Prefer: include-statistics`
    /// was honored. `None` when the service returned no `statistics` object.
    pub stats: Option<QueryStats>,
}

/// Cost/statistics for a single Log Analytics query, extracted from the
/// response `statistics` object. Plain data (no serde derive) to keep the
/// siem crate dependency-light; the API layer maps this into its own
/// serializable cost DTO for tool responses.
#[derive(Debug, Clone, Default)]
pub struct QueryStats {
    /// Bytes scanned across input datasets, when the service reports it.
    pub bytes_scanned: Option<u64>,
    /// Server-side execution time in milliseconds (`statistics.query.executionTime`).
    pub server_duration_ms: Option<u64>,
}

/// Best-effort extraction of `statistics` from a Log Analytics query response.
/// Defensive: any missing/renamed field degrades to `None` rather than erroring,
/// because the statistics shape is not part of the stable contract and is only
/// present when `Prefer: include-statistics` was honored.
pub fn parse_query_stats(raw: &serde_json::Value) -> Option<QueryStats> {
    let query = raw.get("statistics")?.get("query")?;
    // executionTime is in seconds (float); convert to ms.
    let server_duration_ms = query
        .get("executionTime")
        .and_then(|v| v.as_f64())
        .map(|secs| (secs * 1000.0).round() as u64);
    // Bytes scanned is not consistently exposed; sum per-table `tableSize`
    // from datasetStatistics when present.
    let bytes_scanned = query
        .get("datasetStatistics")
        .and_then(|v| v.as_array())
        .map(|tables| {
            tables
                .iter()
                .filter_map(|t| t.get("tableSize").and_then(|s| s.as_u64()))
                .sum::<u64>()
        })
        .filter(|&b| b > 0);
    if server_duration_ms.is_none() && bytes_scanned.is_none() {
        return None;
    }
    Some(QueryStats { bytes_scanned, server_duration_ms })
}

/// Optional Azure AD credentials. When provided, used instead of env vars.
#[derive(Clone)]
pub struct SentinelAuth {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
}

/// Runs a KQL query against Log Analytics and returns normalized JSON + pagination state.
///
/// - `workspace_id`: Log Analytics workspace ID (GUID).
/// - `query`: KQL query string (if empty, a default is used: SecurityEvent, last 24h, take 10000).
/// - `auth`: When provided, use these credentials; otherwise read AZURE_* from env.
pub fn run_sentinel_query(
    workspace_id: &str,
    query: &str,
    auth: Option<SentinelAuth>,
) -> Result<SentinelQueryResult, String> {
    let (tenant, client_id, client_secret) = match auth {
        Some(a) => (a.tenant_id, a.client_id, a.client_secret),
        None => (
            std::env::var("AZURE_TENANT_ID").map_err(|_| "AZURE_TENANT_ID not set")?,
            std::env::var("AZURE_CLIENT_ID").map_err(|_| "AZURE_CLIENT_ID not set")?,
            std::env::var("AZURE_CLIENT_SECRET").map_err(|_| "AZURE_CLIENT_SECRET not set")?,
        ),
    };

    let token = get_azure_token(&tenant, &client_id, &client_secret)?;
    let query = if query.trim().is_empty() {
        "SecurityEvent | where TimeGenerated > ago(24h) | take 10000"
    } else {
        query
    };
    let raw = execute_log_analytics_query(workspace_id, query, &token)?;
    normalize_log_analytics_response(&raw)
}

/// Obtains a Bearer token for Log Analytics scope using client credentials.
fn get_azure_token(tenant: &str, client_id: &str, client_secret: &str) -> Result<String, String> {
    let url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant
    );
    let params = [
        ("grant_type", "client_credentials"),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("scope", "https://api.loganalytics.io/.default"),
    ];
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&url)
        .form(&params)
        .send()
        .map_err(|e| format!("token request failed: {}", e))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(format!("token request failed: {} {}", status, body));
    }
    let json: serde_json::Value = resp
        .json()
        .map_err(|e| format!("token response parse failed: {}", e))?;
    let access_token = json
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or("token response missing access_token")?;
    Ok(access_token.to_string())
}

/// POST to Log Analytics query API.
fn execute_log_analytics_query(
    workspace_id: &str,
    query: &str,
    bearer: &str,
) -> Result<serde_json::Value, String> {
    let url = format!(
        "https://api.loganalytics.io/v1/workspaces/{}/query",
        workspace_id
    );
    let body = serde_json::json!({
        "query": query
    });
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", bearer))
        .header("Content-Type", "application/json")
        // Ask Log Analytics to attach a `statistics` object so callers can
        // surface query cost (bytes scanned, server execution time).
        .header("Prefer", "include-statistics")
        .json(&body)
        .send()
        .map_err(|e| format!("query request failed: {}", e))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(format!("query failed: {} {}", status, body));
    }
    let json: serde_json::Value = resp
        .json()
        .map_err(|e| format!("query response parse failed: {}", e))?;
    Ok(json)
}

/// Converts Log Analytics response (tables[].columns + rows) to a JSON array of objects
/// and finds the latest TimeGenerated for pagination.
fn normalize_log_analytics_response(raw: &serde_json::Value) -> Result<SentinelQueryResult, String> {
    let tables = raw
        .get("tables")
        .and_then(|t| t.as_array())
        .ok_or("response missing tables array")?;
    let mut all_rows: Vec<Map<String, Value>> = Vec::new();
    let mut last_time: Option<String> = None;

    for table in tables {
        let columns = table
            .get("columns")
            .and_then(|c| c.as_array())
            .ok_or("table missing columns")?;
        let col_names: Vec<&str> = columns
            .iter()
            .filter_map(|c| c.get("name").and_then(|n| n.as_str()))
            .collect();
        let time_col = col_names.iter().position(|&n| n == "TimeGenerated");
        let rows = table
            .get("rows")
            .and_then(|r| r.as_array())
            .ok_or("table missing rows")?;

        for row in rows {
            let arr = row.as_array().ok_or("row is not array")?;
            let mut obj = Map::new();
            for (i, cell) in arr.iter().enumerate() {
                if let Some(&name) = col_names.get(i) {
                    let value = cell_value_to_json(cell);
                    if Some(i) == time_col {
                        if let Value::String(s) = &value {
                            if last_time.as_ref().map(|t| s.as_str() > t.as_str()).unwrap_or(true) {
                                last_time = Some(s.clone());
                            }
                        }
                    }
                    obj.insert(name.to_string(), value);
                }
            }
            all_rows.push(obj);
        }
    }

    let data = serde_json::to_string(&all_rows).map_err(|e| e.to_string())?;
    Ok(SentinelQueryResult {
        data,
        next_query_start: last_time,
        stats: parse_query_stats(raw),
    })
}

/// Converts a Log Analytics cell (which may be number, string, bool, etc.) to a JSON Value.
fn cell_value_to_json(v: &serde_json::Value) -> Value {
    match v {
        Value::Null => Value::Null,
        Value::Bool(b) => Value::Bool(*b),
        Value::Number(n) => Value::Number(n.clone()),
        Value::String(s) => Value::String(s.clone()),
        Value::Array(a) => Value::Array(a.iter().map(cell_value_to_json).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, v)| (k.clone(), cell_value_to_json(v))).collect()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinel_normalize_log_analytics_response() {
        // Minimal response mimicking Log Analytics API.
        let raw = serde_json::json!({
            "tables": [{
                "name": "PrimaryResult",
                "columns": [
                    {"name": "Type", "type": "string"},
                    {"name": "TimeGenerated", "type": "datetime"},
                    {"name": "Computer", "type": "string"}
                ],
                "rows": [
                    ["SecurityEvent", "2024-01-15T14:30:00Z", "DC-01"],
                    ["SecurityEvent", "2024-01-15T14:31:00Z", "DC-02"]
                ]
            }]
        });
        let result = normalize_log_analytics_response(&raw).unwrap();
        assert!(result.data.contains("SecurityEvent"));
        assert!(result.data.contains("DC-01"));
        assert_eq!(result.next_query_start.as_deref(), Some("2024-01-15T14:31:00Z"));
        // No statistics object in this response → no cost captured.
        assert!(result.stats.is_none());
    }

    #[test]
    fn parse_query_stats_extracts_duration_and_bytes() {
        let raw = serde_json::json!({
            "tables": [],
            "statistics": {
                "query": {
                    "executionTime": 0.5,
                    "datasetStatistics": [
                        {"tableSize": 1000},
                        {"tableSize": 2000}
                    ]
                }
            }
        });
        let stats = parse_query_stats(&raw).expect("stats present");
        assert_eq!(stats.server_duration_ms, Some(500));
        assert_eq!(stats.bytes_scanned, Some(3000));
    }

    #[test]
    fn parse_query_stats_absent_is_none() {
        let raw = serde_json::json!({ "tables": [] });
        assert!(parse_query_stats(&raw).is_none());
    }
}
