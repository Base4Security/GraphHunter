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
}

/// Optional Azure AD credentials. When provided, used instead of env vars.
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
    }
}
