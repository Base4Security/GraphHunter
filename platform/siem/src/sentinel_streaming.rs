//! Async Sentinel streaming primitives: transport trait, token cache,
//! KQL query builder, and per-table watermark tracking.
//!
//! Designed for the real-time polling connector in the Tauri app.
//! The transport trait (DIP) allows mock-testing the polling loop.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde_json::{Map, Value};
use tokio::sync::RwLock;

use super::sentinel::{SentinelAuth, SentinelQueryResult, parse_query_stats};

// ── Token response ──

pub struct TokenResponse {
    pub access_token: String,
    /// Seconds until the token expires (from Azure response).
    pub expires_in: u64,
}

// ── Transport trait (DIP: depend on abstraction, not concrete HTTP) ──

/// Abstraction over Azure OAuth + Log Analytics HTTP calls.
/// Enables unit-testing the polling loop with a mock transport.
pub trait SentinelTransport: Send + Sync {
    fn acquire_token(
        &self,
        tenant_id: &str,
        client_id: &str,
        client_secret: &str,
    ) -> impl std::future::Future<Output = Result<TokenResponse, String>> + Send;

    fn execute_query(
        &self,
        workspace_id: &str,
        query: &str,
        bearer: &str,
    ) -> impl std::future::Future<Output = Result<Value, String>> + Send;
}

/// Rejects IDs containing path separators to prevent URL-injection.
fn validate_url_segment(value: &str, name: &str) -> Result<(), String> {
    if value.contains('/') || value.contains('\\') {
        return Err(format!("invalid {name}: must not contain path separators"));
    }
    Ok(())
}

// ── HTTP transport (default implementation) ──

/// Production transport using reqwest async client with connection pooling.
pub struct HttpSentinelTransport {
    client: reqwest::Client,
}

impl HttpSentinelTransport {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .pool_max_idle_per_host(2)
                .timeout(Duration::from_secs(60))
                .build()
                .expect("reqwest client"),
        }
    }
}

impl SentinelTransport for HttpSentinelTransport {
    async fn acquire_token(
        &self,
        tenant_id: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<TokenResponse, String> {
        validate_url_segment(tenant_id, "tenant_id")?;
        let url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            tenant_id
        );
        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("scope", "https://api.loganalytics.io/.default"),
        ];
        let resp = self
            .client
            .post(&url)
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("token request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("token request failed: {} {}", status, body));
        }

        let json: Value = resp
            .json()
            .await
            .map_err(|e| format!("token response parse failed: {}", e))?;
        let access_token = json
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or("token response missing access_token")?
            .to_string();
        let expires_in = json
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600);

        Ok(TokenResponse {
            access_token,
            expires_in,
        })
    }

    async fn execute_query(
        &self,
        workspace_id: &str,
        query: &str,
        bearer: &str,
    ) -> Result<Value, String> {
        validate_url_segment(workspace_id, "workspace_id")?;
        let url = format!(
            "https://api.loganalytics.io/v1/workspaces/{}/query",
            workspace_id
        );
        let body = serde_json::json!({ "query": query });
        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", bearer))
            .header("Content-Type", "application/json")
            // Mirror the sync runner: request the `statistics` object so query
            // cost can be surfaced to callers.
            .header("Prefer", "include-statistics")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("query request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("query failed: {} {}", status, body));
        }

        resp.json()
            .await
            .map_err(|e| format!("query response parse failed: {}", e))
    }
}

// ── Token cache ──

struct CachedToken {
    access_token: String,
    expires_at: Instant,
}

/// Thread-safe token cache with double-checked locking.
/// Proactively refreshes 60 seconds before actual expiry.
pub struct SentinelTokenCache {
    inner: RwLock<Option<CachedToken>>,
}

impl SentinelTokenCache {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(None),
        }
    }

    /// Returns a valid token, refreshing if expired or absent.
    pub async fn get_or_refresh(
        &self,
        transport: &impl SentinelTransport,
        auth: &SentinelAuth,
    ) -> Result<String, String> {
        // Fast path: read lock
        {
            let guard = self.inner.read().await;
            if let Some(cached) = guard.as_ref() {
                if Instant::now() < cached.expires_at {
                    return Ok(cached.access_token.clone());
                }
            }
        }
        // Slow path: write lock, double-check
        let mut guard = self.inner.write().await;
        if let Some(cached) = guard.as_ref() {
            if Instant::now() < cached.expires_at {
                return Ok(cached.access_token.clone());
            }
        }
        let resp = transport
            .acquire_token(&auth.tenant_id, &auth.client_id, &auth.client_secret)
            .await?;
        let expires_at = Instant::now() + Duration::from_secs(resp.expires_in.saturating_sub(60));
        let token = resp.access_token.clone();
        *guard = Some(CachedToken {
            access_token: resp.access_token,
            expires_at,
        });
        Ok(token)
    }

    /// Invalidates the cached token (e.g., after auth error).
    pub async fn invalidate(&self) {
        let mut guard = self.inner.write().await;
        *guard = None;
    }
}

// ── KQL query builder ──

pub struct KqlQueryBuilder;

impl KqlQueryBuilder {
    /// Builds a KQL query for a Sentinel table.
    ///
    /// Cursors on `ingestion_time()` — monotonic w.r.t. when a row became
    /// queryable — rather than `TimeGenerated` (event time). Log Analytics
    /// ingests rows minutes after their event time, so a `TimeGenerated >
    /// watermark` cursor silently drops any row whose event time falls
    /// before the watermark but that ingests after it (late-arriving /
    /// out-of-order logs). `ingestion_time()` never skips a late arrival.
    ///
    /// `coalesce(ingestion_time(), TimeGenerated)` degrades gracefully for
    /// tables without an ingestion-time policy (those rows fall back to
    /// event time). `_ingest_ts` is an added column — every row keeps its
    /// original `TimeGenerated` for the parser.
    ///
    /// Resolution order for the `where ...` clause:
    ///   1. `watermark` set → `where _ingest_ts > datetime({watermark})`
    ///      (incremental polling — wins over any caller-supplied window).
    ///   2. `time_window_filter` set → use the caller's pre-rendered
    ///      event-time filter verbatim (first-poll backfill). Phase L: the
    ///      api crate renders this from its `TimeWindow` DTO via
    ///      `kql_filter()`; siem stays DTO-free so the dep direction
    ///      (api → siem, not the reverse) is preserved. The result is
    ///      still ordered by `_ingest_ts` so the watermark captured after
    ///      this poll is an ingestion-time value.
    ///   3. Neither set → `where _ingest_ts > ago(24h)` fallback for
    ///      callers that haven't migrated.
    pub fn build(
        table: &str,
        watermark: Option<&str>,
        batch_size: u32,
        time_window_filter: Option<&str>,
    ) -> String {
        let time_filter = match (watermark, time_window_filter) {
            (Some(w), _) => format!("where _ingest_ts > datetime({})", w),
            (None, Some(tw)) => tw.to_string(),
            (None, None) => "where _ingest_ts > ago(24h)".to_string(),
        };
        format!(
            "{} | extend _ingest_ts = coalesce(ingestion_time(), TimeGenerated) | {} | order by _ingest_ts asc | take {}",
            table, time_filter, batch_size
        )
    }
}

// ── Watermark store ──

/// Tracks per-table high-water marks for incremental polling.
pub struct SentinelWatermarkStore {
    watermarks: HashMap<String, String>,
}

impl SentinelWatermarkStore {
    pub fn new() -> Self {
        Self {
            watermarks: HashMap::new(),
        }
    }

    pub fn get(&self, table: &str) -> Option<&String> {
        self.watermarks.get(table)
    }

    pub fn set(&mut self, table: &str, watermark: String) {
        self.watermarks.insert(table.to_string(), watermark);
    }
}

// ── Normalize response (async-friendly re-export of existing logic) ──

/// Converts Log Analytics response to a `SentinelQueryResult`.
/// Re-uses the exact same normalization logic as the sync path.
pub fn normalize_response(raw: &Value) -> Result<SentinelQueryResult, String> {
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
        let ingest_ts_col = col_names.iter().position(|&n| n == "_ingest_ts");
        // Per-table decision: prefer `_ingest_ts` (ingestion-time watermark)
        // when this table's response projected it; otherwise fall back to
        // `TimeGenerated` so the sync hydration path (which never projects
        // `_ingest_ts`) keeps advancing its watermark unchanged.
        let watermark_col = ingest_ts_col.or(time_col);
        let rows = table
            .get("rows")
            .and_then(|r| r.as_array())
            .ok_or("table missing rows")?;

        for row in rows {
            let arr = row.as_array().ok_or("row is not array")?;
            let mut obj = Map::new();
            for (i, cell) in arr.iter().enumerate() {
                if let Some(&name) = col_names.get(i) {
                    let value = cell.clone();
                    if Some(i) == watermark_col {
                        if let Value::String(s) = &value {
                            if last_time
                                .as_ref()
                                .map(|t| s.as_str() > t.as_str())
                                .unwrap_or(true)
                            {
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

// ── Polling config ──

/// Configuration for the Sentinel polling connector.
#[derive(Clone)]
pub struct SentinelPollingConfig {
    pub workspace_id: String,
    pub auth: SentinelAuth,
    pub poll_interval_secs: u64,
    pub tables: Vec<String>,
    pub batch_size: u32,
    /// Pre-rendered KQL `where TimeGenerated ...` clause to apply on
    /// the first poll (before a watermark exists). Phase L: the api
    /// crate renders this from its `TimeWindow` DTO so the connector
    /// stays DTO-free. `None` keeps the legacy `ago(24h)` default.
    pub initial_time_window_filter: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kql_with_watermark() {
        let q = KqlQueryBuilder::build("SecurityEvent", Some("2024-01-15T14:30:00Z"), 10000, None);
        assert_eq!(
            q,
            "SecurityEvent | extend _ingest_ts = coalesce(ingestion_time(), TimeGenerated) \
             | where _ingest_ts > datetime(2024-01-15T14:30:00Z) \
             | order by _ingest_ts asc | take 10000"
        );
    }

    #[test]
    fn kql_without_watermark_uses_ingestion_time_default() {
        let q = KqlQueryBuilder::build("SigninLogs", None, 5000, None);
        assert_eq!(
            q,
            "SigninLogs | extend _ingest_ts = coalesce(ingestion_time(), TimeGenerated) \
             | where _ingest_ts > ago(24h) \
             | order by _ingest_ts asc | take 5000"
        );
    }

    /// Phase L / Sentinel Task 1: no watermark yet, so the caller's
    /// event-time backfill filter is used verbatim — but the query still
    /// projects + orders by `_ingest_ts` so the first watermark captured
    /// is an ingestion_time value (subsequent polls are ingestion-cursored).
    #[test]
    fn kql_first_poll_uses_caller_window_then_orders_by_ingest_ts() {
        let q = KqlQueryBuilder::build(
            "SigninLogs",
            None,
            5000,
            Some("where TimeGenerated > ago(7d)"),
        );
        assert_eq!(
            q,
            "SigninLogs | extend _ingest_ts = coalesce(ingestion_time(), TimeGenerated) \
             | where TimeGenerated > ago(7d) \
             | order by _ingest_ts asc | take 5000"
        );
    }

    /// Phase L: watermark always wins — the per-table incremental
    /// pointer is more authoritative than a UI lookback selection.
    #[test]
    fn kql_watermark_wins_over_time_window() {
        let q = KqlQueryBuilder::build(
            "SigninLogs",
            Some("2024-01-15T14:30:00Z"),
            5000,
            Some("where TimeGenerated > ago(7d)"),
        );
        assert!(
            q.contains("_ingest_ts > datetime(2024-01-15T14:30:00Z)"),
            "watermark must win: {q}"
        );
        assert!(
            !q.contains("ago(7d)"),
            "time_window leaked despite watermark: {q}"
        );
    }

    #[test]
    fn watermark_store_tracks_per_table() {
        let mut store = SentinelWatermarkStore::new();
        store.set("SecurityEvent", "2024-01-15T14:30:00Z".into());
        store.set("SigninLogs", "2024-01-15T15:00:00Z".into());
        assert_eq!(store.get("SecurityEvent").unwrap(), "2024-01-15T14:30:00Z");
        assert_eq!(store.get("SigninLogs").unwrap(), "2024-01-15T15:00:00Z");
        assert!(store.get("DeviceProcessEvents").is_none());
    }

    #[test]
    fn normalize_advances_watermark_on_ingest_ts_when_present() {
        let raw = serde_json::json!({
            "tables": [{
                "columns": [
                    {"name": "TimeGenerated", "type": "datetime"},
                    {"name": "_ingest_ts", "type": "datetime"}
                ],
                "rows": [
                    ["2024-01-15T10:00:00Z", "2024-01-15T10:05:00Z"],
                    ["2024-01-15T09:00:00Z", "2024-01-15T10:07:00Z"]  // late event, later ingest
                ]
            }]
        });
        let r = normalize_response(&raw).unwrap();
        // Watermark = max ingestion time, NOT max event time.
        assert_eq!(r.next_query_start.as_deref(), Some("2024-01-15T10:07:00Z"));
    }

    #[test]
    fn normalize_falls_back_to_timegenerated_without_ingest_ts() {
        let raw = serde_json::json!({
            "tables": [{
                "columns": [{"name": "TimeGenerated", "type": "datetime"}],
                "rows": [["2024-01-15T10:00:00Z"], ["2024-01-15T10:30:00Z"]]
            }]
        });
        let r = normalize_response(&raw).unwrap();
        assert_eq!(r.next_query_start.as_deref(), Some("2024-01-15T10:30:00Z"));
    }
}
