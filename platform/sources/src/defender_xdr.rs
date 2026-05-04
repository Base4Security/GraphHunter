//! Microsoft Defender XDR Advanced Hunting source.
//!
//! Implements [`LogSource`] against the Advanced Hunting REST API:
//!
//!   `POST https://api.security.microsoft.com/api/advancedhunting/run`
//!
//! Body shape:
//!
//! ```json
//! { "Query": "DeviceProcessEvents | where ... | take 100" }
//! ```
//!
//! Defender XDR uses the same KQL dialect as Log Analytics but a
//! different table surface (device-centric, no `TimeGenerated` — the
//! `Timestamp` column is the temporal field). This impl ships parser
//! support for three tables the plan calls out explicitly:
//!
//! - `DeviceProcessEvents`
//! - `DeviceNetworkEvents`
//! - `DeviceFileEvents`
//!
//! Additional tables can be added by extending `AVAILABLE_TABLES` and
//! adding rows to `ENTITY_COLUMN_ROUTING`. No other code changes needed.
//!
//! Auth scope: `https://api.security.microsoft.com/.default`
//! (see [`SourceKind::DefenderXdr::resource_scope`]).
//!
//! Quotas to remember in Phase 5's rate limiter:
//! - ~45 calls per minute per tenant
//! - ~100K rows max per call
//! - Per-tenant CPU resource quota enforced server-side (no precise
//!   number — throttled queries return an error in the body)
//!
//! [`LogSource`]: crate::LogSource

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::{self, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use crate::http_client::{HttpClient, HttpRequest, StatusClass};
use crate::token_cache::{AzureTokenCache, TokenKey};
use crate::{
    ChunkEncoding, ChunkStream, LogSource, PollStream, QueryScope, RawChunk, SourceError,
    SourceKind, Watermark,
};

/// Default Advanced Hunting API endpoint. Overridable for tests and
/// alternate-cloud / GCC deployments.
pub const DEFAULT_XDR_ENDPOINT: &str = "https://api.security.microsoft.com";

/// Curated tables this source supports. Matches the plan §2c directive
/// to ship three tables initially; extend as new parsers land.
const AVAILABLE_TABLES: &[&str] = &[
    "DeviceProcessEvents",
    "DeviceNetworkEvents",
    "DeviceFileEvents",
];

/// `(table, entity_type, column_name)` routing for Defender XDR tables.
/// Column names are drawn from the official Advanced Hunting schema
/// reference.
const ENTITY_COLUMN_ROUTING: &[(&str, &str, &str)] = &[
    ("DeviceProcessEvents", "Host", "DeviceName"),
    ("DeviceProcessEvents", "Process", "FileName"),
    ("DeviceProcessEvents", "User", "AccountName"),
    ("DeviceNetworkEvents", "Host", "DeviceName"),
    ("DeviceNetworkEvents", "IpAddress", "RemoteIP"),
    ("DeviceNetworkEvents", "Url", "RemoteUrl"),
    ("DeviceFileEvents", "Host", "DeviceName"),
    ("DeviceFileEvents", "File", "FileName"),
    ("DeviceFileEvents", "Process", "InitiatingProcessFileName"),
];

fn route_entity_column(table: &str, entity_type: &str) -> Option<&'static str> {
    ENTITY_COLUMN_ROUTING
        .iter()
        .find_map(|(t, et, col)| (*t == table && *et == entity_type).then_some(*col))
}

/// Configuration for a [`DefenderXdrSource`] instance.
#[derive(Debug, Clone)]
pub struct DefenderXdrConfig {
    pub source_id: String,
    pub tenant_id: String,
    pub endpoint: String,
    pub request_timeout: Duration,
    pub default_page_size: u32,
}

impl DefenderXdrConfig {
    pub fn new(source_id: impl Into<String>, tenant_id: impl Into<String>) -> Self {
        Self {
            source_id: source_id.into(),
            tenant_id: tenant_id.into(),
            endpoint: DEFAULT_XDR_ENDPOINT.to_string(),
            request_timeout: Duration::from_secs(60),
            // Defender XDR caps at ~100K rows per call; 10K is a safe
            // default for interactive drill-down.
            default_page_size: 10_000,
        }
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }
}

pub struct DefenderXdrSource {
    config: DefenderXdrConfig,
    http: Arc<dyn HttpClient>,
    tokens: Arc<AzureTokenCache>,
}

impl DefenderXdrSource {
    pub fn new(
        config: DefenderXdrConfig,
        http: Arc<dyn HttpClient>,
        tokens: Arc<AzureTokenCache>,
    ) -> Self {
        Self {
            config,
            http,
            tokens,
        }
    }

    fn token_key(&self) -> TokenKey {
        TokenKey::new(
            &self.config.tenant_id,
            SourceKind::DefenderXdr.resource_scope(),
        )
    }

    fn query_url(&self) -> String {
        format!("{}/api/advancedhunting/run", self.config.endpoint)
    }

    fn build_scoped_query(&self, table: &str, scope: &QueryScope) -> String {
        let (t_start_iso, t_end_iso) = epoch_ms_range_iso(scope.time_range);
        let cap = if scope.max_rows_per_table == 0 {
            self.config.default_page_size
        } else {
            scope.max_rows_per_table
        };
        // Note: Defender tables use `Timestamp`, not `TimeGenerated`.
        let mut query = format!(
            "{table} | where Timestamp between (datetime({ts}) .. datetime({te}))",
            table = table,
            ts = t_start_iso,
            te = t_end_iso,
        );
        if let Some(col) = route_entity_column(table, &scope.entity.entity_type) {
            query.push_str(&format!(
                " | where {} == \"{}\"",
                col,
                escape_kql(&scope.entity.value)
            ));
        }
        query.push_str(&format!(" | order by Timestamp asc | take {cap}"));
        query
    }

    fn build_poll_query(&self, table: &str, watermark: &Watermark) -> String {
        let wm_filter = if watermark.is_empty() {
            "ago(24h)".to_string()
        } else {
            format!("datetime({})", watermark.as_str())
        };
        format!(
            "{table} | where Timestamp > {wm} | order by Timestamp asc | take {cap}",
            table = table,
            wm = wm_filter,
            cap = self.config.default_page_size,
        )
    }

    fn build_request_body(&self, query: &str) -> Bytes {
        // Advanced Hunting uses capital "Query", not "query".
        let body = serde_json::json!({ "Query": query });
        Bytes::from(body.to_string().into_bytes())
    }
}

fn now_epoch_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn epoch_ms_range_iso(range: (i64, i64)) -> (String, String) {
    use chrono::{TimeZone, Utc};
    let start = Utc
        .timestamp_millis_opt(range.0)
        .single()
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());
    let end = Utc
        .timestamp_millis_opt(range.1)
        .single()
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());
    (start, end)
}

fn escape_kql(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[async_trait]
impl LogSource for DefenderXdrSource {
    fn source_id(&self) -> &str {
        &self.config.source_id
    }

    fn kind(&self) -> SourceKind {
        SourceKind::DefenderXdr
    }

    fn available_tables(&self) -> &[&'static str] {
        AVAILABLE_TABLES
    }

    async fn check_auth(&self) -> Result<(), SourceError> {
        self.tokens
            .get_token(&self.token_key())
            .await
            .map(|_| ())
            .map_err(|_| SourceError::Auth)
    }

    async fn query_scoped(
        &self,
        scope: QueryScope,
        cancel: CancellationToken,
    ) -> Result<ChunkStream, SourceError> {
        let tables: Vec<String> = if scope.tables.is_empty() {
            AVAILABLE_TABLES.iter().map(|t| t.to_string()).collect()
        } else {
            scope.tables.clone()
        };

        let mut queries: Vec<(String, String)> = Vec::with_capacity(tables.len());
        for t in &tables {
            queries.push((t.clone(), self.build_scoped_query(t, &scope)));
        }

        let http = self.http.clone();
        let tokens = self.tokens.clone();
        let config = self.config.clone();
        let source_id = self.config.source_id.clone();

        let initial_state = (queries.into_iter(), http, tokens, config, source_id, cancel);
        let stream = stream::unfold(
            initial_state,
            move |(mut q_iter, http, tokens, config, source_id, cancel)| async move {
                let (table, query) = q_iter.next()?;
                if cancel.is_cancelled() {
                    return Some((
                        Err(SourceError::Fatal("cancelled".to_string())),
                        (q_iter, http, tokens, config, source_id, cancel),
                    ));
                }

                let token_result = tokens
                    .get_token(&TokenKey::new(
                        &config.tenant_id,
                        SourceKind::DefenderXdr.resource_scope(),
                    ))
                    .await;
                let token = match token_result {
                    Ok(t) => t,
                    Err(_) => {
                        return Some((
                            Err(SourceError::Auth),
                            (q_iter, http, tokens, config, source_id, cancel),
                        ));
                    }
                };

                let body = Bytes::from(
                    serde_json::json!({ "Query": query })
                        .to_string()
                        .into_bytes(),
                );
                let url = format!("{}/api/advancedhunting/run", config.endpoint);
                let req = HttpRequest::post(url)
                    .with_bearer(&token)
                    .with_json_body(body)
                    .with_header("x-ms-client-request-id", &source_id)
                    .with_timeout(config.request_timeout);

                let resp = http.send(req, cancel.clone()).await;
                let chunk_result = match resp {
                    Ok(r) if r.is_success() => {
                        let fetched_at = now_epoch_ms();
                        Ok(RawChunk {
                            source_id: source_id.clone(),
                            table: table.clone(),
                            rows: r.body,
                            encoding: ChunkEncoding::Json,
                            fetched_at,
                            watermark_candidate: None,
                        })
                    }
                    Ok(r) => Err(map_http_status_to_source_error(r.status, r.retry_after())),
                    Err(e) => Err(map_http_error_to_source_error(e)),
                };
                Some((
                    chunk_result,
                    (q_iter, http, tokens, config, source_id, cancel),
                ))
            },
        );
        Ok(stream.boxed())
    }

    async fn poll_since(
        &self,
        table: &str,
        watermark: Watermark,
        cancel: CancellationToken,
    ) -> Result<PollStream, SourceError> {
        let query = self.build_poll_query(table, &watermark);
        let token = self
            .tokens
            .get_token(&self.token_key())
            .await
            .map_err(|_| SourceError::Auth)?;

        let body = self.build_request_body(&query);
        let req = HttpRequest::post(self.query_url())
            .with_bearer(&token)
            .with_json_body(body)
            .with_header("x-ms-client-request-id", &self.config.source_id)
            .with_timeout(self.config.request_timeout);

        let resp = self
            .http
            .send(req, cancel)
            .await
            .map_err(map_http_error_to_source_error)?;

        match resp.status_class() {
            StatusClass::Success => {
                let chunk = RawChunk {
                    source_id: self.config.source_id.clone(),
                    table: table.to_string(),
                    rows: resp.body,
                    encoding: ChunkEncoding::Json,
                    fetched_at: now_epoch_ms(),
                    watermark_candidate: Some(watermark.clone()),
                };
                Ok(stream::iter(vec![Ok((chunk, watermark))]).boxed())
            }
            _ => Err(map_http_status_to_source_error(
                resp.status,
                resp.retry_after(),
            )),
        }
    }
}

fn map_http_status_to_source_error(status: u16, retry_after: Option<Duration>) -> SourceError {
    match status {
        401 | 403 => SourceError::Auth,
        429 => SourceError::Throttled(retry_after.unwrap_or(Duration::from_secs(60))),
        408 | 504 => SourceError::Timeout,
        s if (400..500).contains(&s) => SourceError::Fatal(format!("XDR {s} response")),
        s if (500..600).contains(&s) => SourceError::Network(format!("XDR 5xx: {s}")),
        s => SourceError::Fatal(format!("unexpected XDR status: {s}")),
    }
}

fn map_http_error_to_source_error(e: crate::http_client::HttpError) -> SourceError {
    use crate::http_client::HttpError;
    match e {
        HttpError::Timeout => SourceError::Timeout,
        HttpError::Cancelled => SourceError::Fatal("cancelled".to_string()),
        HttpError::Transport(msg) => SourceError::Network(msg),
        HttpError::Invalid(msg) => SourceError::Fatal(msg),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EntityRef;
    use crate::http_client::{MockHttpClient, MockResponse};
    use crate::token_cache::{TokenError, TokenFetcher};
    use futures::StreamExt;

    struct StaticFetcher(String);
    #[async_trait]
    impl TokenFetcher for StaticFetcher {
        async fn fetch(&self, _key: &TokenKey) -> Result<(String, u64), TokenError> {
            Ok((self.0.clone(), 3600))
        }
    }

    fn make_source(http: Arc<MockHttpClient>) -> DefenderXdrSource {
        let tokens = Arc::new(AzureTokenCache::new(Arc::new(StaticFetcher(
            "xdr-mock-token".to_string(),
        ))));
        let config = DefenderXdrConfig::new("xdr:tenant-a", "tenant-a");
        DefenderXdrSource::new(config, http as Arc<dyn HttpClient>, tokens)
    }

    #[test]
    fn entity_column_routing_covers_known_combinations() {
        assert_eq!(
            route_entity_column("DeviceProcessEvents", "Host"),
            Some("DeviceName")
        );
        assert_eq!(
            route_entity_column("DeviceNetworkEvents", "IpAddress"),
            Some("RemoteIP")
        );
        assert_eq!(
            route_entity_column("DeviceFileEvents", "File"),
            Some("FileName")
        );
        assert_eq!(route_entity_column("DeviceProcessEvents", "Unknown"), None);
    }

    #[test]
    fn build_scoped_query_uses_timestamp_not_time_generated() {
        let http: Arc<dyn HttpClient> = Arc::new(MockHttpClient::new());
        let tokens = Arc::new(AzureTokenCache::new(Arc::new(StaticFetcher(
            "t".to_string(),
        ))));
        let source = DefenderXdrSource::new(DefenderXdrConfig::new("xdr:t-1", "t-1"), http, tokens);
        let scope = QueryScope {
            entity: EntityRef {
                entity_type: "IpAddress".to_string(),
                value: "8.8.8.8".to_string(),
            },
            time_range: (0, 86_400_000),
            tables: vec!["DeviceNetworkEvents".to_string()],
            max_rows_per_table: 200,
        };
        let q = source.build_scoped_query("DeviceNetworkEvents", &scope);
        assert!(q.contains("Timestamp between"), "got: {q}");
        assert!(!q.contains("TimeGenerated"), "got: {q}");
        assert!(q.contains("RemoteIP == \"8.8.8.8\""), "got: {q}");
        assert!(q.contains("take 200"), "got: {q}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn query_scoped_uses_advanced_hunting_endpoint() {
        let http = Arc::new(MockHttpClient::new());
        http.push(MockResponse::json(r#"{"Results":[]}"#)).await;

        let source = make_source(http.clone());
        let scope = QueryScope {
            entity: EntityRef {
                entity_type: "Host".to_string(),
                value: "WORKSTATION01".to_string(),
            },
            time_range: (0, 86_400_000),
            tables: vec!["DeviceProcessEvents".to_string()],
            max_rows_per_table: 100,
        };
        let mut stream = source
            .query_scoped(scope, CancellationToken::new())
            .await
            .unwrap();
        let chunk = stream.next().await.unwrap().unwrap();
        assert_eq!(chunk.table, "DeviceProcessEvents");

        let recorded = http.recorded().await;
        assert_eq!(recorded.len(), 1);
        assert!(recorded[0].url.ends_with("/api/advancedhunting/run"));

        // Body must use capital "Query", not lowercase.
        let body_str = std::str::from_utf8(recorded[0].body.as_ref().unwrap()).unwrap();
        assert!(body_str.contains("\"Query\""), "got: {body_str}");
        assert!(!body_str.contains("\"query\""), "got: {body_str}");
        assert!(
            body_str.contains("DeviceName == \\\"WORKSTATION01\\\""),
            "got: {body_str}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn query_scoped_fires_one_request_per_table() {
        let http = Arc::new(MockHttpClient::new());
        // Three tables in the default set → three responses.
        for _ in 0..3 {
            http.push(MockResponse::json(r#"{"Results":[]}"#)).await;
        }

        let source = make_source(http.clone());
        let scope = QueryScope {
            entity: EntityRef {
                entity_type: "IpAddress".to_string(),
                value: "10.0.0.1".to_string(),
            },
            time_range: (0, 86_400_000),
            tables: Vec::new(), // empty = use default set (3 tables)
            max_rows_per_table: 100,
        };
        let mut stream = source
            .query_scoped(scope, CancellationToken::new())
            .await
            .unwrap();
        let mut count = 0;
        while let Some(item) = stream.next().await {
            let _ = item.unwrap();
            count += 1;
        }
        assert_eq!(count, 3);
        assert_eq!(http.call_count().await, 3);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn poll_since_builds_timestamp_watermark_filter() {
        let http = Arc::new(MockHttpClient::new());
        http.push(MockResponse::json(r#"{"Results":[]}"#)).await;

        let source = make_source(http.clone());
        let wm = Watermark::new("2026-04-09T10:00:00Z");
        let _ = source
            .poll_since("DeviceProcessEvents", wm.clone(), CancellationToken::new())
            .await
            .unwrap();

        let body = http.recorded().await[0].body.clone().unwrap();
        let body_str = std::str::from_utf8(&body).unwrap();
        assert!(
            body_str.contains("Timestamp > datetime(2026-04-09T10:00:00Z)"),
            "got: {body_str}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn poll_since_with_empty_watermark_uses_24h_lookback() {
        let http = Arc::new(MockHttpClient::new());
        http.push(MockResponse::json(r#"{"Results":[]}"#)).await;

        let source = make_source(http.clone());
        let _ = source
            .poll_since(
                "DeviceProcessEvents",
                Watermark::default(),
                CancellationToken::new(),
            )
            .await
            .unwrap();

        let body = http.recorded().await[0].body.clone().unwrap();
        let body_str = std::str::from_utf8(&body).unwrap();
        assert!(body_str.contains("Timestamp > ago(24h)"), "got: {body_str}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn query_scoped_maps_429_to_throttled() {
        let http = Arc::new(MockHttpClient::new());
        http.push(MockResponse::throttled(15)).await;

        let source = make_source(http);
        let scope = QueryScope {
            entity: EntityRef {
                entity_type: "Host".to_string(),
                value: "WS-1".to_string(),
            },
            time_range: (0, 86_400_000),
            tables: vec!["DeviceProcessEvents".to_string()],
            max_rows_per_table: 100,
        };
        let mut stream = source
            .query_scoped(scope, CancellationToken::new())
            .await
            .unwrap();
        match stream.next().await.unwrap() {
            Err(SourceError::Throttled(d)) => assert_eq!(d, Duration::from_secs(15)),
            other => panic!("expected Throttled(15s), got {other:?}"),
        }
    }

    #[test]
    fn source_reports_correct_kind_and_scope() {
        let http: Arc<dyn HttpClient> = Arc::new(MockHttpClient::new());
        let tokens = Arc::new(AzureTokenCache::new(Arc::new(StaticFetcher(
            "t".to_string(),
        ))));
        let source = DefenderXdrSource::new(DefenderXdrConfig::new("xdr:t-1", "t-1"), http, tokens);
        assert_eq!(source.kind(), SourceKind::DefenderXdr);
        assert_eq!(
            source.kind().resource_scope(),
            "https://api.security.microsoft.com/.default"
        );
        assert_eq!(source.available_tables().len(), 3);
    }
}
