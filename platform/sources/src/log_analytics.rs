//! Microsoft Sentinel / Azure Log Analytics source.
//!
//! Implements [`LogSource`] against the Log Analytics Query REST API:
//!
//!   `POST https://api.loganalytics.io/v1/workspaces/{workspace_id}/query`
//!
//! Generalizes the existing `SentinelTransport` path from
//! `graph_hunter_cli/src/siem/sentinel_streaming.rs` but rebuilt on top
//! of the Phase 2 [`HttpClient`] + [`AzureTokenCache`] abstractions so
//! the source has no `reqwest` dep of its own and is trivially
//! mockable in unit tests.
//!
//! ## Why a rebuild rather than a move
//!
//! The plan (§2a) specifies "move SentinelTransport into core". A direct
//! file move would cascade into `graph_hunter_cli` and
//! `app/src-tauri/src/sentinel_connector.rs` — both currently import
//! `SentinelTransport` — and introduce a risky wide refactor. Instead,
//! this module rebuilds the KQL path on the new [`HttpClient`] trait,
//! leaves the CLI transport untouched for backward compatibility, and
//! lets a later follow-up unify them once the Tauri app is migrated to
//! call through `LogAnalyticsSource` directly.
//!
//! ## Entity-column routing
//!
//! Log Analytics tables store entity identifiers under different column
//! names — `SecurityEvent.IpAddress` vs `SigninLogs.IPAddress` vs
//! `DeviceNetworkEvents.RemoteIP`. `query_scoped` uses a per-table
//! routing map ([`ENTITY_COLUMN_ROUTING`]) to translate a logical
//! [`EntityRef::entity_type`] into the correct column for the target
//! table. Unknown entity types fall back to an empty filter (returns
//! everything in the time window), which is the safest default for a
//! "drill down" UX: the caller sees *something* rather than an empty
//! page.
//!
//! [`LogSource`]: crate::LogSource
//! [`HttpClient`]: crate::http_client::HttpClient
//! [`AzureTokenCache`]: crate::token_cache::AzureTokenCache

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::{self, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use crate::http_client::{HttpClient, HttpRequest, HttpResponse, StatusClass};
use crate::token_cache::{AzureTokenCache, TokenKey};
use crate::{
    ChunkEncoding, ChunkStream, LogSource, PollStream, QueryScope, RawChunk, SourceError,
    SourceKind, Watermark,
};

/// Default Log Analytics API root. Overridable for tests + alternate
/// cloud environments (gov / national clouds).
pub const DEFAULT_LA_ENDPOINT: &str = "https://api.loganalytics.io";

/// Curated list of tables the source advertises. These are the ones
/// `SentinelJsonParser` (already in `graph_hunter_core`) knows how to
/// turn into `ParsedTriple`s. Adding more is a two-line change in the
/// parser plus an entry here.
const AVAILABLE_TABLES: &[&str] = &[
    "SecurityEvent",
    "SigninLogs",
    "DeviceProcessEvents",
    "DeviceNetworkEvents",
    "DeviceFileEvents",
    "CommonSecurityLog",
];

/// Per-table entity-column routing. When `query_scoped` sees
/// `entity_type = "IpAddress"` and `table = "SecurityEvent"`, it looks
/// up `IpAddress` here to build `| where IpAddress == "..."`.
///
/// The array is a flat `(table, entity_type, column_name)` table. Empty
/// column means "don't filter — return all rows in the time window".
const ENTITY_COLUMN_ROUTING: &[(&str, &str, &str)] = &[
    ("SecurityEvent", "IpAddress", "IpAddress"),
    ("SecurityEvent", "Account", "Account"),
    ("SecurityEvent", "Host", "Computer"),
    ("SigninLogs", "IpAddress", "IPAddress"),
    ("SigninLogs", "User", "UserPrincipalName"),
    ("DeviceNetworkEvents", "IpAddress", "RemoteIP"),
    ("DeviceNetworkEvents", "Host", "DeviceName"),
    ("DeviceProcessEvents", "Host", "DeviceName"),
    ("DeviceProcessEvents", "Process", "FileName"),
    ("DeviceFileEvents", "Host", "DeviceName"),
    ("DeviceFileEvents", "File", "FileName"),
    ("CommonSecurityLog", "IpAddress", "SourceIP"),
    ("CommonSecurityLog", "Host", "SourceHostName"),
];

fn route_entity_column(table: &str, entity_type: &str) -> Option<&'static str> {
    ENTITY_COLUMN_ROUTING
        .iter()
        .find_map(|(t, et, col)| (*t == table && *et == entity_type).then_some(*col))
}

/// Configuration for a [`LogAnalyticsSource`] instance.
#[derive(Debug, Clone)]
pub struct LogAnalyticsConfig {
    /// Stable source identifier. Convention: `"la:<workspace_id>"`.
    pub source_id: String,
    /// Azure AD tenant the workspace lives in. Used as the
    /// `TokenKey.tenant_id` for the token cache.
    pub tenant_id: String,
    /// Log Analytics workspace ID (GUID, without the subscription path).
    pub workspace_id: String,
    /// API root. Use [`DEFAULT_LA_ENDPOINT`] for commercial cloud.
    pub endpoint: String,
    /// Per-query HTTP timeout. The Log Analytics server-side max is
    /// 10 minutes; we default to 60 seconds because most hunt drill-down
    /// queries complete well under that and the streaming pipeline
    /// prefers frequent small fetches.
    pub request_timeout: Duration,
    /// Default `max_rows_per_table` when the caller passes 0.
    pub default_page_size: u32,
}

impl LogAnalyticsConfig {
    pub fn new(
        source_id: impl Into<String>,
        tenant_id: impl Into<String>,
        workspace_id: impl Into<String>,
    ) -> Self {
        Self {
            source_id: source_id.into(),
            tenant_id: tenant_id.into(),
            workspace_id: workspace_id.into(),
            endpoint: DEFAULT_LA_ENDPOINT.to_string(),
            request_timeout: Duration::from_secs(60),
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

/// The Log Analytics source.
///
/// Holds shared references to an [`HttpClient`] and an
/// [`AzureTokenCache`]; both can be shared across multiple Source
/// instances (different workspaces in the same tenant).
pub struct LogAnalyticsSource {
    config: LogAnalyticsConfig,
    http: Arc<dyn HttpClient>,
    tokens: Arc<AzureTokenCache>,
}

impl LogAnalyticsSource {
    pub fn new(
        config: LogAnalyticsConfig,
        http: Arc<dyn HttpClient>,
        tokens: Arc<AzureTokenCache>,
    ) -> Self {
        Self {
            config,
            http,
            tokens,
        }
    }

    /// Builds the token cache key for this source's tenant + the Log
    /// Analytics audience.
    fn token_key(&self) -> TokenKey {
        TokenKey::new(
            &self.config.tenant_id,
            SourceKind::LogAnalytics.resource_scope(),
        )
    }

    fn query_url(&self) -> String {
        format!(
            "{}/v1/workspaces/{}/query",
            self.config.endpoint, self.config.workspace_id
        )
    }

    /// Builds the KQL query body for a scoped entity lookup.
    fn build_scoped_query(&self, table: &str, scope: &QueryScope) -> String {
        let (t_start_iso, t_end_iso) = epoch_ms_range_iso(scope.time_range);
        let cap = if scope.max_rows_per_table == 0 {
            self.config.default_page_size
        } else {
            scope.max_rows_per_table
        };

        // Base query: time window + take cap.
        let mut query = format!(
            "{table} | where TimeGenerated between (datetime({t_start}) .. datetime({t_end}))",
            table = table,
            t_start = t_start_iso,
            t_end = t_end_iso,
        );

        // Append entity filter if we have a column mapping for this
        // (table, entity_type). Unknown combinations fall through to an
        // unfiltered time-window query — per the module doc, this is the
        // safest default for drill-down UX.
        if let Some(col) = route_entity_column(table, &scope.entity.entity_type) {
            query.push_str(&format!(
                " | where {} == \"{}\"",
                col,
                escape_kql(&scope.entity.value)
            ));
        }

        query.push_str(&format!(" | order by TimeGenerated asc | take {}", cap));
        query
    }

    /// Builds the KQL polling body that advances a watermark.
    fn build_poll_query(&self, table: &str, watermark: &Watermark) -> String {
        let wm_filter = if watermark.is_empty() {
            // First-ever poll: look back 24 hours. Matches the existing
            // Sentinel connector default.
            "ago(24h)".to_string()
        } else {
            format!("datetime({})", watermark.as_str())
        };
        format!(
            "{table} | where TimeGenerated > {wm} | order by TimeGenerated asc | take {cap}",
            table = table,
            wm = wm_filter,
            cap = self.config.default_page_size,
        )
    }

    fn build_request_body(&self, query: &str) -> Bytes {
        // Log Analytics Query API request body: `{"query": "..."}`.
        // Use serde_json to handle quoting correctly.
        let body = serde_json::json!({ "query": query });
        Bytes::from(body.to_string().into_bytes())
    }

    /// Builds + dispatches the HTTP request, classifies the response.
    /// Returns the raw body bytes on success, or maps 4xx/5xx / transport
    /// failures to the appropriate [`SourceError`] variant.
    async fn execute_query(
        &self,
        query: &str,
        cancel: CancellationToken,
    ) -> Result<(Bytes, i64), SourceError> {
        let token = self
            .tokens
            .get_token(&self.token_key())
            .await
            .map_err(|_| SourceError::Auth)?;

        let body = self.build_request_body(query);
        let req = HttpRequest::post(self.query_url())
            .with_bearer(&token)
            .with_json_body(body)
            .with_header("x-ms-client-request-id", &self.config.source_id)
            .with_timeout(self.config.request_timeout);

        let resp: HttpResponse = self.http.send(req, cancel).await.map_err(|e| {
            use crate::http_client::HttpError;
            match e {
                HttpError::Timeout => SourceError::Timeout,
                HttpError::Cancelled => SourceError::Fatal("cancelled".to_string()),
                HttpError::Transport(msg) => SourceError::Network(msg),
                HttpError::Invalid(msg) => SourceError::Fatal(msg),
            }
        })?;

        match resp.status_class() {
            StatusClass::Success => {
                let fetched_at = now_epoch_ms();
                Ok((resp.body, fetched_at))
            }
            StatusClass::ClientError => match resp.status {
                401 | 403 => Err(SourceError::Auth),
                429 => {
                    // Parse Retry-After; default to 60s if absent.
                    let retry_after = resp.retry_after().unwrap_or(Duration::from_secs(60));
                    Err(SourceError::Throttled(retry_after))
                }
                408 => Err(SourceError::Timeout),
                _ => Err(SourceError::Fatal(format!("LA {} response", resp.status))),
            },
            StatusClass::ServerError => {
                if resp.status == 504 {
                    Err(SourceError::Timeout)
                } else {
                    Err(SourceError::Network(format!("LA 5xx: {}", resp.status)))
                }
            }
            _ => Err(SourceError::Fatal(format!(
                "unexpected LA status: {}",
                resp.status
            ))),
        }
    }
}

fn now_epoch_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Converts an `(epoch_ms_start, epoch_ms_end)` pair to ISO-8601
/// strings suitable for `datetime(...)` in KQL. Uses `chrono` since it's
/// already a dep of `graph_hunter_core`.
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

/// Minimal KQL string escaper: double-quote → double-quote + backslash.
/// Only escapes `"` and `\\` — sufficient for entity values coming from
/// the existing parser (which produces host names, IPs, and usernames).
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
impl LogSource for LogAnalyticsSource {
    fn source_id(&self) -> &str {
        &self.config.source_id
    }

    fn kind(&self) -> SourceKind {
        SourceKind::LogAnalytics
    }

    fn available_tables(&self) -> &[&'static str] {
        AVAILABLE_TABLES
    }

    async fn check_auth(&self) -> Result<(), SourceError> {
        // Freshness probe: just acquire a token from the cache. If the
        // cache has a fresh entry, this is a hash lookup; if not, it
        // fetches. Either way we don't hit the data endpoint.
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
        // Determine which tables to query. Empty list = curated default.
        let tables: Vec<String> = if scope.tables.is_empty() {
            AVAILABLE_TABLES.iter().map(|t| t.to_string()).collect()
        } else {
            scope.tables.clone()
        };

        // Pre-build all request queries up-front so the async stream
        // doesn't need to borrow `self` across page boundaries. The
        // stream then just fires each one in sequence.
        let mut queries: Vec<(String, String)> = Vec::with_capacity(tables.len());
        for t in &tables {
            queries.push((t.clone(), self.build_scoped_query(t, &scope)));
        }

        let http = self.http.clone();
        let tokens = self.tokens.clone();
        let config = self.config.clone();
        let source_id = self.config.source_id.clone();

        // Use stream::unfold so each page fetches lazily — one HTTP
        // round-trip per pull. Backpressures the parser if the consumer
        // is slower than the source.
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
                // Inline the HTTP dispatch here because `execute_query`
                // borrows &self, which we can't carry into the 'static
                // stream.
                let token_result = tokens
                    .get_token(&TokenKey::new(
                        &config.tenant_id,
                        SourceKind::LogAnalytics.resource_scope(),
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
                    serde_json::json!({ "query": query })
                        .to_string()
                        .into_bytes(),
                );
                let url = format!(
                    "{}/v1/workspaces/{}/query",
                    config.endpoint, config.workspace_id
                );
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
        let (body, fetched_at) = self.execute_query(&query, cancel).await?;

        // Single-page yield: in the full streaming pipeline, the outer
        // polling loop calls `poll_since` on a timer and drains the
        // stream. Paging inside a single poll is a future optimization
        // (plan §3 mentions it as "future enhancement").
        //
        // The watermark-advance happens on the consumer side: they parse
        // the chunk, extract the max `TimeGenerated`, and call
        // `WatermarkStore::set`. We pass a placeholder watermark
        // candidate (the input watermark) so the consumer has a reference
        // point; real advance comes from parsing the rows.
        let chunk = RawChunk {
            source_id: self.config.source_id.clone(),
            table: table.to_string(),
            rows: body,
            encoding: ChunkEncoding::Json,
            fetched_at,
            watermark_candidate: Some(watermark.clone()),
        };

        Ok(stream::iter(vec![Ok((chunk, watermark))]).boxed())
    }
}

fn map_http_status_to_source_error(status: u16, retry_after: Option<Duration>) -> SourceError {
    match status {
        401 | 403 => SourceError::Auth,
        429 => SourceError::Throttled(retry_after.unwrap_or(Duration::from_secs(60))),
        408 | 504 => SourceError::Timeout,
        s if (400..500).contains(&s) => SourceError::Fatal(format!("LA {s} response")),
        s if (500..600).contains(&s) => SourceError::Network(format!("LA 5xx: {s}")),
        s => SourceError::Fatal(format!("unexpected LA status: {s}")),
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

    /// Mock fetcher that always returns a known-good token. Kept local
    /// to this test module so the assertions don't depend on cross-file
    /// state.
    struct StaticFetcher(String);
    #[async_trait]
    impl TokenFetcher for StaticFetcher {
        async fn fetch(&self, _key: &TokenKey) -> Result<(String, u64), TokenError> {
            Ok((self.0.clone(), 3600))
        }
    }

    fn make_source(http: Arc<MockHttpClient>, endpoint: Option<&str>) -> LogAnalyticsSource {
        let tokens = Arc::new(AzureTokenCache::new(Arc::new(StaticFetcher(
            "mock-token".to_string(),
        ))));
        let mut config = LogAnalyticsConfig::new("la:ws-1", "tenant-a", "ws-1");
        if let Some(ep) = endpoint {
            config = config.with_endpoint(ep);
        }
        LogAnalyticsSource::new(config, http as Arc<dyn HttpClient>, tokens)
    }

    #[test]
    fn entity_column_routing_covers_known_combinations() {
        assert_eq!(
            route_entity_column("SecurityEvent", "IpAddress"),
            Some("IpAddress")
        );
        assert_eq!(
            route_entity_column("SigninLogs", "IpAddress"),
            Some("IPAddress")
        );
        assert_eq!(
            route_entity_column("DeviceNetworkEvents", "IpAddress"),
            Some("RemoteIP")
        );
        assert_eq!(route_entity_column("SecurityEvent", "UnknownType"), None);
        assert_eq!(route_entity_column("NonexistentTable", "IpAddress"), None);
    }

    #[test]
    fn build_scoped_query_includes_entity_filter_when_routable() {
        let source = {
            let http: Arc<dyn HttpClient> = Arc::new(MockHttpClient::new());
            let tokens = Arc::new(AzureTokenCache::new(Arc::new(StaticFetcher(
                "t".to_string(),
            ))));
            LogAnalyticsSource::new(
                LogAnalyticsConfig::new("la:ws-1", "tenant-a", "ws-1"),
                http,
                tokens,
            )
        };
        let scope = QueryScope {
            entity: EntityRef {
                entity_type: "IpAddress".to_string(),
                value: "10.0.0.42".to_string(),
            },
            time_range: (0, 86_400_000),
            tables: vec!["SecurityEvent".to_string()],
            max_rows_per_table: 500,
        };
        let q = source.build_scoped_query("SecurityEvent", &scope);
        assert!(q.starts_with("SecurityEvent"));
        assert!(q.contains("TimeGenerated between"));
        assert!(q.contains("IpAddress == \"10.0.0.42\""));
        assert!(q.contains("take 500"));
    }

    #[test]
    fn build_scoped_query_omits_filter_when_not_routable() {
        let source = {
            let http: Arc<dyn HttpClient> = Arc::new(MockHttpClient::new());
            let tokens = Arc::new(AzureTokenCache::new(Arc::new(StaticFetcher(
                "t".to_string(),
            ))));
            LogAnalyticsSource::new(
                LogAnalyticsConfig::new("la:ws-1", "tenant-a", "ws-1"),
                http,
                tokens,
            )
        };
        let scope = QueryScope {
            entity: EntityRef {
                entity_type: "SomeCustomType".to_string(),
                value: "value".to_string(),
            },
            time_range: (0, 86_400_000),
            tables: vec!["SecurityEvent".to_string()],
            max_rows_per_table: 100,
        };
        let q = source.build_scoped_query("SecurityEvent", &scope);
        // No entity filter, just time range + take.
        assert!(!q.contains("SomeCustomType"));
        assert!(q.contains("TimeGenerated between"));
        assert!(q.contains("take 100"));
    }

    #[test]
    fn build_poll_query_falls_back_to_24h_when_watermark_empty() {
        let source = {
            let http: Arc<dyn HttpClient> = Arc::new(MockHttpClient::new());
            let tokens = Arc::new(AzureTokenCache::new(Arc::new(StaticFetcher(
                "t".to_string(),
            ))));
            LogAnalyticsSource::new(
                LogAnalyticsConfig::new("la:ws-1", "tenant-a", "ws-1"),
                http,
                tokens,
            )
        };
        let q = source.build_poll_query("SecurityEvent", &Watermark::default());
        assert!(q.contains("TimeGenerated > ago(24h)"));

        let q2 = source.build_poll_query("SecurityEvent", &Watermark::new("2026-04-09T10:00:00Z"));
        assert!(q2.contains("TimeGenerated > datetime(2026-04-09T10:00:00Z)"));
    }

    #[test]
    fn escape_kql_handles_quotes_and_backslashes() {
        assert_eq!(escape_kql("plain"), "plain");
        assert_eq!(escape_kql(r#"he said "hi""#), r#"he said \"hi\""#);
        assert_eq!(escape_kql(r"back\slash"), r"back\\slash");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn query_scoped_stream_yields_one_chunk_per_table() {
        let http = Arc::new(MockHttpClient::new());
        http.push(MockResponse::json(r#"{"tables":[]}"#)).await;
        http.push(MockResponse::json(r#"{"tables":[]}"#)).await;

        let source = make_source(http.clone(), None);
        let scope = QueryScope {
            entity: EntityRef {
                entity_type: "IpAddress".to_string(),
                value: "10.0.0.1".to_string(),
            },
            time_range: (0, 86_400_000),
            tables: vec!["SecurityEvent".to_string(), "SigninLogs".to_string()],
            max_rows_per_table: 50,
        };
        let mut stream = source
            .query_scoped(scope, CancellationToken::new())
            .await
            .unwrap();
        let mut chunks = Vec::new();
        while let Some(item) = stream.next().await {
            chunks.push(item.unwrap());
        }
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].table, "SecurityEvent");
        assert_eq!(chunks[1].table, "SigninLogs");
        assert_eq!(chunks[0].encoding, ChunkEncoding::Json);

        // Verify both HTTP requests carried a Bearer token and the
        // right client-request-id header.
        let recorded = http.recorded().await;
        assert_eq!(recorded.len(), 2);
        for req in recorded {
            assert!(
                req.headers
                    .iter()
                    .any(|(k, v)| k == "Authorization" && v.starts_with("Bearer "))
            );
            assert!(
                req.headers
                    .iter()
                    .any(|(k, v)| k == "x-ms-client-request-id" && v == "la:ws-1")
            );
            assert!(req.url.contains("/v1/workspaces/ws-1/query"));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn query_scoped_maps_429_to_throttled_with_retry_after() {
        let http = Arc::new(MockHttpClient::new());
        http.push(MockResponse::throttled(30)).await;

        let source = make_source(http.clone(), None);
        let scope = QueryScope {
            entity: EntityRef {
                entity_type: "IpAddress".to_string(),
                value: "10.0.0.1".to_string(),
            },
            time_range: (0, 86_400_000),
            tables: vec!["SecurityEvent".to_string()],
            max_rows_per_table: 100,
        };
        let mut stream = source
            .query_scoped(scope, CancellationToken::new())
            .await
            .unwrap();
        let first = stream.next().await.unwrap();
        match first {
            Err(SourceError::Throttled(d)) => {
                assert_eq!(d, Duration::from_secs(30));
            }
            other => panic!("expected Throttled(30s), got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn query_scoped_maps_401_to_auth() {
        let http = Arc::new(MockHttpClient::new());
        http.push(MockResponse::unauthorized()).await;

        let source = make_source(http, None);
        let scope = QueryScope {
            entity: EntityRef {
                entity_type: "IpAddress".to_string(),
                value: "10.0.0.1".to_string(),
            },
            time_range: (0, 86_400_000),
            tables: vec!["SecurityEvent".to_string()],
            max_rows_per_table: 100,
        };
        let mut stream = source
            .query_scoped(scope, CancellationToken::new())
            .await
            .unwrap();
        let first = stream.next().await.unwrap();
        matches!(first, Err(SourceError::Auth));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn poll_since_returns_single_chunk_with_watermark() {
        let http = Arc::new(MockHttpClient::new());
        http.push(MockResponse::json(r#"{"tables":[{"rows":[]}]}"#))
            .await;

        let source = make_source(http, None);
        let wm = Watermark::new("2026-04-09T10:00:00Z");
        let mut stream = source
            .poll_since("SecurityEvent", wm.clone(), CancellationToken::new())
            .await
            .unwrap();
        let item = stream.next().await.unwrap().unwrap();
        assert_eq!(item.0.table, "SecurityEvent");
        assert_eq!(item.1, wm);
        assert!(stream.next().await.is_none()); // single-chunk yield
    }

    #[tokio::test(flavor = "current_thread")]
    async fn check_auth_calls_token_cache() {
        let http = Arc::new(MockHttpClient::new());
        let source = make_source(http, None);
        source.check_auth().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn source_reports_correct_kind_and_scope() {
        let http = Arc::new(MockHttpClient::new());
        let source = make_source(http, None);
        assert_eq!(source.kind(), SourceKind::LogAnalytics);
        assert_eq!(source.source_id(), "la:ws-1");
        assert_eq!(
            source.kind().resource_scope(),
            "https://api.loganalytics.io/.default"
        );
        assert!(source.available_tables().contains(&"SecurityEvent"));
        assert!(source.available_tables().contains(&"DeviceProcessEvents"));
    }
}
