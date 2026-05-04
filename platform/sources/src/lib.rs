//! Log source abstractions for Azure streaming ingest.
//!
//! This module defines the [`LogSource`] trait that every Azure connector
//! — Log Analytics, Sentinel Data Lake v2, Defender XDR Advanced Hunting,
//! and future Blob export — implements. The trait is intentionally
//! object-safe (via `#[async_trait]`) so that callers can hold
//! `Vec<Arc<dyn LogSource>>` and dispatch across connected sources without
//! static generics.
//!
//! ## Why `async_trait` and not RPITIT
//!
//! The existing `SentinelTransport` trait in `graph_hunter_cli` uses
//! return-position-impl-trait-in-trait (`-> impl Future + Send`), which is
//! NOT object-safe as of stable Rust today. You cannot coerce it to
//! `dyn SentinelTransport`. Spike 1 (`spikes/logsource_objectsafety/`)
//! validated that `#[async_trait::async_trait]` + `BoxStream<'static, ...>`
//! compose cleanly and allow both static-Vec and `stream::unfold`-based
//! implementations to coexist in a single `Vec<Arc<dyn LogSource>>`. The
//! per-call `Box::pin` allocation cost is fine because LogSource methods
//! run at polling rate (seconds to minutes between calls), not in a hot
//! inner loop.
//!
//! ## Trait shape highlights
//!
//! - `query_scoped` — one-shot entity-scoped query used by the on-demand
//!   enrichment path (`cmd_enrich_entity` in Phase 7). Returns a boxed
//!   stream so implementations can yield pages as they fetch them; a
//!   single query may page internally and the stream lets the caller
//!   backpressure the source naturally.
//! - `poll_since` — long-lived polling query that advances a [`Watermark`].
//!   This is the shape the existing `sentinel_connector.rs` polling loop
//!   will migrate to in Phase 3.
//! - Both return `BoxStream<'static, ...>` so the stream can outlive the
//!   borrow on `&self` and be consumed by a separate task (the parser /
//!   writer chain in Phase 4's ingest pipeline).
//! - [`RawChunk`] carries raw bytes + encoding rather than parsed triples,
//!   so the parser (source-specific) decodes after the stream boundary.
//!   This preserves the zero-copy-until-parse property that matters at
//!   tera-scale.
//!
//! ## Error taxonomy
//!
//! [`SourceError`] is the shared taxonomy the connector loops use to
//! decide retry, pause, bisect, or fail. See plan §9 for the full recovery
//! matrix. Implementations should map HTTP status codes + body parsing
//! into this enum so the upper layers (failure table, quota limiter,
//! observability) can react uniformly across sources.

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::BoxStream;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Which Azure surface a `LogSource` queries. Drives quota accounting,
/// retry policy, and parser dispatch in the upper layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SourceKind {
    /// Log Analytics Query API (REST) — the existing `SentinelTransport`
    /// path, generalized. Auth scope: `https://api.loganalytics.io/.default`.
    LogAnalytics,
    /// Sentinel Data Lake v2 KQL endpoint. Auth scope:
    /// `https://securityplatform.microsoft.com/.default`.
    DataLakeV2,
    /// Defender XDR Advanced Hunting API
    /// (`api.security.microsoft.com/api/advancedhunting/run`). Auth scope:
    /// `https://api.security.microsoft.com/.default`.
    DefenderXdr,
    /// Log Analytics Continuous Export to Blob Storage. Not a query API;
    /// the "query" is a blob list + read loop. Auth scope: the storage
    /// account's scope.
    BlobExport,
}

impl SourceKind {
    /// Short stable identifier used in watermark keys, metrics labels,
    /// Tauri event payloads, etc.
    pub fn as_str(self) -> &'static str {
        match self {
            SourceKind::LogAnalytics => "la",
            SourceKind::DataLakeV2 => "datalake_v2",
            SourceKind::DefenderXdr => "xdr",
            SourceKind::BlobExport => "blob_export",
        }
    }

    /// Azure AD resource scope ("audience") this source authenticates
    /// against. Each scope needs a separate access token in
    /// [`crate::token_cache::AzureTokenCache`].
    pub fn resource_scope(self) -> &'static str {
        match self {
            SourceKind::LogAnalytics => "https://api.loganalytics.io/.default",
            SourceKind::DataLakeV2 => "https://securityplatform.microsoft.com/.default",
            SourceKind::DefenderXdr => "https://api.security.microsoft.com/.default",
            SourceKind::BlobExport => "https://storage.azure.com/.default",
        }
    }
}

/// Entity scope for [`LogSource::query_scoped`]. The connector translates
/// this into a source-specific predicate (KQL `where` clause, blob path
/// filter, etc.) before dispatching the query.
#[derive(Debug, Clone)]
pub struct EntityRef {
    /// Entity type name that the upper layer uses — e.g., `"IpAddress"`,
    /// `"User"`, `"Host"`, `"Process"`, `"File"`. Must match the column/
    /// field name the source uses to index on; connectors may normalize
    /// via a per-source routing table (`entity_type_to_column`).
    pub entity_type: String,
    /// Literal entity value, e.g., `"192.168.1.42"` or `"alice@contoso.com"`.
    /// Connectors are responsible for quoting / escaping appropriately for
    /// the target query language.
    pub value: String,
}

/// Scope parameters for a one-shot entity-driven query. Used by the
/// on-demand enrichment path.
#[derive(Debug, Clone)]
pub struct QueryScope {
    /// The entity to scope the query to.
    pub entity: EntityRef,
    /// `(start_ms, end_ms)` epoch-millisecond range, inclusive. Matches
    /// the existing graph timestamp representation.
    pub time_range: (i64, i64),
    /// Which tables to query. Empty vector means "use the source's default
    /// table set" (see [`LogSource::available_tables`]).
    pub tables: Vec<String>,
    /// Maximum rows per table to fetch. Upper layers cap this via
    /// `ENRICHMENT_MAX_RELATIONS` (plan §5). Source implementations must
    /// enforce the cap on the server side when possible (KQL `take`) and
    /// re-enforce on the client to be defensive.
    pub max_rows_per_table: u32,
}

/// Opaque per-source watermark. Each source encodes its resume state as
/// a UTF-8 string. The format is source-specific:
///
/// - Log Analytics / Data Lake v2: ISO-8601 timestamp (the max
///   `TimeGenerated` seen in the last page).
/// - Defender XDR: ISO-8601 timestamp (same shape).
/// - Blob export: the CBOR or JSON encoding of
///   `{ blob_name, byte_offset }`.
///
/// The [`crate::watermark_store::WatermarkStore`] persists these strings
/// transparently — it does not need to understand the encoding.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Watermark(pub String);

impl Watermark {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// How the bytes in a [`RawChunk`] are encoded. The parser layer
/// dispatches on this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkEncoding {
    /// A single JSON value (typically an object with a `tables` or `rows`
    /// key — what Log Analytics returns).
    Json,
    /// Newline-delimited JSON. One row per line. This is the shape the
    /// blob export writes.
    Jsonl,
    /// Columnar Parquet bytes. Reserved for the future Data Lake v2
    /// Parquet path; no parser implements this yet.
    Parquet,
}

/// A raw response fragment from a log source. Held as [`Bytes`] so HTTP
/// transports can hand ownership of the response buffer to the parser
/// task without cloning (plan §3 backpressure pipeline).
#[derive(Debug, Clone)]
pub struct RawChunk {
    /// Stable identifier of the source that produced this chunk.
    pub source_id: String,
    /// Source-specific table or schema name this chunk came from (e.g.,
    /// `"SecurityEvent"`, `"DeviceProcessEvents"`).
    pub table: String,
    /// The raw response bytes.
    pub rows: Bytes,
    /// How `rows` is encoded. The parser dispatches on this.
    pub encoding: ChunkEncoding,
    /// Epoch-millisecond timestamp at which this chunk was fetched.
    /// Used for observability and cache keys.
    pub fetched_at: i64,
    /// Optional candidate watermark advance. If present, the connector
    /// should bump its watermark to this value *after* the chunk has been
    /// successfully parsed and inserted. Producing this ahead of time
    /// rather than after parse keeps the source layer stateless — the
    /// watermark advance is an atomic property of the chunk.
    pub watermark_candidate: Option<Watermark>,
}

/// Errors a [`LogSource`] implementation can return. The variants map
/// directly onto the failure recovery matrix in plan §9 so upper layers
/// (polling loop, retry logic, quota limiter, observability) can react
/// uniformly across sources.
#[derive(Debug, Clone)]
pub enum SourceError {
    /// HTTP 401/403 or token refresh failed. The upper layer should
    /// refresh once; if it fails again, trip the 3-strike auth breaker
    /// and require user-initiated reconnect.
    Auth,
    /// HTTP 429 or source-specific throttling response. The caller should
    /// sleep for at least the attached duration before retrying, and
    /// penalize the per-source quota limiter by the same amount.
    Throttled(Duration),
    /// Query exceeded the source's server-side time budget (Log Analytics
    /// returns 504 or `QueryTimeout` in the body). The caller should
    /// bisect the time window and retry each half.
    Timeout,
    /// The response was truncated because it hit the server's row or
    /// byte cap (500K rows / ~100 MB for Log Analytics). The caller
    /// should bump the watermark to the last row seen and immediately
    /// re-poll to fetch the remainder — NOT sleep.
    Truncated,
    /// Unknown column / table / row shape. Non-fatal: the parser should
    /// skip the offending row/field and continue.
    Schema(String),
    /// Transient network error (DNS, TCP reset, TLS handshake). Retry
    /// with exponential backoff (existing policy in sentinel_connector.rs).
    Network(String),
    /// Permanent failure — invalid config, deleted workspace, bad tenant
    /// ID. The caller should stop polling this source until the user
    /// reconfigures it.
    Fatal(String),
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceError::Auth => write!(f, "authentication failed"),
            SourceError::Throttled(d) => {
                write!(f, "throttled, retry after {}s", d.as_secs())
            }
            SourceError::Timeout => write!(f, "query timed out on the server"),
            SourceError::Truncated => write!(f, "response truncated at server cap"),
            SourceError::Schema(msg) => write!(f, "schema drift: {msg}"),
            SourceError::Network(msg) => write!(f, "network error: {msg}"),
            SourceError::Fatal(msg) => write!(f, "fatal: {msg}"),
        }
    }
}

impl std::error::Error for SourceError {}

/// Type alias for the one-shot query stream returned by
/// [`LogSource::query_scoped`]. The `'static` lifetime means each chunk
/// is owned data (or reference-counted bytes), so the consumer can hold
/// the stream across await points without borrowing from the source.
pub type ChunkStream = BoxStream<'static, Result<RawChunk, SourceError>>;

/// Type alias for the polling stream returned by [`LogSource::poll_since`].
/// Pairs each chunk with the new watermark the caller should persist
/// after successfully processing it.
pub type PollStream = BoxStream<'static, Result<(RawChunk, Watermark), SourceError>>;

/// The log source trait implemented by every Azure connector. Object-safe
/// via `#[async_trait]` — callers can hold `Vec<Arc<dyn LogSource>>` and
/// iterate to dispatch across all connected sources.
///
/// Implementations must be `Send + Sync` because connector tasks spawn
/// them on the tokio multi-thread runtime. State that needs interior
/// mutation should live behind `Mutex` or `RwLock`.
#[async_trait]
pub trait LogSource: Send + Sync {
    /// Stable identifier for this source instance. Typically a combination
    /// of kind + workspace/tenant, e.g., `"la:prod-workspace-eu"` or
    /// `"xdr:contoso-tenant"`.
    fn source_id(&self) -> &str;

    /// Which Azure surface this source queries.
    fn kind(&self) -> SourceKind;

    /// Tables / schemas this source can query. For KQL-based sources this
    /// is a curated subset of the available tables (plan §2a) — not every
    /// table a workspace has, just the ones GraphHunter knows how to
    /// parse into `ParsedTriple`s.
    fn available_tables(&self) -> &[&'static str];

    /// Credential freshness probe. Should NOT actually hit a data
    /// endpoint — just verify the token is valid (token cache lookup +
    /// optional `/me`-style round-trip). Used on startup and reconnect
    /// to surface auth errors early.
    async fn check_auth(&self) -> Result<(), SourceError>;

    /// One-shot entity-scoped query used by the on-demand enrichment path.
    ///
    /// The returned stream yields zero or more `RawChunk`s in fetch order.
    /// Implementations that page internally (e.g., Log Analytics `take N`
    /// loops) should yield one chunk per page, not the whole response at
    /// once, so the parser/writer pipeline can backpressure the source.
    ///
    /// `cancel` is observed at page boundaries; a cancelled token causes
    /// the stream to end (or yield a single `Err(SourceError::Fatal)` with
    /// a "cancelled" message, at the impl's discretion).
    async fn query_scoped(
        &self,
        scope: QueryScope,
        cancel: CancellationToken,
    ) -> Result<ChunkStream, SourceError>;

    /// Long-lived polling query that advances a watermark. Used by the
    /// streaming ingest pipeline (Phase 4) — the polling loop calls this,
    /// drains the stream into the parser channel, and persists each
    /// yielded watermark after the chunk is successfully inserted.
    ///
    /// The returned stream should yield chunks in strict `(source, table,
    /// watermark)` order per invocation. If there is no new data, the
    /// stream ends immediately — the outer polling loop is responsible
    /// for sleeping and re-invoking.
    async fn poll_since(
        &self,
        table: &str,
        watermark: Watermark,
        cancel: CancellationToken,
    ) -> Result<PollStream, SourceError>;
}

// Submodules. `aad_training_export` stayed in graph_hunter_core because
// it bridges the graph ↔ GNN training pipeline, not a log source — only
// its filename put it here. Everything else is pure transport.
pub mod backoff;
pub mod data_lake;
pub mod defender_xdr;
pub mod http_client;
pub mod http_token_fetcher;
pub mod log_analytics;
pub mod quota;
pub mod token_cache;
pub mod token_storage;

// ---------------------------------------------------------------------------
// Tests — just enough to prove the trait is object-safe and the types all
// compose. Source-specific impls get their own test files in Phase 3.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use futures::stream::{self, StreamExt};
    use std::sync::Arc;

    /// Minimum-viable mock that returns a single pre-built chunk. Exists
    /// purely so the trait's object-safety is verified at compile time —
    /// if anything about the trait shape stops being object-safe, this
    /// file will fail to compile.
    struct MockSource {
        id: String,
        tables: Vec<&'static str>,
    }

    #[async_trait]
    impl LogSource for MockSource {
        fn source_id(&self) -> &str {
            &self.id
        }

        fn kind(&self) -> SourceKind {
            SourceKind::LogAnalytics
        }

        fn available_tables(&self) -> &[&'static str] {
            &self.tables
        }

        async fn check_auth(&self) -> Result<(), SourceError> {
            Ok(())
        }

        async fn query_scoped(
            &self,
            scope: QueryScope,
            _cancel: CancellationToken,
        ) -> Result<ChunkStream, SourceError> {
            let chunk = RawChunk {
                source_id: self.id.clone(),
                table: scope
                    .tables
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "SecurityEvent".to_string()),
                rows: Bytes::from_static(b"{}"),
                encoding: ChunkEncoding::Json,
                fetched_at: 0,
                watermark_candidate: None,
            };
            Ok(stream::iter(vec![Ok(chunk)]).boxed())
        }

        async fn poll_since(
            &self,
            table: &str,
            _watermark: Watermark,
            _cancel: CancellationToken,
        ) -> Result<PollStream, SourceError> {
            let chunk = RawChunk {
                source_id: self.id.clone(),
                table: table.to_string(),
                rows: Bytes::from_static(b"{}"),
                encoding: ChunkEncoding::Json,
                fetched_at: 0,
                watermark_candidate: Some(Watermark::new("bump")),
            };
            Ok(stream::iter(vec![Ok((chunk, Watermark::new("bump")))]).boxed())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dyn_logsource_is_object_safe() {
        // This is THE regression guard: if any change to the trait breaks
        // object-safety, the line below fails to compile.
        let sources: Vec<Arc<dyn LogSource>> = vec![
            Arc::new(MockSource {
                id: "mock-1".to_string(),
                tables: vec!["SecurityEvent"],
            }),
            Arc::new(MockSource {
                id: "mock-2".to_string(),
                tables: vec!["SigninLogs", "DeviceProcessEvents"],
            }),
        ];
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0].source_id(), "mock-1");
        assert_eq!(sources[1].available_tables().len(), 2);

        // Dispatch through `dyn` to exercise the full call path.
        for s in &sources {
            s.check_auth().await.unwrap();
            let scope = QueryScope {
                entity: EntityRef {
                    entity_type: "IpAddress".to_string(),
                    value: "10.0.0.1".to_string(),
                },
                time_range: (0, 1_000_000),
                tables: vec!["SecurityEvent".to_string()],
                max_rows_per_table: 100,
            };
            let mut stream = s
                .query_scoped(scope, CancellationToken::new())
                .await
                .unwrap();
            let first = stream.next().await.unwrap().unwrap();
            assert_eq!(first.encoding, ChunkEncoding::Json);
        }
    }

    #[test]
    fn source_kind_as_str_stable() {
        // The stable identifiers are used in watermark keys and metrics
        // labels. Changing them is a breaking change for persisted state.
        assert_eq!(SourceKind::LogAnalytics.as_str(), "la");
        assert_eq!(SourceKind::DataLakeV2.as_str(), "datalake_v2");
        assert_eq!(SourceKind::DefenderXdr.as_str(), "xdr");
        assert_eq!(SourceKind::BlobExport.as_str(), "blob_export");
    }

    #[test]
    fn source_kind_resource_scopes() {
        // Each source maps to a distinct Azure AD audience. The
        // AzureTokenCache keys on (tenant_id, resource_scope), so if two
        // kinds ever collide on this field the cache would serve the
        // wrong token.
        use std::collections::HashSet;
        let mut seen: HashSet<&str> = HashSet::new();
        for kind in [
            SourceKind::LogAnalytics,
            SourceKind::DataLakeV2,
            SourceKind::DefenderXdr,
            SourceKind::BlobExport,
        ] {
            assert!(
                seen.insert(kind.resource_scope()),
                "scope collision on {:?}: {}",
                kind,
                kind.resource_scope()
            );
        }
    }

    #[test]
    fn watermark_helpers() {
        let empty = Watermark::default();
        assert!(empty.is_empty());
        let w = Watermark::new("2026-04-09T12:00:00Z");
        assert!(!w.is_empty());
        assert_eq!(w.as_str(), "2026-04-09T12:00:00Z");
    }

    #[test]
    fn source_error_display_carries_context() {
        // Useful for log line sanity — we want the error message to carry
        // the triage-relevant info without leaking entity values.
        let e = SourceError::Throttled(Duration::from_secs(30));
        assert_eq!(format!("{e}"), "throttled, retry after 30s");
        let e = SourceError::Schema("unknown field Foo".to_string());
        assert_eq!(format!("{e}"), "schema drift: unknown field Foo");
    }
}
