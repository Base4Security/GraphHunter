//! Microsoft Sentinel Data Lake v2 source — STUB IMPLEMENTATION.
//!
//! The plan (fancy-hugging-hearth.md §2b) explicitly calls for shipping
//! the trait hook + auth scaffold here, but NOT the full end-to-end KQL
//! v2 query path. Rationale: Data Lake v2 is a brand-new Sentinel tier
//! with low market penetration as of 2026, and implementing the full
//! query/parser surface against a tier we have no production users on
//! is speculative work. A later 2-day PR flips the stub to a real impl
//! when a customer actually has Data Lake enabled.
//!
//! This module intentionally:
//! - Defines `DataLakeV2Source` that implements [`LogSource`].
//! - Returns a compile-valid, object-safe impl that can be stored in
//!   `Vec<Arc<dyn LogSource>>` alongside the other sources.
//! - Returns [`SourceError::Fatal`] from every data-plane method so a
//!   mis-configured caller fails loudly and early rather than silently
//!   ingesting nothing.
//!
//! Endpoint (for the future real impl):
//! `POST https://api.securityplatform.microsoft.com/lake/kql/v2/rest/query`
//!
//! Auth scope: `https://securityplatform.microsoft.com/.default`
//! (see [`SourceKind::DataLakeV2::resource_scope`]).

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use crate::{ChunkStream, LogSource, PollStream, QueryScope, SourceError, SourceKind, Watermark};

/// A minimal, stubbed Sentinel Data Lake v2 source. Holds identity info
/// so it can participate in the upper layers (health dashboard, metrics,
/// watermark store keying) even though the data plane is unimplemented.
pub struct DataLakeV2Source {
    source_id: String,
    tenant_id: String,
    workspace_id: String,
    available_tables: Vec<&'static str>,
}

impl DataLakeV2Source {
    /// Constructs a Data Lake v2 stub for the given tenant/workspace.
    /// `source_id` is the stable identifier used by watermarks and metrics
    /// (convention: `"datalake_v2:<workspace_id>"`).
    pub fn new(
        source_id: impl Into<String>,
        tenant_id: impl Into<String>,
        workspace_id: impl Into<String>,
    ) -> Self {
        Self {
            source_id: source_id.into(),
            tenant_id: tenant_id.into(),
            workspace_id: workspace_id.into(),
            // Reserved: the full impl will expose the same KQL-table
            // surface as Log Analytics. Stubbed to empty so callers that
            // inspect this list before querying don't accidentally pick
            // a table the stub can't serve.
            available_tables: Vec::new(),
        }
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }
}

#[async_trait]
impl LogSource for DataLakeV2Source {
    fn source_id(&self) -> &str {
        &self.source_id
    }

    fn kind(&self) -> SourceKind {
        SourceKind::DataLakeV2
    }

    fn available_tables(&self) -> &[&'static str] {
        &self.available_tables
    }

    /// Always returns OK so the polling loop doesn't 3-strike-breaker a
    /// source that merely lacks a data-plane impl. Real auth happens
    /// against Azure AD via the `AzureTokenCache` + `HttpTokenFetcher`
    /// path shared across sources.
    async fn check_auth(&self) -> Result<(), SourceError> {
        Ok(())
    }

    async fn query_scoped(
        &self,
        _scope: QueryScope,
        _cancel: CancellationToken,
    ) -> Result<ChunkStream, SourceError> {
        Err(SourceError::Fatal(
            "Data Lake v2 source is a stub. See plan §2b — the full KQL v2 \
             impl ships in a follow-up PR when a customer with Data Lake \
             enabled is available to test against."
                .to_string(),
        ))
    }

    async fn poll_since(
        &self,
        _table: &str,
        _watermark: Watermark,
        _cancel: CancellationToken,
    ) -> Result<PollStream, SourceError> {
        Err(SourceError::Fatal(
            "Data Lake v2 source is a stub. See plan §2b.".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EntityRef, QueryScope};
    use std::sync::Arc;

    #[tokio::test(flavor = "current_thread")]
    async fn stub_returns_fatal_on_query_scoped() {
        let source = DataLakeV2Source::new("datalake_v2:ws-1", "tenant-a", "ws-1");
        let scope = QueryScope {
            entity: EntityRef {
                entity_type: "IpAddress".to_string(),
                value: "10.0.0.1".to_string(),
            },
            time_range: (0, 1_000_000),
            tables: vec!["SecurityEvent".to_string()],
            max_rows_per_table: 100,
        };
        // Can't use `.unwrap_err()` because ChunkStream is `BoxStream<...>`,
        // which doesn't implement Debug (required by unwrap_err for the Ok
        // variant format). Match directly.
        match source.query_scoped(scope, CancellationToken::new()).await {
            Err(SourceError::Fatal(msg)) => {
                assert!(msg.contains("stub"), "got: {msg}");
                assert!(msg.contains("Data Lake"), "got: {msg}");
            }
            Err(other) => panic!("expected Fatal, got {other:?}"),
            Ok(_) => panic!("expected Err, got Ok(stream)"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stub_returns_fatal_on_poll_since() {
        let source = DataLakeV2Source::new("datalake_v2:ws-1", "tenant-a", "ws-1");
        match source
            .poll_since(
                "SecurityEvent",
                Watermark::default(),
                CancellationToken::new(),
            )
            .await
        {
            Err(SourceError::Fatal(_)) => {}
            Err(other) => panic!("expected Fatal, got {other:?}"),
            Ok(_) => panic!("expected Err, got Ok(stream)"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stub_check_auth_succeeds() {
        let source = DataLakeV2Source::new("datalake_v2:ws-1", "tenant-a", "ws-1");
        assert!(source.check_auth().await.is_ok());
    }

    #[test]
    fn stub_reports_correct_kind_and_scope() {
        let source = DataLakeV2Source::new("datalake_v2:ws-1", "tenant-a", "ws-1");
        assert_eq!(source.kind(), SourceKind::DataLakeV2);
        assert_eq!(source.source_id(), "datalake_v2:ws-1");
        assert_eq!(
            source.kind().resource_scope(),
            "https://securityplatform.microsoft.com/.default"
        );
        assert_eq!(source.tenant_id(), "tenant-a");
        assert_eq!(source.workspace_id(), "ws-1");
        assert!(source.available_tables().is_empty());
    }

    #[test]
    fn stub_can_live_in_dyn_logsource_vec() {
        // Object-safety cross-check: the stub must coexist with other
        // Source impls in a `Vec<Arc<dyn LogSource>>`.
        let _sources: Vec<Arc<dyn LogSource>> = vec![Arc::new(DataLakeV2Source::new(
            "datalake_v2:ws-1",
            "t",
            "w",
        ))];
    }
}
