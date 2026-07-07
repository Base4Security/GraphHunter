//! Aggregated ingest metrics registry.
//!
//! The streaming pipeline already publishes per-task metrics via three
//! task-local atomic structs:
//!
//! - [`WriterMetrics`] — single shared writer, tracks chunks/triples/batches
//! - [`ParserMetrics`] — one per source, tracks parse throughput + drops
//! - [`PollerMetrics`] — one per source, tracks polling cycles + watermarks
//!
//! This module provides a thin registry that holds Arc handles to all
//! of those, along with optional [`QuotaLimiter`] handles per tenant,
//! so a single `cmd_get_ingest_metrics` call at the Tauri layer can
//! return a flat snapshot without cross-referencing the task-local
//! state directly.
//!
//! The registry is purely additive: tasks continue to update their
//! own counters; the registry just knows about them.
//!
//! Wire-up (future Tauri work):
//!
//! 1. At app startup, construct `Arc<WriterMetrics>` and hand it to
//!    both the `GraphWriter` and the registry.
//! 2. When spawning a `SourcePoller` + `ParserTask` for a new source,
//!    call `registry.register_source(id, poller_metrics, parser_metrics)`.
//! 3. When adding a quota limiter for a (source_kind, tenant) key,
//!    call `registry.register_quota(key, limiter)`.
//! 4. Expose `registry.snapshot()` via a Tauri command.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use graph_hunter_sources::SourceKind;
use graph_hunter_sources::quota::QuotaLimiter;

use super::parser_task::{ParserMetrics, ParserMetricsSnapshot};
use super::source_poller::{PollerMetrics, PollerMetricsSnapshot};
use super::writer::{WriterMetrics, WriterMetricsSnapshot};

/// Composite key for a quota limiter. Mirrors the plan §3 quota
/// accounting rules: quotas are enforced per `(source_kind, tenant_id)`
/// because Azure enforces them at the tenant level and each API has
/// its own budget.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct QuotaKey {
    pub source_kind: SourceKind,
    pub tenant_id: String,
}

impl QuotaKey {
    pub fn new(source_kind: SourceKind, tenant_id: impl Into<String>) -> Self {
        Self {
            source_kind,
            tenant_id: tenant_id.into(),
        }
    }
}

/// Per-source metric handles as registered with the registry.
#[derive(Clone)]
pub struct SourceMetricHandles {
    pub parser: Arc<ParserMetrics>,
    pub poller: Arc<PollerMetrics>,
}

/// The global ingest metrics registry. Holds Arc handles to every
/// task-local metrics struct plus per-tenant quota limiters.
pub struct IngestMetricsRegistry {
    writer: Arc<WriterMetrics>,
    sources: RwLock<BTreeMap<String, SourceMetricHandles>>,
    quotas: RwLock<BTreeMap<QuotaKey, Arc<QuotaLimiter>>>,
}

impl IngestMetricsRegistry {
    /// Constructs an empty registry bound to the single shared
    /// `WriterMetrics` handle. The registry must be constructed before
    /// the `GraphWriter` task is spawned so the Arc can be cloned for
    /// both consumers.
    pub fn new(writer: Arc<WriterMetrics>) -> Self {
        Self {
            writer,
            sources: RwLock::new(BTreeMap::new()),
            quotas: RwLock::new(BTreeMap::new()),
        }
    }

    /// Registers a source's parser + poller metrics handles under the
    /// given source id. Re-registering the same id replaces the
    /// previous handles (useful when a source reconnects).
    pub fn register_source(
        &self,
        source_id: impl Into<String>,
        parser: Arc<ParserMetrics>,
        poller: Arc<PollerMetrics>,
    ) {
        let id = source_id.into();
        let mut sources = self.sources.write().unwrap();
        sources.insert(id, SourceMetricHandles { parser, poller });
    }

    /// Drops a source's metric handles. Called when a source is
    /// disconnected. The task-local metrics structs stay alive as long
    /// as the task holds its Arc — this just removes the registry's
    /// reference so future snapshots omit the source.
    pub fn unregister_source(&self, source_id: &str) {
        let mut sources = self.sources.write().unwrap();
        sources.remove(source_id);
    }

    /// Registers a per-quota-key limiter. Multiple sources can share
    /// the same limiter (e.g., two workspaces in one tenant share the
    /// Log Analytics quota).
    pub fn register_quota(&self, key: QuotaKey, limiter: Arc<QuotaLimiter>) {
        let mut quotas = self.quotas.write().unwrap();
        quotas.insert(key, limiter);
    }

    /// Removes a quota limiter. Called on permanent source disconnect.
    pub fn unregister_quota(&self, key: &QuotaKey) {
        let mut quotas = self.quotas.write().unwrap();
        quotas.remove(key);
    }

    /// Access to the shared writer metrics handle. Needed so the
    /// caller can give the same Arc to the `GraphWriter` task.
    pub fn writer(&self) -> Arc<WriterMetrics> {
        self.writer.clone()
    }

    /// Takes a point-in-time snapshot of all registered metrics.
    /// Cheap: just reads atomic counters and clones small Strings.
    pub fn snapshot(&self) -> IngestMetricsSnapshot {
        let writer_snap = self.writer.snapshot();

        let sources = self.sources.read().unwrap();
        let source_snaps: Vec<SourceMetricsSnapshot> = sources
            .iter()
            .map(|(id, handles)| SourceMetricsSnapshot {
                source_id: id.clone(),
                parser: handles.parser.snapshot(),
                poller: handles.poller.snapshot(),
            })
            .collect();

        let quotas = self.quotas.read().unwrap();
        let quota_snaps: Vec<QuotaSnapshot> = quotas
            .iter()
            .map(|(key, limiter)| QuotaSnapshot {
                source_kind: key.source_kind,
                tenant_id: key.tenant_id.clone(),
                tokens_available: limiter.available(),
                penalty_remaining_ms: limiter.penalty_remaining().map(|d| d.as_millis() as u64),
            })
            .collect();

        IngestMetricsSnapshot {
            writer: writer_snap,
            sources: source_snaps,
            quotas: quota_snaps,
        }
    }
}

/// A flat, Clone-able snapshot of the entire ingest metrics space.
#[derive(Debug, Clone)]
pub struct IngestMetricsSnapshot {
    pub writer: WriterMetricsSnapshot,
    pub sources: Vec<SourceMetricsSnapshot>,
    pub quotas: Vec<QuotaSnapshot>,
}

#[derive(Debug, Clone)]
pub struct SourceMetricsSnapshot {
    pub source_id: String,
    pub parser: ParserMetricsSnapshot,
    pub poller: PollerMetricsSnapshot,
}

#[derive(Debug, Clone)]
pub struct QuotaSnapshot {
    pub source_kind: SourceKind,
    pub tenant_id: String,
    pub tokens_available: f64,
    pub penalty_remaining_ms: Option<u64>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    #[test]
    fn register_and_snapshot_empty_registry() {
        let writer = Arc::new(WriterMetrics::default());
        let registry = IngestMetricsRegistry::new(writer);
        let snap = registry.snapshot();
        assert_eq!(snap.sources.len(), 0);
        assert_eq!(snap.quotas.len(), 0);
        assert_eq!(snap.writer.batches_processed, 0);
    }

    #[test]
    fn registered_sources_appear_in_snapshot_alphabetically() {
        let writer = Arc::new(WriterMetrics::default());
        let registry = IngestMetricsRegistry::new(writer);

        // Register out of order to verify BTreeMap ordering.
        let parser_c = Arc::new(ParserMetrics::default());
        let poller_c = Arc::new(PollerMetrics::default());
        registry.register_source("la:c-workspace", parser_c.clone(), poller_c.clone());

        let parser_a = Arc::new(ParserMetrics::default());
        let poller_a = Arc::new(PollerMetrics::default());
        registry.register_source("la:a-workspace", parser_a.clone(), poller_a.clone());

        let parser_b = Arc::new(ParserMetrics::default());
        let poller_b = Arc::new(PollerMetrics::default());
        registry.register_source("la:b-workspace", parser_b.clone(), poller_b.clone());

        let snap = registry.snapshot();
        assert_eq!(snap.sources.len(), 3);
        assert_eq!(snap.sources[0].source_id, "la:a-workspace");
        assert_eq!(snap.sources[1].source_id, "la:b-workspace");
        assert_eq!(snap.sources[2].source_id, "la:c-workspace");
    }

    #[test]
    fn source_metrics_reflect_task_local_state() {
        let writer = Arc::new(WriterMetrics::default());
        let registry = IngestMetricsRegistry::new(writer);

        let parser = Arc::new(ParserMetrics::default());
        let poller = Arc::new(PollerMetrics::default());
        registry.register_source("la:ws-1", parser.clone(), poller.clone());

        // Mutate through the Arc (simulating the task updating its
        // own counters).
        parser.chunks_received.fetch_add(10, Ordering::Relaxed);
        parser.triples_forwarded.fetch_add(123, Ordering::Relaxed);
        poller.cycles.fetch_add(5, Ordering::Relaxed);
        poller.watermark_advances.fetch_add(7, Ordering::Relaxed);

        let snap = registry.snapshot();
        assert_eq!(snap.sources[0].parser.chunks_received, 10);
        assert_eq!(snap.sources[0].parser.triples_forwarded, 123);
        assert_eq!(snap.sources[0].poller.cycles, 5);
        assert_eq!(snap.sources[0].poller.watermark_advances, 7);
    }

    #[test]
    fn unregister_source_removes_from_snapshot() {
        let writer = Arc::new(WriterMetrics::default());
        let registry = IngestMetricsRegistry::new(writer);
        registry.register_source(
            "la:ws-1",
            Arc::new(ParserMetrics::default()),
            Arc::new(PollerMetrics::default()),
        );
        assert_eq!(registry.snapshot().sources.len(), 1);

        registry.unregister_source("la:ws-1");
        assert_eq!(registry.snapshot().sources.len(), 0);
    }

    #[test]
    fn re_registering_replaces_handles() {
        let writer = Arc::new(WriterMetrics::default());
        let registry = IngestMetricsRegistry::new(writer);

        let parser_v1 = Arc::new(ParserMetrics::default());
        parser_v1.chunks_received.store(100, Ordering::Relaxed);
        registry.register_source("la:ws-1", parser_v1, Arc::new(PollerMetrics::default()));

        let parser_v2 = Arc::new(ParserMetrics::default());
        parser_v2.chunks_received.store(5, Ordering::Relaxed);
        registry.register_source("la:ws-1", parser_v2, Arc::new(PollerMetrics::default()));

        let snap = registry.snapshot();
        assert_eq!(snap.sources.len(), 1);
        // The v2 handle is what's registered now.
        assert_eq!(snap.sources[0].parser.chunks_received, 5);
    }

    #[test]
    fn quota_registration_shows_in_snapshot() {
        let writer = Arc::new(WriterMetrics::default());
        let registry = IngestMetricsRegistry::new(writer);

        let la_quota = Arc::new(QuotaLimiter::new(200, 200.0 / 30.0));
        let xdr_quota = Arc::new(QuotaLimiter::new(45, 45.0 / 60.0));
        registry.register_quota(
            QuotaKey::new(SourceKind::LogAnalytics, "tenant-a"),
            la_quota.clone(),
        );
        registry.register_quota(
            QuotaKey::new(SourceKind::DefenderXdr, "tenant-a"),
            xdr_quota.clone(),
        );

        let snap = registry.snapshot();
        assert_eq!(snap.quotas.len(), 2);

        // DefenderXdr < LogAnalytics by the enum discriminant order,
        // so BTreeMap orders them as XDR first — but we're asserting
        // by content, not position.
        let la = snap
            .quotas
            .iter()
            .find(|q| q.source_kind == SourceKind::LogAnalytics)
            .unwrap();
        assert_eq!(la.tenant_id, "tenant-a");
        assert!(la.tokens_available >= 199.9);

        // Apply a penalty and verify the snapshot reflects it.
        la_quota.penalize(Duration::from_secs(30));
        let snap2 = registry.snapshot();
        let la2 = snap2
            .quotas
            .iter()
            .find(|q| q.source_kind == SourceKind::LogAnalytics)
            .unwrap();
        let pen = la2.penalty_remaining_ms.unwrap();
        assert!(pen >= 29_000 && pen <= 31_000);
    }

    #[test]
    fn writer_handle_shared_between_registry_and_writer() {
        let writer = Arc::new(WriterMetrics::default());
        let registry = IngestMetricsRegistry::new(writer.clone());
        // Both point to the same underlying atomics.
        writer.triples_inserted.store(42, Ordering::Relaxed);
        let snap = registry.snapshot();
        assert_eq!(snap.writer.triples_inserted, 42);
    }
}
