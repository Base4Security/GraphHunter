//! Hierarchical cancellation tree for the ingest pipeline.
//!
//! Plan §8 defines a 4-level cancellation hierarchy:
//!
//! ```text
//! AppCancelToken (root)
//! ├── IngestCancelToken (bulk file ingest + streaming ingest)
//! │   └── per-source PollerCancelToken (one per `SourcePoller`)
//! ├── EnrichmentCancelToken (one per in-flight enrichment click)
//! └── HuntCancelToken (one per hunt execution)
//! ```
//!
//! All tokens descend from a single `root` so shutdown is a one-call
//! `cancel_all()` that propagates through every branch. Individual
//! branches can be cancelled independently without affecting the
//! others — e.g., `cancel_enrichment()` leaves streaming ingest
//! running.
//!
//! This module provides [`IngestCancelTree`], a thin struct that
//! owns the tree and exposes typed accessors. The Tauri app (Phase 9
//! follow-up) holds the tree in `AppState`, hands child tokens to
//! spawned tasks, and intercepts `WindowEvent::CloseRequested` to
//! call `cancel_all()`.

use std::collections::HashMap;
use std::sync::RwLock;
use tokio_util::sync::CancellationToken;

/// Hierarchical cancellation tokens for the ingest pipeline.
///
/// Construct once at app startup, hand child tokens to spawned tasks.
/// All tokens are cheap clones (`Arc<_>` internally), so consumers
/// can freely clone the result of each accessor.
pub struct IngestCancelTree {
    root: CancellationToken,
    ingest: CancellationToken,
    enrichment: CancellationToken,
    hunt: CancellationToken,
    /// Per-source child tokens under the ingest branch. Lazily
    /// created on first `source(id)` call.
    sources: RwLock<HashMap<String, CancellationToken>>,
}

impl Default for IngestCancelTree {
    fn default() -> Self {
        Self::new()
    }
}

impl IngestCancelTree {
    pub fn new() -> Self {
        let root = CancellationToken::new();
        let ingest = root.child_token();
        let enrichment = root.child_token();
        let hunt = root.child_token();
        Self {
            root,
            ingest,
            enrichment,
            hunt,
            sources: RwLock::new(HashMap::new()),
        }
    }

    /// Clone of the root cancellation token. Cancelling this token
    /// propagates through every descendant (ingest, enrichment, hunt,
    /// and every per-source token).
    pub fn root(&self) -> CancellationToken {
        self.root.clone()
    }

    /// Clone of the ingest branch token. Cancelling this token
    /// propagates through every per-source token but leaves
    /// enrichment and hunt alone.
    pub fn ingest(&self) -> CancellationToken {
        self.ingest.clone()
    }

    /// Clone of the enrichment branch token. Independent of ingest
    /// and hunt — useful for mid-drill-down cancellation when the
    /// user clicks a different entity.
    pub fn enrichment(&self) -> CancellationToken {
        self.enrichment.clone()
    }

    /// Clone of the hunt branch token. Independent of ingest and
    /// enrichment — cancels a hunt mid-execution without stopping
    /// the streaming pipeline.
    pub fn hunt(&self) -> CancellationToken {
        self.hunt.clone()
    }

    /// Gets or creates a per-source cancellation token under the
    /// ingest branch. Subsequent calls with the same `source_id`
    /// return the same token (via clone) so multiple tasks for the
    /// same source share cancellation state.
    pub fn source(&self, source_id: &str) -> CancellationToken {
        // Fast path: read lock.
        {
            let map = self.sources.read().unwrap();
            if let Some(tok) = map.get(source_id) {
                return tok.clone();
            }
        }
        // Slow path: upgrade to write lock and insert.
        let mut map = self.sources.write().unwrap();
        if let Some(tok) = map.get(source_id) {
            return tok.clone();
        }
        let tok = self.ingest.child_token();
        map.insert(source_id.to_string(), tok.clone());
        tok
    }

    /// Cancels the entire ingest branch. All per-source tokens under
    /// it fire; enrichment and hunt are untouched.
    pub fn cancel_ingest(&self) {
        self.ingest.cancel();
    }

    /// Cancels a single source's token (if it exists). Does nothing
    /// if the source was never registered.
    pub fn cancel_source(&self, source_id: &str) {
        let map = self.sources.read().unwrap();
        if let Some(tok) = map.get(source_id) {
            tok.cancel();
        }
    }

    /// Cancels the enrichment branch. Every in-flight enrichment
    /// sees its token fire. Typically called when the user closes a
    /// drill-down panel or clicks a new entity.
    pub fn cancel_enrichment(&self) {
        self.enrichment.cancel();
    }

    /// Cancels the hunt branch. Use to abort a long-running hunt
    /// from the UI.
    pub fn cancel_hunt(&self) {
        self.hunt.cancel();
    }

    /// Global cancellation. Every token under the root — ingest,
    /// every source, enrichment, hunt — fires. Called on app
    /// shutdown.
    pub fn cancel_all(&self) {
        self.root.cancel();
    }

    /// Drops a per-source token from the internal map. The token
    /// itself stays alive as long as any task holds a clone, but
    /// subsequent `source(id)` calls will create a fresh token. Use
    /// this when a source is disconnected and reconnected fresh.
    pub fn forget_source(&self, source_id: &str) {
        let mut map = self.sources.write().unwrap();
        map.remove(source_id);
    }

    /// Number of per-source tokens currently tracked. For tests and
    /// metrics.
    pub fn source_count(&self) -> usize {
        self.sources.read().unwrap().len()
    }

    /// Convenience: returns true if the root has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.root.is_cancelled()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_tree_has_no_cancellations() {
        let tree = IngestCancelTree::new();
        assert!(!tree.root().is_cancelled());
        assert!(!tree.ingest().is_cancelled());
        assert!(!tree.enrichment().is_cancelled());
        assert!(!tree.hunt().is_cancelled());
        assert_eq!(tree.source_count(), 0);
    }

    #[test]
    fn cancel_all_propagates_to_every_branch() {
        let tree = IngestCancelTree::new();
        let la_source = tree.source("la:ws-1");
        let xdr_source = tree.source("xdr:tenant-a");
        let ingest = tree.ingest();
        let enrich = tree.enrichment();
        let hunt = tree.hunt();

        tree.cancel_all();

        assert!(tree.is_cancelled());
        assert!(ingest.is_cancelled());
        assert!(enrich.is_cancelled());
        assert!(hunt.is_cancelled());
        assert!(la_source.is_cancelled());
        assert!(xdr_source.is_cancelled());
    }

    #[test]
    fn cancel_ingest_affects_sources_but_not_enrichment_or_hunt() {
        let tree = IngestCancelTree::new();
        let la_source = tree.source("la:ws-1");
        let enrich = tree.enrichment();
        let hunt = tree.hunt();

        tree.cancel_ingest();

        assert!(tree.ingest().is_cancelled());
        assert!(la_source.is_cancelled());
        assert!(
            !enrich.is_cancelled(),
            "enrichment unaffected by ingest cancel"
        );
        assert!(!hunt.is_cancelled(), "hunt unaffected by ingest cancel");
        assert!(!tree.is_cancelled(), "root unaffected");
    }

    #[test]
    fn cancel_enrichment_only_affects_enrichment_branch() {
        let tree = IngestCancelTree::new();
        let la_source = tree.source("la:ws-1");
        let enrich = tree.enrichment();
        let hunt = tree.hunt();

        tree.cancel_enrichment();

        assert!(enrich.is_cancelled());
        assert!(!tree.ingest().is_cancelled());
        assert!(!la_source.is_cancelled());
        assert!(!hunt.is_cancelled());
    }

    #[test]
    fn cancel_hunt_only_affects_hunt_branch() {
        let tree = IngestCancelTree::new();
        let la_source = tree.source("la:ws-1");
        let enrich = tree.enrichment();
        let hunt = tree.hunt();

        tree.cancel_hunt();

        assert!(hunt.is_cancelled());
        assert!(!tree.ingest().is_cancelled());
        assert!(!la_source.is_cancelled());
        assert!(!enrich.is_cancelled());
    }

    #[test]
    fn cancel_source_only_affects_that_source() {
        let tree = IngestCancelTree::new();
        let la_source = tree.source("la:ws-1");
        let xdr_source = tree.source("xdr:tenant-a");

        tree.cancel_source("la:ws-1");

        assert!(la_source.is_cancelled());
        assert!(!xdr_source.is_cancelled());
        assert!(!tree.ingest().is_cancelled());
    }

    #[test]
    fn cancel_source_for_unknown_id_is_noop() {
        let tree = IngestCancelTree::new();
        tree.cancel_source("doesnt-exist");
        assert!(!tree.ingest().is_cancelled());
    }

    #[test]
    fn source_returns_same_token_on_repeated_calls() {
        let tree = IngestCancelTree::new();
        let a1 = tree.source("la:ws-1");
        let a2 = tree.source("la:ws-1");
        // They must share state — cancelling one cancels the other.
        a1.cancel();
        assert!(a2.is_cancelled());
        assert_eq!(tree.source_count(), 1);
    }

    #[test]
    fn source_is_child_of_ingest_branch() {
        let tree = IngestCancelTree::new();
        let la = tree.source("la:ws-1");
        tree.cancel_ingest();
        assert!(la.is_cancelled());
    }

    #[test]
    fn forget_source_creates_fresh_token_on_next_call() {
        let tree = IngestCancelTree::new();
        let old = tree.source("la:ws-1");
        old.cancel();
        assert!(old.is_cancelled());

        tree.forget_source("la:ws-1");
        assert_eq!(tree.source_count(), 0);

        // Next call produces a new, non-cancelled token.
        let new_tok = tree.source("la:ws-1");
        assert!(!new_tok.is_cancelled());
        assert_eq!(tree.source_count(), 1);
    }

    #[test]
    fn multiple_sources_independent() {
        let tree = IngestCancelTree::new();
        let a = tree.source("la:ws-1");
        let b = tree.source("la:ws-2");
        let c = tree.source("xdr:tenant");

        a.cancel();

        assert!(a.is_cancelled());
        assert!(!b.is_cancelled());
        assert!(!c.is_cancelled());
        assert_eq!(tree.source_count(), 3);
    }

    #[test]
    fn is_cancelled_tracks_root() {
        let tree = IngestCancelTree::new();
        assert!(!tree.is_cancelled());
        tree.cancel_all();
        assert!(tree.is_cancelled());
    }
}
