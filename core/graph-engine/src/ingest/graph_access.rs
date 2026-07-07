//! The `GraphAccess` trait — the writer's abstraction over the graph
//! write lock.
//!
//! The core concern: `GraphWriter` lives in `graph_hunter_core`, but
//! the production graph is wrapped in `Arc<tokio::sync::RwLock<
//! GraphHunter>>` inside the Tauri app layer. We don't want to pull
//! a tokio RwLock assumption into core, and we definitely don't want
//! to take a hard dep on a specific app-level state type. The solution
//! is a thin trait that exposes exactly one operation: "insert one
//! chunk of triples, acquiring and releasing whatever locking the
//! implementor uses".
//!
//! Implementors:
//!
//! - Production (Phase 5 in `app/src-tauri/src/ingest`): wraps the
//!   Tauri app's `Arc<tokio::sync::RwLock<GraphHunter>>`. Each call
//!   acquires the write lock, calls `insert_triples_chunk`, and
//!   releases.
//! - Tests (`InMemoryGraphAccess` below): holds a plain
//!   `tokio::sync::Mutex<GraphHunter>` so the writer's behavior can
//!   be verified without any Tauri wiring.
//!
//! ## Why not `Arc<tokio::sync::RwLock<GraphHunter>>` directly
//!
//! Embedding that type in the writer would:
//!
//! 1. Couple graph_hunter_core to `tokio::sync::RwLock` (a bigger
//!    feature bet than the current `tokio = ["sync"]`).
//! 2. Prevent users who wrap the graph in `parking_lot::RwLock` or
//!    `std::sync::RwLock` from using the writer.
//! 3. Make writer unit tests bring up a full lock story for no
//!    reason — the mock trait impl is a direct `Mutex<GraphHunter>`.
//!
//! A trait costs one vtable dispatch per chunk write, which is free at
//! the ~5K-triples-per-chunk granularity.

use async_trait::async_trait;

use crate::errors::GraphError;
use crate::parser::{ParsedTriple, RawIngestEvent};

/// Default chunk size for `GraphWriter` — the number of triples
/// processed per write-lock acquisition. Small enough that readers
/// (hunts, enrichment) can make progress between chunks, large enough
/// that per-chunk locking overhead is amortized across many inserts.
///
/// Tuning notes:
/// - Measured in triples, not bytes. A typical triple produces one
///   `CompactRelation` (32 bytes) + two entity upserts.
/// - At 5 000 / chunk, a 500 000-row Log Analytics response breaks into
///   100 chunks; between each, `tokio::task::yield_now` lets readers
///   acquire the lock.
/// - At 1 TB/day ingest, writer throughput dominates; tune upward if
///   writer saturation is high. Plan §Risks #3.
pub const DEFAULT_WRITE_CHUNK_SIZE: usize = 5_000;

/// Abstracts over "grab the graph's write lock, insert a chunk of
/// triples, release the lock". Implemented at the app layer with
/// whatever locking primitive the caller uses.
///
/// Implementations MUST:
///
/// 1. Acquire the write lock.
/// 2. Call `GraphHunter::insert_triples_chunk(pending, dataset_id, chunk_size)`.
/// 3. Release the lock before returning.
/// 4. Return the number of triples actually inserted (same value as
///    `insert_triples_chunk`).
///
/// Implementations MUST NOT hold the lock across any `.await` point
/// other than the await inside a blocking task wrapper — the whole
/// point of the chunk-and-release design is to keep lock hold times
/// bounded.
#[async_trait]
pub trait GraphAccess: Send + Sync {
    /// Inserts one chunk (up to `chunk_size` triples) from the front
    /// of `pending`, draining the inserted triples from the Vec.
    /// Returns the number inserted.
    ///
    /// If `pending` is empty the implementation MUST return `Ok(0)`
    /// without acquiring the lock.
    async fn insert_chunk(
        &self,
        pending: &mut Vec<ParsedTriple>,
        dataset_id: Option<&str>,
        chunk_size: usize,
    ) -> Result<usize, GraphError>;

    /// Raw-event variant of [`insert_chunk`]. Inserts up to
    /// `chunk_size` events from the front of `pending` via
    /// `GraphHunter::insert_raw_events_chunk`. The streaming pipeline
    /// uses this path; see plan §perf RawIngestEvent.
    ///
    /// Default impl lifts each event through `ParsedTriple` and
    /// delegates to `insert_chunk` so existing implementors keep
    /// working; production implementors should override to call
    /// `insert_raw_events_chunk` directly and capture the alloc
    /// savings.
    async fn insert_raw_chunk(
        &self,
        pending: &mut Vec<RawIngestEvent>,
        dataset_id: Option<&str>,
        chunk_size: usize,
    ) -> Result<usize, GraphError> {
        if pending.is_empty() {
            return Ok(0);
        }
        let n = pending.len().min(chunk_size);
        let chunk: Vec<RawIngestEvent> = pending.drain(..n).collect();
        let mut triples: Vec<ParsedTriple> = chunk
            .into_iter()
            .map(|ev| {
                use crate::entity::Entity;
                use crate::relation::Relation;
                let mut src = Entity::new(ev.src_id, ev.src_type);
                src.metadata = ev.src_metadata;
                let mut dst = Entity::new(ev.dst_id, ev.dst_type);
                dst.metadata = ev.dst_metadata;
                let mut rel =
                    Relation::new(&src.id, &dst.id, ev.rel_type, ev.timestamp);
                rel.metadata = ev.rel_metadata;
                (src, rel, dst)
            })
            .collect();
        // Delegate via the legacy chunk path. `chunk_size` here is
        // the full `n`; the chunk vec is already sized.
        self.insert_chunk(&mut triples, dataset_id, n).await
    }
}

// ---------------------------------------------------------------------------
// InMemoryGraphAccess — a test + doc example implementation.
// Exposed publicly (not #[cfg(test)]) so downstream crates and docs
// can use it to exercise the writer without spinning up Tauri.
// ---------------------------------------------------------------------------

use crate::graph::GraphHunter;
use std::sync::Arc;
use tokio::sync::Mutex;

/// A `GraphAccess` backed by a plain `tokio::sync::Mutex<GraphHunter>`.
/// Used by the writer's own unit tests and as the reference impl
/// documentation for downstream `GraphAccess` implementors.
///
/// Not recommended for production — a `Mutex` serializes reads and
/// writes, which defeats the point of the chunk-release dance. Use a
/// `RwLock`-backed impl in production.
pub struct InMemoryGraphAccess {
    graph: Arc<Mutex<GraphHunter>>,
}

impl InMemoryGraphAccess {
    pub fn new(graph: GraphHunter) -> Self {
        Self {
            graph: Arc::new(Mutex::new(graph)),
        }
    }

    pub fn from_arc(graph: Arc<Mutex<GraphHunter>>) -> Self {
        Self { graph }
    }

    /// Gives tests a read handle to verify post-insert state.
    pub fn graph(&self) -> Arc<Mutex<GraphHunter>> {
        self.graph.clone()
    }
}

#[async_trait]
impl GraphAccess for InMemoryGraphAccess {
    async fn insert_chunk(
        &self,
        pending: &mut Vec<ParsedTriple>,
        dataset_id: Option<&str>,
        chunk_size: usize,
    ) -> Result<usize, GraphError> {
        if pending.is_empty() {
            return Ok(0);
        }
        let mut guard = self.graph.lock().await;
        guard.insert_triples_chunk(pending, dataset_id, chunk_size)
    }

    async fn insert_raw_chunk(
        &self,
        pending: &mut Vec<RawIngestEvent>,
        dataset_id: Option<&str>,
        chunk_size: usize,
    ) -> Result<usize, GraphError> {
        if pending.is_empty() {
            return Ok(0);
        }
        let mut guard = self.graph.lock().await;
        guard.insert_raw_events_chunk(pending, dataset_id, chunk_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::Entity;
    use crate::relation::Relation;
    use crate::types::{EntityType, RelationType};

    fn mk_triple(src_id: &str, dst_id: &str) -> ParsedTriple {
        (
            Entity::new(src_id, EntityType::User),
            Relation::new(src_id, dst_id, RelationType::Auth, 1_700_000_000),
            Entity::new(dst_id, EntityType::Process),
        )
    }

    #[tokio::test(flavor = "current_thread")]
    async fn in_memory_insert_chunk_inserts_up_to_chunk_size() {
        let graph = GraphHunter::new();
        let access = InMemoryGraphAccess::new(graph);

        let mut pending = vec![
            mk_triple("alice", "proc-1"),
            mk_triple("bob", "proc-2"),
            mk_triple("carol", "proc-3"),
        ];
        let n = access.insert_chunk(&mut pending, None, 2).await.unwrap();
        assert_eq!(n, 2);
        assert_eq!(pending.len(), 1); // one left over

        let g = access.graph();
        let guard = g.lock().await;
        assert!(guard.get_entity("alice").is_some());
        assert!(guard.get_entity("bob").is_some());
        assert!(guard.get_entity("carol").is_none()); // not inserted yet
    }

    #[tokio::test(flavor = "current_thread")]
    async fn in_memory_insert_empty_is_zero() {
        let access = InMemoryGraphAccess::new(GraphHunter::new());
        let mut pending: Vec<ParsedTriple> = Vec::new();
        let n = access.insert_chunk(&mut pending, None, 10).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn in_memory_drain_loop_inserts_everything() {
        let access = InMemoryGraphAccess::new(GraphHunter::new());
        let mut pending = vec![
            mk_triple("u-1", "p-1"),
            mk_triple("u-2", "p-2"),
            mk_triple("u-3", "p-3"),
            mk_triple("u-4", "p-4"),
            mk_triple("u-5", "p-5"),
        ];
        let total = pending.len();
        let mut total_inserted = 0;
        while !pending.is_empty() {
            total_inserted += access.insert_chunk(&mut pending, None, 2).await.unwrap();
        }
        assert_eq!(total_inserted, total);

        let g = access.graph();
        let guard = g.lock().await;
        for i in 1..=5 {
            assert!(guard.get_entity(&format!("u-{i}")).is_some());
        }
    }
}
