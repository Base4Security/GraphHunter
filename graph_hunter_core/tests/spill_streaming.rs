//! Integration tests for the streaming `SpillableEdgeStore::finalize()`.
//!
//! These live outside the lib so they exercise only the public API of
//! `graph_hunter_core::spill`. The in-module `spill::tests` cover the
//! tight unit cases; this file covers the larger workloads that validate
//! the streaming merge doesn't regress at scale.
//!
//! Long-running tests are marked `#[ignore]` so they don't slow down a
//! regular `cargo test` run. Invoke explicitly:
//!
//! ```text
//! cargo test --release --test spill_streaming -- --ignored
//! ```

use graph_hunter_core::{CompactRelation, RelationType, SpillableEdgeStore, StrId};

const RECORD_SIZE: usize = std::mem::size_of::<CompactRelation>();

/// Forces ~100 spill files with a small memory budget and verifies the
/// streaming k-way merge produces a correctly-sorted, complete result.
///
/// This is a "quick" stress test (~100K edges) that runs in the default
/// `cargo test` pass. It's the main regression guard for finalize() — if
/// you break the merge, this test catches it in under 1 second.
#[test]
fn streaming_merge_100k_edges_correctness() {
    // Budget of 1024 records per spill → 100K edges → ~100 spill files.
    let budget = RECORD_SIZE * 1024;
    let mut store = SpillableEdgeStore::new(budget).with_disk_guard_bytes(0);

    let num_sources: u32 = 200;
    let edges_per_source: u32 = 500;
    let total = (num_sources * edges_per_source) as usize;

    // Interleaved push order: for each timestamp bucket, push one edge for
    // every source. This forces every spill file to span many source_sids,
    // which in turn forces the k-way merge to actually interleave during
    // reconstruction. A per-source push order would let the merge be
    // trivially correct by accident.
    for ts_bucket in 0..edges_per_source {
        for src in 0..num_sources {
            let ts = (ts_bucket as i64) * 1000 + (src as i64);
            store
                .push(CompactRelation::new(
                    StrId::from_raw(src),
                    StrId::from_raw(src + 100_000),
                    &RelationType::Connect,
                    ts,
                ))
                .expect("push failed");
        }
    }

    store.finalize().expect("finalize failed");
    assert!(store.is_finalized());
    assert_eq!(store.len(), total);

    // Verify each source's slice is sorted and complete.
    for src in 0..num_sources {
        let edges = store.get_edges(StrId::from_raw(src));
        assert_eq!(
            edges.len(),
            edges_per_source as usize,
            "source {} has {} edges, expected {}",
            src,
            edges.len(),
            edges_per_source
        );
        for (i, e) in edges.iter().enumerate() {
            assert_eq!(
                e.source_sid,
                StrId::from_raw(src),
                "source {} edge {} has wrong source_sid",
                src,
                i
            );
        }
        // Timestamps must be monotonically non-decreasing within a source.
        for i in 1..edges.len() {
            assert!(
                edges[i - 1].timestamp <= edges[i].timestamp,
                "source {} not sorted at idx {}: {} > {}",
                src,
                i,
                edges[i - 1].timestamp,
                edges[i].timestamp
            );
        }
    }
}

/// Stress test: 1M edges across 2000 sources with a small memory budget
/// (forces ~1000 spill files). Validates that the streaming merge scales
/// to workloads where the reference `Vec<CompactRelation>` materialization
/// would matter (Vec of 32 MB vs k=1000 cursors).
///
/// Marked `#[ignore]` so it only runs on explicit request. At ~1M edges
/// this takes several seconds on a laptop; the 100K test above is the
/// default regression guard.
#[test]
#[ignore]
fn streaming_merge_1m_edges_stress() {
    let budget = RECORD_SIZE * 1024;
    let mut store = SpillableEdgeStore::new(budget).with_disk_guard_bytes(0);

    let num_sources: u32 = 2000;
    let edges_per_source: u32 = 500;
    let total = (num_sources * edges_per_source) as usize;

    for ts_bucket in 0..edges_per_source {
        for src in 0..num_sources {
            let ts = (ts_bucket as i64) * 1000 + (src as i64);
            store
                .push(CompactRelation::new(
                    StrId::from_raw(src),
                    StrId::from_raw(src + 100_000),
                    &RelationType::Execute,
                    ts,
                ))
                .expect("push failed");
        }
    }

    store.finalize().expect("finalize failed");
    assert_eq!(store.len(), total);

    // Spot-check a handful of sources rather than all 2000.
    for &src in &[0u32, 1, 100, 999, num_sources - 1] {
        let edges = store.get_edges(StrId::from_raw(src));
        assert_eq!(edges.len(), edges_per_source as usize);
        for i in 1..edges.len() {
            assert!(edges[i - 1].timestamp <= edges[i].timestamp);
        }
    }
}

/// Verifies the timestamp-window query returns correct results on a
/// multi-spill store with interleaved keys.
#[test]
fn get_edges_in_window_large_spill() {
    let budget = RECORD_SIZE * 128;
    let mut store = SpillableEdgeStore::new(budget).with_disk_guard_bytes(0);

    // One source, 1000 edges with timestamps 0, 10, 20, ..., 9990.
    for i in 0..1000 {
        store
            .push(CompactRelation::new(
                StrId::from_raw(42),
                StrId::from_raw(99),
                &RelationType::Auth,
                (i * 10) as i64,
            ))
            .unwrap();
    }
    store.finalize().unwrap();

    let sid = StrId::from_raw(42);

    // Window containing exactly 100 edges (timestamps 2000..2990 step 10).
    let w = store.get_edges_in_window(sid, 2000, 2990);
    assert_eq!(w.len(), 100);
    assert_eq!(w[0].timestamp, 2000);
    assert_eq!(w[99].timestamp, 2990);

    // Single-edge window.
    let w = store.get_edges_in_window(sid, 5000, 5000);
    assert_eq!(w.len(), 1);
    assert_eq!(w[0].timestamp, 5000);

    // Full range.
    let w = store.get_edges_in_window(sid, 0, 9999);
    assert_eq!(w.len(), 1000);

    // Empty windows.
    assert!(store.get_edges_in_window(sid, -100, -10).is_empty());
    assert!(store.get_edges_in_window(sid, 10_000, 20_000).is_empty());
}
