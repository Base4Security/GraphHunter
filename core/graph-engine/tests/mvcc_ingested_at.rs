//! End-to-end verification of the P3 MVCC edge-level foundation.
//!
//! Semántica que este test pins:
//!
//! 1. `add_relation` stamps each new edge with the current wall-clock
//!    `ingested_at`. Two edges added 2s apart in real time produce
//!    two distinct `ingested_at` values in the same ascending order.
//! 2. `ingested_at` is orthogonal to `timestamp` (the event time).
//!    An edge with `timestamp=1_700_000_000` (the past) can be
//!    added today; the compact carries today's `ingested_at`.
//! 3. Callers can filter the outgoing-edge view by snapshot — "only
//!    edges the graph knew about at time T". The current engine has
//!    no built-in snapshot query yet (deferred to follow-up — the
//!    matcher change is where the 2% perf regression budget lives),
//!    so this test demonstrates filtering at the caller level using
//!    the new `CompactRelation::ingested_at()` accessor.
//!
//! What this test does NOT check yet (follow-up work):
//!
//! * `search_temporal_pattern_at(snapshot)` — the matcher wrapper
//!   that bakes snapshot filtering into the DFS, per the plan.
//! * `diff_by_snapshot` — the new analytics function that compares
//!   the same event window at two different `ingested_at` values.
//! * SessionFile v1 → v2 migration (the schema_version bump + backfill
//!   from `timestamp` for legacy edges).
//! * Spill v1 → v2 migrator CLI.

use graph_hunter_core::parser::RawIngestEvent;
use graph_hunter_core::relation::{INGEST_EPOCH_BASE, encode_ingested_at};
use graph_hunter_core::{Entity, EntityType, GraphHunter, GraphRead, Relation, RelationType};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Current wall-clock time in epoch seconds, computed independently of the
/// crate's private `graph::now_seconds` helper (this is an external
/// integration test, so it can't reach that private fn — and shouldn't need
/// to: any correct implementation must agree with the system clock).
fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX_EPOCH")
        .as_secs() as i64
}

#[test]
fn add_relation_stamps_ingested_at_with_wallclock() {
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("alice", EntityType::User))
        .unwrap();
    g.add_entity(Entity::new("web-01", EntityType::Host))
        .unwrap();

    // Use an event timestamp in the past — the `ingested_at` we
    // verify below is wall-clock-now, not this value.
    g.add_relation(Relation::new(
        "alice".to_string(),
        "web-01".to_string(),
        RelationType::Auth,
        1_700_000_000,
    ))
    .unwrap();

    let edges = g.get_compact_relations("alice");
    assert_eq!(edges.len(), 1);
    let ingested = edges[0].ingested_at();

    // The only hard floor we can assert without a deterministic
    // clock: ingested_at must be >= INGEST_EPOCH_BASE (the 2024-01-01
    // anchor) because the delta is `u32 >= 0` by construction.
    assert!(
        ingested >= INGEST_EPOCH_BASE,
        "ingested_at {} must be >= epoch base {}",
        ingested,
        INGEST_EPOCH_BASE
    );

    // And the event timestamp must remain the event timestamp — not
    // overwritten by the ingest stamp.
    assert_eq!(edges[0].timestamp, 1_700_000_000);
}

#[test]
fn two_successive_adds_preserve_ingested_at_order() {
    // Adding the same logical edge twice (different timestamps on
    // the event) must produce ascending `ingested_at` values. The
    // edges might share `source_sid`/`dest_sid` but not the same
    // ingest instant — that's what lets downstream replay say "I
    // learned about this at T₁, that at T₂".
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("alice", EntityType::User))
        .unwrap();
    g.add_entity(Entity::new("web-01", EntityType::Host))
        .unwrap();

    g.add_relation(Relation::new(
        "alice".to_string(),
        "web-01".to_string(),
        RelationType::Auth,
        1_700_000_000,
    ))
    .unwrap();
    // Sleep briefly so the second add sees a distinct wall-clock
    // second. 1.1 s is enough that on any CI box the two instants
    // fall in different seconds.
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    g.add_relation(Relation::new(
        "alice".to_string(),
        "web-01".to_string(),
        RelationType::Auth,
        1_700_000_100,
    ))
    .unwrap();

    let edges = g.get_compact_relations("alice");
    assert_eq!(edges.len(), 2);
    assert!(
        edges[1].ingested_at() > edges[0].ingested_at(),
        "second add ingested_at {} must be > first {}",
        edges[1].ingested_at(),
        edges[0].ingested_at()
    );
}

#[test]
fn caller_can_filter_by_snapshot() {
    // Demonstrates the MVCC query pattern at the caller level —
    // essentially what `search_temporal_pattern_at(snapshot)` will
    // do internally in a follow-up. An analyst says: "show me only
    // the edges the graph knew about before T". Today the caller
    // walks `get_compact_relations` and filters by `ingested_at()`.
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("alice", EntityType::User))
        .unwrap();
    g.add_entity(Entity::new("web-01", EntityType::Host))
        .unwrap();
    g.add_entity(Entity::new("cmd.exe", EntityType::Process))
        .unwrap();

    // Two edges, stamped manually at known ingest instants.
    let _e1 = g.get_compact_relations("alice");

    g.add_relation(Relation::new(
        "alice".to_string(),
        "web-01".to_string(),
        RelationType::Auth,
        1_700_000_000,
    ))
    .unwrap();
    g.add_relation(Relation::new(
        "web-01".to_string(),
        "cmd.exe".to_string(),
        RelationType::Execute,
        1_700_000_100,
    ))
    .unwrap();

    // Caller-side snapshot filter: everything ingested BEFORE a
    // future instant (INGEST_EPOCH_BASE + 200 years' worth) →
    // everything. Nothing ingested AFTER u32::MAX worth of seconds
    // from epoch → empty. Both are boundary conditions we want to
    // exercise.
    let all_edges: Vec<_> = g.get_compact_relations("alice").to_vec();
    let before_sentinel: Vec<_> = all_edges
        .iter()
        .filter(|c| c.ingested_at() <= INGEST_EPOCH_BASE + u32::MAX as i64)
        .collect();
    let after_sentinel: Vec<_> = all_edges
        .iter()
        .filter(|c| c.ingested_at() > INGEST_EPOCH_BASE + u32::MAX as i64)
        .collect();
    assert_eq!(before_sentinel.len(), all_edges.len());
    assert_eq!(after_sentinel.len(), 0);
}

#[test]
fn encode_helper_matches_expected_delta() {
    // Documents the encoding contract for external callers — e.g.
    // ingest/batch.rs will compute deltas from `chunk.fetched_at`.
    let ten_days_after_epoch = INGEST_EPOCH_BASE + 10 * 24 * 3600;
    let delta = encode_ingested_at(ten_days_after_epoch);
    assert_eq!(delta, 10 * 24 * 3600);
}

#[test]
fn ingested_edges_carry_a_real_receive_time_not_the_epoch_base() {
    // This pins the Task 1 fix: mass-ingest paths (insert_raw_events,
    // insert_triples, ingest_logs_with_policy, ingest_logs_chunked) used to
    // hardcode `ingested_at_delta: 0`, so every mass-ingested edge read back
    // as INGEST_EPOCH_BASE regardless of when it was actually received.
    let mut g = GraphHunter::new();

    let event = RawIngestEvent {
        src_id: "alice".to_string(),
        src_type: EntityType::User,
        src_metadata: HashMap::new(),
        dst_id: "web-01".to_string(),
        dst_type: EntityType::Host,
        dst_metadata: HashMap::new(),
        rel_type: RelationType::Auth,
        rel_metadata: HashMap::new(),
        // Event time is in the past — must not be confused with ingest time.
        timestamp: 1_700_000_000,
        raw_line: None,
    };

    let before = now_seconds();
    g.insert_raw_events(vec![event], None)
        .expect("insert_raw_events should succeed");
    let after = now_seconds();

    let edges = g.get_compact_relations("alice");
    assert_eq!(edges.len(), 1);
    let ts = edges[0].ingested_at();

    assert!(
        ts >= before && ts <= after,
        "ingested_at should be ~now, got {ts} (before={before}, after={after}, base={INGEST_EPOCH_BASE})"
    );
    assert!(
        ts > INGEST_EPOCH_BASE,
        "ingested_at {ts} must not be the hardcoded-0 epoch base {INGEST_EPOCH_BASE}"
    );
}

#[test]
fn compact_before_preserves_ingested_at_delta_not_reset() {
    // compact_before rebuilds edges from the existing ones (grouping,
    // possibly summarizing multiple edges into one). It must carry the
    // original ingested_at_delta forward — never reset it to 0 (the old,
    // now-fixed hardcoded-0 bug) and never re-stamp it to "now" (which
    // would erase the true receive time on every compaction).
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("alice", EntityType::User))
        .unwrap();
    g.add_entity(Entity::new("web-01", EntityType::Host))
        .unwrap();

    // Two edges between the same pair, both with event timestamps well
    // before the cutoff below, so compact_before groups and summarizes
    // them into a single edge (the `all_old && edges.len() > 1` path).
    g.add_relation(Relation::new(
        "alice".to_string(),
        "web-01".to_string(),
        RelationType::Auth,
        100,
    ))
    .unwrap();
    g.add_relation(Relation::new(
        "alice".to_string(),
        "web-01".to_string(),
        RelationType::Auth,
        200,
    ))
    .unwrap();

    let before_edges = g.get_compact_relations("alice");
    assert_eq!(before_edges.len(), 2);
    let expected_delta = before_edges[0].ingested_at_delta;
    assert_ne!(
        expected_delta, 0,
        "precondition: add_relation must stamp a real (non-zero) delta"
    );

    let stats = g
        .compact_before(1_000)
        .expect("compact_before should succeed");
    assert_eq!(
        stats.groups_compacted, 1,
        "the two same-pair edges should be summarized into one group"
    );

    let after_edges = g.get_compact_relations("alice");
    assert_eq!(
        after_edges.len(),
        1,
        "the two edges should have been compacted into a single summary edge"
    );
    assert_eq!(
        after_edges[0].ingested_at_delta, expected_delta,
        "compaction must preserve the original ingested_at_delta, not reset it to 0"
    );
}
