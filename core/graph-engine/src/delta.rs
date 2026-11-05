//! GraphDelta: an idempotent unit of graph change derived from a canonical
//! journal envelope. The `event_id` (the envelope's native id when the source
//! provides one, else its canonical hash) is the edge's identity — distinct
//! from the logical triple (src,rel,dst,ts), which cannot tell a re-ingested
//! duplicate apart from two genuinely-repeated events. Applying a delta whose
//! event_id was already applied is a no-op; this is what makes journal replay
//! non-duplicating after a crash **within the current process/session** —
//! e.g. a poller task that crashes and re-polls in the same running
//! `GraphHunter` (design spec §11; closes the crash_reingest context of the
//! edge_multiplicity channel). `applied_event_ids` lives only in memory, so a
//! full process restart wipes it: cross-restart durability would require
//! seeding `applied_event_ids` from the journal on startup (future work).
//!
//! `event_id` stability across re-parse depends on the journal's `raw_payload`
//! being serialized deterministically (sorted map keys) — see
//! `platform/api/src/journal.rs`'s canonicalizing serialization. Without that,
//! `RawIngestEvent`'s `HashMap` metadata fields serialize in per-instance
//! `RandomState` iteration order, so re-parsing the same source row after a
//! crash produces a different `canonical_hash` each time and this whole
//! dedup collapses (critical-fix wave, Fase C-1 final review).

use crate::parser::RawIngestEvent;

#[derive(Clone, Debug)]
pub struct GraphDelta {
    pub event: RawIngestEvent,
    pub event_id: String,
    /// The dataset this event belongs to, threaded through to
    /// `insert_raw_events` so `apply_delta` doesn't silently drop dataset
    /// attribution the way the direct ingest path (which passes
    /// `Some(dataset_id)`) never does.
    pub dataset_id: Option<String>,
}

impl GraphDelta {
    pub fn new(event: RawIngestEvent, event_id: String, dataset_id: Option<String>) -> Self {
        GraphDelta {
            event,
            event_id,
            dataset_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::GraphHunter;
    use crate::parser::RawIngestEvent;
    use crate::types::{EntityType, RelationType};
    use std::collections::HashMap;

    fn ev(src: &str, dst: &str, ts: i64) -> RawIngestEvent {
        RawIngestEvent {
            src_id: src.into(),
            src_type: EntityType::User,
            src_metadata: HashMap::new(),
            dst_id: dst.into(),
            dst_type: EntityType::Host,
            dst_metadata: HashMap::new(),
            rel_type: RelationType::Auth,
            rel_metadata: HashMap::new(),
            timestamp: ts,
            raw_line: None,
        }
    }

    #[test]
    fn first_apply_inserts_edge() {
        let mut g = GraphHunter::new();
        let out = g
            .apply_delta(&GraphDelta::new(ev("u", "h", 100), "evt-1".into(), None))
            .unwrap();
        assert!(out.applied);
        assert_eq!(g.relation_count(), 1);
    }

    #[test]
    fn reapplying_same_event_id_is_a_noop() {
        let mut g = GraphHunter::new();
        let d = GraphDelta::new(ev("u", "h", 100), "evt-1".into(), None);
        g.apply_delta(&d).unwrap();
        let out2 = g.apply_delta(&d).unwrap(); // crash replay: same event_id
        assert!(!out2.applied);
        assert_eq!(g.relation_count(), 1); // NOT 2 — idempotent
    }

    #[test]
    fn apply_delta_threads_dataset_id_into_inserted_entities() {
        // apply_delta must not drop dataset attribution the way it used to
        // (insert_raw_events(vec![delta.event.clone()], None) hardcoded
        // None) — the direct ingest path passes Some(dataset_id), and the
        // delta-apply path must match it or per-dataset views/removal miss
        // these entities.
        let mut g = GraphHunter::new();
        let d = GraphDelta::new(ev("u", "h", 100), "evt-1".into(), Some("ds-42".into()));
        g.apply_delta(&d).unwrap();
        assert_eq!(
            g.get_entity("u").unwrap().dataset_id.as_deref(),
            Some("ds-42")
        );
        assert_eq!(
            g.get_entity("h").unwrap().dataset_id.as_deref(),
            Some("ds-42")
        );
    }

    #[test]
    fn distinct_event_ids_preserve_multiplicity() {
        let mut g = GraphHunter::new();
        // two genuinely different events between the same entities at the same ts
        g.apply_delta(&GraphDelta::new(ev("u", "h", 100), "evt-1".into(), None))
            .unwrap();
        g.apply_delta(&GraphDelta::new(ev("u", "h", 100), "evt-2".into(), None))
            .unwrap();
        assert_eq!(g.relation_count(), 2); // multiplicity preserved
    }

    /// The batch path must dedup exactly like per-event `apply_delta`:
    /// across calls (crash replay), within one batch, and against ids that
    /// `apply_delta` already recorded — both paths share one key space.
    #[test]
    fn batch_idempotent_insert_matches_apply_delta() {
        let key = GraphHunter::event_key;
        let mut g = GraphHunter::new();
        let batch = vec![ev("u", "h", 1), ev("u", "h", 2), ev("u", "h", 1)];
        let keys = [key("a"), key("b"), key("a")]; // "a" repeats in-batch
        let (_, r) = g
            .insert_raw_events_idempotent(batch.clone(), &keys, Some("ds"))
            .unwrap();
        assert_eq!(r, 2, "in-batch duplicate collapses");
        let (_, r) = g
            .insert_raw_events_idempotent(batch, &keys, Some("ds"))
            .unwrap();
        assert_eq!(r, 0, "replaying the batch adds nothing");
        let out = g
            .apply_delta(&GraphDelta::new(ev("u", "h", 2), "b".into(), None))
            .unwrap();
        assert!(!out.applied, "apply_delta sees ids the batch path recorded");
        g.apply_delta(&GraphDelta::new(ev("u", "h", 3), "c".into(), None))
            .unwrap();
        let (_, r) = g
            .insert_raw_events_idempotent(vec![ev("u", "h", 3)], &[key("c")], None)
            .unwrap();
        assert_eq!(r, 0, "the batch path sees ids apply_delta recorded");
        assert_eq!(g.relation_count(), 3);
    }
}
