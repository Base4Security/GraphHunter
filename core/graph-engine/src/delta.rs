//! GraphDelta: an idempotent unit of graph change derived from a canonical
//! journal envelope. The `event_id` (the envelope's native id when the source
//! provides one, else its canonical hash) is the edge's identity — distinct
//! from the logical triple (src,rel,dst,ts), which cannot tell a re-ingested
//! duplicate apart from two genuinely-repeated events. Applying a delta whose
//! event_id was already applied is a no-op; this is what makes journal replay
//! after a crash non-duplicating (design spec §11; closes the crash_reingest
//! context of the edge_multiplicity channel).

use crate::parser::RawIngestEvent;

#[derive(Clone, Debug)]
pub struct GraphDelta {
    pub event: RawIngestEvent,
    pub event_id: String,
}

impl GraphDelta {
    pub fn new(event: RawIngestEvent, event_id: String) -> Self {
        GraphDelta { event, event_id }
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
        }
    }

    #[test]
    fn first_apply_inserts_edge() {
        let mut g = GraphHunter::new();
        let out = g
            .apply_delta(&GraphDelta::new(ev("u", "h", 100), "evt-1".into()))
            .unwrap();
        assert!(out.applied);
        assert_eq!(g.relation_count(), 1);
    }

    #[test]
    fn reapplying_same_event_id_is_a_noop() {
        let mut g = GraphHunter::new();
        let d = GraphDelta::new(ev("u", "h", 100), "evt-1".into());
        g.apply_delta(&d).unwrap();
        let out2 = g.apply_delta(&d).unwrap(); // crash replay: same event_id
        assert!(!out2.applied);
        assert_eq!(g.relation_count(), 1); // NOT 2 — idempotent
    }

    #[test]
    fn distinct_event_ids_preserve_multiplicity() {
        let mut g = GraphHunter::new();
        // two genuinely different events between the same entities at the same ts
        g.apply_delta(&GraphDelta::new(ev("u", "h", 100), "evt-1".into()))
            .unwrap();
        g.apply_delta(&GraphDelta::new(ev("u", "h", 100), "evt-2".into()))
            .unwrap();
        assert_eq!(g.relation_count(), 2); // multiplicity preserved
    }
}
