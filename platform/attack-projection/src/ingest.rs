//! Journal envelopes → projection input.
//!
//! The journal (`platform/api/src/journal.rs`) stores one `CanonicalEnvelope`
//! per ingested event, with the parser's `RawIngestEvent` serialized in
//! `raw_payload`. This module rebuilds the triple, projects it to OCSF with
//! `graph_hunter_canonical::triple_to_ocsf` and wraps it in the
//! `{event_id, change, ocsf}` shape the projector reads. The event id is the
//! one `envelope_to_delta` uses (source-native id, else canonical hash), so an
//! attack edge's support and a graph edge point at the same event.

use graph_hunter_canonical::{CanonicalEnvelope, ChangeKind, triple_to_ocsf};
use graph_hunter_core::entity::Entity;
use graph_hunter_core::parser::RawIngestEvent;
use graph_hunter_core::relation::Relation;
use serde_json::{Value, json};

use crate::{AttackDelta, Projector};

/// Relation timestamps are epoch seconds in most parsers, while the
/// projection's lifetimes are in milliseconds. Values below 1e11 are read as
/// seconds (1e11 s is year 5138; 1e11 ms is 1973), the rest as milliseconds.
pub fn to_millis(t: i64) -> i64 {
    if t.abs() < 100_000_000_000 {
        t * 1000
    } else {
        t
    }
}

/// The projector's input for one envelope, or `None` when an insert carries
/// no rebuildable triple (it never produced an edge either).
pub fn projection_input(env: &CanonicalEnvelope) -> Option<Value> {
    let event_id = env
        .native_id
        .clone()
        .unwrap_or_else(|| env.canonical_hash.clone());
    let change = match env.change_kind {
        ChangeKind::Insert => "Insert",
        ChangeKind::Correction => "Correction",
        ChangeKind::Tombstone => return Some(json!({"event_id": event_id, "change": "Tombstone"})),
        ChangeKind::Skipped => return Some(json!({"event_id": event_id, "change": "Skipped"})),
    };
    let ev: RawIngestEvent = serde_json::from_str(&env.raw_payload).ok()?;
    let mut src = Entity::new(ev.src_id.clone(), ev.src_type.clone());
    src.metadata.extend(ev.src_metadata.clone());
    let mut dst = Entity::new(ev.dst_id.clone(), ev.dst_type.clone());
    dst.metadata.extend(ev.dst_metadata.clone());
    let mut rel = Relation::new(&ev.src_id, &ev.dst_id, ev.rel_type.clone(), ev.timestamp);
    rel.metadata.extend(ev.rel_metadata.clone());
    let mut ocsf = serde_json::to_value(triple_to_ocsf(&src, &rel, &dst, &env.provenance)).ok()?;
    ocsf["time"] = json!(to_millis(ev.timestamp));
    Some(json!({"event_id": event_id, "change": change, "ocsf": ocsf}))
}

/// Feeds a batch of journal envelopes, in journal order, to the projector.
pub fn apply_envelopes(
    projector: &mut Projector,
    envelopes: &[CanonicalEnvelope],
) -> Vec<AttackDelta> {
    envelopes
        .iter()
        .filter_map(projection_input)
        .flat_map(|input| projector.apply(&input))
        .collect()
}
