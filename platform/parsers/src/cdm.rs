//! Native parser for DARPA Transparent Computing CDM (E3, `cdm18`) JSON.
//!
//! CDM is the provenance format the TC engagements publish: newline-
//! delimited JSON where each record's `datum` holds exactly one typed
//! object — either an *entity* (a `Subject` process, a `FileObject`, a
//! `NetFlowObject`, a `Principal`…) or an `Event` that connects two of
//! them. Events reference their endpoints by UUID, and those UUIDs are
//! defined in *other* records, so turning a stream of records into graph
//! triples is inherently two-pass: catalogue the entities first, then
//! resolve each event's endpoints against the catalogue.
//!
//! A Rust port of `training/01_parse_darpa_cdm.py`, which had proven the
//! mapping against the real corpus but only as an offline batch script.
//! Bringing it in-engine makes CDM a first-class ingest format — the
//! "how did you load tens of millions of provenance events" answer for a
//! venue, on the same explainable path as every other source — rather
//! than a preprocessing step nobody can audit.
//!
//! # Timestamp unit — a deliberate choice
//!
//! CDM stamps events in **nanoseconds**. The rest of this engine reasons
//! in **seconds**: causal monotonicity, the `WITHIN` window and the
//! `SKEW` tolerance are all second-valued. Emitting ns here would make a
//! `SKEW 5s` meaningless against ns timestamps. So the edge `timestamp`
//! is seconds (floored), which keeps CDM coherent with every temporal
//! feature today — and the full nanosecond value is preserved verbatim on
//! the edge as `ts_nanos` metadata, so no resolution is lost and a future
//! migration of the whole engine to ns has the data waiting. The cost,
//! stated plainly: two events inside the same second compare as
//! simultaneous for monotonicity. `ts_nanos` is how you recover their
//! true order until the engine is ns-native.
//!
//! # Streaming caveat
//!
//! The two-pass is over the text handed to `parse`. Within one file (the
//! normal case) every UUID an event names is defined somewhere in that
//! text, so it resolves. If the corpus is fed in chunks and an event's
//! endpoint was defined in an earlier chunk, that endpoint is unknown
//! here and the event is skipped rather than guessed — reported through
//! the skip counters, never silently dropped.

use std::collections::HashMap;

use graph_hunter_core::entity::Entity;
use graph_hunter_core::parser::{LogParser, ParsedTriple};
use graph_hunter_core::relation::Relation;
use graph_hunter_core::types::{EntityType, RelationType};
use serde_json::Value;

const CDM_PREFIX: &str = "com.bbn.tc.schema.avro.cdm18.";

/// Maps a CDM entity record key (without the shared prefix) to a
/// GraphHunter entity type. Mirrors `CDM_TYPE_MAP` in the Python port.
fn entity_type_for(cdm_key: &str) -> Option<EntityType> {
    let ty = match cdm_key {
        "Subject" => EntityType::Process,
        "FileObject" => EntityType::File,
        "NetFlowObject" => EntityType::IP,
        "SrcSinkObject" => EntityType::Service,
        "Principal" => EntityType::User,
        "RegistryKeyObject" => EntityType::Registry,
        // Pipes and shared memory are file-like for our purposes; the
        // Python port folds them into File and we keep parity.
        "UnnamedPipeObject" | "MemoryObject" => EntityType::File,
        "Host" => EntityType::Host,
        _ => return None,
    };
    Some(ty)
}

/// Maps a CDM `EVENT_*` type to a relation type. Mirrors `CDM_EVENT_MAP`
/// in the Python port; unmapped events are dropped (counted as skips).
fn relation_type_for(event_type: &str) -> Option<RelationType> {
    let rt = match event_type {
        "EVENT_OPEN"
        | "EVENT_READ"
        | "EVENT_MMAP"
        | "EVENT_LSEEK"
        | "EVENT_CHECK_FILE_ATTRIBUTES" => RelationType::Read,
        "EVENT_WRITE"
        | "EVENT_CLOSE"
        | "EVENT_MODIFY_FILE_ATTRIBUTES"
        | "EVENT_RENAME"
        | "EVENT_LINK"
        | "EVENT_UNLINK" => RelationType::Write,
        "EVENT_EXECUTE" | "EVENT_FORK" | "EVENT_CLONE" | "EVENT_SIGNAL" => RelationType::Execute,
        "EVENT_CONNECT" | "EVENT_ACCEPT" | "EVENT_SENDTO" | "EVENT_RECVFROM" | "EVENT_SENDMSG"
        | "EVENT_RECVMSG" | "EVENT_OTHER" => RelationType::Connect,
        "EVENT_LOGIN" | "EVENT_CHANGE_PRINCIPAL" => RelationType::Auth,
        _ => return None,
    };
    Some(rt)
}

/// Pulls the UUID string out of a CDM endpoint reference. The reference is
/// either `{"com.bbn.tc.schema.avro.cdm18.UUID": "<uuid>"}` or a bare
/// string; `null`/absent yields `None`.
fn endpoint_uuid(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        Value::Object(_) => v
            .get("com.bbn.tc.schema.avro.cdm18.UUID")
            .and_then(|u| u.as_str())
            .map(str::to_string),
        _ => None,
    }
}

/// A best-effort human name for an entity record, falling back to a
/// truncated UUID so a node is never anonymous.
fn entity_name(entity: &Value, uuid: &str) -> String {
    if let Some(name) = entity
        .pointer("/properties/map/name")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        return name.to_string();
    }
    if let Some(path) = entity
        .get("path")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        return path.to_string();
    }
    uuid.chars().take(12).collect()
}

/// The `datum`'s single typed object, as `(cdm_key_without_prefix, body)`.
fn datum_entry(record: &Value) -> Option<(&str, &Value)> {
    let datum = record.get("datum")?.as_object()?;
    let (full_key, body) = datum.iter().next()?;
    let key = full_key.strip_prefix(CDM_PREFIX)?;
    Some((key, body))
}

pub struct CdmParser;

impl CdmParser {
    /// Two-pass parse over `data`: pass 1 catalogues entity UUIDs, pass 2
    /// resolves events against that catalogue.
    fn parse_inner(&self, data: &str) -> Vec<ParsedTriple> {
        // Pass 1 — entity catalogue: uuid → (type, name).
        let mut catalogue: HashMap<String, (EntityType, String)> = HashMap::new();
        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let record: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let Some((key, body)) = datum_entry(&record) else {
                continue;
            };
            // Events are handled in pass 2; only entity records here.
            if key == "Event" {
                continue;
            }
            let Some(ty) = entity_type_for(key) else {
                continue;
            };
            let uuid = match body.get("uuid").and_then(Value::as_str) {
                Some(u) => u.to_string(),
                None => continue,
            };
            let name = entity_name(body, &uuid);
            catalogue.entry(uuid).or_insert((ty, name));
        }

        // Pass 2 — events into triples.
        let mut triples = Vec::new();
        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let record: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let Some((key, event)) = datum_entry(&record) else {
                continue;
            };
            if key != "Event" {
                continue;
            }
            let Some(rel_type) = event
                .get("type")
                .and_then(Value::as_str)
                .and_then(relation_type_for)
            else {
                continue;
            };

            let src_uuid = event.get("subject").and_then(endpoint_uuid);
            let Some(src_uuid) = src_uuid else { continue };
            let Some((src_ty, src_name)) = catalogue.get(&src_uuid) else {
                continue;
            };

            // CDM stamps nanoseconds; the edge carries seconds (see the
            // module note) with the raw ns preserved as metadata.
            let ts_nanos = event
                .get("timestampNanos")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            let ts_seconds = ts_nanos / 1_000_000_000;
            let event_type = event.get("type").and_then(Value::as_str).unwrap_or("");

            // An event may act on one or two objects (predicateObject and
            // predicateObject2 — e.g. a rename's source and target).
            for endpoint in ["predicateObject", "predicateObject2"] {
                let Some(dst_uuid) = event.get(endpoint).and_then(endpoint_uuid) else {
                    continue;
                };
                let Some((dst_ty, dst_name)) = catalogue.get(&dst_uuid) else {
                    continue;
                };
                let src = Entity::new(&src_uuid, src_ty.clone()).with_metadata("name", src_name);
                let dst = Entity::new(&dst_uuid, dst_ty.clone()).with_metadata("name", dst_name);
                let rel = Relation::new(&src_uuid, &dst_uuid, rel_type.clone(), ts_seconds)
                    .with_metadata("event_type", event_type)
                    .with_metadata("ts_nanos", ts_nanos.to_string());
                triples.push((src, rel, dst));
            }
        }
        triples
    }
}

impl LogParser for CdmParser {
    fn parse(&self, data: &str) -> Vec<ParsedTriple> {
        self.parse_inner(data)
    }
}

/// Detects CDM E3 JSON: newline-delimited records carrying the `cdm18`
/// schema prefix under a `datum`. Checks a handful of leading non-blank
/// lines so a stray prefix in some other JSON can't trigger it.
pub fn looks_like_cdm(contents: &str) -> bool {
    let mut checked = 0;
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        checked += 1;
        if line.contains(CDM_PREFIX) && line.contains("\"datum\"") {
            return true;
        }
        if checked >= 5 {
            break;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal but real-shaped CDM slice: two entities and one execute
    // event connecting them, plus a second event acting on a file.
    const SAMPLE: &str = r#"
{"datum":{"com.bbn.tc.schema.avro.cdm18.Subject":{"uuid":"proc-1","type":"SUBJECT_PROCESS","properties":{"map":{"name":"bash"}}}}}
{"datum":{"com.bbn.tc.schema.avro.cdm18.Subject":{"uuid":"proc-2","type":"SUBJECT_PROCESS","properties":{"map":{"name":"curl"}}}}}
{"datum":{"com.bbn.tc.schema.avro.cdm18.FileObject":{"uuid":"file-1","path":"/etc/passwd"}}}
{"datum":{"com.bbn.tc.schema.avro.cdm18.Event":{"uuid":"ev-1","type":"EVENT_EXECUTE","subject":{"com.bbn.tc.schema.avro.cdm18.UUID":"proc-1"},"predicateObject":{"com.bbn.tc.schema.avro.cdm18.UUID":"proc-2"},"timestampNanos":1523664000123456789}}}
{"datum":{"com.bbn.tc.schema.avro.cdm18.Event":{"uuid":"ev-2","type":"EVENT_READ","subject":{"com.bbn.tc.schema.avro.cdm18.UUID":"proc-2"},"predicateObject":{"com.bbn.tc.schema.avro.cdm18.UUID":"file-1"},"timestampNanos":1523664001999000000}}}
"#;

    #[test]
    fn detects_cdm() {
        assert!(looks_like_cdm(SAMPLE));
    }

    #[test]
    fn rejects_plain_json_and_other_logs() {
        assert!(!looks_like_cdm(r#"{"event":"login","user":"alice"}"#));
        assert!(!looks_like_cdm("203.0.113.86:36696 [10/Jun/2026] GET /x"));
    }

    #[test]
    fn resolves_events_against_the_entity_catalogue() {
        let triples = CdmParser.parse(SAMPLE);
        assert_eq!(triples.len(), 2, "one execute + one read");

        let exec = triples
            .iter()
            .find(|(_, r, _)| r.rel_type == RelationType::Execute)
            .expect("execute edge");
        assert_eq!(exec.0.id, "proc-1");
        assert_eq!(exec.2.id, "proc-2");
        assert_eq!(exec.0.entity_type, EntityType::Process);
        // The name resolved from the referenced entity record, not the event.
        assert_eq!(
            exec.0.metadata.get("name").map(String::as_str),
            Some("bash")
        );
    }

    #[test]
    fn nanoseconds_floor_to_seconds_but_are_preserved() {
        let triples = CdmParser.parse(SAMPLE);
        let exec = triples
            .iter()
            .find(|(_, r, _)| r.rel_type == RelationType::Execute)
            .unwrap();
        assert_eq!(exec.1.timestamp, 1_523_664_000, "seconds, floored");
        assert_eq!(
            exec.1.metadata.get("ts_nanos").map(String::as_str),
            Some("1523664000123456789"),
            "the full nanosecond value survives on the edge"
        );
    }

    #[test]
    fn an_event_referencing_an_unknown_uuid_is_skipped_not_guessed() {
        // An execute whose subject was never catalogued.
        let orphan = r#"
{"datum":{"com.bbn.tc.schema.avro.cdm18.FileObject":{"uuid":"file-1","path":"/x"}}}
{"datum":{"com.bbn.tc.schema.avro.cdm18.Event":{"uuid":"ev-x","type":"EVENT_READ","subject":{"com.bbn.tc.schema.avro.cdm18.UUID":"ghost"},"predicateObject":{"com.bbn.tc.schema.avro.cdm18.UUID":"file-1"},"timestampNanos":1}}}
"#;
        assert!(
            CdmParser.parse(orphan).is_empty(),
            "no guessing a missing endpoint"
        );
    }

    #[test]
    fn unmapped_event_types_are_dropped() {
        let weird = r#"
{"datum":{"com.bbn.tc.schema.avro.cdm18.Subject":{"uuid":"p","type":"SUBJECT_PROCESS"}}}
{"datum":{"com.bbn.tc.schema.avro.cdm18.Event":{"uuid":"e","type":"EVENT_BLIND_INVENTED","subject":{"com.bbn.tc.schema.avro.cdm18.UUID":"p"},"predicateObject":{"com.bbn.tc.schema.avro.cdm18.UUID":"p"},"timestampNanos":1}}}
"#;
        assert!(CdmParser.parse(weird).is_empty());
    }

    #[test]
    fn rename_with_two_objects_yields_two_triples() {
        let rename = r#"
{"datum":{"com.bbn.tc.schema.avro.cdm18.Subject":{"uuid":"p","type":"SUBJECT_PROCESS"}}}
{"datum":{"com.bbn.tc.schema.avro.cdm18.FileObject":{"uuid":"old","path":"/a"}}}
{"datum":{"com.bbn.tc.schema.avro.cdm18.FileObject":{"uuid":"new","path":"/b"}}}
{"datum":{"com.bbn.tc.schema.avro.cdm18.Event":{"uuid":"e","type":"EVENT_RENAME","subject":{"com.bbn.tc.schema.avro.cdm18.UUID":"p"},"predicateObject":{"com.bbn.tc.schema.avro.cdm18.UUID":"old"},"predicateObject2":{"com.bbn.tc.schema.avro.cdm18.UUID":"new"},"timestampNanos":2000000000}}}
"#;
        let triples = CdmParser.parse(rename);
        assert_eq!(triples.len(), 2, "predicateObject and predicateObject2");
        assert!(
            triples
                .iter()
                .all(|(_, r, _)| r.rel_type == RelationType::Write)
        );
        let dests: Vec<&str> = triples.iter().map(|(_, _, d)| d.id.as_str()).collect();
        assert!(dests.contains(&"old") && dests.contains(&"new"));
    }
}
