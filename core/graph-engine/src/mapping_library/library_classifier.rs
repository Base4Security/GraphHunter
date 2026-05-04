//! M6 reference [`FieldRoleClassifier`] backed by approved library
//! entries.
//!
//! For any field name the analyst has already classified in a prior
//! approved mapping, we vote with the majority role/entity-type seen
//! there. This is the "weak supervision" baseline the plan calls out:
//! we don't need a fine-tuned model for the field names users keep
//! re-encountering — the library already encodes their preference.
//!
//! Confidence policy. We treat the library as evidence, not authority:
//!   * 1 prior observation → 0.6 confidence (just clears the bar).
//!   * 2 prior observations → 0.75.
//!   * 3+ prior observations → 0.9 (caps to leave room for a future
//!     ML classifier whose 0.95+ should always win).
//! When prior observations disagree (split vote), confidence is scaled
//! down by the agreement ratio so a tied 1-vs-1 falls below the bar.
//!
//! The classifier is read-only and stateless beyond the `Arc<Store>`
//! handle, so it's cheap to construct and safe to share across the
//! preview pipeline.

use std::collections::HashMap;
use std::sync::Arc;

use crate::field_preview::{ClassifierVote, FieldRole, FieldRoleClassifier};
use crate::mapping_library::MappingLibraryStore;

/// Reads from a [`MappingLibraryStore`] each call. Cheap because the
/// library is small (human-gated). If it ever grows past a few thousand
/// entries we can cache an inverted index inside the struct without
/// touching the trait surface.
pub struct MappingLibraryClassifier {
    store: Arc<MappingLibraryStore>,
}

impl MappingLibraryClassifier {
    pub fn new(store: Arc<MappingLibraryStore>) -> Self {
        Self { store }
    }
}

impl FieldRoleClassifier for MappingLibraryClassifier {
    fn classify(&self, raw_name: &str, _sample_values: &[String]) -> Option<ClassifierVote> {
        let entries = self.store.list().ok()?;
        let lname = raw_name.to_ascii_lowercase();

        // Tally (role, entity_type) votes from every prior mapping that
        // contained a field with this name (case-insensitive).
        let mut votes: HashMap<(String, Option<String>), usize> = HashMap::new();
        let mut total = 0usize;
        for entry in entries {
            for m in entry.field_config.mappings {
                if m.raw_name.to_ascii_lowercase() == lname {
                    let key = (role_tag(&m.role).to_string(), m.entity_type.clone());
                    *votes.entry(key).or_insert(0) += 1;
                    total += 1;
                }
            }
        }

        if total == 0 {
            return None;
        }

        let ((role_tag, entity_type), winning_count) = votes.into_iter().max_by_key(|&(_, n)| n)?;
        let role = role_from_tag(&role_tag);
        let agreement = winning_count as f32 / total as f32;
        let base = match winning_count {
            1 => 0.60,
            2 => 0.75,
            _ => 0.90,
        };
        let confidence = (base * agreement).clamp(0.0, 0.99);

        Some(ClassifierVote {
            role,
            entity_type,
            confidence,
        })
    }
}

fn role_tag(r: &FieldRole) -> &'static str {
    match r {
        FieldRole::Node => "node",
        FieldRole::Metadata => "metadata",
        FieldRole::Ignore => "ignore",
    }
}

fn role_from_tag(t: &str) -> FieldRole {
    match t {
        "node" => FieldRole::Node,
        "ignore" => FieldRole::Ignore,
        _ => FieldRole::Metadata,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field_preview::{FieldConfig, FieldMapping, FieldRole};
    use crate::mapping_library::{PublishSource, PublishedMapping};

    fn cfg(rows: &[(&str, FieldRole, Option<&str>)]) -> FieldConfig {
        FieldConfig {
            mappings: rows
                .iter()
                .map(|(n, r, et)| FieldMapping {
                    raw_name: (*n).into(),
                    role: r.clone(),
                    entity_type: et.map(|s| s.into()),
                    timestamp_format: None,
                    locale: None,
                })
                .collect(),
        }
    }

    fn publish(store: &MappingLibraryStore, rows: &[(&str, FieldRole, Option<&str>)], at: i64) {
        store
            .publish(PublishedMapping {
                mapping_id: String::new(),
                fingerprint: String::new(),
                field_config: cfg(rows),
                vrl_source: None,
                mapping_hash: None,
                ocsf_category: None,
                source: PublishSource::IngestNegotiator,
                origin_draft_id: None,
                published_at: at,
            })
            .unwrap();
    }

    #[test]
    fn returns_none_when_field_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MappingLibraryStore::open(dir.path()).unwrap());
        publish(&store, &[("User", FieldRole::Node, Some("User"))], 1);
        let c = MappingLibraryClassifier::new(store);
        assert!(c.classify("nothing_here", &[]).is_none());
    }

    #[test]
    fn single_observation_clears_minimum_confidence() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MappingLibraryStore::open(dir.path()).unwrap());
        publish(&store, &[("Image", FieldRole::Node, Some("Process"))], 1);
        let c = MappingLibraryClassifier::new(store);
        let v = c.classify("image", &[]).expect("should vote");
        assert_eq!(v.role, FieldRole::Node);
        assert_eq!(v.entity_type.as_deref(), Some("Process"));
        assert!(
            v.confidence >= 0.60 && v.confidence < 0.61,
            "got: {}",
            v.confidence
        );
    }

    #[test]
    fn three_consistent_observations_bump_confidence() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MappingLibraryStore::open(dir.path()).unwrap());
        for at in 1..=3 {
            publish(&store, &[("Image", FieldRole::Node, Some("Process"))], at);
        }
        let c = MappingLibraryClassifier::new(store);
        let v = c.classify("Image", &[]).unwrap();
        assert!(v.confidence > 0.85, "got: {}", v.confidence);
    }

    #[test]
    fn split_vote_drags_confidence_below_bar() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MappingLibraryStore::open(dir.path()).unwrap());
        publish(&store, &[("Hashes", FieldRole::Node, Some("FileHash"))], 1);
        publish(&store, &[("Hashes", FieldRole::Metadata, None)], 2);
        let c = MappingLibraryClassifier::new(store);
        let v = c.classify("Hashes", &[]).unwrap();
        // 1 of 2 votes for the winning class; agreement = 0.5; base = 0.6
        // → 0.30 confidence, well below the 0.6 bar enforced by the
        // preview pipeline.
        assert!(v.confidence < 0.5, "got: {}", v.confidence);
    }
}
