//! M6.c integration check: the [`FieldRoleClassifier`] seam must
//! actually flow into [`preview_fields_from_events_with_classifier`]'s
//! output, but only on field names the heuristic doesn't already
//! recognize. The canonical-name path stays authoritative — we don't
//! want a wobbly classifier to overrule the analyst-curated catalog.

use std::sync::Arc;

use graph_hunter_core::field_preview::{
    ClassifierVote, FieldRole, FieldRoleClassifier, preview_fields_from_events,
    preview_fields_from_events_with_classifier,
};
use graph_hunter_core::field_preview::{FieldConfig, FieldMapping};
use graph_hunter_core::mapping_library::{
    MappingLibraryClassifier, MappingLibraryStore, PublishSource, PublishedMapping,
};
use serde_json::json;

struct StubClassifier {
    role: FieldRole,
    entity_type: Option<String>,
    confidence: f32,
}

impl FieldRoleClassifier for StubClassifier {
    fn classify(&self, _name: &str, _samples: &[String]) -> Option<ClassifierVote> {
        Some(ClassifierVote {
            role: self.role.clone(),
            entity_type: self.entity_type.clone(),
            confidence: self.confidence,
        })
    }
}

fn events() -> Vec<serde_json::Value> {
    vec![json!({
        "User": "alice",
        "ev_actor": "svc-bot",
        "Image": "cmd.exe"
    })]
}

#[test]
fn classifier_overrides_metadata_for_unknown_name_when_confidence_high() {
    let stub = StubClassifier {
        role: FieldRole::Node,
        entity_type: Some("ServiceAccount".into()),
        confidence: 0.9,
    };
    let fields = preview_fields_from_events_with_classifier(&events(), Some(&stub));
    let ev_actor = fields.iter().find(|f| f.raw_name == "ev_actor").unwrap();
    assert_eq!(ev_actor.current_role, FieldRole::Node);
    assert_eq!(
        ev_actor.suggested_entity_type.as_deref(),
        Some("ServiceAccount")
    );
    assert_eq!(ev_actor.suggestion_source.as_deref(), Some("classifier"));
}

#[test]
fn classifier_does_not_override_canonical_known_field() {
    // `User` is a canonical-known field. Even with a contradictory
    // high-confidence vote, the heuristic must win.
    let stub = StubClassifier {
        role: FieldRole::Metadata,
        entity_type: None,
        confidence: 0.99,
    };
    let fields = preview_fields_from_events_with_classifier(&events(), Some(&stub));
    let user = fields.iter().find(|f| f.raw_name == "User").unwrap();
    assert_eq!(user.current_role, FieldRole::Node);
}

#[test]
fn low_confidence_vote_is_ignored() {
    let stub = StubClassifier {
        role: FieldRole::Node,
        entity_type: Some("Bogus".into()),
        confidence: 0.3, // below 0.6 threshold
    };
    let fields = preview_fields_from_events_with_classifier(&events(), Some(&stub));
    let ev_actor = fields.iter().find(|f| f.raw_name == "ev_actor").unwrap();
    assert_eq!(ev_actor.current_role, FieldRole::Metadata);
    assert!(
        ev_actor.suggestion_source.as_deref() != Some("classifier"),
        "low-confidence vote should not have been adopted"
    );
}

#[test]
fn legacy_signature_is_unchanged_when_no_classifier() {
    // Same input, both signatures, both should agree.
    let a = preview_fields_from_events(&events());
    let b = preview_fields_from_events_with_classifier(&events(), None);
    assert_eq!(a.len(), b.len());
    for (x, y) in a.iter().zip(b.iter()) {
        assert_eq!(x.raw_name, y.raw_name);
        assert_eq!(x.current_role, y.current_role);
        assert_eq!(x.suggested_entity_type, y.suggested_entity_type);
        assert_eq!(x.suggestion_source, y.suggestion_source);
    }
}

#[test]
fn library_classifier_votes_from_prior_approval() {
    // End-to-end sanity: publish a mapping that classifies `ev_actor`
    // as a ServiceAccount node, then verify the preview adopts the
    // vote on a fresh sample.
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MappingLibraryStore::open(dir.path()).unwrap());
    store
        .publish(PublishedMapping {
            mapping_id: String::new(),
            fingerprint: String::new(),
            field_config: FieldConfig {
                mappings: vec![FieldMapping {
                    raw_name: "ev_actor".into(),
                    role: FieldRole::Node,
                    entity_type: Some("ServiceAccount".into()),
                    timestamp_format: None,
                    locale: None,
                }],
            },
            vrl_source: None,
            mapping_hash: None,
            ocsf_category: None,
            source: PublishSource::IngestNegotiator,
            origin_draft_id: None,
            published_at: 1,
        })
        .unwrap();

    let classifier = MappingLibraryClassifier::new(Arc::clone(&store));
    let fields = preview_fields_from_events_with_classifier(&events(), Some(&classifier));
    let ev_actor = fields.iter().find(|f| f.raw_name == "ev_actor").unwrap();
    assert_eq!(ev_actor.current_role, FieldRole::Node);
    assert_eq!(
        ev_actor.suggested_entity_type.as_deref(),
        Some("ServiceAccount")
    );
}
