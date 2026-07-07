//! Regression tests for the predicate-aware `hunt_diagnostic` path added
//! after a real hunt: `User -[Auth {risk_tag="anonymizing"}]-> IP` returned
//! zero paths with the generic "temporal ordering or k-simplicity" reason,
//! when the true cause was that `risk_tag` is never populated. The
//! diagnostic must name the missing key and advise fixing the ingest
//! pipeline rather than the DSL.

use graph_hunter_core::{Entity, EntityType, GraphHunter, Relation, RelationType, parse_dsl};

fn auth_graph() -> GraphHunter {
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("alice", EntityType::User))
        .unwrap();
    g.add_entity(Entity::new("1.2.3.4", EntityType::IP))
        .unwrap();
    g.add_relation(
        Relation::new("alice", "1.2.3.4", RelationType::Auth, 100)
            .with_metadata("status", "Success")
            .with_metadata("app", "Browser"),
    )
    .unwrap();
    g
}

#[test]
fn diagnostic_names_missing_key_for_positive_predicate() {
    // The dataset has `status` and `app` on every Auth edge, but no
    // `risk_tag`. cat-019's pattern asks for `risk_tag="anonymizing"`.
    let g = auth_graph();
    let h = parse_dsl(r#"User -[Auth {risk_tag="anonymizing"}]-> IP"#, None)
        .unwrap()
        .hypothesis;
    let d = g.hunt_diagnostic(&h);
    let reason = d.reason;
    assert!(
        reason.contains("risk_tag"),
        "diagnostic must name the missing key, got: {reason}"
    );
    assert!(
        reason.contains("not populated") || reason.contains("not present"),
        "diagnostic must say the field is missing, got: {reason}"
    );
    let suggestion = d
        .suggestion
        .expect("suggestion should be set for predicate failure");
    assert!(
        suggestion.contains("status") && suggestion.contains("app"),
        "suggestion must enumerate observed keys, got: {suggestion}"
    );
}

#[test]
fn diagnostic_reports_value_mismatch_when_key_exists() {
    // `status` is observed on every edge but only with value "Success".
    // A predicate `status="Phishing"` must be flagged as value-mismatch,
    // not as missing-key.
    let g = auth_graph();
    let h = parse_dsl(r#"User -[Auth {status="Phishing"}]-> IP"#, None)
        .unwrap()
        .hypothesis;
    let d = g.hunt_diagnostic(&h);
    assert!(
        d.reason.contains("0/") && d.reason.contains("sampled edges"),
        "diagnostic must report the sample miss rate, got: {}",
        d.reason
    );
}

#[test]
fn diagnostic_does_not_trigger_when_predicate_matches() {
    // When the predicate succeeds but the chain fails for structural
    // reasons, fall back to the generic temporal-ordering hint.
    let mut g = auth_graph();
    g.add_entity(Entity::new("host-a", EntityType::Host))
        .unwrap();
    let h = parse_dsl(
        r#"User -[Auth {status="Success"}]-> IP -[Connect]-> Host"#,
        None,
    )
    .unwrap()
    .hypothesis;
    // IP -> Host doesn't exist at all; the generic path should take over
    // (this is the pre-existing reverse-direction / missing-rel branch).
    let d = g.hunt_diagnostic(&h);
    assert!(
        !d.reason.contains("not populated"),
        "must not claim missing key when the real issue is a missing edge triple, got: {}",
        d.reason
    );
}
