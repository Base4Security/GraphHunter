//! Integration tests for 3.A: DSL metadata predicates parsing + evaluation.
//! Covers the single concrete example from the post-hunt feedback:
//! `User -[Auth {status="Failure"}]-> IP` must filter out successes.

use graph_hunter_core::{Entity, EntityType, GraphHunter, Relation, RelationType, parse_dsl};

fn path_strs(p: &[std::sync::Arc<str>]) -> Vec<&str> {
    p.iter().map(|s| &**s).collect()
}

fn graph_with_auth() -> GraphHunter {
    let mut g = GraphHunter::new();
    for id in ["alice", "1.2.3.4", "5.6.7.8"] {
        let et = if id == "alice" {
            EntityType::User
        } else {
            EntityType::IP
        };
        g.add_entity(Entity::new(id, et)).unwrap();
    }
    g.add_relation(
        Relation::new("alice", "1.2.3.4", RelationType::Auth, 100)
            .with_metadata("status", "Failure"),
    )
    .unwrap();
    g.add_relation(
        Relation::new("alice", "1.2.3.4", RelationType::Auth, 200)
            .with_metadata("status", "Success"),
    )
    .unwrap();
    g.add_relation(
        Relation::new("alice", "5.6.7.8", RelationType::Auth, 300)
            .with_metadata("status", "Failure")
            .with_metadata("app", "Azure Active Directory PowerShell"),
    )
    .unwrap();
    g
}

#[test]
fn parse_rejects_none_predicate_is_unchanged() {
    // Sanity: predicates are opt-in; old patterns parse identically.
    let r = parse_dsl("User -[Auth]-> IP", None).unwrap();
    assert_eq!(r.hypothesis.steps.len(), 1);
    assert!(r.hypothesis.steps[0].edge_predicates.is_empty());
}

#[test]
fn parse_eq_predicate() {
    let r = parse_dsl(r#"User -[Auth {status="Failure"}]-> IP"#, None).unwrap();
    assert_eq!(r.hypothesis.steps[0].edge_predicates.len(), 1);
    let formatted = r.formatted;
    assert!(formatted.contains(r#"status="Failure""#), "got {formatted}");
}

#[test]
fn parse_multiple_predicates() {
    let r = parse_dsl(
        r#"User -[Auth {status="Failure", app~"PowerShell"}]-> IP"#,
        None,
    )
    .unwrap();
    assert_eq!(r.hypothesis.steps[0].edge_predicates.len(), 2);
}

#[test]
fn parse_in_list_predicate() {
    let r = parse_dsl(
        r#"Host -[Connect {remote_port in ["443","8443"]}]-> IP"#,
        None,
    )
    .unwrap();
    assert_eq!(r.hypothesis.steps[0].edge_predicates.len(), 1);
}

#[test]
fn engine_filters_by_eq_predicate() {
    // Integration: end-to-end parse + search. Only the two Failure edges
    // must produce paths; the Success edge must not.
    let g = graph_with_auth();
    let h = parse_dsl(r#"User -[Auth {status="Failure"}]-> IP"#, None)
        .unwrap()
        .hypothesis;
    let (paths, _) = g.search_temporal_pattern(&h, None, None).unwrap();
    // Two Failure edges → two raw paths (one per edge to 1.2.3.4 with Failure,
    // one to 5.6.7.8 with Failure). The Success edge is filtered out.
    assert_eq!(paths.len(), 2);
}

#[test]
fn engine_filters_by_substring_match() {
    let g = graph_with_auth();
    let h = parse_dsl(r#"User -[Auth {app~"PowerShell"}]-> IP"#, None)
        .unwrap()
        .hypothesis;
    let (paths, _) = g.search_temporal_pattern(&h, None, None).unwrap();
    // Only the edge carrying app="...PowerShell" should match.
    assert_eq!(paths.len(), 1);
    assert_eq!(path_strs(&paths[0]), vec!["alice", "5.6.7.8"]);
}

#[test]
fn engine_filters_by_not_in_list() {
    let g = graph_with_auth();
    let h = parse_dsl(r#"User -[Auth {status not in ["Success"]}]-> IP"#, None)
        .unwrap()
        .hypothesis;
    let (paths, _) = g.search_temporal_pattern(&h, None, None).unwrap();
    assert_eq!(paths.len(), 2); // 2 Failures
}

#[test]
fn dsl_accepts_other_relation_types_for_cloud_patterns() {
    // Post-hunt B.1 catalog entries use rel types like Consent, Assign,
    // Create that are not in the built-in enum. The DSL parser must
    // accept them as `RelationType::Other(_)` rather than failing.
    let r = parse_dsl("User -[Consent]-> OAuthApp", None).unwrap();
    assert_eq!(r.hypothesis.steps.len(), 1);
    // Round-trip: Display string preserves the name.
    assert_eq!(
        format!("{}", r.hypothesis.steps[0].relation_type),
        "Consent"
    );
    // And formatted back into DSL retains the form.
    assert!(r.formatted.contains("-[Consent]->"), "got {}", r.formatted);
}

#[test]
fn engine_empty_metadata_does_not_match_positive_predicate() {
    // Regression check: if an edge has no metadata at all, positive
    // predicates (Eq, Match, In) must fail — not silently pass.
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("a", EntityType::User)).unwrap();
    g.add_entity(Entity::new("b", EntityType::IP)).unwrap();
    g.add_relation(Relation::new("a", "b", RelationType::Auth, 100))
        .unwrap();

    let h = parse_dsl(r#"User -[Auth {status="Failure"}]-> IP"#, None)
        .unwrap()
        .hypothesis;
    let (paths, _) = g.search_temporal_pattern(&h, None, None).unwrap();
    assert_eq!(paths.len(), 0);
}
