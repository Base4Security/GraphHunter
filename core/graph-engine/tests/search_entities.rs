//! Integration tests for `GraphHunter::search_entities`, covering the
//! list-mode behavior on empty queries introduced alongside the HTTP
//! validation fix. The engine itself stays permissive (lists everything
//! when `q` is empty); callers (Tauri command + HTTP handler) enforce
//! the "q or type_filter required" policy.

use graph_hunter_core::{Entity, EntityType, GraphHunter};

fn graph_with(entities: &[(&str, EntityType, f64)]) -> GraphHunter {
    let mut g = GraphHunter::new();
    for (id, et, score) in entities {
        g.add_entity(Entity::with_score(*id, et.clone(), *score))
            .unwrap();
    }
    g
}

#[test]
fn empty_query_with_type_returns_top_n_by_score() {
    // Three Host entities with distinct scores. List-mode should order by
    // score desc; limit truncates after the sort so we get the two best,
    // not an arbitrary HashMap-order pair.
    let g = graph_with(&[
        ("host-a", EntityType::Host, 10.0),
        ("host-b", EntityType::Host, 50.0),
        ("host-c", EntityType::Host, 30.0),
        // A non-Host that must be excluded by the type filter.
        ("alice", EntityType::User, 999.0),
    ]);

    let results = g.search_entities("", Some(&EntityType::Host), 2);
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].id, "host-b");
    assert_eq!(results[0].score, 50.0);
    assert_eq!(results[1].id, "host-c");
    // User with score 999 must not leak in despite its high score.
    assert!(results.iter().all(|r| r.entity_type == "Host"));
}

#[test]
fn empty_query_without_type_returns_top_n_globally() {
    // Engine stays permissive; policy is enforced at the caller layer.
    // Here we just assert the sort order is by score desc across all types.
    let g = graph_with(&[
        ("host-a", EntityType::Host, 10.0),
        ("alice", EntityType::User, 50.0),
        ("1.2.3.4", EntityType::IP, 30.0),
    ]);

    let results = g.search_entities("", None, 10);
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].id, "alice");
    assert_eq!(results[1].id, "1.2.3.4");
    assert_eq!(results[2].id, "host-a");
}

#[test]
fn nonempty_query_still_substring_matches() {
    // Preservation check: the existing substring-match path must keep
    // working unchanged for real queries.
    let g = graph_with(&[
        ("host-alpha", EntityType::Host, 10.0),
        ("host-beta", EntityType::Host, 50.0),
        ("server-01", EntityType::Host, 99.0),
    ]);

    let results = g.search_entities("host", Some(&EntityType::Host), 10);
    let ids: Vec<&str> = results.iter().map(|r| r.id.as_str()).collect();
    assert!(ids.contains(&"host-alpha"));
    assert!(ids.contains(&"host-beta"));
    assert!(!ids.contains(&"server-01"));
}

#[test]
fn unknown_type_filter_returns_empty() {
    // When the type doesn't exist in the graph, list-mode must not fall
    // back to "all entities" — return an empty result so callers can
    // distinguish "no such type" from "type exists but has no members".
    let g = graph_with(&[("host-a", EntityType::Host, 10.0)]);
    let results = g.search_entities("", Some(&EntityType::File), 10);
    assert!(results.is_empty());
}

#[test]
fn query_is_case_insensitive() {
    let g = graph_with(&[("Host-UPPER", EntityType::Host, 10.0)]);
    let results = g.search_entities("UPPER", None, 10);
    assert_eq!(results.len(), 1);
    let results_lower = g.search_entities("upper", None, 10);
    assert_eq!(results_lower.len(), 1);
}
