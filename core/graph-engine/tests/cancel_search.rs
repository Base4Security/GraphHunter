//! A cancelled search stops instead of running to completion.
//!
//! The graph is a full bipartite fan (every user authenticates to every
//! host), so an uncancelled `User -[Auth]-> Host` hunt has
//! `USERS * HOSTS` matches. A token cancelled before the search starts
//! must make each DFS variant give up at its first frame.

use graph_hunter_core::cancel::{self, CancelToken};
use graph_hunter_core::{Entity, EntityType, GraphHunter, Relation, RelationType, parse_dsl};

const USERS: usize = 80;
const HOSTS: usize = 40;

fn fan_graph() -> GraphHunter {
    let mut graph = GraphHunter::new();
    for h in 0..HOSTS {
        graph
            .add_entity(Entity::new(format!("host-{h}"), EntityType::Host))
            .unwrap();
    }
    for u in 0..USERS {
        graph
            .add_entity(Entity::new(format!("user-{u}"), EntityType::User))
            .unwrap();
        for h in 0..HOSTS {
            graph
                .add_relation(Relation::new(
                    format!("user-{u}"),
                    format!("host-{h}"),
                    RelationType::Auth,
                    1_700_000_000 + (u * HOSTS + h) as i64,
                ))
                .unwrap();
        }
    }
    graph.sort_edges_by_timestamp().unwrap();
    graph
}

#[test]
fn plain_search_stops_when_cancelled() {
    let graph = fan_graph();
    let hypothesis = parse_dsl("User -[Auth]-> Host", None).unwrap().hypothesis;

    let (all, _) = graph
        .search_temporal_pattern(&hypothesis, None, Some(100_000))
        .unwrap();
    assert_eq!(all.len(), USERS * HOSTS, "baseline: every pair matches");

    let token = CancelToken::new();
    token.cancel();
    let (partial, _) = cancel::scope(&token, || {
        graph.search_temporal_pattern(&hypothesis, None, Some(100_000))
    })
    .unwrap();
    assert!(
        partial.is_empty(),
        "a search cancelled up front must not match anything, got {}",
        partial.len()
    );
}

#[test]
fn anomaly_guided_search_stops_when_cancelled() {
    let mut graph = fan_graph();
    graph.enable_anomaly_scoring(Default::default());
    graph.finalize_anomaly_scorer();
    let hypothesis = parse_dsl("User -[Auth]-> Host", None).unwrap().hypothesis;

    let (all, _) = graph
        .search_temporal_pattern_smart(&hypothesis, None, 100_000)
        .unwrap();
    assert_eq!(all.len(), USERS * HOSTS, "baseline: every pair matches");

    let token = CancelToken::new();
    token.cancel();
    let (partial, _) = cancel::scope(&token, || {
        graph.search_temporal_pattern_smart(&hypothesis, None, 100_000)
    })
    .unwrap();
    assert!(
        partial.is_empty(),
        "a search cancelled up front must not match anything, got {}",
        partial.len()
    );
}

#[test]
fn token_outside_its_scope_does_not_affect_other_searches() {
    let graph = fan_graph();
    let hypothesis = parse_dsl("User -[Auth]-> Host", None).unwrap().hypothesis;

    let token = CancelToken::new();
    token.cancel();
    cancel::scope(&token, || {});

    // The scope ended: this search runs with no token and completes.
    let (all, _) = graph
        .search_temporal_pattern(&hypothesis, None, Some(100_000))
        .unwrap();
    assert_eq!(all.len(), USERS * HOSTS);
}

/// A pattern joined by bindings runs on the tree enumerator, which has no
/// work bound other than the result cap; it has to honour the token too.
#[test]
fn graph_shaped_search_stops_when_cancelled() {
    let graph = fan_graph();
    let hypothesis = parse_dsl("User u -[Auth]-> Host h; User v -[Auth]-> Host h", None)
        .unwrap()
        .hypothesis;

    let (all, _) = graph
        .search_temporal_pattern(&hypothesis, None, Some(500))
        .unwrap();
    assert_eq!(all.len(), 500, "baseline: far more matches than the cap");

    let token = CancelToken::new();
    token.cancel();
    let (partial, _) = cancel::scope(&token, || {
        graph.search_temporal_pattern(&hypothesis, None, Some(500))
    })
    .unwrap();
    assert!(
        partial.is_empty(),
        "a search cancelled up front must not match anything, got {}",
        partial.len()
    );
}
