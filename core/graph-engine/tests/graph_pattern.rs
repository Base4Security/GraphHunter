//! Integration tests for temporal pattern matching in `GraphHunter`.
//!
//! These exercise the core DFS search via the public API. Kept here (not
//! in `src/graph.rs`) so a refactor of the internals can't accidentally
//! bypass the public contract. Mirrors the structure of
//! `tests/spill_streaming.rs`.

use graph_hunter_core::{
    Entity, EntityType, GraphHunter, Hypothesis, HypothesisStep, Relation, RelationType,
};

/// Convert a HuntResult path (Vec<Arc<str>>) to Vec<&str> for cheap
/// `assert_eq!(..., vec!["literal"])` test assertions.
fn path_strs(p: &[std::sync::Arc<str>]) -> Vec<&str> {
    p.iter().map(|s| &**s).collect()
}

/// Minimal builder: adds entities then edges, returns the graph.
/// Panics on any add_entity / add_relation error — tests should assert
/// on search results, not on construction plumbing.
fn build_graph(
    entities: &[(&str, EntityType)],
    edges: &[(&str, &str, RelationType, i64)],
) -> GraphHunter {
    let mut g = GraphHunter::new();
    for (id, et) in entities {
        g.add_entity(Entity::new(*id, et.clone()))
            .unwrap_or_else(|e| panic!("add_entity({id}) failed: {e:?}"));
    }
    for (src, dst, rel, ts) in edges {
        g.add_relation(Relation::new(*src, *dst, rel.clone(), *ts))
            .unwrap_or_else(|e| panic!("add_relation({src}->{dst}) failed: {e:?}"));
    }
    g
}

fn hyp(steps: &[(EntityType, RelationType, EntityType)]) -> Hypothesis {
    let mut h = Hypothesis::new("test");
    for (o, r, d) in steps {
        h = h.add_step(HypothesisStep::new(o.clone(), r.clone(), d.clone()));
    }
    h
}

#[test]
fn linear_path_single_match() {
    // IP -[Connect]-> Host -[Auth]-> User
    let g = build_graph(
        &[
            ("1.2.3.4", EntityType::IP),
            ("server-01", EntityType::Host),
            ("alice", EntityType::User),
        ],
        &[
            ("1.2.3.4", "server-01", RelationType::Connect, 100),
            ("server-01", "alice", RelationType::Auth, 200),
        ],
    );

    let h = hyp(&[
        (EntityType::IP, RelationType::Connect, EntityType::Host),
        (EntityType::Host, RelationType::Auth, EntityType::User),
    ]);

    let (paths, truncated) = g.search_temporal_pattern(&h, None, None).unwrap();
    assert!(!truncated);
    assert_eq!(paths.len(), 1);
    assert_eq!(path_strs(&paths[0]), vec!["1.2.3.4", "server-01", "alice"]);
}

#[test]
fn branching_paths_yield_all_combinations() {
    // One IP connects to two hosts; each host auths two users.
    // Expected paths: 2 × 2 = 4.
    let g = build_graph(
        &[
            ("10.0.0.1", EntityType::IP),
            ("host-a", EntityType::Host),
            ("host-b", EntityType::Host),
            ("user1", EntityType::User),
            ("user2", EntityType::User),
            ("user3", EntityType::User),
            ("user4", EntityType::User),
        ],
        &[
            ("10.0.0.1", "host-a", RelationType::Connect, 10),
            ("10.0.0.1", "host-b", RelationType::Connect, 20),
            ("host-a", "user1", RelationType::Auth, 30),
            ("host-a", "user2", RelationType::Auth, 40),
            ("host-b", "user3", RelationType::Auth, 50),
            ("host-b", "user4", RelationType::Auth, 60),
        ],
    );

    let h = hyp(&[
        (EntityType::IP, RelationType::Connect, EntityType::Host),
        (EntityType::Host, RelationType::Auth, EntityType::User),
    ]);

    let (paths, _) = g.search_temporal_pattern(&h, None, None).unwrap();
    assert_eq!(
        paths.len(),
        4,
        "expected 4 paths, got {}: {:?}",
        paths.len(),
        paths
    );
}

#[test]
fn temporal_ordering_enforced_by_default() {
    // If the Auth edge is BEFORE the Connect edge, the path must not match
    // because the search enforces causal monotonicity (ts[i+1] >= ts[i]).
    let g = build_graph(
        &[
            ("ip-1", EntityType::IP),
            ("host-1", EntityType::Host),
            ("user-1", EntityType::User),
        ],
        &[
            ("ip-1", "host-1", RelationType::Connect, 500),
            ("host-1", "user-1", RelationType::Auth, 100), // BEFORE
        ],
    );

    let h = hyp(&[
        (EntityType::IP, RelationType::Connect, EntityType::Host),
        (EntityType::Host, RelationType::Auth, EntityType::User),
    ]);

    let (paths, _) = g.search_temporal_pattern(&h, None, None).unwrap();
    assert!(
        paths.is_empty(),
        "out-of-order timestamps must yield no matches; got {paths:?}"
    );
}

#[test]
fn time_window_filters_paths() {
    // Two candidate paths, one inside the window, one outside.
    let g = build_graph(
        &[
            ("a", EntityType::IP),
            ("h1", EntityType::Host),
            ("h2", EntityType::Host),
            ("u1", EntityType::User),
            ("u2", EntityType::User),
        ],
        &[
            ("a", "h1", RelationType::Connect, 100),
            ("h1", "u1", RelationType::Auth, 200), // inside [0, 1000]
            ("a", "h2", RelationType::Connect, 5_000),
            ("h2", "u2", RelationType::Auth, 6_000), // outside
        ],
    );

    let h = hyp(&[
        (EntityType::IP, RelationType::Connect, EntityType::Host),
        (EntityType::Host, RelationType::Auth, EntityType::User),
    ]);

    let (paths, _) = g
        .search_temporal_pattern(&h, Some((0, 1_000)), None)
        .unwrap();
    assert_eq!(paths.len(), 1);
    assert_eq!(path_strs(&paths[0]), vec!["a", "h1", "u1"]);
}

#[test]
fn wildcards_match_any_type() {
    // Pattern: Any -[Any]-> Any -[Any]-> Any should match every 3-node path.
    let g = build_graph(
        &[
            ("ip-a", EntityType::IP),
            ("proc-b", EntityType::Process),
            ("file-c", EntityType::File),
        ],
        &[
            ("ip-a", "proc-b", RelationType::Connect, 1),
            ("proc-b", "file-c", RelationType::Write, 2),
        ],
    );

    let h = hyp(&[
        (EntityType::Any, RelationType::Any, EntityType::Any),
        (EntityType::Any, RelationType::Any, EntityType::Any),
    ]);

    let (paths, _) = g.search_temporal_pattern(&h, None, None).unwrap();
    assert_eq!(paths.len(), 1);
    assert_eq!(path_strs(&paths[0]), vec!["ip-a", "proc-b", "file-c"]);
}

#[test]
fn max_results_truncates_and_flags() {
    // Two sources, each reaches two hosts → 4 paths total.
    // Cap to 2 and verify truncated=true.
    let g = build_graph(
        &[
            ("src1", EntityType::IP),
            ("src2", EntityType::IP),
            ("h1", EntityType::Host),
            ("h2", EntityType::Host),
        ],
        &[
            ("src1", "h1", RelationType::Connect, 1),
            ("src1", "h2", RelationType::Connect, 2),
            ("src2", "h1", RelationType::Connect, 3),
            ("src2", "h2", RelationType::Connect, 4),
        ],
    );

    let h = hyp(&[(EntityType::IP, RelationType::Connect, EntityType::Host)]);

    let (paths, truncated) = g.search_temporal_pattern(&h, None, Some(2)).unwrap();
    assert_eq!(paths.len(), 2);
    assert!(
        truncated,
        "expected truncated=true when results hit the cap"
    );
}

#[test]
fn k_simplicity_default_prevents_revisit() {
    // Cycle A → B → A via two Connect edges. Default k_simplicity=1
    // (simple path) must reject paths that revisit A.
    let g = build_graph(
        &[("A", EntityType::Host), ("B", EntityType::Host)],
        &[
            ("A", "B", RelationType::Connect, 1),
            ("B", "A", RelationType::Connect, 2),
        ],
    );

    let h = hyp(&[
        (EntityType::Host, RelationType::Connect, EntityType::Host),
        (EntityType::Host, RelationType::Connect, EntityType::Host),
    ]);

    let (paths, _) = g.search_temporal_pattern(&h, None, None).unwrap();
    for p in &paths {
        assert_ne!(
            p[0], p[2],
            "simple-path mode must not revisit vertex A: {p:?}"
        );
    }
}

#[test]
fn empty_hypothesis_is_rejected() {
    let g = GraphHunter::new();
    let h = Hypothesis::new("empty"); // no steps
    let err = g.search_temporal_pattern(&h, None, None).unwrap_err();
    // Any error is acceptable; the point is we don't return a successful
    // empty-result panic or OOB panic. Format it for readability on failure.
    let _ = format!("{err:?}");
}

#[test]
fn entity_type_other_matches_exact_name() {
    // Custom-typed entities (from DSL `Foo` renames). The DSL parser accepts
    // unknown names as `EntityType::Other("Foo")`; the graph must match them
    // by exact string equality.
    let g = build_graph(
        &[
            ("widget-1", EntityType::Other("Widget".to_string())),
            ("widget-2", EntityType::Other("Widget".to_string())),
            ("gadget-1", EntityType::Other("Gadget".to_string())),
        ],
        &[
            ("widget-1", "widget-2", RelationType::Connect, 1),
            ("widget-1", "gadget-1", RelationType::Connect, 2),
        ],
    );

    let h = hyp(&[(
        EntityType::Other("Widget".to_string()),
        RelationType::Connect,
        EntityType::Other("Widget".to_string()),
    )]);

    let (paths, _) = g.search_temporal_pattern(&h, None, None).unwrap();
    assert_eq!(
        paths.len(),
        1,
        "Other(Widget)->Other(Widget) should match exactly 1 path"
    );
    assert_eq!(path_strs(&paths[0]), vec!["widget-1", "widget-2"]);
}

#[test]
fn empty_graph_yields_no_paths() {
    let g = GraphHunter::new();
    let h = hyp(&[(EntityType::IP, RelationType::Connect, EntityType::Host)]);
    let (paths, truncated) = g.search_temporal_pattern(&h, None, None).unwrap();
    assert!(paths.is_empty());
    assert!(!truncated);
}
