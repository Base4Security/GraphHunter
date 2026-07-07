//! Integration tests for the zero-path diagnostic introduced in 2.A.
//! Covers the three classes of failure the feedback calls out explicitly:
//! wrong direction, missing rel type, and schema-present-but-chain-fails.

use graph_hunter_core::{
    Entity, EntityType, GraphHunter, Hypothesis, HypothesisStep, Relation, RelationType,
};

fn hyp(steps: &[(EntityType, RelationType, EntityType)]) -> Hypothesis {
    let mut h = Hypothesis::new("test");
    for (o, r, d) in steps {
        h = h.add_step(HypothesisStep::new(o.clone(), r.clone(), d.clone()));
    }
    h
}

fn graph_with(
    entities: &[(&str, EntityType)],
    edges: &[(&str, &str, RelationType, i64)],
) -> GraphHunter {
    let mut g = GraphHunter::new();
    for (id, et) in entities {
        g.add_entity(Entity::new(*id, et.clone())).unwrap();
    }
    for (src, dst, rel, ts) in edges {
        g.add_relation(Relation::new(*src, *dst, rel.clone(), *ts))
            .unwrap();
    }
    g
}

#[test]
fn wrong_direction_suggests_reversal() {
    // Dataset has Host -[Connect]-> IP but analyst authors IP -[Connect]-> Host.
    // Matches the exact example from feedback §1.2.
    let g = graph_with(
        &[("host-a", EntityType::Host), ("1.2.3.4", EntityType::IP)],
        &[("host-a", "1.2.3.4", RelationType::Connect, 100)],
    );
    let h = hyp(&[(EntityType::IP, RelationType::Connect, EntityType::Host)]);
    let d = g.hunt_diagnostic(&h);
    assert_eq!(d.failed_step_index, 0);
    let s = d
        .suggestion
        .expect("suggestion should be set for reversal case");
    assert!(
        s.contains("Host -[Connect]-> IP"),
        "expected reversed hint, got: {s}"
    );
    assert_eq!(d.first_step_matches, 0);
}

#[test]
fn missing_rel_type_explains_clearly() {
    let g = graph_with(
        &[("u", EntityType::User), ("ip", EntityType::IP)],
        &[("u", "ip", RelationType::Auth, 100)],
    );
    // Hypothesis asks for Spawn — which doesn't exist in this dataset.
    let h = hyp(&[(EntityType::User, RelationType::Spawn, EntityType::IP)]);
    let d = g.hunt_diagnostic(&h);
    let s = d.suggestion.expect("suggestion should be set");
    assert!(
        s.contains("does not appear"),
        "expected missing-rel-type hint, got: {s}"
    );
}

#[test]
fn schema_matches_but_chain_fails_returns_terminal_hint() {
    // Two edges exist separately (A->B Connect, C->D Auth) but no chain
    // connects them — schema lookup succeeds for each step, but DFS would
    // still return zero.
    let g = graph_with(
        &[
            ("a", EntityType::IP),
            ("b", EntityType::Host),
            ("c", EntityType::Host),
            ("d", EntityType::User),
        ],
        &[
            ("a", "b", RelationType::Connect, 100),
            ("c", "d", RelationType::Auth, 200),
        ],
    );
    let h = hyp(&[
        (EntityType::IP, RelationType::Connect, EntityType::Host),
        (EntityType::Host, RelationType::Auth, EntityType::User),
    ]);
    let d = g.hunt_diagnostic(&h);
    // Both steps have schema matches; failed_step_index lands on the last step.
    let s = d.suggestion.expect("suggestion should be set");
    assert!(
        s.contains("time_window") || s.contains("expand_node_grouped"),
        "got: {s}"
    );
    assert!(d.first_step_matches > 0);
}

#[test]
fn empty_hypothesis_returns_graceful_diagnostic() {
    let g = graph_with(&[], &[]);
    let h = Hypothesis::new("empty");
    let d = g.hunt_diagnostic(&h);
    assert_eq!(d.reason, "hypothesis has no steps");
}

#[test]
fn diagnostic_messages_never_leak_cmd_prefix() {
    // The MCP tool names never carry the Tauri-internal `cmd_` prefix.
    // Any user-facing diagnostic that mentions a command by name must
    // use the MCP form. This test exercises every branch of
    // hunt_diagnostic and asserts the `cmd_` substring is absent.
    let scenarios = [
        // Wrong direction -> reversal branch
        (
            graph_with(
                &[("h", EntityType::Host), ("1.2.3.4", EntityType::IP)],
                &[("h", "1.2.3.4", RelationType::Connect, 100)],
            ),
            hyp(&[(EntityType::IP, RelationType::Connect, EntityType::Host)]),
        ),
        // Missing rel_type branch
        (
            graph_with(
                &[("u", EntityType::User), ("ip", EntityType::IP)],
                &[("u", "ip", RelationType::Auth, 100)],
            ),
            hyp(&[(EntityType::User, RelationType::Spawn, EntityType::IP)]),
        ),
        // Schema matches but chain fails
        (
            graph_with(
                &[
                    ("a", EntityType::IP),
                    ("b", EntityType::Host),
                    ("c", EntityType::Host),
                    ("d", EntityType::User),
                ],
                &[
                    ("a", "b", RelationType::Connect, 100),
                    ("c", "d", RelationType::Auth, 200),
                ],
            ),
            hyp(&[
                (EntityType::IP, RelationType::Connect, EntityType::Host),
                (EntityType::Host, RelationType::Auth, EntityType::User),
            ]),
        ),
    ];
    for (g, h) in scenarios {
        let d = g.hunt_diagnostic(&h);
        assert!(
            !d.reason.contains("cmd_"),
            "reason leaked cmd_ prefix: {}",
            d.reason
        );
        if let Some(s) = &d.suggestion {
            assert!(!s.contains("cmd_"), "suggestion leaked cmd_ prefix: {s}");
        }
    }
}
