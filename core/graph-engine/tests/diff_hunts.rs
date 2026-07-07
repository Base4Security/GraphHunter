//! Integration tests for C.1 — time-travel / snapshot diff.
//!
//! The pilot report identified the canonical scenario: "run the same
//! hunt at T0 and T+6h, see exactly which attacker IPs appeared in the
//! window". These tests encode that shape end-to-end.

use graph_hunter_core::{Entity, EntityType, GraphHunter, Relation, RelationType, parse_dsl};

/// Build a spraying graph where:
///   - `attacker` authenticates (Failure) from IPs 1.1.1.1, 2.2.2.2,
///     3.3.3.3 at timestamps 1000..1200. Baseline.
///   - Between t=1300 and t=2600, 14 new IPs join the spray. Current.
///
/// cat-017 (spray with HAVING count distinct IP >= 3) matches at both
/// bounds; the diff reveals the 14 new IPs.
fn two_stage_spray_graph() -> GraphHunter {
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("attacker", EntityType::User))
        .unwrap();
    // Baseline IPs (3).
    for (i, ip) in ["1.1.1.1", "2.2.2.2", "3.3.3.3"].iter().enumerate() {
        g.add_entity(Entity::new(*ip, EntityType::IP)).unwrap();
        g.add_relation(
            Relation::new("attacker", *ip, RelationType::Auth, 1000 + i as i64 * 100)
                .with_metadata("status", "Failure"),
        )
        .unwrap();
    }
    // Current-window IPs (14 new, joining between t=1300 and t=2600).
    // Anonymized to RFC5737 TEST-NET-2 (198.51.100.0/24); last octet
    // preserved from the original fixture to keep variance shape.
    let later_ips = [
        "198.51.100.208",
        "198.51.100.50",
        "198.51.100.47",
        "198.51.100.74",
        "198.51.100.73",
        "198.51.100.222",
        "198.51.100.38",
        "198.51.100.54",
        "198.51.100.217",
        "198.51.100.183",
        "198.51.100.10",
        "198.51.100.99",
        "198.51.100.12",
        "198.51.100.200",
    ];
    for (i, ip) in later_ips.iter().enumerate() {
        g.add_entity(Entity::new(*ip, EntityType::IP)).unwrap();
        g.add_relation(
            Relation::new("attacker", *ip, RelationType::Auth, 1300 + i as i64 * 100)
                .with_metadata("status", "Failure"),
        )
        .unwrap();
    }
    g
}

#[test]
fn diff_surfaces_newly_added_paths_between_two_timestamps() {
    let g = two_stage_spray_graph();
    let h = parse_dsl(r#"User -[Auth {status="Failure"}]-> IP"#, None)
        .unwrap()
        .hypothesis;

    let diff = g
        .diff_hunts(&h, /* baseline_ts */ 1250, /* current_ts */ 2600)
        .unwrap();

    assert_eq!(diff.baseline_count, 3, "3 IPs visible at t=1250");
    assert_eq!(diff.current_count, 17, "17 IPs visible at t=2600 (3 + 14)");
    assert_eq!(
        diff.added.len(),
        14,
        "diff should report exactly the 14 new IPs"
    );
    assert_eq!(
        diff.removed.len(),
        0,
        "no paths should disappear in monotonic ingest"
    );
    // The `attacker` anchor must be the first node in every added path.
    for sp in &diff.added {
        assert_eq!(sp.path[0], "attacker");
    }
}

#[test]
fn diff_with_identical_timestamps_is_all_zero() {
    let g = two_stage_spray_graph();
    let h = parse_dsl(r#"User -[Auth {status="Failure"}]-> IP"#, None)
        .unwrap()
        .hypothesis;
    let diff = g.diff_hunts(&h, 2600, 2600).unwrap();
    assert_eq!(diff.baseline_count, 17);
    assert_eq!(diff.current_count, 17);
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
}

#[test]
fn diff_returns_removed_when_baseline_is_a_superset() {
    // Synthetic check: swap the args so baseline > current → everything
    // that exists at the later window must show as `removed` from the
    // earlier one, nothing `added`. Useful for tracking purging /
    // retention cycles.
    let g = two_stage_spray_graph();
    let h = parse_dsl(r#"User -[Auth {status="Failure"}]-> IP"#, None)
        .unwrap()
        .hypothesis;
    // Run diff(2600, 1250) via the engine (which doesn't enforce ordering
    // — the Tauri command does). This documents the raw semantics.
    let diff = g.diff_hunts(&h, 2600, 1250).unwrap();
    assert_eq!(diff.baseline_count, 17);
    assert_eq!(diff.current_count, 3);
    assert!(
        diff.added.is_empty(),
        "no new paths when current window is earlier"
    );
    assert_eq!(
        diff.removed.len(),
        14,
        "the later-added IPs should show as removed from the earlier window"
    );
}

#[test]
fn diff_on_empty_hypothesis_result_returns_empty_sets() {
    // A pattern that matches nothing at either bound must diff to all-empty.
    let g = two_stage_spray_graph();
    let h = parse_dsl(r#"Host -[Connect]-> Process"#, None)
        .unwrap()
        .hypothesis;
    let diff = g.diff_hunts(&h, 1250, 2600).unwrap();
    assert_eq!(diff.baseline_count, 0);
    assert_eq!(diff.current_count, 0);
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
}
