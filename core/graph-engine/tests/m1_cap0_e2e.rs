//! End-to-end verification for Cap 0 of the GraphHunter book (M1).
//!
//! Loads `docs/libro/examples/parte0/auth-events.jsonl` via the GenericParser,
//! runs the DSL hypothesis `User -[Auth]-> IP HAVING count(distinct IP) >= 3 WITHIN 15m`,
//! and asserts:
//!   - Exactly 1 user is flagged (alicia@empresa.com)
//!   - The number of distinct IPs for alicia is 9
//!   - Neither eduardo nor beatriz is flagged (they each have only 1 IP)
//!
//! This test is the proof that `docs/libro/examples/parte0/hipotesis.dsl`
//! produces exactly 1 finding on `auth-events.jsonl`.

use graph_hunter_core::{GenericParser, GraphHunter, parse_dsl};
use std::collections::HashSet;

const AUTH_EVENTS: &str = include_str!("../../../docs/libro/examples/parte0/auth-events.jsonl");

#[test]
fn cap0_credential_stuffing_finds_exactly_alicia() {
    // 1. Ingest
    let mut g = GraphHunter::new();
    let (entities, relations) = g
        .ingest_logs(AUTH_EVENTS, &GenericParser, None)
        .expect("ingest must succeed");
    assert!(entities > 0, "ingest produced no entities");
    assert!(relations > 0, "ingest produced no relations");

    // 2. Parse hypothesis
    let dsl = "User -[Auth]-> IP HAVING count(distinct IP) >= 3 WITHIN 15m";
    let result = parse_dsl(dsl, None).expect("DSL must parse");
    let h = result.hypothesis;

    // 3. Run hunt
    let (paths, _truncated) = g
        .search_temporal_pattern(&h, None, None)
        .expect("search must succeed");

    // 4. Collect which users appear in the results
    // Each path is Vec<Arc<str>> with [user_id, ip_id]
    let flagged_users: HashSet<String> = paths
        .iter()
        .map(|path| path[0].to_string())
        .collect();

    // 5. Assert: only alicia is flagged
    assert_eq!(
        flagged_users.len(),
        1,
        "expected exactly 1 flagged user, got {}: {:?}",
        flagged_users.len(),
        flagged_users
    );
    assert!(
        flagged_users.contains("alicia@empresa.com"),
        "expected alicia@empresa.com to be flagged, got: {:?}",
        flagged_users
    );

    // 6. Assert: eduardo and beatriz are NOT flagged
    assert!(
        !flagged_users.contains("eduardo@empresa.com"),
        "eduardo should not be flagged (only 1 IP)"
    );
    assert!(
        !flagged_users.contains("beatriz@empresa.com"),
        "beatriz should not be flagged (only 1 IP)"
    );

    // 7. Count distinct IPs for alicia in the results
    let alicia_ips: HashSet<String> = paths
        .iter()
        .filter(|p| &*p[0] == "alicia@empresa.com")
        .map(|p| p[1].to_string())
        .collect();

    assert!(
        alicia_ips.len() >= 3,
        "alicia must match at least 3 distinct IPs, got: {}",
        alicia_ips.len()
    );

    // The attack window has 9 unique IPs for alicia; verify they are all there
    assert_eq!(
        alicia_ips.len(),
        9,
        "expected 9 distinct IPs for alicia in the 15m window, got {}: {:?}",
        alicia_ips.len(),
        alicia_ips
    );

    println!(
        "\n[cap0_e2e] PASS: {} paths, {} distinct IPs for alicia",
        paths.len(),
        alicia_ips.len()
    );
}
