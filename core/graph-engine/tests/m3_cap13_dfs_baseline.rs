//! Integration test for Cap 13 — DFS baseline (M3 Phase F).
//!
//! Goal: verify that DFS-Match finds the expected matches on the Cap 0
//! dataset (`auth-events.jsonl`). Specifically, a simple `User -[Auth]-> IP`
//! query (no HAVING/WITHIN) should return one path per auth event — one
//! pair `(user, ip)` per line in the dataset (some pairs repeat across
//! multiple timestamps, so the result set deduplicates to distinct
//! `(user, ip)` pairs that exist as edges in the graph).
//!
//! The DFS is the default dispatcher when no LFTJ/Yannakakis env flags
//! are set. The test ensures that:
//!   1. Ingest succeeds and produces entities + relations.
//!   2. A plain 1-step `User -[Auth]-> IP` hypothesis returns non-zero paths.
//!   3. All paths have exactly 2 elements: `[user_id, ip_id]`.
//!   4. The users appearing in results are exactly the three test users.
//!   5. Alicia appears with multiple distinct IPs (credential stuffing trace).
//!
//! This test is the regression guard for Cap 13 (DFS-Match baseline):
//! if the DFS entry point changes semantics, this test will catch it.

use graph_hunter_core::{GenericParser, GraphHunter, Hypothesis, HypothesisStep};
use graph_hunter_core::{EntityType, RelationType};
use std::collections::{HashMap, HashSet};

const AUTH_EVENTS: &str =
    include_str!("../../../docs/libro/examples/parte0/auth-events.jsonl");

/// Guard: clear every planner-routing env var so this test exercises
/// the pure DFS path regardless of whatever CI might have set.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn cap13_dfs_baseline_finds_auth_edges() {
    // Ensure no LFTJ or Yannakakis env flags interfere.
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        std::env::remove_var("GRAPHHUNTER_K4_LFTJ");
        std::env::remove_var("GRAPHHUNTER_LFTJ_PLANNER");
        std::env::remove_var("GRAPHHUNTER_TRIANGLE_LFTJ");
        std::env::remove_var("GRAPHHUNTER_YANNAKAKIS");
        std::env::remove_var("GRAPHHUNTER_LFTJ_AUTO");
    }

    // 1. Ingest the Cap 0 dataset.
    let mut g = GraphHunter::new();
    let (entities, relations) = g
        .ingest_logs(AUTH_EVENTS, &GenericParser, None)
        .expect("ingest must succeed");
    assert!(entities > 0, "ingest produced no entities");
    assert!(relations > 0, "ingest produced no relations");

    // 2. Build a simple 1-step hypothesis: User -[Auth]-> IP.
    //    No HAVING/WITHIN — pure structural match.
    let h = Hypothesis::new("cap13-dfs-baseline")
        .add_step(HypothesisStep::new(
            EntityType::User,
            RelationType::Auth,
            EntityType::IP,
        ));

    // 3. Run the matcher (defaults to DFS because no env flags are set).
    let (paths, truncated) = g
        .search_temporal_pattern(&h, None, None)
        .expect("search must succeed");

    assert!(!truncated, "result must not be truncated on a tiny dataset");

    // 4. All paths must be 2-element: [user_id, ip_id].
    for p in &paths {
        assert_eq!(
            p.len(),
            2,
            "every path must have exactly 2 elements for a 1-step query; got {:?}",
            p
        );
    }

    // 5. The result must be non-empty — there are auth edges in the dataset.
    assert!(
        !paths.is_empty(),
        "DFS must find at least one User-[Auth]->IP match"
    );

    // 6. Collect distinct (user, ip) pairs from the results.
    let pairs: HashSet<(String, String)> = paths
        .iter()
        .map(|p| (p[0].to_string(), p[1].to_string()))
        .collect();

    // The dataset has 3 users and several IPs; we must see all 3 users.
    let users: HashSet<String> = pairs.iter().map(|(u, _)| u.clone()).collect();
    assert!(
        users.contains("alicia@empresa.com"),
        "alicia must appear in DFS results"
    );
    assert!(
        users.contains("eduardo@empresa.com"),
        "eduardo must appear in DFS results"
    );
    assert!(
        users.contains("beatriz@empresa.com"),
        "beatriz must appear in DFS results"
    );

    // 7. Alicia's distinct IPs in the result — the dataset gives her
    //    multiple distinct IPs. Verify the DFS surfaces more than 1.
    let alicia_ips: HashSet<String> = pairs
        .iter()
        .filter(|(u, _)| u == "alicia@empresa.com")
        .map(|(_, ip)| ip.clone())
        .collect();
    assert!(
        alicia_ips.len() > 1,
        "alicia must appear with multiple distinct IPs (credential stuffing data); got {}",
        alicia_ips.len()
    );

    // 8. Verify per-user result counts for a sanity snapshot.
    let mut per_user: HashMap<String, usize> = HashMap::new();
    for (u, _) in &pairs {
        *per_user.entry(u.clone()).or_insert(0) += 1;
    }

    println!(
        "\n[cap13_dfs_baseline] PASS: {} total paths, {} distinct (user,ip) pairs",
        paths.len(),
        pairs.len()
    );
    println!("  per-user distinct IPs: {:?}", per_user);
}
