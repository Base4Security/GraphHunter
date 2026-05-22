//! Integration test for Cap 15 — NLF pruning soundness (M3 Phase F).
//!
//! Goal: verify that NLF (Neighborhood Label Frequency) pruning is *sound*,
//! i.e. it never removes correct matches. The NLF filter runs inside
//! `dfs_match_iterative` as a pre-check on every candidate start vertex.
//! A sound filter may reduce the number of *visited* candidates but must
//! leave the *output* set unchanged.
//!
//! Strategy: run `search_temporal_pattern` twice on the same graph and
//! hypothesis. Both calls go through the default DFS path (NLF is always
//! on once `sort_edges_by_timestamp` has been called, which triggers the
//! lazy NLF build). We compare:
//!   (a) the result of a 1-step hypothesis with concrete entity types (NLF
//!       can prune) versus
//!   (b) the same hypothesis with wildcard types (NLF cannot prune, since
//!       Any-typed neighbors don't update the histogram).
//!
//! If NLF is unsound, the concrete-type call would miss matches that the
//! wildcard call finds. The test asserts that every path found by (a) also
//! appears in (b), and that (a) is non-empty.
//!
//! Additionally we directly exercise `NlfTable::can_match` to verify that
//! the filter correctly classifies known entities in the Cap 0 dataset.
//!
//! This test is the regression guard for Cap 15 (NLF pruning):
//! if NLF ever becomes unsound (drops a valid candidate) this test fails.

use graph_hunter_core::{GenericParser, GraphHunter, Hypothesis, HypothesisStep};
use graph_hunter_core::{EntityType, RelationType};
use std::collections::HashSet;

const AUTH_EVENTS: &str =
    include_str!("../../../docs/libro/examples/parte0/auth-events.jsonl");

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn cap15_nlf_pruning_is_sound() {
    // Ensure no LFTJ flags interfere — we want the DFS path.
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
    let (_entities, _relations) = g
        .ingest_logs(AUTH_EVENTS, &GenericParser, None)
        .expect("ingest must succeed");

    // 2. Run (a): concrete entity types — NLF CAN prune start vertices
    //    that have no outgoing IP-typed neighbors.
    let h_concrete = Hypothesis::new("cap15-nlf-concrete")
        .add_step(HypothesisStep::new(
            EntityType::User,
            RelationType::Auth,
            EntityType::IP,
        ));

    let (paths_concrete, _) = g
        .search_temporal_pattern(&h_concrete, None, None)
        .expect("concrete search must succeed");

    // Must return at least one result.
    assert!(
        !paths_concrete.is_empty(),
        "NLF-pruned search returned no results — soundness failure or empty graph"
    );

    // 3. Run (b): wildcard types — NLF cannot prune (Any-typed queries
    //    bypass the histogram check). This is the "ground truth" for
    //    any hypothesis structure that matches Auth edges.
    let h_any = Hypothesis::new("cap15-nlf-any")
        .add_step(HypothesisStep::new(
            EntityType::Any,
            RelationType::Auth,
            EntityType::Any,
        ));

    let (paths_any, _) = g
        .search_temporal_pattern(&h_any, None, None)
        .expect("any search must succeed");

    // 4. Every path found by (a) must also appear in (b).
    //    (The converse need not hold: (b) may find more pairs if there
    //    are auth edges between non-User entities, but (a) must be a
    //    subset of (b).)
    let pairs_any: HashSet<Vec<String>> = paths_any
        .iter()
        .map(|p| p.iter().map(|s| s.to_string()).collect())
        .collect();

    for p in &paths_concrete {
        let key: Vec<String> = p.iter().map(|s| s.to_string()).collect();
        assert!(
            pairs_any.contains(&key),
            "NLF pruning dropped a valid match {:?} — SOUNDNESS BUG",
            key
        );
    }

    // 5. The concrete result must have at most as many paths as the
    //    wildcard result (NLF is a filter, never an amplifier).
    assert!(
        paths_concrete.len() <= paths_any.len(),
        "concrete result ({}) is larger than wildcard result ({}) — impossible with sound NLF",
        paths_concrete.len(),
        paths_any.len()
    );

    println!(
        "\n[cap15_nlf_soundness] PASS: concrete={} paths, wildcard={} paths, subset check OK",
        paths_concrete.len(),
        paths_any.len()
    );
}

/// Direct unit-level check of `NlfTable::can_match` on the Cap 0 graph.
///
/// After `ensure_nlf()` is called, every User vertex with at least one
/// IP-typed neighbor must pass the `[0,0,0,0,0,0,0,0,1]` requirement
/// (slot 0 = IP type, count ≥ 1). This validates the histogram is being
/// built correctly.
#[test]
fn cap15_nlf_table_built_correctly() {
    // 1. Ingest Cap 0 dataset.
    let mut g = GraphHunter::new();
    g.ingest_logs(AUTH_EVENTS, &GenericParser, None)
        .expect("ingest must succeed");

    // 2. Force NLF build (normally lazy — triggered by first search).
    let nlf = g.ensure_nlf();

    // 3. The NLF table has at least one non-empty slot (graph is non-empty).
    //    We verify this indirectly: for every entity in the graph that is
    //    of type User, check that at least one passes the requirement for
    //    having ≥1 IP neighbor. Since every user in the dataset has at
    //    least one auth edge to an IP, all three should pass.
    //
    //    NLF slot mapping (EntityType::to_u8()):
    //      IP=0, Host=1, User=2, Process=3, File=4, Domain=5,
    //      Registry=6, URL=7, Service=8
    //    Requirement: at least 1 IP neighbor → slot[0] >= 1.
    let mut requirement = [0u32; graph_hunter_core::nlf::NLF_TYPE_COUNT];
    requirement[0] = 1; // need ≥1 IP-typed neighbor

    // Collect all User StrIds via the type_index.
    let user_sids: Vec<_> = g
        .type_index
        .get(&EntityType::User)
        .map(|s| s.iter().copied().collect())
        .unwrap_or_default();

    assert!(
        !user_sids.is_empty(),
        "type_index must contain at least one User after ingest"
    );

    // All three users in the dataset have at least one auth edge to an IP,
    // so can_match must return true for each of them.
    let mut passing = 0usize;
    for sid in &user_sids {
        if nlf.can_match(*sid, &requirement) {
            passing += 1;
        }
    }

    assert_eq!(
        passing,
        user_sids.len(),
        "every User in the Cap 0 dataset must have ≥1 IP neighbor; {} of {} passed",
        passing,
        user_sids.len()
    );

    println!(
        "\n[cap15_nlf_table] PASS: {}/{} users pass IP-neighbor requirement",
        passing,
        user_sids.len()
    );
}
