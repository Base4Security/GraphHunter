//! Result-set parity between the WCOJ/LFTJ operators and the DFS.
//!
//! Roadmap item #2 asks whether the worst-case-optimal operators
//! (Triangle / K5 / C6, still env-gated off) are safe to default-on. The
//! `k4_lftj_dispatch` suite only proves the planner *routes* to them; no
//! test compared what they *return* against the DFS. Routing to an
//! operator that returns a different result set would be a correctness
//! bug shipped as a speed-up — the worst possible trade — so this file
//! supplies the missing evidence.
//!
//! The question each test answers is deliberately narrow and falsifiable:
//! for a hypothesis the planner would route to operator X, does X return
//! the same set of paths the DFS returns on the same graph?
//!
//! HONEST NOTE ON WHAT "SAME" MEANS HERE. The DFS emits a path per
//! matching *walk* of the hypothesis chain; the clique/cycle enumerators
//! emit one tuple per *structure* found. These are different emission
//! contracts, so a raw count comparison is not meaningful in general.
//! What must hold — and what these tests check — is that the two agree on
//! the *set of vertices implicated*: an operator must never surface a
//! vertex set the DFS would not, and must never miss one the DFS finds.
//! That is the property an analyst depends on (no invented findings, no
//! silently dropped ones), and it is the property a default-on flip would
//! risk.

use std::collections::BTreeSet;

use graph_hunter_core::{
    Entity, EntityType, GraphHunter, Hypothesis, HypothesisStep, Relation, RelationType,
};

/// Serializes env mutations across tests in this binary — same reason as
/// `k4_lftj_dispatch`'s lock (these tests flip dispatch flags).
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A dense-ish homogeneous graph: `n` Hosts, every ordered pair (i<j)
/// connected with a strictly increasing timestamp. Contains triangles,
/// 4-cliques and 5-cliques by construction, so every operator under test
/// has something real to find.
fn clique_graph(n: usize) -> GraphHunter {
    let mut g = GraphHunter::new();
    for i in 0..n {
        g.add_entity(Entity::new(format!("v{i}"), EntityType::Host))
            .unwrap();
    }
    let mut t = 1i64;
    for i in 0..n {
        for j in (i + 1)..n {
            g.add_relation(Relation::new(
                format!("v{i}"),
                format!("v{j}"),
                RelationType::Connect,
                t,
            ))
            .unwrap();
            t += 1;
        }
    }
    g.sort_edges_by_timestamp().unwrap();
    g
}

/// A homogeneous `Host -[Connect]-> Host` chain of `len` steps. This is
/// the shape the structural detectors key on (`is_homogeneous_*_shape`):
/// 3 steps => triangle, 6 => K4/C6, 10 => K5.
fn homogeneous(name: &str, len: usize) -> Hypothesis {
    let mut h = Hypothesis::new(name);
    for _ in 0..len {
        h = h.add_step(HypothesisStep::new(
            EntityType::Host,
            RelationType::Connect,
            EntityType::Host,
        ));
    }
    h
}

/// The set of vertices each returned path implicates, as sorted tuples.
fn vertex_sets(paths: &[Vec<std::sync::Arc<str>>]) -> BTreeSet<Vec<String>> {
    paths
        .iter()
        .map(|p| {
            let mut v: Vec<String> = p.iter().map(|s| s.to_string()).collect();
            v.sort();
            v.dedup();
            v
        })
        .collect()
}

/// Runs `hypothesis` with the given env flag set, and again with every
/// dispatch flag cleared (forcing the DFS), returning (operator, dfs).
fn operator_vs_dfs(
    g: &GraphHunter,
    h: &Hypothesis,
    flag: &str,
) -> (BTreeSet<Vec<String>>, BTreeSet<Vec<String>>) {
    let all_flags = [
        "GRAPHHUNTER_TRIANGLE_LFTJ",
        "GRAPHHUNTER_K4_LFTJ",
        "GRAPHHUNTER_K5_LFTJ",
        "GRAPHHUNTER_C6_LFTJ",
        "GRAPHHUNTER_LFTJ_PLANNER",
        "GRAPHHUNTER_LFTJ_AUTO",
        "GRAPHHUNTER_YANNAKAKIS",
    ];
    // SAFETY: the ENV_LOCK held by the caller serializes these mutations.
    for f in all_flags {
        unsafe { std::env::remove_var(f) };
    }
    let (dfs_paths, _) = g.search_temporal_pattern(h, None, None).expect("dfs search");

    unsafe { std::env::set_var(flag, "1") };
    let (op_paths, _) = g
        .search_temporal_pattern(h, None, None)
        .expect("operator search");
    for f in all_flags {
        unsafe { std::env::remove_var(f) };
    }

    (vertex_sets(&op_paths), vertex_sets(&dfs_paths))
}

/// The Triangle operator must not invent vertex sets the DFS never finds.
/// A superset would mean the analyst sees fabricated findings.
#[test]
fn triangle_operator_invents_nothing() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let g = clique_graph(6);
    let h = homogeneous("tri", 3);
    let (op, dfs) = operator_vs_dfs(&g, &h, "GRAPHHUNTER_TRIANGLE_LFTJ");
    let invented: Vec<_> = op.difference(&dfs).collect();
    assert!(
        invented.is_empty(),
        "triangle operator surfaced {} vertex set(s) the DFS never found: {:?}",
        invented.len(),
        invented.iter().take(3).collect::<Vec<_>>()
    );
}

/// The K5 operator must not invent vertex sets.
#[test]
fn k5_operator_invents_nothing() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let g = clique_graph(6);
    let h = homogeneous("k5", 10);
    let (op, dfs) = operator_vs_dfs(&g, &h, "GRAPHHUNTER_K5_LFTJ");
    let invented: Vec<_> = op.difference(&dfs).collect();
    assert!(
        invented.is_empty(),
        "k5 operator surfaced {} vertex set(s) the DFS never found: {:?}",
        invented.len(),
        invented.iter().take(3).collect::<Vec<_>>()
    );
}

/// The C6 operator must not invent vertex sets.
#[test]
fn c6_operator_invents_nothing() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let g = clique_graph(6);
    let mut h = homogeneous("6-cycle", 6);
    h.name = "6-cycle".into();
    let (op, dfs) = operator_vs_dfs(&g, &h, "GRAPHHUNTER_C6_LFTJ");
    let invented: Vec<_> = op.difference(&dfs).collect();
    assert!(
        invented.is_empty(),
        "c6 operator surfaced {} vertex set(s) the DFS never found: {:?}",
        invented.len(),
        invented.iter().take(3).collect::<Vec<_>>()
    );
}

/// THE REGRESSION GUARD THIS FILE EXISTS FOR.
///
/// A plain homogeneous 6-step chain (`T -[r]-> T` ×6) is an ordinary thing
/// to author meaning "a 6-hop path" — and it is *also* the edge count of a
/// 4-clique. The planner used to dispatch on that shape ALONE, so with
/// `GRAPHHUNTER_LFTJ_PLANNER=1` (which both shipped apps set at startup)
/// such a hypothesis was routed to the clique enumerator and came back
/// with all C(6,4)=15 four-cliques instead of paths. This test caught that
/// in production configuration.
///
/// The fix: the structural routes now require the author's explicit name
/// marker (`k4-clique`, `triangle`, `k5-clique`) *in addition to* the
/// shape — mirroring what `is_homogeneous_c6_shape` already did. Shape is
/// not intent.
///
/// So this test now asserts the property that was violated: a 6-hop chain
/// with the planner enabled must return exactly what the DFS returns.
#[test]
fn a_plain_six_hop_chain_is_not_routed_to_the_clique_enumerator() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let g = clique_graph(6);
    // No `k4-clique` marker: the author asked for a path, not cliques.
    let h = homogeneous("six-hop-path", 6);

    let all = [
        "GRAPHHUNTER_TRIANGLE_LFTJ",
        "GRAPHHUNTER_K4_LFTJ",
        "GRAPHHUNTER_K5_LFTJ",
        "GRAPHHUNTER_C6_LFTJ",
        "GRAPHHUNTER_LFTJ_PLANNER",
        "GRAPHHUNTER_LFTJ_AUTO",
        "GRAPHHUNTER_YANNAKAKIS",
    ];
    // SAFETY: ENV_LOCK is held for the duration.
    for f in all {
        unsafe { std::env::remove_var(f) };
    }
    let (dfs_paths, _) = g.search_temporal_pattern(&h, None, None).unwrap();

    // Production configuration: the planner flag on.
    unsafe { std::env::set_var("GRAPHHUNTER_LFTJ_PLANNER", "1") };
    let (planner_paths, _) = g.search_temporal_pattern(&h, None, None).unwrap();
    for f in all {
        unsafe { std::env::remove_var(f) };
    }

    assert_eq!(
        vertex_sets(&planner_paths),
        vertex_sets(&dfs_paths),
        "a plain 6-hop homogeneous chain must return the DFS result with the \
         planner enabled; a divergence means shape-based routing sent it to a \
         clique enumerator again"
    );
}

/// The complement: an author who explicitly asks for cliques still gets the
/// fast operator. Narrowing the route must not disable the feature.
#[test]
fn an_explicitly_marked_clique_hypothesis_still_reaches_the_operator() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let g = clique_graph(6);
    let h = homogeneous("k4-clique", 6);

    // SAFETY: ENV_LOCK is held.
    unsafe { std::env::set_var("GRAPHHUNTER_LFTJ_PLANNER", "1") };
    let (paths, _) = g.search_temporal_pattern(&h, None, None).unwrap();
    unsafe { std::env::remove_var("GRAPHHUNTER_LFTJ_PLANNER") };

    let sets = vertex_sets(&paths);
    assert!(
        !sets.is_empty(),
        "a marked k4-clique hypothesis must still route to the clique operator"
    );
    assert!(
        sets.iter().all(|vs| vs.len() == 4),
        "the clique operator should emit 4-vertex tuples, got {:?}",
        sets.iter().take(3).collect::<Vec<_>>()
    );
}
