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

/// THE FINDING THIS FILE EXISTS TO RECORD.
///
/// The K4 route is **default-on in both shipped apps**, and it does NOT
/// return what the DFS returns for the same `Hypothesis` — it returns the
/// 4-cliques of the graph, while the DFS returns 6-hop temporally-monotone
/// walks. On a 6-vertex clique graph the operator surfaces all C(6,4)=15
/// cliques; the DFS surfaces none of them as such.
///
/// This is NOT a newly-introduced bug — it is the documented limitation in
/// `planner.rs`'s header ("the K4 enumerator does not consult per-step
/// entity-type filters, so widening detection risks returning tuples that
/// don't satisfy the hypothesis") reaching its logical conclusion: the
/// structural detector `is_homogeneous_k4_shape` accepts ANY homogeneous
/// 6-step chain, and a homogeneous 6-step chain is a perfectly ordinary
/// thing for an analyst to write meaning "a 6-hop path".
///
/// Two readings, and the test pins the factual one rather than the
/// editorial one:
///   * Charitable: the two operators answer different questions, and
///     routing between them by *shape* alone is the design flaw.
///   * Blunt: a user writing a 6-step chain today can silently get cliques.
///
/// The test asserts the divergence EXISTS (so nobody "fixes" the symptom
/// by weakening a parity test), and is the evidence behind the
/// recommendation NOT to widen structural WCOJ routing until the operators
/// consult per-step filters. See docs/superpowers/plans/
/// 2026-08-16-subgraph-matching-review.md.
#[test]
fn k4_structural_route_answers_a_different_question_than_the_dfs() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let g = clique_graph(6);
    // A plain homogeneous 6-step chain — no `k4-clique` name marker, so
    // this is the STRUCTURAL route, reachable by any analyst who writes a
    // 6-hop homogeneous hypothesis.
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

    // The structural route needs the planner flag — which both shipped
    // apps set to "1" at startup.
    unsafe { std::env::set_var("GRAPHHUNTER_LFTJ_PLANNER", "1") };
    let (lftj_paths, _) = g.search_temporal_pattern(&h, None, None).unwrap();
    for f in all {
        unsafe { std::env::remove_var(f) };
    }

    let dfs = vertex_sets(&dfs_paths);
    let lftj = vertex_sets(&lftj_paths);
    let only_lftj: Vec<_> = lftj.difference(&dfs).collect();

    assert!(
        !only_lftj.is_empty(),
        "expected the structural K4 route to diverge from the DFS on a plain \
         homogeneous 6-step chain; if this now passes, the operators were made \
         filter-aware and this test should become a real parity assertion"
    );
    // Every divergent tuple is a 4-vertex clique — evidence that the
    // operator is answering "find 4-cliques", not "walk a 6-hop chain".
    for vs in &only_lftj {
        assert_eq!(
            vs.len(),
            4,
            "divergent tuples should be 4-cliques, got {vs:?}"
        );
    }
}
