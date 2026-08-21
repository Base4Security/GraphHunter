//! The triangle enumerator's temporal semantics, aligned with the DFS.
//!
//! An audit reported four divergences between
//! `enumerate_triangles_lftj_simd_window` and the DFS matcher; all four
//! were verified to reproduce, and all four are now fixed. These tests
//! guard the aligned behaviour, one test per former divergence, each with
//! a control that isolates the variable.
//!
//! The four, and what each used to do wrong:
//!
//! 1. **Strictness.** Required `t_bc > t_ab` (strict) while the DFS floor
//!    keeps edges whose timestamp *equals* the previous hop's. Dropped
//!    same-second causal chains — which are the common case, since sources
//!    stamp ordered events inside one second and our CDM parser floors
//!    nanoseconds to seconds.
//! 2. **Window bounds.** Half-open upper bound against the DFS's
//!    inclusive one.
//! 3. **Window coverage.** Only the first edge was window-checked, so a
//!    triangle whose other edges fell outside the window was emitted
//!    anyway. This one *over*-reported — the only one that could invent a
//!    finding.
//! 4. **Multi-edge.** `MinTimestampMap` stored only the minimum timestamp
//!    per pair, so exactly one candidate combination was tested and valid
//!    triangles with parallel edges were dropped.
//!
//! The last test is the real gate: an independent brute-force reference,
//! written here rather than reusing any enumerator variant, so this is a
//! genuine cross-check and not four implementations agreeing with each
//! other.

use std::collections::BTreeSet;

use graph_hunter_core::{
    Entity, EntityType, GraphHunter, Hypothesis, HypothesisStep, Relation, RelationType,
};

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const FLAGS: [&str; 7] = [
    "GRAPHHUNTER_TRIANGLE_LFTJ",
    "GRAPHHUNTER_K4_LFTJ",
    "GRAPHHUNTER_K5_LFTJ",
    "GRAPHHUNTER_C6_LFTJ",
    "GRAPHHUNTER_LFTJ_PLANNER",
    "GRAPHHUNTER_LFTJ_AUTO",
    "GRAPHHUNTER_YANNAKAKIS",
];

fn clear_flags() {
    // SAFETY: callers hold ENV_LOCK.
    for f in FLAGS {
        unsafe { std::env::remove_var(f) };
    }
}

/// Triangle a→b→c plus the closing a→c, with explicit per-edge stamps.
fn triangle_with(t_ab: i64, t_bc: i64, t_ac: i64) -> GraphHunter {
    let mut g = GraphHunter::new();
    for id in ["a", "b", "c"] {
        g.add_entity(Entity::new(id, EntityType::Host)).unwrap();
    }
    g.add_relation(Relation::new("a", "b", RelationType::Connect, t_ab)).unwrap();
    g.add_relation(Relation::new("b", "c", RelationType::Connect, t_bc)).unwrap();
    g.add_relation(Relation::new("a", "c", RelationType::Connect, t_ac)).unwrap();
    g.sort_edges_by_timestamp().unwrap();
    g
}

/// A 3-step homogeneous hypothesis carrying the `triangle` marker — what
/// actually reaches the triangle operator after the routing fix.
fn triangle_hypothesis() -> Hypothesis {
    let mut h = Hypothesis::new("triangle probe");
    for _ in 0..3 {
        h = h.add_step(HypothesisStep::new(
            EntityType::Host,
            RelationType::Connect,
            EntityType::Host,
        ));
    }
    h
}

fn via_operator(g: &GraphHunter, tw: Option<(i64, i64)>) -> usize {
    clear_flags();
    // SAFETY: ENV_LOCK held by the caller.
    unsafe { std::env::set_var("GRAPHHUNTER_TRIANGLE_LFTJ", "1") };
    let (paths, _) = g
        .search_temporal_pattern(&triangle_hypothesis(), tw, None)
        .expect("operator search");
    clear_flags();
    paths.len()
}

/// FORMER DIVERGENCE 1 — strictness. Equal timestamps on consecutive hops
/// are valid to the DFS (its floor is non-strict) and must be valid here.
#[test]
fn equal_timestamps_on_consecutive_hops_are_accepted() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // a→b and b→c share t=100; a→c later.
    assert_eq!(
        via_operator(&triangle_with(100, 100, 200), None),
        1,
        "a same-second causal chain must match, as it does in the DFS"
    );
    // All three equal is still a valid time-respecting triangle.
    assert_eq!(
        via_operator(&triangle_with(100, 100, 100), None),
        1,
        "three edges in the same second must match"
    );
    // Genuinely backwards still does not.
    assert_eq!(
        via_operator(&triangle_with(100, 50, 200), None),
        0,
        "a strictly earlier second hop must NOT match"
    );
}

/// FORMER DIVERGENCE 2 — window bounds. The upper bound is inclusive, as
/// in the DFS, so a triangle sitting exactly on `t_hi` is inside it.
#[test]
fn the_window_upper_bound_is_inclusive() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // All three edges exactly on the boundary.
    let g = triangle_with(200, 200, 200);
    assert_eq!(
        via_operator(&g, Some((100, 200))),
        1,
        "edges exactly on t_hi are inside an inclusive window"
    );
    // One tick below the boundary excludes it — the control proving the
    // bound is what decides, not something else about the graph.
    assert_eq!(
        via_operator(&g, Some((100, 199))),
        0,
        "t_hi = 199 must exclude edges at 200"
    );
}

/// FORMER DIVERGENCE 3 — window coverage. Every edge is window-checked, so
/// a triangle whose later edges fall outside the requested window is NOT
/// emitted. This is the divergence that used to over-report.
#[test]
fn edges_outside_the_window_are_no_longer_emitted() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // First edge inside [100,200]; the other two far in the future.
    assert_eq!(
        via_operator(&triangle_with(150, 5_000, 9_000), Some((100, 200))),
        0,
        "a triangle whose 2nd/3rd edges are outside the window must not be \
         emitted — the analyst asked for that window"
    );
    // Widen the window to cover all three and it appears.
    assert_eq!(
        via_operator(&triangle_with(150, 5_000, 9_000), Some((100, 10_000))),
        1,
        "with the window covering every edge the same triangle matches"
    );
}

/// FORMER DIVERGENCE 4 — multi-edge. The operator now asks whether ANY
/// combination of parallel edges is time-respecting, not just the one
/// built from each pair's minimum.
#[test]
fn a_valid_combination_of_parallel_edges_is_found() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut g = GraphHunter::new();
    for id in ["a", "b", "c"] {
        g.add_entity(Entity::new(id, EntityType::Host)).unwrap();
    }
    g.add_relation(Relation::new("a", "b", RelationType::Connect, 10)).unwrap();
    // Two parallel b→c edges: one too early to use, one that works.
    g.add_relation(Relation::new("b", "c", RelationType::Connect, 5)).unwrap();
    g.add_relation(Relation::new("b", "c", RelationType::Connect, 20)).unwrap();
    g.add_relation(Relation::new("a", "c", RelationType::Connect, 30)).unwrap();
    g.sort_edges_by_timestamp().unwrap();

    assert_eq!(
        via_operator(&g, None),
        1,
        "(10,20,30) is time-respecting; the early parallel b→c must not \
         hide it — that was the min-timestamp bug"
    );

    // Control: with NO usable parallel edge the triangle really is absent.
    let mut g2 = GraphHunter::new();
    for id in ["a", "b", "c"] {
        g2.add_entity(Entity::new(id, EntityType::Host)).unwrap();
    }
    g2.add_relation(Relation::new("a", "b", RelationType::Connect, 10)).unwrap();
    g2.add_relation(Relation::new("b", "c", RelationType::Connect, 5)).unwrap();
    g2.add_relation(Relation::new("a", "c", RelationType::Connect, 30)).unwrap();
    g2.sort_edges_by_timestamp().unwrap();
    assert_eq!(
        via_operator(&g2, None),
        0,
        "with only the early b→c there is no time-respecting combination"
    );
}

/// REACHABILITY — the calibration that sets severity. All of the above
/// needs a hypothesis explicitly marked `triangle`. An unmarked 3-step
/// chain routes to the DFS, so the shipped default never depended on any
/// of these semantics.
#[test]
fn an_unmarked_three_step_chain_does_not_reach_the_operator() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let g = triangle_with(100, 100, 200);
    let mut h = Hypothesis::new("ordinary three hop");
    for _ in 0..3 {
        h = h.add_step(HypothesisStep::new(
            EntityType::Host,
            RelationType::Connect,
            EntityType::Host,
        ));
    }

    clear_flags();
    // SAFETY: ENV_LOCK held.
    unsafe { std::env::set_var("GRAPHHUNTER_LFTJ_PLANNER", "1") };
    let (planner_paths, _) = g.search_temporal_pattern(&h, None, None).unwrap();
    clear_flags();
    let (dfs_paths, _) = g.search_temporal_pattern(&h, None, None).unwrap();

    assert_eq!(
        planner_paths.len(),
        dfs_paths.len(),
        "an unmarked 3-step chain must get DFS semantics in production config"
    );
}

// ── The gate: an independent reference implementation ──

/// Brute-force "is there a time-respecting triangle on (a,b,c)?", written
/// directly against the graph's relations.
///
/// This deliberately shares NO code with any enumerator variant: the
/// pre-existing `lftj_matches_naive_baseline` compares four
/// implementations that encode the *same* predicate, so it can only catch
/// a coding slip, never a wrong shared premise — and a wrong shared
/// premise is exactly what the four divergences were. This reference
/// states the semantics from scratch: exists edges a→b, b→c, a→c with
/// `t_ab <= t_bc <= t_ac`, all inside the inclusive window.
fn reference_triangles(g: &GraphHunter, tw: Option<(i64, i64)>) -> BTreeSet<Vec<String>> {
    let (lo, hi) = tw.unwrap_or((i64::MIN, i64::MAX));
    let (entities, relations) = g.to_snapshot();
    let ids: Vec<String> = entities.iter().map(|e| e.id.clone()).collect();

    // All timestamps per ordered pair, inside the window.
    let stamps = |src: &str, dst: &str| -> Vec<i64> {
        let mut v: Vec<i64> = relations
            .iter()
            .filter(|r| r.source_id == src && r.dest_id == dst)
            .map(|r| r.timestamp)
            .filter(|t| *t >= lo && *t <= hi)
            .collect();
        v.sort_unstable();
        v
    };

    let mut out = BTreeSet::new();
    for a in &ids {
        for b in &ids {
            if a == b {
                continue;
            }
            let ab = stamps(a, b);
            if ab.is_empty() {
                continue;
            }
            for c in &ids {
                if c == a || c == b {
                    continue;
                }
                let bc = stamps(b, c);
                let ac = stamps(a, c);
                if bc.is_empty() || ac.is_empty() {
                    continue;
                }
                // Exists t_ab <= t_bc <= t_ac?
                let found = ab.iter().any(|&t1| {
                    bc.iter()
                        .filter(|&&t2| t2 >= t1)
                        .any(|&t2| ac.iter().any(|&t3| t3 >= t2))
                });
                if found {
                    out.insert(vec![a.clone(), b.clone(), c.clone()]);
                }
            }
        }
    }
    out
}

/// THE GATE. Deterministic pseudo-random graphs with parallel edges,
/// duplicate timestamps and windows — precisely the inputs the four
/// divergences lived in — compared against the independent reference.
#[test]
fn operator_matches_an_independent_reference_across_random_graphs() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // xorshift64 so the corpus is reproducible without a dependency.
    let mut state: u64 = 0x2026_08_16;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for case in 0..40u32 {
        let n = 4 + (next() % 3) as usize; // 4..6 vertices
        let mut g = GraphHunter::new();
        for i in 0..n {
            g.add_entity(Entity::new(format!("v{i}"), EntityType::Host)).unwrap();
        }
        // Edges with deliberately small timestamp range so ties and
        // parallel edges are frequent, not incidental.
        let edges = 6 + (next() % 10) as usize;
        for _ in 0..edges {
            let s = (next() % n as u64) as usize;
            let d = (next() % n as u64) as usize;
            if s == d {
                continue;
            }
            let t = (next() % 8) as i64 * 10;
            g.add_relation(Relation::new(
                format!("v{s}"),
                format!("v{d}"),
                RelationType::Connect,
                t,
            ))
            .unwrap();
        }
        g.sort_edges_by_timestamp().unwrap();

        // Half the cases with a window, half without.
        let tw = if case % 2 == 0 { None } else { Some((10i64, 50i64)) };

        clear_flags();
        // SAFETY: ENV_LOCK held.
        unsafe { std::env::set_var("GRAPHHUNTER_TRIANGLE_LFTJ", "1") };
        let (paths, truncated) = g
            .search_temporal_pattern(&triangle_hypothesis(), tw, None)
            .expect("operator search");
        clear_flags();
        assert!(!truncated, "case {case}: cap must not interfere");

        let got: BTreeSet<Vec<String>> = paths
            .iter()
            .map(|p| p.iter().map(|s| s.to_string()).collect())
            .collect();
        let want = reference_triangles(&g, tw);

        assert_eq!(
            got, want,
            "case {case} (n={n}, edges={edges}, window={tw:?}): operator and \
             independent reference disagree.\n  only operator: {:?}\n  only \
             reference: {:?}",
            got.difference(&want).collect::<Vec<_>>(),
            want.difference(&got).collect::<Vec<_>>(),
        );
    }
}
