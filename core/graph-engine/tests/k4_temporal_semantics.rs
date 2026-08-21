//! The K4 (4-clique) enumerator's temporal semantics, aligned with the DFS.
//!
//! K4 carried the same four divergences as the triangle operator — and a
//! fifth that only it had: its SIMD variants lacked the distinctness
//! guards the naive baseline enforced (`c != b`, `d != b && d != c`).
//! Those were *accidentally* masked by the strict comparisons: a `d == b`
//! forces `t_ad == t_ab`, which a strict `<` rejected. Relaxing to
//! non-strict removes that cover, so the guards had to become explicit in
//! the same change — otherwise self-loops would surface degenerate
//! "cliques" of fewer than four distinct vertices.
//!
//! That is not hypothetical here. GraphHunter's single-endpoint ingest
//! fallback deliberately emits `IP -[Connect]-> IP` self-loops for events
//! that name only one entity, so real ingested graphs contain them.
//!
//! The predicate is one chain over six pairwise timestamps:
//!   `t_ab <= t_ac <= t_ad <= t_bc <= t_bd <= t_cd`
//! every link now non-strict, every edge window-checked, and every link
//! resolved across ALL parallel edges via `MinTimestampMap::successor`.

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

/// The six K4 edges in chain order: ab, ac, ad, bc, bd, cd.
fn k4_with(ts: [i64; 6]) -> GraphHunter {
    let mut g = GraphHunter::new();
    for id in ["a", "b", "c", "d"] {
        g.add_entity(Entity::new(id, EntityType::Host)).unwrap();
    }
    let edges = [
        ("a", "b", ts[0]),
        ("a", "c", ts[1]),
        ("a", "d", ts[2]),
        ("b", "c", ts[3]),
        ("b", "d", ts[4]),
        ("c", "d", ts[5]),
    ];
    for (s, d, t) in edges {
        g.add_relation(Relation::new(s, d, RelationType::Connect, t)).unwrap();
    }
    g.sort_edges_by_timestamp().unwrap();
    g
}

/// A 6-step homogeneous hypothesis carrying the `k4-clique` marker — what
/// reaches the K4 operator after the shape-is-not-intent fix.
fn k4_hypothesis() -> Hypothesis {
    let mut h = Hypothesis::new("k4-clique probe");
    for _ in 0..6 {
        h = h.add_step(HypothesisStep::new(
            EntityType::Host,
            RelationType::Connect,
            EntityType::Host,
        ));
    }
    h
}

fn via_operator(g: &GraphHunter, tw: Option<(i64, i64)>) -> Vec<Vec<String>> {
    clear_flags();
    // SAFETY: ENV_LOCK held by the caller.
    unsafe { std::env::set_var("GRAPHHUNTER_K4_LFTJ", "1") };
    let (paths, _) = g
        .search_temporal_pattern(&k4_hypothesis(), tw, None)
        .expect("operator search");
    clear_flags();
    paths
        .iter()
        .map(|p| p.iter().map(|s| s.to_string()).collect())
        .collect()
}

/// DIVERGENCE 1 — strictness. Ties on consecutive links are valid to the
/// DFS and must be valid here.
#[test]
fn equal_timestamps_along_the_chain_are_accepted() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // A tie at each link in turn, and then all six equal.
    for ts in [
        [10, 10, 30, 40, 50, 60], // t_ab == t_ac
        [10, 20, 20, 40, 50, 60], // t_ac == t_ad
        [10, 20, 30, 30, 50, 60], // t_ad == t_bc
        [10, 20, 30, 40, 40, 60], // t_bc == t_bd
        [10, 20, 30, 40, 50, 50], // t_bd == t_cd
        [10, 10, 10, 10, 10, 10], // all in one second
    ] {
        assert_eq!(
            via_operator(&k4_with(ts), None).len(),
            1,
            "ties are valid under the DFS's non-strict floor: {ts:?}"
        );
    }
    // A genuinely backwards link still rejects.
    assert_eq!(
        via_operator(&k4_with([10, 20, 30, 25, 50, 60]), None).len(),
        0,
        "t_bc strictly before t_ad must not match"
    );
}

/// DIVERGENCE 2 — window bounds. Inclusive upper bound, as in the DFS.
#[test]
fn the_window_upper_bound_is_inclusive() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let g = k4_with([200, 200, 200, 200, 200, 200]);
    assert_eq!(
        via_operator(&g, Some((100, 200))).len(),
        1,
        "edges exactly on t_hi are inside an inclusive window"
    );
    assert_eq!(
        via_operator(&g, Some((100, 199))).len(),
        0,
        "t_hi = 199 must exclude edges at 200"
    );
}

/// DIVERGENCE 3 — window coverage. All six edges are checked, not only the
/// first. This was the over-reporting one: five of six edges were unbounded
/// above.
#[test]
fn later_edges_outside_the_window_are_no_longer_emitted() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // First edge inside [100,200]; the other five far in the future.
    assert_eq!(
        via_operator(&k4_with([150, 5_000, 6_000, 7_000, 8_000, 9_000]), Some((100, 200))).len(),
        0,
        "five edges up to 45x outside the requested window must not be \
         emitted as a match inside it"
    );
    assert_eq!(
        via_operator(&k4_with([150, 5_000, 6_000, 7_000, 8_000, 9_000]), Some((100, 10_000))).len(),
        1,
        "with the window covering every edge the same clique matches"
    );
}

/// DIVERGENCE 4 — multi-edge. A parallel edge with a lower timestamp must
/// not hide an otherwise valid clique.
#[test]
fn a_valid_combination_of_parallel_edges_is_found() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut g = k4_with([10, 20, 30, 40, 50, 60]);
    // A decoy a->c edge earlier than t_ab: min(t_ac) would now be 5, which
    // fails `t_ac >= t_ab` — but the real 20 still works.
    g.add_relation(Relation::new("a", "c", RelationType::Connect, 5)).unwrap();
    g.sort_edges_by_timestamp().unwrap();
    assert_eq!(
        via_operator(&g, None).len(),
        1,
        "an early parallel a->c must not hide the valid (10,20,30,40,50,60) \
         clique — that was the min-timestamp bug"
    );
}

/// DIVERGENCE 5 — THE K4-ONLY ONE. Self-loops must not produce degenerate
/// "cliques" spanning fewer than four distinct vertices. The SIMD variants
/// had no distinctness guard; strictness was masking it by accident, so
/// relaxing strictness without adding the guards would have surfaced these.
#[test]
fn self_loops_do_not_produce_degenerate_cliques() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut g = k4_with([10, 20, 30, 40, 50, 60]);
    // Self-loops of exactly the kind the single-endpoint ingest fallback
    // emits for events that name only one entity.
    for v in ["a", "b", "c", "d"] {
        g.add_relation(Relation::new(v, v, RelationType::Connect, 15)).unwrap();
    }
    g.sort_edges_by_timestamp().unwrap();

    let got = via_operator(&g, None);
    for tuple in &got {
        let distinct: BTreeSet<&String> = tuple.iter().collect();
        assert_eq!(
            distinct.len(),
            4,
            "a 4-clique must span four DISTINCT vertices, got {tuple:?}"
        );
    }
    assert_eq!(got.len(), 1, "still exactly the one real clique, got {got:?}");
}

// ── The gate: an independent reference implementation ──

/// Brute-force "is there a time-respecting 4-clique on (a,b,c,d)?",
/// written directly against the graph's relations and sharing no code with
/// any enumerator variant — the pre-existing naive/simd/par parity test
/// compares three encodings of the SAME predicate, so it cannot catch a
/// wrong shared premise, which is what all five defects were.
fn reference_k4s(g: &GraphHunter, tw: Option<(i64, i64)>) -> BTreeSet<Vec<String>> {
    let (lo, hi) = tw.unwrap_or((i64::MIN, i64::MAX));
    let (entities, relations) = g.to_snapshot();
    let ids: Vec<String> = entities.iter().map(|e| e.id.clone()).collect();

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
    // Earliest stamp at or after `floor`, or None.
    let succ = |v: &[i64], floor: i64| -> Option<i64> {
        v.iter().copied().find(|&t| t >= floor)
    };

    let mut out = BTreeSet::new();
    for a in &ids {
        for b in &ids {
            if b == a {
                continue;
            }
            for c in &ids {
                if c == a || c == b {
                    continue;
                }
                for d in &ids {
                    if d == a || d == b || d == c {
                        continue;
                    }
                    let (ab, ac, ad) = (stamps(a, b), stamps(a, c), stamps(a, d));
                    let (bc, bd, cd) = (stamps(b, c), stamps(b, d), stamps(c, d));
                    // Greedy along the chain, which is optimal for a chain.
                    let ok = (|| {
                        let t1 = *ab.first()?;
                        let t2 = succ(&ac, t1)?;
                        let t3 = succ(&ad, t2)?;
                        let t4 = succ(&bc, t3)?;
                        let t5 = succ(&bd, t4)?;
                        succ(&cd, t5)?;
                        Some(())
                    })()
                    .is_some();
                    if ok {
                        out.insert(vec![a.clone(), b.clone(), c.clone(), d.clone()]);
                    }
                }
            }
        }
    }
    out
}

/// THE GATE. Deterministic pseudo-random graphs dense in exactly what
/// broke the operator: parallel edges, duplicate timestamps, self-loops
/// and windows.
#[test]
fn operator_matches_an_independent_reference_across_random_graphs() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut state: u64 = 0x2026_08_16_04;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for case in 0..30u32 {
        let n = 4 + (next() % 3) as usize; // 4..6 vertices
        let mut g = GraphHunter::new();
        for i in 0..n {
            g.add_entity(Entity::new(format!("v{i}"), EntityType::Host)).unwrap();
        }
        // Dense enough that 4-cliques actually occur, with a small stamp
        // range so ties and parallel edges are frequent.
        let edges = 14 + (next() % 12) as usize;
        for _ in 0..edges {
            let s = (next() % n as u64) as usize;
            let d = (next() % n as u64) as usize;
            let t = (next() % 6) as i64 * 10;
            // Self-loops are ALLOWED here on purpose — they are what the
            // distinctness guards exist for.
            g.add_relation(Relation::new(
                format!("v{s}"),
                format!("v{d}"),
                RelationType::Connect,
                t,
            ))
            .unwrap();
        }
        g.sort_edges_by_timestamp().unwrap();

        let tw = if case % 2 == 0 { None } else { Some((10i64, 40i64)) };

        clear_flags();
        // SAFETY: ENV_LOCK held.
        unsafe { std::env::set_var("GRAPHHUNTER_K4_LFTJ", "1") };
        let (paths, truncated) = g
            .search_temporal_pattern(&k4_hypothesis(), tw, None)
            .expect("operator search");
        clear_flags();
        assert!(!truncated, "case {case}: cap must not interfere");

        let got: BTreeSet<Vec<String>> = paths
            .iter()
            .map(|p| p.iter().map(|s| s.to_string()).collect())
            .collect();
        let want = reference_k4s(&g, tw);

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
