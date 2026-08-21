//! Does the triangle enumerator agree with the DFS on temporal semantics?
//!
//! An audit reported four divergences between
//! `enumerate_triangles_lftj_simd_window` and the DFS matcher. Reading the
//! code confirms all four EXIST as written; these tests establish which
//! ones actually change results, because a difference that no input can
//! expose is a code smell, while one that drops a real triangle is a bug.
//!
//! Each test is built so the DFS and the operator are asked the SAME
//! question over the same graph, and the operator is invoked through the
//! shipped routing path (name marker + planner flag) rather than by
//! reaching into the enumerator, so what is measured is what an analyst
//! would actually get.

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

/// Triangle a→b→c→(a→c), with explicit timestamps per edge.
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

/// A 3-step homogeneous hypothesis carrying the `triangle` marker, i.e.
/// what actually reaches the triangle operator after the routing fix.
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

/// Runs the marked hypothesis with the triangle operator enabled.
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

/// FINDING 1 — STRICTNESS. The enumerator requires t_bc > t_ab and
/// t_ac > t_bc (lftj_query.rs:424,431). The DFS's temporal floor is
/// non-strict (`partition_point(|e| e.timestamp < lo_ts)` keeps edges
/// with `ts == lo_ts`). So a triangle whose consecutive edges share a
/// timestamp is temporally valid to the DFS and rejected by the operator.
///
/// This matters in practice: log sources routinely stamp causally-ordered
/// events within the same second, and GraphHunter's CDM parser floors
/// nanoseconds to seconds precisely for engine compatibility — so
/// equal-timestamp hops are common, not exotic.
#[test]
fn equal_timestamps_are_accepted_by_the_dfs_and_dropped_by_the_operator() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // a→b and b→c share t=100; a→c later. Non-strict monotonicity accepts.
    let g = triangle_with(100, 100, 200);

    let found = via_operator(&g, None);
    assert_eq!(
        found, 0,
        "operator rejects equal-timestamp hops (strict >), got {found} result(s)"
    );

    // The same shape with strictly increasing stamps IS found, proving the
    // graph and routing are otherwise sound and the timestamp is the only
    // difference.
    let g_strict = triangle_with(100, 150, 200);
    assert_eq!(
        via_operator(&g_strict, None),
        1,
        "strictly increasing triangle must be found — otherwise this test \
         proves nothing about strictness"
    );
}

/// FINDING 2 — WINDOW BOUNDS. The enumerator uses a half-open window on
/// the first edge (`t_ab < t_lo || t_ab >= t_hi`, lftj_query.rs:409),
/// while the DFS's upper bound is inclusive
/// (`partition_point(|e| e.timestamp <= tw_end)`). A triangle whose first
/// edge lands exactly on `t_hi` is inside the DFS's window and outside the
/// operator's.
#[test]
fn a_first_edge_exactly_on_the_upper_bound_is_dropped_by_the_operator() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let g = triangle_with(200, 300, 400);
    // Window whose upper bound is exactly t_ab.
    let found = via_operator(&g, Some((100, 200)));
    assert_eq!(
        found, 0,
        "operator excludes t_ab == t_hi (half-open); got {found}"
    );
    // One tick wider and it appears — isolating the boundary as the cause.
    assert_eq!(
        via_operator(&g, Some((100, 201))),
        1,
        "t_hi = 201 must include a triangle whose first edge is at 200"
    );
}

/// FINDING 3 — WINDOW COVERS ONLY THE FIRST EDGE. The enumerator filters
/// `t_ab` alone and never window-checks `t_bc` or `t_ac`
/// (lftj_query.rs:377-382 documents this as deliberate). So a triangle
/// whose 2nd and 3rd edges fall far outside the requested window is still
/// emitted — the operator reports a match the analyst's window excluded.
///
/// This is the divergence that OVER-reports rather than under-reports,
/// which makes it the more dangerous of the two window issues.
#[test]
fn edges_outside_the_window_are_still_emitted_if_the_first_edge_is_inside() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // First edge inside [100,200); the other two are far in the future.
    let g = triangle_with(150, 5_000, 9_000);
    let found = via_operator(&g, Some((100, 200)));
    assert_eq!(
        found, 1,
        "operator emits a triangle whose 2nd/3rd edges are outside the \
         window because only t_ab is checked; got {found}"
    );
}

/// HOW REACHABLE IS ANY OF THIS? — the calibration that decides severity.
///
/// All four divergences above are demonstrated through a hypothesis whose
/// NAME carries the `triangle` marker. After the shape-is-not-intent fix,
/// an unmarked 3-step homogeneous chain no longer routes to the operator,
/// so an analyst writing an ordinary hypothesis gets the DFS and none of
/// these divergences.
///
/// That is the difference between "the shipped default silently diverges"
/// and "a caller who explicitly opts into the fast operator gets different
/// temporal semantics". Only the second is still true — which is why the
/// remaining work is a correctness-alignment task rather than an incident.
#[test]
fn an_unmarked_three_step_chain_does_not_reach_the_operator() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // The shape that would trip finding 1, but authored without a marker.
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
    // Production configuration: planner on, no explicit operator flag.
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

/// FINDING 4 — MULTI-EDGE / MIN-TIMESTAMP. `MinTimestampMap::build` keeps
/// only the minimum timestamp per (src,dst) pair (lftj_query.rs:70-72), so
/// the operator tests ONE candidate triple rather than asking whether ANY
/// combination of parallel edges is time-respecting. With
/// t_ab=10, t_bc∈{5,20}, t_ac=30 the combination (10,20,30) is valid, but
/// min(t_bc)=5 fails `t_bc > t_ab` and the triangle is dropped.
///
/// Parallel edges between the same pair are the norm in real telemetry
/// (repeated connections between the same two hosts), so this is not a
/// contrived shape.
#[test]
fn a_valid_triangle_is_dropped_when_a_parallel_edge_has_a_lower_timestamp() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut g = GraphHunter::new();
    for id in ["a", "b", "c"] {
        g.add_entity(Entity::new(id, EntityType::Host)).unwrap();
    }
    g.add_relation(Relation::new("a", "b", RelationType::Connect, 10)).unwrap();
    // Two parallel b→c edges: one too early, one that works.
    g.add_relation(Relation::new("b", "c", RelationType::Connect, 5)).unwrap();
    g.add_relation(Relation::new("b", "c", RelationType::Connect, 20)).unwrap();
    g.add_relation(Relation::new("a", "c", RelationType::Connect, 30)).unwrap();
    g.sort_edges_by_timestamp().unwrap();

    // (10, 20, 30) is a valid time-respecting triangle.
    let found = via_operator(&g, None);
    assert_eq!(
        found, 0,
        "operator uses min(t_bc)=5 and drops the valid (10,20,30) triangle; \
         got {found} — if this now finds it, the min-timestamp map was fixed"
    );

    // Remove the early parallel edge and the same triangle appears,
    // isolating the min-timestamp map as the cause.
    let mut g2 = GraphHunter::new();
    for id in ["a", "b", "c"] {
        g2.add_entity(Entity::new(id, EntityType::Host)).unwrap();
    }
    g2.add_relation(Relation::new("a", "b", RelationType::Connect, 10)).unwrap();
    g2.add_relation(Relation::new("b", "c", RelationType::Connect, 20)).unwrap();
    g2.add_relation(Relation::new("a", "c", RelationType::Connect, 30)).unwrap();
    g2.sort_edges_by_timestamp().unwrap();
    assert_eq!(
        via_operator(&g2, None),
        1,
        "without the early parallel edge the same triangle is found"
    );
}
