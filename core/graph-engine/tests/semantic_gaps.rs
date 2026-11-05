//! Probes for six places where a read of the code suggested an operator or
//! a prune diverges from the hunt semantics the DFS implements:
//! typed steps, inclusive window on every edge, non-strict temporal order
//! (`τ(eᵢ₊₁) ≥ τ(eᵢ) − δ`), k-simplicity, and post-filters (`WITHIN`,
//! `HAVING`) applied to whatever the matcher returns.
//!
//! Each test asserts the semantics, not the current behaviour: a failure
//! confirms the divergence, a pass rules it out.

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

fn graph(
    entities: &[(&str, EntityType)],
    edges: &[(&str, &str, RelationType, i64)],
) -> GraphHunter {
    let mut g = GraphHunter::new();
    for (id, t) in entities {
        g.add_entity(Entity::new(*id, t.clone())).unwrap();
    }
    for (s, d, r, t) in edges {
        g.add_relation(Relation::new(*s, *d, r.clone(), *t))
            .unwrap();
    }
    g.sort_edges_by_timestamp().unwrap();
    g
}

fn chain(name: &str, steps: &[(EntityType, RelationType, EntityType)]) -> Hypothesis {
    let mut h = Hypothesis::new(name);
    for (o, r, d) in steps {
        h = h.add_step(HypothesisStep::new(o.clone(), r.clone(), d.clone()));
    }
    h
}

fn hunt(g: &GraphHunter, h: &Hypothesis, tw: Option<(i64, i64)>) -> Vec<Vec<String>> {
    let (paths, _) = g.search_temporal_pattern(h, tw, None).expect("search");
    paths
        .iter()
        .map(|p| p.iter().map(|s| s.to_string()).collect())
        .collect()
}

/// Point 1 — symmetry breaking on a directed graph. The chain
/// `Host -[Connect]-> Host -[Connect]-> Host` is palindromic, so the DFS
/// keeps only paths whose first interned id is smaller than the last. On a
/// directed graph the reverse path is not a match, so a path whose ids run
/// the other way has no mirror to stand in for it.
#[test]
fn palindromic_chain_keeps_a_match_without_a_mirror() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_flags();
    // Interned in reverse: "c" gets the smallest id, "a" the largest.
    let g = graph(
        &[
            ("c", EntityType::Host),
            ("b", EntityType::Host),
            ("a", EntityType::Host),
        ],
        &[
            ("a", "b", RelationType::Connect, 10),
            ("b", "c", RelationType::Connect, 20),
        ],
    );
    let h = chain(
        "two-hop lateral",
        &[
            (EntityType::Host, RelationType::Connect, EntityType::Host),
            (EntityType::Host, RelationType::Connect, EntityType::Host),
        ],
    );
    assert_eq!(
        hunt(&g, &h, None),
        vec![vec!["a".to_string(), "b".into(), "c".into()]],
        "a->b->c is the only match and has no reverse in the graph"
    );
}

/// Point 2 — the k-hop reachability prune looks MAX_DEPTH = 4 hops ahead.
/// A five-step hypothesis whose final type is first reachable at distance
/// five must not lose its start.
#[test]
fn five_step_chain_is_not_pruned_by_khop_reach() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_flags();
    let g = graph(
        &[
            ("u", EntityType::User),
            ("h", EntityType::Host),
            ("p", EntityType::Process),
            ("d", EntityType::Domain),
            ("i", EntityType::IP),
            ("w", EntityType::URL),
        ],
        &[
            ("u", "h", RelationType::Auth, 10),
            ("h", "p", RelationType::Execute, 20),
            ("p", "d", RelationType::DNS, 30),
            ("d", "i", RelationType::Connect, 40),
            ("i", "w", RelationType::Connect, 50),
        ],
    );
    let h = chain(
        "five steps",
        &[
            (EntityType::User, RelationType::Auth, EntityType::Host),
            (EntityType::Host, RelationType::Execute, EntityType::Process),
            (EntityType::Process, RelationType::DNS, EntityType::Domain),
            (EntityType::Domain, RelationType::Connect, EntityType::IP),
            (EntityType::IP, RelationType::Connect, EntityType::URL),
        ],
    );
    let mut four = h.clone();
    four.steps.pop();
    assert_eq!(
        hunt(&g, &four, None).len(),
        1,
        "control: the 4-step prefix matches"
    );
    assert_eq!(
        hunt(&g, &h, None).len(),
        1,
        "URL is reachable from u at distance 5"
    );
}

/// Point 3 — the window is inclusive on both ends for every edge. The
/// k-hop prune's temporal check must not treat it as `[lo, hi)`.
#[test]
fn first_edge_on_the_window_upper_bound_is_kept() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_flags();
    let g = graph(
        &[
            ("u", EntityType::User),
            ("h", EntityType::Host),
            ("p", EntityType::Process),
        ],
        &[
            ("u", "h", RelationType::Auth, 200),
            ("h", "p", RelationType::Execute, 200),
        ],
    );
    let h = chain(
        "logon then exec",
        &[
            (EntityType::User, RelationType::Auth, EntityType::Host),
            (EntityType::Host, RelationType::Execute, EntityType::Process),
        ],
    );
    assert_eq!(
        hunt(&g, &h, Some((100, 201))).len(),
        1,
        "control: hi just past the edges"
    );
    let mut one = h.clone();
    one.steps.pop();
    assert_eq!(
        hunt(&g, &one, Some((100, 200))).len(),
        1,
        "control: one step (k-hop prune skipped) keeps an edge on t_hi"
    );
    assert_eq!(
        hunt(&g, &h, Some((100, 200))).len(),
        1,
        "both edges sit exactly on t_hi of an inclusive window"
    );
}

/// Point 4 — the Yannakakis route (default-on in the shipped apps) must
/// accept equal timestamps on consecutive steps, as the DFS does.
#[test]
fn yannakakis_accepts_same_second_steps_like_the_dfs() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_flags();
    let g = graph(
        &[
            ("u", EntityType::User),
            ("h", EntityType::Host),
            ("p", EntityType::Process),
        ],
        &[
            ("u", "h", RelationType::Auth, 100),
            ("h", "p", RelationType::Execute, 100),
        ],
    );
    let h = chain(
        "logon then exec",
        &[
            (EntityType::User, RelationType::Auth, EntityType::Host),
            (EntityType::Host, RelationType::Execute, EntityType::Process),
        ],
    );
    let dfs = hunt(&g, &h, None);
    // SAFETY: ENV_LOCK held.
    unsafe { std::env::set_var("GRAPHHUNTER_YANNAKAKIS", "1") };
    let yan = hunt(&g, &h, None);
    clear_flags();
    assert_eq!(dfs.len(), 1, "control: the DFS accepts the tie");
    assert_eq!(yan, dfs, "Yannakakis must return what the DFS returns");
}

/// Point 5 — `WITHIN` is a post-filter on the matcher's output; turning
/// on gap tolerance must not switch it off.
#[test]
fn within_still_applies_when_gap_tolerance_is_on() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_flags();
    let g = graph(
        &[
            ("u", EntityType::User),
            ("h", EntityType::Host),
            ("p", EntityType::Process),
        ],
        &[
            // Not 0: path_time_span skips timestamp 0 (atemporal facts).
            ("u", "h", RelationType::Auth, 1),
            ("h", "p", RelationType::Execute, 1_001),
        ],
    );
    let mut h = chain(
        "logon then exec",
        &[
            (EntityType::User, RelationType::Auth, EntityType::Host),
            (EntityType::Host, RelationType::Execute, EntityType::Process),
        ],
    );
    h.window_seconds = Some(10);
    assert_eq!(
        hunt(&g, &h, None).len(),
        0,
        "control: 1000 s span fails WITHIN 10"
    );
    let gapped = h.with_max_gap(1);
    assert_eq!(
        hunt(&g, &gapped, None).len(),
        0,
        "the same span must still fail WITHIN 10 with GAP 1"
    );
}

/// Point 6 — the triangle operator must not report a degenerate triangle
/// built from a self-loop (fewer than three distinct vertices), which the
/// ingest fallback does produce in real graphs.
#[test]
fn triangle_operator_ignores_self_loop_degenerates() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_flags();
    // a->b, b->b, a->b: with c = b the forward-triangle predicate
    // t_ab <= t_bc <= t_ac holds (10 <= 20 <= 30).
    let g = graph(
        &[("a", EntityType::Host), ("b", EntityType::Host)],
        &[
            ("a", "b", RelationType::Connect, 10),
            ("b", "b", RelationType::Connect, 20),
            ("a", "b", RelationType::Connect, 30),
        ],
    );
    let h = chain(
        "triangle probe",
        &[
            (EntityType::Host, RelationType::Connect, EntityType::Host),
            (EntityType::Host, RelationType::Connect, EntityType::Host),
            (EntityType::Host, RelationType::Connect, EntityType::Host),
        ],
    );
    // SAFETY: ENV_LOCK held.
    unsafe { std::env::set_var("GRAPHHUNTER_TRIANGLE_LFTJ", "1") };
    let found = hunt(&g, &h, None);
    clear_flags();
    assert!(
        found.is_empty(),
        "two distinct vertices cannot form a triangle, got {found:?}"
    );
}
