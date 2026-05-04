//! Fase 2 — negative / safety-invariant tests for the FFI wrappers.
//!
//! Each test documents a boundary condition the wrappers handle. The
//! positive-path equivalence tests live in `simd_matcher_test.rs` and
//! `equivalence_proptest.rs`; this file is exclusively for cases where
//! the caller supplies input that violates a pre-condition or the C
//! side returns a sentinel we must translate back into a safe Rust
//! outcome.
//!
//! Limitation: the panic pathway of `ensure_abi_compatible` is not
//! directly exercised here. Triggering it would require either (a) a
//! compile-time mismatch between `EXPECTED_ABI_VERSION` and the C
//! header (caught by `test_abi_version_matches_expected` in
//! `simd_matcher_test.rs`) or (b) a mock symbol, which is heavier than
//! the guarantee is worth — the assertion panics once per process via
//! `std::sync::Once`, so in-process retry tests are impossible. The
//! existing positive test is sufficient evidence that the check runs.

#![cfg(feature = "simd")]

use graph_hunter_core::{
    Entity, EntityType, GraphHunter, Hypothesis, HypothesisStep, Relation, RelationType,
};
use graph_hunter_matcher_ffi::ffi;

// ------------------------------------------------------------------
// Empty-graph boundary: the wrapper must not crash and must return an
// empty result set. Exercises the null/empty handling in
// `run_simd_search` + `GmResults::count` == 0 path.
// ------------------------------------------------------------------
#[test]
fn empty_graph_returns_empty_results() {
    let g = GraphHunter::new();
    let hypothesis = Hypothesis::new("anything").add_step(HypothesisStep::new(
        EntityType::User,
        RelationType::Execute,
        EntityType::Process,
    ));

    let cached = ffi::build_gm_graph(&g);
    let out = ffi::run_simd_search(&cached, &g.interner, &hypothesis, None, Some(1000));
    assert!(out.is_empty(), "empty graph produced {} results", out.len());
}

// ------------------------------------------------------------------
// Unknown `EntityType::Other(name)` falls back to GM_ENTITY_ANY
// (u8 tag 254). This is documented wildcard behavior — the read-only
// lookup returns 254 when the name is not registered, and the C side
// treats 254 as "any entity type", so an unregistered Other collapses
// into a wildcard match. This test pins that behavior so a future
// change from "wildcard" to "no match" is caught.
// ------------------------------------------------------------------
#[test]
fn unknown_other_entity_type_becomes_wildcard() {
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("u1", EntityType::User)).unwrap();
    g.add_entity(Entity::new("p1", EntityType::Process))
        .unwrap();
    g.add_relation(Relation::new("u1", "p1", RelationType::Execute, 100))
        .unwrap();
    g.sort_edges_by_timestamp().unwrap();

    let hypothesis = Hypothesis::new("unknown-step").add_step(HypothesisStep::new(
        EntityType::Other("DoesNotExistInGraph".to_string()),
        RelationType::Execute,
        EntityType::Process,
    ));

    let cached = ffi::build_gm_graph(&g);
    let out = ffi::run_simd_search(&cached, &g.interner, &hypothesis, None, Some(1000));
    assert!(
        !out.is_empty(),
        "unknown Other should fall back to GM_ENTITY_ANY and match; got 0 paths"
    );
}

// ------------------------------------------------------------------
// `max_results = Some(1)` caps the returned set. The graph below has
// three candidate paths under the hypothesis; supplying `Some(1)` must
// yield at most one. Documents the cap-on-result-count contract.
//
// Note: `Some(0)` is NOT tested as "zero paths" because the current C
// implementation treats 0 as uncapped. If that behavior ever changes
// to "zero means zero", add a dedicated test — until then, the
// meaningful caller contract is "Some(N>0) caps at N".
// ------------------------------------------------------------------
#[test]
fn max_results_one_caps_result_set() {
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("u1", EntityType::User)).unwrap();
    g.add_entity(Entity::new("p1", EntityType::Process))
        .unwrap();
    g.add_entity(Entity::new("p2", EntityType::Process))
        .unwrap();
    g.add_entity(Entity::new("p3", EntityType::Process))
        .unwrap();
    g.add_relation(Relation::new("u1", "p1", RelationType::Execute, 100))
        .unwrap();
    g.add_relation(Relation::new("u1", "p2", RelationType::Execute, 200))
        .unwrap();
    g.add_relation(Relation::new("u1", "p3", RelationType::Execute, 300))
        .unwrap();
    g.sort_edges_by_timestamp().unwrap();

    let hypothesis = Hypothesis::new("capped").add_step(HypothesisStep::new(
        EntityType::User,
        RelationType::Execute,
        EntityType::Process,
    ));

    let cached = ffi::build_gm_graph(&g);
    let out = ffi::run_simd_search(&cached, &g.interner, &hypothesis, None, Some(1));
    assert!(
        out.len() <= 1,
        "max_results=1 returned {} paths, expected at most 1",
        out.len()
    );
    assert!(
        !out.is_empty(),
        "max_results=1 returned 0 paths on a graph with 3 candidates"
    );
}

// ------------------------------------------------------------------
// Time window that excludes every edge: the post-filter in
// `run_simd_search` compares each returned path's timestamps against
// the window and drops matches with any timestamp outside. Supplying
// a window in the far past must yield an empty set even when the C
// matcher finds candidates.
// ------------------------------------------------------------------
#[test]
fn time_window_far_in_past_excludes_all() {
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("u1", EntityType::User)).unwrap();
    g.add_entity(Entity::new("p1", EntityType::Process))
        .unwrap();
    g.add_relation(Relation::new("u1", "p1", RelationType::Execute, 1_000_000))
        .unwrap();
    g.sort_edges_by_timestamp().unwrap();

    let hypothesis = Hypothesis::new("window-excluded").add_step(HypothesisStep::new(
        EntityType::User,
        RelationType::Execute,
        EntityType::Process,
    ));

    let cached = ffi::build_gm_graph(&g);
    let out = ffi::run_simd_search(
        &cached,
        &g.interner,
        &hypothesis,
        Some((0, 100)),
        Some(1000),
    );
    assert!(
        out.is_empty(),
        "window [0,100] matched an edge at ts=1_000_000 ({} paths)",
        out.len()
    );
}

// ------------------------------------------------------------------
// "Invalid pattern" path: a hypothesis whose types cannot appear in
// the graph at all must collapse to an empty result set. The C side
// represents this as a matcher that either fails to allocate (null
// handle from `gm_matcher_new`) or runs to completion with 0 rows.
// Both code paths land in the same `Vec::new()` at the wrapper; this
// test pins that behavior so a future refactor to a typed error
// (`Err(FfiError::InvalidPattern)`) is a deliberate, visible change.
// ------------------------------------------------------------------
#[test]
fn invalid_pattern_shape_returns_empty_vec() {
    let mut g = GraphHunter::new();
    // Graph contains only User→Process via Execute. The hypothesis
    // below asks for File→Domain via DNS — no node of type File
    // exists, so the matcher either refuses to start or runs with
    // zero candidate roots.
    g.add_entity(Entity::new("u1", EntityType::User)).unwrap();
    g.add_entity(Entity::new("p1", EntityType::Process))
        .unwrap();
    g.add_relation(Relation::new("u1", "p1", RelationType::Execute, 100))
        .unwrap();
    g.sort_edges_by_timestamp().unwrap();

    let hypothesis = Hypothesis::new("unmatched-types").add_step(HypothesisStep::new(
        EntityType::File,
        RelationType::DNS,
        EntityType::Domain,
    ));

    let cached = ffi::build_gm_graph(&g);
    let out = ffi::run_simd_search(&cached, &g.interner, &hypothesis, None, Some(1000));
    assert!(
        out.is_empty(),
        "invalid pattern (File→Domain) against a User→Process-only graph \
         produced {} paths, expected 0",
        out.len()
    );
}

// ------------------------------------------------------------------
// Null-handle path inside the matcher: when the C side's
// `gm_matcher_new` returns null (e.g. the graph has zero nodes of the
// start type), the wrapper must translate that to an empty Vec rather
// than panicking or dereferencing null. This complements the
// `invalid_pattern_shape_returns_empty_vec` case above — here the
// graph *has* edges, but none of the right start type.
// ------------------------------------------------------------------
#[test]
fn matcher_on_graph_without_start_type_returns_empty() {
    let mut g = GraphHunter::new();
    // Only File and Domain nodes — no User, no Process.
    g.add_entity(Entity::new("f1", EntityType::File)).unwrap();
    g.add_entity(Entity::new("d1", EntityType::Domain)).unwrap();
    g.add_relation(Relation::new("f1", "d1", RelationType::DNS, 100))
        .unwrap();
    g.sort_edges_by_timestamp().unwrap();

    // Hypothesis starts at User — no User node exists, so the matcher
    // cannot seed any root. Must return empty, not panic.
    let hypothesis = Hypothesis::new("no-start").add_step(HypothesisStep::new(
        EntityType::User,
        RelationType::Execute,
        EntityType::Process,
    ));

    let cached = ffi::build_gm_graph(&g);
    let out = ffi::run_simd_search(&cached, &g.interner, &hypothesis, None, Some(1000));
    assert!(
        out.is_empty(),
        "matcher with no graph nodes of the start type produced {} paths",
        out.len()
    );
}

// ------------------------------------------------------------------
// Double-drop compile-time proof. `CachedSimdGraph` is neither Clone
// nor Copy (see its rustdoc `compile_fail` example); ownership is
// therefore always single. The best runtime evidence we can add is
// that rebuilding the cache against the same graph is legal, works,
// and the two `CachedSimdGraph` instances are independent — each
// owning its own C++ handle with its own Drop. The compile-fail
// doctest on the type is the primary proof; this runtime test is a
// sanity gate that the Drop implementation is actually exercised.
// ------------------------------------------------------------------
#[test]
fn independent_cached_graphs_drop_cleanly() {
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("u1", EntityType::User)).unwrap();
    g.add_entity(Entity::new("p1", EntityType::Process))
        .unwrap();
    g.add_relation(Relation::new("u1", "p1", RelationType::Execute, 100))
        .unwrap();
    g.sort_edges_by_timestamp().unwrap();

    let hypothesis = Hypothesis::new("dup").add_step(HypothesisStep::new(
        EntityType::User,
        RelationType::Execute,
        EntityType::Process,
    ));

    // Build twice. If CachedSimdGraph were erroneously Clone/Copy,
    // `gm_graph_free` would double-free one handle on scope exit and
    // the process would abort in the C++ runtime (ASan / glibc). The
    // fact that both caches run to completion AND the test process
    // exits cleanly is indirect evidence that Drop is single-owner.
    let cached_a = ffi::build_gm_graph(&g);
    let cached_b = ffi::build_gm_graph(&g);

    let a = ffi::run_simd_search(&cached_a, &g.interner, &hypothesis, None, Some(10));
    let b = ffi::run_simd_search(&cached_b, &g.interner, &hypothesis, None, Some(10));
    assert_eq!(
        a.len(),
        b.len(),
        "independent caches produced different result counts"
    );
    // cached_a and cached_b drop here, each freeing its own handle.
}
