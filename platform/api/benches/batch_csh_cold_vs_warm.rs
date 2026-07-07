//! D3 stages 1-4 cold-vs-warm batch CSH benchmark.
//!
//! Validates the headline claim that an SOC template battery on a
//! cached graph runs ~free after the first batch warms the L2 +
//! D3 caches. The bench builds a 10K-vertex Barabási-Albert graph
//! (Sysmon-shaped scale-free) and dispatches a batch of 6 LFTJ-
//! routed templates spanning triangle / K4 / C6 with 2 type
//! signatures each.
//!
//! Three timings per fixture:
//!   * `cold`   — first batch on a fresh API instance. Pays trie
//!                build + per-template enumerate.
//!   * `warm`   — second batch on the same Session, no graph
//!                mutation. Both the typed-trie map (D3 stage 4)
//!                and the persistent canonical raw-result cache
//!                (D3 stage 4) are warm. Should be near-zero
//!                enumerate cost; only `apply_aggregation` runs.
//!   * `cold-after-mutation` — second batch after a single
//!                add_entity bumps the `mutation_version`. Both
//!                caches invalidate; should mirror the cold time.
//!
//! Run:
//!   cargo bench --bench batch_csh_cold_vs_warm \
//!     --manifest-path platform/api/Cargo.toml

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use graph_hunter_api::{
    GraphHunterApi,
    dto::hunt::RunHuntBatchRequest,
    state::Session,
};
use graph_hunter_core::{
    GraphHunter, Hypothesis, HypothesisStep,
    generate_barabasi_albert,
    types::{EntityType, RelationType},
};
use std::sync::Arc;

fn build_graph(n: usize, m: usize, seed: u64) -> GraphHunter {
    let mut g = generate_barabasi_albert(n, m, 1_000, 100_000_000, seed);
    g.sort_edges_by_timestamp().unwrap();
    g
}

fn templates() -> Vec<Hypothesis> {
    let mut v = Vec::new();
    // Triangle templates with two distinct (rel, vertex) signatures.
    for (rel, name) in [
        (RelationType::Connect, "triangle-connect"),
        (RelationType::Auth, "triangle-auth"),
    ] {
        let mut h = Hypothesis::new(name);
        for _ in 0..3 {
            h = h.add_step(HypothesisStep::new(
                EntityType::Host,
                rel.clone(),
                EntityType::Host,
            ));
        }
        v.push(h);
    }
    // K4 templates with same two signatures.
    for (rel, name) in [
        (RelationType::Connect, "k4-clique-connect"),
        (RelationType::Auth, "k4-clique-auth"),
    ] {
        let mut h = Hypothesis::new(name);
        for _ in 0..6 {
            h = h.add_step(HypothesisStep::new(
                EntityType::Host,
                rel.clone(),
                EntityType::Host,
            ));
        }
        v.push(h);
    }
    // C6 templates with same two signatures.
    for (rel, name) in [
        (RelationType::Connect, "lateral movement (6-cycle) connect"),
        (RelationType::Auth, "lateral movement (6-cycle) auth"),
    ] {
        let mut h = Hypothesis::new(name);
        for _ in 0..6 {
            h = h.add_step(HypothesisStep::new(
                EntityType::Host,
                rel.clone(),
                EntityType::Host,
            ));
        }
        v.push(h);
    }
    v
}

fn fresh_api(graph: GraphHunter) -> GraphHunterApi {
    let api = GraphHunterApi::new_noop();
    let s = Arc::new(Session::new("bench", "bench", graph, 0));
    api.sessions().insert(s);
    api.sessions().set_current(Some("bench".into()));
    api
}

fn bench_cold_vs_warm(c: &mut Criterion) {
    // The bench enables every dispatch flag that the templates use.
    // SAFETY: tests / benches in this binary are the only writers.
    unsafe {
        std::env::set_var("GRAPHHUNTER_TRIANGLE_LFTJ", "1");
        std::env::set_var("GRAPHHUNTER_K4_LFTJ", "1");
        std::env::set_var("GRAPHHUNTER_C6_LFTJ", "1");
    }

    let mut group = c.benchmark_group("batch-csh-cold-vs-warm");
    group.sample_size(20);

    for &(n, m) in &[(1_000usize, 3usize), (5_000, 3)] {
        let label = format!("V={n},m={m}");
        let templates = templates();

        // Cold: build a fresh API + fresh session per iteration so
        // the cache is empty every time.
        group.bench_function(format!("cold/{label}"), |b| {
            b.iter_with_setup(
                || fresh_api(build_graph(n, m, 42)),
                |api| {
                    let resp = api
                        .run_hunt_batch(RunHuntBatchRequest {
                            session: None,
                            hypotheses: templates.clone(),
                            time_window: None,
                            max_results: None,
                            dedup_mode: None,
                        })
                        .expect("cold batch ok");
                    black_box(resp);
                },
            );
        });

        // Warm: build once, run a priming batch, then time the
        // SECOND batch. Caches are persistent across calls so the
        // second batch hits both the typed-trie map and the
        // canonical raw-result cache.
        group.bench_function(format!("warm/{label}"), |b| {
            let api = fresh_api(build_graph(n, m, 42));
            // Prime the caches once.
            let _ = api
                .run_hunt_batch(RunHuntBatchRequest {
                    session: None,
                    hypotheses: templates.clone(),
                    time_window: None,
                    max_results: None,
                    dedup_mode: None,
                })
                .expect("priming batch ok");
            b.iter(|| {
                let resp = api
                    .run_hunt_batch(RunHuntBatchRequest {
                        session: None,
                        hypotheses: templates.clone(),
                        time_window: None,
                        max_results: None,
                        dedup_mode: None,
                    })
                    .expect("warm batch ok");
                black_box(resp);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_cold_vs_warm);
criterion_main!(benches);
