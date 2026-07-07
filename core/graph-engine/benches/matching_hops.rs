//! F8 — multi-hop matching benchmark.
//!
//! Measures `search_temporal_pattern` latency for 2, 3, and 4-hop
//! hypotheses over random graphs sized |V| ∈ {1 000, 10 000} with a
//! fixed branching factor. This is the chart the paper cites when
//! comparing GraphHunter's pruning to a naive DFS — the CI-friendly
//! sizes exist so `cargo bench` completes in minutes, not hours; larger
//! sweeps (|V|=100 000, branching ∈ {8, 32}) run manually via
//! `BENCH_LARGE=1 cargo bench --bench matching_hops` (see env-var
//! block below).
//!
//! Run: `cargo bench --bench matching_hops`

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use graph_hunter_core::{
    Entity, EntityType, GraphHunter, Hypothesis, HypothesisStep, Relation, RelationType,
};

/// Build a layered graph with `layers` entity types arranged in a
/// linear type-chain (IP→Host→User→Process→File), `nodes_per_layer`
/// entities per type, and a fixed `branching` out-degree per node.
/// Timestamps increase monotonically so the DFS's temporal ordering
/// logic stays on the happy path.
fn build_layered_graph(layers: usize, nodes_per_layer: usize, branching: usize) -> GraphHunter {
    let types = [
        EntityType::IP,
        EntityType::Host,
        EntityType::User,
        EntityType::Process,
        EntityType::File,
    ];
    let rels = [
        RelationType::Connect,
        RelationType::Auth,
        RelationType::Execute,
        RelationType::Write,
    ];
    assert!(layers <= types.len(), "max 5 layers");
    let mut g = GraphHunter::new();
    // Seed entities
    for (layer_idx, t) in types.iter().take(layers).enumerate() {
        for n in 0..nodes_per_layer {
            g.add_entity(Entity::new(&format!("L{layer_idx}_N{n}"), t.clone()))
                .unwrap();
        }
    }
    // Seed edges between consecutive layers; each src fans out to
    // `branching` dsts deterministically.
    let mut ts: i64 = 1_000;
    for layer_idx in 0..(layers.saturating_sub(1)) {
        let rel = rels[layer_idx.min(rels.len() - 1)].clone();
        for src in 0..nodes_per_layer {
            for k in 0..branching {
                let dst = (src * branching + k) % nodes_per_layer;
                let _ = g.add_relation(Relation::new(
                    &format!("L{layer_idx}_N{src}"),
                    &format!("L{}_N{dst}", layer_idx + 1),
                    rel.clone(),
                    ts,
                ));
                ts += 1;
            }
        }
    }
    g.sort_edges_by_timestamp().unwrap();
    g
}

fn build_hop_hypothesis(hops: usize) -> Hypothesis {
    let types = [
        EntityType::IP,
        EntityType::Host,
        EntityType::User,
        EntityType::Process,
        EntityType::File,
    ];
    let rels = [
        RelationType::Connect,
        RelationType::Auth,
        RelationType::Execute,
        RelationType::Write,
    ];
    let mut h = Hypothesis::new("hop-probe");
    for i in 0..hops {
        h = h.add_step(HypothesisStep::new(
            types[i].clone(),
            rels[i.min(rels.len() - 1)].clone(),
            types[i + 1].clone(),
        ));
    }
    h
}

fn bench_hops(c: &mut Criterion) {
    let big = std::env::var("BENCH_LARGE").ok().is_some();
    let sizes: &[usize] = if big {
        &[1_000, 10_000, 100_000]
    } else {
        &[1_000, 10_000]
    };
    let branchings: &[usize] = if big { &[2, 8, 32] } else { &[2] };

    for &hops in &[2usize, 3, 4] {
        let mut group = c.benchmark_group(format!("match-{hops}hop"));
        for &n in sizes {
            for &b_factor in branchings {
                // Cap the 4-hop × 10k × 32-branching combo that would
                // blow up in interactive bench runs.
                if hops == 4 && n >= 10_000 && b_factor >= 32 {
                    continue;
                }
                let g = build_layered_graph(hops + 1, n, b_factor);
                let h = build_hop_hypothesis(hops);
                let label = format!("V={n},b={b_factor}");
                group.bench_with_input(BenchmarkId::from_parameter(&label), &label, |b, _| {
                    b.iter(|| {
                        // `Some(usize::MAX)` so the search never short-circuits;
                        // we want to measure the cost of fully enumerating the
                        // matchset, not the cost of stopping at 10K.
                        let (paths, _) = g
                            .search_temporal_pattern(black_box(&h), None, Some(usize::MAX))
                            .unwrap();
                        black_box(paths)
                    });
                });
            }
        }
        group.finish();
    }
}

criterion_group!(benches, bench_hops);
criterion_main!(benches);
