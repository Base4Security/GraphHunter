//! F8 — per-path scoring benchmark.
//!
//! Measures `AnomalyScorer::score_path` on paths of 1..=4 nodes over a
//! pre-finalized scorer. This isolates scoring cost from matching
//! cost — combined with `matching_hops.rs`, reviewers can reconstruct
//! what fraction of a hunt's wall-time is spent in each layer.
//!
//! Run: `cargo bench --bench scoring_path`

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use graph_hunter_core::{Entity, EntityType, GraphHunter, Relation, RelationType, ScoringWeights};

/// Build a graph with a realistic frequency-tail plus a pre-finalized
/// `AnomalyScorer`. The paths we bench touch both common and rare
/// nodes so the ER / EdgeR components exercise their non-zero paths.
fn finalized_graph(n_common: usize, n_rare: usize) -> GraphHunter {
    let mut g = GraphHunter::new();
    g.enable_anomaly_scoring(ScoringWeights::default());
    for i in 0..n_common {
        g.add_entity(Entity::new(&format!("c{i}"), EntityType::Host))
            .unwrap();
        g.add_entity(Entity::new(&format!("u{i}"), EntityType::User))
            .unwrap();
        for k in 0..10 {
            g.add_relation(Relation::new(
                &format!("u{i}"),
                &format!("c{i}"),
                RelationType::Auth,
                1000 + k as i64,
            ))
            .unwrap();
        }
    }
    for i in 0..n_rare {
        g.add_entity(Entity::new(&format!("r{i}"), EntityType::Process))
            .unwrap();
        g.add_relation(Relation::new(
            "u0",
            &format!("r{i}"),
            RelationType::Execute,
            5000 + i as i64,
        ))
        .unwrap();
    }
    g.sort_edges_by_timestamp().unwrap();
    g.finalize_anomaly_scorer();
    g
}

fn bench_score_path(c: &mut Criterion) {
    let g = finalized_graph(50, 10);
    let scorer = g.anomaly_scorer.as_ref().expect("scorer finalized");

    let mut group = c.benchmark_group("score-path");
    for &len in &[1usize, 2, 3, 4] {
        let path: Vec<String> = (0..len)
            .map(|i| match i {
                0 => "u0".to_string(),
                1 => "c0".to_string(),
                2 => "r0".to_string(),
                _ => format!("r{}", i - 1),
            })
            .collect();
        group.throughput(Throughput::Elements(len as u64));
        group.bench_with_input(BenchmarkId::from_parameter(len), &len, |b, _| {
            b.iter(|| {
                let (s, bd) = scorer.score_path(black_box(&path), &g);
                black_box((s, bd))
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_score_path);
criterion_main!(benches);
