//! Benchmark: score_and_paginate_paths with DedupMode::ByPath on
//! highly-redundant result sets (the 2523 → 20 collapse case).
//!
//! Run: `cargo bench --bench dedup_throughput`

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use graph_hunter_core::{DedupMode, Entity, EntityType, GraphHunter, Relation, RelationType};

fn build_redundant_paths(distinct: usize, dup_factor: usize) -> (GraphHunter, Vec<Vec<String>>) {
    let mut g = GraphHunter::new();
    let mut paths = Vec::with_capacity(distinct * dup_factor);
    for i in 0..distinct {
        let src = format!("u{i}");
        let dst = format!("p{i}");
        g.add_entity(Entity::new(&src, EntityType::User)).unwrap();
        g.add_entity(Entity::new(&dst, EntityType::Process))
            .unwrap();
        for k in 0..dup_factor {
            g.add_relation(Relation::new(
                &src,
                &dst,
                RelationType::Execute,
                1000 + k as i64,
            ))
            .unwrap();
            paths.push(vec![src.clone(), dst.clone()]);
        }
    }
    (g, paths)
}

fn bench_dedup(c: &mut Criterion) {
    let mut group = c.benchmark_group("dedup-score-paginate");
    for (distinct, dup) in &[(10usize, 100), (50, 50), (100, 25)] {
        let (g, paths) = build_redundant_paths(*distinct, *dup);
        let label = format!("{}x{}", distinct, dup);
        group.bench_with_input(BenchmarkId::from_parameter(&label), &label, |b, _| {
            b.iter(|| {
                let (scored, _) =
                    g.score_and_paginate_paths(black_box(&paths), 0, 50, None, DedupMode::ByPath);
                black_box(scored)
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_dedup);
criterion_main!(benches);
