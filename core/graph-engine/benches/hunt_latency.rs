//! Benchmark: time a single `search_temporal_pattern` call against
//! graphs of varying size. Records a baseline so CI can alert on
//! regressions >10% between PRs.
//!
//! Run: `cargo bench --bench hunt_latency`

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use graph_hunter_core::{
    Entity, EntityType, GraphHunter, Hypothesis, HypothesisStep, Relation, RelationType,
};

fn build_spray_graph(n_ips: usize) -> GraphHunter {
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("attacker", EntityType::User))
        .unwrap();
    for i in 0..n_ips {
        let ip = format!("10.{}.{}.{}", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
        g.add_entity(Entity::new(&ip, EntityType::IP)).unwrap();
        g.add_relation(
            Relation::new("attacker", ip, RelationType::Auth, 1000 + i as i64)
                .with_metadata("status", "Failure"),
        )
        .unwrap();
    }
    g
}

fn bench_user_auth_ip(c: &mut Criterion) {
    let mut group = c.benchmark_group("User-Auth-IP");
    for n in &[1_000usize, 10_000, 100_000] {
        let g = build_spray_graph(*n);
        let h = Hypothesis::new("spray").add_step(HypothesisStep::new(
            EntityType::User,
            RelationType::Auth,
            EntityType::IP,
        ));
        group.bench_with_input(BenchmarkId::from_parameter(n), n, |b, _| {
            b.iter(|| {
                // `Some(usize::MAX)` disables the internal 10K cap so the
                // 100K case actually walks 100K paths instead of stopping
                // early. Without this, hunt_latency/100K reported < 10K
                // because the search short-circuited.
                let (paths, _) = g
                    .search_temporal_pattern(black_box(&h), None, Some(usize::MAX))
                    .unwrap();
                black_box(paths)
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_user_auth_ip);
criterion_main!(benches);
