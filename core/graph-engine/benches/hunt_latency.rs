//! Benchmark: time a single `search_temporal_pattern` call against
//! graphs of varying size. Records a baseline so CI can alert on
//! regressions >10% between PRs.
//!
//! **Regression policy:** CI compares against the committed Criterion
//! baseline named `main` (see `benches/baseline/criterion/` and
//! `benches/baseline/hunt_latency_baseline.json`). CI fails soft until
//! baseline stabilizes across Windows + Linux runners.
//!
//! Default sizes finish in minutes; larger spray (500K, 1M) and hub
//! (100K, 500K) tiers run via `BENCH_LARGE=1 cargo bench --bench hunt_latency`.
//! The `User-Auth-IP-hub` group measures hub-and-spoke spray graphs where
//! one IP concentrates many auth failures.
//!
//! Run: `cargo bench --bench hunt_latency`
//!
//! Refresh baseline (default tiers only — do not set `BENCH_LARGE`):
//! `cargo bench --manifest-path core/graph-engine/Cargo.toml --bench hunt_latency -- --save-baseline main`
//! then copy `target/criterion/{user-auth-ip,user-auth-ip-hub}/**/main/` into
//! `benches/baseline/criterion/`.

use std::time::Duration;

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
    g.sort_edges_by_timestamp().unwrap();
    g
}

fn build_hub_spray_graph(n_spokes: usize) -> GraphHunter {
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("attacker", EntityType::User))
        .unwrap();
    g.add_entity(Entity::new("10.0.0.1", EntityType::IP)).unwrap();
    for i in 0..n_spokes {
        let user = format!("user_{i}");
        g.add_entity(Entity::new(&user, EntityType::User)).unwrap();
        g.add_relation(
            Relation::new(user, "10.0.0.1", RelationType::Auth, 1000 + i as i64)
                .with_metadata("status", "Failure"),
        )
        .unwrap();
    }
    g.sort_edges_by_timestamp().unwrap();
    g
}

fn spray_hypothesis() -> Hypothesis {
    Hypothesis::new("spray").add_step(HypothesisStep::new(
        EntityType::User,
        RelationType::Auth,
        EntityType::IP,
    ))
}

fn configure_large_tier(group: &mut criterion::BenchmarkGroup<criterion::measurement::WallTime>) {
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));
}

fn bench_user_auth_ip(c: &mut Criterion) {
    let big = std::env::var("BENCH_LARGE").ok().is_some();
    let sizes: &[usize] = if big {
        &[1_000, 10_000, 100_000, 500_000, 1_000_000]
    } else {
        &[1_000, 10_000, 100_000]
    };

    let mut group = c.benchmark_group("User-Auth-IP");
    for &n in sizes {
        if n >= 100_000 {
            configure_large_tier(&mut group);
        }
        let g = build_spray_graph(n);
        let h = spray_hypothesis();
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
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

fn bench_user_auth_ip_hub(c: &mut Criterion) {
    let big = std::env::var("BENCH_LARGE").ok().is_some();
    let sizes: &[usize] = if big {
        &[10_000, 100_000, 500_000]
    } else {
        &[10_000]
    };

    let mut group = c.benchmark_group("User-Auth-IP-hub");
    for &n in sizes {
        if n >= 100_000 {
            configure_large_tier(&mut group);
        }
        let g = build_hub_spray_graph(n);
        let h = spray_hypothesis();
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                let (paths, _) = g
                    .search_temporal_pattern(black_box(&h), None, Some(usize::MAX))
                    .unwrap();
                black_box(paths)
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_user_auth_ip, bench_user_auth_ip_hub);
criterion_main!(benches);
