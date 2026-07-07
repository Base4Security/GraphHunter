//! Power-law-degree matching bench. The other matching benches build
//! uniform-degree layered graphs which mask cache-tier optimizations
//! (B3 Hub-Sort, B4 prefetch) because the working set fits in L1.
//! This one uses Barabási-Albert preferential attachment so degree
//! distribution is heavy-tailed — closer to real Sysmon-style graphs
//! where services.exe / svchost.exe form mega-hubs.
//!
//! Run: `cargo bench --bench matching_powerlaw`
//! Large sweep: `BENCH_LARGE=1 cargo bench --bench matching_powerlaw`

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use graph_hunter_core::{
    EntityType, GraphHunter, Hypothesis, HypothesisStep, RelationType, generate_barabasi_albert,
};

fn build_ba_graph(n: usize, m: usize) -> GraphHunter {
    let mut g = generate_barabasi_albert(n, m, 1_000, 1_000_000, 42);
    g.sort_edges_by_timestamp().unwrap();
    g
}

fn build_typed_2hop() -> Hypothesis {
    Hypothesis::new("ba-2hop")
        .add_step(HypothesisStep::new(
            EntityType::Process,
            RelationType::Spawn,
            EntityType::File,
        ))
        .add_step(HypothesisStep::new(
            EntityType::File,
            RelationType::Write,
            EntityType::Host,
        ))
}

fn build_any_2hop() -> Hypothesis {
    Hypothesis::new("ba-any-2hop")
        .add_step(HypothesisStep::new(
            EntityType::Any,
            RelationType::Any,
            EntityType::Any,
        ))
        .add_step(HypothesisStep::new(
            EntityType::Any,
            RelationType::Any,
            EntityType::Any,
        ))
}

fn bench_powerlaw(c: &mut Criterion) {
    let big = std::env::var("BENCH_LARGE").ok().is_some();
    let sizes: &[usize] = if big {
        &[10_000, 100_000]
    } else {
        &[1_000, 10_000]
    };
    let m_values: &[usize] = &[4];

    let mut typed = c.benchmark_group("ba-typed-2hop");
    for &n in sizes {
        for &m in m_values {
            let g = build_ba_graph(n, m);
            let h = build_typed_2hop();
            let label = format!("V={n},m={m}");
            typed.bench_with_input(BenchmarkId::from_parameter(&label), &label, |b, _| {
                b.iter(|| {
                    let (paths, _) = g
                        .search_temporal_pattern(black_box(&h), None, Some(10_000))
                        .unwrap();
                    black_box(paths)
                });
            });
        }
    }
    typed.finish();

    let mut any = c.benchmark_group("ba-any-2hop");
    for &n in sizes {
        for &m in m_values {
            let g = build_ba_graph(n, m);
            let h = build_any_2hop();
            let label = format!("V={n},m={m}");
            any.bench_with_input(BenchmarkId::from_parameter(&label), &label, |b, _| {
                b.iter(|| {
                    let (paths, _) = g
                        .search_temporal_pattern(black_box(&h), None, Some(10_000))
                        .unwrap();
                    black_box(paths)
                });
            });
        }
    }
    any.finish();
}

criterion_group!(benches, bench_powerlaw);
criterion_main!(benches);
