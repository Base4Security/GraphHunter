//! D1 stage 4 — Sysmon-scale C6 bench. Validates the BlackHat 2026
//! claim that LFTJ delivers 1–3 orders of magnitude over DFS on
//! production-scale, hub-heavy graphs.
//!
//! Why Barabási-Albert: real Sysmon process-graphs are scale-free with
//! a small number of high-degree hubs (services.exe, lsass.exe, svchost,
//! the domain controller) connected to many leaves. The BA preferential-
//! attachment generator emits the same power-law degree distribution.
//! Vertex labels here are random `EntityType`s — the LFTJ enumerator
//! ignores types so the topological shape is what drives the bench.
//!
//! Tier sweep:
//!   * V=10K (m=3): naive vs LFTJ+SIMD vs LFTJ+SIMD+par — calibration
//!   * V=100K (m=3): same — medium production scale
//!   * V=1M (m=3): LFTJ+SIMD+par only — naive is m·d^4·log d, infeasible
//!
//! Run:
//!   cargo bench --bench cycle6_sysmon_scale --manifest-path core/graph-engine/Cargo.toml
//!
//! At V=1M the bench takes 5-10 minutes per criterion sample; criterion
//! adapts the sample count automatically. Prefer `--measurement-time 60`
//! for stable numbers; use `BENCH_LARGE=1` to include the V=1M tier
//! (skipped by default to keep CI/local runs under 10 min total).

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use graph_hunter_core::generate_barabasi_albert;
use graph_hunter_core::graph::GraphHunter;
use graph_hunter_core::lftj::MaterializedCsrTrie;
use graph_hunter_core::lftj_query::{
    MinTimestampMap, enumerate_6cycles_lftj_simd, enumerate_6cycles_lftj_simd_par,
    enumerate_6cycles_naive,
};

struct Fixture {
    graph: GraphHunter,
    forward: MaterializedCsrTrie,
    reverse: MaterializedCsrTrie,
    ts_map: MinTimestampMap,
    edge_count: usize,
}

fn build(n: usize, m: usize, seed: u64) -> Fixture {
    let mut g = generate_barabasi_albert(n, m, 1_000, 100_000_000, seed);
    g.sort_edges_by_timestamp().unwrap();
    let forward = MaterializedCsrTrie::build(&g);
    let reverse = MaterializedCsrTrie::build_reverse(&g);
    let ts_map = MinTimestampMap::build(&g, &forward);
    let edge_count = forward.dst_keys.len();
    Fixture {
        graph: g,
        forward,
        reverse,
        ts_map,
        edge_count,
    }
}

fn bench_cycle6_sysmon_scale(c: &mut Criterion) {
    let big = std::env::var("BENCH_LARGE").ok().is_some();

    // Tier 1: V=10K with both impls for asymptotic-crossover evidence.
    // V=100K with naive pushes 20+ min/sample on hub-heavy fixtures
    // because of the d^4 fanout, so it lives behind BENCH_LARGE.
    let small_cases: &[(usize, usize)] = &[(10_000, 3)];

    for &(n, m) in small_cases {
        let fx = build(n, m, 42);
        let label = format!("V={n},E={},m={m}", fx.edge_count);

        let mut group = c.benchmark_group("cycle6-sysmon-scale");
        // Naive at V=100K with d^4 hub fanout pushes minutes per sample
        // — cap measurement-time generously and accept a small sample
        // count. Criterion handles this automatically; we just expose
        // the bench so the operator can tune `--measurement-time`.
        group.sample_size(10);
        group.bench_with_input(BenchmarkId::new("naive", &label), &&fx, |b, &fx| {
            b.iter(|| {
                black_box(enumerate_6cycles_naive(
                    black_box(&fx.graph),
                    black_box(&fx.forward),
                    black_box(&fx.ts_map),
                    i64::MIN,
                    i64::MAX,
                    1_000_000,
                ))
            })
        });
        group.bench_with_input(BenchmarkId::new("lftj+simd", &label), &&fx, |b, &fx| {
            b.iter(|| {
                black_box(enumerate_6cycles_lftj_simd(
                    black_box(&fx.graph),
                    black_box(&fx.forward),
                    black_box(&fx.reverse),
                    black_box(&fx.ts_map),
                    i64::MIN,
                    i64::MAX,
                    1_000_000,
                ))
            })
        });
        group.bench_with_input(
            BenchmarkId::new("lftj+simd+par", &label),
            &&fx,
            |b, &fx| {
                b.iter(|| {
                    black_box(enumerate_6cycles_lftj_simd_par(
                        black_box(&fx.graph),
                        black_box(&fx.forward),
                        black_box(&fx.reverse),
                        black_box(&fx.ts_map),
                        i64::MIN,
                        i64::MAX,
                        1_000_000,
                    ))
                })
            },
        );
        group.finish();
    }

    if big {
        // Tier 2: V=100K naive + LFTJ. Behind BENCH_LARGE because naive
        // can take ~20 min per sample on hub-heavy fixtures.
        let fx = build(100_000, 3, 42);
        let label = format!("V=100000,E={},m=3", fx.edge_count);
        let mut group = c.benchmark_group("cycle6-sysmon-scale-100K");
        group.sample_size(10);
        group.bench_with_input(BenchmarkId::new("naive", &label), &&fx, |b, &fx| {
            b.iter(|| {
                black_box(enumerate_6cycles_naive(
                    black_box(&fx.graph),
                    black_box(&fx.forward),
                    black_box(&fx.ts_map),
                    i64::MIN,
                    i64::MAX,
                    1_000_000,
                ))
            })
        });
        group.bench_with_input(
            BenchmarkId::new("lftj+simd+par", &label),
            &&fx,
            |b, &fx| {
                b.iter(|| {
                    black_box(enumerate_6cycles_lftj_simd_par(
                        black_box(&fx.graph),
                        black_box(&fx.forward),
                        black_box(&fx.reverse),
                        black_box(&fx.ts_map),
                        i64::MIN,
                        i64::MAX,
                        1_000_000,
                    ))
                })
            },
        );
        group.finish();

        // Tier 3: V=1M, LFTJ-only. Naive infeasible (hours per sample).
        // The wall-clock number on lftj+simd+par is the production-
        // feasibility data point — "GraphHunter can hunt 6-cycles on a
        // million-vertex Sysmon graph in under a second" is the
        // BlackHat-style headline.
        let fx = build(1_000_000, 3, 42);
        let label = format!("V=1000000,E={},m=3", fx.edge_count);
        let mut group = c.benchmark_group("cycle6-sysmon-scale-1M");
        group.sample_size(10);
        group.bench_with_input(
            BenchmarkId::new("lftj+simd+par", &label),
            &&fx,
            |b, &fx| {
                b.iter(|| {
                    black_box(enumerate_6cycles_lftj_simd_par(
                        black_box(&fx.graph),
                        black_box(&fx.forward),
                        black_box(&fx.reverse),
                        black_box(&fx.ts_map),
                        i64::MIN,
                        i64::MAX,
                        1_000_000,
                    ))
                })
            },
        );
        group.finish();
    }
}

criterion_group!(benches, bench_cycle6_sysmon_scale);
criterion_main!(benches);
