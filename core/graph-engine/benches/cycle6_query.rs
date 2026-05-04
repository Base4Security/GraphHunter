//! D1 stage 4 — directed 6-cycle enumeration with the temporal
//! predicate (`t_ab < t_bc < t_cd < t_de < t_ef < t_fa`) and a
//! rayon-parallel variant. Validates the C6 enumerator end-to-end on
//! the canonical APT lateral-movement shape.
//!
//! Why C6 is the talk-justifying contribution. Of all D1 shapes, C6
//! has the largest AGM-vs-DFS gap: ρ*(C_6) = 3 vs DFS's m·d^5·log d.
//! Lateral movement (User → Host → Host → User → Host → Host →
//! cycle close) is structurally a directed 6-cycle, and on Sysmon-
//! scale graphs (10^5–10^6 vertices, hub degree 10^2) the gap turns
//! into 1–3 orders of magnitude, not a constant factor. This bench
//! demonstrates the crossover on synthetic ER fixtures small enough
//! that naive completes; the asymptotic story extrapolates from there.
//!
//! Run:
//!   `cargo bench --bench cycle6_query --manifest-path core/graph-engine/Cargo.toml`

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use graph_hunter_core::generate_erdos_renyi;
use graph_hunter_core::graph::GraphHunter;
use graph_hunter_core::lftj::MaterializedCsrTrie;
use graph_hunter_core::lftj_query::{
    MinTimestampMap, enumerate_6cycles_lftj_simd, enumerate_6cycles_lftj_simd_par,
    enumerate_6cycles_naive, sort_6cycles,
};

struct Fixture {
    graph: GraphHunter,
    forward: MaterializedCsrTrie,
    reverse: MaterializedCsrTrie,
    ts_map: MinTimestampMap,
    edge_count: usize,
}

fn build(n: usize, p: f64, seed: u64) -> Fixture {
    let mut g = generate_erdos_renyi(n, p, 1_000, 100_000_000, seed);
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

fn bench_cycle6_query(c: &mut Criterion) {
    // Density sweep tighter than K4 because C6's m^3 AGM bound puts
    // even small ER graphs into seconds-per-iter for naive. p=0.05 at
    // V=300 gives ~4500 edges and exercises both the structural and
    // chronological filters.
    let cases: &[(usize, f64)] = &[(200, 0.05), (200, 0.10), (300, 0.05)];

    for &(n, p) in cases {
        let fx = build(n, p, 42);
        // Pre-bench parity check on the bench fixture itself.
        let naive = sort_6cycles(enumerate_6cycles_naive(
            &fx.graph,
            &fx.forward,
            &fx.ts_map,
            i64::MIN,
            i64::MAX,
            10_000_000,
        ));
        let simd = sort_6cycles(enumerate_6cycles_lftj_simd(
            &fx.graph,
            &fx.forward,
            &fx.reverse,
            &fx.ts_map,
            i64::MIN,
            i64::MAX,
            10_000_000,
        ));
        let par = sort_6cycles(enumerate_6cycles_lftj_simd_par(
            &fx.graph,
            &fx.forward,
            &fx.reverse,
            &fx.ts_map,
            i64::MIN,
            i64::MAX,
            10_000_000,
        ));
        assert_eq!(simd, naive, "LFTJ-SIMD C6 enumerate parity at n={n} p={p}");
        assert_eq!(par, naive, "rayon C6 enumerate parity at n={n} p={p}");
        let label = format!("V={n},E={},C6={}", fx.edge_count, naive.len());

        let mut group = c.benchmark_group("cycle6-query");
        group.bench_with_input(BenchmarkId::new("naive", &label), &&fx, |b, &fx| {
            b.iter(|| {
                black_box(enumerate_6cycles_naive(
                    black_box(&fx.graph),
                    black_box(&fx.forward),
                    black_box(&fx.ts_map),
                    i64::MIN,
                    i64::MAX,
                    10_000_000,
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
                    10_000_000,
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
                        10_000_000,
                    ))
                })
            },
        );

        // Windowed: keep only C6s whose t_ab falls in the lower 25%
        // of the timestamp range. Validates that the window cut
        // composes with the LFTJ structural pruning.
        let t_lo: i64 = 1_000;
        let t_hi: i64 = 1_000 + (100_000_000 - 1_000) / 4;
        let label_w = format!("V={n},E={},C6=window-25%", fx.edge_count);
        group.bench_with_input(
            BenchmarkId::new("naive-window", &label_w),
            &&fx,
            |b, &fx| {
                b.iter(|| {
                    black_box(enumerate_6cycles_naive(
                        black_box(&fx.graph),
                        black_box(&fx.forward),
                        black_box(&fx.ts_map),
                        t_lo,
                        t_hi,
                        10_000_000,
                    ))
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("lftj+simd-window", &label_w),
            &&fx,
            |b, &fx| {
                b.iter(|| {
                    black_box(enumerate_6cycles_lftj_simd(
                        black_box(&fx.graph),
                        black_box(&fx.forward),
                        black_box(&fx.reverse),
                        black_box(&fx.ts_map),
                        t_lo,
                        t_hi,
                        10_000_000,
                    ))
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("lftj+simd+par-window", &label_w),
            &&fx,
            |b, &fx| {
                b.iter(|| {
                    black_box(enumerate_6cycles_lftj_simd_par(
                        black_box(&fx.graph),
                        black_box(&fx.forward),
                        black_box(&fx.reverse),
                        black_box(&fx.ts_map),
                        t_lo,
                        t_hi,
                        10_000_000,
                    ))
                })
            },
        );
        group.finish();
    }
}

criterion_group!(benches, bench_cycle6_query);
criterion_main!(benches);
