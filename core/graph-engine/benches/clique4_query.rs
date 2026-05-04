//! D1 — 4-clique enumeration with the full vertical: temporal
//! predicate (chronological lex order on the six edges), optional
//! `[t_lo, t_hi)` window on `t_ab`, and a rayon-parallel variant.
//!
//! Where the count bench (`clique4_count`) is structure-only — every
//! K4 in the graph is reported — this bench measures the path that a
//! real ATT&CK-style query would take: the strict chronological
//! predicate keeps `1/720` of structural K4s on uniform random
//! timestamps, so the output is much smaller than the AGM bound. The
//! win for LFTJ over naive comes from two places: (a) the AGM
//! structural improvement that already shows up in `clique4_count`
//! (m^2 vs ~m^3/n^2), and (b) early-out short-circuits driven by the
//! temporal predicate.
//!
//! The bench fixes V=1_000 and runs at p ∈ {0.01, 0.02, 0.05}. At
//! p=0.05 naive starts to push past 100 ms per iteration so the
//! group is run with smaller `sample-size` if needed (criterion
//! handles this automatically when measurement-time is set).
//!
//! Run:
//!   `cargo bench --bench clique4_query --manifest-path core/graph-engine/Cargo.toml`

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use graph_hunter_core::generate_erdos_renyi;
use graph_hunter_core::graph::GraphHunter;
use graph_hunter_core::lftj::MaterializedCsrTrie;
use graph_hunter_core::lftj_query::{
    MinTimestampMap, enumerate_4cliques_lftj_simd, enumerate_4cliques_lftj_simd_par,
    enumerate_4cliques_naive, sort_4cliques,
};

struct Fixture {
    graph: GraphHunter,
    trie: MaterializedCsrTrie,
    ts_map: MinTimestampMap,
    edge_count: usize,
}

fn build(n: usize, p: f64, seed: u64) -> Fixture {
    let mut g = generate_erdos_renyi(n, p, 1_000, 1_000_000, seed);
    g.sort_edges_by_timestamp().unwrap();
    let trie = MaterializedCsrTrie::build(&g);
    let ts_map = MinTimestampMap::build(&g, &trie);
    let edge_count = trie.dst_keys.len();
    Fixture {
        graph: g,
        trie,
        ts_map,
        edge_count,
    }
}

fn bench_clique4_query(c: &mut Criterion) {
    let cases: &[(usize, f64)] = &[(1_000, 0.01), (1_000, 0.02), (1_000, 0.05)];

    for &(n, p) in cases {
        let fx = build(n, p, 42);
        // Pre-bench parity: all three impls agree on this fixture.
        let naive = sort_4cliques(enumerate_4cliques_naive(
            &fx.graph,
            &fx.trie,
            &fx.ts_map,
            i64::MIN,
            i64::MAX,
            10_000_000,
        ));
        let simd = sort_4cliques(enumerate_4cliques_lftj_simd(
            &fx.graph,
            &fx.trie,
            &fx.ts_map,
            i64::MIN,
            i64::MAX,
            10_000_000,
        ));
        let par = sort_4cliques(enumerate_4cliques_lftj_simd_par(
            &fx.graph,
            &fx.trie,
            &fx.ts_map,
            i64::MIN,
            i64::MAX,
            10_000_000,
        ));
        assert_eq!(simd, naive, "LFTJ-SIMD K4 enumerate parity at n={n} p={p}");
        assert_eq!(par, naive, "rayon K4 enumerate parity at n={n} p={p}");
        let label = format!("V={n},E={},K4={}", fx.edge_count, naive.len());

        let mut group = c.benchmark_group("clique4-query");
        group.bench_with_input(
            BenchmarkId::new("naive", &label),
            &&fx,
            |b, &fx| {
                b.iter(|| {
                    black_box(enumerate_4cliques_naive(
                        black_box(&fx.graph),
                        black_box(&fx.trie),
                        black_box(&fx.ts_map),
                        i64::MIN,
                        i64::MAX,
                        10_000_000,
                    ))
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("lftj+simd", &label),
            &&fx,
            |b, &fx| {
                b.iter(|| {
                    black_box(enumerate_4cliques_lftj_simd(
                        black_box(&fx.graph),
                        black_box(&fx.trie),
                        black_box(&fx.ts_map),
                        i64::MIN,
                        i64::MAX,
                        10_000_000,
                    ))
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("lftj+simd+par", &label),
            &&fx,
            |b, &fx| {
                b.iter(|| {
                    black_box(enumerate_4cliques_lftj_simd_par(
                        black_box(&fx.graph),
                        black_box(&fx.trie),
                        black_box(&fx.ts_map),
                        i64::MIN,
                        i64::MAX,
                        10_000_000,
                    ))
                })
            },
        );

        // Windowed: keep only K4s whose t_ab falls in the lower 25%
        // of the timestamp range. Demonstrates that the window cut
        // composes with the LFTJ structural pruning — naive sees the
        // same window cut and pays the same proportional reduction
        // (no asymmetric win or loss).
        let t_lo: i64 = 1_000;
        let t_hi: i64 = 1_000 + (1_000_000 - 1_000) / 4;
        let label_w = format!("V={n},E={},K4=window-25%", fx.edge_count);
        group.bench_with_input(
            BenchmarkId::new("naive-window", &label_w),
            &&fx,
            |b, &fx| {
                b.iter(|| {
                    black_box(enumerate_4cliques_naive(
                        black_box(&fx.graph),
                        black_box(&fx.trie),
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
                    black_box(enumerate_4cliques_lftj_simd(
                        black_box(&fx.graph),
                        black_box(&fx.trie),
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
                    black_box(enumerate_4cliques_lftj_simd_par(
                        black_box(&fx.graph),
                        black_box(&fx.trie),
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

criterion_group!(benches, bench_clique4_query);
criterion_main!(benches);
