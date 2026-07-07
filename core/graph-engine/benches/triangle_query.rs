//! D1 — Triangle query enumeration: naive vs LFTJ end-to-end.
//!
//! Mirrors `triangle_count` but exercises the actual query path
//! (`enumerate_triangles_lftj` and `enumerate_triangles_naive`) so we
//! measure the cost of materialising `Vec<HuntResult>` and resolving
//! `StrId -> Arc<str>`, not just counting tuples. This is the bench
//! that reflects what a real D1 caller pays.
//!
//! With random timestamps in [t_min, t_max), each forward triangle has
//! a 1/6 probability of being time-respecting, so the result set is
//! ~|triangles| / 6.
//!
//! Run: `cargo bench --bench triangle_query --manifest-path core/graph-engine/Cargo.toml`
//! Larger sweep: `BENCH_LARGE=1 cargo bench --bench triangle_query ...`

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use graph_hunter_core::generate_erdos_renyi;
use graph_hunter_core::graph::GraphHunter;
use graph_hunter_core::lftj::MaterializedCsrTrie;
use graph_hunter_core::lftj_query::{
    MinTimestampMap, enumerate_triangles_lftj, enumerate_triangles_lftj_simd,
    enumerate_triangles_naive, sort_triangles,
};

fn build_graph(n: usize, p: f64, seed: u64) -> (GraphHunter, MaterializedCsrTrie) {
    let mut g = generate_erdos_renyi(n, p, 1_000, 1_000_000, seed);
    g.sort_edges_by_timestamp().unwrap();
    let trie = MaterializedCsrTrie::build(&g);
    (g, trie)
}

fn bench_query(c: &mut Criterion) {
    let big = std::env::var("BENCH_LARGE").ok().is_some();
    let cases: &[(usize, f64)] = if big {
        &[
            (1_000, 0.005),
            (1_000, 0.02),
            (1_000, 0.05),
            (2_000, 0.01),
        ]
    } else {
        &[
            (500, 0.01),
            (1_000, 0.005),
            (1_000, 0.02),
        ]
    };

    let cap: usize = std::env::var("BENCH_CAP")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(usize::MAX);

    for &(n, p) in cases {
        let (g, trie) = build_graph(n, p, 42);
        let ts_map = MinTimestampMap::build(&g, &trie);
        // Parity check before benching — a silent regression would
        // invalidate the numbers.
        let lftj =
            sort_triangles(enumerate_triangles_lftj(&g, &trie, &ts_map, usize::MAX));
        let naive =
            sort_triangles(enumerate_triangles_naive(&g, &trie, &ts_map, usize::MAX));
        let simd =
            sort_triangles(enumerate_triangles_lftj_simd(&g, &trie, &ts_map, usize::MAX));
        assert_eq!(
            lftj, naive,
            "LFTJ vs naive triangle finders disagree at n={n}, p={p}"
        );
        assert_eq!(
            simd, naive,
            "SIMD enumerator vs naive disagree at n={n}, p={p}"
        );

        let label = format!("V={n},E={},T={}", trie.edge_count(), naive.len());

        let inputs = (&g, &trie, &ts_map);
        let mut group = c.benchmark_group("triangle-query");
        group.bench_with_input(
            BenchmarkId::new("naive", &label),
            &inputs,
            |b, &(g, t, m)| {
                b.iter(|| {
                    black_box(enumerate_triangles_naive(
                        black_box(g),
                        black_box(t),
                        black_box(m),
                        cap,
                    ))
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("lftj", &label),
            &inputs,
            |b, &(g, t, m)| {
                b.iter(|| {
                    black_box(enumerate_triangles_lftj(
                        black_box(g),
                        black_box(t),
                        black_box(m),
                        cap,
                    ))
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("lftj+simd", &label),
            &inputs,
            |b, &(g, t, m)| {
                b.iter(|| {
                    black_box(enumerate_triangles_lftj_simd(
                        black_box(g),
                        black_box(t),
                        black_box(m),
                        cap,
                    ))
                })
            },
        );
        group.finish();
    }
}

criterion_group!(benches, bench_query);
criterion_main!(benches);
