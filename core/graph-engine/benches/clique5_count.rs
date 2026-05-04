//! D1 — 5-clique counting: naive vs LFTJ-SIMD across an Erdős-Rényi
//! density sweep. Closes the AGM curve K3 → K4 → K5 for the paper.
//!
//! AGM bound for K5 is `ρ*=5/2`, so the worst-case output size is
//! `m^2.5`. The naive quintuple loop scales as `m^4/n^3` (one binary
//! search per inner level). The asymmetric factor between LFTJ and
//! naive is therefore `m^{1.5}/n^3 ∝ p^{1.5} · n^{−1.5}` — the
//! density growth dominates, so the gap widens fast with `p`. By
//! `p=0.10` the naive path runs into minutes-per-iter territory, so
//! the dense end of the sweep is gated behind `BENCH_LARGE=1`.
//!
//! Run: `cargo bench --bench clique5_count --manifest-path core/graph-engine/Cargo.toml`

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use graph_hunter_core::generate_erdos_renyi;
use graph_hunter_core::lftj::{
    MaterializedCsrTrie, count_5cliques_canonical_lftj_simd,
    count_5cliques_canonical_lftj_simd_par, count_5cliques_lftj_simd,
    count_5cliques_lftj_simd_par, count_5cliques_naive,
};

fn build_trie(n: usize, p: f64, seed: u64) -> MaterializedCsrTrie {
    let mut g = generate_erdos_renyi(n, p, 1_000, 1_000_000, seed);
    g.sort_edges_by_timestamp().unwrap();
    MaterializedCsrTrie::build(&g)
}

fn bench_clique5(c: &mut Criterion) {
    let big = std::env::var("BENCH_LARGE").ok().is_some();
    let cases: &[(usize, f64)] = if big {
        &[
            (1_000, 0.01),
            (1_000, 0.02),
            (1_000, 0.05),
            (1_000, 0.10),
        ]
    } else {
        // Naive K5 at p=0.05 is already several seconds per iter.
        // Default sweep stays light; AGM curve is already visible at
        // p=0.02 vs p=0.01.
        &[(1_000, 0.01), (1_000, 0.02)]
    };

    for &(n, p) in cases {
        let trie = build_trie(n, p, 42);
        let lftj_count = count_5cliques_lftj_simd(&trie);
        let naive_count = count_5cliques_naive(&trie);
        let par_count = count_5cliques_lftj_simd_par(&trie);
        let canonical_count = count_5cliques_canonical_lftj_simd(&trie);
        assert_eq!(
            lftj_count, naive_count,
            "LFTJ vs naive 5-clique count disagree at n={n}, p={p}"
        );
        assert_eq!(
            par_count, lftj_count,
            "rayon-parallel vs sequential LFTJ 5-clique count disagree at n={n}, p={p}"
        );
        // No `canonical * 120 == naive` assert here. naive counts
        // ordered K_5 tuples where the ten directed edges in a
        // specific orientation all exist; ER's directed-edge
        // independence means most orderings of a 5-vertex set fail
        // and canonical is a strict subset. Equality is checked at
        // the unit-test level on the bidirectional K_5 fixture.
        let _ = canonical_count;
        let label = format!("V={n},E={},K5={}", trie.edge_count(), naive_count);

        let mut group = c.benchmark_group("clique5-count");
        group.bench_with_input(
            BenchmarkId::new("naive", &label),
            &&trie,
            |b, &trie| b.iter(|| black_box(count_5cliques_naive(black_box(trie)))),
        );
        group.bench_with_input(
            BenchmarkId::new("lftj+simd", &label),
            &&trie,
            |b, &trie| b.iter(|| black_box(count_5cliques_lftj_simd(black_box(trie)))),
        );
        group.bench_with_input(
            BenchmarkId::new("lftj+simd+par", &label),
            &&trie,
            |b, &trie| b.iter(|| black_box(count_5cliques_lftj_simd_par(black_box(trie)))),
        );
        group.bench_with_input(
            BenchmarkId::new("lftj+simd+canonical", &label),
            &&trie,
            |b, &trie| {
                b.iter(|| black_box(count_5cliques_canonical_lftj_simd(black_box(trie))))
            },
        );
        group.bench_with_input(
            BenchmarkId::new("lftj+simd+canonical+par", &label),
            &&trie,
            |b, &trie| {
                b.iter(|| {
                    black_box(count_5cliques_canonical_lftj_simd_par(black_box(trie)))
                })
            },
        );
        group.finish();
    }
}

criterion_group!(benches, bench_clique5);
criterion_main!(benches);
