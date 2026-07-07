//! D1 — 4-clique counting: naive vs LFTJ-SIMD across an Erdős-Rényi
//! density sweep. The point is to show the AGM crossover.
//!
//! For triangles (`ρ*=3/2`), the naive triple-loop already matches the
//! AGM bound `m^1.5` to within constants — that's why the count
//! crossover for triangles only crosses at `p=0.05` and the win is
//! 1.30×, not orders of magnitude. For K4 (`ρ*=2`), the naive
//! quadruple-loop scales as `m^3/n^2` while LFTJ stays at the AGM
//! bound `m^2`. The asymmetry is `m/n` — average degree — so the gap
//! grows with density.
//!
//! The bench fixes `V=1_000` and sweeps `p ∈ {0.005, 0.01, 0.02,
//! 0.05, 0.1}`, so average degree ranges from 5 to 100. At the dense
//! end the LFTJ path should beat naive by 1–2 orders of magnitude.
//!
//! Run: `cargo bench --bench clique4_count --manifest-path core/graph-engine/Cargo.toml`

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use graph_hunter_core::generate_erdos_renyi;
use graph_hunter_core::lftj::{
    MaterializedCsrTrie, count_4cliques_canonical_lftj_simd,
    count_4cliques_canonical_lftj_simd_par, count_4cliques_lftj_simd,
    count_4cliques_lftj_simd_par, count_4cliques_naive,
};

fn build_trie(n: usize, p: f64, seed: u64) -> MaterializedCsrTrie {
    let mut g = generate_erdos_renyi(n, p, 1_000, 1_000_000, seed);
    g.sort_edges_by_timestamp().unwrap();
    MaterializedCsrTrie::build(&g)
}

fn bench_clique4(c: &mut Criterion) {
    // Density sweep at fixed V=1000. Big-mode adds V=2000/p=0.02 and
    // a denser p=0.10 — only run when explicitly asked, the dense
    // naive case is minutes per sample.
    let big = std::env::var("BENCH_LARGE").ok().is_some();
    let cases: &[(usize, f64)] = if big {
        &[
            (1_000, 0.005),
            (1_000, 0.01),
            (1_000, 0.02),
            (1_000, 0.05),
            (1_000, 0.10),
            (2_000, 0.02),
        ]
    } else {
        // Dense end (p=0.05) goes into BENCH_LARGE — naive at that
        // density is minutes per sample, the asymptotic story is
        // already visible at p=0.02.
        &[
            (1_000, 0.005),
            (1_000, 0.01),
            (1_000, 0.02),
        ]
    };

    for &(n, p) in cases {
        let trie = build_trie(n, p, 42);
        let lftj_count = count_4cliques_lftj_simd(&trie);
        let naive_count = count_4cliques_naive(&trie);
        let par_count = count_4cliques_lftj_simd_par(&trie);
        let canonical_count = count_4cliques_canonical_lftj_simd(&trie);
        assert_eq!(
            lftj_count, naive_count,
            "LFTJ vs naive 4-clique count disagree at n={n}, p={p}"
        );
        assert_eq!(
            par_count, lftj_count,
            "rayon-parallel vs sequential LFTJ 4-clique count disagree at n={n}, p={p}"
        );
        // No `canonical * 24 == naive` assert here. naive counts
        // ordered tuples (a,b,c,d) where the six *directed* edges
        // a→b, a→c, a→d, b→c, b→d, c→d all exist. On a bidirectional
        // host graph (the unit-test fixture has all 12 directed pairs)
        // every ordering of a 4-vertex set has those edges and parity
        // holds. ER places each directed edge independently, so most
        // orderings of a 4-vertex set fail the directed pattern and
        // canonical (a single chain ordering on StrIds) is a strict
        // subset of naive. Equality is checked at the unit-test level
        // on the bidirectional fixture.
        let _ = canonical_count;
        let label = format!("V={n},E={},K4={}", trie.edge_count(), naive_count);

        let mut group = c.benchmark_group("clique4-count");
        group.bench_with_input(
            BenchmarkId::new("naive", &label),
            &&trie,
            |b, &trie| b.iter(|| black_box(count_4cliques_naive(black_box(trie)))),
        );
        group.bench_with_input(
            BenchmarkId::new("lftj+simd", &label),
            &&trie,
            |b, &trie| b.iter(|| black_box(count_4cliques_lftj_simd(black_box(trie)))),
        );
        group.bench_with_input(
            BenchmarkId::new("lftj+simd+par", &label),
            &&trie,
            |b, &trie| b.iter(|| black_box(count_4cliques_lftj_simd_par(black_box(trie)))),
        );
        group.bench_with_input(
            BenchmarkId::new("lftj+simd+canonical", &label),
            &&trie,
            |b, &trie| {
                b.iter(|| black_box(count_4cliques_canonical_lftj_simd(black_box(trie))))
            },
        );
        group.bench_with_input(
            BenchmarkId::new("lftj+simd+canonical+par", &label),
            &&trie,
            |b, &trie| {
                b.iter(|| {
                    black_box(count_4cliques_canonical_lftj_simd_par(black_box(trie)))
                })
            },
        );
        group.finish();
    }
}

criterion_group!(benches, bench_clique4);
criterion_main!(benches);
