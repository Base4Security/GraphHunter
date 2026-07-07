//! S2 — directed 6-cycle count: naive (binary-search closure) vs
//! LFTJ-SIMD with reverse trie (intersect-count closure).
//!
//! The cycle a→b→c→d→e→f→a has $\rho^*(C_6) = 3$, AGM bound `m^3`.
//! Unlike K_k, no pair of consecutive cycle edges share a vertex on
//! which to intersect during expansion — the pure WCOJ shape can't
//! collapse `(b,c)` neighborhoods because `b → c` is just one edge,
//! not a clique. The leverage point is the *closure* `f → a`: with a
//! reverse trie, `f` candidates are `N_forward(e) ∩ predecessors(a)`,
//! computable as one SIMD intersect per `(a,b,c,d,e)` instead of one
//! binary search per `f`.
//!
//! Run: `cargo bench --bench cycle6_count --manifest-path core/graph-engine/Cargo.toml`

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use graph_hunter_core::generate_erdos_renyi;
use graph_hunter_core::lftj::{
    MaterializedCsrTrie, count_6cycles_canonical_lftj_simd,
    count_6cycles_canonical_lftj_simd_par, count_6cycles_lftj_simd,
    count_6cycles_lftj_simd_par, count_6cycles_naive,
};

struct Fixture {
    fwd: MaterializedCsrTrie,
    rev: MaterializedCsrTrie,
}

fn build(n: usize, p: f64, seed: u64) -> Fixture {
    let mut g = generate_erdos_renyi(n, p, 1_000, 1_000_000, seed);
    g.sort_edges_by_timestamp().unwrap();
    let fwd = MaterializedCsrTrie::build(&g);
    let rev = MaterializedCsrTrie::build_reverse(&g);
    Fixture { fwd, rev }
}

fn bench_cycle6(c: &mut Criterion) {
    // C6 naive cost is O(m·d^4·log d). The C6 *output* in ER scales
    // as `(n·p)^6`, so even at p=0.01 V=1000 there are ~10^6 ordered
    // cycles — the cost is output-dominated, not structural. The
    // density sweep stays correspondingly tight; BENCH_LARGE=1 takes
    // it to where naive starts pushing seconds per iter (still within
    // criterion's adaptive sample budget).
    let big = std::env::var("BENCH_LARGE").ok().is_some();
    let cases: &[(usize, f64)] = if big {
        &[(1_000, 0.005), (1_000, 0.01), (1_000, 0.02)]
    } else {
        &[(1_000, 0.005), (1_000, 0.01)]
    };

    for &(n, p) in cases {
        let fx = build(n, p, 42);
        let lftj_count = count_6cycles_lftj_simd(&fx.fwd, &fx.rev);
        let naive_count = count_6cycles_naive(&fx.fwd);
        let par_count = count_6cycles_lftj_simd_par(&fx.fwd, &fx.rev);
        let canonical_count = count_6cycles_canonical_lftj_simd(&fx.fwd, &fx.rev);
        assert_eq!(
            lftj_count, naive_count,
            "LFTJ vs naive C6 count disagree at n={n}, p={p}"
        );
        assert_eq!(
            par_count, lftj_count,
            "rayon-parallel vs sequential C6 count disagree at n={n}, p={p}"
        );
        // No `canonical * 6 == naive` assert here. naive counts every
        // closed 6-walk including ones with repeated vertices; canonical
        // requires `a` to be strictly less than every other position,
        // which filters out walks where the minimum appears more than
        // once (e.g. lollipops `0→1→0→3→4→5→0`). The strict-equality
        // identity holds only on simple 6-cycles, which is what the
        // unit-test fixture verifies. Counting closed walks here lets
        // the bench keep its existing semantics.
        let _ = canonical_count;
        let label = format!("V={n},E={},C6={}", fx.fwd.edge_count(), naive_count);

        let mut group = c.benchmark_group("cycle6-count");
        group.bench_with_input(
            BenchmarkId::new("naive", &label),
            &&fx,
            |b, &fx| b.iter(|| black_box(count_6cycles_naive(black_box(&fx.fwd)))),
        );
        group.bench_with_input(
            BenchmarkId::new("lftj+simd", &label),
            &&fx,
            |b, &fx| {
                b.iter(|| {
                    black_box(count_6cycles_lftj_simd(
                        black_box(&fx.fwd),
                        black_box(&fx.rev),
                    ))
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("lftj+simd+par", &label),
            &&fx,
            |b, &fx| {
                b.iter(|| {
                    black_box(count_6cycles_lftj_simd_par(
                        black_box(&fx.fwd),
                        black_box(&fx.rev),
                    ))
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("lftj+simd+canonical", &label),
            &&fx,
            |b, &fx| {
                b.iter(|| {
                    black_box(count_6cycles_canonical_lftj_simd(
                        black_box(&fx.fwd),
                        black_box(&fx.rev),
                    ))
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("lftj+simd+canonical+par", &label),
            &&fx,
            |b, &fx| {
                b.iter(|| {
                    black_box(count_6cycles_canonical_lftj_simd_par(
                        black_box(&fx.fwd),
                        black_box(&fx.rev),
                    ))
                })
            },
        );
        group.finish();
    }
}

criterion_group!(benches, bench_cycle6);
criterion_main!(benches);
