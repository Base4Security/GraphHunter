//! D1 — Triangle count: naive vs LFTJ vs LFTJ+SIMD.
//!
//! Compares the three triangle-count routines on Erdős-Rényi-style
//! directed graphs. The naive baseline is O(n^3) over the trie, LFTJ
//! follows the Veldhuizen leapfrog with attribute order [a, b, c], and
//! the SIMD variant routes the leaf-level intersection through
//! `simd_rust::intersect_sorted_u32_count` (runtime AVX2 dispatch with
//! scalar fallback).
//!
//! Run: `cargo bench --bench triangle_count --manifest-path core/graph-engine/Cargo.toml`
//! Larger sweep: `BENCH_LARGE=1 cargo bench --bench triangle_count ...`

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use graph_hunter_core::generate_erdos_renyi;
use graph_hunter_core::lftj::{
    MaterializedCsrTrie, count_triangles_canonical_lftj_simd,
    count_triangles_canonical_lftj_simd_par, count_triangles_lftj, count_triangles_lftj_simd,
};

/// Brute-force triple-loop baseline. Same shape as the in-tree test
/// helper; reproduced here because the test helper is private.
fn count_triangles_naive(trie: &MaterializedCsrTrie) -> usize {
    let mut count = 0usize;
    for ai in 0..trie.src_keys.len() {
        let a_dsts =
            &trie.dst_keys[trie.dst_offsets[ai] as usize..trie.dst_offsets[ai + 1] as usize];
        for &b in a_dsts {
            let bi = match trie.src_keys.binary_search(&b) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let b_dsts =
                &trie.dst_keys[trie.dst_offsets[bi] as usize..trie.dst_offsets[bi + 1] as usize];
            for &c in b_dsts {
                if a_dsts.binary_search(&c).is_ok() {
                    count += 1;
                }
            }
        }
    }
    count
}

fn build_trie(n: usize, p: f64, seed: u64) -> MaterializedCsrTrie {
    let mut g = generate_erdos_renyi(n, p, 1_000, 1_000_000, seed);
    g.sort_edges_by_timestamp().unwrap();
    MaterializedCsrTrie::build(&g)
}

fn bench_triangles(c: &mut Criterion) {
    let big = std::env::var("BENCH_LARGE").ok().is_some();
    // (n, p) — p is tuned so the expected directed edge count is
    // n*(n-1)*p ≈ 5n. For n=1000 that's ~5K edges, the canonical
    // mid-density Erdős-Rényi the WCOJ literature reports on.
    // Density sweep — sparse, mid, dense at fixed n=1000 — exposes
    // how the LFTJ overhead amortizes as the result set grows. The
    // naive baseline degrades faster than LFTJ as p grows because its
    // inner binary-search probes scale with deg(b), while leapfrog
    // intersection on already-sorted dst lists scales with the
    // overlap size.
    let cases: &[(usize, f64)] = if big {
        &[
            (1_000, 0.005),  // ~5K edges,  sparse
            (1_000, 0.02),   // ~20K edges, mid
            (1_000, 0.05),   // ~50K edges, dense
            (2_000, 0.01),   // ~40K edges, mid at larger n
        ]
    } else {
        &[
            (500, 0.01),    // ~2.5K edges, sparse
            (1_000, 0.005), // ~5K edges,   sparse (literature default)
            (1_000, 0.02),  // ~20K edges,  mid-density
        ]
    };

    for &(n, p) in cases {
        let trie = build_trie(n, p, 42);
        // Verify all three paths agree on this graph before benching —
        // a regression would silently invalidate the numbers.
        let naive = count_triangles_naive(&trie);
        let lftj = count_triangles_lftj(&trie);
        let simd = count_triangles_lftj_simd(&trie);
        assert_eq!(naive, lftj, "naive vs LFTJ disagree at n={n}");
        assert_eq!(lftj, simd, "LFTJ vs SIMD disagree at n={n}");

        let label = format!("V={n},E={},T={}", trie.edge_count(), naive);

        let mut group = c.benchmark_group("triangle-count");
        group.bench_with_input(
            BenchmarkId::new("naive", &label),
            &trie,
            |b, t| b.iter(|| black_box(count_triangles_naive(black_box(t)))),
        );
        group.bench_with_input(
            BenchmarkId::new("lftj", &label),
            &trie,
            |b, t| b.iter(|| black_box(count_triangles_lftj(black_box(t)))),
        );
        group.bench_with_input(
            BenchmarkId::new("lftj+simd", &label),
            &trie,
            |b, t| b.iter(|| black_box(count_triangles_lftj_simd(black_box(t)))),
        );
        // Canonical chain a<b<c on StrIds. On bidirectional fixtures
        // canonical * 6 == naive (verified at the unit-test level on
        // the bidirectional triangle); on directed ER each ordering
        // checks a different directed pattern so canonical is a
        // strict subset of the over-counted variants. No count assert
        // here; the row measures wall-clock only.
        group.bench_with_input(
            BenchmarkId::new("lftj+simd+canonical", &label),
            &trie,
            |b, t| b.iter(|| black_box(count_triangles_canonical_lftj_simd(black_box(t)))),
        );
        group.bench_with_input(
            BenchmarkId::new("lftj+simd+canonical+par", &label),
            &trie,
            |b, t| {
                b.iter(|| black_box(count_triangles_canonical_lftj_simd_par(black_box(t))))
            },
        );
        group.finish();
    }
}

criterion_group!(benches, bench_triangles);
criterion_main!(benches);
