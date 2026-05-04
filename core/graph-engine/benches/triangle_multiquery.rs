//! D3 — Multi-query amortization of the LFTJ trie + timestamp cache.
//!
//! The Ren-Wang 2016 / CECI 2019 setup: dozens of MITRE ATT&CK
//! templates run on the same EDR stream. They share the same graph
//! and therefore the same `MaterializedCsrTrie` and `MinTimestampMap`,
//! both `O(E)` to build. If those structures are constructed once and
//! reused across K queries, the per-query amortized cost drops to
//! `build / K + enumerate`. At K large enough the build cost vanishes
//! and only the SIMD-accelerated enumerate dominates.
//!
//! This bench compares two paths over the same graph and the same K:
//!
//!   - "shared":  build trie + ts_map once, run K enumerations.
//!   - "rebuild": for each of K queries, build trie + ts_map + run
//!                one enumeration.
//!
//! Reports total wall time. The amortized per-query cost is the
//! reported time / K. K=1 is the no-amortization baseline (where the
//! two paths must agree); K=8 and K=64 expose the multiplicative
//! win.
//!
//! Run: `cargo bench --bench triangle_multiquery --manifest-path core/graph-engine/Cargo.toml`

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use graph_hunter_core::generate_erdos_renyi;
use graph_hunter_core::graph::GraphHunter;
use graph_hunter_core::lftj::MaterializedCsrTrie;
use graph_hunter_core::lftj_query::{
    MinTimestampMap, enumerate_triangles_lftj_simd, enumerate_triangles_lftj_simd_window,
};

/// Synthetic time-window splits over [t_lo, t_hi). Mirrors a real
/// threat-hunt batch where each ATT&CK template applies to its own
/// time slice (last 5 min, last 1h, etc.) and shares only the graph.
fn windows(k: usize, t_lo: i64, t_hi: i64) -> Vec<(i64, i64)> {
    let span = (t_hi - t_lo).max(1);
    let step = span / k as i64;
    (0..k)
        .map(|i| {
            let lo = t_lo + step * i as i64;
            let hi = if i + 1 == k {
                t_hi
            } else {
                t_lo + step * (i as i64 + 1)
            };
            (lo, hi)
        })
        .collect()
}

fn build_graph(n: usize, p: f64, seed: u64) -> GraphHunter {
    let mut g = generate_erdos_renyi(n, p, 1_000, 1_000_000, seed);
    g.sort_edges_by_timestamp().unwrap();
    g
}

fn run_shared(g: &GraphHunter, k: usize, cap: usize) -> usize {
    let trie = MaterializedCsrTrie::build(g);
    let ts_map = MinTimestampMap::build(g, &trie);
    let mut total = 0usize;
    for _ in 0..k {
        total = total.wrapping_add(
            enumerate_triangles_lftj_simd(g, &trie, &ts_map, cap).len(),
        );
    }
    total
}

fn run_rebuild(g: &GraphHunter, k: usize, cap: usize) -> usize {
    let mut total = 0usize;
    for _ in 0..k {
        let trie = MaterializedCsrTrie::build(g);
        let ts_map = MinTimestampMap::build(g, &trie);
        total = total.wrapping_add(
            enumerate_triangles_lftj_simd(g, &trie, &ts_map, cap).len(),
        );
    }
    total
}

/// Windowed shared path: build trie + ts_map once; each of K queries
/// uses a disjoint time slice. Total enumerate work ≈ original (the
/// union of windows covers the full timeline) but per-query output is
/// O(|OUT| / K) — the regime where amortization is supposed to pay.
fn run_shared_windowed(
    g: &GraphHunter,
    windows: &[(i64, i64)],
    cap: usize,
) -> usize {
    let trie = MaterializedCsrTrie::build(g);
    let ts_map = MinTimestampMap::build(g, &trie);
    let mut total = 0usize;
    for &(t_lo, t_hi) in windows {
        total = total.wrapping_add(
            enumerate_triangles_lftj_simd_window(g, &trie, &ts_map, t_lo, t_hi, cap).len(),
        );
    }
    total
}

fn run_rebuild_windowed(
    g: &GraphHunter,
    windows: &[(i64, i64)],
    cap: usize,
) -> usize {
    let mut total = 0usize;
    for &(t_lo, t_hi) in windows {
        let trie = MaterializedCsrTrie::build(g);
        let ts_map = MinTimestampMap::build(g, &trie);
        total = total.wrapping_add(
            enumerate_triangles_lftj_simd_window(g, &trie, &ts_map, t_lo, t_hi, cap).len(),
        );
    }
    total
}

fn bench_multiquery(c: &mut Criterion) {
    // Two graphs spanning the regime where lftj+simd already beats
    // naive (V=1000, p=0.05) and a mid-density case where the
    // amortization story is the only win to be had.
    let cases: &[(usize, f64)] = &[(1_000, 0.02), (1_000, 0.05)];
    let ks: &[usize] = &[1, 4, 16, 64];

    for &(n, p) in cases {
        let g = build_graph(n, p, 42);
        let trie_size = {
            let trie = MaterializedCsrTrie::build(&g);
            trie.edge_count()
        };
        let label_base = format!("V={n},E={trie_size}");

        // The Erdős-Rényi generator currently emits timestamps in
        // [1_000, 1_000_000). Slice that range into K disjoint windows
        // for the windowed variants.
        let (t_lo, t_hi) = (1_000i64, 1_000_000i64);

        for &k in ks {
            let wins = windows(k, t_lo, t_hi);
            let mut group = c.benchmark_group("triangle-multiquery");
            let label = format!("{label_base},K={k}");
            group.bench_with_input(
                BenchmarkId::new("shared", &label),
                &(&g, k),
                |b, &(g, k)| {
                    b.iter(|| black_box(run_shared(black_box(g), k, usize::MAX)))
                },
            );
            group.bench_with_input(
                BenchmarkId::new("rebuild", &label),
                &(&g, k),
                |b, &(g, k)| {
                    b.iter(|| black_box(run_rebuild(black_box(g), k, usize::MAX)))
                },
            );
            group.bench_with_input(
                BenchmarkId::new("shared-window", &label),
                &(&g, &wins),
                |b, &(g, w)| {
                    b.iter(|| black_box(run_shared_windowed(black_box(g), w, usize::MAX)))
                },
            );
            group.bench_with_input(
                BenchmarkId::new("rebuild-window", &label),
                &(&g, &wins),
                |b, &(g, w)| {
                    b.iter(|| black_box(run_rebuild_windowed(black_box(g), w, usize::MAX)))
                },
            );
            group.finish();
        }
    }
}

criterion_group!(benches, bench_multiquery);
criterion_main!(benches);
