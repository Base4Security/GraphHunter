//! Micro-benchmark for search_temporal_pattern and search_temporal_pattern_smart.
//!
//! Generates a synthetic Barabási–Albert graph, runs pattern matching several
//! times, and reports wall-clock time + sanity checks on the returned paths.
//!
//! Intent: validate the DFS-returns-StrId refactor behaves identically to the
//! String-based version, and provide a repeatable timing reference.

use std::time::Instant;

use graph_hunter_core::benchmark::{
    build_lateral_movement_hypothesis, build_spawn_chain_hypothesis, generate_barabasi_albert,
};
use graph_hunter_core::GraphHunter;
use graph_hunter_core::Hypothesis;
use graph_hunter_core::HypothesisStep;
use graph_hunter_core::ScoringWeights;
use graph_hunter_core::{EntityType, RelationType};

/// Builds a hypothesis with `length` Any-typed steps so it matches *every*
/// outgoing edge — useful to saturate the result cap and measure how the
/// DFS hot loop scales when allocations dominate.
fn build_any_chain(length: usize) -> Hypothesis {
    let mut h = Hypothesis::new(format!("any_chain_L{}", length));
    for _ in 0..length {
        h.steps.push(HypothesisStep::new(
            EntityType::Any,
            RelationType::Any,
            EntityType::Any,
        ));
    }
    h
}

fn bench_one(label: &str, g: &mut GraphHunter, h: &Hypothesis, iters: usize) {
    // Sort edges once (required for the optimized search path).
    g.sort_edges_by_timestamp().expect("sort edges");

    // Warm-up
    let (warmup_results, _) = g
        .search_temporal_pattern(h, None, Some(10_000))
        .expect("search failed");

    // Sanity check: path length must be steps.len() + 1, and every id must
    // resolve to a real entity in the graph.
    for path in warmup_results.iter().take(5) {
        assert_eq!(
            path.len(),
            h.steps.len() + 1,
            "path length mismatch for {}",
            label
        );
        for id in path {
            assert!(
                g.get_entity(id).is_some(),
                "path contains unknown entity {} in {}",
                id,
                label
            );
        }
    }

    let mut total_ns: u128 = 0;
    let mut last_count: usize = 0;
    for _ in 0..iters {
        let t0 = Instant::now();
        let (results, _) = g
            .search_temporal_pattern(h, None, Some(10_000))
            .expect("search failed");
        total_ns += t0.elapsed().as_nanos();
        last_count = results.len();
    }

    let avg_ms = (total_ns as f64 / iters as f64) / 1_000_000.0;
    println!(
        "{:<40} iters={}  results={:<6}  avg={:.3} ms",
        label, iters, last_count, avg_ms
    );
}

/// Benchmark for `search_temporal_pattern_smart` (anomaly-pruned top-K).
/// Requires the graph to have a finalized anomaly scorer; the caller is
/// responsible for calling `enable_anomaly_scoring(...)` first.
fn bench_smart(label: &str, g: &mut GraphHunter, h: &Hypothesis, top_k: usize, iters: usize) {
    g.sort_edges_by_timestamp().expect("sort edges");

    // Warm-up + correctness check
    let (warmup, _) = g
        .search_temporal_pattern_smart(h, None, top_k)
        .expect("smart search failed");
    for path in warmup.iter().take(5) {
        assert_eq!(path.len(), h.steps.len() + 1, "smart: path length mismatch");
        for id in path {
            assert!(g.get_entity(id).is_some(), "smart: unknown entity {}", id);
        }
    }

    let mut total_ns: u128 = 0;
    let mut last_count = 0usize;
    for _ in 0..iters {
        let t0 = Instant::now();
        let (results, _) = g
            .search_temporal_pattern_smart(h, None, top_k)
            .expect("smart search failed");
        total_ns += t0.elapsed().as_nanos();
        last_count = results.len();
    }
    let avg_ms = (total_ns as f64 / iters as f64) / 1_000_000.0;
    println!(
        "{:<40} iters={}  results={:<6}  avg={:.3} ms",
        label, iters, last_count, avg_ms
    );
}

fn main() {
    println!("=== DFS pattern-match micro-benchmark ===");
    println!("(verifying StrId-based DFS refactor; paths must still materialize to valid entity ids)\n");

    // Small-medium graph: ~5K nodes, ~40K edges
    let mut g_small = generate_barabasi_albert(5_000, 4, 0, 1_000_000, 42);
    println!(
        "Graph(small): {} entities, {} relations",
        g_small.entity_count(),
        g_small.relation_count()
    );

    let h2 = build_spawn_chain_hypothesis(2);
    let h3 = build_spawn_chain_hypothesis(3);
    let h_lat3 = build_lateral_movement_hypothesis(3);
    let h_lat4 = build_lateral_movement_hypothesis(4);

    bench_one("small / spawn_chain L=2", &mut g_small, &h2, 20);
    bench_one("small / spawn_chain L=3", &mut g_small, &h3, 20);
    bench_one("small / lateral L=3", &mut g_small, &h_lat3, 20);
    bench_one("small / lateral L=4", &mut g_small, &h_lat4, 20);

    // Larger graph: ~20K nodes, ~160K edges
    let mut g_big = generate_barabasi_albert(20_000, 4, 0, 1_000_000, 43);
    println!(
        "\nGraph(big): {} entities, {} relations",
        g_big.entity_count(),
        g_big.relation_count()
    );

    bench_one("big   / spawn_chain L=2", &mut g_big, &h2, 10);
    bench_one("big   / spawn_chain L=3", &mut g_big, &h3, 10);
    bench_one("big   / lateral L=3", &mut g_big, &h_lat3, 10);
    bench_one("big   / lateral L=4", &mut g_big, &h_lat4, 10);

    // Saturate-the-cap scenarios: Any/Any chains hit the 10K cap easily.
    // This is the workload where the StrId refactor has the biggest impact:
    // 10K results × (L+1) nodes used to allocate one String per node.
    let h_any2 = build_any_chain(2);
    let h_any3 = build_any_chain(3);
    let h_any4 = build_any_chain(4);

    println!("\n--- Saturation workloads (Any/Any chains, cap=10K) ---");
    bench_one("small / any_chain L=2", &mut g_small, &h_any2, 10);
    bench_one("small / any_chain L=3", &mut g_small, &h_any3, 10);
    bench_one("small / any_chain L=4", &mut g_small, &h_any4, 10);
    bench_one("big   / any_chain L=2", &mut g_big, &h_any2, 10);
    bench_one("big   / any_chain L=3", &mut g_big, &h_any3, 10);
    bench_one("big   / any_chain L=4", &mut g_big, &h_any4, 10);

    // ── Anomaly-pruned smart search (search_temporal_pattern_smart) ──
    // Builds independent graph copies with the scorer enabled so the
    // measurements aren't tainted by reuse of the cap-based runs above.
    println!("\n--- Smart top-K search (anomaly-pruned, top_k=1000) ---");
    let mut g_small_a = generate_barabasi_albert(5_000, 4, 0, 1_000_000, 42);
    g_small_a.enable_anomaly_scoring(ScoringWeights::default());
    let mut g_big_a = generate_barabasi_albert(20_000, 4, 0, 1_000_000, 43);
    g_big_a.enable_anomaly_scoring(ScoringWeights::default());

    bench_smart("small / smart any_chain L=3", &mut g_small_a, &h_any3, 1000, 10);
    bench_smart("small / smart any_chain L=4", &mut g_small_a, &h_any4, 1000, 10);
    bench_smart("big   / smart any_chain L=3", &mut g_big_a, &h_any3, 1000, 10);
    bench_smart("big   / smart any_chain L=4", &mut g_big_a, &h_any4, 1000, 10);
    bench_smart("big   / smart spawn_chain L=2", &mut g_big_a, &h2, 1000, 10);
    bench_smart("big   / smart lateral L=3", &mut g_big_a, &h_lat3, 1000, 10);

    #[cfg(feature = "simd")]
    {
        use graph_hunter_core::simd_matcher::ffi::{build_gm_graph, simd_isa_name};

        let isa = simd_isa_name();
        println!("\n=== SIMD vs pure-Rust comparison ===");
        if matches!(isa, "scalar" | "none" | "unknown") {
            println!("[bench_dfs] SIMD ISA = {} — measuring scalar fallback path", isa);
        } else {
            println!("[bench_dfs] SIMD ISA = {}", isa);
        }

        let cached_small = build_gm_graph(&g_small);
        let cached_big = build_gm_graph(&g_big);

        let small_cases: [(&str, &Hypothesis, usize); 7] = [
            ("small / spawn_chain L=2", &h2, 20),
            ("small / spawn_chain L=3", &h3, 20),
            ("small / lateral L=3", &h_lat3, 20),
            ("small / lateral L=4", &h_lat4, 20),
            ("small / any_chain L=2", &h_any2, 10),
            ("small / any_chain L=3", &h_any3, 10),
            ("small / any_chain L=4", &h_any4, 10),
        ];
        for (label, h, iters) in small_cases {
            bench_simd_vs_rust(label, &mut g_small, &cached_small, h, iters);
        }

        let big_cases: [(&str, &Hypothesis, usize); 7] = [
            ("big   / spawn_chain L=2", &h2, 10),
            ("big   / spawn_chain L=3", &h3, 10),
            ("big   / lateral L=3", &h_lat3, 10),
            ("big   / lateral L=4", &h_lat4, 10),
            ("big   / any_chain L=2", &h_any2, 10),
            ("big   / any_chain L=3", &h_any3, 10),
            ("big   / any_chain L=4", &h_any4, 10),
        ];
        for (label, h, iters) in big_cases {
            bench_simd_vs_rust(label, &mut g_big, &cached_big, h, iters);
        }
    }

    println!("\nOK: all paths produced valid, resolvable entity ids.");
}

/// Times both paths back-to-back so they measure the exact same graph state.
/// `bench_one` above can't be reused because it discards its timing and
/// doesn't touch the SIMD path.
#[cfg(feature = "simd")]
fn bench_simd_vs_rust(
    label: &str,
    g: &mut GraphHunter,
    cached: &graph_hunter_core::simd_matcher::ffi::CachedSimdGraph,
    h: &Hypothesis,
    iters: usize,
) {
    use graph_hunter_core::simd_matcher::ffi::run_simd_search;

    g.sort_edges_by_timestamp().expect("sort edges");

    let _ = g
        .search_temporal_pattern(h, None, Some(10_000))
        .expect("search failed");
    let _ = run_simd_search(cached, &g.interner, h, None, Some(10_000));

    let mut rust_ns: u128 = 0;
    let mut rust_count: usize = 0;
    for _ in 0..iters {
        let t0 = Instant::now();
        let (results, _) = g
            .search_temporal_pattern(h, None, Some(10_000))
            .expect("search failed");
        rust_ns += t0.elapsed().as_nanos();
        rust_count = results.len();
    }

    let mut simd_ns: u128 = 0;
    let mut simd_count: usize = 0;
    for _ in 0..iters {
        let t0 = Instant::now();
        let results = run_simd_search(cached, &g.interner, h, None, Some(10_000));
        simd_ns += t0.elapsed().as_nanos();
        simd_count = results.len();
    }

    let rust_ms = (rust_ns as f64 / iters as f64) / 1_000_000.0;
    let simd_ms = (simd_ns as f64 / iters as f64) / 1_000_000.0;
    let speedup = if simd_ms > 0.0 { rust_ms / simd_ms } else { 0.0 };
    println!(
        "{:<40} rust={:>10.3} ms  simd={:>10.3} ms  x{:.2}  (rust={} simd={})",
        label, rust_ms, simd_ms, speedup, rust_count, simd_count
    );
}
