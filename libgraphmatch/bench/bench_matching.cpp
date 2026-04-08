/// @file bench_matching.cpp
/// @brief End-to-end matching benchmark: various graph sizes and chain lengths.

#include "graphmatch/csr_graph.hpp"
#include "graphmatch/matcher.hpp"
#include "graphmatch/pattern.hpp"
#include "graphmatch/simd_intersect.hpp"
#include "graphmatch/types.h"

#include <chrono>
#include <cstdio>
#include <random>
#include <vector>

using namespace gm;
using Clock = std::chrono::high_resolution_clock;

// ---------------------------------------------------------------------------
// Graph generators
// ---------------------------------------------------------------------------

/// Build a random temporal graph with the given number of nodes and edges.
/// Entity types cycle through Process, Host, File, User, IP.
/// Edges have random timestamps and relation types.
static CSRTemporalGraph make_random_graph(
    uint32_t num_nodes, uint32_t num_edges, uint32_t seed)
{
    std::mt19937 rng(seed);
    std::uniform_int_distribution<uint32_t> node_dist(0, num_nodes - 1);
    std::uniform_int_distribution<int64_t> ts_dist(1000, 1000000);
    std::uniform_int_distribution<uint8_t> rel_dist(0, 8);

    EntityTypeTag types[] = {
        GM_ENTITY_PROCESS, GM_ENTITY_HOST, GM_ENTITY_FILE,
        GM_ENTITY_USER, GM_ENTITY_IP
    };

    CSRTemporalGraph g;
    for (uint32_t i = 0; i < num_nodes; ++i) {
        g.add_node(i, types[i % 5]);
    }
    for (uint32_t i = 0; i < num_edges; ++i) {
        g.add_edge(node_dist(rng), node_dist(rng), rel_dist(rng), ts_dist(rng));
    }
    g.finalize();
    return g;
}

/// Build a chain-structured graph (best case for matching).
/// N nodes in a line: 0 → 1 → 2 → ... → N-1.
static CSRTemporalGraph make_chain_graph(uint32_t length) {
    EntityTypeTag types[] = {
        GM_ENTITY_IP, GM_ENTITY_HOST, GM_ENTITY_USER,
        GM_ENTITY_PROCESS, GM_ENTITY_FILE
    };

    CSRTemporalGraph g;
    for (uint32_t i = 0; i < length; ++i) {
        g.add_node(i, types[i % 5]);
    }
    for (uint32_t i = 0; i + 1 < length; ++i) {
        g.add_edge(i, i + 1, static_cast<RelTypeTag>(i % 9),
                   static_cast<Timestamp>(i * 100 + 100));
    }
    g.finalize();
    return g;
}

// ---------------------------------------------------------------------------
// Benchmark harness
// ---------------------------------------------------------------------------

template<typename Fn>
static double bench_ms(Fn&& fn, int iters = 1) {
    auto t0 = Clock::now();
    for (int i = 0; i < iters; ++i) fn();
    auto t1 = Clock::now();
    return std::chrono::duration<double, std::milli>(t1 - t0).count() / iters;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main() {
    gm::simd::init();
    std::printf("=== Matching Benchmark ===\n");
    std::printf("SIMD ISA: %s\n\n", [] {
        switch (gm::simd::active_isa()) {
            case GM_ISA_AVX512: return "avx512";
            case GM_ISA_AVX2:   return "avx2";
            case GM_ISA_SSE42:  return "sse42";
            case GM_ISA_NEON:   return "neon";
            default:            return "scalar";
        }
    }());

    // --- Chain matching benchmark ---
    std::printf("--- Chain matching (5-step pattern, varying graph size) ---\n");
    std::printf("%-12s  %-8s  %-8s  %-12s  %-10s\n",
                "Nodes", "Edges", "Matches", "Time (ms)", "Matches/s");

    for (uint32_t n : {1000u, 10000u, 100000u, 500000u}) {
        uint32_t edges = n * 3; // avg degree ~3
        auto g = make_random_graph(n, edges, 42);

        TemporalMatcher matcher(g);
        PatternCompiler compiler;

        // 5-step wildcard pattern (maximum branching)
        std::vector<PatternStep> steps = {
            {GM_ENTITY_ANY, GM_REL_ANY, true},
            {GM_ENTITY_ANY, GM_REL_ANY, true},
            {GM_ENTITY_ANY, GM_REL_ANY, true},
            {GM_ENTITY_ANY, GM_REL_ANY, true},
            {GM_ENTITY_ANY, GM_REL_ANY, true},
        };
        auto query = compiler.compile_simple(steps, GM_ENTITY_ANY, 0);

        uint32_t max_results = 10000;
        size_t match_count = 0;

        double ms = bench_ms([&]() {
            auto results = matcher.match(query, max_results);
            match_count = results.size();
        }, 1);

        std::printf("%-12u  %-8u  %-8zu  %-12.2f  %-10.0f\n",
                    n, g.edge_count(), match_count, ms,
                    match_count > 0 ? match_count / (ms / 1000.0) : 0.0);
    }

    // --- Chain graph benchmark (best case) ---
    std::printf("\n--- Chain graph (perfect chain, varying pattern length) ---\n");
    std::printf("%-12s  %-12s  %-8s  %-12s\n",
                "Chain len", "Pattern len", "Matches", "Time (ms)");

    uint32_t chain_len = 10000;
    auto chain = make_chain_graph(chain_len);
    TemporalMatcher chain_matcher(chain);
    PatternCompiler compiler;

    for (uint32_t plen : {2u, 3u, 5u, 8u, 10u}) {
        std::vector<PatternStep> steps;
        for (uint32_t i = 0; i < plen; ++i) {
            steps.push_back({GM_ENTITY_ANY, GM_REL_ANY, true});
        }
        auto query = compiler.compile_simple(steps, GM_ENTITY_ANY, 0);

        size_t match_count = 0;
        double ms = bench_ms([&]() {
            auto results = chain_matcher.match(query, 100000);
            match_count = results.size();
        }, 3);

        std::printf("%-12u  %-12u  %-8zu  %-12.2f\n",
                    chain_len, plen, match_count, ms);
    }

    // --- Memory footprint ---
    std::printf("\n--- Memory footprint ---\n");
    std::printf("sizeof(TemporalEdge) = %zu bytes\n", sizeof(TemporalEdge));
    std::printf("sizeof(NodeId)       = %zu bytes\n", sizeof(NodeId));

    for (uint32_t n : {10000u, 100000u, 1000000u}) {
        uint32_t e = n * 5;
        auto g = make_random_graph(n, e, 42);
        // Approximate: node arrays + edge arrays + sorted targets
        size_t node_bytes = n * (sizeof(EntityTypeTag) + sizeof(float)); // types + scores
        size_t edge_bytes = g.edge_count() * sizeof(TemporalEdge);
        size_t total_approx = node_bytes + edge_bytes * 2; // forward + reverse

        std::printf("  %uK nodes, %uK edges: ~%.1f MB  (%.1f B/node, %.1f B/edge)\n",
                    n / 1000, g.edge_count() / 1000,
                    total_approx / (1024.0 * 1024.0),
                    static_cast<double>(total_approx) / n,
                    static_cast<double>(total_approx) / g.edge_count());
    }

    return 0;
}
