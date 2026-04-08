/// @file graphmatch_cabi.cpp
/// @brief C ABI implementation — bridges the C interface to C++ internals.

#include "graphmatch/graphmatch.h"
#include "graphmatch/csr_graph.hpp"
#include "graphmatch/matcher.hpp"
#include "graphmatch/pattern.hpp"
#include "graphmatch/result.hpp"
#include "graphmatch/simd_intersect.hpp"
#include "graphmatch/types.h"

#include <cstdlib>
#include <cstring>
#include <vector>

// ---------------------------------------------------------------------------
// Opaque handle definitions
// ---------------------------------------------------------------------------

struct gm_graph_t {
    gm::CSRTemporalGraph graph;
};

struct gm_matcher_t {
    const gm::CSRTemporalGraph* graph;  // Borrowed reference
    std::vector<gm::PatternStep> steps;
    uint8_t start_type;
    int64_t time_window_ms;
};

struct gm_results_t {
    gm::MatchResultSet result_set;
};

// ---------------------------------------------------------------------------
// Graph construction
// ---------------------------------------------------------------------------

extern "C" {

gm_graph_t* gm_graph_new(void) {
    auto* g = new (std::nothrow) gm_graph_t;
    return g;
}

void gm_graph_add_node(gm_graph_t* g, uint32_t id, uint8_t entity_type) {
    if (!g) return;
    g->graph.add_node(id, entity_type);
}

void gm_graph_add_edge(gm_graph_t* g, uint32_t src, uint32_t dst,
                        uint8_t rel_type, int64_t timestamp) {
    if (!g) return;
    g->graph.add_edge(src, dst, rel_type, timestamp);
}

void gm_graph_finalize(gm_graph_t* g) {
    if (!g) return;
    g->graph.finalize();
}

void gm_graph_free(gm_graph_t* g) {
    delete g;
}

// ---------------------------------------------------------------------------
// Graph stats
// ---------------------------------------------------------------------------

uint32_t gm_graph_node_count(const gm_graph_t* g) {
    if (!g) return 0;
    return g->graph.node_count();
}

uint32_t gm_graph_edge_count(const gm_graph_t* g) {
    if (!g) return 0;
    return g->graph.edge_count();
}

// ---------------------------------------------------------------------------
// String interning
// ---------------------------------------------------------------------------

uint32_t gm_graph_intern(gm_graph_t* g, const char* name) {
    if (!g || !name) return UINT32_MAX;
    return g->graph.interner().intern(name);
}

const char* gm_graph_resolve(const gm_graph_t* g, uint32_t id) {
    if (!g) return nullptr;
    return g->graph.interner().resolve(id);
}

// ---------------------------------------------------------------------------
// Pattern matching
// ---------------------------------------------------------------------------

gm_matcher_t* gm_matcher_new(const gm_graph_t* g) {
    if (!g) return nullptr;
    auto* m = new (std::nothrow) gm_matcher_t;
    if (!m) return nullptr;
    m->graph = &g->graph;
    m->start_type = GM_ENTITY_ANY;
    m->time_window_ms = 0;
    return m;
}

void gm_matcher_set_start_type(gm_matcher_t* m, uint8_t entity_type) {
    if (!m) return;
    m->start_type = entity_type;
}

void gm_matcher_add_step(gm_matcher_t* m, uint8_t entity_type,
                          uint8_t rel_type, int32_t enforce_causality) {
    if (!m) return;
    m->steps.push_back({entity_type, rel_type, enforce_causality != 0});
}

void gm_matcher_set_time_window(gm_matcher_t* m, int64_t window_ms) {
    if (!m) return;
    m->time_window_ms = window_ms;
}

gm_results_t* gm_matcher_run(gm_matcher_t* m, uint32_t max_results, float min_score) {
    if (!m || !m->graph) return nullptr;

    gm::PatternCompiler compiler;
    auto query = compiler.compile_simple(
        m->steps, m->start_type, m->time_window_ms);

    gm::TemporalMatcher matcher(*m->graph);
    auto results = matcher.match(query, max_results, min_score);

    auto* r = new (std::nothrow) gm_results_t;
    if (!r) return nullptr;
    r->result_set = gm::MatchResultSet(std::move(results));
    return r;
}

void gm_matcher_free(gm_matcher_t* m) {
    delete m;
}

// ---------------------------------------------------------------------------
// Results access
// ---------------------------------------------------------------------------

uint32_t gm_results_count(const gm_results_t* r) {
    if (!r) return 0;
    return r->result_set.count();
}

const uint32_t* gm_results_get_path(const gm_results_t* r, uint32_t idx,
                                     uint32_t* path_len) {
    if (!r || !path_len) return nullptr;
    return r->result_set.get_path(idx, *path_len);
}

const int64_t* gm_results_get_timestamps(const gm_results_t* r, uint32_t idx) {
    if (!r) return nullptr;
    return r->result_set.get_timestamps(idx);
}

float gm_results_get_score(const gm_results_t* r, uint32_t idx) {
    if (!r) return 0.0f;
    return r->result_set.get_score(idx);
}

char* gm_results_to_json(const gm_results_t* r) {
    if (!r) return nullptr;
    return r->result_set.to_json();
}

void gm_results_free(gm_results_t* r) {
    delete r;
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

void gm_free_string(char* s) {
    std::free(s);
}

const char* gm_simd_isa(void) {
    SimdIsa isa = gm::simd::active_isa();
    switch (isa) {
        case GM_ISA_AVX512: return "avx512";
        case GM_ISA_AVX2:   return "avx2";
        case GM_ISA_SSE42:  return "sse42";
        case GM_ISA_NEON:   return "neon";
        default:            return "scalar";
    }
}

} // extern "C"
