/// @file test_pruning.cpp
/// @brief Unit tests for the PruningEngine.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "graphmatch/pruning.hpp"
#include "graphmatch/types.h"

using namespace gm;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static TemporalEdge make_edge(NodeId target, RelTypeTag rel, Timestamp ts) {
    return TemporalEdge{target, rel, {}, ts};
}

// ---------------------------------------------------------------------------
// Individual pruning strategies
// ---------------------------------------------------------------------------

TEST_SUITE("pruning") {

TEST_CASE("relation type filter") {
    EntityTypeTag types[] = {GM_ENTITY_HOST, GM_ENTITY_PROCESS, GM_ENTITY_FILE};
    TemporalEdge edges[] = {
        make_edge(0, GM_REL_CONNECT, 100),
        make_edge(1, GM_REL_EXECUTE, 200),
        make_edge(2, GM_REL_WRITE,   300),
    };
    TemporalEdge survivors[3];
    PruningEngine pruner;

    size_t n = pruner.apply_all(
        edges, 3,
        GM_REL_EXECUTE,      // Only Execute edges
        GM_ENTITY_ANY,        // Any entity type
        types,
        GM_TS_MIN,            // No causal constraint
        GM_TS_MIN, GM_TS_MAX, // No time window
        nullptr, 0,           // No visited set
        1, nullptr,
        survivors);

    CHECK(n == 1);
    CHECK(survivors[0].target == 1);
    CHECK(survivors[0].rel_type == GM_REL_EXECUTE);
}

TEST_CASE("relation type wildcard passes all") {
    EntityTypeTag types[] = {GM_ENTITY_HOST, GM_ENTITY_PROCESS, GM_ENTITY_FILE};
    TemporalEdge edges[] = {
        make_edge(0, GM_REL_CONNECT, 100),
        make_edge(1, GM_REL_EXECUTE, 200),
        make_edge(2, GM_REL_WRITE,   300),
    };
    TemporalEdge survivors[3];
    PruningEngine pruner;

    size_t n = pruner.apply_all(
        edges, 3, GM_REL_ANY, GM_ENTITY_ANY, types,
        GM_TS_MIN, GM_TS_MIN, GM_TS_MAX,
        nullptr, 0, 1, nullptr, survivors);

    CHECK(n == 3);
}

TEST_CASE("entity type filter") {
    EntityTypeTag types[] = {GM_ENTITY_HOST, GM_ENTITY_PROCESS, GM_ENTITY_FILE};
    TemporalEdge edges[] = {
        make_edge(0, GM_REL_CONNECT, 100),
        make_edge(1, GM_REL_EXECUTE, 200),
        make_edge(2, GM_REL_WRITE,   300),
    };
    TemporalEdge survivors[3];
    PruningEngine pruner;

    size_t n = pruner.apply_all(
        edges, 3,
        GM_REL_ANY,           // Any relation
        GM_ENTITY_FILE,       // Only File targets
        types,
        GM_TS_MIN, GM_TS_MIN, GM_TS_MAX,
        nullptr, 0, 1, nullptr, survivors);

    CHECK(n == 1);
    CHECK(survivors[0].target == 2);
}

TEST_CASE("causal monotonicity") {
    EntityTypeTag types[] = {GM_ENTITY_HOST, GM_ENTITY_HOST, GM_ENTITY_HOST};
    TemporalEdge edges[] = {
        make_edge(0, GM_REL_CONNECT, 100),
        make_edge(1, GM_REL_CONNECT, 200),
        make_edge(2, GM_REL_CONNECT, 300),
    };
    TemporalEdge survivors[3];
    PruningEngine pruner;

    // last_timestamp = 250 → only edge at t=300 survives
    size_t n = pruner.apply_all(
        edges, 3,
        GM_REL_ANY, GM_ENTITY_ANY, types,
        250,                  // last_timestamp
        GM_TS_MIN, GM_TS_MAX,
        nullptr, 0, 1, nullptr, survivors);

    CHECK(n == 1);
    CHECK(survivors[0].timestamp == 300);
}

TEST_CASE("time window") {
    EntityTypeTag types[] = {GM_ENTITY_HOST, GM_ENTITY_HOST, GM_ENTITY_HOST, GM_ENTITY_HOST};
    TemporalEdge edges[] = {
        make_edge(0, GM_REL_CONNECT, 100),
        make_edge(1, GM_REL_CONNECT, 200),
        make_edge(2, GM_REL_CONNECT, 300),
        make_edge(3, GM_REL_CONNECT, 400),
    };
    TemporalEdge survivors[4];
    PruningEngine pruner;

    // Window [150, 350] → edges at 200 and 300 survive
    size_t n = pruner.apply_all(
        edges, 4,
        GM_REL_ANY, GM_ENTITY_ANY, types,
        GM_TS_MIN,
        150, 350,             // time window
        nullptr, 0, 1, nullptr, survivors);

    CHECK(n == 2);
    CHECK(survivors[0].timestamp == 200);
    CHECK(survivors[1].timestamp == 300);
}

TEST_CASE("cycle avoidance with visit_counts") {
    EntityTypeTag types[] = {GM_ENTITY_HOST, GM_ENTITY_HOST, GM_ENTITY_HOST};
    TemporalEdge edges[] = {
        make_edge(0, GM_REL_CONNECT, 100),
        make_edge(1, GM_REL_CONNECT, 200),
        make_edge(2, GM_REL_CONNECT, 300),
    };
    TemporalEdge survivors[3];
    PruningEngine pruner;

    // Node 1 already visited once (k=1 → blocked)
    uint32_t visit_counts[] = {0, 1, 0};

    size_t n = pruner.apply_all(
        edges, 3,
        GM_REL_ANY, GM_ENTITY_ANY, types,
        GM_TS_MIN, GM_TS_MIN, GM_TS_MAX,
        nullptr, 0,
        1,                    // k_simplicity = 1
        visit_counts,
        survivors);

    CHECK(n == 2);
    CHECK(survivors[0].target == 0);
    CHECK(survivors[1].target == 2);
}

TEST_CASE("cycle avoidance with sorted visited set") {
    EntityTypeTag types[] = {GM_ENTITY_HOST, GM_ENTITY_HOST, GM_ENTITY_HOST};
    TemporalEdge edges[] = {
        make_edge(0, GM_REL_CONNECT, 100),
        make_edge(1, GM_REL_CONNECT, 200),
        make_edge(2, GM_REL_CONNECT, 300),
    };
    TemporalEdge survivors[3];
    PruningEngine pruner;

    uint32_t visited[] = {1}; // Node 1 visited

    size_t n = pruner.apply_all(
        edges, 3,
        GM_REL_ANY, GM_ENTITY_ANY, types,
        GM_TS_MIN, GM_TS_MIN, GM_TS_MAX,
        visited, 1,
        1, nullptr,
        survivors);

    CHECK(n == 2);
    CHECK(survivors[0].target == 0);
    CHECK(survivors[1].target == 2);
}

TEST_CASE("combined pruning: all five active") {
    EntityTypeTag types[] = {
        GM_ENTITY_IP,       // 0
        GM_ENTITY_HOST,     // 1
        GM_ENTITY_PROCESS,  // 2
        GM_ENTITY_HOST,     // 3
        GM_ENTITY_FILE,     // 4
    };

    TemporalEdge edges[] = {
        make_edge(0, GM_REL_CONNECT, 50),   // Wrong rel, wrong entity, too early
        make_edge(1, GM_REL_AUTH,    200),   // Correct! Host, Auth, in window, not visited
        make_edge(2, GM_REL_AUTH,    250),   // Wrong entity (Process)
        make_edge(3, GM_REL_AUTH,    350),   // Correct type but visited
        make_edge(4, GM_REL_AUTH,    500),   // Outside time window
    };

    TemporalEdge survivors[5];
    PruningEngine pruner;

    uint32_t visited[] = {3}; // Node 3 visited

    size_t n = pruner.apply_all(
        edges, 5,
        GM_REL_AUTH,          // Only Auth
        GM_ENTITY_HOST,       // Only Host targets
        types,
        100,                  // last_timestamp = 100
        100, 400,             // time window
        visited, 1,
        1, nullptr,
        survivors);

    CHECK(n == 1);
    CHECK(survivors[0].target == 1);
    CHECK(survivors[0].timestamp == 200);
}

TEST_CASE("temporal_range matches edge_range_sid") {
    TemporalEdge edges[] = {
        make_edge(0, GM_REL_CONNECT, 100),
        make_edge(1, GM_REL_CONNECT, 200),
        make_edge(2, GM_REL_CONNECT, 300),
        make_edge(3, GM_REL_CONNECT, 400),
        make_edge(4, GM_REL_CONNECT, 500),
    };

    size_t lo, hi;
    PruningEngine::temporal_range(edges, 5, 200, GM_TS_MIN, 400, lo, hi);
    CHECK(lo == 1); // First edge with ts >= 200
    CHECK(hi == 4); // First edge with ts > 400

    PruningEngine::temporal_range(edges, 5, GM_TS_MIN, 250, 350, lo, hi);
    CHECK(lo == 2); // First edge with ts >= 250
    CHECK(hi == 3); // First edge with ts > 350
}

TEST_CASE("count_survivors matches apply_all") {
    EntityTypeTag types[] = {GM_ENTITY_HOST, GM_ENTITY_PROCESS, GM_ENTITY_FILE};
    TemporalEdge edges[] = {
        make_edge(0, GM_REL_CONNECT, 100),
        make_edge(1, GM_REL_EXECUTE, 200),
        make_edge(2, GM_REL_WRITE,   300),
    };
    TemporalEdge survivors[3];
    PruningEngine pruner;

    size_t n = pruner.apply_all(
        edges, 3, GM_REL_ANY, GM_ENTITY_PROCESS, types,
        GM_TS_MIN, GM_TS_MIN, GM_TS_MAX,
        nullptr, 0, 1, nullptr, survivors);

    size_t c = pruner.count_survivors(
        edges, 3, GM_REL_ANY, GM_ENTITY_PROCESS, types,
        GM_TS_MIN, GM_TS_MIN, GM_TS_MAX,
        nullptr, 0, 1, nullptr);

    CHECK(n == c);
}

} // TEST_SUITE pruning
