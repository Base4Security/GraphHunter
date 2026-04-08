/// @file test_matcher.cpp
/// @brief Unit tests for TemporalMatcher.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "graphmatch/matcher.hpp"
#include "graphmatch/pattern.hpp"
#include "graphmatch/csr_graph.hpp"
#include "graphmatch/types.h"

using namespace gm;

// ---------------------------------------------------------------------------
// Helper: build the standard lateral movement graph.
// IP(0) -[Connect@100]-> Host(1) -[Auth@200]-> User(2)
//                                                -[Execute@300]-> Process(3)
//                                                                  -[Write@400]-> File(4)
// ---------------------------------------------------------------------------

static CSRTemporalGraph build_lateral_movement() {
    CSRTemporalGraph g;
    g.add_node(0, GM_ENTITY_IP);
    g.add_node(1, GM_ENTITY_HOST);
    g.add_node(2, GM_ENTITY_USER);
    g.add_node(3, GM_ENTITY_PROCESS);
    g.add_node(4, GM_ENTITY_FILE);

    g.add_edge(0, 1, GM_REL_CONNECT, 100);
    g.add_edge(1, 2, GM_REL_AUTH,    200);
    g.add_edge(2, 3, GM_REL_EXECUTE, 300);
    g.add_edge(3, 4, GM_REL_WRITE,   400);

    g.finalize();
    return g;
}

/// Build a branching graph with multiple paths.
/// IP(0) -[Connect@100]-> Host(1) -[Auth@200]-> User(2) -[Execute@300]-> Process(3) -[Write@400]-> File(4)
///                                -[Auth@150]-> User(5) -[Execute@250]-> Process(6) -[Write@350]-> File(7)
static CSRTemporalGraph build_branching_graph() {
    CSRTemporalGraph g;
    g.add_node(0, GM_ENTITY_IP);
    g.add_node(1, GM_ENTITY_HOST);
    g.add_node(2, GM_ENTITY_USER);
    g.add_node(3, GM_ENTITY_PROCESS);
    g.add_node(4, GM_ENTITY_FILE);
    g.add_node(5, GM_ENTITY_USER);
    g.add_node(6, GM_ENTITY_PROCESS);
    g.add_node(7, GM_ENTITY_FILE);

    g.add_edge(0, 1, GM_REL_CONNECT, 100);
    g.add_edge(1, 2, GM_REL_AUTH,    200);
    g.add_edge(1, 5, GM_REL_AUTH,    150);
    g.add_edge(2, 3, GM_REL_EXECUTE, 300);
    g.add_edge(5, 6, GM_REL_EXECUTE, 250);
    g.add_edge(3, 4, GM_REL_WRITE,   400);
    g.add_edge(6, 7, GM_REL_WRITE,   350);

    g.finalize();
    return g;
}

// ---------------------------------------------------------------------------
// Basic matching
// ---------------------------------------------------------------------------

TEST_SUITE("matcher") {

TEST_CASE("empty pattern returns empty") {
    auto g = build_lateral_movement();
    TemporalMatcher matcher(g);
    PatternCompiler compiler;
    auto query = compiler.compile_simple({}, GM_ENTITY_IP, 0);
    auto results = matcher.match(query);
    CHECK(results.empty());
}

TEST_CASE("single step match") {
    auto g = build_lateral_movement();
    TemporalMatcher matcher(g);
    PatternCompiler compiler;

    // IP -[Connect]-> Host
    std::vector<PatternStep> steps = {
        {GM_ENTITY_HOST, GM_REL_CONNECT, true},
    };
    auto query = compiler.compile_simple(steps, GM_ENTITY_IP, 0);
    auto results = matcher.match(query);

    REQUIRE(results.size() == 1);
    CHECK(results[0].path.size() == 2); // [IP, Host]
    CHECK(results[0].path[0] == 0);
    CHECK(results[0].path[1] == 1);
    CHECK(results[0].timestamps.size() == 1);
    CHECK(results[0].timestamps[0] == 100);
}

TEST_CASE("full 4-step chain") {
    auto g = build_lateral_movement();
    TemporalMatcher matcher(g);
    PatternCompiler compiler;

    // IP -[Connect]-> Host -[Auth]-> User -[Execute]-> Process -[Write]-> File
    std::vector<PatternStep> steps = {
        {GM_ENTITY_HOST,    GM_REL_CONNECT, true},
        {GM_ENTITY_USER,    GM_REL_AUTH,    true},
        {GM_ENTITY_PROCESS, GM_REL_EXECUTE, true},
        {GM_ENTITY_FILE,    GM_REL_WRITE,   true},
    };
    auto query = compiler.compile_simple(steps, GM_ENTITY_IP, 0);
    auto results = matcher.match(query);

    REQUIRE(results.size() == 1);
    CHECK(results[0].path.size() == 5);
    CHECK(results[0].path[0] == 0); // IP
    CHECK(results[0].path[1] == 1); // Host
    CHECK(results[0].path[2] == 2); // User
    CHECK(results[0].path[3] == 3); // Process
    CHECK(results[0].path[4] == 4); // File

    // Timestamps must be monotonically increasing
    for (size_t i = 1; i < results[0].timestamps.size(); ++i) {
        CHECK(results[0].timestamps[i] >= results[0].timestamps[i - 1]);
    }
}

TEST_CASE("no match with wrong relation type") {
    auto g = build_lateral_movement();
    TemporalMatcher matcher(g);
    PatternCompiler compiler;

    // IP -[Auth]-> Host — wrong relation (should be Connect)
    std::vector<PatternStep> steps = {
        {GM_ENTITY_HOST, GM_REL_AUTH, true},
    };
    auto query = compiler.compile_simple(steps, GM_ENTITY_IP, 0);
    auto results = matcher.match(query);
    CHECK(results.empty());
}

TEST_CASE("no match with wrong entity type") {
    auto g = build_lateral_movement();
    TemporalMatcher matcher(g);
    PatternCompiler compiler;

    // IP -[Connect]-> Process — wrong entity (should be Host)
    std::vector<PatternStep> steps = {
        {GM_ENTITY_PROCESS, GM_REL_CONNECT, true},
    };
    auto query = compiler.compile_simple(steps, GM_ENTITY_IP, 0);
    auto results = matcher.match(query);
    CHECK(results.empty());
}

TEST_CASE("wildcard relation matches any") {
    auto g = build_lateral_movement();
    TemporalMatcher matcher(g);
    PatternCompiler compiler;

    // IP -[*]-> Host
    std::vector<PatternStep> steps = {
        {GM_ENTITY_HOST, GM_REL_ANY, true},
    };
    auto query = compiler.compile_simple(steps, GM_ENTITY_IP, 0);
    auto results = matcher.match(query);
    CHECK(results.size() == 1);
}

TEST_CASE("wildcard entity matches any") {
    auto g = build_lateral_movement();
    TemporalMatcher matcher(g);
    PatternCompiler compiler;

    // IP -[Connect]-> *
    std::vector<PatternStep> steps = {
        {GM_ENTITY_ANY, GM_REL_CONNECT, true},
    };
    auto query = compiler.compile_simple(steps, GM_ENTITY_IP, 0);
    auto results = matcher.match(query);
    CHECK(results.size() == 1);
}

TEST_CASE("branching graph finds two paths") {
    auto g = build_branching_graph();
    TemporalMatcher matcher(g);
    PatternCompiler compiler;

    std::vector<PatternStep> steps = {
        {GM_ENTITY_HOST,    GM_REL_CONNECT, true},
        {GM_ENTITY_USER,    GM_REL_AUTH,    true},
        {GM_ENTITY_PROCESS, GM_REL_EXECUTE, true},
        {GM_ENTITY_FILE,    GM_REL_WRITE,   true},
    };
    auto query = compiler.compile_simple(steps, GM_ENTITY_IP, 0);
    auto results = matcher.match(query, 100);

    CHECK(results.size() == 2);

    // Both paths should have 5 nodes
    for (auto& r : results) {
        CHECK(r.path.size() == 5);
        CHECK(r.path[0] == 0); // IP
        CHECK(r.path[1] == 1); // Host
        // Then diverge: User 2 or 5
    }
}

TEST_CASE("max_results limits output") {
    auto g = build_branching_graph();
    TemporalMatcher matcher(g);
    PatternCompiler compiler;

    std::vector<PatternStep> steps = {
        {GM_ENTITY_HOST,    GM_REL_CONNECT, true},
        {GM_ENTITY_USER,    GM_REL_AUTH,    true},
        {GM_ENTITY_PROCESS, GM_REL_EXECUTE, true},
        {GM_ENTITY_FILE,    GM_REL_WRITE,   true},
    };
    auto query = compiler.compile_simple(steps, GM_ENTITY_IP, 0);
    auto results = matcher.match(query, 1);

    CHECK(results.size() == 1);
}

TEST_CASE("causal monotonicity prevents backward-in-time matches") {
    CSRTemporalGraph g;
    g.add_node(0, GM_ENTITY_IP);
    g.add_node(1, GM_ENTITY_HOST);
    g.add_node(2, GM_ENTITY_USER);

    // Edges go backward in time: 300 → 100
    g.add_edge(0, 1, GM_REL_CONNECT, 300);
    g.add_edge(1, 2, GM_REL_AUTH,    100); // timestamp < previous!

    g.finalize();

    TemporalMatcher matcher(g);
    PatternCompiler compiler;

    std::vector<PatternStep> steps = {
        {GM_ENTITY_HOST, GM_REL_CONNECT, true},
        {GM_ENTITY_USER, GM_REL_AUTH,    true},
    };
    auto query = compiler.compile_simple(steps, GM_ENTITY_IP, 0);
    auto results = matcher.match(query);

    // Should not match: causal monotonicity violated
    CHECK(results.empty());
}

TEST_CASE("time window constraint") {
    CSRTemporalGraph g;
    g.add_node(0, GM_ENTITY_IP);
    g.add_node(1, GM_ENTITY_HOST);
    g.add_node(2, GM_ENTITY_USER);

    g.add_edge(0, 1, GM_REL_CONNECT, 1000);
    g.add_edge(1, 2, GM_REL_AUTH,    5000); // 4 seconds later

    g.finalize();

    TemporalMatcher matcher(g);
    PatternCompiler compiler;

    std::vector<PatternStep> steps = {
        {GM_ENTITY_HOST, GM_REL_CONNECT, true},
        {GM_ENTITY_USER, GM_REL_AUTH,    true},
    };

    // Window of 10 seconds → should match
    auto q1 = compiler.compile_simple(steps, GM_ENTITY_IP, 10000);
    auto r1 = matcher.match(q1);
    CHECK(r1.size() == 1);

    // Window of 2 seconds → should NOT match (gap is 4 seconds)
    auto q2 = compiler.compile_simple(steps, GM_ENTITY_IP, 2000);
    auto r2 = matcher.match(q2);
    CHECK(r2.empty());
}

TEST_CASE("cycle avoidance prevents revisiting nodes") {
    CSRTemporalGraph g;
    g.add_node(0, GM_ENTITY_HOST);
    g.add_node(1, GM_ENTITY_HOST);

    // Cycle: 0 → 1 → 0
    g.add_edge(0, 1, GM_REL_CONNECT, 100);
    g.add_edge(1, 0, GM_REL_CONNECT, 200);

    g.finalize();

    TemporalMatcher matcher(g);
    PatternCompiler compiler;

    // Two-step pattern: Host -[Connect]-> Host -[Connect]-> Host
    // With k=1, node 0 can't be revisited, so no 3-node path exists
    std::vector<PatternStep> steps = {
        {GM_ENTITY_HOST, GM_REL_CONNECT, true},
        {GM_ENTITY_HOST, GM_REL_CONNECT, true},
    };
    auto query = compiler.compile_simple(steps, GM_ENTITY_HOST, 0);
    auto results = matcher.match(query, 1000, 0.0f, 1);

    // From node 0: 0→1→(0 blocked) — no complete path
    // From node 1: 1→0→(1 blocked) — no complete path
    CHECK(results.empty());
}

TEST_CASE("match confidence is 1.0 for complete matches") {
    auto g = build_lateral_movement();
    TemporalMatcher matcher(g);
    PatternCompiler compiler;

    std::vector<PatternStep> steps = {
        {GM_ENTITY_HOST, GM_REL_CONNECT, true},
    };
    auto query = compiler.compile_simple(steps, GM_ENTITY_IP, 0);
    auto results = matcher.match(query);

    REQUIRE(!results.empty());
    CHECK(results[0].match_confidence == doctest::Approx(1.0f));
}

} // TEST_SUITE matcher

// ---------------------------------------------------------------------------
// Larger graph stress test
// ---------------------------------------------------------------------------

TEST_SUITE("matcher_stress") {

TEST_CASE("linear chain of 100 nodes") {
    CSRTemporalGraph g;
    for (uint32_t i = 0; i < 100; ++i) {
        g.add_node(i, (i % 2 == 0) ? GM_ENTITY_HOST : GM_ENTITY_PROCESS);
    }
    for (uint32_t i = 0; i < 99; ++i) {
        g.add_edge(i, i + 1, GM_REL_EXECUTE, static_cast<Timestamp>(i * 100));
    }
    g.finalize();

    TemporalMatcher matcher(g);
    PatternCompiler compiler;

    // 2-step pattern: Host -[Execute]-> Process -[Execute]-> Host
    std::vector<PatternStep> steps = {
        {GM_ENTITY_PROCESS, GM_REL_EXECUTE, true},
        {GM_ENTITY_HOST,    GM_REL_EXECUTE, true},
    };
    auto query = compiler.compile_simple(steps, GM_ENTITY_HOST, 0);
    auto results = matcher.match(query, 10000);

    // Each even node 0,2,4,...,96 can start a chain:
    // even(i) → odd(i+1) → even(i+2)
    // That's 49 matches (nodes 0→1→2, 2→3→4, ... 96→97→98)
    CHECK(results.size() == 49);
}

TEST_CASE("fan-out graph") {
    // Hub node connected to many leaves
    CSRTemporalGraph g;
    g.add_node(0, GM_ENTITY_HOST);
    for (uint32_t i = 1; i <= 50; ++i) {
        g.add_node(i, GM_ENTITY_FILE);
        g.add_edge(0, i, GM_REL_WRITE, static_cast<Timestamp>(i * 10));
    }
    g.finalize();

    TemporalMatcher matcher(g);
    PatternCompiler compiler;

    std::vector<PatternStep> steps = {
        {GM_ENTITY_FILE, GM_REL_WRITE, true},
    };
    auto query = compiler.compile_simple(steps, GM_ENTITY_HOST, 0);
    auto results = matcher.match(query, 10000);

    CHECK(results.size() == 50);
}

} // TEST_SUITE matcher_stress
