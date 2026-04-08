/// @file test_csr_graph.cpp
/// @brief Unit tests for CSR Temporal Multigraph Store.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "graphmatch/csr_graph.hpp"
#include "graphmatch/types.h"

using namespace gm;

// ---------------------------------------------------------------------------
// Helper: build a small lateral movement graph.
// Topology: IP(0) -[Connect@100]-> Host(1) -[Auth@200]-> User(2)
//                                                         -[Execute@300]-> Process(3)
//                                                                          -[Write@400]-> File(4)
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

// ---------------------------------------------------------------------------
// Basic construction
// ---------------------------------------------------------------------------

TEST_SUITE("construction") {

TEST_CASE("empty graph") {
    CSRTemporalGraph g;
    g.finalize();
    CHECK(g.node_count() == 0);
    CHECK(g.edge_count() == 0);
    CHECK(g.is_finalized());
}

TEST_CASE("nodes only") {
    CSRTemporalGraph g;
    g.add_node(0, GM_ENTITY_IP);
    g.add_node(1, GM_ENTITY_HOST);
    g.add_node(2, GM_ENTITY_USER);
    g.finalize();
    CHECK(g.node_count() == 3);
    CHECK(g.edge_count() == 0);
}

TEST_CASE("lateral movement graph") {
    auto g = build_lateral_movement();
    CHECK(g.node_count() == 5);
    CHECK(g.edge_count() == 4);
}

TEST_CASE("node types are correct") {
    auto g = build_lateral_movement();
    CHECK(g.node_type(0) == GM_ENTITY_IP);
    CHECK(g.node_type(1) == GM_ENTITY_HOST);
    CHECK(g.node_type(2) == GM_ENTITY_USER);
    CHECK(g.node_type(3) == GM_ENTITY_PROCESS);
    CHECK(g.node_type(4) == GM_ENTITY_FILE);
}

TEST_CASE("node scores default to zero") {
    auto g = build_lateral_movement();
    for (uint32_t i = 0; i < 5; ++i) {
        CHECK(g.node_score(i) == 0.0f);
    }
}

TEST_CASE("set and get node score") {
    CSRTemporalGraph g;
    g.add_node(0, GM_ENTITY_IP);
    g.set_node_score(0, 0.75f);
    g.finalize();
    CHECK(g.node_score(0) == doctest::Approx(0.75f));
}

TEST_CASE("double finalize is idempotent") {
    auto g = build_lateral_movement();
    uint32_t nc = g.node_count();
    uint32_t ec = g.edge_count();
    g.finalize(); // second call
    CHECK(g.node_count() == nc);
    CHECK(g.edge_count() == ec);
}

} // TEST_SUITE construction

// ---------------------------------------------------------------------------
// add_edge boundary behavior
//
// Contract (current, asymmetric):
//   - add_edge() itself does NOT validate src/dst against node_count_; it
//     just pushes into pending_edges_.
//   - build_forward_csr() skips edges whose `source >= node_count_` but does
//     NOT validate `target` — a dst-OOB edge lands in edge_list_ with a
//     dangling target id that downstream code (matcher.hpp DFS) will index
//     into a node-sized vector, producing out-of-bounds access.
//   - build_reverse_csr() is the mirror: skips `target >= node_count_` but
//     keeps src-OOB edges in rev_edge_list_ with a dangling source id.
//
// These tests pin the boundary behavior at the exact line so:
//   1. A regression that turns "valid id at node_count_-1" into a drop is caught.
//   2. A future tightening that fully rejects OOB edges (preferred fix for
//      finding #4 in the post-merge security review) updates the OOB cases
//      to `edge_count() == 0` and the dangling-reference assertions go away.
//
// FIXME(security): The asymmetric drop is a real defense-in-depth gap. The
// matcher in matcher.hpp does `visit_count[e.target]++` where visit_count is
// sized to node_count() — feeding it a dst-OOB edge is undefined behavior in
// release. The right fix is to validate eagerly in add_edge() and drop bad
// edges before they ever hit pending_edges_. Tracked in the post-merge
// security review notes.
// ---------------------------------------------------------------------------

TEST_SUITE("add_edge_boundary") {

// Helper: 2-node graph so node_count_ == 2 and max valid id == 1.
static CSRTemporalGraph two_node_graph() {
    CSRTemporalGraph g;
    g.add_node(0, GM_ENTITY_HOST);
    g.add_node(1, GM_ENTITY_PROCESS);
    return g;
}

TEST_CASE("src == node_count_ - 1 is accepted (max valid source)") {
    auto g = two_node_graph();
    g.add_edge(1, 0, GM_REL_EXECUTE, 100); // src = 1 == node_count_-1
    g.finalize();

    CHECK(g.node_count() == 2);
    // Forward CSR holds it (valid src), reverse CSR holds it (valid dst).
    // pending_edges_.size() == 1 → edge_list_.size() == 1.
    CHECK(g.edge_count() == 1);

    size_t count = 0;
    const TemporalEdge* edges = g.outgoing(1, count);
    REQUIRE(count == 1);
    CHECK(edges[0].target == 0);
    CHECK(edges[0].rel_type == GM_REL_EXECUTE);

    const TemporalEdge* rev = g.incoming(0, count);
    REQUIRE(count == 1);
    CHECK(rev[0].target == 1); // reverse stores source in `target`
}

TEST_CASE("dst == node_count_ - 1 is accepted (max valid target)") {
    auto g = two_node_graph();
    g.add_edge(0, 1, GM_REL_EXECUTE, 100); // dst = 1 == node_count_-1
    g.finalize();

    CHECK(g.edge_count() == 1);

    size_t count = 0;
    const TemporalEdge* edges = g.outgoing(0, count);
    REQUIRE(count == 1);
    CHECK(edges[0].target == 1);

    const TemporalEdge* rev = g.incoming(1, count);
    REQUIRE(count == 1);
    CHECK(rev[0].target == 0);
}

// The next two tests pin the *current* asymmetric behavior. When the
// security fix lands, both should be tightened to assert that the edge is
// fully dropped from BOTH CSRs and outgoing/incoming on the OOB id returns
// nullptr. See the FIXME above.

TEST_CASE("src == node_count_ — dropped from forward CSR, kept in reverse (current behavior)") {
    auto g = two_node_graph();
    g.add_edge(2, 0, GM_REL_EXECUTE, 100); // src = 2 == node_count_, OOB
    g.finalize();

    // edge_list_ is sized to pending_edges_.size() = 1, but the fill loop
    // skips this edge — slot 0 is zero-initialized (target=0, rel=0, ts=0).
    // edge_count() returns edge_list_.size(), so it reads as 1.
    CHECK(g.edge_count() == 1);

    // outgoing() on the OOB id is bounds-checked safely → empty.
    size_t count = 99;
    const TemporalEdge* fwd_oob = g.outgoing(2, count);
    CHECK(count == 0);
    CHECK(fwd_oob == nullptr);

    // outgoing() on a valid id has no real edges from node 0 either.
    const TemporalEdge* fwd_0 = g.outgoing(0, count);
    CHECK(count == 0);

    // BUT the reverse CSR keeps the edge with the dangling source id (=2)
    // stored in the `target` field. This is the dangling reference.
    const TemporalEdge* rev = g.incoming(0, count);
    REQUIRE(count == 1);
    CHECK(rev[0].target == 2); // OOB id leaks into the reverse edge list
    // FIXME(security): when add_edge() validates eagerly, this becomes
    // CHECK(count == 0) and the rev-list assertion is removed.
}

TEST_CASE("dst == node_count_ — kept in forward CSR with dangling target, dropped from reverse (current behavior)") {
    auto g = two_node_graph();
    g.add_edge(0, 2, GM_REL_EXECUTE, 100); // dst = 2 == node_count_, OOB
    g.finalize();

    CHECK(g.edge_count() == 1);

    // The forward CSR keeps the edge with the dangling target id (=2).
    // This is the dangling reference that the matcher's DFS would index
    // into a node_count_-sized visit_count vector.
    size_t count = 0;
    const TemporalEdge* fwd = g.outgoing(0, count);
    REQUIRE(count == 1);
    CHECK(fwd[0].target == 2); // OOB id leaks into the forward edge list

    // Reverse CSR drops it (target check skips).
    const TemporalEdge* rev_oob = g.incoming(2, count);
    CHECK(count == 0);
    CHECK(rev_oob == nullptr);

    // FIXME(security): when add_edge() validates eagerly, this becomes
    // CHECK(g.edge_count() == 0) and the fwd-list assertion is removed.
}

TEST_CASE("mixed batch: valid edges have correct outgoing slot") {
    auto g = two_node_graph();
    g.add_edge(0, 1, GM_REL_EXECUTE, 100); // valid
    g.add_edge(2, 0, GM_REL_EXECUTE, 200); // OOB src — fwd dropped, rev kept
    g.add_edge(1, 0, GM_REL_EXECUTE, 300); // valid
    g.add_edge(0, 2, GM_REL_EXECUTE, 400); // OOB dst — fwd kept, rev dropped
    g.finalize();

    // Each valid source still has its real outgoing edge reachable.
    size_t count = 0;
    const TemporalEdge* from_0 = g.outgoing(0, count);
    REQUIRE(count >= 1);
    // Find the real edge (target == 1, ts == 100); the OOB one has target == 2.
    bool found_real = false;
    for (size_t i = 0; i < count; ++i) {
        if (from_0[i].target == 1 && from_0[i].timestamp == 100) {
            found_real = true;
            CHECK(from_0[i].rel_type == GM_REL_EXECUTE);
        }
    }
    CHECK(found_real);

    const TemporalEdge* from_1 = g.outgoing(1, count);
    REQUIRE(count == 1);
    CHECK(from_1[0].target == 0);
    CHECK(from_1[0].timestamp == 300);
}

} // TEST_SUITE add_edge_boundary

// ---------------------------------------------------------------------------
// Outgoing edges
// ---------------------------------------------------------------------------

TEST_SUITE("outgoing") {

TEST_CASE("basic outgoing") {
    auto g = build_lateral_movement();
    size_t count = 0;

    // Node 0 (IP) has one outgoing: Connect to Host
    const TemporalEdge* edges = g.outgoing(0, count);
    REQUIRE(count == 1);
    CHECK(edges[0].target == 1);
    CHECK(edges[0].rel_type == GM_REL_CONNECT);
    CHECK(edges[0].timestamp == 100);
}

TEST_CASE("leaf node has no outgoing") {
    auto g = build_lateral_movement();
    size_t count = 0;
    const TemporalEdge* edges = g.outgoing(4, count);
    CHECK(count == 0);
}

TEST_CASE("invalid node returns empty") {
    auto g = build_lateral_movement();
    size_t count = 999;
    const TemporalEdge* edges = g.outgoing(999, count);
    CHECK(count == 0);
    CHECK(edges == nullptr);
}

TEST_CASE("edges sorted by timestamp") {
    CSRTemporalGraph g;
    g.add_node(0, GM_ENTITY_HOST);
    g.add_node(1, GM_ENTITY_PROCESS);
    g.add_node(2, GM_ENTITY_FILE);
    g.add_node(3, GM_ENTITY_DOMAIN);

    // Add edges out of timestamp order
    g.add_edge(0, 3, GM_REL_DNS,     300);
    g.add_edge(0, 1, GM_REL_EXECUTE, 100);
    g.add_edge(0, 2, GM_REL_WRITE,   200);

    g.finalize();

    size_t count = 0;
    const TemporalEdge* edges = g.outgoing(0, count);
    REQUIRE(count == 3);
    CHECK(edges[0].timestamp == 100);
    CHECK(edges[1].timestamp == 200);
    CHECK(edges[2].timestamp == 300);
}

TEST_CASE("multi-edge (multigraph)") {
    CSRTemporalGraph g;
    g.add_node(0, GM_ENTITY_HOST);
    g.add_node(1, GM_ENTITY_FILE);

    // Multiple edges between same pair (different timestamps/types)
    g.add_edge(0, 1, GM_REL_READ,  100);
    g.add_edge(0, 1, GM_REL_WRITE, 200);
    g.add_edge(0, 1, GM_REL_READ,  300);

    g.finalize();

    size_t count = 0;
    const TemporalEdge* edges = g.outgoing(0, count);
    REQUIRE(count == 3);
    CHECK(edges[0].timestamp <= edges[1].timestamp);
    CHECK(edges[1].timestamp <= edges[2].timestamp);
}

} // TEST_SUITE outgoing

// ---------------------------------------------------------------------------
// Incoming (reverse) edges
// ---------------------------------------------------------------------------

TEST_SUITE("incoming") {

TEST_CASE("basic incoming") {
    auto g = build_lateral_movement();
    size_t count = 0;

    // Node 1 (Host) has one incoming: Connect from IP
    const TemporalEdge* edges = g.incoming(1, count);
    REQUIRE(count == 1);
    CHECK(edges[0].target == 0); // In reverse CSR, "target" is the source
    CHECK(edges[0].rel_type == GM_REL_CONNECT);
}

TEST_CASE("root node has no incoming") {
    auto g = build_lateral_movement();
    size_t count = 0;
    g.incoming(0, count);
    CHECK(count == 0);
}

TEST_CASE("fan-in node") {
    CSRTemporalGraph g;
    g.add_node(0, GM_ENTITY_IP);
    g.add_node(1, GM_ENTITY_IP);
    g.add_node(2, GM_ENTITY_HOST);

    g.add_edge(0, 2, GM_REL_CONNECT, 100);
    g.add_edge(1, 2, GM_REL_CONNECT, 200);

    g.finalize();

    size_t count = 0;
    const TemporalEdge* edges = g.incoming(2, count);
    REQUIRE(count == 2);
}

} // TEST_SUITE incoming

// ---------------------------------------------------------------------------
// Temporal window queries
// ---------------------------------------------------------------------------

TEST_SUITE("temporal_window") {

TEST_CASE("full window returns all") {
    auto g = build_lateral_movement();
    size_t count = 0;
    // Node 0 has edge at t=100
    const TemporalEdge* edges = g.outgoing_in_window(0, 0, 1000, count);
    CHECK(count == 1);
}

TEST_CASE("narrow window includes only matching") {
    CSRTemporalGraph g;
    g.add_node(0, GM_ENTITY_HOST);
    g.add_node(1, GM_ENTITY_PROCESS);
    g.add_node(2, GM_ENTITY_FILE);
    g.add_node(3, GM_ENTITY_DOMAIN);

    g.add_edge(0, 1, GM_REL_EXECUTE, 100);
    g.add_edge(0, 2, GM_REL_WRITE,   200);
    g.add_edge(0, 3, GM_REL_DNS,     300);

    g.finalize();

    size_t count = 0;
    const TemporalEdge* edges = g.outgoing_in_window(0, 150, 250, count);
    REQUIRE(count == 1);
    CHECK(edges[0].target == 2);
    CHECK(edges[0].timestamp == 200);
}

TEST_CASE("window excludes all") {
    auto g = build_lateral_movement();
    size_t count = 0;
    g.outgoing_in_window(0, 500, 1000, count);
    CHECK(count == 0);
}

TEST_CASE("exact boundary inclusion") {
    CSRTemporalGraph g;
    g.add_node(0, GM_ENTITY_HOST);
    g.add_node(1, GM_ENTITY_FILE);

    g.add_edge(0, 1, GM_REL_WRITE, 200);
    g.finalize();

    size_t count = 0;
    // Exact match on both bounds
    g.outgoing_in_window(0, 200, 200, count);
    CHECK(count == 1);
}

} // TEST_SUITE temporal_window

// ---------------------------------------------------------------------------
// Sorted neighbors for SIMD
// ---------------------------------------------------------------------------

TEST_SUITE("sorted_neighbors") {

TEST_CASE("basic sorted neighbors") {
    CSRTemporalGraph g;
    g.add_node(0, GM_ENTITY_HOST);
    g.add_node(1, GM_ENTITY_PROCESS);
    g.add_node(2, GM_ENTITY_FILE);
    g.add_node(3, GM_ENTITY_DOMAIN);

    // Add edges: 0 -> {3, 1, 2} (not in sorted order)
    g.add_edge(0, 3, GM_REL_DNS,     300);
    g.add_edge(0, 1, GM_REL_EXECUTE, 100);
    g.add_edge(0, 2, GM_REL_WRITE,   200);

    g.finalize();

    size_t count = 0;
    const uint32_t* neigh = g.sorted_neighbors(0, count);
    REQUIRE(count == 3);
    // Must be sorted ascending
    CHECK(neigh[0] == 1);
    CHECK(neigh[1] == 2);
    CHECK(neigh[2] == 3);
}

TEST_CASE("deduplicated when multi-edges") {
    CSRTemporalGraph g;
    g.add_node(0, GM_ENTITY_HOST);
    g.add_node(1, GM_ENTITY_FILE);

    g.add_edge(0, 1, GM_REL_READ,  100);
    g.add_edge(0, 1, GM_REL_WRITE, 200);
    g.add_edge(0, 1, GM_REL_READ,  300);

    g.finalize();

    size_t count = 0;
    const uint32_t* neigh = g.sorted_neighbors(0, count);
    REQUIRE(count == 1); // Deduplicated
    CHECK(neigh[0] == 1);
}

} // TEST_SUITE sorted_neighbors

// ---------------------------------------------------------------------------
// Type index
// ---------------------------------------------------------------------------

TEST_SUITE("type_index") {

TEST_CASE("nodes_of_type returns correct sets") {
    auto g = build_lateral_movement();
    size_t count = 0;

    const uint32_t* ips = g.nodes_of_type(GM_ENTITY_IP, count);
    CHECK(count == 1);
    CHECK(ips[0] == 0);

    const uint32_t* hosts = g.nodes_of_type(GM_ENTITY_HOST, count);
    CHECK(count == 1);
    CHECK(hosts[0] == 1);
}

TEST_CASE("non-existent type returns empty") {
    auto g = build_lateral_movement();
    size_t count = 99;
    const uint32_t* svc = g.nodes_of_type(GM_ENTITY_SERVICE, count);
    CHECK(count == 0);
}

} // TEST_SUITE type_index

// ---------------------------------------------------------------------------
// String interner
// ---------------------------------------------------------------------------

TEST_SUITE("interner") {

TEST_CASE("intern and resolve") {
    StringInterner si;
    uint32_t id = si.intern("attacker-ip");
    CHECK(id == 0);
    CHECK(std::string(si.resolve(id)) == "attacker-ip");
}

TEST_CASE("duplicate interning returns same id") {
    StringInterner si;
    uint32_t a = si.intern("host-1");
    uint32_t b = si.intern("host-1");
    CHECK(a == b);
}

TEST_CASE("get without interning") {
    StringInterner si;
    CHECK(si.get("missing") == GM_INVALID_NODE);
    si.intern("present");
    CHECK(si.get("present") == 0);
}

} // TEST_SUITE interner
