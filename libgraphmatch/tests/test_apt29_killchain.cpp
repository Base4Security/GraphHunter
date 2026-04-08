/// @file test_apt29_killchain.cpp
/// @brief End-to-end validation: APT29-like kill chain matching.
///
/// Reproduces Graph Hunter's APT29 test scenario using the C++ engine.
/// Validates that the matcher correctly identifies multi-step attack
/// patterns in a realistic graph with both malicious and benign activity.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "graphmatch/graphmatch.h"
#include "graphmatch/csr_graph.hpp"
#include "graphmatch/matcher.hpp"
#include "graphmatch/pattern.hpp"
#include "graphmatch/scorer.hpp"
#include "graphmatch/types.h"

#include <cstring>

using namespace gm;

// ---------------------------------------------------------------------------
// Build an APT29-like attack simulation graph.
//
// Based on demo_data/apt_attack_simulation.json and the MITRE ATT&CK
// framework for APT29 (Cozy Bear).
//
// Kill chain:
//   C2-IP → Connect → DMZ-Host → Auth → Service-Account → Execute → PowerShell
//     → Spawn → mimikatz.exe → Write → credentials.dmp → Read → PsExec
//     → Connect → DC-Host
//
// Background (benign) activity is interspersed to test selectivity.
// ---------------------------------------------------------------------------

static CSRTemporalGraph build_apt29_graph() {
    CSRTemporalGraph g;

    // --- Entities ---
    // Attack chain
    enum : NodeId {
        C2_IP         = 0,
        DMZ_HOST      = 1,
        SVC_ACCOUNT   = 2,
        POWERSHELL    = 3,
        MIMIKATZ      = 4,
        CRED_DUMP     = 5,
        PSEXEC        = 6,
        DC_HOST       = 7,
        // Benign entities
        SVCHOST       = 8,
        OUTLOOK       = 9,
        CHROME        = 10,
        NORMAL_FILE   = 11,
        ADMIN_USER    = 12,
        NORMAL_IP     = 13,
        DNS_SERVER    = 14,
        UPDATE_HOST   = 15,
    };

    g.add_node(C2_IP,       GM_ENTITY_IP);
    g.add_node(DMZ_HOST,    GM_ENTITY_HOST);
    g.add_node(SVC_ACCOUNT, GM_ENTITY_USER);
    g.add_node(POWERSHELL,  GM_ENTITY_PROCESS);
    g.add_node(MIMIKATZ,    GM_ENTITY_PROCESS);
    g.add_node(CRED_DUMP,   GM_ENTITY_FILE);
    g.add_node(PSEXEC,      GM_ENTITY_PROCESS);
    g.add_node(DC_HOST,     GM_ENTITY_HOST);

    g.add_node(SVCHOST,     GM_ENTITY_PROCESS);
    g.add_node(OUTLOOK,     GM_ENTITY_PROCESS);
    g.add_node(CHROME,      GM_ENTITY_PROCESS);
    g.add_node(NORMAL_FILE, GM_ENTITY_FILE);
    g.add_node(ADMIN_USER,  GM_ENTITY_USER);
    g.add_node(NORMAL_IP,   GM_ENTITY_IP);
    g.add_node(DNS_SERVER,  GM_ENTITY_HOST);
    g.add_node(UPDATE_HOST, GM_ENTITY_HOST);

    // --- Benign background activity (12:00 - 13:50) ---
    // Timestamps in seconds, starting at 43200 (12:00)
    g.add_edge(SVCHOST, NORMAL_FILE, GM_REL_WRITE, 43200); // svchost writes log
    g.add_edge(CHROME, NORMAL_IP, GM_REL_CONNECT, 43500);  // Chrome browsing
    g.add_edge(OUTLOOK, NORMAL_FILE, GM_REL_READ, 44000);  // Outlook reads attachment
    g.add_edge(ADMIN_USER, DMZ_HOST, GM_REL_AUTH, 44500);  // Legit admin login
    g.add_edge(DMZ_HOST, DNS_SERVER, GM_REL_CONNECT, 44800); // DNS query
    g.add_edge(SVCHOST, UPDATE_HOST, GM_REL_CONNECT, 45000); // Windows Update

    // More benign: high-frequency svchost activity
    for (int i = 0; i < 20; ++i) {
        g.add_edge(SVCHOST, NORMAL_FILE, GM_REL_WRITE, 43200 + i * 60);
        g.add_edge(SVCHOST, DNS_SERVER, GM_REL_CONNECT, 43230 + i * 60);
    }

    // --- Attack Phase 1: Initial Compromise (14:00 = 50400) ---
    g.add_edge(C2_IP, DMZ_HOST, GM_REL_CONNECT, 50400);         // C2 connects to DMZ

    // --- Attack Phase 2: Auth + Execution (14:02) ---
    g.add_edge(DMZ_HOST, SVC_ACCOUNT, GM_REL_AUTH, 50520);      // Compromised auth

    // --- Attack Phase 3: PowerShell + Credential Theft (14:05) ---
    g.add_edge(SVC_ACCOUNT, POWERSHELL, GM_REL_EXECUTE, 50700); // PowerShell launched
    g.add_edge(POWERSHELL, MIMIKATZ, GM_REL_SPAWN, 50760);      // mimikatz spawned
    g.add_edge(MIMIKATZ, CRED_DUMP, GM_REL_WRITE, 50820);       // Credential dump

    // --- Attack Phase 4: Lateral Movement (14:10) ---
    g.add_edge(CRED_DUMP, PSEXEC, GM_REL_READ, 51000);          // PsExec reads creds
    g.add_edge(PSEXEC, DC_HOST, GM_REL_CONNECT, 51060);         // Lateral to DC

    // Post-attack benign noise
    g.add_edge(CHROME, NORMAL_IP, GM_REL_CONNECT, 51200);
    g.add_edge(SVCHOST, NORMAL_FILE, GM_REL_WRITE, 51300);

    g.finalize();
    return g;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST_SUITE("apt29") {

TEST_CASE("full kill chain: C2→DMZ→Auth→Execute→Spawn→Write→Read→Connect") {
    auto g = build_apt29_graph();
    TemporalMatcher matcher(g);
    PatternCompiler compiler;

    // 7-step hypothesis matching the full APT29 kill chain
    std::vector<PatternStep> steps = {
        {GM_ENTITY_HOST,    GM_REL_CONNECT, true},  // C2 → DMZ-Host
        {GM_ENTITY_USER,    GM_REL_AUTH,    true},  // DMZ → Service-Account
        {GM_ENTITY_PROCESS, GM_REL_EXECUTE, true},  // Account → PowerShell
        {GM_ENTITY_PROCESS, GM_REL_SPAWN,   true},  // PS → mimikatz
        {GM_ENTITY_FILE,    GM_REL_WRITE,   true},  // mimikatz → credentials.dmp
        {GM_ENTITY_PROCESS, GM_REL_READ,    true},  // creds → PsExec
        {GM_ENTITY_HOST,    GM_REL_CONNECT, true},  // PsExec → DC-Host
    };

    auto query = compiler.compile_simple(steps, GM_ENTITY_IP, 0);
    auto results = matcher.match(query, 100);

    // Should find exactly one complete kill chain
    REQUIRE(results.size() == 1);

    auto& r = results[0];
    CHECK(r.path.size() == 8); // 7 steps + start node

    // Verify path: C2_IP → DMZ → SVC → PS → MIMI → CRED → PSEXEC → DC
    CHECK(r.path[0] == 0);  // C2_IP
    CHECK(r.path[1] == 1);  // DMZ_HOST
    CHECK(r.path[2] == 2);  // SVC_ACCOUNT
    CHECK(r.path[3] == 3);  // POWERSHELL
    CHECK(r.path[4] == 4);  // MIMIKATZ
    CHECK(r.path[5] == 5);  // CRED_DUMP
    CHECK(r.path[6] == 6);  // PSEXEC
    CHECK(r.path[7] == 7);  // DC_HOST

    // Verify causal monotonicity: timestamps must be non-decreasing
    for (size_t i = 1; i < r.timestamps.size(); ++i) {
        CHECK(r.timestamps[i] >= r.timestamps[i - 1]);
    }

    // Verify timestamps span the attack window (14:00 - 14:17)
    CHECK(r.timestamps.front() == 50400); // First edge: C2→DMZ
    CHECK(r.timestamps.back()  == 51060); // Last edge: PsExec→DC
}

TEST_CASE("partial chain: initial compromise only") {
    auto g = build_apt29_graph();
    TemporalMatcher matcher(g);
    PatternCompiler compiler;

    // 2-step: IP -[Connect]-> Host -[Auth]-> User
    std::vector<PatternStep> steps = {
        {GM_ENTITY_HOST, GM_REL_CONNECT, true},
        {GM_ENTITY_USER, GM_REL_AUTH,    true},
    };

    auto query = compiler.compile_simple(steps, GM_ENTITY_IP, 0);
    auto results = matcher.match(query, 100);

    // C2_IP → DMZ → SVC_ACCOUNT
    // The benign admin auth (ADMIN_USER→DMZ at 44500) shouldn't create
    // a match because it goes DMZ→Admin, not IP→DMZ→Auth
    // But NORMAL_IP doesn't have outgoing Connect edges in attack chain
    CHECK(results.size() >= 1);

    // At least one result should be the attack path
    bool found_attack = false;
    for (auto& r : results) {
        if (r.path[0] == 0 && r.path[1] == 1 && r.path[2] == 2) {
            found_attack = true;
        }
    }
    CHECK(found_attack);
}

TEST_CASE("credential theft sub-chain") {
    auto g = build_apt29_graph();
    TemporalMatcher matcher(g);
    PatternCompiler compiler;

    // Process -[Spawn]-> Process -[Write]-> File
    std::vector<PatternStep> steps = {
        {GM_ENTITY_PROCESS, GM_REL_SPAWN, true},
        {GM_ENTITY_FILE,    GM_REL_WRITE, true},
    };

    auto query = compiler.compile_simple(steps, GM_ENTITY_PROCESS, 0);
    auto results = matcher.match(query, 100);

    REQUIRE(results.size() >= 1);

    // Should find: PowerShell → mimikatz → credentials.dmp
    bool found = false;
    for (auto& r : results) {
        if (r.path.size() == 3 && r.path[0] == 3 && r.path[1] == 4 && r.path[2] == 5) {
            found = true;
        }
    }
    CHECK(found);
}

TEST_CASE("no false positives: wrong chain order") {
    auto g = build_apt29_graph();
    TemporalMatcher matcher(g);
    PatternCompiler compiler;

    // Reverse the chain: Host -[Connect]-> IP (no such edges in attack path)
    std::vector<PatternStep> steps = {
        {GM_ENTITY_IP, GM_REL_CONNECT, true},
    };

    auto query = compiler.compile_simple(steps, GM_ENTITY_HOST, 0);
    auto results = matcher.match(query, 100);

    // DMZ_HOST and DNS_SERVER connect to things, but to hosts/IPs
    // Chrome→NORMAL_IP is Process→IP, not Host→IP
    // Check no result contains the attack chain in reverse
    for (auto& r : results) {
        // Should NOT find DMZ→C2_IP (no such edge exists)
        bool is_reverse_attack = (r.path[0] == 1 && r.path[1] == 0);
        CHECK_FALSE(is_reverse_attack);
    }
}

TEST_CASE("time window filters out slow attacks") {
    auto g = build_apt29_graph();
    TemporalMatcher matcher(g);
    PatternCompiler compiler;

    std::vector<PatternStep> steps = {
        {GM_ENTITY_HOST,    GM_REL_CONNECT, true},
        {GM_ENTITY_USER,    GM_REL_AUTH,    true},
        {GM_ENTITY_PROCESS, GM_REL_EXECUTE, true},
        {GM_ENTITY_PROCESS, GM_REL_SPAWN,   true},
        {GM_ENTITY_FILE,    GM_REL_WRITE,   true},
        {GM_ENTITY_PROCESS, GM_REL_READ,    true},
        {GM_ENTITY_HOST,    GM_REL_CONNECT, true},
    };

    // Very tight window: 60 seconds (attack spans ~660 seconds: 50400→51060)
    auto q_tight = compiler.compile_simple(steps, GM_ENTITY_IP, 60);
    auto r_tight = matcher.match(q_tight, 100);
    CHECK(r_tight.empty());

    // Generous window: 3600 seconds — should find the chain
    auto q_wide = compiler.compile_simple(steps, GM_ENTITY_IP, 3600);
    auto r_wide = matcher.match(q_wide, 100);
    CHECK(r_wide.size() == 1);
}

} // TEST_SUITE apt29

// ---------------------------------------------------------------------------
// C ABI integration test
// ---------------------------------------------------------------------------

TEST_SUITE("cabi") {

TEST_CASE("full roundtrip via C ABI") {
    // Build graph via C API
    gm_graph_t* g = gm_graph_new();
    REQUIRE(g != nullptr);

    gm_graph_add_node(g, 0, GM_ENTITY_IP);
    gm_graph_add_node(g, 1, GM_ENTITY_HOST);
    gm_graph_add_node(g, 2, GM_ENTITY_USER);
    gm_graph_add_node(g, 3, GM_ENTITY_PROCESS);
    gm_graph_add_node(g, 4, GM_ENTITY_FILE);

    gm_graph_add_edge(g, 0, 1, GM_REL_CONNECT, 100);
    gm_graph_add_edge(g, 1, 2, GM_REL_AUTH,    200);
    gm_graph_add_edge(g, 2, 3, GM_REL_EXECUTE, 300);
    gm_graph_add_edge(g, 3, 4, GM_REL_WRITE,   400);

    gm_graph_finalize(g);

    CHECK(gm_graph_node_count(g) == 5);
    CHECK(gm_graph_edge_count(g) == 4);

    // Create matcher
    gm_matcher_t* m = gm_matcher_new(g);
    REQUIRE(m != nullptr);

    gm_matcher_set_start_type(m, GM_ENTITY_IP);
    gm_matcher_add_step(m, GM_ENTITY_HOST,    GM_REL_CONNECT, 1);
    gm_matcher_add_step(m, GM_ENTITY_USER,    GM_REL_AUTH,    1);
    gm_matcher_add_step(m, GM_ENTITY_PROCESS, GM_REL_EXECUTE, 1);
    gm_matcher_add_step(m, GM_ENTITY_FILE,    GM_REL_WRITE,   1);

    gm_results_t* r = gm_matcher_run(m, 100, 0.0f);
    REQUIRE(r != nullptr);

    CHECK(gm_results_count(r) == 1);

    uint32_t path_len = 0;
    const uint32_t* path = gm_results_get_path(r, 0, &path_len);
    REQUIRE(path != nullptr);
    CHECK(path_len == 5);
    CHECK(path[0] == 0);
    CHECK(path[4] == 4);

    const int64_t* ts = gm_results_get_timestamps(r, 0);
    REQUIRE(ts != nullptr);
    CHECK(ts[0] == 100);
    CHECK(ts[3] == 400);

    // JSON serialization
    char* json = gm_results_to_json(r);
    REQUIRE(json != nullptr);
    CHECK(std::strlen(json) > 10);
    // Should contain "path" and "timestamps"
    CHECK(std::strstr(json, "\"path\"") != nullptr);
    CHECK(std::strstr(json, "\"timestamps\"") != nullptr);
    gm_free_string(json);

    // SIMD ISA query
    const char* isa = gm_simd_isa();
    REQUIRE(isa != nullptr);
    CHECK(std::strlen(isa) > 0);

    // Cleanup
    gm_results_free(r);
    gm_matcher_free(m);
    gm_graph_free(g);
}

TEST_CASE("string interning via C ABI") {
    gm_graph_t* g = gm_graph_new();

    uint32_t id1 = gm_graph_intern(g, "attacker-ip");
    uint32_t id2 = gm_graph_intern(g, "dmz-host");
    uint32_t id3 = gm_graph_intern(g, "attacker-ip"); // duplicate

    CHECK(id1 == id3); // Same string → same ID
    CHECK(id1 != id2);

    const char* name = gm_graph_resolve(g, id1);
    REQUIRE(name != nullptr);
    CHECK(std::strcmp(name, "attacker-ip") == 0);

    gm_graph_free(g);
}

TEST_CASE("NULL safety") {
    // All functions should handle NULL gracefully
    gm_graph_free(nullptr);
    gm_matcher_free(nullptr);
    gm_results_free(nullptr);
    gm_free_string(nullptr);

    CHECK(gm_graph_node_count(nullptr) == 0);
    CHECK(gm_graph_edge_count(nullptr) == 0);
    CHECK(gm_results_count(nullptr) == 0);
    CHECK(gm_matcher_new(nullptr) == nullptr);
}

} // TEST_SUITE cabi
