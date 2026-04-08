/// @file test_simd_intersect.cpp
/// @brief Unit tests for SIMD sorted set intersection.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "graphmatch/simd_intersect.hpp"
#include "graphmatch/types.h"

#include <algorithm>
#include <cstdint>
#include <numeric>
#include <random>
#include <vector>

using namespace gm::simd;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a sorted unique vector of random uint32 values.
static std::vector<uint32_t> random_sorted_set(size_t n, uint32_t max_val, uint32_t seed) {
    std::mt19937 rng(seed);
    std::uniform_int_distribution<uint32_t> dist(0, max_val);

    std::vector<uint32_t> v;
    v.reserve(n * 2);
    while (v.size() < n) {
        v.push_back(dist(rng));
    }
    std::sort(v.begin(), v.end());
    v.erase(std::unique(v.begin(), v.end()), v.end());
    // May have fewer than n elements after dedup — that's fine
    return v;
}

/// Reference (brute-force) intersection for validation.
static std::vector<uint32_t> reference_intersect(
    const std::vector<uint32_t>& a, const std::vector<uint32_t>& b) {
    std::vector<uint32_t> result;
    std::set_intersection(a.begin(), a.end(), b.begin(), b.end(),
                          std::back_inserter(result));
    return result;
}

// ---------------------------------------------------------------------------
// ISA detection
// ---------------------------------------------------------------------------

TEST_CASE("detect_best_isa returns valid ISA") {
    SimdIsa isa = detect_best_isa();
    CHECK(isa <= GM_ISA_NEON);
    MESSAGE("Detected ISA: ", static_cast<int>(isa));
}

TEST_CASE("active_isa returns same after init") {
    init();
    SimdIsa a1 = active_isa();
    SimdIsa a2 = active_isa();
    CHECK(a1 == a2);
}

// ---------------------------------------------------------------------------
// Scalar intersection
// ---------------------------------------------------------------------------

TEST_SUITE("scalar") {

TEST_CASE("empty arrays") {
    uint32_t out[1];
    CHECK(scalar::intersect(nullptr, 0, nullptr, 0, out) == 0);
    uint32_t a[] = {1, 2, 3};
    CHECK(scalar::intersect(a, 3, nullptr, 0, out) == 0);
    CHECK(scalar::intersect(nullptr, 0, a, 3, out) == 0);
}

TEST_CASE("identical arrays") {
    uint32_t a[] = {1, 2, 3, 4, 5};
    uint32_t out[5];
    size_t n = scalar::intersect(a, 5, a, 5, out);
    CHECK(n == 5);
    for (size_t i = 0; i < 5; ++i) CHECK(out[i] == a[i]);
}

TEST_CASE("disjoint arrays") {
    uint32_t a[] = {1, 3, 5, 7};
    uint32_t b[] = {2, 4, 6, 8};
    uint32_t out[4];
    CHECK(scalar::intersect(a, 4, b, 4, out) == 0);
}

TEST_CASE("partial overlap") {
    uint32_t a[] = {1, 2, 3, 4, 5};
    uint32_t b[] = {3, 4, 5, 6, 7};
    uint32_t out[5];
    size_t n = scalar::intersect(a, 5, b, 5, out);
    CHECK(n == 3);
    CHECK(out[0] == 3);
    CHECK(out[1] == 4);
    CHECK(out[2] == 5);
}

TEST_CASE("single element match") {
    uint32_t a[] = {42};
    uint32_t b[] = {42};
    uint32_t out[1];
    CHECK(scalar::intersect(a, 1, b, 1, out) == 1);
    CHECK(out[0] == 42);
}

TEST_CASE("single element no match") {
    uint32_t a[] = {42};
    uint32_t b[] = {43};
    uint32_t out[1];
    CHECK(scalar::intersect(a, 1, b, 1, out) == 0);
}

TEST_CASE("asymmetric sizes") {
    uint32_t a[] = {5, 10, 15, 20, 25, 30, 35, 40, 45, 50};
    uint32_t b[] = {10, 30, 50};
    uint32_t out[10];
    size_t n = scalar::intersect(a, 10, b, 3, out);
    CHECK(n == 3);
    CHECK(out[0] == 10);
    CHECK(out[1] == 30);
    CHECK(out[2] == 50);
}

TEST_CASE("count-only matches intersect") {
    uint32_t a[] = {1, 2, 3, 4, 5};
    uint32_t b[] = {3, 4, 5, 6, 7};
    uint32_t out[5];
    size_t n = scalar::intersect(a, 5, b, 5, out);
    size_t c = scalar::intersect_count(a, 5, b, 5);
    CHECK(n == c);
}

TEST_CASE("random correctness" * doctest::test_suite("random")) {
    for (uint32_t seed = 0; seed < 50; ++seed) {
        auto a = random_sorted_set(100 + seed * 7, 500, seed);
        auto b = random_sorted_set(80 + seed * 5, 500, seed + 1000);
        auto expected = reference_intersect(a, b);

        std::vector<uint32_t> out(std::min(a.size(), b.size()));
        size_t n = scalar::intersect(a.data(), a.size(), b.data(), b.size(), out.data());
        CHECK(n == expected.size());
        for (size_t i = 0; i < n; ++i) {
            CHECK(out[i] == expected[i]);
        }
    }
}

} // TEST_SUITE scalar

// ---------------------------------------------------------------------------
// Dispatched intersection (uses best available ISA)
// ---------------------------------------------------------------------------

TEST_SUITE("dispatched") {

TEST_CASE("empty") {
    uint32_t out[1];
    CHECK(intersect_sorted(nullptr, 0, nullptr, 0, out) == 0);
}

TEST_CASE("basic correctness") {
    uint32_t a[] = {1, 3, 5, 7, 9, 11, 13, 15, 17, 19};
    uint32_t b[] = {2, 3, 5, 8, 11, 14, 17, 20};
    uint32_t out[10];
    size_t n = intersect_sorted(a, 10, b, 8, out);
    CHECK(n == 4);
    CHECK(out[0] == 3);
    CHECK(out[1] == 5);
    CHECK(out[2] == 11);
    CHECK(out[3] == 17);
}

TEST_CASE("count matches materialize") {
    uint32_t a[] = {1, 3, 5, 7, 9, 11, 13, 15, 17, 19};
    uint32_t b[] = {2, 3, 5, 8, 11, 14, 17, 20};
    uint32_t out[10];
    size_t n = intersect_sorted(a, 10, b, 8, out);
    size_t c = intersect_count(a, 10, b, 8);
    CHECK(n == c);
}

TEST_CASE("random stress test" * doctest::test_suite("random")) {
    for (uint32_t seed = 0; seed < 100; ++seed) {
        auto a = random_sorted_set(200 + seed * 3, 2000, seed);
        auto b = random_sorted_set(150 + seed * 4, 2000, seed + 5000);
        auto expected = reference_intersect(a, b);

        std::vector<uint32_t> out(std::min(a.size(), b.size()));
        size_t n = intersect_sorted(a.data(), a.size(), b.data(), b.size(), out.data());

        CAPTURE(seed);
        REQUIRE(n == expected.size());
        for (size_t i = 0; i < n; ++i) {
            CAPTURE(i);
            CHECK(out[i] == expected[i]);
        }

        // Count must match
        CHECK(intersect_count(a.data(), a.size(), b.data(), b.size()) == expected.size());
    }
}

TEST_CASE("large arrays" * doctest::test_suite("random")) {
    auto a = random_sorted_set(10000, 50000, 42);
    auto b = random_sorted_set(8000, 50000, 99);
    auto expected = reference_intersect(a, b);

    std::vector<uint32_t> out(std::min(a.size(), b.size()));
    size_t n = intersect_sorted(a.data(), a.size(), b.data(), b.size(), out.data());

    CHECK(n == expected.size());
    for (size_t i = 0; i < n; ++i) {
        CHECK(out[i] == expected[i]);
    }
}

TEST_CASE("asymmetric ratio > 32:1") {
    // Small list vs large list — tests galloping-like behavior
    uint32_t small[] = {100, 500, 1000};
    auto large = random_sorted_set(4096, 2000, 777);

    auto expected = reference_intersect(
        std::vector<uint32_t>(small, small + 3), large);

    std::vector<uint32_t> out(3);
    size_t n = intersect_sorted(small, 3, large.data(), large.size(), out.data());
    CHECK(n == expected.size());
}

} // TEST_SUITE dispatched

// ---------------------------------------------------------------------------
// Temporal intersection
// ---------------------------------------------------------------------------

TEST_SUITE("temporal") {

TEST_CASE("empty inputs") {
    uint32_t cands[] = {1, 2, 3};
    uint32_t out[3];
    CHECK(intersect_temporal(nullptr, 0, cands, 3, 0, 100, out) == 0);

    TemporalEdge edges[1] = {{1, GM_REL_CONNECT, {}, 50}};
    CHECK(intersect_temporal(edges, 1, nullptr, 0, 0, 100, out) == 0);
}

TEST_CASE("basic temporal filtering") {
    // Edges with different timestamps and targets
    TemporalEdge edges[] = {
        {10, GM_REL_CONNECT, {}, 100},
        {20, GM_REL_CONNECT, {}, 200},
        {30, GM_REL_CONNECT, {}, 300},
        {40, GM_REL_CONNECT, {}, 400},
        {50, GM_REL_CONNECT, {}, 500},
    };
    uint32_t candidates[] = {10, 30, 50, 70};
    uint32_t out[4];

    // Full window: should match targets 10, 30, 50
    size_t n = intersect_temporal(edges, 5, candidates, 4, 0, 1000, out);
    CHECK(n == 3);

    // Window [200, 400]: edges at t=200(target=20), t=300(target=30), t=400(target=40)
    // Candidates: 10, 30, 50, 70 → only 30 matches
    n = intersect_temporal(edges, 5, candidates, 4, 200, 400, out);
    CHECK(n == 1);
    CHECK(out[0] == 30);
}

TEST_CASE("window excludes all edges") {
    TemporalEdge edges[] = {
        {1, GM_REL_AUTH, {}, 100},
        {2, GM_REL_AUTH, {}, 200},
    };
    uint32_t cands[] = {1, 2};
    uint32_t out[2];
    CHECK(intersect_temporal(edges, 2, cands, 2, 300, 400, out) == 0);
}

TEST_CASE("duplicate targets in window") {
    TemporalEdge edges[] = {
        {5, GM_REL_EXECUTE, {}, 100},
        {5, GM_REL_WRITE,   {}, 150},
        {5, GM_REL_READ,    {}, 200},
        {10, GM_REL_AUTH,   {}, 250},
    };
    uint32_t cands[] = {5, 10};
    uint32_t out[2];
    size_t n = intersect_temporal(edges, 4, cands, 2, 0, 300, out);
    // Target 5 appears 3 times but should be deduplicated
    CHECK(n == 2);
}

} // TEST_SUITE temporal

// ---------------------------------------------------------------------------
// AVX2 explicit tests (only on x86_64)
// ---------------------------------------------------------------------------

#if defined(__x86_64__) || defined(_M_X64)

TEST_SUITE("avx2_explicit") {

TEST_CASE("matches scalar on random data" * doctest::test_suite("random")) {
    for (uint32_t seed = 0; seed < 50; ++seed) {
        auto a = random_sorted_set(256 + seed * 10, 5000, seed);
        auto b = random_sorted_set(200 + seed * 8, 5000, seed + 3000);

        std::vector<uint32_t> out_scalar(std::min(a.size(), b.size()));
        std::vector<uint32_t> out_avx2(std::min(a.size(), b.size()));

        size_t ns = scalar::intersect(a.data(), a.size(), b.data(), b.size(), out_scalar.data());
        size_t na = avx2::intersect(a.data(), a.size(), b.data(), b.size(), out_avx2.data());

        CAPTURE(seed);
        REQUIRE(na == ns);
        for (size_t i = 0; i < ns; ++i) {
            CAPTURE(i);
            CHECK(out_avx2[i] == out_scalar[i]);
        }

        CHECK(avx2::intersect_count(a.data(), a.size(), b.data(), b.size()) == ns);
    }
}

} // TEST_SUITE avx2_explicit

#endif // x86_64
