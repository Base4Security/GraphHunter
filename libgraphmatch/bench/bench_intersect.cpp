/// @file bench_intersect.cpp
/// @brief Benchmark: SIMD vs scalar sorted set intersection throughput.
///
/// Reports elements/second for various list sizes and ISA backends.
/// Compile: g++ -O3 -mavx2 -std=c++20 -I../include -o bench_intersect bench_intersect.cpp ../src/simd_intersect.cpp

#include "graphmatch/simd_intersect.hpp"
#include "graphmatch/types.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <numeric>
#include <random>
#include <vector>

// ---------------------------------------------------------------------------
// Simple benchmark harness (no external deps)
// ---------------------------------------------------------------------------

struct BenchResult {
    double elapsed_ns;
    size_t iterations;
    size_t elements_processed;
};

template<typename Fn>
BenchResult run_bench(const char* name, size_t total_elements, Fn&& fn) {
    // Warmup
    for (int i = 0; i < 3; ++i) fn();

    // Measure: run for at least 200ms or 10 iterations
    using Clock = std::chrono::high_resolution_clock;
    auto t0 = Clock::now();
    size_t iters = 0;
    while (true) {
        fn();
        ++iters;
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now() - t0).count();
        if (elapsed >= 200 && iters >= 10) break;
        if (iters >= 100000) break; // Safety cap
    }
    auto t1 = Clock::now();
    double ns = static_cast<double>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count());

    return {ns, iters, total_elements * iters};
}

static void print_result(const char* label, const BenchResult& r) {
    double ns_per_iter = r.elapsed_ns / static_cast<double>(r.iterations);
    double throughput = static_cast<double>(r.elements_processed) / (r.elapsed_ns / 1e9);
    std::printf("  %-20s  %8.1f ns/iter  %10.1f Melems/s  (%zu iters)\n",
                label, ns_per_iter, throughput / 1e6, r.iterations);
}

// ---------------------------------------------------------------------------
// Data generation
// ---------------------------------------------------------------------------

static std::vector<uint32_t> make_sorted_set(size_t n, uint32_t max_val, uint32_t seed) {
    std::mt19937 rng(seed);
    std::uniform_int_distribution<uint32_t> dist(0, max_val);
    std::vector<uint32_t> v;
    v.reserve(n * 2);
    while (v.size() < n) v.push_back(dist(rng));
    std::sort(v.begin(), v.end());
    v.erase(std::unique(v.begin(), v.end()), v.end());
    return v;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main() {
    gm::simd::init();

    const char* isa_names[] = {"scalar", "sse42", "avx2", "avx512", "neon"};
    std::printf("=== SIMD Intersection Benchmark ===\n");
    std::printf("Active ISA: %s\n\n", isa_names[gm::simd::active_isa()]);

    // Test sizes
    size_t sizes[] = {16, 64, 256, 1024, 4096, 16384};

    for (size_t sz : sizes) {
        auto a = make_sorted_set(sz, sz * 10, 42);
        auto b = make_sorted_set(sz, sz * 10, 99);
        size_t total = a.size() + b.size();

        std::vector<uint32_t> out(std::min(a.size(), b.size()));

        std::printf("--- Size: %zu (a=%zu, b=%zu) ---\n", sz, a.size(), b.size());

        // Scalar
        auto r_scalar = run_bench("scalar", total, [&]() {
            gm::simd::scalar::intersect(a.data(), a.size(), b.data(), b.size(), out.data());
        });
        print_result("scalar", r_scalar);

        // Scalar count-only
        auto r_scalar_cnt = run_bench("scalar_count", total, [&]() {
            gm::simd::scalar::intersect_count(a.data(), a.size(), b.data(), b.size());
        });
        print_result("scalar_count", r_scalar_cnt);

#if defined(__x86_64__) || defined(_M_X64)
        // AVX2
        auto r_avx2 = run_bench("avx2", total, [&]() {
            gm::simd::avx2::intersect(a.data(), a.size(), b.data(), b.size(), out.data());
        });
        print_result("avx2", r_avx2);

        auto r_avx2_cnt = run_bench("avx2_count", total, [&]() {
            gm::simd::avx2::intersect_count(a.data(), a.size(), b.data(), b.size());
        });
        print_result("avx2_count", r_avx2_cnt);

        // Speedup
        double speedup = (r_scalar.elapsed_ns / r_scalar.iterations) /
                         (r_avx2.elapsed_ns / r_avx2.iterations);
        std::printf("  >> AVX2 speedup: %.2fx\n", speedup);
#endif

        // Dispatched
        auto r_disp = run_bench("dispatched", total, [&]() {
            gm::simd::intersect_sorted(a.data(), a.size(), b.data(), b.size(), out.data());
        });
        print_result("dispatched", r_disp);

        std::printf("\n");
    }

    // Verify correctness
    {
        auto a = make_sorted_set(1000, 5000, 42);
        auto b = make_sorted_set(800, 5000, 99);
        std::vector<uint32_t> ref_out(std::min(a.size(), b.size()));
        std::vector<uint32_t> test_out(std::min(a.size(), b.size()));

        size_t nr = gm::simd::scalar::intersect(
            a.data(), a.size(), b.data(), b.size(), ref_out.data());
        size_t nt = gm::simd::intersect_sorted(
            a.data(), a.size(), b.data(), b.size(), test_out.data());

        if (nr != nt) {
            std::printf("CORRECTNESS FAILURE: scalar=%zu dispatched=%zu\n", nr, nt);
            return 1;
        }
        for (size_t i = 0; i < nr; ++i) {
            if (ref_out[i] != test_out[i]) {
                std::printf("MISMATCH at %zu: scalar=%u dispatched=%u\n",
                            i, ref_out[i], test_out[i]);
                return 1;
            }
        }
        std::printf("Correctness check: PASSED (%zu matches verified)\n", nr);
    }

    return 0;
}
