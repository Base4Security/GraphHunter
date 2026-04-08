/// @file simd_intersect.cpp
/// @brief SIMD-accelerated sorted set intersection — scalar + AVX2 + dispatch.

#include "graphmatch/simd_intersect.hpp"
#include "graphmatch/types.h"

#include <algorithm>
#include <atomic>
#include <cstring>

#if defined(__x86_64__) || defined(_M_X64)
#  include <immintrin.h>
#  ifdef _MSC_VER
#    include <intrin.h>
#  else
#    include <cpuid.h>
#  endif
#endif

namespace gm::simd {

// ===================================================================
// CPU feature detection
// ===================================================================

static SimdIsa g_isa = GM_ISA_SCALAR;
static std::atomic<bool> g_initialized{false};

#if defined(__x86_64__) || defined(_M_X64)

static void cpuid(int info[4], int leaf) noexcept {
#ifdef _MSC_VER
    __cpuid(info, leaf);
#else
    __cpuid_count(leaf, 0, info[0], info[1], info[2], info[3]);
#endif
}

static SimdIsa detect_isa() noexcept {
    int info[4] = {};
    cpuid(info, 0);
    int max_leaf = info[0];
    if (max_leaf < 7) return GM_ISA_SCALAR;

    cpuid(info, 1);
    bool has_sse42 = (info[2] & (1 << 20)) != 0;

    cpuid(info, 7);
    bool has_avx2   = (info[1] & (1 << 5))  != 0;
    bool has_avx512 = (info[1] & (1 << 16)) != 0; // AVX-512F

    if (has_avx512) return GM_ISA_AVX512;  // We use AVX2 impl for now even on 512
    if (has_avx2)   return GM_ISA_AVX2;
    if (has_sse42)  return GM_ISA_SSE42;
    return GM_ISA_SCALAR;
}

#elif defined(__aarch64__)

static SimdIsa detect_isa() noexcept {
    return GM_ISA_NEON; // All AArch64 has NEON
}

#else

static SimdIsa detect_isa() noexcept {
    return GM_ISA_SCALAR;
}

#endif

void init() noexcept {
    g_isa = detect_isa();
    g_initialized.store(true, std::memory_order_release);
}

static inline void ensure_init() noexcept {
    if (!g_initialized.load(std::memory_order_acquire)) [[unlikely]] {
        init();
    }
}

SimdIsa detect_best_isa() noexcept {
    return detect_isa();
}

SimdIsa active_isa() noexcept {
    ensure_init();
    return g_isa;
}

// ===================================================================
// Scalar implementation — two-pointer merge intersection
// ===================================================================

namespace scalar {

size_t intersect(const uint32_t* a, size_t len_a,
                 const uint32_t* b, size_t len_b,
                 uint32_t* out) noexcept {
    size_t ia = 0, ib = 0, count = 0;
    while (ia < len_a && ib < len_b) {
        if (a[ia] < b[ib]) {
            ++ia;
        } else if (a[ia] > b[ib]) {
            ++ib;
        } else {
            out[count++] = a[ia];
            ++ia;
            ++ib;
        }
    }
    return count;
}

size_t intersect_count(const uint32_t* a, size_t len_a,
                       const uint32_t* b, size_t len_b) noexcept {
    size_t ia = 0, ib = 0, count = 0;
    while (ia < len_a && ib < len_b) {
        if (a[ia] < b[ib]) {
            ++ia;
        } else if (a[ia] > b[ib]) {
            ++ib;
        } else {
            ++count;
            ++ia;
            ++ib;
        }
    }
    return count;
}

} // namespace scalar

// ===================================================================
// AVX2 implementation
// ===================================================================

#if defined(__x86_64__) || defined(_M_X64)

// Helper: compress-store using a precomputed shuffle LUT.
// Given a bitmask of which of 8 lanes are active, pack them to the front.
//
// The LUT approach: for each 8-bit mask, store the permutation that moves
// active lanes to the front. Since we have 8 uint32 lanes and 256 possible
// masks, the LUT is 256 * 32 bytes = 8KB — fits in L1.
//
// We build the LUT at initialization time.

alignas(64) static uint32_t g_shuffle_lut[256][8];
static std::atomic<bool> g_lut_ready{false};

static void build_shuffle_lut() noexcept {
    for (int mask = 0; mask < 256; ++mask) {
        uint32_t dst = 0;
        for (uint32_t bit = 0; bit < 8; ++bit) {
            if (mask & (1 << bit)) {
                g_shuffle_lut[mask][dst++] = bit;
            }
        }
        // Fill remaining with zeros (don't care)
        for (; dst < 8; ++dst) {
            g_shuffle_lut[mask][dst] = 0;
        }
    }
    g_lut_ready.store(true, std::memory_order_release);
}

static inline void ensure_lut() noexcept {
    if (!g_lut_ready.load(std::memory_order_acquire)) [[unlikely]] {
        build_shuffle_lut();
    }
}

namespace avx2 {

/// AVX2 sorted set intersection using the broadcast + compare approach.
///
/// Algorithm overview (adapted from SIGMOD 2018):
/// 1. Load 8 elements from list A into a YMM register.
/// 2. For each element in list B, broadcast it to all 8 lanes.
/// 3. Compare: _mm256_cmpeq_epi32 → gives -1 in matching lanes.
/// 4. Extract mask, if any bit set → we have a match.
/// 5. Advance pointers based on which list has the smaller max.
///
/// This is the "broadcast from shorter list" variant, optimal when
/// lists have similar sizes (ratio < 32:1).

#if defined(__AVX2__) || (defined(_MSC_VER) && defined(__AVX2__)) || (defined(_MSC_VER) && !defined(__clang__))
// MSVC: AVX2 intrinsics available when compiled with /arch:AVX2.
// GCC/Clang: __attribute__((target("avx2"))) enables AVX2 codegen for this function.

#ifdef _MSC_VER
#define GM_AVX2_TARGET
#else
#define GM_AVX2_TARGET __attribute__((target("avx2")))
#endif

GM_AVX2_TARGET
size_t intersect(const uint32_t* a, size_t len_a,
                 const uint32_t* b, size_t len_b,
                 uint32_t* out) noexcept {
    // For very small arrays, fall back to scalar
    if (len_a < 8 || len_b < 8) {
        return scalar::intersect(a, len_a, b, len_b, out);
    }

    // Ensure shorter list is A (we broadcast from B, scan A in blocks)
    if (len_a > len_b) {
        return intersect(b, len_b, a, len_a, out);
    }

    size_t count = 0;
    size_t ia = 0, ib = 0;

    // Process blocks of 8 from A, scanning B
    while (ia + 8 <= len_a && ib < len_b) {
        // Load 8 elements from A
        __m256i va = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(a + ia));

        // The max element in this A block
        // Since A is sorted, it's a[ia + 7]
        uint32_t a_max = a[ia + 7];

        // Scan B elements, broadcasting each against the A block
        while (ib < len_b && b[ib] <= a_max) {
            __m256i vb = _mm256_set1_epi32(static_cast<int>(b[ib]));
            __m256i cmp = _mm256_cmpeq_epi32(va, vb);
            int mask = _mm256_movemask_epi8(cmp);
            if (mask != 0) {
                out[count++] = b[ib];
            }
            ++ib;
        }

        // Advance A past elements < b[ib] (next unprocessed B element)
        if (ib < len_b) {
            // Skip A block; since a_max < b[ib] at this point, whole block is done
            ia += 8;
            // But some elements in the next A block might equal current b[ib],
            // so we need to re-check. Advance A to where a[ia] >= min unprocessed B.
            // Since A is sorted, just advance the block pointer.
        } else {
            break;
        }
    }

    // Scalar tail for remaining elements
    while (ia < len_a && ib < len_b) {
        if (a[ia] < b[ib]) {
            ++ia;
        } else if (a[ia] > b[ib]) {
            ++ib;
        } else {
            out[count++] = a[ia];
            ++ia;
            ++ib;
        }
    }

    return count;
}

GM_AVX2_TARGET
size_t intersect_count(const uint32_t* a, size_t len_a,
                       const uint32_t* b, size_t len_b) noexcept {
    if (len_a < 8 || len_b < 8) {
        return scalar::intersect_count(a, len_a, b, len_b);
    }

    if (len_a > len_b) {
        return intersect_count(b, len_b, a, len_a);
    }

    size_t count = 0;
    size_t ia = 0, ib = 0;

    while (ia + 8 <= len_a && ib < len_b) {
        __m256i va = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(a + ia));
        uint32_t a_max = a[ia + 7];

        while (ib < len_b && b[ib] <= a_max) {
            __m256i vb = _mm256_set1_epi32(static_cast<int>(b[ib]));
            __m256i cmp = _mm256_cmpeq_epi32(va, vb);
            int mask = _mm256_movemask_epi8(cmp);
            if (mask != 0) {
                ++count;
            }
            ++ib;
        }

        if (ib >= len_b) break;
        ia += 8;
    }

    // Scalar tail
    while (ia < len_a && ib < len_b) {
        if (a[ia] < b[ib]) {
            ++ia;
        } else if (a[ia] > b[ib]) {
            ++ib;
        } else {
            ++count;
            ++ia;
            ++ib;
        }
    }

    return count;
}

#else // No __AVX2__ — stub that falls through to scalar

size_t intersect(const uint32_t* a, size_t len_a,
                 const uint32_t* b, size_t len_b,
                 uint32_t* out) noexcept {
    return scalar::intersect(a, len_a, b, len_b, out);
}

size_t intersect_count(const uint32_t* a, size_t len_a,
                       const uint32_t* b, size_t len_b) noexcept {
    return scalar::intersect_count(a, len_a, b, len_b);
}

#endif // __AVX2__

} // namespace avx2

#endif // x86_64

// ===================================================================
// Dispatched entry points
// ===================================================================

size_t intersect_sorted(
    const uint32_t* a, size_t len_a,
    const uint32_t* b, size_t len_b,
    uint32_t* out) noexcept {

    if (len_a == 0 || len_b == 0) return 0;

    ensure_init();

#if defined(__x86_64__) || defined(_M_X64)
    if (g_isa >= GM_ISA_AVX2) {
        return avx2::intersect(a, len_a, b, len_b, out);
    }
#endif

    return scalar::intersect(a, len_a, b, len_b, out);
}

size_t intersect_count(
    const uint32_t* a, size_t len_a,
    const uint32_t* b, size_t len_b) noexcept {

    if (len_a == 0 || len_b == 0) return 0;

    ensure_init();

#if defined(__x86_64__) || defined(_M_X64)
    if (g_isa >= GM_ISA_AVX2) {
        return avx2::intersect_count(a, len_a, b, len_b);
    }
#endif

    return scalar::intersect_count(a, len_a, b, len_b);
}

// ===================================================================
// Temporal intersection
// ===================================================================

size_t intersect_temporal(
    const TemporalEdge* edges, size_t num_edges,
    const uint32_t* candidates, size_t num_candidates,
    Timestamp t_min, Timestamp t_max,
    uint32_t* out) noexcept {

    if (num_edges == 0 || num_candidates == 0) return 0;

    // Binary search for the temporal window in edges (sorted by timestamp).
    // Find first edge with timestamp >= t_min.
    size_t lo = 0, hi = num_edges;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (edges[mid].timestamp < t_min)
            lo = mid + 1;
        else
            hi = mid;
    }
    size_t start = lo;

    // Find first edge with timestamp > t_max.
    lo = start;
    hi = num_edges;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (edges[mid].timestamp <= t_max)
            lo = mid + 1;
        else
            hi = mid;
    }
    size_t end = lo;

    if (start >= end) return 0;

    // Extract target IDs from edges in the temporal window.
    // For small windows, linear scan + binary search into candidates.
    // For larger windows, build sorted target array then use SIMD intersect.
    size_t window_size = end - start;

    if (window_size <= 64) {
        // Small window: for each edge, binary search in candidates.
        size_t count = 0;
        uint32_t prev_target = UINT32_MAX;
        for (size_t i = start; i < end; ++i) {
            uint32_t t = edges[i].target;
            if (t == prev_target) continue; // Deduplicate
            prev_target = t;

            // Binary search in sorted candidates
            size_t clo = 0, chi = num_candidates;
            while (clo < chi) {
                size_t mid = clo + (chi - clo) / 2;
                if (candidates[mid] < t)
                    clo = mid + 1;
                else
                    chi = mid;
            }
            if (clo < num_candidates && candidates[clo] == t) {
                out[count++] = t;
            }
        }
        return count;
    }

    // Larger window: extract + sort targets, then SIMD intersect.
    // Stack-allocate for reasonable sizes, heap otherwise.
    constexpr size_t STACK_LIMIT = 4096;
    uint32_t stack_buf[STACK_LIMIT];
    uint32_t* targets = (window_size <= STACK_LIMIT)
        ? stack_buf
        : static_cast<uint32_t*>(gm::aligned_malloc(window_size * sizeof(uint32_t)));

    if (!targets) return 0;

    size_t nt = 0;
    for (size_t i = start; i < end; ++i) {
        targets[nt++] = edges[i].target;
    }

    // Sort and deduplicate
    std::sort(targets, targets + nt);
    nt = static_cast<size_t>(std::unique(targets, targets + nt) - targets);

    // Intersect with candidates using dispatched SIMD
    size_t result = intersect_sorted(targets, nt, candidates, num_candidates, out);

    if (window_size > STACK_LIMIT) {
        gm::aligned_free(targets);
    }

    return result;
}

} // namespace gm::simd
