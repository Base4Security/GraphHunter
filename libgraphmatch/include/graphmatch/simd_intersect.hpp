/// @file simd_intersect.hpp
/// @brief SIMD-accelerated sorted set intersection for uint32_t arrays.
///
/// Provides runtime-dispatched implementations (scalar, AVX2, AVX-512)
/// for the hot path of graph pattern matching: intersecting adjacency
/// lists during DFS candidate filtering.
///
/// Reference: Han, Zou, Yu. "Speeding Up Set Intersections in Graph
/// Algorithms using SIMD Instructions." SIGMOD 2018.

#ifndef GRAPHMATCH_SIMD_INTERSECT_HPP
#define GRAPHMATCH_SIMD_INTERSECT_HPP

#include "types.h"
#include <cstddef>
#include <cstdint>

namespace gm::simd {

// ---------------------------------------------------------------------------
// Runtime ISA detection
// ---------------------------------------------------------------------------

/// Detect the best SIMD ISA available on the current CPU.
SimdIsa detect_best_isa() noexcept;

/// Return the ISA that will be used by dispatched functions.
SimdIsa active_isa() noexcept;

// ---------------------------------------------------------------------------
// Core intersection routines
// ---------------------------------------------------------------------------

/// Intersect two sorted uint32_t arrays, writing results to `out`.
/// @param a        First sorted array.
/// @param len_a    Length of a.
/// @param b        Second sorted array.
/// @param len_b    Length of b.
/// @param out      Output buffer (capacity >= min(len_a, len_b)).
/// @return         Number of elements written to out.
///
/// Arrays need NOT be aligned — the implementation handles unaligned loads
/// with a small perf penalty. For best throughput, align to 32 bytes.
size_t intersect_sorted(
    const uint32_t* a, size_t len_a,
    const uint32_t* b, size_t len_b,
    uint32_t* out) noexcept;

/// Count-only variant — does not materialize results.
size_t intersect_count(
    const uint32_t* a, size_t len_a,
    const uint32_t* b, size_t len_b) noexcept;

// ---------------------------------------------------------------------------
// Explicit ISA implementations (for testing / benchmarking)
// ---------------------------------------------------------------------------

namespace scalar {
size_t intersect(const uint32_t* a, size_t len_a,
                 const uint32_t* b, size_t len_b,
                 uint32_t* out) noexcept;
size_t intersect_count(const uint32_t* a, size_t len_a,
                       const uint32_t* b, size_t len_b) noexcept;
} // namespace scalar

#if defined(__x86_64__) || defined(_M_X64)
namespace avx2 {
size_t intersect(const uint32_t* a, size_t len_a,
                 const uint32_t* b, size_t len_b,
                 uint32_t* out) noexcept;
size_t intersect_count(const uint32_t* a, size_t len_a,
                       const uint32_t* b, size_t len_b) noexcept;
} // namespace avx2
#endif

// ---------------------------------------------------------------------------
// Temporal filtering: intersect edge targets within a time window.
// ---------------------------------------------------------------------------

/// Given a list of temporal edges (sorted by timestamp) and a sorted array
/// of candidate node IDs, find edges whose target is in candidates AND
/// whose timestamp falls within [t_min, t_max].
///
/// @param edges           Temporal edge array (sorted by timestamp).
/// @param num_edges       Number of edges.
/// @param candidates      Sorted array of candidate NodeIds.
/// @param num_candidates  Length of candidates.
/// @param t_min           Minimum timestamp (inclusive).
/// @param t_max           Maximum timestamp (inclusive).
/// @param out             Output buffer for matching target NodeIds.
/// @return                Number of elements written.
size_t intersect_temporal(
    const TemporalEdge* edges, size_t num_edges,
    const uint32_t* candidates, size_t num_candidates,
    Timestamp t_min, Timestamp t_max,
    uint32_t* out) noexcept;

// ---------------------------------------------------------------------------
// Initialization (called automatically on first use)
// ---------------------------------------------------------------------------

/// Force re-detection and dispatch table update. Normally not needed.
void init() noexcept;

} // namespace gm::simd

#endif // GRAPHMATCH_SIMD_INTERSECT_HPP
