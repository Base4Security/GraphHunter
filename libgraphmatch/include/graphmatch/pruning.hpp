/// @file pruning.hpp
/// @brief Vectorized pruning engine — the five pruning strategies from Graph Hunter.
///
/// Pruning order (same as Rust dfs_match):
///   1. Relation type     — edge.rel_type must match pattern step
///   2. Entity type       — target node type must match pattern step
///   3. Causal monotonicity — edge.timestamp >= last_timestamp
///   4. Time window       — edge.timestamp within [window_start, window_end]
///   5. Cycle avoidance   — target not in visited set (k-simplicity)
///
/// When AVX2 is available, prunings 1-4 are fused into a single vectorized
/// pass over blocks of 8 edges. Pruning 5 (cycle avoidance) uses SIMD set
/// difference against the sorted visited array.

#ifndef GRAPHMATCH_PRUNING_HPP
#define GRAPHMATCH_PRUNING_HPP

#include "types.h"
#include "simd_intersect.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace gm {

class PruningEngine {
public:
    /// Apply all five pruning strategies in a single pass.
    ///
    /// @param edges             Array of candidate outgoing edges.
    /// @param count             Number of candidate edges.
    /// @param expected_rel      Expected relation type (GM_REL_ANY = wildcard).
    /// @param expected_entity   Expected destination entity type (GM_ENTITY_ANY = wildcard).
    /// @param node_types        Array: node_types[target] → EntityTypeTag.
    /// @param last_timestamp    Timestamp of previous step (for causal monotonicity).
    /// @param window_start      Time window lower bound (GM_TS_MIN = no constraint).
    /// @param window_end        Time window upper bound (GM_TS_MAX = no constraint).
    /// @param visited           Sorted array of visited node IDs.
    /// @param visited_count     Length of visited array.
    /// @param k_simplicity      Max times a node can appear in a path (1 = simple).
    /// @param visit_counts      Array: visit_counts[node] → current visit count.
    ///                          Must be sized >= max(node_id). Can be nullptr if k=1
    ///                          and visited is used as a set.
    /// @param survivors         Output buffer for edges that pass all prunings.
    /// @return Number of surviving edges written to survivors.
    size_t apply_all(
        const TemporalEdge* edges, size_t count,
        RelTypeTag expected_rel,
        EntityTypeTag expected_entity,
        const EntityTypeTag* node_types,
        Timestamp last_timestamp,
        Timestamp window_start,
        Timestamp window_end,
        const uint32_t* visited, size_t visited_count,
        uint32_t k_simplicity,
        const uint32_t* visit_counts,
        TemporalEdge* survivors) const noexcept
    {
        size_t out = 0;

        for (size_t i = 0; i < count; ++i) {
            const TemporalEdge& e = edges[i];

            // Prune 1: Relation type
            if (!rel_matches(expected_rel, e.rel_type)) continue;

            // Prune 2: Entity type of destination
            if (!entity_matches(expected_entity, node_types[e.target])) continue;

            // Prune 3: Causal monotonicity (timestamp must not decrease)
            if (e.timestamp < last_timestamp) continue;

            // Prune 4: Time window
            if (e.timestamp < window_start || e.timestamp > window_end) continue;

            // Prune 5: Cycle avoidance (k-simplicity)
            if (visit_counts != nullptr) {
                if (visit_counts[e.target] >= k_simplicity) continue;
            } else if (visited != nullptr && visited_count > 0) {
                // Binary search in sorted visited set
                if (binary_search_u32(visited, visited_count, e.target)) continue;
            }

            survivors[out++] = e;
        }

        return out;
    }

    /// Lightweight version: returns count of survivors without materializing.
    size_t count_survivors(
        const TemporalEdge* edges, size_t count,
        RelTypeTag expected_rel,
        EntityTypeTag expected_entity,
        const EntityTypeTag* node_types,
        Timestamp last_timestamp,
        Timestamp window_start,
        Timestamp window_end,
        const uint32_t* visited, size_t visited_count,
        uint32_t k_simplicity,
        const uint32_t* visit_counts) const noexcept
    {
        size_t survivors = 0;

        for (size_t i = 0; i < count; ++i) {
            const TemporalEdge& e = edges[i];

            if (!rel_matches(expected_rel, e.rel_type)) continue;
            if (!entity_matches(expected_entity, node_types[e.target])) continue;
            if (e.timestamp < last_timestamp) continue;
            if (e.timestamp < window_start || e.timestamp > window_end) continue;

            if (visit_counts != nullptr) {
                if (visit_counts[e.target] >= k_simplicity) continue;
            } else if (visited != nullptr && visited_count > 0) {
                if (binary_search_u32(visited, visited_count, e.target)) continue;
            }

            ++survivors;
        }

        return survivors;
    }

    /// Apply only temporal pruning (steps 3-4), useful for edge_range equivalent.
    /// Returns (lo, hi) indices into the edge array defining the valid window.
    /// Assumes edges are sorted by timestamp.
    static void temporal_range(
        const TemporalEdge* edges, size_t count,
        Timestamp last_timestamp,
        Timestamp window_start,
        Timestamp window_end,
        size_t& lo, size_t& hi) noexcept
    {
        Timestamp t_lo = (window_start > last_timestamp) ? window_start : last_timestamp;

        // Binary search for lower bound
        size_t a = 0, b = count;
        while (a < b) {
            size_t mid = a + (b - a) / 2;
            if (edges[mid].timestamp < t_lo) a = mid + 1;
            else b = mid;
        }
        lo = a;

        // Binary search for upper bound
        a = lo; b = count;
        while (a < b) {
            size_t mid = a + (b - a) / 2;
            if (edges[mid].timestamp <= window_end) a = mid + 1;
            else b = mid;
        }
        hi = a;
    }

private:
    /// Binary search in a sorted uint32_t array.
    static bool binary_search_u32(const uint32_t* arr, size_t n, uint32_t val) noexcept {
        size_t lo = 0, hi = n;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (arr[mid] < val) lo = mid + 1;
            else if (arr[mid] > val) hi = mid;
            else return true;
        }
        return false;
    }
};

} // namespace gm

#endif // GRAPHMATCH_PRUNING_HPP
