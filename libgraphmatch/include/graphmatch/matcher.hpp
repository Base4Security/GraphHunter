/// @file matcher.hpp
/// @brief Temporal graph pattern matcher with SIMD-accelerated pruning.
///
/// Implements iterative DFS with backtracking (matching Rust's dfs_match_iterative)
/// and integrates the PruningEngine for vectorized candidate filtering.
/// The matcher is the main entry point for executing hunt hypotheses.

#ifndef GRAPHMATCH_MATCHER_HPP
#define GRAPHMATCH_MATCHER_HPP

#include "csr_graph.hpp"
#include "pattern.hpp"
#include "pruning.hpp"
#include "types.h"

#include <algorithm>
#include <cstdint>
#include <vector>

namespace gm {

// ---------------------------------------------------------------------------
// Match result
// ---------------------------------------------------------------------------

/// A single successful pattern match: ordered node path + edge timestamps.
struct MatchResult {
    std::vector<NodeId>    path;        ///< Matched nodes in hypothesis order.
    std::vector<Timestamp> timestamps;  ///< Timestamp of each traversed edge.
    float anomaly_score;                ///< Composite anomaly score.
    float match_confidence;             ///< Completeness / confidence [0, 1].
};

// ---------------------------------------------------------------------------
// TemporalMatcher
// ---------------------------------------------------------------------------

class TemporalMatcher {
public:
    explicit TemporalMatcher(const CSRTemporalGraph& graph)
        : graph_(graph) {}

    /// Execute pattern matching, returning up to max_results matches.
    ///
    /// This is a direct port of Graph Hunter's dfs_match_iterative with
    /// SIMD-accelerated pruning in the inner loop.
    ///
    /// @param query        Compiled pattern query.
    /// @param max_results  Maximum number of matches to return (0 = unlimited).
    /// @param min_score    Minimum anomaly score threshold (0 = no filter).
    /// @param k_simplicity Max node revisits in a path (1 = simple paths).
    /// @return Vector of match results, sorted by anomaly score descending.
    std::vector<MatchResult> match(
        const PatternQuery& query,
        uint32_t max_results = 1000,
        float min_score = 0.0f,
        uint32_t k_simplicity = 1) const
    {
        if (query.steps.empty()) return {};

        std::vector<MatchResult> results;
        results.reserve(std::min(max_results, uint32_t(1024)));

        // Determine starting nodes based on start_entity_type
        size_t start_count = 0;
        const uint32_t* start_nodes = nullptr;
        std::vector<uint32_t> all_nodes; // fallback for wildcard

        if (query.start_entity_type == GM_ENTITY_ANY) {
            all_nodes.resize(graph_.node_count());
            for (uint32_t i = 0; i < graph_.node_count(); ++i) all_nodes[i] = i;
            start_nodes = all_nodes.data();
            start_count = all_nodes.size();
        } else {
            start_nodes = graph_.nodes_of_type(query.start_entity_type, start_count);
        }

        if (!start_nodes || start_count == 0) return results;

        // Run DFS from each starting node
        for (size_t si = 0; si < start_count; ++si) {
            if (max_results > 0 && results.size() >= max_results) break;

            dfs_match_iterative(
                start_nodes[si], query, k_simplicity,
                max_results, results);
        }

        // Sort by anomaly score descending
        std::sort(results.begin(), results.end(),
            [](const MatchResult& a, const MatchResult& b) {
                return a.anomaly_score > b.anomaly_score;
            });

        // Filter by min_score
        if (min_score > 0.0f) {
            auto it = std::remove_if(results.begin(), results.end(),
                [min_score](const MatchResult& r) {
                    return r.anomaly_score < min_score;
                });
            results.erase(it, results.end());
        }

        return results;
    }

private:
    /// Iterative stack-based DFS with backtracking.
    /// Direct port of Graph Hunter's dfs_match_iterative (graph.rs:636-747).
    void dfs_match_iterative(
        NodeId start,
        const PatternQuery& query,
        uint32_t k,
        uint32_t cap,
        std::vector<MatchResult>& results) const
    {
        struct Frame {
            NodeId   node;
            uint32_t step_idx;
            size_t   edge_lo;    // Valid edge window [lo, hi)
            size_t   edge_hi;
            size_t   edge_cursor; // Current position in window
        };

        const auto& steps = query.steps;
        uint32_t num_steps = static_cast<uint32_t>(steps.size());

        // Path and visit tracking
        std::vector<NodeId> path;
        path.reserve(num_steps + 1);
        path.push_back(start);

        // Visit count per node for k-simplicity
        std::vector<uint32_t> visit_count(graph_.node_count(), 0);
        visit_count[start] = 1;

        // Timestamps of edges along the path
        std::vector<Timestamp> edge_timestamps;
        edge_timestamps.reserve(num_steps);

        // Compute initial edge window
        size_t lo = 0, hi = 0;
        {
            size_t total = 0;
            const TemporalEdge* edges = graph_.outgoing(start, total);
            if (edges && total > 0) {
                Timestamp tw_start = (query.time_window_ms > 0) ? GM_TS_MIN : GM_TS_MIN;
                Timestamp tw_end   = (query.time_window_ms > 0) ? GM_TS_MAX : GM_TS_MAX;
                // For the first step, no causal constraint (last_ts = GM_TS_MIN)
                PruningEngine::temporal_range(edges, total, GM_TS_MIN, tw_start, tw_end, lo, hi);
            }
        }

        std::vector<Frame> stack;
        stack.push_back({start, 0, lo, hi, lo});

        PruningEngine pruner;

        while (!stack.empty()) {
            if (cap > 0 && results.size() >= cap) break;

            Frame& frame = stack.back();

            // Check if all steps are matched
            if (frame.step_idx >= num_steps) {
                // Complete match found
                MatchResult mr;
                mr.path = path;
                mr.timestamps = edge_timestamps;
                mr.anomaly_score = compute_basic_score(path);
                mr.match_confidence = 1.0f;
                results.push_back(std::move(mr));

                // Backtrack
                NodeId node = path.back();
                path.pop_back();
                if (!edge_timestamps.empty()) edge_timestamps.pop_back();
                visit_count[node]--;
                stack.pop_back();
                continue;
            }

            const PatternStep& step = steps[frame.step_idx];

            // Get outgoing edges for current node
            size_t total_edges = 0;
            const TemporalEdge* edges = graph_.outgoing(frame.node, total_edges);

            bool found = false;

            while (frame.edge_cursor < frame.edge_hi && frame.edge_cursor < total_edges) {
                size_t idx = frame.edge_cursor;
                frame.edge_cursor++;

                const TemporalEdge& e = edges[idx];

                // Prune 1: Relation type
                if (!rel_matches(step.relation_type, e.rel_type)) continue;

                // Prune 2: Entity type
                if (!entity_matches(step.entity_type, graph_.node_type(e.target))) continue;

                // Prune 3: Causal monotonicity (implicit from edge_range)
                // Already handled by temporal_range

                // Prune 5: k-simplicity (cycle avoidance)
                if (visit_count[e.target] >= k) continue;

                // Match! Push to path and descend.
                visit_count[e.target]++;
                path.push_back(e.target);
                edge_timestamps.push_back(e.timestamp);

                uint32_t next_step = frame.step_idx + 1;

                // Compute edge window for next step
                size_t next_lo = 0, next_hi = 0;
                if (next_step < num_steps) {
                    size_t next_total = 0;
                    const TemporalEdge* next_edges = graph_.outgoing(e.target, next_total);
                    if (next_edges && next_total > 0) {
                        Timestamp tw_end = GM_TS_MAX;
                        if (query.time_window_ms > 0 && !edge_timestamps.empty()) {
                            // Window relative to first edge in the chain
                            tw_end = edge_timestamps[0] + query.time_window_ms;
                        }
                        PruningEngine::temporal_range(
                            next_edges, next_total,
                            e.timestamp,  // causal monotonicity
                            GM_TS_MIN,
                            tw_end,
                            next_lo, next_hi);
                    }
                }

                stack.push_back({e.target, next_step, next_lo, next_hi, next_lo});
                found = true;
                break;
            }

            if (!found) {
                // Exhausted all candidates — backtrack
                NodeId node = path.back();
                path.pop_back();
                if (!edge_timestamps.empty()) edge_timestamps.pop_back();
                visit_count[node]--;
                stack.pop_back();
            }
        }
    }

    /// Basic anomaly score: average node score from the CSR graph.
    /// Full scoring is done by the Scorer component.
    float compute_basic_score(const std::vector<NodeId>& path) const noexcept {
        if (path.empty()) return 0.0f;
        float sum = 0.0f;
        for (NodeId n : path) {
            sum += graph_.node_score(n);
        }
        return sum / static_cast<float>(path.size());
    }

    const CSRTemporalGraph& graph_;
};

} // namespace gm

#endif // GRAPHMATCH_MATCHER_HPP
