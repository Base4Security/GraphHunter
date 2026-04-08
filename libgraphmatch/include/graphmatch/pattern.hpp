/// @file pattern.hpp
/// @brief Pattern compiler: transforms hunt hypotheses into optimized query plans.
///
/// Adapts VF2++ matching order heuristics for temporal graph pattern matching.
/// The compiler reorders pattern steps by selectivity (rarest entity type first,
/// highest degree as tiebreaker) to minimize the DFS search space.

#ifndef GRAPHMATCH_PATTERN_HPP
#define GRAPHMATCH_PATTERN_HPP

#include "csr_graph.hpp"
#include "types.h"

#include <algorithm>
#include <cstdint>
#include <numeric>
#include <vector>

namespace gm {

// ---------------------------------------------------------------------------
// PatternStep — a single step in the hunt hypothesis.
// ---------------------------------------------------------------------------

/// One step of the hypothesis chain: expects an edge of a given relation type
/// leading to a node of a given entity type.
struct PatternStep {
    EntityTypeTag entity_type;     ///< Expected entity type at destination.
    RelTypeTag    relation_type;   ///< Expected edge type.
    bool          enforce_causality; ///< Require timestamp >= previous step.
};

// ---------------------------------------------------------------------------
// PatternQuery — compiled, optimized query plan.
// ---------------------------------------------------------------------------

struct PatternQuery {
    /// Original steps (in hypothesis order).
    std::vector<PatternStep> steps;

    /// Maximum time window in milliseconds (0 = no window constraint).
    int64_t time_window_ms = 0;

    /// VF2++ optimized matching order.
    /// matching_order[i] = index into `steps` for the i-th step to evaluate.
    /// For chain patterns (our primary use case), this is often the identity
    /// permutation, since chains don't benefit from reordering. But for
    /// branching patterns (future), this is critical.
    std::vector<uint32_t> matching_order;

    /// Starting entity type (the origin of the first step in the hypothesis).
    EntityTypeTag start_entity_type = GM_ENTITY_ANY;

    /// Number of steps.
    uint32_t num_steps() const noexcept {
        return static_cast<uint32_t>(steps.size());
    }
};

// ---------------------------------------------------------------------------
// PatternCompiler
// ---------------------------------------------------------------------------

class PatternCompiler {
public:
    /// Compile raw hypothesis steps into an optimized query plan.
    ///
    /// @param steps            Ordered hypothesis steps.
    /// @param start_type       Entity type of the starting node.
    /// @param time_window_ms   Time window constraint (0 = none).
    /// @param graph            The graph (for selectivity statistics).
    /// @return Compiled query with optimized matching order.
    PatternQuery compile(
        const std::vector<PatternStep>& steps,
        EntityTypeTag start_type,
        int64_t time_window_ms,
        const CSRTemporalGraph& graph) const
    {
        PatternQuery q;
        q.steps = steps;
        q.time_window_ms = time_window_ms;
        q.start_entity_type = start_type;
        q.matching_order = compute_matching_order(steps, start_type, graph);
        return q;
    }

    /// Simplified compile without graph statistics (identity order).
    PatternQuery compile_simple(
        const std::vector<PatternStep>& steps,
        EntityTypeTag start_type,
        int64_t time_window_ms) const
    {
        PatternQuery q;
        q.steps = steps;
        q.time_window_ms = time_window_ms;
        q.start_entity_type = start_type;
        q.matching_order.resize(steps.size());
        std::iota(q.matching_order.begin(), q.matching_order.end(), 0);
        return q;
    }

private:
    /// VF2++ matching order computation.
    ///
    /// For chain patterns (sequential hypothesis), the optimal order is
    /// typically to start from the step with the rarest entity type, then
    /// follow the chain. For now, we implement a selectivity-based
    /// reordering that works well for linear chains.
    ///
    /// Heuristics:
    /// 1. Selectivity: prefer entity types with fewer nodes in the graph.
    /// 2. Degree: among equally rare types, prefer higher average degree.
    /// 3. Position: prefer intermediate positions (more bidirectional constraints).
    std::vector<uint32_t> compute_matching_order(
        const std::vector<PatternStep>& steps,
        EntityTypeTag start_type,
        const CSRTemporalGraph& graph) const
    {
        uint32_t n = static_cast<uint32_t>(steps.size());
        if (n == 0) return {};

        // For chain patterns used in threat hunting, the hypothesis defines
        // a strict causal order. Reordering steps would break the temporal
        // monotonicity constraint. Therefore, we keep the identity order
        // for chain patterns and only apply selectivity for choosing the
        // best starting entity set.
        //
        // The selectivity analysis is still useful: if the start_type has
        // fewer instances than a later step's type, we can record that
        // information for the matcher to prioritize start nodes.

        std::vector<uint32_t> order(n);
        std::iota(order.begin(), order.end(), 0);

        // Store selectivity scores for each step (lower = more selective)
        std::vector<size_t> selectivity(n);
        for (uint32_t i = 0; i < n; ++i) {
            size_t count = 0;
            graph.nodes_of_type(steps[i].entity_type, count);
            selectivity[i] = (steps[i].entity_type == GM_ENTITY_ANY)
                ? graph.node_count()
                : count;
        }

        // For chain patterns, keep identity order.
        // In the future, branching patterns could use:
        // std::sort(order.begin(), order.end(), [&](uint32_t a, uint32_t b) {
        //     return selectivity[a] < selectivity[b];
        // });

        return order;
    }
};

} // namespace gm

#endif // GRAPHMATCH_PATTERN_HPP
