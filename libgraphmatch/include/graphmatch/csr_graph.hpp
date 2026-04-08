/// @file csr_graph.hpp
/// @brief Compressed Sparse Row temporal multigraph store.
///
/// Optimized for cache-friendly sequential scans and SIMD-accelerated
/// neighbor intersection. Mirrors Graph Hunter's GraphHunter + SpillableEdgeStore
/// but with a flat, contiguous memory layout.
///
/// Design invariants (after finalize()):
///   - edge_list_ sorted per-source by timestamp (primary), target (secondary)
///   - sorted_targets_ contains per-source target IDs sorted for SIMD intersection
///   - reverse CSR built for incoming-edge queries
///   - All arrays are contiguous — no linked lists, no indirection

#ifndef GRAPHMATCH_CSR_GRAPH_HPP
#define GRAPHMATCH_CSR_GRAPH_HPP

#include "types.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <numeric>
#include <string>
#include <unordered_map>
#include <vector>

namespace gm {

// ---------------------------------------------------------------------------
// String interner — bidirectional string ↔ uint32_t mapping.
// ---------------------------------------------------------------------------

class StringInterner {
public:
    /// Intern a string, returning its ID. If already interned, returns existing ID.
    uint32_t intern(const std::string& s) {
        auto it = map_.find(s);
        if (it != map_.end()) return it->second;
        uint32_t id = static_cast<uint32_t>(strings_.size());
        strings_.push_back(s);
        map_[s] = id;
        return id;
    }

    /// Resolve an ID back to its string. Returns nullptr if invalid.
    const char* resolve(uint32_t id) const noexcept {
        if (id < strings_.size()) return strings_[id].c_str();
        return nullptr;
    }

    /// Look up without interning. Returns GM_INVALID_NODE if not found.
    uint32_t get(const std::string& s) const noexcept {
        auto it = map_.find(s);
        return (it != map_.end()) ? it->second : GM_INVALID_NODE;
    }

    size_t size() const noexcept { return strings_.size(); }

    void reserve(size_t n) {
        strings_.reserve(n);
        map_.reserve(n);
    }

private:
    std::vector<std::string> strings_;
    std::unordered_map<std::string, uint32_t> map_;
};

// ---------------------------------------------------------------------------
// Builder edge — used during construction before finalize().
// ---------------------------------------------------------------------------

struct BuilderEdge {
    NodeId   source;
    NodeId   target;
    RelTypeTag rel_type;
    Timestamp  timestamp;
};

// ---------------------------------------------------------------------------
// CSRTemporalGraph
// ---------------------------------------------------------------------------

class CSRTemporalGraph {
public:
    CSRTemporalGraph() = default;

    // -- Builder API (before finalize) ------------------------------------

    /// Add a node with the given type. Duplicate IDs are ignored.
    void add_node(NodeId id, EntityTypeTag type) {
        if (id >= node_types_.size()) {
            node_types_.resize(id + 1, GM_ENTITY_ANY);
            node_scores_.resize(id + 1, 0.0f);
        }
        node_types_[id] = type;

        type_index_[type].push_back(id);

        if (id >= node_count_) node_count_ = id + 1;
    }

    /// Add a directed temporal edge.
    void add_edge(NodeId src, NodeId dst, RelTypeTag rel_type, Timestamp ts) {
        pending_edges_.push_back({src, dst, rel_type, ts});
    }

    /// Set anomaly score for a node.
    void set_node_score(NodeId id, float score) {
        if (id < node_scores_.size()) node_scores_[id] = score;
    }

    /// Build CSR arrays, sort edges, construct indices.
    /// Must be called before any query. After this, add_node/add_edge are invalid.
    void finalize() {
        if (finalized_) return;
        build_forward_csr();
        build_reverse_csr();
        build_sorted_targets();
        deduplicate_type_index();
        finalized_ = true;
    }

    // -- Query API (after finalize) ---------------------------------------

    /// Number of nodes.
    uint32_t node_count() const noexcept { return node_count_; }

    /// Number of edges.
    uint32_t edge_count() const noexcept {
        return static_cast<uint32_t>(edge_list_.size());
    }

    /// Entity type of a node.
    EntityTypeTag node_type(NodeId id) const noexcept {
        return (id < node_types_.size()) ? node_types_[id] : GM_ENTITY_ANY;
    }

    /// Anomaly score of a node.
    float node_score(NodeId id) const noexcept {
        return (id < node_scores_.size()) ? node_scores_[id] : 0.0f;
    }

    /// All outgoing edges from a node (sorted by timestamp, then target).
    /// Returns pointer + count via out parameters.
    const TemporalEdge* outgoing(NodeId node, size_t& count) const noexcept {
        if (node >= row_ptr_.size() - 1) { count = 0; return nullptr; }
        size_t start = row_ptr_[node];
        size_t end   = row_ptr_[node + 1];
        count = end - start;
        return (count > 0) ? &edge_list_[start] : nullptr;
    }

    /// All incoming edges to a node (sorted by timestamp).
    const TemporalEdge* incoming(NodeId node, size_t& count) const noexcept {
        if (node >= rev_row_ptr_.size() - 1) { count = 0; return nullptr; }
        size_t start = rev_row_ptr_[node];
        size_t end   = rev_row_ptr_[node + 1];
        count = end - start;
        return (count > 0) ? &rev_edge_list_[start] : nullptr;
    }

    /// Outgoing edges within a temporal window [t_start, t_end].
    /// Uses binary search on the timestamp-sorted edge list.
    /// Returns pointer to first valid edge + count.
    const TemporalEdge* outgoing_in_window(
        NodeId node, Timestamp t_start, Timestamp t_end,
        size_t& count) const noexcept
    {
        size_t total;
        const TemporalEdge* edges = outgoing(node, total);
        if (!edges || total == 0) { count = 0; return nullptr; }

        // Lower bound: first edge with timestamp >= t_start
        size_t lo = 0, hi = total;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (edges[mid].timestamp < t_start) lo = mid + 1;
            else hi = mid;
        }
        size_t start = lo;

        // Upper bound: first edge with timestamp > t_end
        lo = start; hi = total;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (edges[mid].timestamp <= t_end) lo = mid + 1;
            else hi = mid;
        }
        size_t end = lo;

        count = (end > start) ? end - start : 0;
        return (count > 0) ? &edges[start] : nullptr;
    }

    /// Sorted neighbor target IDs for SIMD intersection.
    /// These are the unique target node IDs from outgoing edges, sorted ascending.
    const uint32_t* sorted_neighbors(NodeId node, size_t& count) const noexcept {
        if (node >= st_row_ptr_.size() - 1) { count = 0; return nullptr; }
        size_t start = st_row_ptr_[node];
        size_t end   = st_row_ptr_[node + 1];
        count = end - start;
        return (count > 0) ? &sorted_targets_[start] : nullptr;
    }

    /// All node IDs of a given entity type.
    const uint32_t* nodes_of_type(EntityTypeTag type, size_t& count) const noexcept {
        auto it = type_index_.find(type);
        if (it == type_index_.end()) { count = 0; return nullptr; }
        count = it->second.size();
        return it->second.data();
    }

    /// Access the string interner (for resolving node names).
    const StringInterner& interner() const noexcept { return interner_; }
    StringInterner& interner() noexcept { return interner_; }

    /// Whether finalize() has been called.
    bool is_finalized() const noexcept { return finalized_; }

private:
    // -- Internal builders ------------------------------------------------

    void build_forward_csr() {
        // Sort pending edges by source, then timestamp, then target
        std::sort(pending_edges_.begin(), pending_edges_.end(),
            [](const BuilderEdge& a, const BuilderEdge& b) {
                if (a.source != b.source) return a.source < b.source;
                if (a.timestamp != b.timestamp) return a.timestamp < b.timestamp;
                return a.target < b.target;
            });

        // Build row_ptr and edge_list
        row_ptr_.resize(node_count_ + 1, 0);
        edge_list_.resize(pending_edges_.size());

        for (const auto& e : pending_edges_) {
            if (e.source < node_count_) row_ptr_[e.source + 1]++;
        }
        // Prefix sum
        for (uint32_t i = 1; i <= node_count_; ++i) {
            row_ptr_[i] += row_ptr_[i - 1];
        }

        // Fill edge_list (already sorted, just copy in order)
        std::vector<size_t> cursors(node_count_, 0);
        for (uint32_t i = 0; i < node_count_; ++i) {
            cursors[i] = row_ptr_[i];
        }
        for (const auto& e : pending_edges_) {
            if (e.source >= node_count_) continue;
            size_t pos = cursors[e.source]++;
            edge_list_[pos] = TemporalEdge{e.target, e.rel_type, {}, e.timestamp};
        }
    }

    void build_reverse_csr() {
        // Count incoming edges per node
        std::vector<uint32_t> rev_count(node_count_ + 1, 0);
        for (const auto& e : pending_edges_) {
            if (e.target < node_count_) rev_count[e.target + 1]++;
        }
        // Prefix sum
        rev_row_ptr_.resize(node_count_ + 1, 0);
        for (uint32_t i = 1; i <= node_count_; ++i) {
            rev_row_ptr_[i] = rev_row_ptr_[i - 1] + rev_count[i];
        }

        // Build reverse edge list (edges point "from" the source, stored at target's slot)
        rev_edge_list_.resize(pending_edges_.size());
        std::vector<size_t> cursors(node_count_, 0);
        for (uint32_t i = 0; i < node_count_; ++i) {
            cursors[i] = rev_row_ptr_[i];
        }

        // Sort pending edges by target, then timestamp for reverse
        std::vector<size_t> order(pending_edges_.size());
        std::iota(order.begin(), order.end(), 0);
        std::sort(order.begin(), order.end(), [&](size_t i, size_t j) {
            const auto& a = pending_edges_[i];
            const auto& b = pending_edges_[j];
            if (a.target != b.target) return a.target < b.target;
            return a.timestamp < b.timestamp;
        });

        for (size_t idx : order) {
            const auto& e = pending_edges_[idx];
            if (e.target >= node_count_) continue;
            size_t pos = cursors[e.target]++;
            // In reverse CSR, the "target" field stores the source node
            rev_edge_list_[pos] = TemporalEdge{e.source, e.rel_type, {}, e.timestamp};
        }
    }

    void build_sorted_targets() {
        // For each node, extract unique target IDs from outgoing edges, sorted
        st_row_ptr_.resize(node_count_ + 1, 0);

        // First pass: count unique targets per node
        for (uint32_t n = 0; n < node_count_; ++n) {
            size_t start = row_ptr_[n];
            size_t end   = row_ptr_[n + 1];
            if (start >= end) continue;

            // Collect targets
            uint32_t prev = GM_INVALID_NODE;
            uint32_t unique_count = 0;
            // We need sorted by target, but edge_list is sorted by timestamp.
            // Collect all targets, sort, deduplicate.
            tmp_targets_.clear();
            for (size_t i = start; i < end; ++i) {
                tmp_targets_.push_back(edge_list_[i].target);
            }
            std::sort(tmp_targets_.begin(), tmp_targets_.end());
            auto last = std::unique(tmp_targets_.begin(), tmp_targets_.end());
            size_t cnt = static_cast<size_t>(last - tmp_targets_.begin());
            st_row_ptr_[n + 1] = static_cast<uint32_t>(cnt);
        }

        // Prefix sum
        for (uint32_t i = 1; i <= node_count_; ++i) {
            st_row_ptr_[i] += st_row_ptr_[i - 1];
        }

        // Second pass: fill sorted_targets
        sorted_targets_.resize(st_row_ptr_[node_count_]);
        for (uint32_t n = 0; n < node_count_; ++n) {
            size_t start = row_ptr_[n];
            size_t end   = row_ptr_[n + 1];
            if (start >= end) continue;

            tmp_targets_.clear();
            for (size_t i = start; i < end; ++i) {
                tmp_targets_.push_back(edge_list_[i].target);
            }
            std::sort(tmp_targets_.begin(), tmp_targets_.end());
            auto last = std::unique(tmp_targets_.begin(), tmp_targets_.end());
            size_t cnt = static_cast<size_t>(last - tmp_targets_.begin());

            size_t dst = st_row_ptr_[n];
            for (size_t i = 0; i < cnt; ++i) {
                sorted_targets_[dst + i] = tmp_targets_[i];
            }
        }
    }

    void deduplicate_type_index() {
        for (auto& [type, ids] : type_index_) {
            std::sort(ids.begin(), ids.end());
            ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
        }
    }

    // -- Data members -----------------------------------------------------

    // Builder state
    std::vector<BuilderEdge> pending_edges_;
    bool finalized_ = false;
    uint32_t node_count_ = 0;

    // Forward CSR (outgoing edges)
    std::vector<size_t>       row_ptr_;       // node_count + 1
    std::vector<TemporalEdge> edge_list_;     // sorted by (source, timestamp, target)

    // Reverse CSR (incoming edges)
    std::vector<size_t>       rev_row_ptr_;
    std::vector<TemporalEdge> rev_edge_list_;

    // Sorted target arrays for SIMD intersection
    std::vector<uint32_t> st_row_ptr_;       // node_count + 1
    std::vector<uint32_t> sorted_targets_;   // unique targets per node, sorted

    // Node metadata
    std::vector<EntityTypeTag> node_types_;
    std::vector<float>         node_scores_;

    // Type index: entity_type → [node_ids]
    std::unordered_map<EntityTypeTag, std::vector<uint32_t>> type_index_;

    // String interner
    StringInterner interner_;

    // Temp buffer (reused during build)
    std::vector<uint32_t> tmp_targets_;
};

} // namespace gm

#endif // GRAPHMATCH_CSR_GRAPH_HPP
