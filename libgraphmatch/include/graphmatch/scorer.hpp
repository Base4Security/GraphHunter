/// @file scorer.hpp
/// @brief Endogenous anomaly scorer — ports Graph Hunter's AnomalyScorer to C++.
///
/// Five scoring components:
///   1. Entity Rarity (ER)        — 1 - ln(freq(v)) / ln(max_freq)
///   2. Edge Rarity (EdgeR)       — 1 - ln(freq(s,d)) / ln(max_pair_freq)
///   3. Neighborhood Conc. (NC)   — 1 - H(v)/log2(|N(v)|)
///   4. Temporal Novelty (TN)     — (τ_first(v) - τ_min) / (τ_max - τ_min)
///   5. GNN Threat (optional)     — external ML score in [0, 1]

#ifndef GRAPHMATCH_SCORER_HPP
#define GRAPHMATCH_SCORER_HPP

#include "csr_graph.hpp"
#include "types.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace gm {

// ---------------------------------------------------------------------------
// Scoring weights
// ---------------------------------------------------------------------------

struct ScoringWeights {
    float w1_entity_rarity     = 0.25f;
    float w2_edge_rarity       = 0.30f;
    float w3_neighborhood_conc = 0.25f;
    float w4_temporal_novelty  = 0.20f;
    float w5_gnn_threat        = 0.00f; // Disabled by default.
};

// ---------------------------------------------------------------------------
// Score breakdown
// ---------------------------------------------------------------------------

struct ScoreBreakdown {
    float entity_rarity;
    float edge_rarity;
    float neighborhood_concentration;
    float temporal_novelty;
    float gnn_threat;
};

// ---------------------------------------------------------------------------
// AnomalyScorer
// ---------------------------------------------------------------------------

class AnomalyScorer {
public:
    explicit AnomalyScorer(ScoringWeights weights = {})
        : weights_(weights) {}

    /// Record entity observation during ingestion.
    void observe_entity(NodeId id, Timestamp ts) {
        entity_freq_[id]++;
        auto it = first_seen_.find(id);
        if (it == first_seen_.end() || (ts > 0 && ts < it->second)) {
            first_seen_[id] = ts;
        }
    }

    /// Record edge observation during ingestion.
    void observe_edge(NodeId src, NodeId dst) {
        pair_freq_[{src, dst}]++;
    }

    /// Finalize: compute derived caches. Must call after all observations.
    void finalize(const CSRTemporalGraph& graph) {
        // Max entity frequency
        uint64_t max_freq = 1;
        for (auto& [id, freq] : entity_freq_) {
            if (freq > max_freq) max_freq = freq;
        }
        log_max_freq_ = std::log(static_cast<double>(max_freq));

        // Max pair frequency
        uint64_t max_pair = 1;
        for (auto& [pair, freq] : pair_freq_) {
            if (freq > max_pair) max_pair = freq;
        }
        log_max_pair_freq_ = std::log(static_cast<double>(max_pair));

        // Temporal range
        tau_min_ = INT64_MAX;
        tau_max_ = INT64_MIN;
        for (auto& [id, ts] : first_seen_) {
            if (ts > 0) {
                if (ts < tau_min_) tau_min_ = ts;
                if (ts > tau_max_) tau_max_ = ts;
            }
        }
        if (tau_min_ == INT64_MAX) tau_min_ = 0;
        if (tau_max_ == INT64_MIN) tau_max_ = 0;

        // Neighborhood concentration for each node
        nc_cache_.clear();
        for (uint32_t n = 0; n < graph.node_count(); ++n) {
            nc_cache_[n] = compute_nc(n, graph);
        }

        finalized_ = true;
    }

    /// Score a path. Returns composite score and breakdown.
    float score_path(const NodeId* path, size_t path_len,
                     ScoreBreakdown* breakdown = nullptr) const
    {
        if (path_len == 0 || !finalized_) {
            if (breakdown) *breakdown = {0, 0, 0, 0, 0};
            return 0.0f;
        }

        // 1. Entity Rarity
        float er = 0.0f;
        if (log_max_freq_ > 0.0) {
            double sum = 0.0;
            for (size_t i = 0; i < path_len; ++i) {
                auto it = entity_freq_.find(path[i]);
                uint64_t freq = (it != entity_freq_.end()) ? it->second : 1;
                sum += 1.0 - std::log(static_cast<double>(freq)) / log_max_freq_;
            }
            er = static_cast<float>(
                std::clamp(sum / static_cast<double>(path_len), 0.0, 1.0));
        }

        // 2. Edge Rarity
        float edge_r = 0.0f;
        if (path_len > 1 && log_max_pair_freq_ > 0.0) {
            double sum = 0.0;
            size_t edge_count = path_len - 1;
            for (size_t i = 0; i < edge_count; ++i) {
                auto it = pair_freq_.find({path[i], path[i + 1]});
                uint64_t freq = (it != pair_freq_.end()) ? it->second : 1;
                sum += 1.0 - std::log(static_cast<double>(freq)) / log_max_pair_freq_;
            }
            edge_r = static_cast<float>(
                std::clamp(sum / static_cast<double>(edge_count), 0.0, 1.0));
        }

        // 3. Neighborhood Concentration
        float nc = 0.0f;
        {
            double sum = 0.0;
            for (size_t i = 0; i < path_len; ++i) {
                auto it = nc_cache_.find(path[i]);
                sum += (it != nc_cache_.end()) ? it->second : 1.0;
            }
            nc = static_cast<float>(
                std::clamp(sum / static_cast<double>(path_len), 0.0, 1.0));
        }

        // 4. Temporal Novelty
        float tn = 0.0f;
        if (tau_max_ > tau_min_) {
            double range = static_cast<double>(tau_max_ - tau_min_);
            double sum = 0.0;
            for (size_t i = 0; i < path_len; ++i) {
                auto it = first_seen_.find(path[i]);
                Timestamp ts = (it != first_seen_.end()) ? it->second : tau_min_;
                if (ts <= 0) ts = tau_min_;
                sum += static_cast<double>(ts - tau_min_) / range;
            }
            tn = static_cast<float>(
                std::clamp(sum / static_cast<double>(path_len), 0.0, 1.0));
        }

        // 5. GNN Threat
        float gnn = 0.0f;
        if (!gnn_cache_.empty()) {
            double sum = 0.0;
            for (size_t i = 0; i < path_len; ++i) {
                auto it = gnn_cache_.find(path[i]);
                sum += (it != gnn_cache_.end()) ? it->second : 0.0;
            }
            gnn = static_cast<float>(
                std::clamp(sum / static_cast<double>(path_len), 0.0, 1.0));
        }

        if (breakdown) {
            *breakdown = {er, edge_r, nc, tn, gnn};
        }

        // Composite
        float w_sum = weights_.w1_entity_rarity + weights_.w2_edge_rarity
                    + weights_.w3_neighborhood_conc + weights_.w4_temporal_novelty
                    + weights_.w5_gnn_threat;

        if (w_sum <= 0.0f) return 0.0f;

        float composite = (weights_.w1_entity_rarity * er
                         + weights_.w2_edge_rarity * edge_r
                         + weights_.w3_neighborhood_conc * nc
                         + weights_.w4_temporal_novelty * tn
                         + weights_.w5_gnn_threat * gnn) / w_sum;

        return std::clamp(composite, 0.0f, 1.0f);
    }

    /// Fast O(1) node anomaly estimate (for DFS pruning).
    float node_estimate(NodeId id) const {
        if (!finalized_) return 0.5f;

        float er = 0.0f;
        if (log_max_freq_ > 0.0) {
            auto it = entity_freq_.find(id);
            uint64_t freq = (it != entity_freq_.end()) ? it->second : 1;
            er = static_cast<float>(
                std::clamp(1.0 - std::log(static_cast<double>(freq)) / log_max_freq_, 0.0, 1.0));
        }

        auto nc_it = nc_cache_.find(id);
        float nc = (nc_it != nc_cache_.end()) ? static_cast<float>(nc_it->second) : 1.0f;

        float tn = 0.0f;
        if (tau_max_ > tau_min_) {
            auto it = first_seen_.find(id);
            Timestamp ts = (it != first_seen_.end()) ? it->second : tau_min_;
            if (ts <= 0) ts = tau_min_;
            tn = static_cast<float>(
                std::clamp(static_cast<double>(ts - tau_min_) /
                           static_cast<double>(tau_max_ - tau_min_), 0.0, 1.0));
        }

        float gnn = 0.0f;
        auto gnn_it = gnn_cache_.find(id);
        if (gnn_it != gnn_cache_.end()) gnn = static_cast<float>(gnn_it->second);

        float w_sum = weights_.w1_entity_rarity + weights_.w3_neighborhood_conc
                    + weights_.w4_temporal_novelty + weights_.w5_gnn_threat;
        if (w_sum <= 0.0f) return 0.5f;

        return std::clamp(
            (weights_.w1_entity_rarity * er + weights_.w3_neighborhood_conc * nc
             + weights_.w4_temporal_novelty * tn + weights_.w5_gnn_threat * gnn) / w_sum,
            0.0f, 1.0f);
    }

    void set_weights(ScoringWeights w) { weights_ = w; }
    const ScoringWeights& weights() const { return weights_; }
    bool is_finalized() const { return finalized_; }

    /// Inject external GNN scores.
    void set_gnn_scores(std::unordered_map<NodeId, double> scores) {
        gnn_cache_ = std::move(scores);
    }

private:
    float compute_nc(NodeId node, const CSRTemporalGraph& graph) const {
        std::unordered_map<EntityTypeTag, uint32_t> type_counts;
        uint32_t total = 0;

        size_t count = 0;
        const TemporalEdge* out = graph.outgoing(node, count);
        for (size_t i = 0; i < count; ++i) {
            type_counts[graph.node_type(out[i].target)]++;
            total++;
        }
        const TemporalEdge* in = graph.incoming(node, count);
        for (size_t i = 0; i < count; ++i) {
            type_counts[graph.node_type(in[i].target)]++;
            total++;
        }

        if (type_counts.size() <= 1) return 1.0f;

        double entropy = 0.0;
        double t = static_cast<double>(total);
        for (auto& [type, cnt] : type_counts) {
            double p = static_cast<double>(cnt) / t;
            if (p > 0.0) entropy -= p * std::log2(p);
        }
        double h_max = std::log2(static_cast<double>(type_counts.size()));
        if (h_max == 0.0) return 1.0f;

        return static_cast<float>(std::clamp(1.0 - entropy / h_max, 0.0, 1.0));
    }

    struct PairHash {
        size_t operator()(const std::pair<NodeId, NodeId>& p) const noexcept {
            return std::hash<uint64_t>{}(
                (static_cast<uint64_t>(p.first) << 32) | p.second);
        }
    };

    ScoringWeights weights_;
    bool finalized_ = false;

    std::unordered_map<NodeId, uint64_t> entity_freq_;
    std::unordered_map<std::pair<NodeId, NodeId>, uint64_t, PairHash> pair_freq_;
    std::unordered_map<NodeId, Timestamp> first_seen_;
    std::unordered_map<NodeId, double> nc_cache_;
    std::unordered_map<NodeId, double> gnn_cache_;

    double log_max_freq_ = 0.0;
    double log_max_pair_freq_ = 0.0;
    Timestamp tau_min_ = 0;
    Timestamp tau_max_ = 0;
};

} // namespace gm

#endif // GRAPHMATCH_SCORER_HPP
