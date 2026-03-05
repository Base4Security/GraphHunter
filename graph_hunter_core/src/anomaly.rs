use ahash::{HashMap, HashMapExt};
use serde::{Deserialize, Serialize};

use crate::graph::GraphHunter;

/// Configurable weights for the five anomaly scoring components.
/// Weights are automatically renormalized when computing scores.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScoringWeights {
    pub w1_entity_rarity: f64,
    pub w2_edge_rarity: f64,
    pub w3_neighborhood_conc: f64,
    pub w4_temporal_novelty: f64,
    /// GNN-based threat classification score (from GraphOS-APT models).
    /// Default 0.0 = disabled; set > 0 to activate ML scoring.
    #[serde(default)]
    pub w5_gnn_threat: f64,
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            w1_entity_rarity: 0.25,
            w2_edge_rarity: 0.30,
            w3_neighborhood_conc: 0.25,
            w4_temporal_novelty: 0.20,
            w5_gnn_threat: 0.0,
        }
    }
}

/// Breakdown of the five anomaly scoring components for a single path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    pub entity_rarity: f64,
    pub edge_rarity: f64,
    pub neighborhood_concentration: f64,
    pub temporal_novelty: f64,
    /// GNN threat score (0.0 if ML scoring is not active).
    #[serde(default)]
    pub gnn_threat: f64,
}

/// Threat classes from GraphOS-APT GNN classification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatClass {
    Benign,
    Exfiltration,
    C2Beacon,
    LateralMovement,
    PrivilegeEscalation,
}

impl ThreatClass {
    /// Map from argmax index to threat class.
    pub fn from_index(idx: usize) -> Self {
        match idx {
            1 => ThreatClass::Exfiltration,
            2 => ThreatClass::C2Beacon,
            3 => ThreatClass::LateralMovement,
            4 => ThreatClass::PrivilegeEscalation,
            _ => ThreatClass::Benign,
        }
    }

    /// Convert 5-class logits to a single threat score in [0, 1].
    /// Uses max non-benign softmax probability as the threat score.
    pub fn threat_score_from_logits(logits: &[f64; 5]) -> f64 {
        let max_logit = logits.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let exp_sum: f64 = logits.iter().map(|&l| (l - max_logit).exp()).sum();
        let benign_prob = (logits[0] - max_logit).exp() / exp_sum;
        (1.0 - benign_prob).clamp(0.0, 1.0)
    }
}

/// Post-processing anomaly scorer that operates on the ingested graph.
///
/// Usage:
/// 1. Create with `new(weights)`
/// 2. Call `observe_entity` and `observe_edge` during ingestion
/// 3. Call `finalize(graph)` after all data is loaded
/// 4. Call `score_path(path, graph)` for each hunt result path
#[derive(Clone, Debug)]
pub struct AnomalyScorer {
    /// entity_id → observation count
    entity_freq: HashMap<String, u64>,
    /// (src_id, dst_id) → observation count
    pair_freq: HashMap<(String, String), u64>,
    /// entity_id → first-seen timestamp
    first_seen: HashMap<String, i64>,
    /// entity_id → neighborhood concentration (1 - normalized Shannon entropy)
    nc_cache: HashMap<String, f64>,
    /// entity_id → GNN threat score in [0, 1] (from GraphOS-APT models)
    gnn_cache: HashMap<String, f64>,
    /// ln(max entity frequency), cached after finalize
    log_max_freq: f64,
    /// ln(max pair frequency), cached after finalize
    log_max_pair_freq: f64,
    /// Minimum first-seen timestamp across all entities
    tau_min: i64,
    /// Maximum first-seen timestamp across all entities
    tau_max: i64,
    /// Scoring weights
    weights: ScoringWeights,
    /// Whether finalize() has been called
    finalized: bool,
}

impl AnomalyScorer {
    /// Creates a new scorer with the given weights.
    pub fn new(weights: ScoringWeights) -> Self {
        Self {
            entity_freq: HashMap::new(),
            pair_freq: HashMap::new(),
            first_seen: HashMap::new(),
            nc_cache: HashMap::new(),
            gnn_cache: HashMap::new(),
            log_max_freq: 0.0,
            log_max_pair_freq: 0.0,
            tau_min: i64::MAX,
            tau_max: i64::MIN,
            weights,
            finalized: false,
        }
    }

    /// Record an entity observation during ingestion.
    pub fn observe_entity(&mut self, id: &str, timestamp: i64) {
        *self.entity_freq.entry(id.to_string()).or_insert(0) += 1;
        let ts = self.first_seen.entry(id.to_string()).or_insert(timestamp);
        if timestamp > 0 && (timestamp < *ts || *ts == 0) {
            *ts = timestamp;
        }
        self.finalized = false;
    }

    /// Record an edge observation during ingestion.
    pub fn observe_edge(&mut self, src: &str, dst: &str) {
        *self
            .pair_freq
            .entry((src.to_string(), dst.to_string()))
            .or_insert(0) += 1;
        self.finalized = false;
    }

    /// Finalize the scorer: compute derived caches from the graph.
    /// Must be called after all ingestion is complete, before scoring paths.
    pub fn finalize(&mut self, graph: &GraphHunter) {
        // Compute log_max_freq
        let max_freq = self.entity_freq.values().copied().max().unwrap_or(1);
        self.log_max_freq = (max_freq as f64).ln();

        // Compute log_max_pair_freq
        let max_pair = self.pair_freq.values().copied().max().unwrap_or(1);
        self.log_max_pair_freq = (max_pair as f64).ln();

        // Compute tau_min, tau_max from first_seen (only non-zero timestamps)
        self.tau_min = i64::MAX;
        self.tau_max = i64::MIN;
        for &ts in self.first_seen.values() {
            if ts > 0 {
                if ts < self.tau_min {
                    self.tau_min = ts;
                }
                if ts > self.tau_max {
                    self.tau_max = ts;
                }
            }
        }
        if self.tau_min == i64::MAX {
            self.tau_min = 0;
        }
        if self.tau_max == i64::MIN {
            self.tau_max = 0;
        }

        // Compute neighborhood concentration for each entity
        // graph.entities is keyed by StrId; resolve to &str for nc_cache keys
        self.nc_cache.clear();
        for (&sid, _entity) in &graph.entities {
            let entity_id_str = graph.interner.resolve(sid);
            let nc = self.compute_nc(sid, graph);
            self.nc_cache.insert(entity_id_str.to_string(), nc);
        }

        self.finalized = true;
    }

    /// Compute neighborhood concentration NC(v) = 1 - H(v)/log2(|N(v)|)
    /// where H(v) is the Shannon entropy of neighbor type distribution.
    fn compute_nc(&self, sid: crate::interner::StrId, graph: &GraphHunter) -> f64 {
        // Collect neighbor type counts (outgoing + incoming)
        let mut type_counts: HashMap<String, usize> = HashMap::new();
        let mut total_neighbors = 0usize;

        if let Some(rels) = graph.adjacency_list.get(&sid) {
            for rel in rels {
                if let Some(dest_sid) = graph.interner.get(&rel.dest_id) {
                    if let Some(dest) = graph.entities.get(&dest_sid) {
                        *type_counts
                            .entry(format!("{}", dest.entity_type))
                            .or_default() += 1;
                        total_neighbors += 1;
                    }
                }
            }
        }
        if let Some(sources) = graph.reverse_adj.get(&sid) {
            for &source_sid in sources {
                if let Some(src) = graph.entities.get(&source_sid) {
                    *type_counts
                        .entry(format!("{}", src.entity_type))
                        .or_default() += 1;
                    total_neighbors += 1;
                }
            }
        }

        let num_types = type_counts.len();
        if num_types <= 1 {
            // Single type or no neighbors → maximally concentrated
            return 1.0;
        }

        // Shannon entropy H(v) = -Σ p_i * log2(p_i)
        let total = total_neighbors as f64;
        let mut entropy = 0.0f64;
        for &count in type_counts.values() {
            let p = count as f64 / total;
            if p > 0.0 {
                entropy -= p * p.log2();
            }
        }

        // Normalize: H_max = log2(|types|)
        let h_max = (num_types as f64).log2();
        if h_max == 0.0 {
            return 1.0;
        }

        (1.0 - entropy / h_max).clamp(0.0, 1.0)
    }

    /// Score a single path and return the composite score S(p) ∈ [0,1] plus breakdown.
    pub fn score_path(&self, path: &[String], _graph: &GraphHunter) -> (f64, ScoreBreakdown) {
        if path.is_empty() || !self.finalized {
            return (
                0.0,
                ScoreBreakdown {
                    entity_rarity: 0.0,
                    edge_rarity: 0.0,
                    neighborhood_concentration: 0.0,
                    temporal_novelty: 0.0,
                    gnn_threat: 0.0,
                },
            );
        }

        // 1. Entity Rarity: ER(v) = 1 - ln(freq(v)) / ln(max_freq), averaged over path
        let er_avg = if self.log_max_freq > 0.0 {
            let sum: f64 = path
                .iter()
                .map(|id| {
                    let freq = self.entity_freq.get(id).copied().unwrap_or(1);
                    1.0 - (freq as f64).ln() / self.log_max_freq
                })
                .sum();
            (sum / path.len() as f64).clamp(0.0, 1.0)
        } else {
            0.0
        };

        // 2. Edge Rarity: EdgeR(e) = 1 - ln(freq(s,d)) / ln(max_pair_freq), averaged
        let edge_r_avg = if path.len() > 1 && self.log_max_pair_freq > 0.0 {
            let edge_count = path.len() - 1;
            let sum: f64 = (0..edge_count)
                .map(|i| {
                    let pair = (path[i].clone(), path[i + 1].clone());
                    let freq = self.pair_freq.get(&pair).copied().unwrap_or(1);
                    1.0 - (freq as f64).ln() / self.log_max_pair_freq
                })
                .sum();
            (sum / edge_count as f64).clamp(0.0, 1.0)
        } else {
            0.0
        };

        // 3. Neighborhood Concentration: averaged over path nodes
        let nc_avg = {
            let sum: f64 = path
                .iter()
                .map(|id| self.nc_cache.get(id).copied().unwrap_or(1.0))
                .sum();
            (sum / path.len() as f64).clamp(0.0, 1.0)
        };

        // 4. Temporal Novelty: TN(v) = (τ_first(v) - τ_min) / (τ_max - τ_min), averaged
        let tn_avg = if self.tau_max > self.tau_min {
            let range = (self.tau_max - self.tau_min) as f64;
            let sum: f64 = path
                .iter()
                .map(|id| {
                    let ts = self.first_seen.get(id).copied().unwrap_or(self.tau_min);
                    let ts = if ts > 0 { ts } else { self.tau_min };
                    (ts - self.tau_min) as f64 / range
                })
                .sum();
            (sum / path.len() as f64).clamp(0.0, 1.0)
        } else {
            0.0
        };

        // 5. GNN Threat: averaged over path nodes (0.0 if no GNN scores available)
        let gnn_avg = if !self.gnn_cache.is_empty() {
            let sum: f64 = path
                .iter()
                .map(|id| self.gnn_cache.get(id).copied().unwrap_or(0.0))
                .sum();
            (sum / path.len() as f64).clamp(0.0, 1.0)
        } else {
            0.0
        };

        let breakdown = ScoreBreakdown {
            entity_rarity: er_avg,
            edge_rarity: edge_r_avg,
            neighborhood_concentration: nc_avg,
            temporal_novelty: tn_avg,
            gnn_threat: gnn_avg,
        };

        // Composite: S(p) = Σ(wi * ci) / Σ(wi) — renormalized by active weights
        let w_sum = self.weights.w1_entity_rarity
            + self.weights.w2_edge_rarity
            + self.weights.w3_neighborhood_conc
            + self.weights.w4_temporal_novelty
            + self.weights.w5_gnn_threat;

        let composite = if w_sum > 0.0 {
            (self.weights.w1_entity_rarity * er_avg
                + self.weights.w2_edge_rarity * edge_r_avg
                + self.weights.w3_neighborhood_conc * nc_avg
                + self.weights.w4_temporal_novelty * tn_avg
                + self.weights.w5_gnn_threat * gnn_avg)
                / w_sum
        } else {
            0.0
        };

        (composite.clamp(0.0, 1.0), breakdown)
    }

    /// Fast O(1) per-node anomaly estimate (ER + NC + TN + GNN, no pair context).
    /// Used during DFS pruning. Returns a value in [0, 1].
    pub fn node_anomaly_estimate(&self, node_id: &str) -> f64 {
        if !self.finalized {
            return 0.5;
        }
        // Entity Rarity
        let er = if self.log_max_freq > 0.0 {
            let freq = self.entity_freq.get(node_id).copied().unwrap_or(1);
            (1.0 - (freq as f64).ln() / self.log_max_freq).clamp(0.0, 1.0)
        } else {
            0.0
        };
        // Neighborhood Concentration
        let nc = self.nc_cache.get(node_id).copied().unwrap_or(1.0);
        // Temporal Novelty
        let tn = if self.tau_max > self.tau_min {
            let range = (self.tau_max - self.tau_min) as f64;
            let ts = self.first_seen.get(node_id).copied().unwrap_or(self.tau_min);
            let ts = if ts > 0 { ts } else { self.tau_min };
            ((ts - self.tau_min) as f64 / range).clamp(0.0, 1.0)
        } else {
            0.0
        };
        // GNN Threat
        let gnn = self.gnn_cache.get(node_id).copied().unwrap_or(0.0);
        // Weighted average of available components, re-normalized
        let w_sum = self.weights.w1_entity_rarity
            + self.weights.w3_neighborhood_conc
            + self.weights.w4_temporal_novelty
            + self.weights.w5_gnn_threat;
        if w_sum > 0.0 {
            ((self.weights.w1_entity_rarity * er
                + self.weights.w3_neighborhood_conc * nc
                + self.weights.w4_temporal_novelty * tn
                + self.weights.w5_gnn_threat * gnn)
                / w_sum)
                .clamp(0.0, 1.0)
        } else {
            0.5
        }
    }

    /// Fast O(1) per-edge anomaly estimate (EdgeR for the specific pair).
    /// Used during DFS pruning. Returns a value in [0, 1].
    pub fn edge_anomaly_estimate(&self, src: &str, dst: &str) -> f64 {
        if !self.finalized || self.log_max_pair_freq <= 0.0 {
            return 0.5;
        }
        let pair = (src.to_string(), dst.to_string());
        let freq = self.pair_freq.get(&pair).copied().unwrap_or(1);
        (1.0 - (freq as f64).ln() / self.log_max_pair_freq).clamp(0.0, 1.0)
    }

    /// Update weights without re-finalizing.
    pub fn set_weights(&mut self, weights: ScoringWeights) {
        self.weights = weights;
    }

    /// Get current weights.
    pub fn weights(&self) -> &ScoringWeights {
        &self.weights
    }

    /// Whether the scorer has been finalized.
    pub fn is_finalized(&self) -> bool {
        self.finalized
    }

    /// Inject externally computed GNN threat scores (entity_id → score in [0,1]).
    /// Call this after finalize() to add ML-based scores from GraphOS-APT models.
    pub fn set_gnn_scores(&mut self, scores: HashMap<String, f64>) {
        self.gnn_cache = scores;
    }

    /// Get the current GNN threat score cache.
    pub fn gnn_scores(&self) -> &HashMap<String, f64> {
        &self.gnn_cache
    }
}
