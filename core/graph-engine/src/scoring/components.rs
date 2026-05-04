//! The five built-in [`ScoreComponent`] implementations.
//!
//! All five reproduce the math that used to live directly in
//! [`crate::AnomalyScorer::score_path`] — snapshotted bit-for-bit by
//! `tests/scoring_snapshot.rs`. Keeping them separate structs is what
//! lets a future scorer add a sixth component (Bayesian, MITRE
//! overlap, etc.) without editing any of the existing ones.

use super::{PathContext, ScoreComponent};

// ── Entity Rarity ───────────────────────────────────────────────────

/// `ER(v) = 1 - ln(freq(v)) / ln(max_freq)`, averaged over path nodes.
/// Captures "how unusual is it to see these specific entities at all".
pub struct EntityRarity;

impl ScoreComponent for EntityRarity {
    fn name(&self) -> &'static str {
        "entity_rarity"
    }

    fn score_path(&self, ctx: &PathContext<'_>) -> f64 {
        let caches = ctx.caches;
        if ctx.path.is_empty() || caches.log_max_freq <= 0.0 {
            return 0.0;
        }
        let sum: f64 = ctx
            .path
            .iter()
            .map(|id| {
                let freq = caches.entity_freq.get(id).copied().unwrap_or(1);
                1.0 - (freq as f64).ln() / caches.log_max_freq
            })
            .sum();
        (sum / ctx.path.len() as f64).clamp(0.0, 1.0)
    }

    fn explain(&self, value: f64, _ctx: &PathContext<'_>) -> Option<String> {
        (value > 0.7).then(|| {
            format!(
                "High entity rarity ({value:.2}) — these nodes are uncommon in the ingested data."
            )
        })
    }
}

// ── Edge Rarity ─────────────────────────────────────────────────────

/// `EdgeR(s,d) = 1 - ln(freq(s,d)) / ln(max_pair_freq)`, averaged over
/// path edges. Captures "how unusual are these specific transitions".
pub struct EdgeRarity;

impl ScoreComponent for EdgeRarity {
    fn name(&self) -> &'static str {
        "edge_rarity"
    }

    fn score_path(&self, ctx: &PathContext<'_>) -> f64 {
        let path = ctx.path;
        let caches = ctx.caches;
        if path.len() <= 1 || caches.log_max_pair_freq <= 0.0 {
            return 0.0;
        }
        let edge_count = path.len() - 1;
        let sum: f64 = (0..edge_count)
            .map(|i| {
                let pair = (path[i].clone(), path[i + 1].clone());
                let freq = caches.pair_freq.get(&pair).copied().unwrap_or(1);
                1.0 - (freq as f64).ln() / caches.log_max_pair_freq
            })
            .sum();
        (sum / edge_count as f64).clamp(0.0, 1.0)
    }

    fn explain(&self, value: f64, _ctx: &PathContext<'_>) -> Option<String> {
        (value > 0.7).then(|| {
            format!(
                "High edge rarity ({value:.2}) — these transitions are uncommon in the ingested data."
            )
        })
    }
}

// ── Neighborhood Concentration ──────────────────────────────────────

/// Per-node neighborhood concentration (precomputed at finalize time),
/// averaged over the path. High concentration = most neighbors share
/// an entity type, which is often structural centrality rather than
/// novelty.
pub struct NeighborhoodConcentration;

impl ScoreComponent for NeighborhoodConcentration {
    fn name(&self) -> &'static str {
        "neighborhood_concentration"
    }

    fn score_path(&self, ctx: &PathContext<'_>) -> f64 {
        if ctx.path.is_empty() {
            return 0.0;
        }
        let sum: f64 = ctx
            .path
            .iter()
            .map(|id| ctx.caches.nc_cache.get(id).copied().unwrap_or(1.0))
            .sum();
        (sum / ctx.path.len() as f64).clamp(0.0, 1.0)
    }
}

// ── Temporal Novelty ────────────────────────────────────────────────

/// `TN(v) = (τ_first(v) - τ_min) / (τ_max - τ_min)`, averaged over path
/// nodes. Low TN means "this node was around from the beginning" —
/// useful for separating structural centrality from genuine anomaly
/// (see the narrative in `crate::analytics::build_narrative`).
pub struct TemporalNovelty;

impl ScoreComponent for TemporalNovelty {
    fn name(&self) -> &'static str {
        "temporal_novelty"
    }

    fn score_path(&self, ctx: &PathContext<'_>) -> f64 {
        let caches = ctx.caches;
        if ctx.path.is_empty() || caches.tau_max <= caches.tau_min {
            return 0.0;
        }
        let range = (caches.tau_max - caches.tau_min) as f64;
        let sum: f64 = ctx
            .path
            .iter()
            .map(|id| {
                let ts = caches.first_seen.get(id).copied().unwrap_or(caches.tau_min);
                let ts = if ts > 0 { ts } else { caches.tau_min };
                (ts - caches.tau_min) as f64 / range
            })
            .sum();
        (sum / ctx.path.len() as f64).clamp(0.0, 1.0)
    }
}

// ── GNN Threat ──────────────────────────────────────────────────────

/// GNN threat score averaged over path nodes. Returns 0.0 when no
/// GNN scores are loaded, which is the common case for clean
/// environments without an ONNX model.
pub struct GnnThreat;

impl ScoreComponent for GnnThreat {
    fn name(&self) -> &'static str {
        "gnn_threat"
    }

    fn score_path(&self, ctx: &PathContext<'_>) -> f64 {
        let caches = ctx.caches;
        if ctx.path.is_empty() || caches.gnn_cache.is_empty() {
            return 0.0;
        }
        let sum: f64 = ctx
            .path
            .iter()
            .map(|id| caches.gnn_cache.get(id).copied().unwrap_or(0.0))
            .sum();
        (sum / ctx.path.len() as f64).clamp(0.0, 1.0)
    }

    fn explain(&self, value: f64, _ctx: &PathContext<'_>) -> Option<String> {
        (value > 0.5).then(|| {
            format!("GNN model flagged these nodes as likely threat ({value:.2} averaged).")
        })
    }
}
