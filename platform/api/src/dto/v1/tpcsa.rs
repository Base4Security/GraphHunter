//! DTOs for attack-chain reconstruction (TPCSA): exporting the loaded
//! graph as a solver instance and reconstructing chains from seeds.
//!
//! Times inside the exported instance and the returned trees are in
//! **microseconds** (`time_unit = "us"`); the `window` filter is in the
//! engine's edge unit (seconds), because that is what every other
//! endpoint takes.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::state::SessionHandle;
pub use graph_hunter_tpcsa::{Instance, Problem, PruneStats, RejectedTree, TreeReport};

/// A detection to explain: a node with a prize in `[0, 10]` and,
/// optionally, the ATT&CK tactic of the template that produced it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TpcsaSeed {
    pub node: String,
    /// `10 · P(attack)` from a calibrated scorer, or a flat value when only
    /// a template match is known. Clamped to `[0, 10]`; `0` is ignored.
    #[serde(default = "default_prize")]
    pub prize: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tactic: Option<String>,
}

fn default_prize() -> f64 {
    10.0
}

/// Inclusive edge-timestamp window in engine seconds.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct TpcsaWindow {
    pub from: i64,
    pub to: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExportTpcsaInstanceRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    #[serde(default)]
    pub seeds: Vec<TpcsaSeed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<TpcsaWindow>,
    /// Resolution separating cause from effect. Default 1 ms (EDR); use
    /// 1000 for SIEM sources stamped to the second.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epsilon_ms: Option<f64>,
    /// When set, every entity whose `score` is at least this value also
    /// becomes a terminal with prize `10 · score / max_score`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score_threshold: Option<f64>,
    /// Rarity cost spread (default 3). Only the order matters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kappa: Option<f64>,
    /// Entry cost of a public IP (default 2) and of a process/user (default 6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ip_root_cost: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_root_cost: Option<f64>,
    /// Refuse to export more arcs than this (guards the interactive path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_arcs: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ExportStats {
    pub nodes: usize,
    pub arcs: usize,
    pub terminals: usize,
    pub root_candidates: usize,
    /// Arcs whose stored direction was reversed to causal flow (reads and
    /// loads stored as process→file).
    pub flipped_arcs: usize,
    /// Edges outside the window or without resolvable endpoints.
    pub skipped_edges: usize,
    /// Seeds that name no entity in the graph.
    pub unknown_seeds: Vec<String>,
    pub etype_costs: BTreeMap<String, f64>,
    pub time_unit: String,
    pub epsilon: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportTpcsaInstanceResponse {
    pub instance: Instance,
    pub stats: ExportStats,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReconstructChainRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    #[serde(default)]
    pub seeds: Vec<TpcsaSeed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<TpcsaWindow>,
    /// Maximum number of entry points (trees). Default 2 — with 1 the
    /// second implant disappears.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub k: Option<usize>,
    /// Optional cap on arcs per tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<usize>,
    /// Ask the certification sidecar for an optimality certificate.
    /// Honoured by the HTTP/MCP transports; the core operation returns
    /// `certificate = null` and the instance so the transport can call out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certify: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epsilon_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score_threshold: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kappa: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_roots: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_arcs: Option<usize>,
    /// Return the full exported instance alongside the trees (large).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_instance: Option<bool>,
    /// Sidecar time limit in seconds (default 120) and relative MIP gap
    /// (default 0.005) when `certify` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certify_time_limit_s: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certify_gap: Option<f64>,
}

impl ReconstructChainRequest {
    pub fn export_request(&self) -> ExportTpcsaInstanceRequest {
        ExportTpcsaInstanceRequest {
            session: self.session.clone(),
            seeds: self.seeds.clone(),
            window: self.window,
            epsilon_ms: self.epsilon_ms,
            score_threshold: self.score_threshold,
            kappa: self.kappa,
            external_ip_root_cost: None,
            process_root_cost: None,
            max_arcs: self.max_arcs,
        }
    }
}

/// Outcome of the MILP audit. `status` is shown verbatim: `Optimal`,
/// `TimeLimit` (with `gap`), `Infeasible`, `InvalidNumerics` (never
/// present its solution), `TooLarge`, `Unavailable`, `Error`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Certificate {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objective: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dual_bound: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gap: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub solve_seconds: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Greedy objective the certificate is compared against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub greedy_objective: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructChainResponse {
    /// Already ranked: by tactic coverage, then prize/cost. Never by prize alone.
    pub trees: Vec<TreeReport>,
    /// Pairs of ranks whose net gain is within 1 %: show before tree 1.
    pub ties: Vec<(usize, usize)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<Certificate>,
    pub pruning: PruneStats,
    /// Paper-convention forest objective (`Σ cost + Σ dropped prize`).
    pub objective: f64,
    pub total_prize: f64,
    /// Trees the greedy produced but verification rejected (never shown as results).
    pub rejected: Vec<RejectedTree>,
    pub export: ExportStats,
    /// Full instance, only when `include_instance` was requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<Instance>,
    /// The temporally pruned instance the trees were built on, only when
    /// `certify` was requested: it is what the sidecar needs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pruned_instance: Option<Instance>,
}
