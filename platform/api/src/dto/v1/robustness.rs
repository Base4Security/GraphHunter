//! DTOs for attribution robustness: how many records (λ) and how many
//! failure domains (ρ) an attribution can lose before no match is left.

use serde::{Deserialize, Serialize};

use graph_hunter_core::robustness::{AttributionRobustness, RobustnessOptions};

use crate::state::SessionHandle;

/// Pairs evaluated when the request names none and the hunt returns more.
pub const DEFAULT_MAX_PAIRS: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AttributionRobustnessRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    /// A chain hypothesis in the hunt DSL.
    pub hypothesis_dsl: String,
    /// Endpoints of one attribution. Without them the hypothesis is hunted
    /// and every distinct (first, last) pair of its matches is evaluated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default)]
    pub options: RobustnessOptions,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_pairs: Option<usize>,
}

/// Counts over the evaluated pairs, with their denominator.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct RobustnessSummary {
    /// Pairs evaluated.
    pub pairs: usize,
    /// Pairs whose attribution holds with all evidence present.
    pub holding: usize,
    /// Holding pairs whose λ is exact (no record spans two steps).
    pub lambda_exact: usize,
    /// Holding pairs with exact λ ≥ 2.
    pub lambda_at_least_2: usize,
    /// Holding pairs that one failure domain breaks (ρ = 1).
    pub rho_1: usize,
    /// Holding pairs with exact λ ≥ 2 and ρ = 1: redundancy a single domain
    /// takes away.
    pub gap: usize,
    /// Pairs whose ρ stayed a range (too many domains to enumerate).
    pub rho_unresolved: usize,
    /// The hunt had more pairs than `max_pairs`; the counts cover the first
    /// ones only.
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AttributionRobustnessResponse {
    pub summary: RobustnessSummary,
    pub pairs: Vec<AttributionRobustness>,
}
