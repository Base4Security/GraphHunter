//! DTOs for Sigma rule generation from a Hypothesis DSL + IoC set.

use crate::state::SessionHandle;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveHypothesisAsSigmaRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub hypothesis_dsl: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaRuleResponse {
    pub yaml: String,
    pub title: String,
    /// True when every step was recognized and mapped to a known Sigma
    /// logsource; false when some step fell through to a placeholder
    /// comment — the analyst needs to finish it manually.
    pub fully_mapped: bool,
}
