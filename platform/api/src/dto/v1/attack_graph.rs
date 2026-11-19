//! DTOs for `attack_edges`: the attack edges the projection rule derives
//! from the ingestion journal (`operations::attack_graph`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Request body for `attack_edges`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AttackEdgesRequest {
    /// What the projection resolves names against, in the conformance-file
    /// shape: `{domains: {NETBIOS: dns}, hosts: [fqdn…], system_accounts:
    /// [name…], machine_account_suffix?}`. A BloodHound collection provides
    /// it. Users and hosts it does not know are reported as unresolved,
    /// never guessed.
    #[serde(default)]
    pub identities: Value,
    /// Lifetimes in ms (`session_grace_ms`, `session_ttl_ms`,
    /// `process_ttl_ms`, `permission_ttl_ms`); missing keys keep the spec's
    /// defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    /// Epoch-ms instant at which liveness is judged. Defaults to the latest
    /// event time in the replayed journal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watermark_ms: Option<i64>,
    /// Restrict the replay to one dataset's envelopes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_id: Option<String>,
}

/// One attack edge alive at the watermark.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttackEdgeView {
    pub src: String,
    pub kind: String,
    pub dst: String,
    /// `confirmed` or `inferred`; absent for snapshot-only edges.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// Event ids that sustain the edge.
    pub support: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AttackEdgesResponse {
    pub watermark_ms: i64,
    /// Journal envelopes replayed (after the dataset filter).
    pub envelopes: usize,
    /// Edges alive at the watermark, sorted by `(src, kind, dst)`.
    pub edges: Vec<AttackEdgeView>,
    /// Events the projection could not resolve, counted by reason
    /// (`domain_unknown`, `host_ambiguous`, …).
    pub unresolved: BTreeMap<String, usize>,
}
