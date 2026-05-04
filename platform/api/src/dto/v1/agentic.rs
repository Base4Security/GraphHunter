//! DTOs for the six M4 agentic slow-lane operations and the
//! mapping-review queue that gates promotion of LLM-emitted artefacts.
//!
//! The shape principle: every `*Response` that carries a draft
//! includes a `draft_id` so the analyst (or an LLM caller) can refer
//! back to it via `agentic_review_queue.approve(draft_id)`. Drafts
//! are immutable after creation; approvals stamp them onto the active
//! mapping; rejections persist with a reason for audit.

use graph_hunter_core::field_preview::FieldConfig;
use serde::{Deserialize, Serialize};

use crate::state::SessionHandle;

// ── ingest_negotiator ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestNegotiateRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    /// If supplied, the negotiator scopes its proposal to this dataset
    /// (replays its prior FieldConfig as a starting point). Optional —
    /// for cold proposals the negotiator only needs `raw_sample`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_id: Option<String>,
    /// A small slice of raw events (typically the first 50–200 rows)
    /// the negotiator inspects. Bounded by callers.
    pub raw_sample: String,
    /// Format hint passed through to `auto_field_config_for`. When
    /// omitted, the negotiator falls back to format auto-detection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint_format: Option<String>,
    /// Soft cap on negotiation rounds. Currently advisory — a single
    /// pass is enough until M6 lands constrained decoding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_rounds: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestNegotiateResponse {
    pub draft_id: String,
    pub proposed_field_config: FieldConfig,
    pub rationale: String,
    /// `0.0..=1.0` — set to the underlying heuristic's confidence
    /// when the LLM didn't refine, or to a blended score otherwise.
    pub confidence: f32,
    /// Mapping-library matches for the proposed FieldConfig's shape.
    /// Callers (UI or orchestration) can surface these to the analyst
    /// as "reuse an approved mapping" suggestions. Empty when the
    /// library is unconfigured, empty, or nothing matches above the
    /// minimum-score threshold.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub similar_mappings: Vec<SimilarMapping>,
}

/// Library hit surfaced on top of a negotiator proposal. Omits the
/// full FieldConfig to keep responses small — the analyst can fetch
/// the full entry via its `mapping_id` when publish/consume lands
/// in M7.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarMapping {
    pub mapping_id: String,
    pub fingerprint: String,
    pub score: f32,
    pub exact: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapping_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ocsf_category: Option<String>,
    pub source: String,
    pub published_at: i64,
}

// ── canonical_mapper ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalMapRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub field_config: FieldConfig,
    /// Optional pin: if set, the mapper checks whether the FieldConfig
    /// can plausibly project to this OCSF category instead of choosing
    /// from the catalog.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ocsf_category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalMapResponse {
    pub ocsf_category: String,
    /// Provenance template values that downstream calls (parser_generator,
    /// export_ocsf) will stamp onto every event.
    pub provenance_template: ProvenanceTemplate,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceTemplate {
    pub mapping_id: String,
    pub mapping_version: u32,
    pub mapping_hash: String,
    pub parser_name: String,
}

// ── parser_generator ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParserGenerateRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub field_config: FieldConfig,
    /// Optional OCSF target — passed through verbatim into the
    /// resulting program's provenance template.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ocsf_category: Option<String>,
    /// `"speed"` keeps the deterministic compiler output as-is;
    /// `"fidelity"` allows the LLM to propose refinements (still
    /// gated by the review queue and constrained decoding in M6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optimization_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParserGenerateResponse {
    pub draft_id: String,
    pub vrl_source: String,
    pub mapping_hash: String,
    pub mapping_version: u32,
    /// OCSF schema fields the generated VRL is expected to populate;
    /// the regression tester uses this as the diffing universe.
    pub expected_ocsf_fields: Vec<String>,
}

// ── schema_drift_detector ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaDriftRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub dataset_id: String,
    /// Aggregation window in seconds. Defaults to 3600 (1h) when
    /// omitted — matches the Prometheus rollup window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_secs: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaDriftResponse {
    /// `0.0..=1.0` aggregate drift signal. Computed from the per-field
    /// type-tag KL divergence and null-rate EWMA in the drift store.
    pub drift_score: f32,
    pub drifted_fields: Vec<DriftedField>,
    /// `"none" | "review" | "renegotiate"` — gate for whether the
    /// analyst should re-run `ingest_negotiator`.
    pub recommended_action: String,
    /// FieldConfig mapping names that touch any drifted field — these
    /// are the ones that would need re-emission of VRL.
    pub affected_mappings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftedField {
    pub field: String,
    pub kl_divergence: f32,
    pub null_rate: f32,
    /// Short human-readable hint for the UI.
    pub note: String,
}

// ── mapping_regression_tester ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingRegressionRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub candidate_vrl: String,
    pub baseline_dataset_id: String,
    /// Cap on rows to replay. Defaults to 1000 when omitted to keep
    /// the test fast even on very large datasets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_size: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingRegressionResponse {
    pub canary_report_id: String,
    pub triple_diff: TripleDiff,
    pub ocsf_diff: OcsfDiff,
    pub invariant_delta: InvariantDelta,
    /// `"pass" | "warn" | "fail"`. Drives review-queue gating.
    pub verdict: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TripleDiff {
    pub baseline_count: usize,
    pub candidate_count: usize,
    pub jaccard: f32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OcsfDiff {
    pub baseline_count: usize,
    pub candidate_count: usize,
    /// OCSF field names present in baseline but missing from candidate.
    pub missing_fields: Vec<String>,
    /// Fields present in candidate but absent from baseline.
    pub added_fields: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InvariantDelta {
    /// Predicate name → (baseline_violations, candidate_violations).
    pub per_predicate: Vec<(String, usize, usize)>,
}

// ── invariant_checker (hypothetical-VRL extension; concrete check
//    lives at /invariants/check, M2) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantHypotheticalRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    /// When supplied, the checker replays the dataset's raw events
    /// through this VRL instead of reading the live graph.
    pub hypothetical_vrl: String,
    pub dataset_id: String,
    /// Optional sample cap — defaults to 1000 to keep the round trip
    /// cheap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_size: Option<usize>,
}

// ── Review queue ─────────────────────────────────────────────────────

/// All drafts the agentic ops produce land here. Persistence is
/// in-memory for M4.b — promotion to disk happens alongside the rest
/// of M5/M7's mapping library work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingDraft {
    pub draft_id: String,
    pub source: DraftSource,
    pub created_at: i64,
    pub status: DraftStatus,
    pub field_config: Option<FieldConfig>,
    pub vrl_source: Option<String>,
    pub mapping_hash: Option<String>,
    pub rationale: String,
    pub backend_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftSource {
    IngestNegotiator,
    ParserGenerator,
    CanonicalMapper,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftStatus {
    Pending,
    Approved { at: i64 },
    Rejected { at: i64, reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDraftsRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    /// When false, only `Pending` drafts are returned. Defaults to
    /// false so reviewers see only actionable rows.
    #[serde(default)]
    pub include_resolved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDraftsResponse {
    pub drafts: Vec<MappingDraft>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveDraftRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub draft_id: String,
    /// Required when rejecting; ignored on approve. The `Option`
    /// keeps a single DTO usable for both ops.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveDraftResponse {
    pub draft: MappingDraft,
    /// Set on approve when the draft promoted a FieldConfig to the
    /// dataset; `None` when the draft only carried a VRL artefact
    /// (those bind to the dataset via `mapping_hash` provenance,
    /// not by replacing the FieldConfig).
    pub promoted_dataset_id: Option<String>,
}
