//! Local-only LLM backend used by the agentic slow lane.
//!
//! Design rule: **no network calls.** The slow lane's auditability story
//! depends on the LLM never having seen a production event. A backend
//! that could quietly fall back to a hosted provider would break that
//! promise. The trait is local-only by construction.
//!
//! [`MockBackend`] returns deterministic canned responses keyed by
//! [`PromptSpec::template`] and keeps CI green without a model on disk.
//! The real Candle backend (Phi-3-mini-Q4 GGUF, CPU-only) lives in the
//! `candle` module; [`default_backend`] picks it when
//! `GRAPHHUNTER_LOCAL_MODEL_PATH` is set and falls back to the mock
//! otherwise.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Identifies the call-site that produced a prompt. The mock backend
/// uses this as a lookup key for canned responses; the candle backend
/// uses it to pick the right prompt template / decoding parameters.
///
/// New variants must be added when a new agentic operation comes online
/// so that mock fixtures stay exhaustive — the mock backend matches on
/// this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PromptTemplate {
    /// `ingest_negotiator` — propose a FieldConfig from raw samples.
    IngestNegotiate,
    /// `canonical_mapper` — pick an OCSF category for a FieldConfig.
    CanonicalMap,
    /// `parser_generator` — emit VRL from a (FieldConfig, OCSF map).
    /// Only invoked when `optimization_hint = "fidelity"`. The
    /// deterministic compiler is the primary path.
    ParserGenerate,
    /// `schema_drift_detector` — explain a drift signal in plain text.
    DriftExplain,
    /// `mapping_regression_tester` — summarize a triple/ocsf diff.
    RegressionSummarize,
    /// `invariant_checker` — narrate which invariants a hypothetical
    /// VRL program would violate.
    InvariantNarrate,
}

impl PromptTemplate {
    pub fn as_str(self) -> &'static str {
        match self {
            PromptTemplate::IngestNegotiate => "ingest_negotiate",
            PromptTemplate::CanonicalMap => "canonical_map",
            PromptTemplate::ParserGenerate => "parser_generate",
            PromptTemplate::DriftExplain => "drift_explain",
            PromptTemplate::RegressionSummarize => "regression_summarize",
            PromptTemplate::InvariantNarrate => "invariant_narrate",
        }
    }
}

/// What we hand a backend. Kept deliberately small: the agentic ops
/// build the full system+user message themselves and pass it as
/// `prompt`; this struct just carries enough metadata for the backend
/// to route, log, and bound the response.
#[derive(Debug, Clone)]
pub struct PromptSpec {
    pub template: PromptTemplate,
    pub prompt: String,
    /// Caller's hint for response length. Backends may clamp.
    pub max_output_tokens: usize,
}

impl PromptSpec {
    pub fn new(template: PromptTemplate, prompt: impl Into<String>) -> Self {
        Self {
            template,
            prompt: prompt.into(),
            max_output_tokens: 2048,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LocalLlmError {
    /// The backend isn't available in this runtime (e.g., the candle
    /// backend feature is off and no model path is set). Callers should
    /// map this to a user-facing "backend_unavailable" MCP response
    /// with an actionable message rather than a panic.
    #[error("backend_unavailable: {0}")]
    BackendUnavailable(String),
    /// Inference failed (model load, tokenizer error, OOM, …).
    #[error("inference_failed: {0}")]
    InferenceFailed(String),
}

pub type LocalLlmResult<T> = Result<T, LocalLlmError>;

/// Local-only LLM backend.
///
/// Implementations must be `Send + Sync`: the agentic operations are
/// invoked from async transport handlers and may hold the trait object
/// across await points.
pub trait LocalLlm: Send + Sync {
    fn infer(&self, spec: &PromptSpec) -> LocalLlmResult<String>;
    /// Stable identifier for telemetry. Doubles as the value stamped
    /// into the agentic draft so reviewers see which backend produced
    /// it.
    fn backend_id(&self) -> &'static str;
}

/// Convenience type-alias: most call-sites take an
/// `Arc<dyn LocalLlm>` so the same backend can be cloned cheaply
/// across the six agentic operations.
pub type LocalLlmHandle = Arc<dyn LocalLlm>;

mod mock;
pub use mock::MockBackend;

#[cfg(feature = "candle")]
mod candle;
#[cfg(feature = "candle")]
pub use candle::CandleBackend;

/// Default backend factory. Picks the candle-backed Phi-3 path when
/// the `candle` feature is on AND `GRAPHHUNTER_LOCAL_MODEL_PATH`
/// points at a `.gguf` file; falls back to [`MockBackend`] otherwise
/// so unit tests, CI, and headless dev always get a working agentic
/// loop.
pub fn default_backend() -> LocalLlmHandle {
    #[cfg(feature = "candle")]
    {
        if let Ok(path) = std::env::var("GRAPHHUNTER_LOCAL_MODEL_PATH") {
            match CandleBackend::lazy(path.into()) {
                Ok(b) => return Arc::new(b),
                Err(e) => {
                    tracing::warn!(
                        target: "graph_hunter_local_llm",
                        "candle backend unavailable, falling back to mock: {}",
                        e
                    );
                }
            }
        }
    }
    Arc::new(MockBackend::new())
}
