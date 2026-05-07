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
//! `candle` module; [`default_backend`] picks it via
//! [`resolve_model_path`], which checks the `GRAPHHUNTER_LOCAL_MODEL_PATH`
//! override first, then well-known bundled locations next to the
//! executable, then a `target/models` dev-tree fallback. Only when
//! none of those resolve does it fall back to the mock.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

/// Filename of the GGUF checkpoint shipped with the desktop and CLI
/// binaries. Mirrored by `scripts/download-model.sh` (which writes
/// the same name into `target/models/` and the Tauri resources dir
/// during build).
pub const MODEL_FILENAME: &str = "Phi-3-mini-4k-instruct-q4.gguf";

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

/// Driver for prefix-constrained decoding. Defined here in `local-llm`
/// rather than in `constrained-decode` so [`LocalLlm::infer_constrained`]
/// can take it as a trait object without `local-llm` depending on
/// `constrained-decode`'s heavy llguidance / toktrie deps (or its
/// `tokenizers` 0.21 vs candle-transformers' 0.23 version skew).
///
/// The bridge impl lives in `graph_hunter_constrained_decode` under
/// its `xgrammar` feature, where `ConstrainedSampler` is adapted to
/// this shape. Errors are reported as `String` to keep the API free of
/// constrained-decode's `SamplerError` type.
pub trait LogitsMasker: Send {
    /// Set `logits[i] = -inf` for every token id that the grammar
    /// disallows at the current prefix. After this call returns,
    /// sampling from `logits` is constrained-by-construction.
    fn mask_logits(&mut self, logits: &mut [f32]) -> Result<(), String>;
    /// Advance the parser state by the just-sampled token.
    fn consume(&mut self, token_id: u32) -> Result<(), String>;
    /// True once the matcher has reached an accepting state and no
    /// further tokens are required (end-of-grammar).
    fn is_stopped(&self) -> bool;
}

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

    /// Constrained-decode variant: at every token, the `masker` is
    /// consulted to mask out grammar-illegal token ids before sampling
    /// and is advanced after. Default impl returns `BackendUnavailable`
    /// so the mock backend (and any future non-candle backend) compiles
    /// without implementing the constrained path.
    fn infer_constrained(
        &self,
        _spec: &PromptSpec,
        _masker: &mut dyn LogitsMasker,
    ) -> LocalLlmResult<String> {
        Err(LocalLlmError::BackendUnavailable(format!(
            "{} does not support constrained decode",
            self.backend_id()
        )))
    }
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

/// Resolve where `tokenizer.json` lives next to a given GGUF model
/// path. Mirrors the logic that `CandleBackend::lazy` uses internally,
/// exposed at the crate root so the agentic dispatcher can hand the
/// path to a constrained-decode sampler without needing the candle
/// feature compiled in.
///
/// `GRAPHHUNTER_LOCAL_TOKENIZER_PATH` overrides — same env var the
/// candle backend already reads, so power users only set it once.
pub fn resolve_tokenizer_path(model_path: &std::path::Path) -> PathBuf {
    if let Ok(explicit) = std::env::var("GRAPHHUNTER_LOCAL_TOKENIZER_PATH") {
        return PathBuf::from(explicit);
    }
    let dir = model_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    dir.join("tokenizer.json")
}

/// Resolve the location of the Phi-3 GGUF checkpoint, walking through
/// (1) the manual `GRAPHHUNTER_LOCAL_MODEL_PATH` override, (2)
/// well-known paths next to the running executable (matching how the
/// Tauri bundle and the CLI installer place the model), and (3) a
/// dev-tree `target/models/` walk for `npm run tauri dev`.
///
/// Returns `None` when no bundled model is present — callers should
/// degrade to [`MockBackend`] in that case rather than panic. The
/// override path is returned even if the file is missing so
/// `CandleBackend::lazy` surfaces a precise error to the user.
pub fn resolve_model_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("GRAPHHUNTER_LOCAL_MODEL_PATH") {
        #[cfg(feature = "candle")]
        tracing::debug!(
            target: "graph_hunter_local_llm::resolver",
            "resolve_model_path: env override = {}",
            p
        );
        return Some(PathBuf::from(p));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for candidate in [
                dir.join("resources").join("models").join(MODEL_FILENAME),
                dir.join("models").join(MODEL_FILENAME),
            ] {
                #[cfg(feature = "candle")]
                tracing::debug!(
                    target: "graph_hunter_local_llm::resolver",
                    "resolve_model_path: try exe-relative {} -> {}",
                    candidate.display(),
                    if candidate.is_file() { "HIT" } else { "miss" }
                );
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        #[cfg(feature = "candle")]
        tracing::debug!(
            target: "graph_hunter_local_llm::resolver",
            "resolve_model_path: cwd-walk start at {}",
            cwd.display()
        );
        let mut dir = Some(cwd);
        while let Some(d) = dir {
            let cand = d.join("target").join("models").join(MODEL_FILENAME);
            #[cfg(feature = "candle")]
            tracing::debug!(
                target: "graph_hunter_local_llm::resolver",
                "resolve_model_path: try cwd-walk {} -> {}",
                cand.display(),
                if cand.is_file() { "HIT" } else { "miss" }
            );
            if cand.is_file() {
                return Some(cand);
            }
            dir = d.parent().map(|p| p.to_path_buf());
        }
    }
    #[cfg(feature = "candle")]
    tracing::warn!(
        target: "graph_hunter_local_llm::resolver",
        "resolve_model_path: no checkpoint found in any well-known location"
    );
    None
}

/// Default backend factory. Picks the candle-backed Phi-3 path when
/// the `candle` feature is on AND [`resolve_model_path`] returns a
/// path; falls back to [`MockBackend`] otherwise so unit tests, CI,
/// and headless dev always get a working agentic loop.
///
/// **Process-singleton (Phase H)**: the resolved handle is cached in a
/// `OnceLock` so repeated AI requests reuse the same `CandleBackend`
/// instance — and therefore the same warm `LoadedModel` mutex. Before
/// this cache, every dispatcher invocation rebuilt a fresh backend and
/// reloaded the 2.2 GB GGUF on first inference, multiplying RAM by
/// the call count and adding ~5s per call on a Ryzen 5 PRO 5650U.
/// `LocalLlmHandle` is `Arc<dyn LocalLlm>`, cheap to clone.
pub fn default_backend() -> LocalLlmHandle {
    static BACKEND: std::sync::OnceLock<LocalLlmHandle> = std::sync::OnceLock::new();
    BACKEND.get_or_init(build_default_backend).clone()
}

fn build_default_backend() -> LocalLlmHandle {
    #[cfg(feature = "candle")]
    {
        if let Some(path) = resolve_model_path() {
            match CandleBackend::lazy(path.clone()) {
                Ok(b) => {
                    tracing::info!(
                        target: "graph_hunter_local_llm",
                        "candle backend ready: {}",
                        path.display()
                    );
                    return Arc::new(b);
                }
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
