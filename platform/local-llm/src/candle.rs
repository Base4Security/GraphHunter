//! Candle-backed local LLM. Phi-3-mini-4k-instruct Q4_K_M, CPU-only.
//!
//! The `.gguf` checkpoint is loaded lazily on the first `infer` call
//! and held in a Mutex thereafter — `ModelWeights` is `Send` but not
//! `Sync`, and the `LocalLlm` trait requires both. Lazy load avoids a
//! ~5s startup cost for users who never invoke the agentic refinement
//! path; the trade-off is that the first call pays it.
//!
//! The chat template is Phi-3's official one:
//! `<|user|>\n{prompt}<|end|>\n<|assistant|>\n`. Generation stops on
//! `<|end|>` (32007) or `<|endoftext|>` (32000) — checking only the
//! latter (as the candle example does) leaks template tokens into the
//! response.
//!
//! Sampling defaults: top-k=40, top-p=0.9, temperature=0.7. These are
//! the values the candle-examples/quantized-phi3 sample uses and that
//! the Phi-3 paper reports as reasonable for chat. The
//! `infer_constrained` path (wired in the next milestone) replaces the
//! sampling step with a logit-mask-then-sample driven by the xgrammar
//! state machine.

use std::path::PathBuf;
use std::sync::Mutex;

use candle_core::{Device, Tensor, quantized::gguf_file};
use candle_transformers::generation::{LogitsProcessor, Sampling};
use candle_transformers::models::quantized_phi3::ModelWeights;
use tokenizers::Tokenizer;

use super::{LocalLlm, LocalLlmError, LocalLlmResult, LogitsMasker, PromptSpec};

const MAX_OUTPUT_TOKENS_HARD_CAP: usize = 1024;
const SAMPLING_SEED: u64 = 42;
const TOP_K: usize = 40;
const TOP_P: f64 = 0.9;
const TEMPERATURE: f64 = 0.7;

/// Phi-3 stop tokens. Both must be checked: `<|end|>` closes the
/// assistant turn, `<|endoftext|>` closes the document.
const STOP_TOKEN_END: u32 = 32007;
const STOP_TOKEN_ENDOFTEXT: u32 = 32000;

struct LoadedModel {
    weights: ModelWeights,
    tokenizer: Tokenizer,
}

pub struct CandleBackend {
    model_path: PathBuf,
    tokenizer_path: PathBuf,
    loaded: Mutex<Option<LoadedModel>>,
}

impl CandleBackend {
    /// Lazy constructor — does NOT load the model. The first `infer`
    /// call does. Constructor only verifies that both files exist on
    /// disk so a typo in `GRAPHHUNTER_LOCAL_MODEL_PATH` fails fast at
    /// `default_backend()` rather than mid-inference.
    ///
    /// `model_path` points at the `.gguf` weights. The tokenizer is
    /// expected at `<model_dir>/tokenizer.json` unless the
    /// `GRAPHHUNTER_LOCAL_TOKENIZER_PATH` env var overrides it — Phi-3
    /// GGUF files don't bundle the HF tokenizer, so it has to live
    /// next to them.
    pub fn lazy(model_path: PathBuf) -> LocalLlmResult<Self> {
        if !model_path.exists() {
            return Err(LocalLlmError::BackendUnavailable(format!(
                "model path does not exist: {}",
                model_path.display()
            )));
        }
        let tokenizer_path = resolve_tokenizer_path(&model_path);
        if !tokenizer_path.exists() {
            return Err(LocalLlmError::BackendUnavailable(format!(
                "tokenizer.json not found alongside model (expected at {}); set GRAPHHUNTER_LOCAL_TOKENIZER_PATH to override",
                tokenizer_path.display()
            )));
        }
        Ok(Self {
            model_path,
            tokenizer_path,
            loaded: Mutex::new(None),
        })
    }

    fn ensure_loaded<'a>(
        &'a self,
        slot: &'a mut Option<LoadedModel>,
    ) -> LocalLlmResult<&'a mut LoadedModel> {
        if slot.is_none() {
            tracing::info!(
                target: "graph_hunter_local_llm",
                model = %self.model_path.display(),
                "loading candle Phi-3 GGUF weights (first inference)"
            );
            let device = Device::Cpu;
            let mut file = std::fs::File::open(&self.model_path)
                .map_err(|e| LocalLlmError::InferenceFailed(format!("open gguf: {e}")))?;
            let content = gguf_file::Content::read(&mut file)
                .map_err(|e| LocalLlmError::InferenceFailed(format!("read gguf header: {e}")))?;
            let weights = ModelWeights::from_gguf(false, content, &mut file, &device)
                .map_err(|e| LocalLlmError::InferenceFailed(format!("load gguf weights: {e}")))?;
            let tokenizer = Tokenizer::from_file(&self.tokenizer_path)
                .map_err(|e| LocalLlmError::InferenceFailed(format!("load tokenizer: {e}")))?;
            *slot = Some(LoadedModel { weights, tokenizer });
        }
        Ok(slot.as_mut().expect("just inserted"))
    }
}

impl LocalLlm for CandleBackend {
    fn infer(&self, spec: &PromptSpec) -> LocalLlmResult<String> {
        let mut guard = self
            .loaded
            .lock()
            .map_err(|_| LocalLlmError::InferenceFailed("model mutex poisoned".into()))?;
        let LoadedModel { weights, tokenizer } = self.ensure_loaded(&mut guard)?;
        let device = Device::Cpu;

        let templated = phi3_chat_template(&spec.prompt);
        let encoding = tokenizer
            .encode(templated.as_str(), true)
            .map_err(|e| LocalLlmError::InferenceFailed(format!("tokenize: {e}")))?;
        let prompt_ids: Vec<u32> = encoding.get_ids().to_vec();

        let max_new = spec.max_output_tokens.clamp(1, MAX_OUTPUT_TOKENS_HARD_CAP);

        let mut sampler = LogitsProcessor::from_sampling(
            SAMPLING_SEED,
            Sampling::TopKThenTopP {
                k: TOP_K,
                p: TOP_P,
                temperature: TEMPERATURE,
            },
        );

        // Prefill: forward the full prompt and sample the first new token.
        let mut next = {
            let input = Tensor::new(prompt_ids.as_slice(), &device)
                .and_then(|t| t.unsqueeze(0))
                .map_err(|e| LocalLlmError::InferenceFailed(format!("prefill tensor: {e}")))?;
            let logits = weights
                .forward(&input, 0)
                .and_then(|l| l.squeeze(0))
                .map_err(|e| LocalLlmError::InferenceFailed(format!("prefill forward: {e}")))?;
            sampler
                .sample(&logits)
                .map_err(|e| LocalLlmError::InferenceFailed(format!("prefill sample: {e}")))?
        };

        let mut generated: Vec<u32> = Vec::with_capacity(max_new);
        for step in 0..max_new {
            if next == STOP_TOKEN_END || next == STOP_TOKEN_ENDOFTEXT {
                break;
            }
            generated.push(next);
            let input = Tensor::new(&[next], &device)
                .and_then(|t| t.unsqueeze(0))
                .map_err(|e| LocalLlmError::InferenceFailed(format!("step tensor: {e}")))?;
            let logits = weights
                .forward(&input, prompt_ids.len() + step)
                .and_then(|l| l.squeeze(0))
                .map_err(|e| LocalLlmError::InferenceFailed(format!("step forward: {e}")))?;
            next = sampler
                .sample(&logits)
                .map_err(|e| LocalLlmError::InferenceFailed(format!("step sample: {e}")))?;
        }

        let text = tokenizer
            .decode(&generated, true)
            .map_err(|e| LocalLlmError::InferenceFailed(format!("decode: {e}")))?;
        Ok(text)
    }

    fn backend_id(&self) -> &'static str {
        "candle-phi3-q4"
    }

    /// Same prefill + decode loop as [`Self::infer`], but with
    /// per-step logit masking and parser advancement driven by
    /// `masker`. The masker can stop generation early via
    /// `is_stopped`; otherwise the existing Phi-3 stop tokens and
    /// `max_output_tokens` cap apply.
    fn infer_constrained(
        &self,
        spec: &PromptSpec,
        masker: &mut dyn LogitsMasker,
    ) -> LocalLlmResult<String> {
        let mut guard = self
            .loaded
            .lock()
            .map_err(|_| LocalLlmError::InferenceFailed("model mutex poisoned".into()))?;
        let LoadedModel { weights, tokenizer } = self.ensure_loaded(&mut guard)?;
        let device = Device::Cpu;

        let templated = phi3_chat_template(&spec.prompt);
        let encoding = tokenizer
            .encode(templated.as_str(), true)
            .map_err(|e| LocalLlmError::InferenceFailed(format!("tokenize: {e}")))?;
        let prompt_ids: Vec<u32> = encoding.get_ids().to_vec();

        let max_new = spec.max_output_tokens.clamp(1, MAX_OUTPUT_TOKENS_HARD_CAP);

        let mut sampler = LogitsProcessor::from_sampling(
            SAMPLING_SEED,
            Sampling::TopKThenTopP {
                k: TOP_K,
                p: TOP_P,
                temperature: TEMPERATURE,
            },
        );

        // Prefill: forward the full prompt, mask, sample first new token,
        // advance the masker.
        let mut next = {
            let input = Tensor::new(prompt_ids.as_slice(), &device)
                .and_then(|t| t.unsqueeze(0))
                .map_err(|e| LocalLlmError::InferenceFailed(format!("prefill tensor: {e}")))?;
            let logits = weights
                .forward(&input, 0)
                .and_then(|l| l.squeeze(0))
                .map_err(|e| LocalLlmError::InferenceFailed(format!("prefill forward: {e}")))?;
            mask_and_sample(&logits, &device, &mut sampler, masker, "prefill")?
        };
        masker
            .consume(next)
            .map_err(|e| LocalLlmError::InferenceFailed(format!("consume prefill: {e}")))?;

        let mut generated: Vec<u32> = Vec::with_capacity(max_new);
        for step in 0..max_new {
            if next == STOP_TOKEN_END || next == STOP_TOKEN_ENDOFTEXT || masker.is_stopped() {
                break;
            }
            generated.push(next);
            let input = Tensor::new(&[next], &device)
                .and_then(|t| t.unsqueeze(0))
                .map_err(|e| LocalLlmError::InferenceFailed(format!("step tensor: {e}")))?;
            let logits = weights
                .forward(&input, prompt_ids.len() + step)
                .and_then(|l| l.squeeze(0))
                .map_err(|e| LocalLlmError::InferenceFailed(format!("step forward: {e}")))?;
            next = mask_and_sample(&logits, &device, &mut sampler, masker, "step")?;
            masker
                .consume(next)
                .map_err(|e| LocalLlmError::InferenceFailed(format!("consume step: {e}")))?;
        }

        let text = tokenizer
            .decode(&generated, true)
            .map_err(|e| LocalLlmError::InferenceFailed(format!("decode: {e}")))?;
        Ok(text)
    }
}

/// Materialize logits to a `Vec<f32>`, let the masker write `-inf`
/// over disallowed token ids, wrap back into a tensor, and sample.
/// Factored out so the prefill and per-step paths in
/// [`CandleBackend::infer_constrained`] don't duplicate the dance.
fn mask_and_sample(
    logits_tensor: &Tensor,
    device: &Device,
    sampler: &mut LogitsProcessor,
    masker: &mut dyn LogitsMasker,
    stage: &'static str,
) -> LocalLlmResult<u32> {
    let mut logits_vec: Vec<f32> = logits_tensor
        .to_vec1()
        .map_err(|e| LocalLlmError::InferenceFailed(format!("{stage} to_vec: {e}")))?;
    masker
        .mask_logits(&mut logits_vec)
        .map_err(|e| LocalLlmError::InferenceFailed(format!("{stage} mask_logits: {e}")))?;
    let masked = Tensor::new(logits_vec.as_slice(), device)
        .map_err(|e| LocalLlmError::InferenceFailed(format!("{stage} masked tensor: {e}")))?;
    sampler
        .sample(&masked)
        .map_err(|e| LocalLlmError::InferenceFailed(format!("{stage} sample: {e}")))
}

// `resolve_tokenizer_path` lives in `crate::lib` so the dispatcher can
// reuse it without the `candle` feature compiled in. Re-exported here
// as a local alias for backwards-compatible call sites in this file.
use super::resolve_tokenizer_path;

fn phi3_chat_template(user_prompt: &str) -> String {
    format!("<|user|>\n{user_prompt}<|end|>\n<|assistant|>\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PromptTemplate;

    #[test]
    fn lazy_returns_unavailable_when_model_missing() {
        let res = CandleBackend::lazy(PathBuf::from("/nonexistent/phi3.gguf"));
        match res {
            Err(LocalLlmError::BackendUnavailable(msg)) => {
                assert!(msg.contains("model path does not exist"), "got: {msg}");
            }
            Err(other) => panic!("expected BackendUnavailable, got {other}"),
            Ok(_) => panic!("expected BackendUnavailable, got Ok(_)"),
        }
    }

    #[test]
    fn chat_template_wraps_prompt_with_phi3_tags() {
        let templated = phi3_chat_template("classify this");
        assert!(templated.starts_with("<|user|>\n"));
        assert!(templated.contains("classify this"));
        assert!(templated.ends_with("<|assistant|>\n"));
    }

    /// Smoke test that loads the real model. Ignored by default —
    /// requires the 2.2 GB Phi-3 GGUF on disk and a couple of seconds
    /// of CPU time. Run with:
    ///
    ///   GRAPHHUNTER_LOCAL_MODEL_PATH=/abs/path/to/phi-3-mini-q4.gguf \
    ///   cargo test -p graph_hunter_local_llm --features candle \
    ///       -- --ignored candle_smoke
    #[test]
    #[ignore]
    fn candle_smoke_real_model() {
        let path = std::env::var("GRAPHHUNTER_LOCAL_MODEL_PATH")
            .expect("set GRAPHHUNTER_LOCAL_MODEL_PATH for the smoke test");
        let backend = CandleBackend::lazy(PathBuf::from(path)).expect("backend init");
        let spec = PromptSpec {
            template: PromptTemplate::CanonicalMap,
            prompt: "Reply with the single word OK.".into(),
            max_output_tokens: 16,
        };
        let out = backend.infer(&spec).expect("infer");
        assert!(!out.trim().is_empty(), "model returned empty string");
        assert!(
            out.len() < 2000,
            "model produced unexpectedly long output: {} chars",
            out.len()
        );
    }
}
