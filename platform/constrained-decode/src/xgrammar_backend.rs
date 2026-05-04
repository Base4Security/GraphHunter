//! xgrammar-backed constrained sampler.
//!
//! Wraps llguidance (Microsoft) — the spiritual Rust successor to the
//! original Python xgrammar — so the candle decoder can mask logits
//! against `grammars/vrl_subset.lark` *during* sampling rather than
//! validating after the fact. Used by the agentic ingest path when both
//! the `candle` and `xgrammar` features are on.
//!
//! Why this exists alongside `VrlSubsetValidator`:
//!
//! - The validator is a *post-hoc* gate. It runs once the LLM has
//!   already produced a full string. If the LLM drifts halfway through,
//!   the whole output is wasted.
//! - The constrained sampler is a *generation-time* gate. At every
//!   token the parser tells us which token IDs would keep the prefix
//!   parseable; we mask the rest to `-inf` before sampling. The LLM
//!   physically cannot emit a token that would make the prefix
//!   unparseable. Throughput stays the same, retries go to zero.
//!
//! The two paths share the grammar contract — every Lark production
//! here is also a `VrlSubsetValidator` production, enforced by the
//! `grammar_roundtrip` test. So they cannot disagree without CI saying
//! so.
//!
//! Lifecycle:
//! ```ignore
//! let grammar = std::fs::read_to_string("grammars/vrl_subset.lark")?;
//! let tokenizer = tokenizers::Tokenizer::from_file("tokenizer.json")?;
//! let mut sampler = ConstrainedSampler::from_lark(&grammar, tokenizer)?;
//! loop {
//!     let logits = forward(...);  // [vocab_size]
//!     sampler.mask_logits(&mut logits)?;  // -inf to disallowed
//!     let tok = sample(&logits);
//!     sampler.consume(tok)?;
//!     if sampler.is_stopped() { break; }
//! }
//! ```

use std::sync::Arc;

use llguidance::api::TopLevelGrammar;
use llguidance::toktrie::TokEnv;
use llguidance::{Matcher, ParserFactory};
use thiserror::Error;
use tokenizers::Tokenizer;
use toktrie_hf_tokenizers::{ByteTokenizer, ByteTokenizerEnv};

#[derive(Debug, Error)]
pub enum SamplerError {
    #[error("tokenizer adaptation failed: {0}")]
    Tokenizer(String),
    #[error("grammar compile failed: {0}")]
    Grammar(String),
    #[error("parser create failed: {0}")]
    ParserCreate(String),
    #[error("mask compute failed: {0}")]
    Mask(String),
    #[error("token consume failed: {0}")]
    Consume(String),
}

pub type SamplerResult<T> = Result<T, SamplerError>;

/// One sampler == one generation session. Holds the parser state, so
/// it cannot be reused after `is_stopped()`. Cheap to construct after
/// the first time (`ParserFactory` caches grammar compilations).
pub struct ConstrainedSampler {
    matcher: Matcher,
    /// Held to keep the `TokEnv` alive for the matcher's lifetime.
    /// `Matcher` doesn't own it; we do.
    _tok_env: TokEnv,
}

impl ConstrainedSampler {
    /// Build a sampler for `grammar_lark` over `tokenizer`. The
    /// tokenizer must be the *same* one the model was trained with —
    /// every token-id in the mask is interpreted in that vocabulary.
    pub fn from_lark(grammar_lark: &str, tokenizer: Tokenizer) -> SamplerResult<Self> {
        let bt = ByteTokenizer::from_tokenizer(tokenizer)
            .map_err(|e| SamplerError::Tokenizer(e.to_string()))?;
        let env =
            ByteTokenizerEnv::new(bt, None).map_err(|e| SamplerError::Tokenizer(e.to_string()))?;
        let tok_env: TokEnv = Arc::new(env);

        let factory = ParserFactory::new_simple(&tok_env)
            .map_err(|e| SamplerError::Grammar(e.to_string()))?;
        let grammar = TopLevelGrammar::from_lark(grammar_lark.to_string());
        // Matcher::new takes a Result<TokenParser> — it surfaces parser
        // errors lazily on first compute_mask. We pass the raw Result
        // through and let downstream calls report the cause.
        let parser_res = factory.create_parser(grammar);
        let matcher = Matcher::new(parser_res);

        Ok(Self {
            matcher,
            _tok_env: tok_env,
        })
    }

    /// Set logits[i] = -inf for every token id `i` the grammar
    /// disallows at the current prefix. After calling this, sampling
    /// from `logits` is constrained-by-construction.
    pub fn mask_logits(&mut self, logits: &mut [f32]) -> SamplerResult<()> {
        let mask = self
            .matcher
            .compute_mask()
            .map_err(|e| SamplerError::Mask(e.to_string()))?;
        for (i, l) in logits.iter_mut().enumerate() {
            if !mask.is_allowed(i as u32) {
                *l = f32::NEG_INFINITY;
            }
        }
        Ok(())
    }

    /// Advance parser state by the just-sampled token.
    pub fn consume(&mut self, token_id: u32) -> SamplerResult<()> {
        self.matcher
            .consume_token(token_id)
            .map_err(|e| SamplerError::Consume(e.to_string()))?;
        Ok(())
    }

    /// True once the matcher has reached an accepting state and no
    /// further tokens are required (EOG). Driver loop should break.
    pub fn is_stopped(&self) -> bool {
        self.matcher.is_stopped()
    }

    /// True when the matcher *could* legitimately stop here. The
    /// driver may want to bias toward stopping when this flips.
    /// Returns false on internal error rather than panicking — the
    /// driver still has `is_stopped` and `compute_mask` to make
    /// progress.
    pub fn is_accepting(&mut self) -> bool {
        self.matcher.is_accepting().unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: load the real VRL subset grammar from disk and
    /// adapt a tokenizer. Doesn't require the model checkpoint —
    /// `tokenizer.json` is small (~2 MB) and lives next to the
    /// `.gguf`. Gated `#[ignore]` because it requires an env var.
    ///
    /// Run with:
    ///   GRAPHHUNTER_LOCAL_TOKENIZER_PATH=/abs/path/to/tokenizer.json \
    ///   cargo test -p graph_hunter_constrained_decode \
    ///       --features xgrammar -- --ignored xgrammar_smoke
    #[test]
    #[ignore]
    fn xgrammar_smoke_real_tokenizer() {
        let tok_path = std::env::var("GRAPHHUNTER_LOCAL_TOKENIZER_PATH")
            .expect("set GRAPHHUNTER_LOCAL_TOKENIZER_PATH for the smoke test");
        let tokenizer = Tokenizer::from_file(&tok_path).expect("load tokenizer");
        let grammar = std::fs::read_to_string("grammars/vrl_subset.lark")
            .expect("read grammar — run from crate dir");
        let mut sampler = ConstrainedSampler::from_lark(&grammar, tokenizer).expect("sampler init");

        // Smallest sanity check: at the start of generation, the mask
        // must contain at least one allowed token, and `is_stopped`
        // must be false. If either fails the wiring is broken.
        let logits_len = 32_064; // Phi-3 vocab size.
        let mut logits = vec![0.0f32; logits_len];
        sampler
            .mask_logits(&mut logits)
            .expect("compute initial mask");
        let any_allowed = logits.iter().any(|&l| l.is_finite());
        assert!(any_allowed, "no token allowed at start — grammar is empty?");
        assert!(!sampler.is_stopped(), "sampler stopped before any input");
    }
}
