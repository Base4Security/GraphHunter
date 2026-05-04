//! Deterministic mock backend.
//!
//! The mock returns a canned response per [`PromptTemplate`]. This is
//! enough to exercise the agentic loop end-to-end in tests without
//! depending on a model checkpoint, and it lets the deterministic-first
//! M4.c paths (which only fall back to the LLM in narrow conditions)
//! reach their fallback branches deterministically.
//!
//! The canned shapes are *plausible-looking JSON* matching what each
//! agentic op expects to receive — not realistic content. Real prompts
//! in production set custom backends; the mock exists so that
//! `cargo test` does not require a 2 GB model file.

use super::{LocalLlm, LocalLlmResult, PromptSpec, PromptTemplate};

#[derive(Default)]
pub struct MockBackend;

impl MockBackend {
    pub fn new() -> Self {
        Self
    }
}

impl LocalLlm for MockBackend {
    fn infer(&self, spec: &PromptSpec) -> LocalLlmResult<String> {
        Ok(canned(spec.template).to_string())
    }
    fn backend_id(&self) -> &'static str {
        "mock"
    }
}

fn canned(t: PromptTemplate) -> &'static str {
    match t {
        // Empty mappings vector — the negotiator wraps the heuristic
        // result and only uses the LLM to refine. A test that wants
        // the LLM to "win" injects a custom backend.
        PromptTemplate::IngestNegotiate => {
            r#"{"mappings":[],"rationale":"mock backend: no refinements","confidence":0.0}"#
        }
        // Default to the catch-all OCSF category. canonical_mapper
        // only consults the LLM to break ties; in tie-free cases this
        // is never reached.
        PromptTemplate::CanonicalMap => {
            r#"{"category":"unknown","confidence":0.0,"rationale":"mock backend"}"#
        }
        // Empty VRL — parser_generator's primary path is the
        // deterministic compiler. The LLM-tweak branch should consider
        // an empty response as "no refinement" and keep the compiler
        // output.
        PromptTemplate::ParserGenerate => r#"{"vrl_source":"","notes":"mock backend"}"#,
        PromptTemplate::DriftExplain => r#"{"summary":"mock backend: no narrative available"}"#,
        PromptTemplate::RegressionSummarize => r#"{"summary":"mock backend: diff not narrated"}"#,
        PromptTemplate::InvariantNarrate => {
            r#"{"summary":"mock backend: invariants not narrated"}"#
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_distinct_canned_response_per_template() {
        let b = MockBackend::new();
        let templates = [
            PromptTemplate::IngestNegotiate,
            PromptTemplate::CanonicalMap,
            PromptTemplate::ParserGenerate,
            PromptTemplate::DriftExplain,
            PromptTemplate::RegressionSummarize,
            PromptTemplate::InvariantNarrate,
        ];
        let mut seen = std::collections::HashSet::new();
        for t in templates {
            let r = b.infer(&PromptSpec::new(t, "ignored")).unwrap();
            assert!(serde_json::from_str::<serde_json::Value>(&r).is_ok());
            seen.insert(r);
        }
        // Six templates → six distinct strings. Catches lazy
        // copy/paste that would silently make two templates collide.
        assert_eq!(seen.len(), 6);
    }

    #[test]
    fn deterministic_across_calls() {
        let b = MockBackend::new();
        let spec = PromptSpec::new(PromptTemplate::IngestNegotiate, "anything");
        let a = b.infer(&spec).unwrap();
        let b2 = b.infer(&spec).unwrap();
        assert_eq!(a, b2);
    }

    #[test]
    fn backend_id_is_mock() {
        assert_eq!(MockBackend::new().backend_id(), "mock");
    }
}
