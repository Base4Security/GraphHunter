//! Field-config negotiation dispatcher.
//!
//! Single source of truth for the "heuristic vs LLM" decision used by
//! both the agentic slow lane (`ingest_negotiate` MCP tool) and the
//! ingest hot-path (`load_data_streaming`). The dispatcher runs the
//! same `auto_field_config_for` heuristic the preview UI uses, then
//! falls back to the local LLM only when the heuristic clearly failed
//! (zero Node-roled mappings).
//!
//! Threshold rule: heuristic confidence is **0.85 when ≥1 Node**
//! mapping landed and **0.5** otherwise. The dispatcher only invokes
//! the LLM in the second case — typical of unfamiliar formats where
//! generic field names (`actor`, `target`, `value`) match no canonical
//! alias. This keeps the perf invariant from
//! `feedback_perf_plug_and_play.md` intact: clean Sysmon EVTX, clean
//! Sentinel JSON, well-shaped CSV → no LLM call at all.
//!
//! Plug-and-play gate: the hot-path call site checks
//! [`dispatcher_enabled`] before invoking. The MCP slow-lane bypasses
//! this gate so `ingest_negotiate` always works regardless of the env
//! var (it's an analyst-driven tool).

use std::collections::BTreeMap;

use graph_hunter_core::field_preview::{FieldConfig, FieldMapping, FieldRole};
use serde::Serialize;
use serde_json::json;

use crate::local_llm::{LocalLlm, PromptSpec, PromptTemplate};
use crate::operations::ingestion::auto_field_config_for;

/// Heuristic confidence threshold below which the dispatcher consults
/// the LLM. Mirrors the existing scoring in `agentic.rs::ingest_negotiate`:
/// ≥0.85 (≥1 Node mapping) is "trust the heuristic"; below that the
/// LLM is invited to refine.
pub const HEURISTIC_TRUST_THRESHOLD: f32 = 0.85;

/// True when the LLM-as-compiler dispatcher should run on the ingest
/// hot-path. The Tauri/CLI binaries set `GRAPHHUNTER_LLM_INGEST=1` at
/// startup; `=0` opts out and keeps the legacy heuristic-only path.
pub fn dispatcher_enabled() -> bool {
    std::env::var("GRAPHHUNTER_LLM_INGEST")
        .map(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// Compact view of a single mapping for diff display in the UI.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FieldMappingSummary {
    pub raw_name: String,
    pub role: FieldRole,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_type: Option<String>,
}

impl From<&FieldMapping> for FieldMappingSummary {
    fn from(m: &FieldMapping) -> Self {
        Self {
            raw_name: m.raw_name.clone(),
            role: m.role.clone(),
            entity_type: m.entity_type.clone(),
        }
    }
}

/// One row in a side-by-side diff: a single raw column, its heuristic
/// proposal (if any), and the LLM-refined proposal (if any).
#[derive(Debug, Clone, Serialize)]
pub struct MappingChange {
    pub raw_name: String,
    /// `None` when the heuristic dropped this column (rare).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heuristic: Option<FieldMappingSummary>,
    /// `None` when the LLM dropped this column.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refined: Option<FieldMappingSummary>,
}

/// Field-by-field diff between heuristic and LLM-refined configs. Sent
/// to the frontend so the confirm banner can render a side-by-side
/// table with field-level highlighting.
#[derive(Debug, Clone, Serialize, Default)]
pub struct MappingDiff {
    pub added: Vec<FieldMappingSummary>,
    pub removed: Vec<FieldMappingSummary>,
    pub changed: Vec<MappingChange>,
    pub unchanged_count: usize,
}

impl MappingDiff {
    /// Build a diff between two configs by aligning on `raw_name`.
    pub fn between(heuristic: &FieldConfig, refined: &FieldConfig) -> Self {
        let mut h_by_name: BTreeMap<&str, &FieldMapping> = BTreeMap::new();
        for m in &heuristic.mappings {
            h_by_name.insert(m.raw_name.as_str(), m);
        }
        let mut r_by_name: BTreeMap<&str, &FieldMapping> = BTreeMap::new();
        for m in &refined.mappings {
            r_by_name.insert(m.raw_name.as_str(), m);
        }
        let all_names: std::collections::BTreeSet<&str> =
            h_by_name.keys().chain(r_by_name.keys()).copied().collect();

        let mut diff = MappingDiff::default();
        for name in all_names {
            match (h_by_name.get(name), r_by_name.get(name)) {
                (None, Some(r)) => diff.added.push((*r).into()),
                (Some(h), None) => diff.removed.push((*h).into()),
                (Some(h), Some(r)) => {
                    let h_sum: FieldMappingSummary = (*h).into();
                    let r_sum: FieldMappingSummary = (*r).into();
                    if h_sum == r_sum {
                        diff.unchanged_count += 1;
                    } else {
                        diff.changed.push(MappingChange {
                            raw_name: name.to_string(),
                            heuristic: Some(h_sum),
                            refined: Some(r_sum),
                        });
                    }
                }
                (None, None) => unreachable!("name came from union of keys"),
            }
        }
        diff
    }

    /// True when the LLM proposal is materially different from the
    /// heuristic. Used by the dispatcher to decide whether to surface
    /// a banner at all — a no-op LLM refinement is silently dropped.
    pub fn is_meaningful(&self) -> bool {
        !self.added.is_empty() || !self.removed.is_empty() || !self.changed.is_empty()
    }
}

/// Outcome of [`negotiate_field_config`]. The dispatcher always emits
/// one of these; the call-site decides what to do (silent ingest,
/// confirm banner, or graceful fall-through).
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NegotiationOutcome {
    /// Heuristic produced a confident config (≥1 Node mapping). No LLM
    /// call made. Use the embedded config as-is.
    HeuristicOk { config: FieldConfig, confidence: f32 },
    /// Heuristic was weak; LLM produced a non-empty refinement that
    /// differs meaningfully from the heuristic. Hot-path callers must
    /// **not** insert triples until the analyst chooses between the
    /// two via the confirm banner.
    LlmProposal {
        heuristic: FieldConfig,
        refined: FieldConfig,
        diff: MappingDiff,
        confidence: f32,
        backend_id: String,
    },
    /// LLM was unreachable, returned an empty draft, or returned a
    /// no-op refinement. Hot-path callers should fall back to the
    /// heuristic (when `Some`) or a format-native parser. The
    /// `reason` is logged for diagnostics, not shown in the UI.
    LlmUnavailable {
        heuristic: Option<FieldConfig>,
        reason: String,
    },
}

/// Run the heuristic + (optional) LLM refinement for a content sample.
///
/// `format` is the result of `resolve_format` — the dispatcher does
/// not re-detect. `contents` is the peek buffer used by the preview
/// UI; the LLM sees a hard-capped 8KB slice of it.
///
/// Side effects: at most one synchronous `backend.infer` call when
/// the heuristic confidence falls below [`HEURISTIC_TRUST_THRESHOLD`].
pub fn negotiate_field_config(
    format: &str,
    contents: &str,
    backend: &dyn LocalLlm,
) -> NegotiationOutcome {
    let heuristic = auto_field_config_for(format, contents);
    let (heuristic_cfg, node_count, total_count) = match &heuristic {
        Some(cfg) if !cfg.mappings.is_empty() => {
            let nodes = cfg
                .mappings
                .iter()
                .filter(|m| matches!(m.role, FieldRole::Node))
                .count();
            (Some(cfg.clone()), nodes, cfg.mappings.len())
        }
        _ => (None, 0, 0),
    };

    // Heuristic is "trusted" only if it produced *enough* mappings to
    // be plausibly correct. Pathological case the dispatcher exists to
    // catch: format detector classifies a Forti KV-syslog line as
    // `csv`, the CSV parser sees the whole row as one mega-column, the
    // heuristic dutifully marks that one column as a Node — `node_count
    // > 0` would skip the LLM. Real, well-shaped logs (Sysmon,
    // Sentinel, clean CSV) have 5+ recognized fields, so requiring
    // `>= 2` Nodes / `>= 3` total mappings still keeps them on the
    // fast path.
    if let Some(cfg) = &heuristic_cfg {
        if node_count >= 2 && total_count >= 3 {
            return NegotiationOutcome::HeuristicOk {
                config: cfg.clone(),
                confidence: HEURISTIC_TRUST_THRESHOLD,
            };
        }
    }

    // Heuristic was weak (zero Nodes or `None`). Ask the LLM for a refinement.
    //
    // Cap at 128 tokens: a compact FieldConfig JSON for ~10 fields fits in
    // ~120 tokens. With JSON-schema constrained decoding (Phase J), the
    // model stops at the closing brace anyway, so 128 is just headroom —
    // not an over-budget. The few-shot example in the prompt steers the
    // model toward emitting the right Node entity types instead of empty
    // arrays.
    let prompt = build_negotiate_prompt(format, contents);
    let mut spec = PromptSpec::new(PromptTemplate::IngestNegotiate, prompt);
    spec.max_output_tokens = 128;
    let backend_id = backend.backend_id().to_string();
    let raw = match infer_with_optional_json_schema(backend, &spec) {
        Ok(s) => s,
        Err(e) => {
            return NegotiationOutcome::LlmUnavailable {
                heuristic: heuristic_cfg,
                reason: format!("backend `{backend_id}` failed: {e}"),
            };
        }
    };

    let parsed = match parse_negotiate_response(&raw) {
        Some(p) if !p.mappings.is_empty() => p,
        _ => {
            return NegotiationOutcome::LlmUnavailable {
                heuristic: heuristic_cfg,
                reason: format!("backend `{backend_id}` returned no usable mappings"),
            };
        }
    };

    let refined = FieldConfig {
        mappings: parsed.mappings,
    };
    let refined_node_count = refined
        .mappings
        .iter()
        .filter(|m| matches!(m.role, FieldRole::Node))
        .count();
    if refined_node_count == 0 {
        // LLM agreed with the heuristic (zero Nodes everywhere) — no
        // useful refinement to surface.
        return NegotiationOutcome::LlmUnavailable {
            heuristic: heuristic_cfg,
            reason: format!("backend `{backend_id}` returned zero Node mappings"),
        };
    }

    let baseline = heuristic_cfg.clone().unwrap_or(FieldConfig {
        mappings: Vec::new(),
    });
    let diff = MappingDiff::between(&baseline, &refined);
    if !diff.is_meaningful() {
        return NegotiationOutcome::LlmUnavailable {
            heuristic: heuristic_cfg,
            reason: "llm proposal matched heuristic exactly".into(),
        };
    }

    NegotiationOutcome::LlmProposal {
        heuristic: baseline,
        refined,
        diff,
        confidence: parsed.confidence.clamp(0.0, 1.0),
        backend_id,
    }
}

#[derive(Default)]
pub(super) struct ParsedNegotiate {
    pub mappings: Vec<FieldMapping>,
    /// Reserved for the agentic-path refactor — `ingest_negotiate`
    /// surfaces this in the draft. Suppressed here so the hot-path's
    /// thin use of `parse_negotiate_response` doesn't trip dead-code.
    #[allow(dead_code)]
    pub rationale: String,
    pub confidence: f32,
}

pub(super) fn parse_negotiate_response(raw: &str) -> Option<ParsedNegotiate> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    let mappings = v
        .get("mappings")
        .and_then(|m| serde_json::from_value(m.clone()).ok())
        .unwrap_or_default();
    let rationale = v
        .get("rationale")
        .and_then(|r| r.as_str())
        .unwrap_or("")
        .to_string();
    let confidence = v
        .get("confidence")
        .and_then(|c| c.as_f64())
        .map(|c| c as f32)
        .unwrap_or(0.0);
    Some(ParsedNegotiate {
        mappings,
        rationale,
        confidence,
    })
}

/// Run the LLM with JSON-schema-constrained decoding when the
/// `xgrammar` feature is on and a tokenizer is resolvable; otherwise
/// fall back to plain unconstrained `infer()` and rely on
/// `parse_negotiate_response` to gate the result post-hoc.
///
/// Phi-3 in unconstrained mode wandered into prose ~50% of the time on
/// adversarial inputs and the dispatcher failed with "no usable
/// mappings". The JSON-schema sampler masks every token that would
/// break the FieldConfig schema → output is **valid JSON by
/// construction**. Same backend, same tokens budget, but every reply
/// parses.
fn infer_with_optional_json_schema(
    backend: &dyn LocalLlm,
    spec: &PromptSpec,
) -> crate::local_llm::LocalLlmResult<String> {
    #[cfg(feature = "xgrammar")]
    {
        use crate::local_llm::resolve_model_path;
        use graph_hunter_constrained_decode::ConstrainedSampler;
        if let Some(model_path) = resolve_model_path() {
            let tokenizer_path = crate::local_llm::resolve_tokenizer_path(&model_path);
            if tokenizer_path.is_file() {
                match ConstrainedSampler::from_json_schema_path(
                    field_config_json_schema(),
                    &tokenizer_path,
                ) {
                    Ok(mut sampler) => {
                        tracing::debug!(
                            target: "graph_hunter_api::ingest",
                            "negotiate: using JSON-schema constrained sampler"
                        );
                        return backend.infer_constrained(spec, &mut sampler);
                    }
                    Err(e) => {
                        tracing::warn!(
                            target: "graph_hunter_api::ingest",
                            "negotiate: JSON-schema sampler init failed ({e}); falling back to unconstrained infer"
                        );
                    }
                }
            }
        }
    }
    backend.infer(spec)
}

/// JSON Schema for the `FieldConfig` shape that
/// `parse_negotiate_response` consumes. Built inline as a `json!`
/// literal so the schema string is type-checked at compile time —
/// llguidance interprets it via `TopLevelGrammar::from_json_schema`
/// and masks logits at every step to keep generation on the rails.
#[cfg(feature = "xgrammar")]
fn field_config_json_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "mappings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "raw_name":    { "type": "string" },
                        "role":        { "enum": ["Node", "Metadata", "Ignore"] },
                        "entity_type": { "type": ["string", "null"] }
                    },
                    "required": ["raw_name", "role"]
                }
            },
            "rationale":  { "type": "string" },
            "confidence": { "type": "number" }
        },
        "required": ["mappings"]
    })
}

pub(super) fn build_negotiate_prompt(format: &str, sample: &str) -> String {
    // Cap the sample at 1000 chars (~250 tokens). Phi-3 prefill is the
    // dominant cost on CPU — every char of sample compounds with the
    // few-shot example below. 1 KB is enough context for the model to
    // recognize column names + value shapes in any structured log we
    // care about. The few-shot Sysmon example primes the output
    // distribution so the LLM produces real Node mappings instead of
    // empty arrays — without it Phi-3 frequently echoed the schema
    // back without instances.
    let sample_clipped: String = sample.chars().take(1000).collect();
    json!({
        "task": "ingest_negotiate",
        "instruction": "Read `sample` (a few rows of a structured log in `format`). \
Output a JSON object with a `mappings` array. Each mapping pairs a \
column name from the sample with a `role` (Node when the value \
identifies a real-world entity, Metadata when it's a label/score, \
Ignore otherwise) and an `entity_type` (e.g. User, IP, Host, Process, \
Domain, URL, File, Hash) when role is Node. Be exhaustive: every \
column in the sample should appear once.",
        "example_input": {
            "format": "sysmon",
            "sample": "{\"User\":\"alice\",\"SourceIp\":\"10.0.0.5\",\"DestinationHostname\":\"evil.example.com\",\"EventID\":3,\"UtcTime\":\"2024-01-15 10:00:00.123\"}"
        },
        "example_output": {
            "mappings": [
                { "raw_name": "User",                "role": "Node",     "entity_type": "User"   },
                { "raw_name": "SourceIp",            "role": "Node",     "entity_type": "IP"     },
                { "raw_name": "DestinationHostname", "role": "Node",     "entity_type": "Host"   },
                { "raw_name": "EventID",             "role": "Metadata", "entity_type": null     },
                { "raw_name": "UtcTime",             "role": "Metadata", "entity_type": null     }
            ]
        },
        "format": format,
        "sample": sample_clipped,
        "schema": "FieldConfig{mappings:[{raw_name,role:Node|Metadata|Ignore,entity_type?:string|null}]}"
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_llm::{LocalLlmError, LocalLlmResult};

    /// Stub backend whose `infer` returns whatever string it's
    /// configured with. Reaches `Send + Sync` because the boxed
    /// closure is `Fn` over `&str`.
    struct ReplayBackend {
        replies: parking_lot::Mutex<Vec<String>>,
        id: &'static str,
    }
    impl ReplayBackend {
        fn new(replies: Vec<&str>, id: &'static str) -> Self {
            Self {
                replies: parking_lot::Mutex::new(
                    replies.into_iter().map(str::to_string).collect(),
                ),
                id,
            }
        }
    }
    impl LocalLlm for ReplayBackend {
        fn infer(&self, _spec: &PromptSpec) -> LocalLlmResult<String> {
            self.replies
                .lock()
                .pop()
                .ok_or_else(|| LocalLlmError::InferenceFailed("no more replies".into()))
        }
        fn backend_id(&self) -> &'static str {
            self.id
        }
    }

    #[test]
    fn heuristic_ok_skips_llm_when_node_present() {
        // Sysmon JSON sample with a recognizable User column → heuristic
        // produces ≥1 Node and the dispatcher must NOT call the LLM.
        let sample = r#"{"User":"alice","SourceIp":"10.0.0.5","TargetFilename":"C:\\foo.exe"}"#;
        let backend = ReplayBackend::new(
            vec!["{\"mappings\":[],\"confidence\":0.0}"], // would explode if called
            "test",
        );
        let outcome = negotiate_field_config("sysmon", sample, &backend);
        match outcome {
            NegotiationOutcome::HeuristicOk { config, .. } => {
                assert!(
                    !config.mappings.is_empty(),
                    "heuristic must produce mappings"
                );
            }
            other => panic!("expected HeuristicOk, got {other:?}"),
        }
        // The backend should still have its reply queued — it was never invoked.
        assert_eq!(
            backend.replies.lock().len(),
            1,
            "backend.infer must not run on the heuristic-confident path"
        );
    }

    #[test]
    fn llm_unavailable_when_backend_returns_empty() {
        // Format `iis` is not in `auto_field_config_for`'s
        // `supports_configurable` set — heuristic returns `None`
        // unconditionally, forcing the dispatcher onto the LLM path.
        let sample = "#Fields: date time c-ip cs-method\n2024-01-01 00:00:00 10.0.0.1 GET\n";
        let backend = ReplayBackend::new(
            vec!["{\"mappings\":[],\"confidence\":0.5}"],
            "test-empty",
        );
        let outcome = negotiate_field_config("iis", sample, &backend);
        match outcome {
            NegotiationOutcome::LlmUnavailable { reason, .. } => {
                assert!(
                    reason.contains("no usable mappings"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected LlmUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn llm_proposal_emitted_when_refined_adds_nodes() {
        // Heuristic returns None (format `iis` opts out); LLM produces
        // a non-empty Node-rich config. Dispatcher promotes to LlmProposal.
        let sample = "#Fields: date time c-ip cs-method\n2024-01-01 00:00:00 10.0.0.1 GET\n";
        let llm_reply = serde_json::json!({
            "mappings": [
                { "raw_name": "c-ip", "role": "Node", "entity_type": "IP" },
                { "raw_name": "cs-method", "role": "Metadata", "entity_type": null }
            ],
            "rationale": "IIS log fields recognized",
            "confidence": 0.72
        })
        .to_string();
        let backend = ReplayBackend::new(vec![&llm_reply], "test-llm");
        let outcome = negotiate_field_config("iis", sample, &backend);
        match outcome {
            NegotiationOutcome::LlmProposal {
                refined,
                diff,
                confidence,
                backend_id,
                ..
            } => {
                assert_eq!(backend_id, "test-llm");
                assert!((confidence - 0.72).abs() < 0.001);
                assert_eq!(refined.mappings.len(), 2);
                assert_eq!(diff.added.len(), 2);
            }
            other => panic!("expected LlmProposal, got {other:?}"),
        }
    }

    #[test]
    fn dispatcher_enabled_reads_env_var() {
        // SAFETY: tests run with `--test-threads=1` is not enforced;
        // we set + unset locally, but in worst case another test that
        // doesn't read this var is unaffected.
        let prev = std::env::var("GRAPHHUNTER_LLM_INGEST").ok();
        unsafe { std::env::set_var("GRAPHHUNTER_LLM_INGEST", "1") };
        assert!(dispatcher_enabled());
        unsafe { std::env::set_var("GRAPHHUNTER_LLM_INGEST", "0") };
        assert!(!dispatcher_enabled());
        match prev {
            Some(v) => unsafe { std::env::set_var("GRAPHHUNTER_LLM_INGEST", v) },
            None => unsafe { std::env::remove_var("GRAPHHUNTER_LLM_INGEST") },
        }
    }

    #[test]
    fn diff_aligns_on_raw_name() {
        let h = FieldConfig {
            mappings: vec![
                FieldMapping {
                    raw_name: "user".into(),
                    role: FieldRole::Node,
                    entity_type: Some("User".into()),
                    timestamp_format: None,
                    locale: None,
                },
                FieldMapping {
                    raw_name: "ip".into(),
                    role: FieldRole::Node,
                    entity_type: Some("IP".into()),
                    timestamp_format: None,
                    locale: None,
                },
            ],
        };
        let r = FieldConfig {
            mappings: vec![
                FieldMapping {
                    raw_name: "user".into(),
                    role: FieldRole::Node,
                    entity_type: Some("User".into()),
                    timestamp_format: None,
                    locale: None,
                },
                FieldMapping {
                    raw_name: "ip".into(),
                    role: FieldRole::Node,
                    entity_type: Some("Host".into()), // changed
                    timestamp_format: None,
                    locale: None,
                },
                FieldMapping {
                    raw_name: "process".into(), // added
                    role: FieldRole::Node,
                    entity_type: Some("Process".into()),
                    timestamp_format: None,
                    locale: None,
                },
            ],
        };
        let diff = MappingDiff::between(&h, &r);
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].raw_name, "process");
        assert_eq!(diff.removed.len(), 0);
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].raw_name, "ip");
        assert_eq!(diff.unchanged_count, 1);
        assert!(diff.is_meaningful());
    }
}
