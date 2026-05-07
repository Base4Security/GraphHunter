//! M4 agentic slow-lane operations.
//!
//! Three of the six tools live here: `ingest_negotiator`,
//! `canonical_mapper`, and `parser_generator`. The remaining three
//! (`schema_drift_detector`, `mapping_regression_tester`,
//! `invariant_checker`) live in `operations::agentic_drift`.
//!
//! **Deterministic-first.** Every op runs the heuristic / compiled
//! path first and only invokes the [`crate::local_llm::LocalLlm`]
//! backend when the heuristic could not produce a useful answer.
//! This keeps the LLM-as-compiler discipline: no production event
//! ever reaches the model on the happy path. The mock backend in
//! tests therefore does not need to produce realistic content for
//! the ops to round-trip.

use std::sync::Arc;

use graph_hunter_core::field_preview::{FieldConfig, FieldRole};
use serde_json::json;
use uuid::Uuid;

use crate::dto::agentic::{
    CanonicalMapRequest, CanonicalMapResponse, DraftSource, DraftStatus, IngestNegotiateRequest,
    IngestNegotiateResponse, MappingDraft, ParserGenerateRequest, ParserGenerateResponse,
    ProvenanceTemplate, SimilarMapping,
};
use crate::format_registry::resolve_format;
use crate::local_llm::{LocalLlmHandle, PromptSpec, PromptTemplate, default_backend};
use crate::operations::ingestion::auto_field_config_for;
use crate::util::now_secs;
use crate::{ApiError, ApiResult, GraphHunterApi};

impl GraphHunterApi {
    /// Backend factory hook. The default impl returns the mock-or-
    /// candle factory from [`crate::local_llm::default_backend`]; tests
    /// shadow this via the `with_local_llm` test helper.
    fn local_llm(&self) -> LocalLlmHandle {
        default_backend()
    }

    /// `ingest_negotiator` — propose a FieldConfig from raw samples.
    ///
    /// Primary path: replay `auto_field_config_for(format, sample)`,
    /// the same heuristic the ingestion entry point uses. Falls back
    /// to the LLM backend only when the heuristic returns `None` or
    /// emits zero mappings — typical of unfamiliar formats. Even then
    /// the LLM result is a *draft* sitting in the review queue; it
    /// never auto-promotes.
    pub fn ingest_negotiate(
        &self,
        req: IngestNegotiateRequest,
    ) -> ApiResult<IngestNegotiateResponse> {
        let session = self.resolve_session(req.session.as_ref())?;

        let format = req
            .hint_format
            .clone()
            .unwrap_or_else(|| resolve_format(&req.raw_sample, "auto"));

        let backend = self.local_llm();
        let mut backend_id = backend.backend_id().to_string();

        let (proposed_field_config, rationale, confidence) = match auto_field_config_for(
            &format,
            &req.raw_sample,
        ) {
            Some(cfg) if !cfg.mappings.is_empty() => {
                backend_id = "deterministic".into();
                let node_count = cfg
                    .mappings
                    .iter()
                    .filter(|m| matches!(m.role, FieldRole::Node))
                    .count();
                let total_count = cfg.mappings.len();
                (
                    cfg,
                    format!(
                        // 2026-05-06: previously both blanks used
                        // `cfg_len_helper(&Some(node_count))` which
                        // resolved to the same value, so a 6-mapping
                        // result with 5 Nodes printed "5 mappings (5
                        // Node)". Total now reads from
                        // `cfg.mappings.len()` as intended.
                        "auto_field_config_for({format}) produced {} mappings ({} Node).",
                        total_count, node_count,
                    ),
                    // Heuristic confidence is high when at least one
                    // Node mapping landed; calibration is M6 work.
                    if node_count > 0 { 0.85 } else { 0.5 },
                )
            }
            _ => {
                // Fallback: ask the LLM. Mock returns an empty
                // mappings vector, which is fine — the analyst
                // sees the draft is empty and rejects it.
                let prompt = build_negotiate_prompt(&format, &req.raw_sample);
                let raw = backend
                    .infer(&PromptSpec::new(PromptTemplate::IngestNegotiate, prompt))
                    .map_err(|e| ApiError::Upstream {
                        service: "local_llm".into(),
                        message: e.to_string(),
                    })?;
                let parsed = parse_negotiate_response(&raw).unwrap_or_default();
                let confidence = parsed.confidence.clamp(0.0, 1.0);
                let rationale = if parsed.rationale.is_empty() {
                    format!(
                        "deterministic heuristic produced no mappings for format `{format}`; backend `{backend_id}` returned empty draft."
                    )
                } else {
                    parsed.rationale
                };
                (
                    FieldConfig {
                        mappings: parsed.mappings,
                    },
                    rationale,
                    confidence,
                )
            }
        };

        // RAG warm-start: consult the mapping library for previously-
        // approved shapes that match the proposed FieldConfig. If an
        // exact fingerprint match exists, adopt its FieldConfig as the
        // proposal (the prior human gate already approved this shape)
        // and raise confidence. Otherwise just attach the partial hits
        // so the analyst can pick one to reuse.
        let similar = self.lookup_similar_mappings(&proposed_field_config);
        let (proposed_field_config, rationale, confidence, warm_started) =
            maybe_warm_start(proposed_field_config, rationale, confidence, &similar);

        let draft_id = format!("draft-{}", Uuid::new_v4());
        let draft = MappingDraft {
            draft_id: draft_id.clone(),
            source: DraftSource::IngestNegotiator,
            created_at: now_secs(),
            status: DraftStatus::Pending,
            field_config: Some(proposed_field_config.clone()),
            vrl_source: None,
            mapping_hash: None,
            rationale: rationale.clone(),
            backend_id: if warm_started {
                format!("{backend_id}+library")
            } else {
                backend_id.clone()
            },
        };
        push_draft(&session, draft)?;

        Ok(IngestNegotiateResponse {
            draft_id,
            proposed_field_config,
            rationale,
            confidence,
            similar_mappings: similar,
        })
    }

    /// Pull up to 5 library matches for a FieldConfig. Returns an empty
    /// list when the library is unconfigured, empty, or the lookup
    /// errors out (errors are logged, never bubbled — the negotiator
    /// must still produce a draft even if the library is broken).
    fn lookup_similar_mappings(&self, cfg: &FieldConfig) -> Vec<SimilarMapping> {
        let Some(store) = self.mapping_library() else {
            return Vec::new();
        };
        match graph_hunter_core::mapping_library::lookup(&store, cfg, 5, 0.25) {
            Ok(hits) => hits.into_iter().map(rag_match_to_dto).collect(),
            Err(e) => {
                tracing::warn!("mapping_library lookup failed: {e}");
                Vec::new()
            }
        }
    }

    /// `canonical_mapper` — pick an OCSF category for a FieldConfig.
    ///
    /// Deterministic by inspection of which entity types the FieldConfig
    /// declares: a `Process`+`User` config maps to `process_activity`,
    /// an `IP`-only config maps to `network_activity`, etc. The LLM is
    /// only consulted when the heuristic produces `unknown` AND no
    /// `target_ocsf_category` was pinned by the caller.
    pub fn canonical_map(&self, req: CanonicalMapRequest) -> ApiResult<CanonicalMapResponse> {
        // Derive deterministic OCSF target.
        let derived = derive_ocsf_category(&req.field_config);
        let pinned = req.target_ocsf_category.clone();

        let mut warnings = Vec::new();
        let mut backend_id = "deterministic".to_string();

        let category = match (pinned.as_ref(), derived.as_str()) {
            (Some(p), d) if !p.is_empty() && p != d && d != "unknown" => {
                warnings.push(format!(
                    "caller pinned `{p}` but heuristic preferred `{d}` for this FieldConfig"
                ));
                p.clone()
            }
            (Some(p), _) if !p.is_empty() => p.clone(),
            (_, "unknown") => {
                let backend = self.local_llm();
                backend_id = backend.backend_id().to_string();
                let prompt = build_canonical_prompt(&req.field_config);
                let raw = backend
                    .infer(&PromptSpec::new(PromptTemplate::CanonicalMap, prompt))
                    .map_err(|e| ApiError::Upstream {
                        service: "local_llm".into(),
                        message: e.to_string(),
                    })?;
                let parsed = parse_canonical_response(&raw).unwrap_or_default();
                if parsed.category.is_empty() {
                    "unknown".into()
                } else {
                    parsed.category
                }
            }
            (_, d) => d.into(),
        };

        // Compile the FieldConfig so the provenance template carries
        // the deterministic mapping_hash. Keeps the canonical mapper
        // and parser generator stamping the same identifier.
        let program = graph_hunter_vrl::field_config_to_vrl(&req.field_config);
        Ok(CanonicalMapResponse {
            ocsf_category: category,
            provenance_template: ProvenanceTemplate {
                mapping_id: program.provenance_id(),
                mapping_version: program.mapping_version,
                mapping_hash: program.mapping_hash,
                parser_name: format!("vrl/{backend_id}"),
            },
            warnings,
        })
    }

    /// `parser_generator` — emit VRL from a FieldConfig.
    ///
    /// The deterministic compiler is the primary path. The LLM is
    /// consulted only when `optimization_hint = "fidelity"`; on any
    /// other value (or `None`) the compiler output is returned as-is
    /// and a draft is queued so reviewers see what would be promoted.
    pub fn parser_generate(&self, req: ParserGenerateRequest) -> ApiResult<ParserGenerateResponse> {
        let session = self.resolve_session(req.session.as_ref())?;

        let program = graph_hunter_vrl::field_config_to_vrl(&req.field_config);
        let mut vrl_source = program.source.clone();
        let mut backend_id = "deterministic".to_string();

        if matches!(req.optimization_hint.as_deref(), Some("fidelity")) {
            let backend = self.local_llm();
            backend_id = backend.backend_id().to_string();
            let prompt = build_parser_prompt(&req.field_config, &program.source);
            let raw = backend
                .infer(&PromptSpec::new(PromptTemplate::ParserGenerate, prompt))
                .map_err(|e| ApiError::Upstream {
                    service: "local_llm".into(),
                    message: e.to_string(),
                })?;
            // Only accept LLM refinement when it parses cleanly under
            // the VRL-subset grammar validator. The validator enforces
            // the same line-shape the deterministic compiler produces,
            // so anything that drifts into loops, raw arithmetic, or
            // unrecognized function calls is dropped here and we keep
            // the deterministic source. This is M6's hard contract:
            // refinements that touch the review queue are syntactically
            // safe by construction.
            if let Some(refined) = parse_parser_response(&raw) {
                use graph_hunter_constrained_decode::{GrammarValidator, VrlSubsetValidator};
                let has_content = refined
                    .lines()
                    .any(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'));
                if has_content && VrlSubsetValidator::new().validate(&refined).is_ok() {
                    vrl_source = refined;
                } else if has_content {
                    backend_id.push_str("+rejected");
                }
            }
        }

        let expected_ocsf_fields = expected_ocsf_fields(&req.field_config);

        let draft_id = format!("draft-{}", Uuid::new_v4());
        let draft = MappingDraft {
            draft_id: draft_id.clone(),
            source: DraftSource::ParserGenerator,
            created_at: now_secs(),
            status: DraftStatus::Pending,
            field_config: Some(req.field_config.clone()),
            vrl_source: Some(vrl_source.clone()),
            mapping_hash: Some(program.mapping_hash.clone()),
            rationale: format!(
                "compiled by `{backend_id}`; {} OCSF target field(s) expected",
                expected_ocsf_fields.len()
            ),
            backend_id,
        };
        push_draft(&session, draft)?;

        Ok(ParserGenerateResponse {
            draft_id,
            vrl_source,
            mapping_hash: program.mapping_hash,
            mapping_version: program.mapping_version,
            expected_ocsf_fields,
        })
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

fn rag_match_to_dto(m: graph_hunter_core::mapping_library::RagMatch) -> SimilarMapping {
    let pm = m.mapping;
    SimilarMapping {
        mapping_id: pm.mapping_id,
        fingerprint: pm.fingerprint,
        score: m.score,
        exact: m.exact,
        mapping_hash: pm.mapping_hash,
        ocsf_category: pm.ocsf_category,
        source: match pm.source {
            graph_hunter_core::mapping_library::PublishSource::IngestNegotiator => {
                "ingest_negotiator".into()
            }
            graph_hunter_core::mapping_library::PublishSource::ParserGenerator => {
                "parser_generator".into()
            }
            graph_hunter_core::mapping_library::PublishSource::Manual => "manual".into(),
        },
        published_at: pm.published_at,
    }
}

/// If the best library hit is an exact-fingerprint match, bump confidence
/// and annotate the rationale so the analyst sees we warm-started.
/// Returns the possibly-rewritten `(cfg, rationale, confidence, warm_started)`.
fn maybe_warm_start(
    proposed: FieldConfig,
    rationale: String,
    confidence: f32,
    similar: &[SimilarMapping],
) -> (FieldConfig, String, f32, bool) {
    let Some(best) = similar.iter().find(|m| m.exact) else {
        return (proposed, rationale, confidence, false);
    };
    let warm = format!(
        "{rationale} Warm-started from library mapping {} (fingerprint {}; previously approved at {}).",
        best.mapping_id, best.fingerprint, best.published_at
    );
    let bumped = (confidence + 0.1).min(0.99);
    (proposed, warm, bumped, true)
}

// `cfg_len_helper` removed 2026-05-06 — its only caller was the
// rationale-formatting site above, which now reads `total_count` /
// `node_count` directly. Helper was a thin Option<usize> unwrap
// that obscured the real off-by-one bug it was masking.

fn push_draft(session: &Arc<crate::state::Session>, draft: MappingDraft) -> ApiResult<()> {
    let mut q = session
        .agentic_review
        .write()
        .map_err(|e| ApiError::Internal(format!("agentic_review lock poisoned: {e}")))?;
    q.push(draft);
    Ok(())
}

#[derive(Default)]
struct ParsedNegotiate {
    mappings: Vec<graph_hunter_core::field_preview::FieldMapping>,
    rationale: String,
    confidence: f32,
}

fn parse_negotiate_response(raw: &str) -> Option<ParsedNegotiate> {
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

#[derive(Default)]
struct ParsedCanonical {
    category: String,
}

fn parse_canonical_response(raw: &str) -> Option<ParsedCanonical> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    Some(ParsedCanonical {
        category: v
            .get("category")
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

fn parse_parser_response(raw: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    v.get("vrl_source")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
}

fn build_negotiate_prompt(format: &str, sample: &str) -> String {
    json!({
        "task": "ingest_negotiate",
        "format": format,
        "sample": sample.chars().take(8000).collect::<String>(),
        "schema": "FieldConfig{mappings:[{raw_name,role,entity_type,timestamp_format,locale}]}"
    })
    .to_string()
}

fn build_canonical_prompt(cfg: &FieldConfig) -> String {
    json!({
        "task": "canonical_map",
        "field_config": cfg,
        "ocsf_categories": [
            "process_activity",
            "network_activity",
            "dns_activity",
            "file_system_activity",
            "registry_key_activity",
            "authentication"
        ]
    })
    .to_string()
}

fn build_parser_prompt(cfg: &FieldConfig, baseline_vrl: &str) -> String {
    json!({
        "task": "parser_generate",
        "field_config": cfg,
        "baseline_vrl": baseline_vrl,
        "instruction": "return refined VRL source only if it strictly improves fidelity; else return empty"
    })
    .to_string()
}

/// Inspect the FieldConfig's declared entity types and return the
/// OCSF category that best fits. The mapping mirrors the projection
/// in `graph_hunter_canonical/src/ocsf/projection.rs` so the slow
/// lane and the fast lane agree on category for any given config.
fn derive_ocsf_category(cfg: &FieldConfig) -> String {
    use std::collections::HashSet;
    let types: HashSet<&str> = cfg
        .mappings
        .iter()
        .filter(|m| matches!(m.role, FieldRole::Node))
        .filter_map(|m| m.entity_type.as_deref())
        .collect();

    let has = |t: &str| types.contains(t);

    if has("Process") && (has("User") || has("Host")) {
        "process_activity".into()
    } else if has("Domain") {
        "dns_activity".into()
    } else if has("IP") {
        "network_activity".into()
    } else if has("File") {
        "file_system_activity".into()
    } else if has("Registry") {
        "registry_key_activity".into()
    } else if has("User") && has("Host") {
        "authentication".into()
    } else {
        "unknown".into()
    }
}

fn expected_ocsf_fields(cfg: &FieldConfig) -> Vec<String> {
    let mut out: Vec<String> = cfg
        .mappings
        .iter()
        .filter(|m| matches!(m.role, FieldRole::Node))
        .map(|m| m.entity_type.clone().unwrap_or_else(|| m.raw_name.clone()))
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::session::CreateSessionRequest;
    use graph_hunter_core::field_preview::FieldMapping;

    fn cfg_user_process() -> FieldConfig {
        FieldConfig {
            mappings: vec![
                FieldMapping {
                    raw_name: "User".into(),
                    role: FieldRole::Node,
                    entity_type: Some("User".into()),
                    timestamp_format: None,
                    locale: None,
                },
                FieldMapping {
                    raw_name: "Image".into(),
                    role: FieldRole::Node,
                    entity_type: Some("Process".into()),
                    timestamp_format: None,
                    locale: None,
                },
            ],
        }
    }

    fn make_api() -> GraphHunterApi {
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("agentic-test".into()),
        })
        .expect("create_session");
        api
    }

    #[test]
    fn ingest_negotiate_produces_pending_draft() {
        let api = make_api();
        let csv = "User,Image,Time\nalice,cmd.exe,1\nbob,whoami.exe,2\n";
        let resp = api
            .ingest_negotiate(IngestNegotiateRequest {
                session: None,
                dataset_id: None,
                raw_sample: csv.into(),
                hint_format: Some("csv".into()),
                max_rounds: None,
            })
            .expect("negotiate");
        assert!(resp.draft_id.starts_with("draft-"));
        assert!(!resp.proposed_field_config.mappings.is_empty());
        assert!(resp.confidence > 0.0);

        let session = api.sessions().current_session().unwrap();
        let q = session.agentic_review.read().unwrap();
        let pending = q.list(false);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].draft_id, resp.draft_id);
        assert_eq!(pending[0].source, DraftSource::IngestNegotiator);
    }

    #[test]
    fn canonical_map_picks_process_activity_for_user_process() {
        let api = make_api();
        let resp = api
            .canonical_map(CanonicalMapRequest {
                session: None,
                field_config: cfg_user_process(),
                target_ocsf_category: None,
            })
            .expect("canonical_map");
        assert_eq!(resp.ocsf_category, "process_activity");
        assert!(resp.provenance_template.mapping_id.starts_with("vrl-v"));
        assert_eq!(resp.provenance_template.mapping_hash.len(), 64);
    }

    #[test]
    fn canonical_map_warns_on_disagreeing_pin() {
        let api = make_api();
        let resp = api
            .canonical_map(CanonicalMapRequest {
                session: None,
                field_config: cfg_user_process(),
                target_ocsf_category: Some("network_activity".into()),
            })
            .expect("canonical_map");
        assert_eq!(resp.ocsf_category, "network_activity");
        assert!(!resp.warnings.is_empty());
    }

    #[test]
    fn parser_generate_default_path_is_deterministic() {
        let api = make_api();
        let resp = api
            .parser_generate(ParserGenerateRequest {
                session: None,
                field_config: cfg_user_process(),
                ocsf_category: None,
                optimization_hint: None,
            })
            .expect("parser_generate");
        assert_eq!(resp.mapping_hash.len(), 64);
        assert!(resp.vrl_source.contains(".entities"));
        // The deterministic path produces an identical hash on a
        // second call — the wedge property the slow lane exposes.
        let resp2 = api
            .parser_generate(ParserGenerateRequest {
                session: None,
                field_config: cfg_user_process(),
                ocsf_category: None,
                optimization_hint: None,
            })
            .expect("parser_generate");
        assert_eq!(resp.mapping_hash, resp2.mapping_hash);
        assert_eq!(resp.vrl_source, resp2.vrl_source);
        assert_eq!(resp.expected_ocsf_fields, vec!["Process", "User"]);
    }

    #[test]
    fn parser_generate_fidelity_hint_keeps_deterministic_when_llm_empty() {
        // The mock backend returns an empty `vrl_source`. The op must
        // not let an empty refinement clobber the deterministic
        // output. Regression guard for the fallback policy.
        let api = make_api();
        let resp = api
            .parser_generate(ParserGenerateRequest {
                session: None,
                field_config: cfg_user_process(),
                ocsf_category: None,
                optimization_hint: Some("fidelity".into()),
            })
            .expect("parser_generate");
        assert!(resp.vrl_source.contains(".entities"));
    }
}
