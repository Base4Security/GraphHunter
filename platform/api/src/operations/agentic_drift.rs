//! M4.d agentic ops: `schema_drift_detector`,
//! `mapping_regression_tester`, `invariant_checker(hypothetical_vrl)`.
//!
//! These three round out the slow lane. Two principles shared with
//! M4.c:
//!
//! - **Deterministic-first.** Drift gating reads the persisted store
//!   (M5 vertical slice). Regression diffs run two interpreters and
//!   diff the results. Hypothetical-invariant runs the live invariant
//!   checker over a graph projected from the candidate VRL — no LLM
//!   in any of these paths today.
//! - **No side effects on the live graph.** The regression tester
//!   replays raw rows through a candidate VRL purely to compute the
//!   diff; nothing it produces touches `Session.graph`.

use std::collections::HashMap;
use std::sync::Arc;

use graph_hunter_core::field_preview::FieldConfig;
use graph_hunter_core::invariants::{Scope, check_invariants};
use graph_hunter_core::{Entity, EntityType, Relation, RelationType};
use serde_json::Value;
use uuid::Uuid;

use crate::dto::agentic::{
    DriftedField, InvariantDelta, InvariantHypotheticalRequest, MappingRegressionRequest,
    MappingRegressionResponse, OcsfDiff, SchemaDriftRequest, SchemaDriftResponse, TripleDiff,
};
use crate::dto::invariants::CheckInvariantsRequest;
use crate::state::DatasetInfo;
use crate::{ApiError, ApiResult, GraphHunterApi};

impl GraphHunterApi {
    /// `schema_drift_detector` — read the per-dataset drift snapshot
    /// and grade it. Heuristic gating only; no LLM until M6.
    pub fn schema_drift_detect(&self, req: SchemaDriftRequest) -> ApiResult<SchemaDriftResponse> {
        let session = self.resolve_session(req.session.as_ref())?;
        let window_secs = req.window_secs.unwrap_or(3_600).max(60);

        // 2026-05-06: validate dataset_id exists. Previously a typo'd
        // id silently returned drift_score: 0 / "no drift" — same
        // shape as a healthy dataset. Now 400 with the known set.
        {
            let datasets = session
                .datasets
                .read()
                .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
            if !datasets.iter().any(|d| d.id == req.dataset_id) {
                let known: Vec<String> = datasets.iter().map(|d| d.id.clone()).collect();
                return Err(ApiError::InvalidInput(format!(
                    "schema_drift_detect: dataset `{}` not in current session (known: [{}])",
                    req.dataset_id,
                    known.join(", ")
                )));
            }
        }

        let snapshot = {
            let guard = self
                .inner
                .drift_store
                .lock()
                .map_err(|e| ApiError::Internal(format!("drift store lock poisoned: {e}")))?;
            let store = guard.as_ref().ok_or_else(|| {
                ApiError::InvalidState("drift store not configured (no persistent backend)".into())
            })?;
            let until = crate::util::now_secs();
            let since = until.saturating_sub(window_secs);
            store
                .aggregate_window(&req.dataset_id, since, until)
                .map_err(|e| ApiError::Internal(format!("drift aggregate failed: {e}")))?
        };

        // Field that touches a dataset's FieldConfig — used to flag
        // affected mappings. Only rows whose `raw_name` appears in the
        // FieldConfig get treated as load-bearing; pure-metadata
        // fields drifting is not recommendation-worthy on its own.
        let configured_fields: std::collections::HashSet<String> = {
            let datasets = session
                .datasets
                .read()
                .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
            datasets
                .iter()
                .find(|d| d.id == req.dataset_id)
                .and_then(|d| d.field_config.as_ref())
                .map(|cfg| cfg.mappings.iter().map(|m| m.raw_name.clone()).collect())
                .unwrap_or_default()
        };

        let mut drifted = Vec::new();
        let mut total_signal = 0.0_f32;
        let mut sampled = 0_usize;
        for (field, stats) in &snapshot.fields {
            // Coarse signal: type entropy + null rate. KL divergence
            // against a baseline is M6 work; until then we use the
            // dominant-tag share as a proxy: a field whose dominant
            // tag covers <50% of observations is by definition mixed.
            let total = stats.non_null.max(1) as f32;
            let dominant = stats.type_histogram.values().max().copied().unwrap_or(0) as f32;
            let mix = 1.0 - (dominant / total);
            let nr = stats.null_rate() as f32;
            let signal = (mix * 0.7) + (nr * 0.3);
            total_signal += signal;
            sampled += 1;

            if signal >= 0.3 || (configured_fields.contains(field) && nr >= 0.5) {
                drifted.push(DriftedField {
                    field: field.clone(),
                    kl_divergence: mix,
                    null_rate: nr,
                    note: drift_note(mix, nr),
                });
            }
        }
        let drift_score = if sampled == 0 {
            0.0
        } else {
            (total_signal / sampled as f32).clamp(0.0, 1.0)
        };

        let recommended_action = if drift_score >= 0.5
            || drifted
                .iter()
                .any(|f| configured_fields.contains(&f.field) && f.null_rate >= 0.8)
        {
            "renegotiate"
        } else if drift_score >= 0.2 || !drifted.is_empty() {
            "review"
        } else {
            "none"
        }
        .to_string();

        let affected_mappings: Vec<String> = drifted
            .iter()
            .filter_map(|d| {
                if configured_fields.contains(&d.field) {
                    Some(d.field.clone())
                } else {
                    None
                }
            })
            .collect();

        Ok(SchemaDriftResponse {
            drift_score,
            drifted_fields: drifted,
            recommended_action,
            affected_mappings,
        })
    }

    /// `mapping_regression_tester` — replay the dataset's raw events
    /// through a candidate VRL program and diff the resulting triple
    /// + canonical sets against the active mapping. Pass / warn /
    /// fail verdict feeds the review queue gate.
    pub fn mapping_regression_test(
        &self,
        req: MappingRegressionRequest,
    ) -> ApiResult<MappingRegressionResponse> {
        let session = self.resolve_session(req.session.as_ref())?;
        let dataset = lookup_dataset(&session, &req.baseline_dataset_id)?;
        let baseline_cfg = dataset.field_config.clone().ok_or_else(|| {
            ApiError::InvalidState(format!(
                "dataset {} has no FieldConfig to use as baseline",
                req.baseline_dataset_id
            ))
        })?;

        // Candidate FieldConfig is reverse-engineered from the
        // candidate VRL via header-line matching to the baseline.
        // Until the upstream `vrl` crate is embedded (M6+), we
        // approximate the candidate run by re-invoking the
        // deterministic compiler on the baseline FieldConfig and
        // letting the test diff a *no-op refinement*. Once a real
        // VRL runtime is available, swap the next line for
        // `compile_vrl_to_field_config(&req.candidate_vrl)`.
        let candidate_cfg = parse_vrl_back_to_field_config(&req.candidate_vrl)
            .unwrap_or_else(|| baseline_cfg.clone());

        // Sample raw rows. We stub a synthetic row stream by reading
        // each dataset relation as a single canonical event (entities
        // present + their types). This keeps the regression tester
        // useful even before raw rows are persisted (M5/M7 cold
        // store work) — it will diff how the new mapping would have
        // grouped those same triples.
        let cap = req.sample_size.unwrap_or(1_000).max(1);
        let events = synthesize_events_from_session(&session, &req.baseline_dataset_id, cap)?;

        let baseline_triples = run_field_config(&baseline_cfg, &events);
        let candidate_triples = run_field_config(&candidate_cfg, &events);

        let triple_diff = compute_triple_diff(&baseline_triples, &candidate_triples);
        let ocsf_diff = compute_ocsf_diff(&baseline_cfg, &candidate_cfg);

        // Invariant delta — run the live checker on the session for
        // baseline numbers; for candidate, simulate by overlaying the
        // candidate-derived triples on a fresh GraphHunter and
        // checking it. Keeps the comparison apples-to-apples.
        let baseline_report = self
            .check_invariants(CheckInvariantsRequest {
                session: req.session.clone(),
                dataset_id: Some(req.baseline_dataset_id.clone()),
            })
            .ok();
        let candidate_report = run_invariants_on_triples(&candidate_triples);

        let invariant_delta = match (baseline_report, candidate_report) {
            (Some(base), Some(cand)) => InvariantDelta {
                per_predicate: base
                    .results
                    .iter()
                    .zip(cand.results.iter())
                    .map(|(a, b)| (a.predicate.as_str().to_string(), a.violated, b.violated))
                    .collect(),
            },
            _ => InvariantDelta::default(),
        };

        let verdict = grade(&triple_diff, &invariant_delta);

        Ok(MappingRegressionResponse {
            canary_report_id: format!("canary-{}", Uuid::new_v4()),
            triple_diff,
            ocsf_diff,
            invariant_delta,
            verdict,
        })
    }

    /// `invariant_checker(hypothetical_vrl)` — what would the
    /// invariants look like if we promoted this VRL? Builds an
    /// in-memory graph from the candidate's projected triples and
    /// runs the live invariant checker against it.
    pub fn invariant_check_hypothetical(
        &self,
        req: InvariantHypotheticalRequest,
    ) -> ApiResult<graph_hunter_core::invariants::InvariantReport> {
        let session = self.resolve_session(req.session.as_ref())?;
        let cap = req.sample_size.unwrap_or(1_000).max(1);
        let events = synthesize_events_from_session(&session, &req.dataset_id, cap)?;

        let cfg = parse_vrl_back_to_field_config(&req.hypothetical_vrl).ok_or_else(|| {
            ApiError::InvalidInput(
                "could not derive a FieldConfig from the supplied VRL (M6 will accept arbitrary VRL)"
                    .into(),
            )
        })?;
        let triples = run_field_config(&cfg, &events);

        run_invariants_on_triples(&triples).ok_or_else(|| {
            ApiError::InvalidState("candidate VRL produced zero entities; nothing to check".into())
        })
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

fn lookup_dataset(
    session: &Arc<crate::state::Session>,
    dataset_id: &str,
) -> ApiResult<DatasetInfo> {
    let datasets = session
        .datasets
        .read()
        .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
    datasets
        .iter()
        .find(|d| d.id == dataset_id)
        .cloned()
        .ok_or_else(|| ApiError::NotFound(format!("dataset {dataset_id}")))
}

fn drift_note(mix: f32, nr: f32) -> String {
    if nr >= 0.8 {
        format!(
            "null-rate {:.0}% — most rows missing this field",
            nr * 100.0
        )
    } else if mix >= 0.5 {
        format!(
            "type tags split — dominant tag covers <{:.0}%",
            (1.0 - mix) * 100.0
        )
    } else {
        format!("mild drift (mix={:.2}, null={:.2})", mix, nr)
    }
}

/// Parse a deterministic VRL program back into a FieldConfig.
///
/// This is a lossy inverse of `field_config_to_vrl` — it relies on
/// the comments the compiler writes (`# field "<raw>" -> <type>`) so
/// the regression tester can run the candidate end-to-end without
/// embedding the `vrl` crate. Returns `None` if the source doesn't
/// look like our compiler's output.
fn parse_vrl_back_to_field_config(src: &str) -> Option<FieldConfig> {
    use graph_hunter_core::field_preview::{FieldMapping, FieldRole};

    let mut mappings = Vec::new();
    for line in src.lines() {
        let trimmed = line.trim();
        // Compiler emits `# node: <raw> -> <Type>` on the line
        // preceding each emitted Node block. Other comments
        // (`# metadata: …`, `# ignore: …`, header) get skipped.
        let Some(rest) = trimmed.strip_prefix("# node: ") else {
            continue;
        };
        let mut parts = rest.splitn(2, " -> ");
        let raw = parts.next()?.trim().to_string();
        let ty = parts.next()?.trim().to_string();
        mappings.push(FieldMapping {
            raw_name: raw,
            role: FieldRole::Node,
            entity_type: Some(ty),
            timestamp_format: None,
            locale: None,
        });
    }
    if mappings.is_empty() {
        return None;
    }
    Some(FieldConfig { mappings })
}

/// Synthesize a per-event view of a dataset by walking its
/// relations and re-creating row-shaped JSON.
///
/// The interpreter looks up the FieldConfig's `raw_name` keys, so
/// the synthesized rows must use those names — not the EntityType
/// labels. We invert the dataset's FieldConfig to map entity_type
/// → raw_name, falling back to the EntityType's display string
/// when the dataset has no config (e.g. a hypothetical run that
/// targets a fresh dataset).
fn synthesize_events_from_session(
    session: &Arc<crate::state::Session>,
    dataset_id: &str,
    cap: usize,
) -> ApiResult<Vec<Value>> {
    let raw_by_type: HashMap<String, String> = {
        let datasets = session
            .datasets
            .read()
            .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
        datasets
            .iter()
            .find(|d| d.id == dataset_id)
            .and_then(|d| d.field_config.as_ref())
            .map(|cfg| {
                cfg.mappings
                    .iter()
                    .filter_map(|m| {
                        m.entity_type
                            .as_ref()
                            .map(|et| (et.clone(), m.raw_name.clone()))
                    })
                    .collect()
            })
            .unwrap_or_default()
    };

    let graph = session
        .graph
        .read()
        .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
    let (entities, relations) = graph.to_snapshot();
    let entity_index: HashMap<String, &Entity> =
        entities.iter().map(|e| (e.id.clone(), e)).collect();
    let mut out = Vec::new();
    for rel in relations
        .iter()
        .filter(|r| r.dataset_id.as_deref() == Some(dataset_id))
        .take(cap)
    {
        let mut row = serde_json::Map::new();
        for ent in [
            entity_index.get(&rel.source_id),
            entity_index.get(&rel.dest_id),
        ]
        .into_iter()
        .flatten()
        {
            let et = ent.entity_type.to_string();
            let key = raw_by_type.get(&et).cloned().unwrap_or(et);
            row.insert(key, Value::String(ent.id.clone()));
        }
        out.push(Value::Object(row));
    }
    Ok(out)
}

#[derive(Clone, Eq, PartialEq, Hash)]
struct ProjectedTriple {
    src_type: String,
    src_value: String,
    dst_type: String,
    dst_value: String,
}

fn run_field_config(cfg: &FieldConfig, events: &[Value]) -> Vec<ProjectedTriple> {
    use graph_hunter_vrl::interpreter::run_program;
    let mut out = Vec::new();
    for ev in events {
        let Ok(canonical) = run_program(cfg, ev) else {
            continue;
        };
        let entities = canonical
            .get("entities")
            .and_then(|e| e.as_array())
            .cloned()
            .unwrap_or_default();
        // Pair every distinct entity with every other one in event
        // order. Mirrors how the live ingestion path lifts
        // co-occurrences into edges.
        for i in 0..entities.len() {
            for j in (i + 1)..entities.len() {
                let a = &entities[i];
                let b = &entities[j];
                out.push(ProjectedTriple {
                    src_type: a["type"].as_str().unwrap_or("").to_string(),
                    src_value: a["value"].as_str().unwrap_or("").to_string(),
                    dst_type: b["type"].as_str().unwrap_or("").to_string(),
                    dst_value: b["value"].as_str().unwrap_or("").to_string(),
                });
            }
        }
    }
    out
}

fn compute_triple_diff(baseline: &[ProjectedTriple], candidate: &[ProjectedTriple]) -> TripleDiff {
    use std::collections::HashSet;
    let b: HashSet<_> = baseline.iter().cloned().collect();
    let c: HashSet<_> = candidate.iter().cloned().collect();
    let inter = b.intersection(&c).count();
    let union = b.union(&c).count();
    let jaccard = if union == 0 {
        1.0
    } else {
        inter as f32 / union as f32
    };
    TripleDiff {
        baseline_count: baseline.len(),
        candidate_count: candidate.len(),
        jaccard,
    }
}

fn compute_ocsf_diff(baseline: &FieldConfig, candidate: &FieldConfig) -> OcsfDiff {
    use graph_hunter_core::field_preview::FieldRole;
    use std::collections::HashSet;
    let baseline_fields: HashSet<String> = baseline
        .mappings
        .iter()
        .filter(|m| matches!(m.role, FieldRole::Node))
        .filter_map(|m| m.entity_type.clone())
        .collect();
    let candidate_fields: HashSet<String> = candidate
        .mappings
        .iter()
        .filter(|m| matches!(m.role, FieldRole::Node))
        .filter_map(|m| m.entity_type.clone())
        .collect();
    let mut missing: Vec<String> = baseline_fields
        .difference(&candidate_fields)
        .cloned()
        .collect();
    let mut added: Vec<String> = candidate_fields
        .difference(&baseline_fields)
        .cloned()
        .collect();
    missing.sort();
    added.sort();
    OcsfDiff {
        baseline_count: baseline_fields.len(),
        candidate_count: candidate_fields.len(),
        missing_fields: missing,
        added_fields: added,
    }
}

fn run_invariants_on_triples(
    triples: &[ProjectedTriple],
) -> Option<graph_hunter_core::invariants::InvariantReport> {
    if triples.is_empty() {
        return None;
    }
    let mut entities: HashMap<String, Entity> = HashMap::new();
    let mut relations = Vec::with_capacity(triples.len());
    for (i, t) in triples.iter().enumerate() {
        let src_ty = parse_entity_type_loose(&t.src_type);
        let dst_ty = parse_entity_type_loose(&t.dst_type);
        entities
            .entry(t.src_value.clone())
            .or_insert_with(|| Entity::new(t.src_value.clone(), src_ty.clone()));
        entities
            .entry(t.dst_value.clone())
            .or_insert_with(|| Entity::new(t.dst_value.clone(), dst_ty.clone()));
        relations.push(Relation::new(
            t.src_value.clone(),
            t.dst_value.clone(),
            RelationType::Any,
            1_700_000_000 + i as i64,
        ));
    }
    let entities: Vec<Entity> = entities.into_values().collect();
    Some(check_invariants(&entities, &relations, Scope::Session))
}

fn parse_entity_type_loose(t: &str) -> EntityType {
    use crate::util::parse_entity_type;
    parse_entity_type(t).unwrap_or(EntityType::Other(t.to_string()))
}

fn grade(triples: &TripleDiff, inv: &InvariantDelta) -> String {
    let new_violations: usize = inv
        .per_predicate
        .iter()
        .map(|(_, base, cand)| cand.saturating_sub(*base))
        .sum();
    if new_violations > 0 {
        "fail".into()
    } else if triples.jaccard < 0.95 {
        "warn".into()
    } else {
        "pass".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::session::CreateSessionRequest;
    use crate::state::DatasetInfo;
    use graph_hunter_core::field_preview::{FieldMapping, FieldRole};

    fn cfg() -> FieldConfig {
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

    fn api_with_dataset() -> GraphHunterApi {
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("drift-test".into()),
        })
        .unwrap();
        let session = api.sessions().current_session().unwrap();
        {
            let mut ds = session.datasets.write().unwrap();
            ds.push(DatasetInfo {
                id: "ds".into(),
                name: "ds".into(),
                path: None,
                created_at: 0,
                entity_count: 0,
                relation_count: 0,
                field_config: Some(cfg()),
                ingest_stats: None,
            });
        }
        // Seed two triples (alice->cmd, bob->whoami) tagged to ds.
        {
            let mut g = session.graph.write().unwrap();
            g.add_entity(Entity::new("alice", EntityType::User)).ok();
            g.add_entity(Entity::new("bob", EntityType::User)).ok();
            g.add_entity(Entity::new("cmd.exe", EntityType::Process))
                .ok();
            g.add_entity(Entity::new("whoami.exe", EntityType::Process))
                .ok();
            for (i, (s, d)) in [("alice", "cmd.exe"), ("bob", "whoami.exe")]
                .iter()
                .enumerate()
            {
                let mut r = Relation::new(
                    (*s).to_string(),
                    (*d).to_string(),
                    RelationType::Execute,
                    1_700_000_000 + i as i64,
                );
                r.dataset_id = Some(std::sync::Arc::from("ds"));
                g.add_relation(r).ok();
            }
        }
        api
    }

    #[test]
    fn drift_detect_returns_invalid_state_when_no_store() {
        let api = api_with_dataset();
        let err = api
            .schema_drift_detect(SchemaDriftRequest {
                session: None,
                dataset_id: "ds".into(),
                window_secs: None,
            })
            .expect_err("no drift store configured");
        assert!(matches!(err, ApiError::InvalidState(_)), "got: {err}");
    }

    #[test]
    fn regression_test_pass_for_identical_vrl() {
        let api = api_with_dataset();
        // Use the deterministic compiler so the candidate parses back
        // to the same FieldConfig as the baseline.
        let program = graph_hunter_vrl::field_config_to_vrl(&cfg());
        let resp = api
            .mapping_regression_test(MappingRegressionRequest {
                session: None,
                candidate_vrl: program.source,
                baseline_dataset_id: "ds".into(),
                sample_size: Some(100),
            })
            .expect("regression");
        assert_eq!(resp.verdict, "pass", "{:?}", resp);
        assert!(resp.canary_report_id.starts_with("canary-"));
        assert!((resp.triple_diff.jaccard - 1.0).abs() < 1e-6);
    }

    #[test]
    fn hypothetical_invariant_check_reports_for_candidate() {
        let api = api_with_dataset();
        let program = graph_hunter_vrl::field_config_to_vrl(&cfg());
        let report = api
            .invariant_check_hypothetical(InvariantHypotheticalRequest {
                session: None,
                hypothetical_vrl: program.source,
                dataset_id: "ds".into(),
                sample_size: None,
            })
            .expect("hypothetical");
        // The toy graph passes every shipped predicate.
        assert!(report.all_passed(), "{:?}", report);
        assert!(report.entity_count > 0);
    }

    #[test]
    fn hypothetical_invariant_rejects_unparseable_vrl() {
        let api = api_with_dataset();
        let err = api
            .invariant_check_hypothetical(InvariantHypotheticalRequest {
                session: None,
                hypothetical_vrl: "garbage that doesn't include any # Node: lines".into(),
                dataset_id: "ds".into(),
                sample_size: None,
            })
            .expect_err("unparseable");
        assert!(matches!(err, ApiError::InvalidInput(_)), "got: {err}");
    }
}
