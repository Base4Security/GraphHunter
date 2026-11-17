//! Attack-graph edges projected from the ingestion journal.
//!
//! Replays the canonical journal (`journal.rs`) through the projection rule
//! (`graph_hunter_attack_projection`, spec in
//! `docs/unificacion/proyeccion-procedencia-ataque.md`) and returns the edges
//! alive at a watermark. A replay rather than a projector kept on the
//! session: the projector's state is a function of the journal alone, so
//! nothing new is persisted and the session format is untouched. Identities
//! come with the request, because they are what a BloodHound collection
//! knows and the logs do not.

use std::collections::BTreeMap;

use graph_hunter_attack_projection::ingest::projection_input;
use graph_hunter_attack_projection::{AttackDelta, Identities, Params, Projector};
use graph_hunter_canonical::CanonicalEnvelope;
use serde_json::Value;

use crate::dto::attack_graph::{AttackEdgeView, AttackEdgesRequest, AttackEdgesResponse};
use crate::{ApiError, ApiResult, GraphHunterApi};

impl GraphHunterApi {
    /// Attack edges derived from everything journaled so far. An empty
    /// response when the journal is off or has never been written.
    pub fn attack_edges(&self, req: AttackEdgesRequest) -> ApiResult<AttackEdgesResponse> {
        let dir = crate::journal::ingest_journal_dir()
            .ok_or_else(|| ApiError::Internal("could not resolve app data directory".into()))?;
        if !dir.exists() {
            return Ok(attack_edges_from(&[], &req));
        }
        let envelopes = crate::journal::JournalStore::open(&dir)
            .and_then(|s| s.read_all())
            .map_err(|e| ApiError::Internal(format!("journal read failed: {e}")))?;
        Ok(attack_edges_from(&envelopes, &req))
    }
}

/// The projection of `envelopes`, in journal order, judged at the request's
/// watermark.
pub fn attack_edges_from(
    envelopes: &[CanonicalEnvelope],
    req: &AttackEdgesRequest,
) -> AttackEdgesResponse {
    let inputs: Vec<Value> = envelopes
        .iter()
        .filter(|e| {
            req.dataset_id
                .as_deref()
                .is_none_or(|d| e.provenance.source_dataset_id == d)
        })
        .filter_map(projection_input)
        .collect();
    let params = req
        .params
        .as_ref()
        .map(Params::from_json)
        .unwrap_or_default();
    let mut projector = Projector::new(Identities::from_json(&req.identities), params);
    let mut unresolved: BTreeMap<String, usize> = BTreeMap::new();
    for input in &inputs {
        for delta in projector.apply(input) {
            if let AttackDelta::Unresolved { reason, .. } = delta {
                *unresolved.entry(reason.to_string()).or_default() += 1;
            }
        }
    }
    let watermark_ms = req.watermark_ms.unwrap_or_else(|| {
        inputs
            .iter()
            .filter_map(|i| i.pointer("/ocsf/time").and_then(Value::as_i64))
            .max()
            .unwrap_or(0)
    });
    let mut edges: Vec<AttackEdgeView> = projector
        .live(watermark_ms)
        .map(|(e, s)| AttackEdgeView {
            src: e.src.clone(),
            kind: e.kind.clone(),
            dst: e.dst.clone(),
            confidence: s
                .confidence
                .and_then(|c| serde_json::to_value(c).ok())
                .and_then(|v| v.as_str().map(str::to_string)),
            expires_at: s.expires_at,
            support: s.support.iter().cloned().collect(),
        })
        .collect();
    edges.sort_by(|a, b| (&a.src, &a.kind, &a.dst).cmp(&(&b.src, &b.kind, &b.dst)));
    AttackEdgesResponse {
        watermark_ms,
        envelopes: inputs.len(),
        edges,
        unresolved,
    }
}
