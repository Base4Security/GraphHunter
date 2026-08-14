//! Invariant checker operation (M2 D3).
//!
//! Reads the current session graph (optionally filtered to a single
//! dataset), snapshots it, and runs the shipped first-order predicates
//! plus the treewidth heuristic from `graph_hunter_core::invariants`.
//! The returned report is structurally stable so the MCP tool and the
//! UI badge can consume the same wire shape.

use graph_hunter_core::invariants::{
    InvariantReport, MAX_INVARIANT_RELATIONS, Scope, check_invariants,
};

use crate::dto::invariants::CheckInvariantsRequest;
use crate::{ApiError, ApiResult, GraphHunterApi};

impl GraphHunterApi {
    /// Run the invariant checker over the session (or a single dataset)
    /// and return a structured report with per-predicate results plus
    /// a treewidth upper bound.
    pub fn check_invariants(&self, req: CheckInvariantsRequest) -> ApiResult<InvariantReport> {
        // 2026-05-06: validate dataset_id exists before scoping. The
        // old behavior was a fail-silent vacuum: an invalid id (e.g.
        // a typo) returned `passed: true, checked: 0` for every
        // predicate. Analyst couldn't tell apart "all clean" from
        // "you queried nothing". Now we 400 with the actual dataset
        // list so the caller can fix the typo.
        let scope = match req.dataset_id {
            Some(id) => {
                let session = self.resolve_session(req.session.as_ref())?;
                let datasets = session
                    .datasets
                    .read()
                    .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
                if !datasets.iter().any(|d| d.id == id) {
                    let known: Vec<String> = datasets.iter().map(|d| d.id.clone()).collect();
                    return Err(ApiError::InvalidInput(format!(
                        "dataset `{id}` not in current session (known: [{}])",
                        known.join(", ")
                    )));
                }
                Scope::Dataset(id)
            }
            None => Scope::Session,
        };
        self.with_graph_read(req.session.as_ref(), |graph| {
            // Guard before `to_snapshot()`: that call materializes every
            // edge as an owned `Relation` (~144 B), and `check_invariants`
            // clones the in-scope subset again. On a multi-GB ingest (tens
            // of millions of relations) the two copies need >9 GB and abort
            // the process. Above the ceiling, return an all-skipped report
            // instead of snapshotting. See `MAX_INVARIANT_RELATIONS`.
            let relation_count = graph.relation_count();
            if relation_count > MAX_INVARIANT_RELATIONS {
                return Ok(InvariantReport::skipped_too_large(
                    scope,
                    graph.entity_count(),
                    relation_count,
                ));
            }
            let (entities, relations) = graph.to_snapshot();
            Ok(check_invariants(&entities, &relations, scope))
        })
    }
}
