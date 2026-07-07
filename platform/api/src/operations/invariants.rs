//! Invariant checker operation (M2 D3).
//!
//! Reads the current session graph (optionally filtered to a single
//! dataset), snapshots it, and runs the shipped first-order predicates
//! plus the treewidth heuristic from `graph_hunter_core::invariants`.
//! The returned report is structurally stable so the MCP tool and the
//! UI badge can consume the same wire shape.

use graph_hunter_core::invariants::{InvariantReport, Scope, check_invariants};

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
            let (entities, relations) = graph.to_snapshot();
            Ok(check_invariants(&entities, &relations, scope))
        })
    }
}
