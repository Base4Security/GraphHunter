//! Invariant checker operation (M2 D3).
//!
//! Reads the current session graph (optionally filtered to a single
//! dataset), snapshots it, and runs the shipped first-order predicates
//! plus the treewidth heuristic from `graph_hunter_core::invariants`.
//! The returned report is structurally stable so the MCP tool and the
//! UI badge can consume the same wire shape.

use graph_hunter_core::invariants::{InvariantReport, Scope, check_invariants};

use crate::dto::invariants::CheckInvariantsRequest;
use crate::{ApiResult, GraphHunterApi};

impl GraphHunterApi {
    /// Run the invariant checker over the session (or a single dataset)
    /// and return a structured report with per-predicate results plus
    /// a treewidth upper bound.
    pub fn check_invariants(&self, req: CheckInvariantsRequest) -> ApiResult<InvariantReport> {
        let scope = match req.dataset_id {
            Some(id) => Scope::Dataset(id),
            None => Scope::Session,
        };
        self.with_graph_read(req.session.as_ref(), |graph| {
            let (entities, relations) = graph.to_snapshot();
            Ok(check_invariants(&entities, &relations, scope))
        })
    }
}
