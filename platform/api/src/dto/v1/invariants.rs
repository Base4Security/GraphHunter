//! DTO for the invariant checker (M2 D3).
//!
//! The response type reuses `graph_hunter_core::invariants::InvariantReport`
//! directly via `#[serde(transparent)]`-like re-export: callers serialise
//! a core struct, no copy required. Only the request shape lives here.

use serde::{Deserialize, Serialize};

use crate::state::SessionHandle;

/// Request body for `check_invariants`. When `dataset_id` is set, the
/// check runs against only that dataset's entities and relations; when
/// omitted, it runs against the full session.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CheckInvariantsRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_id: Option<String>,
}
