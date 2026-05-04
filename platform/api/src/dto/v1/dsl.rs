//! DTOs for DSL and catalog operations.
//!
//! These are stateless — they don't carry a [`crate::dto::SessionScope`]
//! because parsing DSL and listing the catalog doesn't touch session state.
//! `catalog_with_status` (which does need the current graph schema) is
//! defined separately once the `Session` type exists.

use crate::state::SessionHandle;
use graph_hunter_core::{CatalogEntry, CatalogEntryWithStatus, CatalogLoadError, Hypothesis};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseDslRequest {
    pub input: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Canonical response shape for a successful DSL parse.
///
/// Tauri today returns `DslResult { hypothesis, formatted }` (`types.rs:155`).
/// HTTP today returns `{valid, formatted, steps}` with `valid=false` on
/// parse failure (`http_api.rs:1479`). The canonical shape is a strict
/// superset: parse failures become `ApiError::InvalidInput` (so transports
/// can map to 400) while successful parses carry the full hypothesis plus
/// the `steps` count for HTTP/MCP clients that want it inline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseDslResponse {
    pub hypothesis: Hypothesis,
    pub formatted: String,
    pub steps: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadCatalogHypothesisRequest {
    pub catalog_id: String,
}

/// Response for `get_catalog` — the full built-in catalog list. No
/// request type because it takes no parameters.
pub type GetCatalogResponse = Vec<CatalogEntry>;

/// Request for `get_catalog_with_status`. Resolves against the current
/// session when `session` is omitted.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GetCatalogWithStatusRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
}

/// Response is the list of catalog entries paired with a per-entry
/// compatibility report against the resolved session's graph schema.
pub type GetCatalogWithStatusResponse = Vec<CatalogEntryWithStatus>;

/// Response for `get_catalog_diagnostics` — the list of load errors the
/// catalog loader encountered at startup. Empty when every built-in and
/// user YAML parsed+validated successfully. When non-empty, the UI can
/// surface a warning banner pointing at the offending files so the
/// analyst can fix them instead of silently losing catalog entries.
pub type GetCatalogDiagnosticsResponse = Vec<CatalogLoadError>;
