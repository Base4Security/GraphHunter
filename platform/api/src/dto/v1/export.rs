//! DTOs for export commands: subgraph, hunt results, IoC feeds.

use crate::state::SessionHandle;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportSubgraphRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub format: String,
    pub nodes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportHuntResultsRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<usize>,
    /// When true, collapses identical paths (DedupMode::ByPath).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregate: Option<bool>,
}

/// Export every triple in the session (or a single dataset) as OCSF v1.4
/// events with Graph Hunter's provenance extension. `format` is `"json"`
/// (single JSON array) or `"ndjson"` (one event per line).
///
/// 2026-05-06: `page_size` + `offset` added after a QA pass found
/// the unbounded path OOM'd the JS string limit on real sessions.
/// `page_size = None` now defaults to a 10 000-event cap; the
/// response includes a leading `_meta` line (NDJSON) or `_meta`
/// envelope (JSON) telling the caller how many events were returned
/// out of the full match set so they know whether to page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportOcsfRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    /// When set, only triples whose source entity belongs to this
    /// dataset are exported. `None` means export every dataset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_id: Option<String>,
    /// `"json"` → one JSON array; `"ndjson"` → newline-delimited events.
    pub format: String,
    /// Cap on returned events. `None` defaults to 10 000.  Hard
    /// ceiling 200 000 to keep memory bounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<usize>,
    /// Number of events to skip before starting the page. Used with
    /// `page_size` to walk a large session in chunks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportIocsRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub format: String,
    /// Defaults to `"ioc:"`. Pass `""` to include every tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag_prefix: Option<String>,
}
