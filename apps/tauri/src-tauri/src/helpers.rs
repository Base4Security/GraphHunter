use graph_hunter_core::{EntityType, NeighborhoodFilter};

use crate::types::ExpandFilter;

// `CreatedNote` moved to `graph_hunter_api::dto::entity`. Re-exported here
// so call sites that `use crate::helpers::CreatedNote` keep compiling.
pub use graph_hunter_api::dto::entity::CreatedNote;

/// Extract a JSON string value from a partial JSON prefix (e.g. first 4KB).
pub fn extract_json_string(text: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let idx = text.find(&pattern)?;
    let after_key = &text[idx + pattern.len()..];
    let colon = after_key.find(':')?;
    let after_colon = after_key[colon + 1..].trim_start();
    if !after_colon.starts_with('"') {
        return None;
    }
    let content = &after_colon[1..];
    let end = content.find('"')?;
    Some(content[..end].to_string())
}

/// Extract a JSON integer value from a partial JSON prefix.
pub fn extract_json_i64(text: &str, key: &str) -> Option<i64> {
    let pattern = format!("\"{}\"", key);
    let idx = text.find(&pattern)?;
    let after_key = &text[idx + pattern.len()..];
    let colon = after_key.find(':')?;
    let after_colon = after_key[colon + 1..].trim_start();
    let end = after_colon.find(|c: char| !c.is_ascii_digit() && c != '-')?;
    after_colon[..end].parse().ok()
}

/// Extracts JSON object keys from the first record (array[0] or first NDJSON line or single object).
pub fn extract_json_keys(contents: &str) -> Vec<String> {
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return vec![];
    }
    // Try array first
    if trimmed.starts_with('[') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(arr) = v.as_array() {
                if let Some(first) = arr.first() {
                    if let Some(obj) = first.as_object() {
                        return obj.keys().cloned().collect();
                    }
                }
            }
        }
    }
    // Single object
    if trimmed.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(obj) = v.as_object() {
                return obj.keys().cloned().collect();
            }
        }
    }
    // NDJSON: first line
    if let Some(first_line) = trimmed.lines().next() {
        let line = first_line.trim();
        if line.starts_with('{') {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                if let Some(obj) = v.as_object() {
                    return obj.keys().cloned().collect();
                }
            }
        }
    }
    vec![]
}

/// Extracts CSV header names (first line, simple split by comma).
pub fn extract_csv_headers(contents: &str) -> Vec<String> {
    let trimmed = contents.trim();
    trimmed
        .lines()
        .next()
        .map(|line| {
            line.split(',')
                .map(|s| s.trim().trim_matches('"').to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Converts a string like "IP", "Host", etc. to EntityType. Unknown non-empty strings become Other(name).
pub fn parse_entity_type(s: &str) -> Option<EntityType> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    match t {
        "IP" => Some(EntityType::IP),
        "Host" => Some(EntityType::Host),
        "User" => Some(EntityType::User),
        "Process" => Some(EntityType::Process),
        "File" => Some(EntityType::File),
        "Domain" => Some(EntityType::Domain),
        "Registry" => Some(EntityType::Registry),
        "URL" => Some(EntityType::URL),
        "Service" => Some(EntityType::Service),
        "*" | "Any" => Some(EntityType::Any),
        _ => Some(EntityType::Other(t.to_string())),
    }
}

/// Converts a string to RelationType.
pub fn parse_relation_type(s: &str) -> Option<graph_hunter_core::RelationType> {
    match s {
        "Auth" => Some(graph_hunter_core::RelationType::Auth),
        "Connect" => Some(graph_hunter_core::RelationType::Connect),
        "Execute" => Some(graph_hunter_core::RelationType::Execute),
        "Read" => Some(graph_hunter_core::RelationType::Read),
        "Write" => Some(graph_hunter_core::RelationType::Write),
        "DNS" => Some(graph_hunter_core::RelationType::DNS),
        "Modify" => Some(graph_hunter_core::RelationType::Modify),
        "Spawn" => Some(graph_hunter_core::RelationType::Spawn),
        "Delete" => Some(graph_hunter_core::RelationType::Delete),
        "*" | "Any" => Some(graph_hunter_core::RelationType::Any),
        _ => None,
    }
}

/// Converts frontend ExpandFilter to core NeighborhoodFilter.
pub fn to_core_filter(f: &ExpandFilter) -> NeighborhoodFilter {
    NeighborhoodFilter {
        entity_types: f.entity_types.as_ref().map(|types| {
            types.iter().filter_map(|s| parse_entity_type(s)).collect()
        }),
        relation_types: f.relation_types.as_ref().map(|types| {
            types
                .iter()
                .filter_map(|s| parse_relation_type(s))
                .collect()
        }),
        time_start: f.time_start,
        time_end: f.time_end,
        min_score: f.min_score,
    }
}

// `with_current_session`, `with_current_session_and_graph`,
// `with_current_graph`, `with_current_graph_mut` all removed in P1
// Fase 2. Every command now goes through `Arc<GraphHunterApi>` and
// uses `api.sessions().current_session()` / the per-operation helpers
// `api.with_graph_read` / `api.with_graph_write`. The AppState-backed
// helpers are therefore dead code.

/// Resolve the HTTP API port the same way the server binding does.
/// Matches the logic in `lib.rs` and `cmd_test_http_api`. Forwards to the
/// canonical implementation in `graph_hunter_api::util` to avoid drift.
pub fn resolve_api_port() -> u16 {
    graph_hunter_api::util::resolve_api_port()
}

// `create_note_impl` removed — call sites now delegate through
// `GraphHunterApi::create_note` (see `commands/entity.rs` and
// `http_api.rs::handler_create_note`).
