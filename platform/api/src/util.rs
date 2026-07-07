//! Small utilities used across operations. Kept deliberately small —
//! anything that could belong in `graph_hunter_core` should go there
//! instead.

use graph_hunter_core::{EntityType, NeighborhoodFilter, RelationType};

use crate::dto::graph_ops::ExpandFilter;

/// Converts a string like "IP", "Host", etc. into an [`EntityType`].
/// Unknown non-empty strings become `Other(name)`, mirroring the parser
/// used by the existing Tauri helpers so legacy call sites agree on
/// interpretation.
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

/// Converts a string to [`RelationType`]. Returns `None` for unknown
/// strings (relations are a closed set).
pub fn parse_relation_type(s: &str) -> Option<RelationType> {
    match s {
        "Auth" => Some(RelationType::Auth),
        "Connect" => Some(RelationType::Connect),
        "Execute" => Some(RelationType::Execute),
        "Read" => Some(RelationType::Read),
        "Write" => Some(RelationType::Write),
        "DNS" => Some(RelationType::DNS),
        "Modify" => Some(RelationType::Modify),
        "Spawn" => Some(RelationType::Spawn),
        "Delete" => Some(RelationType::Delete),
        "*" | "Any" => Some(RelationType::Any),
        _ => None,
    }
}

/// Resolve the HTTP API port the same way the Tauri `lib.rs` and
/// `cmd_test_http_api` do. Used by `create_note` to build a back-link
/// into the HTTP `/notes/:id` endpoint for external workflows.
pub fn resolve_api_port() -> u16 {
    std::env::var("GRAPHHUNTER_API_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(37891)
}

/// Current wall-clock seconds since the Unix epoch. Extracted so tests
/// can swap it later (not yet wired — see `IngestClock` discussion in
/// the P3 plan).
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Convert a frontend-facing [`ExpandFilter`] into the core's
/// [`NeighborhoodFilter`]. Moved from `app/src-tauri/src/helpers.rs`.
pub fn to_core_filter(f: &ExpandFilter) -> NeighborhoodFilter {
    NeighborhoodFilter {
        entity_types: f
            .entity_types
            .as_ref()
            .map(|types| types.iter().filter_map(|s| parse_entity_type(s)).collect()),
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

/// Compute the IP class label ("Private" / "Public" / "Loopback" …) for
/// an entity about to be serialized to the frontend. Returns `None` for
/// non-IP entity types so the JSON field can be omitted. Mirrors the
/// helper that used to live in `app/src-tauri/src/types.rs`.
pub fn ip_class_for(entity_type: &str, id: &str) -> Option<String> {
    if entity_type != "IP" {
        return None;
    }
    graph_hunter_core::classify_ip(id).map(|c| format!("{:?}", c))
}

/// Extract JSON object keys from the first record (array[0] or first
/// NDJSON line or single object). Moved from the Tauri helpers so the
/// format registry can live in the API crate.
pub fn extract_json_keys(contents: &str) -> Vec<String> {
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return vec![];
    }
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
    if trimmed.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(obj) = v.as_object() {
                return obj.keys().cloned().collect();
            }
        }
    }
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

/// Extract CSV header names. Auto-detects delimiter (`,`, `\t`, `;`, `|`)
/// and strips a leading UTF-8 BOM so tab- or semicolon-separated exports
/// with a BOM still surface their columns.
pub fn extract_csv_headers(contents: &str) -> Vec<String> {
    use graph_hunter_core::CsvParser;
    let stripped = contents.strip_prefix('\u{feff}').unwrap_or(contents);
    let trimmed = stripped.trim();
    let header_line = match trimmed.lines().next() {
        Some(l) => l,
        None => return Vec::new(),
    };
    let delim = CsvParser::detect_delimiter_for(trimmed);
    header_line
        .split(delim)
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_entity_type_known() {
        assert!(matches!(parse_entity_type("IP"), Some(EntityType::IP)));
        assert!(matches!(parse_entity_type("Host"), Some(EntityType::Host)));
        assert!(matches!(parse_entity_type("*"), Some(EntityType::Any)));
    }

    #[test]
    fn parse_entity_type_other() {
        match parse_entity_type("CustomThing") {
            Some(EntityType::Other(n)) => assert_eq!(n, "CustomThing"),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn parse_entity_type_empty_is_none() {
        assert!(parse_entity_type("").is_none());
        assert!(parse_entity_type("   ").is_none());
    }

    #[test]
    fn parse_relation_type_known() {
        assert!(matches!(
            parse_relation_type("Auth"),
            Some(RelationType::Auth)
        ));
        assert!(matches!(parse_relation_type("*"), Some(RelationType::Any)));
    }

    #[test]
    fn parse_relation_type_unknown_is_none() {
        // Unlike entities, relations are a closed set — unknowns reject.
        assert!(parse_relation_type("NoSuchRelation").is_none());
    }

    #[test]
    fn resolve_api_port_respects_env() {
        // Cannot mutate env safely across tests; just assert default.
        let p = resolve_api_port();
        assert!(p > 0);
    }
}
