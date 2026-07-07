//! Regression: preview defaults for canonical fields.
//!
//! When a column is canonical (e.g. `EVENT_BY` → `source_user`) but
//! the name-heuristic in `suggest_entity_type` doesn't match (the word
//! "event_by" contains none of "user"/"account"/"actor"), the preview
//! must still suggest the canonical entity type ("User"), not the raw
//! column name. Defaulting to the raw name silently diverges from the
//! canonical default, which trips the override-strip path in
//! `ConfigurableParser::apply_timestamp_hints` and causes the field
//! to be removed from the event — leaving anchor detection to fall
//! through to source_ip and producing the "everything connects to IP"
//! shape the analyst saw with the Zoho audit CSV.

use graph_hunter_api::GraphHunterApi;
use graph_hunter_api::dto::ingestion::PreviewIngestRequest;
use std::io::Write;

/// EVENT_BY + IP_ADDRESS columns: canonical aliases that don't match
/// the heuristic. Preview must still default to User / IP.
#[test]
fn preview_defaults_canonical_fields_to_canonical_entity_type() {
    let csv = "TIME,EVENT_BY,IP_ADDRESS,EVENT\n\
               2026-04-19T09:29:00Z,Joel Canepa,10.0.0.5,login\n\
               2026-04-19T09:30:00Z,Carlos null,10.0.0.6,logout\n";

    let mut tmp = tempfile::NamedTempFile::with_suffix(".csv").expect("temp file");
    tmp.write_all(csv.as_bytes()).expect("write csv");
    let path = tmp.path().to_string_lossy().to_string();

    let api = GraphHunterApi::new_noop();
    let result = api
        .preview_ingest(PreviewIngestRequest {
            path,
            format: "csv".to_string(),
        })
        .expect("preview must succeed");

    let by_name: std::collections::HashMap<&str, &str> = result
        .detected_fields
        .iter()
        .map(|d| (d.field_name.as_str(), d.suggested_entity_type.as_str()))
        .collect();

    assert_eq!(
        by_name.get("EVENT_BY").copied(),
        Some("User"),
        "EVENT_BY is a canonical alias for source_user — must default to User, \
         not the raw column name (caused the strip path + 'everything connects \
         to IP' bug)"
    );
    assert_eq!(
        by_name.get("IP_ADDRESS").copied(),
        Some("IP"),
        "IP_ADDRESS is a canonical alias — must default to IP"
    );
    assert_eq!(
        by_name.get("TIME").copied(),
        Some("Skip"),
        "TIME maps to canonical timestamp — must stay Skip (edge metadata)"
    );
    assert_eq!(
        by_name.get("EVENT").copied(),
        Some("EVENT"),
        "EVENT is not canonical and the heuristic doesn't match — fall back \
         to the raw column name as a custom entity type"
    );
}
