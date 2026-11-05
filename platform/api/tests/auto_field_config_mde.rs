//! Regression tests for the auto-FieldConfig node explosion on wide CSV
//! exports (MDE portal timeline, 65 columns).
//!
//! The one-shot ingest path (`load_data_streaming` → `auto_field_config_for`
//! → `ConfigurableParser`) promoted 38 of 65 columns to Node because the
//! name-heuristic suggestion outranked the canonical Skip verdict: ports
//! became IP nodes, command lines became one Process entity per unique
//! 600-char string, and creation-time columns became Process entities whose
//! IDs were timestamps. On a 13K-row export that meant minutes of CPU and
//! ~2 GB RSS — the UI's "se queda ingestando" hang.

use graph_hunter_api::operations::ingestion::auto_field_config_for;
use graph_hunter_core::FieldRole;

/// Header + two data rows lifted from a real MDE machine-timeline export
/// (values anonymized, shape preserved).
const MDE_SAMPLE: &str = "\
Event Time,Computer Name,Action Type,File Name,Folder Path,Sha256,Process Command Line,Account Name,Process Id,Process Creation Time,Remote Url,Remote IP,Remote Port,Local IP,Local Port,Initiating Process Command Line,Initiating Process Creation Time
2026-06-18T15:56:13.736,host1.corp.root,ProcessCreated,updater.exe,C:\\Program Files\\App,f5d2cd6f955b5c066707234562b1cd9983a32f3cfe3aca2c93b575dbd1d5b515,\"\"\"updater.exe\"\" --crash-handler --system --url=https://example.com/report --annotation=prod=Update4\",system,27008,2026-06-18T15:56:13.706,,52.229.170.60,443,10.0.0.5,50123,\"\"\"services.exe\"\"\",2026-06-18T08:46:48.589
2026-06-18T15:57:01.100,host1.corp.root,ConnectionSuccess,chrome.exe,C:\\Program Files\\Chrome,ab12cd6f955b5c066707234562b1cd9983a32f3cfe3aca2c93b575dbd1d5b515,\"\"\"chrome.exe\"\" --type=utility\",jperez,31001,2026-06-18T15:57:00.900,https://example.org/x,142.250.79.14,443,10.0.0.5,50124,\"\"\"explorer.exe\"\"\",2026-06-18T08:50:00.000
";

fn mapping<'a>(
    cfg: &'a graph_hunter_core::FieldConfig,
    raw: &str,
) -> &'a graph_hunter_core::FieldMapping {
    cfg.mappings
        .iter()
        .find(|m| m.raw_name == raw)
        .unwrap_or_else(|| panic!("no mapping for {raw}"))
}

#[test]
fn canonical_skip_beats_name_heuristic_suggestion() {
    let cfg = auto_field_config_for("csv", MDE_SAMPLE).expect("config");
    // Ports are connection metadata, never IP entities.
    for f in ["Remote Port", "Local Port"] {
        assert_eq!(
            mapping(&cfg, f).role,
            FieldRole::Metadata,
            "{f} must stay Metadata (canonical Skip), got Node"
        );
    }
    // Command lines are edge/anchor metadata, never one-entity-per-string.
    for f in ["Process Command Line", "Initiating Process Command Line"] {
        assert_eq!(
            mapping(&cfg, f).role,
            FieldRole::Metadata,
            "{f} must stay Metadata (canonical Skip), got Node"
        );
    }
    // Timestamps never become nodes.
    assert_eq!(mapping(&cfg, "Event Time").role, FieldRole::Metadata);
}

#[test]
fn timestamp_valued_columns_are_not_promoted_by_name() {
    let cfg = auto_field_config_for("csv", MDE_SAMPLE).expect("config");
    // "Process Creation Time" matches the name heuristic for Process, but
    // its values are timestamps — promoting it creates one Process entity
    // per timestamp value.
    for f in ["Process Creation Time", "Initiating Process Creation Time"] {
        assert_eq!(
            mapping(&cfg, f).role,
            FieldRole::Metadata,
            "{f} has timestamp values and must not become a Node"
        );
    }
}

#[test]
fn real_entity_columns_stay_promoted() {
    let cfg = auto_field_config_for("csv", MDE_SAMPLE).expect("config");
    for (f, et) in [
        ("Remote IP", "IP"),
        ("Local IP", "IP"),
        ("Account Name", "User"),
        ("Computer Name", "Host"),
        ("Remote Url", "URL"),
    ] {
        let m = mapping(&cfg, f);
        assert_eq!(m.role, FieldRole::Node, "{f} must stay Node");
        assert_eq!(m.entity_type.as_deref(), Some(et), "{f} type");
    }
}
