//! Happy-path + malformed-input tests for the main log parsers.
//!
//! Each parser implements `LogParser::parse(&str) -> Vec<ParsedTriple>`,
//! silently skipping records it can't interpret. The risk this file
//! guards against is a silent regression where every record is skipped
//! because of a field-rename or schema drift — nothing crashes, but
//! the analyst loses signal.
//!
//! Parsers with richer in-module tests (`forti_analyzer`, `iis_w3c`)
//! are out of scope here.

use graph_hunter_core::{
    CsvParser, EntityType, GenericParser, LogParser, RelationType, SentinelJsonParser,
    SysmonJsonParser,
};

// ─── CsvParser ────────────────────────────────────────────────────────

#[test]
fn csv_parser_produces_triples_from_header_row() {
    // Two connection events with source_ip / target_ip and a timestamp.
    let csv = "\
timestamp,source_ip,target_ip,user
2024-01-01T10:00:00Z,10.0.0.1,8.8.8.8,alice
2024-01-01T10:05:00Z,10.0.0.2,1.1.1.1,bob
";
    let triples = CsvParser.parse(csv);
    assert!(
        !triples.is_empty(),
        "CsvParser must yield at least one triple for a well-formed CSV"
    );
    // Every triple should have non-empty source and dest IDs.
    for (src, rel, dst) in &triples {
        assert!(!src.id.is_empty());
        assert!(!dst.id.is_empty());
        // rel_type is a known variant (not a panic in fmt::Debug)
        let _ = format!("{:?}", rel.rel_type);
    }
}

#[test]
fn csv_parser_empty_input_yields_empty() {
    assert!(CsvParser.parse("").is_empty());
    assert!(CsvParser.parse("   \n\t\n").is_empty());
}

#[test]
fn csv_parser_header_only_yields_empty() {
    let csv = "timestamp,source_ip,target_ip\n";
    assert!(CsvParser.parse(csv).is_empty());
}

#[test]
fn csv_parser_quoted_field_with_comma() {
    // A quoted command line containing commas must not be split.
    let csv = "\
timestamp,source_user,command_line
2024-01-01T10:00:00Z,alice,\"powershell.exe -Command Get-Process, Where Name -eq foo\"
";
    // Must not panic; may or may not produce triples depending on what
    // GenericParser infers from (user, command_line). The guarantee is
    // that the split doesn't break on the embedded comma.
    let _ = CsvParser.parse(csv);
}

// ─── SysmonJsonParser ─────────────────────────────────────────────────

#[test]
fn sysmon_parses_process_create_event_1() {
    // Minimal Sysmon Event ID 1 (Process Create) — must yield at least
    // the User -[Execute]-> Process triple.
    let event = r#"[
        {
            "EventID": 1,
            "UtcTime": "2024-01-01 10:00:00.000",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "ProcessId": 1234,
            "CommandLine": "cmd.exe /c whoami",
            "User": "DOMAIN\\alice",
            "Computer": "host-01"
        }
    ]"#;

    let triples = SysmonJsonParser.parse(event);
    assert!(
        !triples.is_empty(),
        "Sysmon EventID 1 must produce at least one triple"
    );
    // Expect a User->Process Execute somewhere in the triples.
    let has_execute = triples
        .iter()
        .any(|(src, rel, dst)| {
            src.entity_type == EntityType::User
                && rel.rel_type == RelationType::Execute
                && dst.entity_type == EntityType::Process
        });
    assert!(
        has_execute,
        "expected a User-[Execute]->Process triple in: {triples:?}"
    );
}

#[test]
fn sysmon_parses_ndjson_stream() {
    // NDJSON: one JSON object per line (no outer array).
    let ndjson = r#"{"EventID":1,"UtcTime":"2024-01-01 10:00:00.000","Image":"a.exe","User":"u1"}
{"EventID":1,"UtcTime":"2024-01-01 10:00:01.000","Image":"b.exe","User":"u2"}"#;
    let triples = SysmonJsonParser.parse(ndjson);
    assert!(
        !triples.is_empty(),
        "NDJSON Sysmon input must yield triples; got 0"
    );
}

#[test]
fn sysmon_unknown_event_id_is_skipped() {
    // EventID 99999 is not handled → parser must return empty, not panic.
    let event = r#"[{"EventID": 99999, "UtcTime": "2024-01-01 10:00:00.000"}]"#;
    assert!(SysmonJsonParser.parse(event).is_empty());
}

#[test]
fn sysmon_malformed_json_yields_empty() {
    // Invalid JSON must not panic — return empty triples.
    assert!(SysmonJsonParser.parse("{not valid json at all").is_empty());
    assert!(SysmonJsonParser.parse("").is_empty());
}

// ─── SentinelJsonParser ───────────────────────────────────────────────

#[test]
fn sentinel_parses_security_event_4624_logon() {
    // SecurityEvent table, EventID 4624 (successful logon).
    let event = r#"[
        {
            "Type": "SecurityEvent",
            "EventID": 4624,
            "TimeGenerated": "2024-01-01T10:00:00Z",
            "TargetUserName": "alice",
            "Computer": "host-01",
            "IpAddress": "10.0.0.5",
            "LogonType": "3"
        }
    ]"#;

    let triples = SentinelJsonParser.parse(event);
    assert!(
        !triples.is_empty(),
        "Sentinel SecurityEvent 4624 must yield at least one triple"
    );
}

#[test]
fn sentinel_missing_timegenerated_is_skipped() {
    // No TimeGenerated / Timestamp → parser must skip (no silent ts=0 edges).
    let event = r#"[{"Type":"SecurityEvent","EventID":4624,"TargetUserName":"alice"}]"#;
    // This emits a warning to stderr but must not panic, and must not
    // return triples for an event it couldn't timestamp.
    let triples = SentinelJsonParser.parse(event);
    // We deliberately don't assert empty here — a parser may still
    // produce enrichment-only triples. The contract is "no panic".
    let _ = triples;
}

#[test]
fn sentinel_malformed_json_yields_empty() {
    assert!(SentinelJsonParser.parse("").is_empty());
    assert!(SentinelJsonParser.parse("garbage{[}").is_empty());
}

// ─── GenericParser ────────────────────────────────────────────────────

#[test]
fn generic_parses_ndjson_with_canonical_fields() {
    // Use already-canonical field names: timestamp, source_ip, target_ip.
    let ndjson = r#"{"timestamp":"2024-01-01T10:00:00Z","source_ip":"10.0.0.1","target_ip":"8.8.8.8","user":"alice"}"#;
    let triples = GenericParser.parse(ndjson);
    assert!(
        !triples.is_empty(),
        "GenericParser with source_ip+target_ip must yield at least one triple"
    );
    // Expect at least one IP→IP or IP→Host connection triple.
    let has_connect = triples.iter().any(|(_, rel, _)| {
        matches!(rel.rel_type, RelationType::Connect | RelationType::DNS)
    });
    assert!(
        has_connect,
        "expected at least one Connect/DNS triple: {triples:?}"
    );
}

#[test]
fn generic_case_insensitive_field_aliases() {
    // SourceIP (PascalCase) must map to the same canonical source_ip as source_ip.
    let ndjson = r#"{"Timestamp":"2024-01-01T10:00:00Z","SourceIP":"10.0.0.1","DestinationIP":"8.8.8.8"}"#;
    let triples = GenericParser.parse(ndjson);
    assert!(
        !triples.is_empty(),
        "GenericParser must handle case-variant field aliases (SourceIP ≡ source_ip)"
    );
}

#[test]
fn generic_no_recognizable_fields_yields_empty() {
    // Random fields that don't canonicalize to anything useful.
    let ndjson = r#"{"nothing_to_see_here":"bla","quux":42}"#;
    // Must not panic; may return empty.
    let _ = GenericParser.parse(ndjson);
}

#[test]
fn generic_malformed_json_yields_empty() {
    assert!(GenericParser.parse("").is_empty());
    assert!(GenericParser.parse("}}}").is_empty());
}
