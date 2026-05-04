//! F4 — per-source fixture suite (Sysmon / Sentinel / FortiAnalyzer).
//!
//! Runs the three shipping parsers against a fixed 6-variant matrix of
//! raw events and validates that the produced triples project cleanly
//! into schema-valid OCSF. The intent is not to re-test the parsers
//! themselves (their unit tests already do that) but to pin the
//! contract "parser output → canonical projection" source-by-source so
//! a future refactor that drops a source or changes its emission shape
//! surfaces here.
//!
//! The 6 variants per source:
//!   1. **valid**            — happy-path row; must yield ≥1 triple that
//!                             projects to a schema-valid OCSF event.
//!   2. **bad timestamp**    — garbled/empty timestamp field; parser
//!                             skips or falls back cleanly (no panic;
//!                             triples either empty or annotated).
//!   3. **missing field**    — a row missing a key identifier the
//!                             parser needs; produces zero triples
//!                             instead of fabricating an empty-string
//!                             node.
//!   4. **wrong type**       — a field with the wrong JSON type (e.g.
//!                             number where the parser reads a string);
//!                             parser skips without panicking.
//!   5. **unmappable**       — syntactically valid but semantically
//!                             unsupported (unknown EventID for
//!                             Sysmon/Sentinel, or an empty report for
//!                             Forti); yields no data triples.
//!   6. **metadata preserved** — raw fields that carry into entity /
//!                             relation metadata survive the round-trip
//!                             into the OCSF projection.
//!
//! Forti's "empty" case ships a single self-loop ReportContext per the
//! `empty_report_still_emits_context_entity` contract in its unit
//! tests, not an empty Vec — we treat that shape as its unmappable.

use graph_hunter_canonical::{OCSF_V1_4_SCHEMA, OcsfEvent, ProvenanceCtx, triple_to_ocsf};
use graph_hunter_core::parser::{LogParser, ParsedTriple};
use graph_hunter_core::{SentinelJsonParser, SysmonJsonParser};
use graph_hunter_parsers::FortiAnalyzerXmlParser;
use jsonschema::JSONSchema;
use serde_json::Value;

fn compiled_schema() -> JSONSchema {
    let schema: Value = serde_json::from_str(OCSF_V1_4_SCHEMA).expect("schema parses");
    JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft7)
        .compile(&schema)
        .expect("schema compiles")
}

fn assert_projects_cleanly(schema: &JSONSchema, triples: &[ParsedTriple], parser: &str) {
    assert!(
        !triples.is_empty(),
        "{parser}: expected at least one triple for the valid variant"
    );
    for (src, rel, dst) in triples {
        let prov = ProvenanceCtx::for_builtin_parser(parser, "ds-fixture", b"<raw>");
        let ev: OcsfEvent = triple_to_ocsf(src, rel, dst, &prov);
        let serialized = serde_json::to_value(&ev).expect("ocsf serializes");
        if let Err(errors) = schema.validate(&serialized) {
            let msgs: Vec<String> = errors
                .map(|e| format!("{}: {}", e.instance_path, e))
                .collect();
            panic!(
                "{parser}: OCSF event failed schema validation:\n  event={}\n  errors={:?}",
                serde_json::to_string_pretty(&serialized).unwrap(),
                msgs
            );
        }
    }
}

// ========================================================================
// Sysmon (6 variants)
// ========================================================================
mod sysmon {
    use super::*;

    /// Variant 1 — valid Sysmon Event ID 1 (process creation). Must
    /// produce at least one triple that clears the OCSF schema.
    #[test]
    fn variant1_valid_process_create() {
        let schema = compiled_schema();
        // Single-line so the NDJSON branch of SysmonJsonParser parses it.
        let raw = r#"{"EventID":1,"UtcTime":"2024-01-15 14:30:00.123","User":"DOMAIN\\alice","Image":"C:\\Windows\\System32\\cmd.exe","ParentImage":"C:\\Windows\\explorer.exe","ProcessId":1234,"CommandLine":"cmd.exe /c whoami"}"#;
        let triples = SysmonJsonParser.parse(raw);
        assert_projects_cleanly(&schema, &triples, "sysmon");
    }

    /// Variant 2 — bad timestamp. UtcTime is non-parseable. The parser
    /// falls back to timestamp=0 rather than panicking; the row still
    /// produces triples so the downstream analyst sees the event.
    /// The sentinel value 0 is an explicit signal for drift tooling.
    #[test]
    fn variant2_bad_timestamp_falls_back_to_zero() {
        let raw = r#"{"EventID":1,"UtcTime":"not-a-real-date","User":"alice","Image":"cmd.exe"}"#;
        let triples = SysmonJsonParser.parse(raw);
        // Contract: bad timestamp is tolerated but marked (ts=0) — the
        // alternative "drop the row" was rejected for losing evidence.
        for (_, rel, _) in &triples {
            assert_eq!(
                rel.timestamp, 0,
                "bad-ts row should carry sentinel timestamp 0"
            );
        }
    }

    /// Variant 3 — missing required field (Image). The process-create
    /// handler refuses to fabricate an empty-string Process node.
    #[test]
    fn variant3_missing_image_produces_no_triples() {
        let raw = r#"{"EventID":1,"UtcTime":"2024-01-15 14:30:00","User":"alice"}"#;
        let triples = SysmonJsonParser.parse(raw);
        assert!(
            triples.is_empty(),
            "event 1 without Image should yield 0 triples; got {}",
            triples.len()
        );
    }

    /// Variant 4 — wrong type on EventID. Sysmon requires integer;
    /// a string "one" must skip, not panic.
    #[test]
    fn variant4_wrong_type_event_id_is_skipped() {
        let raw =
            r#"{"EventID":"one","UtcTime":"2024-01-15 14:30:00","User":"alice","Image":"cmd.exe"}"#;
        let triples = SysmonJsonParser.parse(raw);
        assert!(
            triples.is_empty(),
            "non-integer EventID should be rejected, got {} triples",
            triples.len()
        );
    }

    /// Variant 5 — unmappable event. Sysmon 999 is not a known event;
    /// the handler catalogue returns empty Vec rather than a generic
    /// placeholder.
    #[test]
    fn variant5_unmappable_event_id_yields_nothing() {
        let raw =
            r#"{"EventID":999,"UtcTime":"2024-01-15 14:30:00","User":"alice","Image":"cmd.exe"}"#;
        let triples = SysmonJsonParser.parse(raw);
        assert!(
            triples.is_empty(),
            "unknown EventID 999 should produce 0 triples; got {}",
            triples.len()
        );
    }

    /// Variant 6 — metadata preservation. The CommandLine + ProcessId
    /// fields must ride along the process entity so the OCSF projection
    /// can surface them; losing them here would break the analyst
    /// drill-down in the UI.
    #[test]
    fn variant6_metadata_preserved_on_process_entity() {
        let raw = r#"{"EventID":1,"UtcTime":"2024-01-15 14:30:00","User":"alice","Image":"cmd.exe","ProcessId":4242,"CommandLine":"cmd.exe /c net user"}"#;
        let triples = SysmonJsonParser.parse(raw);
        let found_cmd = triples.iter().any(|(_, _, dst)| {
            dst.metadata.get("cmdline").map(|s| s.as_str()) == Some("cmd.exe /c net user")
        });
        let found_pid = triples
            .iter()
            .any(|(_, _, dst)| dst.metadata.get("pid").map(|s| s.as_str()) == Some("4242"));
        assert!(
            found_cmd,
            "cmdline metadata should survive on a child Process entity"
        );
        assert!(
            found_pid,
            "pid metadata should survive on a child Process entity"
        );
    }
}

// ========================================================================
// Sentinel (6 variants)
// ========================================================================
mod sentinel {
    use super::*;

    /// Variant 1 — valid SecurityEvent 4624 (logon success).
    #[test]
    fn variant1_valid_security_event_logon() {
        let schema = compiled_schema();
        let raw = r#"[{
            "Type": "SecurityEvent",
            "TimeGenerated": "2024-01-15T14:30:00Z",
            "EventID": 4624,
            "TargetUserName": "alice",
            "Computer": "WORKSTATION-01",
            "IpAddress": "10.0.0.42",
            "LogonType": 3
        }]"#;
        let triples = SentinelJsonParser.parse(raw);
        assert_projects_cleanly(&schema, &triples, "sentinel");
    }

    /// Variant 2 — bad timestamp. Contract: drop the row, don't forge a
    /// fake timestamp. Losing signal here is safer than corrupting the
    /// timeline.
    #[test]
    fn variant2_bad_timestamp_drops_row() {
        let raw = r#"[{
            "Type": "SecurityEvent",
            "TimeGenerated": "15 de enero",
            "EventID": 4624,
            "TargetUserName": "alice",
            "Computer": "WORKSTATION-01"
        }]"#;
        let triples = SentinelJsonParser.parse(raw);
        assert!(
            triples.is_empty(),
            "unparseable TimeGenerated must drop row; got {} triples",
            triples.len()
        );
    }

    /// Variant 3 — missing Computer (host target). The 4624 handler
    /// cannot produce an Auth triple without a destination host.
    #[test]
    fn variant3_missing_computer_yields_nothing() {
        let raw = r#"[{
            "Type": "SecurityEvent",
            "TimeGenerated": "2024-01-15T14:30:00Z",
            "EventID": 4624,
            "TargetUserName": "alice"
        }]"#;
        let triples = SentinelJsonParser.parse(raw);
        assert!(
            triples.is_empty(),
            "4624 without Computer should yield 0 triples; got {}",
            triples.len()
        );
    }

    /// Variant 4 — wrong type on TargetUserName (number, not string).
    /// Must skip the row rather than stringify and fabricate an entity.
    #[test]
    fn variant4_wrong_type_username_is_skipped() {
        let raw = r#"[{
            "Type": "SecurityEvent",
            "TimeGenerated": "2024-01-15T14:30:00Z",
            "EventID": 4624,
            "TargetUserName": 12345,
            "Computer": "WS-01"
        }]"#;
        let triples = SentinelJsonParser.parse(raw);
        assert!(
            triples.is_empty(),
            "numeric TargetUserName must be rejected; got {}",
            triples.len()
        );
    }

    /// Variant 5 — unmappable EventID 9999 (unknown to the
    /// SecurityEvent dispatch). Produces nothing rather than a generic
    /// placeholder.
    #[test]
    fn variant5_unmappable_event_id_yields_nothing() {
        let raw = r#"[{
            "Type": "SecurityEvent",
            "TimeGenerated": "2024-01-15T14:30:00Z",
            "EventID": 9999,
            "TargetUserName": "alice",
            "Computer": "WS-01"
        }]"#;
        let triples = SentinelJsonParser.parse(raw);
        assert!(
            triples.is_empty(),
            "unknown EventID 9999 should be a no-op; got {}",
            triples.len()
        );
    }

    /// Variant 6 — IpAddress + LogonType metadata must be preserved on
    /// the host entity / auth relation so the analyst drill-down shows
    /// the source IP and logon type alongside the triple.
    #[test]
    fn variant6_metadata_preserved_on_auth_triple() {
        let raw = r#"[{
            "Type": "SecurityEvent",
            "TimeGenerated": "2024-01-15T14:30:00Z",
            "EventID": 4624,
            "TargetUserName": "alice",
            "Computer": "WS-01",
            "IpAddress": "10.0.0.42",
            "LogonType": 10
        }]"#;
        let triples = SentinelJsonParser.parse(raw);
        assert!(!triples.is_empty(), "expected at least one triple");
        let (_, rel, dst) = &triples[0];
        assert_eq!(
            dst.metadata.get("source_ip").map(String::as_str),
            Some("10.0.0.42"),
            "source_ip should land on the host entity's metadata"
        );
        assert_eq!(
            rel.metadata.get("logon_type").map(String::as_str),
            Some("10"),
            "logon_type should land on the Auth relation's metadata"
        );
    }
}

// ========================================================================
// FortiAnalyzer (6 variants)
// ========================================================================
mod forti {
    use super::*;

    /// Variant 1 — valid "Top User by Traffic" chart. Produces
    /// (hub, radial, radial) triples; projection must be schema-valid.
    #[test]
    fn variant1_valid_top_user_chart() {
        let schema = compiled_schema();
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<FortiAnalyzer_Report name="Daily Summary Report">
    <chart name="Top User by Traffic">
        <id value="1">
            <User_Name>10.3.10.66</User_Name>
            <Bytes>5983237494</Bytes>
            <Percent_of_Total>29.18%</Percent_of_Total>
        </id>
    </chart>
</FortiAnalyzer_Report>"#;
        let triples = FortiAnalyzerXmlParser::default().parse(xml);
        assert_projects_cleanly(&schema, &triples, "forti_analyzer");
    }

    /// Variant 2 — Forti has no timestamp in the XML schema; the
    /// parser stamps a synthetic report-time on every row. The "bad
    /// timestamp" variant is therefore a missing `<macro name="time">`
    /// block — contract: parser still emits triples with a deterministic
    /// fallback, never panics.
    #[test]
    fn variant2_no_time_macro_still_parses() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<FortiAnalyzer_Report name="Daily Summary Report">
    <chart name="Top User by Traffic">
        <id value="1">
            <User_Name>10.3.10.66</User_Name>
            <Bytes>1234</Bytes>
            <Percent_of_Total>1.0%</Percent_of_Total>
        </id>
    </chart>
</FortiAnalyzer_Report>"#;
        let triples = FortiAnalyzerXmlParser::default().parse(xml);
        assert!(
            !triples.is_empty(),
            "missing time macro must not drop the row"
        );
    }

    /// Variant 3 — missing User_Name field. The handler skips the row
    /// rather than building a radial on empty-string.
    #[test]
    fn variant3_missing_user_name_row_skipped() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<FortiAnalyzer_Report name="Daily Summary Report">
    <chart name="Top User by Traffic">
        <id value="1">
            <Bytes>1234</Bytes>
            <Percent_of_Total>1.0%</Percent_of_Total>
        </id>
    </chart>
</FortiAnalyzer_Report>"#;
        let triples = FortiAnalyzerXmlParser::default().parse(xml);
        // Only the context hub self-loop should remain.
        assert_eq!(
            triples.len(),
            1,
            "row without User_Name should be skipped; got {} triples",
            triples.len()
        );
        let (src, _, dst) = &triples[0];
        assert_eq!(src.id, dst.id, "remaining triple should be the context hub");
    }

    /// Variant 4 — wrong type for Bytes. The XML is untyped text; Forti
    /// treats the Bytes column as a free-form string and just carries
    /// it into metadata. "wrong type" manifests as a clearly-garbled
    /// value — the parser must NOT crash and must still emit the
    /// radial, because dropping it would lose the IoC pivot.
    #[test]
    fn variant4_garbled_bytes_value_still_parses() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<FortiAnalyzer_Report name="Daily Summary Report">
    <chart name="Top User by Traffic">
        <id value="1">
            <User_Name>10.3.10.66</User_Name>
            <Bytes>not-a-number</Bytes>
            <Percent_of_Total>1.0%</Percent_of_Total>
        </id>
    </chart>
</FortiAnalyzer_Report>"#;
        let triples = FortiAnalyzerXmlParser::default().parse(xml);
        assert!(
            triples.len() >= 2,
            "garbled Bytes should not drop the radial; got {} triples",
            triples.len()
        );
    }

    /// Variant 5 — unmappable: empty report body. Contract per the
    /// in-crate `empty_report_still_emits_context_entity` test: one
    /// context self-loop, nothing else.
    #[test]
    fn variant5_empty_report_emits_only_context_hub() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<FortiAnalyzer_Report name="Daily Summary Report">
</FortiAnalyzer_Report>"#;
        let triples = FortiAnalyzerXmlParser::default().parse(xml);
        assert_eq!(
            triples.len(),
            1,
            "empty report must yield exactly the context hub"
        );
        let (src, _, dst) = &triples[0];
        assert_eq!(src.id, dst.id, "context hub is a self-loop");
    }

    /// Variant 6 — bytes / percent metadata must land on the radial
    /// relation so the OCSF projection (Observed observables_list) can
    /// carry them into downstream SIEM exports.
    #[test]
    fn variant6_chart_metadata_preserved_on_relation() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<FortiAnalyzer_Report name="Daily Summary Report">
    <chart name="Top User by Traffic">
        <id value="1">
            <User_Name>10.3.10.66</User_Name>
            <Bytes>5983237494</Bytes>
            <Percent_of_Total>29.18%</Percent_of_Total>
        </id>
    </chart>
</FortiAnalyzer_Report>"#;
        let triples = FortiAnalyzerXmlParser::default().parse(xml);
        let radial = triples
            .iter()
            .find(|(_, _, d)| d.id == "10.3.10.66")
            .expect("radial triple should exist");
        assert_eq!(
            radial.1.metadata.get("bytes").map(String::as_str),
            Some("5983237494"),
            "bytes should ride on the radial relation metadata"
        );
        assert_eq!(
            radial
                .1
                .metadata
                .get("percent_of_total")
                .map(String::as_str),
            Some("29.18%"),
            "percent_of_total should ride on the radial relation metadata"
        );
    }
}
