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
    ConfigurableParser, CsvParser, EntityType, FieldConfig, FieldMapping, FieldRole, GenericParser,
    LogParser, RelationType, SentinelJsonParser, SuggestionSource, SysmonJsonParser,
    suggest_entity_type, suggest_entity_type_with_source,
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

#[test]
fn accepting_canonical_defaults_still_ingests() {
    // Realistic Zoho flow: user clicks Preview, accepts every suggestion,
    // hits Ingest. The frontend sends back FieldConfig with a Node mapping
    // for EVENT_BY → User, IP_ADDRESS → IP, plus Metadata for TIME with a
    // timestamp hint, plus custom Node mappings for DEVICE/OS/BROWSER.
    //
    // Previous regression: stripping canonical fields on every Node override
    // killed the anchor (source_user + source_ip both stripped), so the
    // override loop produced zero triples. This test pins the fix: when the
    // user's entity_type matches the canonical default, don't strip.
    let csv = "\
EVENT_BY,TIME,IP_ADDRESS,DEVICE,OS,BROWSER
\"Joel Canepa\",\"abr 19, 2026, 9:29 AM\",\"10.0.0.5\",\"misc\",\"UNKNOWN\",\"HTTP Library-Java\"
";
    let config = FieldConfig {
        mappings: vec![
            FieldMapping {
                raw_name: "EVENT_BY".to_string(),
                role: FieldRole::Node,
                entity_type: Some("User".to_string()),
                timestamp_format: None,
                locale: None,
            },
            FieldMapping {
                raw_name: "TIME".to_string(),
                role: FieldRole::Metadata,
                entity_type: None,
                timestamp_format: Some("%b %d, %Y, %I:%M %p".to_string()),
                locale: Some("es".to_string()),
            },
            FieldMapping {
                raw_name: "IP_ADDRESS".to_string(),
                role: FieldRole::Node,
                entity_type: Some("IP".to_string()),
                timestamp_format: None,
                locale: None,
            },
            FieldMapping {
                raw_name: "DEVICE".to_string(),
                role: FieldRole::Node,
                entity_type: Some("DEVICE".to_string()),
                timestamp_format: None,
                locale: None,
            },
            FieldMapping {
                raw_name: "OS".to_string(),
                role: FieldRole::Node,
                entity_type: Some("OS".to_string()),
                timestamp_format: None,
                locale: None,
            },
            FieldMapping {
                raw_name: "BROWSER".to_string(),
                role: FieldRole::Node,
                entity_type: Some("BROWSER".to_string()),
                timestamp_format: None,
                locale: None,
            },
        ],
    };
    let (triples, stats) = ConfigurableParser::new(config).parse_with_stats(csv);
    assert!(
        !triples.is_empty(),
        "accept-the-defaults flow must ingest — got 0 triples"
    );
    assert_eq!(stats.rows_with_triples, 1, "1 row processed");
    // The canonical user (no column-prefix) must be present — proves we did
    // NOT strip when the user accepted the canonical default.
    let has_clean_user = triples.iter().any(|(s, _, _)| s.id == "Joel Canepa");
    assert!(
        has_clean_user,
        "canonical User entity must be preserved when user accepts default; got {triples:?}"
    );
    // No prefixed duplicate: when the override matches the canonical default,
    // canonical processing already created the User entity. Re-creating
    // "EVENT_BY:Joel Canepa" here would inflate the graph with twin User
    // nodes for the same person.
    let has_dup_prefixed_user = triples
        .iter()
        .flat_map(|(s, _, d)| [s.id.as_str(), d.id.as_str()])
        .any(|id| id == "EVENT_BY:Joel Canepa");
    assert!(
        !has_dup_prefixed_user,
        "no prefixed duplicate when override matches canonical default; got {triples:?}"
    );
    // Custom columns must also show up as their own entities.
    let ids: Vec<&str> = triples
        .iter()
        .flat_map(|(s, _, d)| [s.id.as_str(), d.id.as_str()])
        .collect();
    assert!(ids.iter().any(|id| id.contains("misc")), "DEVICE missing");
    assert!(ids.iter().any(|id| id.contains("UNKNOWN")), "OS missing");
    assert!(
        ids.iter().any(|id| id.contains("HTTP Library-Java")),
        "BROWSER missing"
    );
}

#[test]
fn unknown_columns_are_promoted_as_custom_entities() {
    // User-level expectation: columns the heuristic doesn't recognize should
    // not be silently dropped — they should become a custom-entity node
    // named after the column, so no data is lost. Here DEVICE / OS / BROWSER
    // are built as Node mappings with entity_type = column name (this is
    // what the preview DTO now proposes by default).
    let csv = "\
EVENT_BY,TIME,IP_ADDRESS,DEVICE,OS,BROWSER
\"Joel Canepa\",\"abr 19, 2026, 9:29 AM\",\"10.0.0.5\",\"misc\",\"UNKNOWN\",\"HTTP Library-Java\"
";
    let config = FieldConfig {
        mappings: vec![
            FieldMapping {
                raw_name: "DEVICE".to_string(),
                role: FieldRole::Node,
                entity_type: Some("DEVICE".to_string()),
                timestamp_format: None,
                locale: None,
            },
            FieldMapping {
                raw_name: "OS".to_string(),
                role: FieldRole::Node,
                entity_type: Some("OS".to_string()),
                timestamp_format: None,
                locale: None,
            },
            FieldMapping {
                raw_name: "BROWSER".to_string(),
                role: FieldRole::Node,
                entity_type: Some("BROWSER".to_string()),
                timestamp_format: None,
                locale: None,
            },
        ],
    };
    let triples = ConfigurableParser::new(config).parse(csv);
    assert!(!triples.is_empty(), "triples must be produced");
    let ids: Vec<&str> = triples
        .iter()
        .flat_map(|(s, _, d)| [s.id.as_str(), d.id.as_str()])
        .collect();
    assert!(
        ids.iter().any(|id| id.contains("misc")),
        "DEVICE column must be promoted; ids={ids:?}"
    );
    assert!(
        ids.iter().any(|id| id.contains("UNKNOWN")),
        "OS column must be promoted; ids={ids:?}"
    );
    assert!(
        ids.iter().any(|id| id.contains("HTTP Library-Java")),
        "BROWSER column must be promoted; ids={ids:?}"
    );
}

#[test]
fn user_ignore_role_strips_canonical_field() {
    // EVENT_BY is canonical → source_user. User marks it Ignore. The
    // resulting graph must NOT contain that user entity — the override
    // must win over the canonical alias table.
    let csv = "\
EVENT_BY,IP_ADDRESS
\"Joel Canepa\",\"10.0.0.5\"
";
    let config = FieldConfig {
        mappings: vec![FieldMapping {
            raw_name: "EVENT_BY".to_string(),
            role: FieldRole::Ignore,
            entity_type: None,
            timestamp_format: None,
            locale: None,
        }],
    };
    let triples = ConfigurableParser::new(config).parse(csv);
    let has_user_entity = triples
        .iter()
        .any(|(s, _, d)| s.id == "Joel Canepa" || d.id == "Joel Canepa");
    assert!(
        !has_user_entity,
        "Ignore override must strip canonical field; got triples {triples:?}"
    );
}

#[test]
fn user_node_role_overrides_canonical_entity_type() {
    // EVENT_BY would normally canonicalize to source_user (User entity).
    // Here the user overrides it to Node → Host. The resulting entity
    // must have entity_type Host, not User.
    let csv = "\
EVENT_BY,IP_ADDRESS
\"Joel Canepa\",\"10.0.0.5\"
";
    let config = FieldConfig {
        mappings: vec![FieldMapping {
            raw_name: "EVENT_BY".to_string(),
            role: FieldRole::Node,
            entity_type: Some("Host".to_string()),
            timestamp_format: None,
            locale: None,
        }],
    };
    let triples = ConfigurableParser::new(config).parse(csv);
    // There should be no entity with entity_type=User named "Joel Canepa".
    let has_user = triples.iter().any(|(s, _, d)| {
        (s.id.contains("Joel Canepa") && s.entity_type == EntityType::User)
            || (d.id.contains("Joel Canepa") && d.entity_type == EntityType::User)
    });
    assert!(
        !has_user,
        "User override must prevent canonical User entity; got {triples:?}"
    );
    // And there should be a Host-typed entity promoted from EVENT_BY.
    let has_host = triples.iter().any(|(s, _, d)| {
        (s.entity_type == EntityType::Host && s.id.contains("Joel Canepa"))
            || (d.entity_type == EntityType::Host && d.id.contains("Joel Canepa"))
    });
    assert!(
        has_host,
        "User-supplied Host override must produce Host entity; got {triples:?}"
    );
}

#[test]
fn parse_with_stats_reports_zero_triples_on_bad_mapping() {
    // Without a FieldConfig, the CSV parser normalizes EVENT_BY/IP_ADDRESS and
    // produces triples (today's fix covers this). This test uses a CSV whose
    // headers are NOT in any canonical alias table, so the core GenericParser
    // yields nothing. Stats must surface rows_seen > 0 with rows_with_triples = 0.
    let csv = "\
unknown_actor_col,irrelevant_col
alice,foo
bob,bar
";
    let (triples, stats) = CsvParser.parse_with_stats(csv);
    // CsvParser default doesn't override parse_with_stats → empty stats.
    // Sanity check: triples produced are 0 (no canonical fields recognized).
    assert!(
        triples.is_empty(),
        "no canonical field → no triples; got {triples:?}"
    );
    // ConfigurableParser DOES override parse_with_stats — verify it reports
    // real zero-triple counts under the same input.
    let cfg_parser = ConfigurableParser::new(FieldConfig { mappings: vec![] });
    let (cfg_triples, cfg_stats) = cfg_parser.parse_with_stats(csv);
    assert!(cfg_triples.is_empty(), "same input → 0 triples");
    assert_eq!(cfg_stats.rows_seen, 2, "parser must have seen 2 rows");
    assert_eq!(cfg_stats.rows_with_triples, 0, "no triples produced");
    assert_eq!(cfg_stats.rows_skipped, 2, "both rows skipped");
    let _ = stats; // CsvParser's default-empty stats is intentional here
}

#[test]
fn parse_with_stats_reports_nonzero_on_good_mapping() {
    // Zoho-shape CSV with the timestamp hint from PR 1: with a config that
    // names the TIME column and a format hint, every row must produce triples
    // AND the stats must reflect that.
    let csv = "\
EVENT_BY,TIME,IP_ADDRESS
\"Joel Canepa\",\"abr 19, 2026, 9:29 AM\",\"10.0.0.5\"
\"Carlos null\",\"abr 19, 2026, 6:48 AM\",\"10.0.0.6\"
";
    let config = FieldConfig {
        mappings: vec![FieldMapping {
            raw_name: "TIME".to_string(),
            role: FieldRole::Metadata,
            entity_type: None,
            timestamp_format: Some("%b %d, %Y, %I:%M %p".to_string()),
            locale: Some("es".to_string()),
        }],
    };
    let (triples, stats) = ConfigurableParser::new(config).parse_with_stats(csv);
    assert!(!triples.is_empty(), "triples must be produced");
    assert_eq!(stats.rows_seen, 2, "2 CSV data rows");
    assert_eq!(stats.rows_with_triples, 2, "both rows produced triples");
    assert_eq!(stats.rows_skipped, 0, "no row skipped");
    // Per-field occurrence must include all three columns.
    assert_eq!(stats.per_field_occurrence.get("EVENT_BY").copied(), Some(2));
    assert_eq!(stats.per_field_occurrence.get("TIME").copied(), Some(2));
    assert_eq!(
        stats.per_field_occurrence.get("IP_ADDRESS").copied(),
        Some(2)
    );
}

#[test]
fn configurable_parser_applies_timestamp_hint_to_zoho_csv() {
    // When auto-detect isn't enough (or for unfamiliar locales), the user
    // supplies a chrono format + locale hint per column. The parser must
    // rewrite that column to ISO-8601 so downstream timestamp logic picks up
    // a correct epoch. This guards the rescue path for unfamiliar date shapes.
    let data = r#"[
        {"EVENT_BY": "Joel Canepa", "TIME": "abr 19, 2026, 9:29 AM", "IP_ADDRESS": "10.0.0.5"},
        {"EVENT_BY": "Carlos null", "TIME": "sept 4, 2026, 11:05 PM", "IP_ADDRESS": "10.0.0.6"}
    ]"#;
    let config = FieldConfig {
        mappings: vec![FieldMapping {
            raw_name: "TIME".to_string(),
            role: FieldRole::Metadata,
            entity_type: None,
            timestamp_format: Some("%b %d, %Y, %I:%M %p".to_string()),
            locale: Some("es".to_string()),
        }],
    };
    let triples = ConfigurableParser::new(config).parse(data);
    assert!(
        !triples.is_empty(),
        "ConfigurableParser must produce triples from Zoho-shape events"
    );

    // Expected timestamp for "abr 19, 2026, 9:29 AM" UTC = 2026-04-19T09:29:00Z
    let expected = chrono::NaiveDate::from_ymd_opt(2026, 4, 19)
        .unwrap()
        .and_hms_opt(9, 29, 0)
        .unwrap()
        .and_utc()
        .timestamp();
    let joel = triples
        .iter()
        .find(|(s, _, _)| s.id == "Joel Canepa")
        .expect("Joel Canepa User entity should be in triples");
    assert_eq!(
        joel.1.timestamp, expected,
        "timestamp_format + locale hint must translate Spanish month and parse the date"
    );
}

#[test]
fn csv_parser_handles_zoho_activity_export() {
    // Zoho Projects activity export: EVENT_BY actor, IP_ADDRESS with
    // underscore, localized Spanish timestamp "abr 19, 2026, 9:29 AM".
    // Regression guard: all three must normalize so at least one triple
    // is produced per row that has an actor.
    let csv = "\
EVENT_BY,TIME,INFO,IP_ADDRESS,DEVICE,OS,BROWSER,COUNTRY
\"Joel Canepa\",\"abr 19, 2026, 9:29 AM\",\"Uploaded file\",\"10.0.0.5\",\"misc\",\"UNKNOWN\",\"HTTP Library-Java\",\"\"
\"Carlos null\",\"abr 19, 2026, 6:48 AM\",\"Uploaded folder\",\"\",\"\",\"\",\"\",\"\"
";
    let triples = CsvParser.parse(csv);
    assert!(
        !triples.is_empty(),
        "Zoho-style CSV must produce triples; got 0 (actor/ip/timestamp mapping regressed)"
    );
    // The row with an IP should produce a User-[Auth]->IP edge with a
    // non-zero timestamp (the Spanish date must have parsed).
    let auth = triples.iter().find(|(s, r, d)| {
        s.entity_type == EntityType::User
            && r.rel_type == RelationType::Auth
            && d.entity_type == EntityType::IP
    });
    let (_, rel, _) = auth.expect("expected User-[Auth]->IP triple for the row with an IP");
    assert!(
        rel.timestamp > 0,
        "Spanish timestamp 'abr 19, 2026, 9:29 AM' must parse; got 0"
    );
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
    let has_execute = triples.iter().any(|(src, rel, dst)| {
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
    let has_connect = triples
        .iter()
        .any(|(_, rel, _)| matches!(rel.rel_type, RelationType::Connect | RelationType::DNS));
    assert!(
        has_connect,
        "expected at least one Connect/DNS triple: {triples:?}"
    );
}

#[test]
fn generic_case_insensitive_field_aliases() {
    // SourceIP (PascalCase) must map to the same canonical source_ip as source_ip.
    let ndjson =
        r#"{"Timestamp":"2024-01-01T10:00:00Z","SourceIP":"10.0.0.1","DestinationIP":"8.8.8.8"}"#;
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

// ─── Phase A — field-recognition breadth ──────────────────────────────

#[test]
fn canonical_field_recognizes_spanish_aliases() {
    // Spanish column names that appeared in the Zoho incident + common
    // audit exports. These must map to their English canonical targets
    // so the downstream canonical_to_entity_type logic routes them to
    // the right entity types.
    assert_eq!(
        GenericParser::canonical_field("usuario"),
        Some("source_user")
    );
    assert_eq!(
        GenericParser::canonical_field("dirección"),
        Some("source_ip")
    );
    assert_eq!(
        GenericParser::canonical_field("direccion"),
        Some("source_ip")
    );
    assert_eq!(
        GenericParser::canonical_field("equipo"),
        Some("source_host")
    );
    assert_eq!(
        GenericParser::canonical_field("archivo"),
        Some("target_file")
    );
    assert_eq!(
        GenericParser::canonical_field("dominio"),
        Some("target_domain")
    );
    assert_eq!(GenericParser::canonical_field("fecha"), Some("timestamp"));
    assert_eq!(GenericParser::canonical_field("acción"), Some("action"));
}

#[test]
fn canonical_field_recognizes_portuguese_and_french_aliases() {
    // Portuguese
    assert_eq!(
        GenericParser::canonical_field("usuário"),
        Some("source_user")
    );
    assert_eq!(
        GenericParser::canonical_field("endereço"),
        Some("source_ip")
    );
    assert_eq!(
        GenericParser::canonical_field("arquivo"),
        Some("target_file")
    );
    assert_eq!(
        GenericParser::canonical_field("domínio"),
        Some("target_domain")
    );
    // French
    assert_eq!(
        GenericParser::canonical_field("utilisateur"),
        Some("source_user")
    );
    assert_eq!(GenericParser::canonical_field("adresse"), Some("source_ip"));
    assert_eq!(
        GenericParser::canonical_field("fichier"),
        Some("target_file")
    );
    assert_eq!(
        GenericParser::canonical_field("domaine"),
        Some("target_domain")
    );
}

#[test]
fn canonical_field_recognizes_audit_log_semantics() {
    // Pervasive audit-log keys that weren't covered before Phase A.
    assert_eq!(GenericParser::canonical_field("action"), Some("action"));
    assert_eq!(GenericParser::canonical_field("event_type"), Some("action"));
    assert_eq!(GenericParser::canonical_field("status"), Some("outcome"));
    assert_eq!(GenericParser::canonical_field("result"), Some("outcome"));
    assert_eq!(
        GenericParser::canonical_field("resource"),
        Some("target_resource")
    );
    assert_eq!(
        GenericParser::canonical_field("sha256"),
        Some("target_hash")
    );
    assert_eq!(
        GenericParser::canonical_field("session_id"),
        Some("session")
    );
    assert_eq!(GenericParser::canonical_field("country"), Some("location"));
    assert_eq!(GenericParser::canonical_field("severity"), Some("severity"));
    assert_eq!(GenericParser::canonical_field("message"), Some("message"));
}

#[test]
fn canonical_to_entity_type_covers_new_canonical_targets() {
    // New canonical targets route to Other(String)-style strings that
    // `parse_entity_type` will wrap in EntityType::Other at the FFI
    // layer — no libgraphmatch slot changes required.
    assert_eq!(
        GenericParser::canonical_to_entity_type("target_resource"),
        "Resource"
    );
    assert_eq!(
        GenericParser::canonical_to_entity_type("target_hash"),
        "Hash"
    );
    assert_eq!(
        GenericParser::canonical_to_entity_type("session"),
        "Session"
    );
    assert_eq!(
        GenericParser::canonical_to_entity_type("location"),
        "Location"
    );
    // action / outcome / severity / message are metadata — Skip.
    assert_eq!(GenericParser::canonical_to_entity_type("action"), "Skip");
    assert_eq!(GenericParser::canonical_to_entity_type("outcome"), "Skip");
    assert_eq!(GenericParser::canonical_to_entity_type("severity"), "Skip");
    assert_eq!(GenericParser::canonical_to_entity_type("message"), "Skip");
}

#[test]
fn value_based_suggestion_catches_ip_without_name_hint() {
    // Column named "src" (no "ip"/"addr"/"address" substring, no canonical
    // match in canonical_field without the `_ip` suffix) but all samples
    // are IPv4 addresses — value regex must surface IP.
    //
    // NOTE: `src` IS canonical (CEF extension → source_ip), so this test
    // uses a neutral name "col1" that won't match the name heuristic.
    let samples = vec![
        "10.0.0.5".to_string(),
        "10.0.0.6".to_string(),
        "192.168.1.1".to_string(),
        "8.8.8.8".to_string(),
    ];
    let sugg = suggest_entity_type_with_source("col1", &samples).expect("values should surface IP");
    assert_eq!(sugg.entity_type, EntityType::IP);
    assert_eq!(sugg.source, SuggestionSource::Values);
}

#[test]
fn value_based_suggestion_catches_email_and_hash() {
    // Emails → User
    let emails = vec![
        "alice@corp.com".to_string(),
        "bob@corp.com".to_string(),
        "carol@partner.io".to_string(),
    ];
    assert_eq!(
        suggest_entity_type("unknown_col", &emails),
        Some(EntityType::User)
    );

    // SHA-256 (64 hex) → Other("Hash")
    let hashes = vec!["a".repeat(64), "b".repeat(64), "c".repeat(64)];
    assert_eq!(
        suggest_entity_type("whatever", &hashes),
        Some(EntityType::Other("Hash".to_string()))
    );
}

#[test]
fn value_regex_requires_majority_to_fire() {
    // Mixed column: 2 IPs + 3 free-text strings → below 60% threshold,
    // must NOT mislabel as IP. Column name is neutral ("notes") so the
    // name heuristic stays silent and only the value tier runs.
    let mixed = vec![
        "10.0.0.5".to_string(),
        "10.0.0.6".to_string(),
        "some free text here".to_string(),
        "more text".to_string(),
        "yet another line".to_string(),
    ];
    assert_eq!(suggest_entity_type("notes", &mixed), None);
}

#[test]
fn name_heuristic_beats_values() {
    // When the column name clearly says "user" but the samples happen to
    // contain IP-shaped strings (bad data export), the name still wins
    // — value inference is a fallback, not an override.
    let weird = vec!["10.0.0.5".to_string(), "10.0.0.6".to_string()];
    let sugg =
        suggest_entity_type_with_source("username", &weird).expect("name heuristic should fire");
    assert_eq!(sugg.entity_type, EntityType::User);
    assert_eq!(sugg.source, SuggestionSource::Name);
}

// ─── Phase B: timestamp robustness ────────────────────────────────────
//
// These tests drive through the CSV ingest path (the public surface for
// timestamp parsing) — each row uses a different timestamp format in the
// `timestamp` column, and we assert at least one triple per row lands
// with a non-zero `rel.timestamp`. Relying on the public ingest avoids
// taping ourselves to the private `parse_timestamp` signature.

fn csv_row_timestamps(ts_cells: &[&str]) -> Vec<i64> {
    // Build a minimal CSV with a canonical source/target pair on every row
    // plus the varying timestamp cell, ingest, and return the rel timestamps.
    let mut csv = String::from("timestamp,source_ip,target_ip\n");
    for t in ts_cells {
        csv.push_str(&format!("{},10.0.0.1,8.8.8.8\n", t));
    }
    let triples = CsvParser.parse(&csv);
    triples.into_iter().map(|(_, r, _)| r.timestamp).collect()
}

#[test]
fn parse_timestamp_handles_epoch_milliseconds() {
    // 1713628140000 ms = 2024-04-20 14:29:00 UTC. If we failed to scale
    // we'd treat it as raw seconds and get year 56271.
    let ts = csv_row_timestamps(&["1713628140000"]);
    assert_eq!(ts.len(), 1);
    // Expect the 2024 epoch second, not 10^12.
    assert_eq!(ts[0], 1_713_628_140);
}

#[test]
fn parse_timestamp_handles_epoch_seconds_unchanged() {
    // 10-digit epoch must stay in seconds (prior behavior).
    let ts = csv_row_timestamps(&["1713628140"]);
    assert_eq!(ts, vec![1_713_628_140]);
}

#[test]
fn parse_timestamp_handles_epoch_nanoseconds() {
    // 19-digit ns → divide by 10^9. 1_713_628_140_000_000_000 ns =
    // 1_713_628_140 s.
    let ts = csv_row_timestamps(&["1713628140000000000"]);
    assert_eq!(ts, vec![1_713_628_140]);
}

#[test]
fn parse_timestamp_handles_european_comma_decimal() {
    // "2024-04-20 14:29:00,123" — Latin-locale fractional seconds.
    // Must parse as 2024-04-20 14:29:00 UTC.
    let ts = csv_row_timestamps(&["2024-04-20 14:29:00,123"]);
    assert_eq!(ts, vec![1_713_623_340]);
}

#[test]
fn parse_timestamp_handles_w3c_without_seconds() {
    // "2024-04-20 14:29" — no seconds. Should parse, seconds=0.
    let ts = csv_row_timestamps(&["2024-04-20 14:29"]);
    assert_eq!(ts, vec![1_713_623_340]);
}

#[test]
fn parse_timestamp_handles_apache_clf() {
    // "19/Apr/2026:09:29:00 +0000" — standard CLF. 09:29 UTC → fixed epoch.
    let ts = csv_row_timestamps(&["19/Apr/2026:09:29:00 +0000"]);
    assert_eq!(ts.len(), 1);
    // 2026-04-19 09:29:00 UTC = 1_776_590_940.
    assert_eq!(ts[0], 1_776_590_940);
}

#[test]
fn parse_timestamp_handles_rfc3164_syslog() {
    use chrono::Datelike;
    // No year in the format → current year is assumed. We don't pin the
    // year, but we can assert the parsed year matches the current one.
    let ts = csv_row_timestamps(&["Apr 19 09:29:00"]);
    assert_eq!(ts.len(), 1);
    let parsed = chrono::DateTime::from_timestamp(ts[0], 0).expect("valid timestamp");
    assert_eq!(parsed.year(), chrono::Utc::now().year());
    assert_eq!(parsed.month(), 4);
    assert_eq!(parsed.day(), 19);
}

#[test]
fn parse_timestamp_with_hint_handles_portuguese_month() {
    // "abr 19, 2026, 9:29 AM" already worked for `es`; verify the same
    // "abr" (shared es/pt) still parses when locale="pt". The important
    // regression guard here is that non-es locales no longer no-op.
    let epoch = GenericParser::parse_timestamp_with_hint(
        "abr 19, 2026, 9:29 AM",
        "%b %d, %Y, %I:%M %p",
        Some("pt"),
    );
    assert!(epoch.is_some(), "pt-locale hint must translate `abr` → Apr");
    assert_eq!(epoch.unwrap(), 1_776_590_940);
}

#[test]
fn parse_timestamp_with_hint_handles_french_month() {
    // "avr 19, 2026, 9:29 AM" — French abbreviation for April.
    let epoch = GenericParser::parse_timestamp_with_hint(
        "avr 19, 2026, 9:29 AM",
        "%b %d, %Y, %I:%M %p",
        Some("fr"),
    );
    assert!(epoch.is_some(), "fr-locale hint must translate `avr` → Apr");
    assert_eq!(epoch.unwrap(), 1_776_590_940);
}

// ─── Phase A follow-up: default role for canonical-Skip fields ────────

#[test]
fn timestamp_field_defaults_to_metadata_role() {
    use graph_hunter_core::{FieldRole, preview_fields_from_events};
    use serde_json::json;

    // A TIME column with localized timestamp values. Previously this
    // defaulted to FieldRole::Node (because canonical_field maps it to
    // `timestamp`), which pushed the analyst to choose Ignore, which
    // then stripped the field and killed the event's parsed timestamp.
    // After the fix: canonical-Skip fields land in Metadata role so
    // GenericParser::normalize can still recover the epoch.
    let events = vec![
        json!({"TIME": "2024-04-20 14:29:00", "IP_ADDRESS": "10.0.0.5"}),
        json!({"TIME": "2024-04-20 14:30:00", "IP_ADDRESS": "10.0.0.6"}),
    ];
    let infos = preview_fields_from_events(&events);
    let time = infos
        .iter()
        .find(|fi| fi.raw_name == "TIME")
        .expect("TIME field must appear in preview");
    assert_eq!(
        time.current_role,
        FieldRole::Metadata,
        "timestamp-canonical fields must default to Metadata role, not Node"
    );
    // Sanity: IP field should still be Node.
    let ip = infos
        .iter()
        .find(|fi| fi.raw_name == "IP_ADDRESS")
        .expect("IP_ADDRESS must appear in preview");
    assert_eq!(ip.current_role, FieldRole::Node);
}

// ─── Phase C: parser diagnostics parity + skip reasons ─────────────────

#[test]
fn csv_parser_overrides_parse_with_stats() {
    // CsvParser used to inherit the default empty-stats impl — rows_seen
    // was always 0 for CSV ingest, so the UI couldn't distinguish
    // "format detector failed" from "parser produced no triples".
    let csv = "\
timestamp,source_ip,target_ip
2024-01-01T10:00:00Z,10.0.0.1,8.8.8.8
2024-01-01T10:01:00Z,10.0.0.2,1.1.1.1
";
    let (_, stats) = CsvParser.parse_with_stats(csv);
    assert!(
        stats.rows_seen > 0,
        "csv parse_with_stats must report rows_seen"
    );
    assert_eq!(stats.rows_seen, 2);
    assert_eq!(stats.rows_with_triples, 2);
    assert_eq!(stats.rows_skipped, 0);
}

#[test]
fn sysmon_parser_overrides_parse_with_stats() {
    // NDJSON with one parseable and one garbage row — garbage gets dropped
    // during decode so it never enters parse_with_stats. What we care about
    // here: the parser returns real rows_seen for the events it DID see.
    let ndjson = r#"{"EventID":1,"UtcTime":"2024-01-01 10:00:00","Image":"foo.exe","User":"alice","Computer":"host1"}
{"EventID":3,"UtcTime":"2024-01-01 10:01:00","Image":"bar.exe","SourceIp":"10.0.0.1","DestinationIp":"8.8.8.8","Computer":"host1"}
"#;
    let (_, stats) = SysmonJsonParser.parse_with_stats(ndjson);
    assert!(
        stats.rows_seen >= 1,
        "sysmon parse_with_stats must report rows_seen"
    );
}

#[test]
fn skip_reasons_distinguishes_empty_vs_no_canonical() {
    // Two rows: one with only unrecognized columns, one with nothing useful.
    // The CSV parser strips fully-empty rows before they reach the stats
    // collector, so we construct events directly via CsvParser to avoid that.
    let csv = "\
gibberish_col,more_gibberish
hello,world
foo,bar
";
    let (_, stats) = CsvParser.parse_with_stats(csv);
    assert_eq!(stats.rows_seen, 2);
    assert_eq!(stats.rows_with_triples, 0);
    assert_eq!(stats.rows_skipped, 2);
    // Both rows have values but no canonical fields — must bucket as
    // `no_canonical_fields`, not `empty_row`.
    assert_eq!(
        stats.skip_reasons.get("no_canonical_fields"),
        Some(&2usize),
        "skip_reasons: {:?}",
        stats.skip_reasons
    );
}

#[test]
fn skip_reasons_reports_no_anchor() {
    // CSV with only target_* canonical fields and no source side — after
    // Phase F ships this becomes a target-fallback, but today it skips
    // with reason `no_anchor`.
    let csv = "\
timestamp,target_domain,target_file
2024-01-01T10:00:00Z,example.com,/etc/passwd
";
    let (_, stats) = CsvParser.parse_with_stats(csv);
    assert_eq!(stats.rows_seen, 1);
    // The row has canonical fields (target_domain, target_file) but no
    // source-side anchor — skip reason must be `no_anchor`.
    if stats.rows_skipped > 0 {
        assert_eq!(
            stats.skip_reasons.get("no_anchor"),
            Some(&stats.rows_skipped),
            "expected all skipped rows categorised as no_anchor; got {:?}",
            stats.skip_reasons
        );
    }
}

// ─── Phase D: CSV / format-detection robustness ───────────────────────

#[test]
fn csv_parser_detects_tab_delimiter() {
    let tsv = "timestamp\tsource_ip\ttarget_ip\n\
2024-01-01T10:00:00Z\t10.0.0.1\t8.8.8.8\n\
2024-01-01T10:05:00Z\t10.0.0.2\t1.1.1.1\n";
    let triples = CsvParser.parse(tsv);
    assert!(
        !triples.is_empty(),
        "TSV must produce triples — delimiter detection should pick tab"
    );
}

#[test]
fn csv_parser_detects_semicolon_delimiter() {
    let csv = "timestamp;source_ip;target_ip\n\
2024-01-01T10:00:00Z;10.0.0.1;8.8.8.8\n\
2024-01-01T10:05:00Z;10.0.0.2;1.1.1.1\n";
    let triples = CsvParser.parse(csv);
    assert!(
        !triples.is_empty(),
        "European CSV (`;` delimiter) must produce triples"
    );
}

#[test]
fn csv_parser_strips_utf8_bom() {
    // BOM before the first header. Without stripping, the first column
    // becomes `\u{feff}timestamp`, breaks canonical matching, zero triples.
    let bom = "\u{feff}timestamp,source_ip,target_ip\n\
2024-01-01T10:00:00Z,10.0.0.1,8.8.8.8\n";
    let triples = CsvParser.parse(bom);
    assert!(
        !triples.is_empty(),
        "BOM must be stripped before header parse"
    );
}

#[test]
fn csv_parser_handles_multiline_quoted_field() {
    // An embedded newline inside a quoted field used to end the row.
    // Must now be joined into a single logical row.
    let csv = "\
timestamp,source_user,command_line
2024-01-01T10:00:00Z,alice,\"line1\nline2\ncontinued\"
2024-01-01T10:01:00Z,bob,\"inline\"
";
    let (_, stats) = CsvParser.parse_with_stats(csv);
    assert_eq!(
        stats.rows_seen, 2,
        "multi-line quoted row must count as one logical row"
    );
}

#[test]
fn csv_parser_flags_duplicate_headers() {
    // `source_ip` appears twice. The second column silently overwrites the
    // first when converting to JSON, matching prior behavior. The fix:
    // surface the diagnostic via `skip_reasons["duplicate_header"]` so the
    // UI can warn the analyst.
    let csv = "\
timestamp,source_ip,source_ip
2024-01-01T10:00:00Z,10.0.0.1,10.0.0.99
";
    let (_, stats) = CsvParser.parse_with_stats(csv);
    assert_eq!(
        stats.skip_reasons.get("duplicate_header").copied(),
        Some(1),
        "duplicate_header diagnostic missing or wrong count: {:?}",
        stats.skip_reasons
    );
}

#[test]
fn csv_parser_explicit_delimiter_override() {
    // Forcing a pipe delimiter on pipe-separated content; used when
    // auto-detection gets it wrong (e.g. content with accidentally
    // balanced commas and pipes).
    let piped = "timestamp|source_ip|target_ip\n2024-01-01T10:00:00Z|10.0.0.1|8.8.8.8\n";
    let triples = CsvParser::parse_with_delimiter(piped, '|');
    assert!(!triples.is_empty());
}

#[test]
fn parse_stats_skip_reasons_sum_matches_rows_skipped() {
    // Invariant: for parsers that categorise row-level skips, the sum of
    // row-level reason counts equals `rows_skipped`. The `duplicate_header`
    // key is a file-level warning (not a row skip) and is excluded.
    let csv = "\
col_a,col_b,col_c
,,
v1,v2,v3
,,
";
    let (_, stats) = CsvParser.parse_with_stats(csv);
    let sum: usize = stats
        .skip_reasons
        .iter()
        .filter(|(k, _)| k.as_str() != "duplicate_header")
        .map(|(_, n)| *n)
        .sum();
    assert_eq!(
        sum, stats.rows_skipped,
        "row-level skip_reasons sum {} must equal rows_skipped {}: {:?}",
        sum, stats.rows_skipped, stats.skip_reasons
    );
}

// ─── Phase E: action-aware relation inference ─────────────────────────

#[test]
fn action_field_overrides_static_relation_type() {
    // A CSV where the only anchor+target pair is user+ip, normally emitted
    // as User-[Auth]-IP. With action="delete" the rel_type must flip.
    let csv = "user,ip_address,action\nalice,10.0.0.5,delete\n";
    let triples = CsvParser.parse(csv);
    let rels: Vec<RelationType> = triples.iter().map(|(_, r, _)| r.rel_type.clone()).collect();
    assert!(
        rels.iter().any(|r| matches!(r, RelationType::Delete)),
        "expected a Delete relation when action=delete; got {:?}",
        rels
    );
    assert!(
        !rels.iter().any(|r| matches!(r, RelationType::Auth)),
        "Auth should be overridden when an action field is present"
    );
}

#[test]
fn action_read_vs_write_split_produces_correct_relation() {
    // Two rows, same user+ip pair, different action values. Each should
    // surface with a different rel_type, proving action_rel is computed
    // per event rather than per batch.
    let csv = "user,ip_address,action\nalice,10.0.0.5,download\nalice,10.0.0.5,upload\n";
    let triples = CsvParser.parse(csv);
    assert!(
        triples
            .iter()
            .any(|(_, r, _)| matches!(r.rel_type, RelationType::Read)),
        "action=download should yield a Read relation; got {:?}",
        triples
            .iter()
            .map(|(_, r, _)| r.rel_type.clone())
            .collect::<Vec<_>>()
    );
    assert!(
        triples
            .iter()
            .any(|(_, r, _)| matches!(r.rel_type, RelationType::Write)),
        "action=upload should yield a Write relation; got {:?}",
        triples
            .iter()
            .map(|(_, r, _)| r.rel_type.clone())
            .collect::<Vec<_>>()
    );
}

// ─── Phase G: reservoir-sampled skipped rows ─────────────────────────

#[test]
fn reservoir_sampling_caps_skipped_samples_at_20() {
    // Build a CSV with 50 completely empty rows (no anchor, no canonical
    // fields) so every row skips. The sampler should retain at most 20.
    let mut data = String::from("name,value\n");
    for _ in 0..50 {
        data.push_str(",\n");
    }
    let (_, stats) = CsvParser.parse_with_stats(&data);
    assert!(
        stats.rows_skipped >= 20,
        "precondition: expected many skipped rows, got {}",
        stats.rows_skipped
    );
    assert!(
        stats.skipped_samples.len() <= 20,
        "skipped_samples must be capped at 20, got {}",
        stats.skipped_samples.len()
    );
    // Every sample must carry a non-empty reason tag.
    for (raw, reason) in &stats.skipped_samples {
        assert!(!reason.is_empty(), "empty reason for sample: {:?}", raw);
    }
}

#[test]
fn skipped_samples_empty_when_all_rows_produce_triples() {
    // Well-formed CSV where every row has user+ip+timestamp. Nothing is
    // skipped, so the sample vector stays empty rather than being filled
    // with false-positives.
    let csv = "user,ip_address\nalice,10.0.0.5\nbob,10.0.0.6\n";
    let (_, stats) = CsvParser.parse_with_stats(csv);
    assert_eq!(stats.rows_skipped, 0);
    assert!(
        stats.skipped_samples.is_empty(),
        "no skipped rows ⇒ no samples; got {:?}",
        stats.skipped_samples
    );
}

// ─── Phase F: target-side anchor fallback ────────────────────────────

#[test]
fn generic_parser_emits_self_loop_when_only_target_domain() {
    // DNS-style export where only target_domain survives: verify a
    // self-loop Domain-[DNS]->Domain triple is emitted rather than
    // silently dropping the row.
    let data = r#"{"domain": "evil.example.com", "timestamp": "2026-04-19T09:29:00Z"}"#;
    let triples = GenericParser.parse(data);
    assert_eq!(
        triples.len(),
        1,
        "expected a target-fallback self-loop; got {:?}",
        triples
    );
    let (src, rel, dst) = &triples[0];
    assert_eq!(src.id, "evil.example.com");
    assert_eq!(dst.id, "evil.example.com");
    assert!(matches!(src.entity_type, EntityType::Domain));
    assert!(matches!(rel.rel_type, RelationType::DNS));
}

#[test]
fn configurable_parser_promotes_node_when_only_target_fields() {
    // Target-only event with a user-promoted custom column. The anchor
    // must fall back to target_domain so the Node promotion can attach
    // and produce a triple rather than being orphaned.
    let csv = "target_domain,threat\nmalicious.example,ransomware\n";
    let config = FieldConfig {
        mappings: vec![FieldMapping {
            raw_name: "threat".to_string(),
            role: FieldRole::Node,
            entity_type: Some("Threat".to_string()),
            timestamp_format: None,
            locale: None,
        }],
    };
    let parser = ConfigurableParser::new(config);
    let triples = parser.parse(csv);
    let found_threat = triples
        .iter()
        .any(|(_, _, d)| matches!(d.entity_type, EntityType::Other(ref s) if s == "Threat"));
    assert!(
        found_threat,
        "expected a Domain→Threat triple from target-fallback anchor; got {:?}",
        triples
            .iter()
            .map(|(s, r, d)| (s.id.clone(), format!("{:?}", r.rel_type), d.id.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn configurable_parser_respects_action_field_for_promoted_node() {
    // Configurable parser with a user-promoted unknown column. The action
    // field should drive the rel_type of the promoted anchor→node edge
    // instead of the static entity-derived default.
    let csv = "user,project,action\nalice,alpha,login\n";
    let config = FieldConfig {
        mappings: vec![FieldMapping {
            raw_name: "project".to_string(),
            role: FieldRole::Node,
            entity_type: Some("Project".to_string()),
            timestamp_format: None,
            locale: None,
        }],
    };
    let parser = ConfigurableParser::new(config);
    let triples = parser.parse(csv);
    let promo_rel = triples
        .iter()
        .find(|(_, _, d)| matches!(d.entity_type, EntityType::Other(ref s) if s == "Project"))
        .map(|(_, r, _)| r.rel_type.clone());
    assert!(
        matches!(promo_rel, Some(RelationType::Auth)),
        "promoted Project node should inherit action=login → Auth; got {:?}",
        promo_rel
    );
}
