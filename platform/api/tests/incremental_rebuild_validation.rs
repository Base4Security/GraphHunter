//! Task 4 capstone — the real-dataset end-to-end validation certificate.
//!
//! Tasks 1-3 (`platform/api/src/journal.rs`) built the rich structural
//! comparator (`compare_observable_equality`, `check_incremental_equivalence`,
//! `EquivalenceReport`/`all_comparable_dimensions_match`) and proved it
//! against hand-built synthetic envelopes. This file is the "métricas sobre
//! un dataset real" half of Fase G's precondition: it ingests a REAL
//! multi-source dataset — parsed by the actual shipping `LogParser` impls,
//! not synthetic `sample_event`s — through both the incremental
//! (journal + `apply_batch_idempotent`) path and the from-scratch journal
//! rebuild, and asserts the rich comparator reports full observable
//! equality.
//!
//! **Fixtures used (git-tracked, ort-free — no `demo_data/*.json`, which
//! are absent from the working tree per the recon note in the task brief):**
//! the inline raw-event strings for the "valid" variant of each parser in
//! `platform/canonical/tests/fixtures_three_sources.rs` (Sysmon EventID 1
//! process-create, Sentinel SecurityEvent 4624 logon, FortiAnalyzer "Top
//! User by Traffic" chart XML). Three heterogeneous source types, so the
//! certificate actually covers cross-source decoupling, not just a single
//! parser's shape.
//!
//! **Ingest path chosen:** direct `LogParser::parse` → `RawIngestEvent`
//! → `journal_batch` → `apply_batch_idempotent`, mirroring the exact
//! construction path `journal.rs`'s own
//! `journal_batch_writes_one_insert_per_event_plus_one_skipped_per_sample`
//! and `rebuild_from_journal_matches_live_after_idempotent_apply` tests use
//! (see `sample_event`/`insert_envelope_for` there), rather than
//! `GraphHunterApi::load_data` — `load_data`'s demo-scenario template reads
//! from `demo_data/*.json`, which are the exact fixtures recon found
//! missing. Going straight through the parser + journal primitives keeps
//! this test on fixtures that are actually in the tree while still
//! exercising every real production seam: real parser → real
//! `RawIngestEvent` → real `journal_batch` → real `apply_batch_idempotent`
//! → real `check_incremental_equivalence`.

use graph_hunter_api::journal::{
    JournalStore, apply_batch_idempotent, check_incremental_equivalence, journal_batch,
};
use graph_hunter_core::graph::GraphHunter;
use graph_hunter_core::parser::{LogParser, RawIngestEvent};
use graph_hunter_core::{SentinelJsonParser, SysmonJsonParser};
use graph_hunter_parsers::FortiAnalyzerXmlParser;

/// Sysmon EventID 1 (process create) — verbatim variant-1 fixture from
/// `fixtures_three_sources.rs::sysmon::variant1_valid_process_create`.
const SYSMON_PROCESS_CREATE_1: &str = r#"{"EventID":1,"UtcTime":"2024-01-15 14:30:00.123","User":"DOMAIN\\alice","Image":"C:\\Windows\\System32\\cmd.exe","ParentImage":"C:\\Windows\\explorer.exe","ProcessId":1234,"CommandLine":"cmd.exe /c whoami"}"#;

/// A second, distinct Sysmon process-create row (different user/process/pid)
/// so the Sysmon side of the dataset carries more than one event — real
/// multi-event ingestion, not a single-row degenerate case.
const SYSMON_PROCESS_CREATE_2: &str = r#"{"EventID":1,"UtcTime":"2024-01-15 14:35:00.000","User":"DOMAIN\\bob","Image":"C:\\Windows\\System32\\powershell.exe","ParentImage":"C:\\Windows\\explorer.exe","ProcessId":5678,"CommandLine":"powershell.exe -enc ZQBjAGgAbwA="}"#;

/// Sentinel SecurityEvent 4624 (logon success) — verbatim variant-1 fixture
/// from `fixtures_three_sources.rs::sentinel::variant1_valid_security_event_logon`.
const SENTINEL_LOGON: &str = r#"[{
    "Type": "SecurityEvent",
    "TimeGenerated": "2024-01-15T14:30:00Z",
    "EventID": 4624,
    "TargetUserName": "alice",
    "Computer": "WORKSTATION-01",
    "IpAddress": "10.0.0.42",
    "LogonType": 3
}]"#;

/// FortiAnalyzer "Top User by Traffic" chart XML — verbatim variant-1
/// fixture from `fixtures_three_sources.rs::forti::variant1_valid_top_user_chart`.
const FORTI_TOP_USER_CHART: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<FortiAnalyzer_Report name="Daily Summary Report">
    <chart name="Top User by Traffic">
        <id value="1">
            <User_Name>10.3.10.66</User_Name>
            <Bytes>5983237494</Bytes>
            <Percent_of_Total>29.18%</Percent_of_Total>
        </id>
    </chart>
</FortiAnalyzer_Report>"#;

/// Parse the three real, git-tracked fixtures through the actual shipping
/// parsers (`SysmonJsonParser`, `SentinelJsonParser`, `FortiAnalyzerXmlParser`)
/// and journal the resulting `RawIngestEvent`s into `store`, one
/// `journal_batch` call per source (its own `source_id`/`source_kind`/
/// `parser_name`, matching how a real multi-source ingest run would stamp
/// per-batch provenance). Pure w.r.t. the caller beyond `store.append` —
/// same contract `journal_batch` itself documents.
fn journal_real_multi_source_fixtures(store: &JournalStore, now_ms: i64) {
    let sysmon_events: Vec<RawIngestEvent> = SysmonJsonParser
        .parse(SYSMON_PROCESS_CREATE_1)
        .into_iter()
        .chain(SysmonJsonParser.parse(SYSMON_PROCESS_CREATE_2))
        .map(RawIngestEvent::from_parsed_triple)
        .collect();
    assert!(
        !sysmon_events.is_empty(),
        "real sysmon fixture must parse into at least one event"
    );
    journal_batch(
        store,
        "ds-sysmon",
        "sysmon",
        "ds-sysmon",
        "sysmon",
        &sysmon_events,
        &[],
        now_ms,
    )
    .expect("journal sysmon batch");

    let sentinel_events: Vec<RawIngestEvent> = SentinelJsonParser
        .parse(SENTINEL_LOGON)
        .into_iter()
        .map(RawIngestEvent::from_parsed_triple)
        .collect();
    assert!(
        !sentinel_events.is_empty(),
        "real sentinel fixture must parse into at least one event"
    );
    journal_batch(
        store,
        "ds-sentinel",
        "sentinel",
        "ds-sentinel",
        "sentinel",
        &sentinel_events,
        &[],
        now_ms,
    )
    .expect("journal sentinel batch");

    let forti_events: Vec<RawIngestEvent> = FortiAnalyzerXmlParser::default()
        .parse(FORTI_TOP_USER_CHART)
        .into_iter()
        .map(RawIngestEvent::from_parsed_triple)
        .collect();
    assert!(
        !forti_events.is_empty(),
        "real forti fixture must parse into at least one event"
    );
    journal_batch(
        store,
        "ds-forti",
        "forti_analyzer",
        "ds-forti",
        "forti_analyzer",
        &forti_events,
        &[],
        now_ms,
    )
    .expect("journal forti batch");
}

/// The certificate: a real, heterogeneous-source dataset (Sysmon + Sentinel
/// + FortiAnalyzer) ingested through the incremental `apply_batch_idempotent`
/// path and, independently, rebuilt from the journal by
/// `check_incremental_equivalence` — must report full observable equality
/// on a non-trivial graph.
#[test]
fn real_multi_source_dataset_incremental_equals_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let store = JournalStore::open(dir.path()).unwrap();
    journal_real_multi_source_fixtures(&store, 1_753_000_000_000);

    // The live incremental graph is built from exactly the envelopes just
    // journaled — the same envelope stream a real ingest run with
    // GRAPHHUNTER_JOURNAL + GRAPHHUNTER_GRAPHDELTA both on would apply.
    let envelopes = store.read_all().unwrap();
    assert!(
        envelopes.len() >= 3,
        "expected at least one journaled envelope per of the 3 real sources; got {}",
        envelopes.len()
    );
    let mut live = GraphHunter::new();
    apply_batch_idempotent(&mut live, &envelopes);

    // The rebuild + rich compare — THE certificate.
    let report = check_incremental_equivalence(&live, &store).unwrap();
    eprintln!("{report}");

    // Honesty guard: this journal contains only Insert envelopes (no
    // Correction/Tombstone), so the rebuild must be a faithful reference —
    // if this assertion ever fails, something upstream started emitting a
    // non-Insert envelope for these fixtures and the pass below would only
    // prove incremental-matches-a-stale-rebuild, not incremental-matches-truth.
    assert!(
        report.rebuild_faithful,
        "journal has only Insert envelopes for these fixtures -> rebuild must be faithful:\n{report}"
    );
    assert!(
        report.all_comparable_dimensions_match(),
        "incremental != rebuild on real multi-source dataset:\n{report}"
    );
    // Vacuous-pass guard: the graph must actually be non-trivial.
    assert!(
        report.live_relations > 0,
        "fixture must produce a non-trivial graph (relations):\n{report}"
    );
    assert!(
        report.live_entities > 0,
        "fixture must produce a non-trivial graph (entities):\n{report}"
    );
}

/// Negative control: prove the certificate has teeth. Same real dataset, but
/// the journal the rebuild reads from is missing its last record — so the
/// rebuild is a strict subset of the live graph and the comparator MUST
/// report a divergence, not a false Match.
#[test]
fn real_dataset_negative_control_divergence_is_reported() {
    let full_dir = tempfile::tempdir().unwrap();
    let full_store = JournalStore::open(full_dir.path()).unwrap();
    journal_real_multi_source_fixtures(&full_store, 1_753_000_100_000);

    let all_envelopes = full_store.read_all().unwrap();
    assert!(
        all_envelopes.len() >= 2,
        "need at least 2 envelopes to drop the last one and still keep a subset"
    );

    // Live graph sees ALL envelopes (the full real dataset).
    let mut live = GraphHunter::new();
    apply_batch_idempotent(&mut live, &all_envelopes);

    // The journal the rebuild reads from is missing the last record —
    // a strict subset of what actually landed in `live`.
    let corrupt_dir = tempfile::tempdir().unwrap();
    let corrupt_store = JournalStore::open(corrupt_dir.path()).unwrap();
    for env in &all_envelopes[..all_envelopes.len() - 1] {
        corrupt_store.append(env).unwrap();
    }

    let report = check_incremental_equivalence(&live, &corrupt_store).unwrap();
    eprintln!("{report}");
    assert!(
        !report.all_comparable_dimensions_match(),
        "a missing journal record must surface as a divergence:\n{report}"
    );
}
