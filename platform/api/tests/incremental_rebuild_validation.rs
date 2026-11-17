//! Task 4 capstone — the real-dataset end-to-end validation certificate.
//!
//! Tasks 1-3 (`platform/api/src/journal.rs`) built the rich structural
//! comparator (`compare_observable_equality`, `check_incremental_equivalence`,
//! `EquivalenceReport`/`all_comparable_dimensions_match`) and proved it
//! against hand-built synthetic envelopes. This file is the "métricas sobre
//! un dataset real" half of Fase G's precondition: it ingests a REAL
//! multi-source dataset — parsed by the actual shipping `LogParser` impls,
//! not synthetic `sample_event`s.
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
//! **What the positive certificate genuinely exercises (whole-phase review
//! fix — see Fix 1):** the SAME parsed `RawIngestEvent`s are applied to two
//! INDEPENDENTLY-built graphs through two DIFFERENT production paths:
//!
//! - `live`: a purely IN-MEMORY incremental build. Each source's events are
//!   wrapped straight into a `GraphDelta` (`graph_hunter_core::delta`) and
//!   applied via `GraphHunter::apply_delta` — one batch per source
//!   (sysmon, then sentinel, then forti) — WITHOUT ever constructing a
//!   `CanonicalEnvelope` or touching a `JournalStore`. The sysmon batch is
//!   then re-applied a second time (a crash-and-reingest replay) to exercise
//!   `apply_delta`'s identity dedup on real parsed data, not a synthetic
//!   fixture.
//! - `rebuilt` (via `check_incremental_equivalence`): the SAME events are
//!   separately journaled to DISK (`journal_batch`, one call per source,
//!   same as `live`'s batching) and then rebuilt FROM SCRATCH by reading the
//!   journal back (`rebuild_from_journal` → `apply_batch_idempotent`) — a
//!   single from-disk replay, never touching the in-memory path above.
//!
//! So this is a genuine memory-vs-disk AND incremental-vs-batch-rebuild
//! comparison, plus a real-data idempotent-dedup property (the crash replay
//! must not inflate `live`'s counts) — not `f(x) == filter(x) |> f` on the
//! identical deserialized stream, which is what an earlier version of this
//! test did (`live` was built by calling `apply_batch_idempotent` on
//! `store.read_all()`, the exact same disk-round-tripped envelopes the
//! rebuild itself replays — that proved nothing about memory-vs-disk
//! separation). This certificate does NOT claim to exercise "every real
//! production seam": `GraphHunterApi::load_data` (the actual API entry
//! point, which also runs `run_full_scoring` post-ingest) is a separate,
//! untested seam here — see `journal.rs`'s `anomaly_scores` doc for why
//! scoring is deliberately out of scope for this comparator.

use graph_hunter_api::journal::{
    DimensionResult, JournalStore, apply_batch_idempotent, check_incremental_equivalence,
    journal_batch,
};
use graph_hunter_core::delta::GraphDelta;
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
/// into in-memory `RawIngestEvent`s, one `Vec` per source. Pure — no I/O, no
/// journal, no graph. Shared by both the genuinely-in-memory `live` build and
/// `journal_parsed_events_per_source` below, so both sides of the certificate
/// start from byte-identical parsed events, not two separate re-parses that
/// merely happen to agree.
fn parse_real_multi_source_events() -> (
    Vec<RawIngestEvent>,
    Vec<RawIngestEvent>,
    Vec<RawIngestEvent>,
) {
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

    let sentinel_events: Vec<RawIngestEvent> = SentinelJsonParser
        .parse(SENTINEL_LOGON)
        .into_iter()
        .map(RawIngestEvent::from_parsed_triple)
        .collect();
    assert!(
        !sentinel_events.is_empty(),
        "real sentinel fixture must parse into at least one event"
    );

    let forti_events: Vec<RawIngestEvent> = FortiAnalyzerXmlParser::default()
        .parse(FORTI_TOP_USER_CHART)
        .into_iter()
        .map(RawIngestEvent::from_parsed_triple)
        .collect();
    assert!(
        !forti_events.is_empty(),
        "real forti fixture must parse into at least one event"
    );

    (sysmon_events, sentinel_events, forti_events)
}

/// Journal already-parsed per-source event batches into `store`, one
/// `journal_batch` call per source (its own `source_id`/`source_kind`/
/// `dataset_id`/`parser_name`, matching how a real multi-source ingest run
/// would stamp per-batch provenance on disk). Pure w.r.t. the caller beyond
/// `store.append` — same contract `journal_batch` itself documents. The
/// `dataset_id` passed per source ("ds-sysmon"/"ds-sentinel"/"ds-forti") is
/// the SAME tag `apply_events_in_memory` below stamps on `live`'s entities,
/// so Fix 3's dataset_id-aware entity comparison still reports `Match` on
/// this fixture (both build paths agree on dataset attribution).
fn journal_parsed_events_per_source(
    store: &JournalStore,
    sysmon_events: &[RawIngestEvent],
    sentinel_events: &[RawIngestEvent],
    forti_events: &[RawIngestEvent],
    now_ms: i64,
) {
    journal_batch(
        store,
        "ds-sysmon",
        "sysmon",
        "ds-sysmon",
        "sysmon",
        sysmon_events,
        &[],
        now_ms,
    )
    .expect("journal sysmon batch");
    journal_batch(
        store,
        "ds-sentinel",
        "sentinel",
        "ds-sentinel",
        "sentinel",
        sentinel_events,
        &[],
        now_ms,
    )
    .expect("journal sentinel batch");
    journal_batch(
        store,
        "ds-forti",
        "forti_analyzer",
        "ds-forti",
        "forti_analyzer",
        forti_events,
        &[],
        now_ms,
    )
    .expect("journal forti batch");
}

/// Convenience wrapper: parse + journal the three real fixtures into `store`
/// in one call. Kept for the negative control below, which only needs the
/// on-disk journal (it reads the envelopes straight back off `store` to seed
/// BOTH its `live` and its deliberately-truncated rebuild journal — that
/// same-stream shape is fine there because the negative control's whole
/// point is a missing-record divergence, not memory-vs-disk separation).
fn journal_real_multi_source_fixtures(store: &JournalStore, now_ms: i64) {
    let (sysmon_events, sentinel_events, forti_events) = parse_real_multi_source_events();
    journal_parsed_events_per_source(
        store,
        &sysmon_events,
        &sentinel_events,
        &forti_events,
        now_ms,
    );
}

/// Apply a slice of already-parsed, purely in-memory `RawIngestEvent`s to
/// `graph` via `GraphDelta` (`graph_hunter_core::delta`) +
/// `GraphHunter::apply_delta` — the SAME application primitive
/// `apply_batch_idempotent` uses internally (via `envelope_to_delta`), but
/// WITHOUT ever materializing a `CanonicalEnvelope` or touching a
/// `JournalStore`: these events came straight out of the real `LogParser`s
/// and never round-tripped through JSON. `event_id` is derived
/// deterministically from `(source_tag, index-in-batch)` so replaying the
/// SAME `events` slice a second time (a crash-and-reingest of this batch)
/// hits `apply_delta`'s identity dedup and applies nothing new — real-data
/// idempotency, exercised entirely in memory.
fn apply_events_in_memory(
    graph: &mut GraphHunter,
    source_tag: &str,
    dataset_id: &str,
    events: &[RawIngestEvent],
) {
    for (i, ev) in events.iter().enumerate() {
        let event_id = format!("{source_tag}-{i}");
        let delta = GraphDelta::new(ev.clone(), event_id, Some(dataset_id.to_string()));
        let _ = graph.apply_delta(&delta);
    }
}

/// The certificate: a real, heterogeneous-source dataset (Sysmon + Sentinel +
/// FortiAnalyzer), applied to an in-memory incremental graph via
/// `GraphDelta`/`apply_delta` (with a crash-replay of one source's batch)
/// and, INDEPENDENTLY, journaled to disk and rebuilt from scratch by
/// `check_incremental_equivalence` — must report full observable equality on
/// a non-trivial graph. See the file header for exactly what "independently"
/// means here (memory vs. disk, incremental vs. from-scratch batch).
#[test]
fn real_multi_source_dataset_incremental_equals_rebuild() {
    let (sysmon_events, sentinel_events, forti_events) = parse_real_multi_source_events();

    // GENUINE in-memory incremental construction: one batch per real source,
    // applied directly via GraphDelta + apply_delta — never touching a
    // CanonicalEnvelope or JournalStore. The sysmon batch is then re-applied
    // a second time (a crash-and-reingest replay) to exercise apply_delta's
    // identity dedup on real parsed data.
    let mut live = GraphHunter::new();
    apply_events_in_memory(&mut live, "ds-sysmon", "ds-sysmon", &sysmon_events);
    apply_events_in_memory(&mut live, "ds-sentinel", "ds-sentinel", &sentinel_events);
    apply_events_in_memory(&mut live, "ds-forti", "ds-forti", &forti_events);
    apply_events_in_memory(&mut live, "ds-sysmon", "ds-sysmon", &sysmon_events); // crash replay

    // Separately, the SAME parsed events are journaled to DISK — one
    // journal_batch call per source, mirroring live's per-source batching.
    let dir = tempfile::tempdir().unwrap();
    let store = JournalStore::open(dir.path()).unwrap();
    journal_parsed_events_per_source(
        &store,
        &sysmon_events,
        &sentinel_events,
        &forti_events,
        1_753_000_000_000,
    );

    // The rebuild + rich compare — THE certificate.
    // `check_incremental_equivalence` rebuilds `rebuilt` FROM SCRATCH by
    // reading the journal back off disk (`rebuild_from_journal` ->
    // `apply_batch_idempotent`), a single from-disk replay entirely
    // independent of how `live` above was constructed.
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
    // Machine-enforce the hypothesis dimension: it must be a REAL Match, not
    // a silent decay to NotComparable/Diff if the battery or fixtures drift —
    // `all_comparable_dimensions_match()` alone would NOT catch a
    // hypothesis_results that quietly became NotComparable (NotComparable
    // doesn't count against equivalence, so the assertion above would still
    // pass even if this dimension stopped proving anything).
    assert!(
        matches!(report.hypothesis_results, DimensionResult::Match),
        "hypothesis dimension must be a real Match, not NotComparable/Diff: {:?}",
        report.hypothesis_results
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
    // Exact counts, pinned: the crash replay above must NOT inflate them —
    // that is the whole point of proving dedup on real, parsed data.
    assert_eq!(
        report.live_entities, 9,
        "crash replay of the sysmon batch must not inflate entity count:\n{report}"
    );
    assert_eq!(
        report.live_relations, 7,
        "crash replay of the sysmon batch must not inflate relation count:\n{report}"
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
