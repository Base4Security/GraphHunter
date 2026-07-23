//! SOT machinery, end-to-end, with ALL FOUR feature flags turned ON.
//!
//! `real_hunt_demo.rs` proves the cross-source hunt works with the flags at
//! their default (off) setting, plus one flag (`GRAPHHUNTER_COVERAGE`) on in
//! its second test. This file is the missing "turn every SOT knob on at
//! once and prove the machinery underneath actually does something" demo:
//!
//!   1. `GRAPHHUNTER_JOURNAL`       — append-only journal receives records
//!   2. `GRAPHHUNTER_GRAPHDELTA`    — idempotent apply dedups a crash-replay
//!   3. `GRAPHHUNTER_COVERAGE`      — hunts come back with `AnswerCoverage`
//!   4. `GRAPHHUNTER_SOURCE_COVERAGE` — a source marked blind surfaces on
//!      `missing_sources`
//!   5. (always-on) frozen per-dataset provenance — `export_ocsf`'s
//!      `mapping_hash` reflects the real `cfg:`/`builtin:{parser}` identity
//!
//! Reuses the exact multi-source fixtures (FortiGate + Sentinel x2 +
//! Sysmon) from `real_hunt_demo.rs` verbatim, so this test exercises the
//! SAME union graph/attack-chain story — this file's job is proving the
//! flags work, not inventing a new dataset.
//!
//! `GRAPHHUNTER_JOURNAL`'s on-disk store is NOT test-isolated: per
//! `platform/api/src/operations/ingestion.rs::journal_batch_best_effort`,
//! it resolves `dirs::data_dir()/GraphHunter/journal` — a real, fixed,
//! per-user OS location, the same one production ingestion appends to
//! (mirrors the DLQ store, which also lives outside any single `Session`).
//! This test therefore measures journal growth as a BEFORE/AFTER delta
//! across its own ingest calls rather than asserting an absolute count,
//! and never deletes or truncates that file.

use std::io::Write;
use std::sync::Mutex;

use graph_hunter_api::GraphHunterApi;
use graph_hunter_api::dto::dsl::ParseDslRequest;
use graph_hunter_api::dto::export::ExportOcsfRequest;
use graph_hunter_api::dto::hunt::RunHuntRequest;
use graph_hunter_api::dto::ingestion::LoadDataRequest;
use graph_hunter_api::dto::session::CreateSessionRequest;

/// Process-wide lock for the `GRAPHHUNTER_*`-mutating test below. Mirrors
/// the `ENV_LOCK` convention already used in `journal.rs` / `coverage.rs` /
/// `operations/hunt.rs` / `real_hunt_demo.rs` — cargo runs tests in a single
/// binary in parallel by default, so two tests flipping the same env vars
/// would race. This file has exactly one `#[test]`, so the lock mostly
/// documents intent, but it costs nothing to keep the convention.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn lock_env() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Write `contents` to a fresh temp file and return its path as a
/// `String`. `load_data` reads a file path (`std::fs::read_to_string`
/// internally), so every source has to land on disk first. Leaks the
/// `NamedTempFile` (via `keep()`) so the file survives past this
/// function's return for the duration of the test process.
fn write_source_file(prefix: &str, contents: &str) -> String {
    let mut f = tempfile::Builder::new()
        .prefix(prefix)
        .suffix(".log")
        .tempfile()
        .expect("create temp file");
    f.write_all(contents.as_bytes()).expect("write temp file");
    f.flush().expect("flush temp file");
    let (_file, path) = f.keep().expect("keep temp file past scope");
    path.to_string_lossy().into_owned()
}

// ── The four sources of the ONE cross-source intrusion (copied verbatim
// from `real_hunt_demo.rs` so this test exercises the identical fixture) ──

const FORTIGATE_LOG: &str = concat!(
    r#"eventtime="1705328880" srcip="203.0.113.5" dstip="10.0.0.42" dstport="443" policyname="allow-web""#,
    "\n"
);

const SENTINEL_NETWORK_LOG: &str = r#"[{"Type":"DeviceNetworkEvents","TimeGenerated":"2024-01-15T14:30:00Z","DeviceName":"WORKSTATION-01","RemoteIP":"10.0.0.42"}]"#;

const SENTINEL_AUTH_LOG: &str = r#"[{"Type":"SecurityEvent","TimeGenerated":"2024-01-15T14:29:00Z","EventID":4624,"TargetUserName":"alice","Computer":"WORKSTATION-01","IpAddress":"10.0.0.42","LogonType":3}]"#;

const SYSMON_PROCESS_LOG: &str = r#"[{"EventID":1,"UtcTime":"2024-01-15 14:31:00.000","Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","ProcessId":4444,"CommandLine":"powershell -enc ...","User":"alice","Computer":"WORKSTATION-01"}]"#;

/// The real production journal location: `dirs::data_dir()/GraphHunter/
/// journal`. Matches `journal_batch_best_effort` exactly so this test reads
/// the SAME store `load_data` just appended to.
fn production_journal_dir() -> std::path::PathBuf {
    dirs::data_dir()
        .expect("resolve OS per-user data dir")
        .join("GraphHunter")
        .join("journal")
}

#[test]
fn sot_all_flags_on_end_to_end_demo() {
    let _env_guard = lock_env();
    // SAFETY: `edition = "2024"` requires `unsafe` around env mutation.
    // Guarded by `ENV_LOCK` (see `lock_env`) so no other test in this
    // binary observes a torn value. Reset at the very end of the test.
    unsafe {
        std::env::set_var("GRAPHHUNTER_JOURNAL", "1");
        std::env::set_var("GRAPHHUNTER_GRAPHDELTA", "1");
        std::env::set_var("GRAPHHUNTER_COVERAGE", "1");
        std::env::set_var("GRAPHHUNTER_SOURCE_COVERAGE", "1");
    }

    eprintln!("\n########## SOT — ALL 4 FEATURE FLAGS ON — END-TO-END DEMO ##########");
    eprintln!(
        "GRAPHHUNTER_JOURNAL         = {:?}",
        std::env::var("GRAPHHUNTER_JOURNAL")
    );
    eprintln!(
        "GRAPHHUNTER_GRAPHDELTA      = {:?}",
        std::env::var("GRAPHHUNTER_GRAPHDELTA")
    );
    eprintln!(
        "GRAPHHUNTER_COVERAGE        = {:?}",
        std::env::var("GRAPHHUNTER_COVERAGE")
    );
    eprintln!(
        "GRAPHHUNTER_SOURCE_COVERAGE = {:?}",
        std::env::var("GRAPHHUNTER_SOURCE_COVERAGE")
    );
    // Confirm the exact enable predicates (env_flag convention: "1" or
    // case-insensitive "true") actually read these as ON before doing
    // anything else — this is the contract the rest of the test leans on.
    assert!(graph_hunter_api::journal::journal_enabled());
    assert!(graph_hunter_api::journal::graphdelta_enabled());
    assert!(graph_hunter_api::coverage::coverage_enabled());
    assert!(graph_hunter_api::coverage::source_coverage_enabled());

    // ══════════════════════════════════════════════════════════════════
    // SETUP — one session, four real sources, one union graph.
    // ══════════════════════════════════════════════════════════════════
    let journal_dir = production_journal_dir();
    let journal_store = graph_hunter_api::journal::JournalStore::open(&journal_dir)
        .expect("open the real production journal store");
    let journal_count_baseline = journal_store
        .count()
        .expect("count pre-existing journal records");
    eprintln!("\n[setup] production journal path: {}", journal_dir.display());
    eprintln!(
        "[setup] journal record count BEFORE this test touches it: {journal_count_baseline}"
    );

    let api = GraphHunterApi::new_noop();
    api.create_session(CreateSessionRequest {
        name: Some("sot-flags-on-demo".into()),
    })
    .expect("create_session");

    let fortigate_path = write_source_file("fortigate-edge-fw", FORTIGATE_LOG);
    let sentinel_net_path = write_source_file("sentinel-network", SENTINEL_NETWORK_LOG);
    let sentinel_auth_path = write_source_file("sentinel-auth", SENTINEL_AUTH_LOG);
    let sysmon_path = write_source_file("sysmon-proc", SYSMON_PROCESS_LOG);

    let sources: [(&str, String, &str); 4] = [
        ("FortiGate firewall (edge-fw)", fortigate_path.clone(), "fortigate"),
        ("Sentinel DeviceNetworkEvents", sentinel_net_path.clone(), "sentinel"),
        ("Sentinel SecurityEvent 4624", sentinel_auth_path.clone(), "sentinel"),
        ("Sysmon EventID 1", sysmon_path.clone(), "sysmon"),
    ];

    for (label, path, format) in &sources {
        let r = api
            .load_data(LoadDataRequest {
                session: None,
                path: path.clone(),
                format: format.to_string(),
            })
            .unwrap_or_else(|e| panic!("load_data failed for {label} ({path}): {e}"));
        eprintln!(
            "[ingest] {label}: +{} entities, +{} relations (zero_triples={})",
            r.new_entities, r.new_relations, r.zero_triples
        );
        assert!(!r.zero_triples, "{label}: parser produced rows but zero triples");
        assert!(r.new_relations > 0, "{label}: expected new relations from a first-time ingest");
    }

    let session = api
        .sessions()
        .current_session()
        .expect("current session must exist after create_session");
    let (entity_count, relation_count_after_ingest) = {
        let graph = session.graph.read().expect("graph lock");
        (graph.entity_count(), graph.relation_count())
    };
    eprintln!("\n=== GRAPH SUMMARY after ingesting 4 sources ===");
    eprintln!("entity_count = {entity_count}, relation_count = {relation_count_after_ingest}");
    assert!(relation_count_after_ingest > 0, "graph must have relations after ingest");

    // ══════════════════════════════════════════════════════════════════
    // [1/5] JOURNAL — append-only journal receives records
    // ══════════════════════════════════════════════════════════════════
    let journal_count_after_ingest = journal_store
        .count()
        .expect("count journal after ingesting 4 sources");
    let journal_delta = journal_count_after_ingest - journal_count_baseline;
    eprintln!("\n--- [1/5] JOURNAL (GRAPHHUNTER_JOURNAL=1) ---");
    eprintln!(
        "journal record count: {journal_count_baseline} (before) -> {journal_count_after_ingest} (after) = +{journal_delta} appended by this test"
    );
    assert!(
        journal_delta > 0,
        "GRAPHHUNTER_JOURNAL=1 must append at least one record per ingested batch; delta={journal_delta}"
    );
    assert!(
        journal_delta >= sources.len(),
        "expected at least 1 journal record per ingested source ({} sources), got delta={journal_delta}",
        sources.len()
    );

    // ══════════════════════════════════════════════════════════════════
    // [2/5] IDEMPOTENT DEDUP (GraphDelta) — crash-replay simulation
    // ══════════════════════════════════════════════════════════════════
    eprintln!("\n--- [2/5] IDEMPOTENT DEDUP (GRAPHHUNTER_GRAPHDELTA=1) ---");
    eprintln!("re-ingesting the IDENTICAL FortiGate batch into the SAME session/graph (crash-and-reingest)");
    let relations_before_replay = relation_count_after_ingest;
    let replay = api
        .load_data(LoadDataRequest {
            session: None,
            path: fortigate_path.clone(),
            format: "fortigate".to_string(),
        })
        .expect("re-ingest (crash replay) load_data must not error");
    let relations_after_replay = {
        let graph = session.graph.read().expect("graph lock");
        graph.relation_count()
    };
    eprintln!(
        "before re-ingest: {relations_before_replay} rels, after: {relations_after_replay} rels (dedup {})",
        if relations_after_replay == relations_before_replay { "\u{2713}" } else { "FAILED" }
    );
    eprintln!(
        "LoadResult.new_relations reported by the replay call: {}",
        replay.new_relations
    );
    assert_eq!(
        relations_after_replay, relations_before_replay,
        "GRAPHHUNTER_GRAPHDELTA=1 must dedup an identical crash-replay batch — \
         relation_count grew from {relations_before_replay} to {relations_after_replay}"
    );
    assert_eq!(
        replay.new_relations, 0,
        "an identical crash-replay must report 0 NEW relations — every envelope should be \
         recognized as already-applied via apply_delta's event-identity dedup"
    );

    // ══════════════════════════════════════════════════════════════════
    // [3/5] ANSWER COVERAGE on hunts
    // ══════════════════════════════════════════════════════════════════
    eprintln!("\n--- [3/5] ANSWER COVERAGE (GRAPHHUNTER_COVERAGE=1) ---");
    let dsl = "User -[Auth]-> Host";
    let parsed = api
        .parse_dsl(ParseDslRequest { input: dsl.into(), name: None })
        .expect("parse_dsl");
    let baseline_hunt = api
        .run_hunt(RunHuntRequest {
            session: None,
            hypothesis: parsed.hypothesis,
            time_window: None,
            max_results: Some(1_000),
            scoring: None,
            dedup_mode: None,
        })
        .expect("run_hunt");
    eprintln!("hypothesis: {dsl}");
    eprintln!("path_count: {}", baseline_hunt.path_count);
    eprintln!("resp.coverage = {:?}", baseline_hunt.coverage);
    assert!(
        baseline_hunt.path_count > 0,
        "expected the User-Auth->Host hunt to find alice -> WORKSTATION-01"
    );
    assert!(
        baseline_hunt.coverage.coverage_start.is_some() && baseline_hunt.coverage.coverage_end.is_some(),
        "with GRAPHHUNTER_COVERAGE on and a non-empty graph, coverage span must be populated; got {:?}",
        baseline_hunt.coverage
    );
    assert!(
        baseline_hunt.coverage.missing_sources.is_empty(),
        "baseline (nothing marked blind yet) should have no missing_sources; got {:?}",
        baseline_hunt.coverage
    );

    // ══════════════════════════════════════════════════════════════════
    // [4/5] SOURCE COVERAGE / missing_sources
    // ══════════════════════════════════════════════════════════════════
    eprintln!("\n--- [4/5] SOURCE COVERAGE (GRAPHHUNTER_SOURCE_COVERAGE=1) ---");
    eprintln!("marking source 'fortigate:edge-fw' blind on the session, then re-running the SAME hunt");
    session
        .source_coverage
        .write()
        .unwrap()
        .record_missing("fortigate:edge-fw");

    let parsed2 = api
        .parse_dsl(ParseDslRequest { input: dsl.into(), name: None })
        .expect("parse_dsl");
    let blind_hunt = api
        .run_hunt(RunHuntRequest {
            session: None,
            hypothesis: parsed2.hypothesis,
            time_window: None,
            max_results: Some(1_000),
            scoring: None,
            dedup_mode: None,
        })
        .expect("run_hunt after marking source blind");
    eprintln!("resp.coverage (after marking blind) = {:?}", blind_hunt.coverage);
    assert_eq!(
        blind_hunt.path_count, baseline_hunt.path_count,
        "marking a source blind must not change the DFS result set itself (blind != empty)"
    );
    assert!(
        blind_hunt
            .coverage
            .missing_sources
            .iter()
            .any(|s| s == "fortigate:edge-fw"),
        "expected coverage.missing_sources to contain 'fortigate:edge-fw'; got {:?}",
        blind_hunt.coverage.missing_sources
    );
    assert!(
        blind_hunt.coverage.possibly_incomplete,
        "a missing source must mark the answer possibly_incomplete; coverage = {:?}",
        blind_hunt.coverage
    );
    eprintln!(
        "missing_sources = {:?}, possibly_incomplete = {}",
        blind_hunt.coverage.missing_sources, blind_hunt.coverage.possibly_incomplete
    );

    // ══════════════════════════════════════════════════════════════════
    // [5/5] FROZEN PROVENANCE — export_ocsf's mapping_hash per edge
    // ══════════════════════════════════════════════════════════════════
    eprintln!("\n--- [5/5] FROZEN PROVENANCE (export_ocsf) ---");
    let out = api
        .export_ocsf(ExportOcsfRequest {
            session: None,
            dataset_id: None,
            format: "ndjson".into(),
            page_size: None,
            offset: None,
        })
        .expect("export_ocsf");

    let mut seen_builtin = false;
    let mut seen_cfg = false;
    let mut printed = 0usize;
    for line in out.lines() {
        let v: serde_json::Value = serde_json::from_str(line).expect("ndjson line parses");
        if v.get("_meta").is_some() {
            continue; // pagination envelope line, not an event
        }
        let prov = &v["provenance"];
        let mapping_hash = prov["mapping_hash"].as_str().unwrap_or("<missing>");
        let parser_name = prov["parser_name"].as_str().unwrap_or("<missing>");
        let class_name = v["class_name"].as_str().unwrap_or("<missing>");
        eprintln!(
            "  edge class_name={class_name} parser_name={parser_name} mapping_hash={mapping_hash}"
        );
        assert_ne!(
            mapping_hash, "builtin:unknown",
            "a real ingested dataset must never fall back to the unknown placeholder"
        );
        if mapping_hash.starts_with("builtin:") {
            seen_builtin = true;
        }
        if mapping_hash.starts_with("cfg:") {
            seen_cfg = true;
        }
        printed += 1;
    }
    eprintln!("printed {printed} exported edges' provenance");
    assert!(printed > 0, "export_ocsf produced no events to inspect");
    assert!(
        seen_builtin,
        "expected at least one builtin:{{parser}} mapping_hash (FortiGate has no ConfigurableParser \
         auto-config support, so it stays on the hand-written parser identity)"
    );
    assert!(
        seen_cfg,
        "expected at least one cfg:<hash> mapping_hash (Sentinel/Sysmon route through the \
         auto-built FieldConfig -> ConfigurableParser path)"
    );

    eprintln!("\n########## ALL 4 SOT FLAGS VERIFIED WORKING END-TO-END ##########\n");

    unsafe {
        std::env::remove_var("GRAPHHUNTER_JOURNAL");
        std::env::remove_var("GRAPHHUNTER_GRAPHDELTA");
        std::env::remove_var("GRAPHHUNTER_COVERAGE");
        std::env::remove_var("GRAPHHUNTER_SOURCE_COVERAGE");
    }
}
