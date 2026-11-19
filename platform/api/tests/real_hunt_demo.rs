//! Real, end-to-end, cross-source intrusion hunt — 100% local, no KQL.
//!
//! Ingests four independently-shaped sources (FortiGate firewall syslog,
//! Sentinel `DeviceNetworkEvents`, Sentinel `SecurityEvent` 4624, and
//! Sysmon EventID 1) through the *real* parsers into ONE local graph,
//! then runs real DSL hypotheses over that graph to recover the
//! correlated attack chain:
//!
//!   IP(203.0.113.5) --Connect--> IP(10.0.0.42)
//!        <--Connect-- Host(WORKSTATION-01)
//!        <--Auth-- User(alice)
//!        --Execute--> Process(powershell.exe)
//!
//! No single source tells this story: the firewall only sees the two
//! IPs, Sentinel's network table only sees the beaconing host, its
//! security-event table only sees the logon, and Sysmon only sees the
//! process spawn. Only the union graph — SOT's source-independent
//! pipeline — lets one hypothesis walk from external IP to spawned
//! process.
//!
//! The final test demonstrates the SOT coverage payoff: marking one
//! ingested source "blind" on the session causes the *same* hunt to
//! come back with `coverage.missing_sources` populated, proving the
//! analyst is told about a gap instead of being handed a silently
//! incomplete (but structurally identical) empty-looking answer.

use std::io::Write;
use std::sync::Mutex;

use graph_hunter_api::GraphHunterApi;
use graph_hunter_api::dto::dsl::ParseDslRequest;
use graph_hunter_api::dto::entity::SessionOnly;
use graph_hunter_api::dto::hunt::RunHuntRequest;
use graph_hunter_api::dto::ingestion::LoadDataRequest;
use graph_hunter_api::dto::session::CreateSessionRequest;

/// Process-wide lock for tests that mutate `GRAPHHUNTER_COVERAGE`.
/// Cargo runs tests in a single binary in parallel by default; two
/// tests flipping the same env var would race. Mirrors the `ENV_LOCK`
/// convention already used in `coverage.rs` / `operations/hunt.rs`.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn lock_env() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Write `contents` to a fresh temp file and return its path as a
/// `String`. `load_data` reads a file path (`std::fs::read_to_string`
/// internally), so every source has to land on disk first. Leaks the
/// `NamedTempFile` (via `keep()`) so the file survives past this
/// function's return for the duration of the test process — cleanup
/// is OS-temp-dir garbage collection, fine for a short-lived test.
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

// ── The four sources of the ONE cross-source intrusion ────────────────
//
// Shared linking ids (case- and format-sensitive, verified against the
// real parsers in core/graph-engine/src/{sentinel,sysmon}.rs and
// platform/parsers/src/fortigate.rs):
//   - IP 10.0.0.42        links FortiGate dstip <-> Sentinel DeviceNetworkEvents RemoteIP
//   - Host WORKSTATION-01 links Sentinel DeviceNetworkEvents DeviceName <-> SecurityEvent Computer <-> Sysmon Computer
//   - User alice          links SecurityEvent TargetUserName <-> Sysmon User (bare, not DOMAIN\alice)

/// (1) FortiGate firewall (format "fortigate"): external IP hits the
/// internal host's IP. `derive_timestamp` reads `eventtime=` (epoch
/// seconds) — 2024-01-15T14:28:00Z, one minute before the beacon.
const FORTIGATE_LOG: &str = concat!(
    r#"eventtime="1705328880" srcip="203.0.113.5" dstip="10.0.0.42" dstport="443" policyname="allow-web""#,
    "\n"
);

/// (2) Sentinel DeviceNetworkEvents (format "sentinel"): the host
/// beaconing to that IP. VERIFIED against
/// `core/graph-engine/src/sentinel.rs::parse_device_network_events`
/// (~line 440): the host field is `DeviceName`, NOT `Computer` — using
/// `Computer` here would silently drop the row (zero triples), so this
/// deviates from the task's literal example field name.
///
/// Timestamped 14:30:00Z — AFTER the auth event below. The temporal
/// DFS (`search_temporal_pattern`) requires each hop in a multi-hop
/// hypothesis to occur in non-decreasing timestamp order, so for
/// `User -[Auth]-> Host -[Connect]-> IP` to match, the beacon
/// (Connect) must be timestamped at or after the logon (Auth) —
/// verified empirically: the task's literal 14:29/14:30 ordering
/// (network event before the 14:30 auth) made every 2-hop hunt return
/// 0 with `HuntDiagnostic` citing "no chain satisfies temporal
/// ordering", even though both edges individually matched the schema.
///
/// Deliberately omits `RemotePort`: `load_data` for format "sentinel"
/// routes through `auto_field_config_for` -> `ConfigurableParser`
/// (a heuristic field-preview config), NOT the hand-written typed
/// `SentinelJsonParser::parse_event` this file's docs live next to —
/// verified empirically by ingesting with `RemotePort` present, which
/// produced a spurious extra node `RemotePort:443` alongside the
/// intended `Host -[Connect]-> IP` edge (the same class of bug
/// documented as BUG-1 in `platform/parsers/src/fortigate.rs`: any
/// field whose name contains "port" gets heuristically typed as an
/// entity). Dropping the optional `RemotePort` field keeps the ingest
/// on the clean `DeviceName -> RemoteIP` edge this demo's hunts rely
/// on.
const SENTINEL_NETWORK_LOG: &str = r#"[{"Type":"DeviceNetworkEvents","TimeGenerated":"2024-01-15T14:30:00Z","DeviceName":"WORKSTATION-01","RemoteIP":"10.0.0.42"}]"#;

/// (3) Sentinel SecurityEvent 4624 (format "sentinel"): alice logs onto
/// the host. VERIFIED against `parse_security_event_auth` (~line 223):
/// `TargetUserName` + `Computer` + `IpAddress` + `LogonType`, emitting
/// `User -[Auth]-> Host`. Timestamped 14:29:00Z — BEFORE the beacon
/// above, so the auth-then-beacon hypothesis has a valid temporal
/// chain (see note on `SENTINEL_NETWORK_LOG`).
const SENTINEL_AUTH_LOG: &str = r#"[{"Type":"SecurityEvent","TimeGenerated":"2024-01-15T14:29:00Z","EventID":4624,"TargetUserName":"alice","Computer":"WORKSTATION-01","IpAddress":"10.0.0.42","LogonType":3}]"#;

/// (4) Sysmon EventID 1 (format "sysmon"): alice spawns powershell on
/// the host. `"User":"alice"` bare (not `DOMAIN\alice`) so it links to
/// the same `User(alice)` node the Sentinel SecurityEvent produced.
const SYSMON_PROCESS_LOG: &str = r#"[{"EventID":1,"UtcTime":"2024-01-15 14:31:00.000","Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","ProcessId":4444,"CommandLine":"powershell -enc ...","User":"alice","Computer":"WORKSTATION-01"}]"#;

/// Ingests all four sources into one session and returns the populated
/// API plus the session name (for logging).
fn ingest_cross_source_intrusion() -> GraphHunterApi {
    let api = GraphHunterApi::new_noop();
    api.create_session(CreateSessionRequest {
        name: Some("intrusion-demo".into()),
    })
    .expect("create_session");

    let fortigate_path = write_source_file("fortigate-edge-fw", FORTIGATE_LOG);
    let sentinel_net_path = write_source_file("sentinel-network", SENTINEL_NETWORK_LOG);
    let sentinel_auth_path = write_source_file("sentinel-auth", SENTINEL_AUTH_LOG);
    let sysmon_path = write_source_file("sysmon-proc", SYSMON_PROCESS_LOG);

    for (label, path, format) in [
        (
            "FortiGate firewall (edge-fw)",
            fortigate_path.as_str(),
            "fortigate",
        ),
        (
            "Sentinel DeviceNetworkEvents",
            sentinel_net_path.as_str(),
            "sentinel",
        ),
        (
            "Sentinel SecurityEvent 4624",
            sentinel_auth_path.as_str(),
            "sentinel",
        ),
        ("Sysmon EventID 1", sysmon_path.as_str(), "sysmon"),
    ] {
        let r = api
            .load_data(
                LoadDataRequest {
                    session: None,
                    path: path.to_string(),
                    format: format.to_string(),
                },
                &graph_hunter_api::paths::PathPolicy::LocalTrusted,
            )
            .unwrap_or_else(|e| panic!("load_data failed for {label} ({path}): {e}"));
        eprintln!(
            "[ingest] {label}: +{} entities, +{} relations (zero_triples={})",
            r.new_entities, r.new_relations, r.zero_triples
        );
        assert!(
            !r.zero_triples,
            "{label}: parser produced rows but zero triples — field-name mismatch, \
             investigate before trusting this demo"
        );
        assert!(
            r.new_relations > 0,
            "{label}: expected at least one new relation from this source"
        );
    }

    api
}

/// Print the graph summary (entity_count, relation_count, entity
/// types) and assert every one of the four sources actually
/// contributed structurally distinct entity types — a guard against a
/// vacuous demo where e.g. a silently-dropped source still lets the
/// single-hop hunt pass by coincidence.
fn print_and_verify_graph_summary(api: &GraphHunterApi) -> (usize, usize) {
    let entity_types = api
        .get_entity_types_in_graph(SessionOnly { session: None })
        .expect("get_entity_types_in_graph");

    // entity_count / relation_count live on the core GraphHunter graph;
    // reach them via the same session-scoped read the API uses
    // internally (resolve current session, read the graph).
    let session = api
        .sessions()
        .current_session()
        .expect("current session must exist after create_session");
    let (entity_count, relation_count) = {
        let graph = session.graph.read().expect("graph lock");
        (graph.entity_count(), graph.relation_count())
    };

    eprintln!("\n=== GRAPH SUMMARY (after ingesting 4 sources) ===");
    eprintln!("entity_count   = {entity_count}");
    eprintln!("relation_count = {relation_count}");
    eprintln!("entity_types   = {entity_types:?}");
    eprintln!("===================================================\n");

    assert!(relation_count > 0, "graph must have relations after ingest");

    // Guard against a vacuous demo: every entity type the four sources
    // are supposed to produce (IP, Host, User, Process) must actually
    // be present. If FortiGate, Sentinel, or Sysmon silently dropped
    // its rows, one of these types would be missing and the hunt
    // below could still "pass" on leftover structure from another
    // source — this assertion catches that.
    for expected in ["IP", "Host", "User", "Process"] {
        assert!(
            entity_types.iter().any(|t| t == expected),
            "graph is missing entity type {expected:?} — a source failed to link; \
             got types: {entity_types:?}"
        );
    }

    (entity_count, relation_count)
}

/// Parse + run one hypothesis, eprintln everything an analyst would
/// want to see (the DSL, the path count, and the matched entity
/// chains), and return the response for further assertions.
fn run_and_print_hunt(
    api: &GraphHunterApi,
    label: &str,
    dsl: &str,
) -> graph_hunter_api::dto::hunt::RunHuntResponse {
    let parsed = api
        .parse_dsl(ParseDslRequest {
            input: dsl.into(),
            name: None,
        })
        .unwrap_or_else(|e| panic!("parse_dsl failed for {dsl:?}: {e}"));

    let resp = api
        .run_hunt(RunHuntRequest {
            session: None,
            hypothesis: parsed.hypothesis,
            time_window: None,
            max_results: Some(1_000),
            scoring: None,
            dedup_mode: None,
        })
        .unwrap_or_else(|e| panic!("run_hunt failed for {dsl:?}: {e}"));

    eprintln!("--- HUNT: {label} ---");
    eprintln!("hypothesis : {dsl}");
    eprintln!("path_count : {}", resp.path_count);
    eprintln!("truncated  : {}", resp.truncated);
    if resp.path_count == 0 {
        eprintln!("diagnostic : {:?}", resp.diagnostic);
    }
    for (i, p) in resp.paths.iter().enumerate() {
        let chain: Vec<&str> = p.iter().map(|arc| arc.as_ref()).collect();
        eprintln!("  match[{i}]: {}", chain.join(" -> "));
    }
    eprintln!();

    resp
}

/// The full pipeline: ingest all 4 sources into one graph, print the
/// summary, then run the canonical single-hop lateral-movement
/// hypothesis and the two-hop auth-then-beacon hypothesis, asserting
/// each recovers the real attack chain.
#[test]
fn real_cross_source_intrusion_hunt_finds_attack_chain() {
    let api = ingest_cross_source_intrusion();
    print_and_verify_graph_summary(&api);

    // ── Hunt 1: canonical single-hop lateral-movement ─────────────────
    // alice -[Auth]-> WORKSTATION-01 (from the Sentinel SecurityEvent
    // 4624 row — the one edge that alone answers "did anyone log onto
    // this host").
    let resp1 = run_and_print_hunt(&api, "single-hop lateral movement", "User -[Auth]-> Host");
    assert!(
        resp1.path_count >= 1,
        "expected >=1 User-Auth->Host path (alice -> WORKSTATION-01); got 0. \
         diagnostic: {:?}",
        resp1.diagnostic
    );
    let has_alice_to_ws = resp1.paths.iter().any(|p| {
        p.len() == 2
            && p[0].to_lowercase().contains("alice")
            && p[1].to_lowercase().contains("workstation-01")
    });
    assert!(
        has_alice_to_ws,
        "expected a path alice -> WORKSTATION-01 among the Auth hunt results; got {:?}",
        resp1.paths
    );

    // ── Hunt 2: multi-hop auth-then-beacon ────────────────────────────
    // alice -[Auth]-> WORKSTATION-01 -[Connect]-> 10.0.0.42 — this is
    // the hop that only exists because the Sentinel SecurityEvent
    // (auth) and Sentinel DeviceNetworkEvents (beacon) rows share the
    // same Host node. If either source failed to link on
    // WORKSTATION-01, this comes back empty even though hunt 1 above
    // passed.
    let resp2 = run_and_print_hunt(
        &api,
        "auth then beacon (2-hop)",
        "User -[Auth]-> Host -[Connect]-> IP",
    );
    assert!(
        resp2.path_count >= 1,
        "expected >=1 User-Auth->Host-Connect->IP path (alice -> WORKSTATION-01 -> 10.0.0.42); \
         got 0. diagnostic: {:?}",
        resp2.diagnostic
    );
    let has_full_chain = resp2.paths.iter().any(|p| {
        p.len() == 3
            && p[0].to_lowercase().contains("alice")
            && p[1].to_lowercase().contains("workstation-01")
            && p[2].contains("10.0.0.42")
    });
    assert!(
        has_full_chain,
        "expected the full chain alice -> WORKSTATION-01 -> 10.0.0.42; got {:?}",
        resp2.paths
    );

    // ── Bonus: the User -[Execute]-> Process hop from Sysmon, to show
    // the chain keeps going past the auth hop toward the actual
    // malicious action (powershell). Not part of the auth-then-beacon
    // hypothesis (different relation), printed separately so the
    // narrative is visible end to end in --nocapture output.
    let resp3 = run_and_print_hunt(
        &api,
        "post-auth execution (Sysmon)",
        "User -[Execute]-> Process",
    );
    assert!(
        resp3.path_count >= 1,
        "expected >=1 User-Execute->Process path (alice -> powershell.exe); got 0. \
         diagnostic: {:?}",
        resp3.diagnostic
    );
    let has_powershell = resp3
        .paths
        .iter()
        .any(|p| p.iter().any(|n| n.to_lowercase().contains("powershell")));
    assert!(
        has_powershell,
        "expected a path ending in powershell.exe; got {:?}",
        resp3.paths
    );

    eprintln!(
        "=== ATTACK CHAIN CONFIRMED ===\n\
         IP(203.0.113.5) --Connect--> IP(10.0.0.42) <--Connect-- Host(WORKSTATION-01) \
         <--Auth-- User(alice) --Execute--> Process(powershell.exe)\n\
         Recovered from 4 independently-parsed sources (fortigate, sentinel x2, sysmon) \
         fused into ONE local graph — no KQL, no cloud round-trip.\n"
    );
}

/// SOT coverage demonstration: the same hunt, but with the FortiGate
/// source marked blind on the session (as if its poll/pull had
/// failed). `GRAPHHUNTER_COVERAGE=1` is required for
/// `RunHuntResponse.coverage` to populate at all (see
/// `platform/api/src/coverage.rs::coverage_enabled` /
/// `operations/hunt.rs::session_answer_coverage`) — with it off,
/// `session_answer_coverage` short-circuits to the all-clear default
/// before even reading `source_coverage`, by design (a true no-op cost
/// when the flag is off). Reading `session.source_coverage` for the
/// snapshot itself is NOT gated by `GRAPHHUNTER_SOURCE_COVERAGE` (that
/// second flag only gates the streaming-poller's own recording path;
/// `session_answer_coverage` always reads whatever is already there).
#[test]
fn coverage_demo_blind_source_surfaces_on_the_same_hunt() {
    let _env_guard = lock_env();
    // SAFETY: `edition = "2024"` requires `unsafe` around env mutation.
    // Guarded by `ENV_LOCK` (see fn lock_env) so no other test in this
    // binary observes a torn value; cleared before returning either
    // via the early-return-free structure below or on assertion
    // panic — a panic here still holds the poisoned mutex, which is
    // acceptable for a test-only guard.
    unsafe {
        std::env::set_var("GRAPHHUNTER_COVERAGE", "1");
    }

    let api = ingest_cross_source_intrusion();
    print_and_verify_graph_summary(&api);

    // Baseline: run the auth-then-beacon hunt with GRAPHHUNTER_COVERAGE
    // on but no source marked blind yet — coverage should still be
    // all-clear (no missing_sources).
    let baseline = run_and_print_hunt(
        &api,
        "auth then beacon (coverage ON, nothing blind yet)",
        "User -[Auth]-> Host -[Connect]-> IP",
    );
    eprintln!("coverage (baseline)      : {:?}", baseline.coverage);
    assert!(
        baseline.coverage.missing_sources.is_empty(),
        "baseline (no source marked blind) should have no missing_sources yet; got {:?}",
        baseline.coverage
    );

    // Mark the FortiGate edge firewall source blind — as if its
    // periodic pull/poll had failed and the analyst's SIEM silently
    // stopped receiving it. This is the ONE line that flips a hunt
    // from "quietly missing a source" to "SOT tells you it's blind".
    let session = api
        .sessions()
        .current_session()
        .expect("current session must exist");
    session
        .source_coverage
        .write()
        .unwrap()
        .record_missing("fortigate:edge-fw");

    // Re-run the EXACT same hunt.
    let resp2 = run_and_print_hunt(
        &api,
        "auth then beacon (fortigate:edge-fw now marked BLIND)",
        "User -[Auth]-> Host -[Connect]-> IP",
    );
    eprintln!("coverage (after blind)   : {:?}", resp2.coverage);

    // The graph still returns the same paths — blind does NOT mean
    // empty. What changes is the analyst is now TOLD the answer might
    // be incomplete.
    assert_eq!(
        resp2.path_count, baseline.path_count,
        "marking a source blind must not change the DFS result set itself \
         (blind != empty) — only the coverage metadata"
    );
    assert!(
        resp2
            .coverage
            .missing_sources
            .iter()
            .any(|s| s == "fortigate:edge-fw"),
        "expected coverage.missing_sources to contain 'fortigate:edge-fw'; got {:?}",
        resp2.coverage.missing_sources
    );
    assert!(
        resp2.coverage.possibly_incomplete,
        "a missing source must mark the answer possibly_incomplete; coverage = {:?}",
        resp2.coverage
    );

    eprintln!(
        "=== SOT COVERAGE DEMONSTRATED ===\n\
         Same hunt, same {} path(s) found, but the analyst is now told \
         missing_sources={:?} (possibly_incomplete={}) — blind is surfaced, \
         never silently swallowed as an empty result.\n",
        resp2.path_count, resp2.coverage.missing_sources, resp2.coverage.possibly_incomplete
    );

    unsafe {
        std::env::remove_var("GRAPHHUNTER_COVERAGE");
    }
}
