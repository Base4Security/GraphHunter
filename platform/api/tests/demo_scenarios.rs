//! F7 — demo-scenario snapshot tests.
//!
//! The three fixtures under `demo_data/` are the reproducible artifacts
//! the paper cites when demonstrating that GraphHunter's ingest →
//! hypothesis → matches pipeline runs end-to-end on realistic data.
//! Each test ingests a single fixture, parses its DSL hypothesis, runs
//! the hunt, and asserts a stable tolerance-bounded path count plus a
//! structural property of the returned paths. That last sanity check
//! is what catches regressions where the path_count matches by
//! coincidence but the *shape* of the paths has changed (e.g. the
//! matcher stops including the start node).
//!
//! The counts here were recorded on the current main branch (see
//! companion script `scripts/demo.sh` for the human-facing runner).
//! Tolerances are ±10 % on path count per the plan's F7 DoD — tight
//! enough that silently breaking a parser is caught, loose enough that
//! a benign reordering of dedup tie-breakers doesn't trigger the test.

use graph_hunter_api::GraphHunterApi;
use graph_hunter_api::dto::dsl::ParseDslRequest;
use graph_hunter_api::dto::hunt::RunHuntRequest;
use graph_hunter_api::dto::ingestion::LoadDataRequest;
use graph_hunter_api::dto::session::CreateSessionRequest;

/// Helper: create a session, ingest `path` with the given format, and
/// return the populated API. Panics on any step — these are snapshot
/// tests, failure should be loud.
fn api_with_fixture(session_name: &str, path: &str, format: &str) -> GraphHunterApi {
    let api = GraphHunterApi::new_noop();
    api.create_session(CreateSessionRequest {
        name: Some(session_name.into()),
    })
    .expect("create_session");
    let result = api
        .load_data(LoadDataRequest {
            session: None,
            path: path.into(),
            format: format.into(),
        })
        .expect("load_data");
    assert!(
        !result.zero_triples,
        "{session_name}: fixture produced zero triples — parser regression"
    );
    api
}

fn run_hunt_paths(api: &GraphHunterApi, dsl: &str) -> Vec<Vec<std::sync::Arc<str>>> {
    let parsed = api
        .parse_dsl(ParseDslRequest {
            input: dsl.into(),
            name: None,
        })
        .expect("parse_dsl");
    let resp = api
        .run_hunt(RunHuntRequest {
            session: None,
            hypothesis: parsed.hypothesis,
            time_window: None,
            max_results: Some(1_000),
            scoring: None,
            dedup_mode: None,
        })
        .expect("run_hunt");
    // `run_hunt` inlines paths when path_count ≤ 100; for these demo
    // fixtures we always expect to be inside that window.
    assert!(
        resp.path_count <= 100,
        "demo fixtures are meant to stay small enough for inline paths \
         (got {}); adjust fixture or use get_hunt_page",
        resp.path_count
    );
    resp.paths
}

/// Assert `actual` is within ±10 % of `expected` (inclusive of the
/// boundary). Catches regressions that drift the result set without
/// pinning brittle exact counts.
fn within_10pct(label: &str, actual: usize, expected: usize) {
    let delta = (expected as f64 * 0.10).ceil() as usize;
    let lo = expected.saturating_sub(delta);
    let hi = expected + delta;
    assert!(
        (lo..=hi).contains(&actual),
        "{label}: path_count={actual} outside tolerance [{lo}, {hi}] \
         (expected ~{expected} ±10%)"
    );
}

// ── Scenario 1 — office-spawn (Sysmon/EDR) ────────────────────────────
/// "Outlook spawns PowerShell, which resolves an attacker domain."
/// Two-hop chain over the Sysmon fixture, exercises the Process→Process
/// (Spawn) + Process→Domain (DNS) edges that make up the classic
/// phishing→execution→C2 pattern.
#[test]
fn demo_office_spawn_sysmon() {
    let api = api_with_fixture(
        "demo-office-spawn",
        "../../demo_data/apt_attack_simulation.json",
        "sysmon",
    );
    let paths = run_hunt_paths(&api, "Process -[Spawn]-> Process -[DNS]-> Domain");

    within_10pct("office-spawn", paths.len(), 22);
    assert!(!paths.is_empty(), "office-spawn: need ≥1 match");

    // Structural property: every path has exactly 3 nodes (2 hops).
    for (i, p) in paths.iter().enumerate() {
        assert_eq!(
            p.len(),
            3,
            "office-spawn[{i}]: path shape expected 3 nodes (Process→Process→Domain), got {:?}",
            p
        );
    }

    // At least one path must involve PowerShell — that's the scenario's
    // narrative. A parser regression that filters out powershell.exe
    // would quietly drop these and make the demo story vacuous.
    let has_powershell = paths
        .iter()
        .any(|p| p.iter().any(|n| n.to_lowercase().contains("powershell")));
    assert!(
        has_powershell,
        "office-spawn: expected at least one path through PowerShell; got {:?}",
        paths
    );
}

// ── Scenario 2 — lateral-movement (Sentinel/AAD) ──────────────────────
/// "User authenticates to a host." Single-hop auth chain over the
/// Sentinel SigninLogs fixture. The fixture only wires User→Host Auth
/// edges (no Host→Host chaining), so the 2-hop variant is explicitly
/// not asserted — see the probe in the commit message.
#[test]
fn demo_lateral_movement_sentinel() {
    let api = api_with_fixture(
        "demo-lateral-movement",
        "../../demo_data/sentinel_attack_simulation.json",
        "sentinel",
    );
    let paths = run_hunt_paths(&api, "User -[Auth]-> Host");

    within_10pct("lateral-movement", paths.len(), 4);
    assert!(!paths.is_empty(), "lateral-movement: need ≥1 match");

    for (i, p) in paths.iter().enumerate() {
        assert_eq!(
            p.len(),
            2,
            "lateral-movement[{i}]: expected 2 nodes (User→Host), got {:?}",
            p
        );
    }
}

// ── Scenario 3 — exfil-dns (generic CSV) ──────────────────────────────
/// "Host connects to an IP." Single-hop connect chain over the generic
/// CSV fixture — which in this release's field heuristics maps the
/// `hostname` column to Host and `dst_ip` to IP. The 3-hop exfil
/// narrative (Host→Process→DNS→Domain) is NOT asserted here because
/// the CSV fixture lacks a Process column; that scenario is marketed
/// in the docs as the "needs an EDR side-channel" variant.
#[test]
fn demo_exfil_dns_generic_csv() {
    let api = api_with_fixture(
        "demo-exfil-dns",
        "../../demo_data/generic_csv_logs.csv",
        "csv",
    );
    let paths = run_hunt_paths(&api, "Host -[Connect]-> IP");

    within_10pct("exfil-dns", paths.len(), 20);
    assert!(!paths.is_empty(), "exfil-dns: need ≥1 match");

    for (i, p) in paths.iter().enumerate() {
        assert_eq!(
            p.len(),
            2,
            "exfil-dns[{i}]: expected 2 nodes (Host→IP), got {:?}",
            p
        );
    }
}
