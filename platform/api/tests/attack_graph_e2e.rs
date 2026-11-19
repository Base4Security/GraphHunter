//! End to end through the ingestion journal: Sentinel SecurityEvent rows are
//! parsed by the Sentinel parser and journaled exactly as `ingest_siem`
//! does after a pull, and `attack_edges` projects them to attack-graph edges
//! (docs/unificacion/proyeccion-procedencia-ataque.md).
//!
//! File ingest (`load_data`) is not the path here: for `sentinel` and
//! `sysmon` files it maps fields with the preview heuristic
//! (`auto_field_config_for`), which keeps neither logon type, SID, domain
//! nor logoffs, so nothing reaches the projection. The second test pins
//! that down.
//!
//! The journal lives under `dirs::data_dir()`; on Linux that honours
//! `XDG_DATA_HOME`, which this test points at a temp dir so it never touches
//! the user's real journal. Other platforms skip it — the projection itself
//! is covered by `graph_hunter_attack_projection`'s own tests.
#![cfg(target_os = "linux")]

use std::io::Write;

use graph_hunter_api::GraphHunterApi;
use graph_hunter_api::dto::attack_graph::AttackEdgesRequest;
use graph_hunter_api::dto::ingestion::LoadDataRequest;
use graph_hunter_api::dto::session::CreateSessionRequest;
use graph_hunter_api::journal::JournalStore;
use serde_json::json;

const SID_ALICE: &str = "S-1-5-21-1000-2000-3000-1104";

// 2026-01-01T10:00:00Z: RDP logon of alice; 10:05 a network logon of bob
// (no session); 10:10 a logon from a domain the collection does not know;
// 18:00 alice logs off.
const SECURITY_EVENTS: &str = r#"[
{"Type":"SecurityEvent","TimeGenerated":"2026-01-01T10:00:00Z","EventID":4624,"Computer":"ws-01.corp.example.com","TargetUserName":"alice","TargetDomainName":"CORP","TargetUserSid":"S-1-5-21-1000-2000-3000-1104","LogonType":10,"IpAddress":"192.0.2.10"},
{"Type":"SecurityEvent","TimeGenerated":"2026-01-01T10:05:00Z","EventID":4624,"Computer":"ws-01.corp.example.com","TargetUserName":"bob","TargetDomainName":"CORP","LogonType":3,"IpAddress":"192.0.2.11"},
{"Type":"SecurityEvent","TimeGenerated":"2026-01-01T10:10:00Z","EventID":4624,"Computer":"ws-01.corp.example.com","TargetUserName":"mallory","TargetDomainName":"OTHER","LogonType":10,"IpAddress":"192.0.2.12"},
{"Type":"SecurityEvent","TimeGenerated":"2026-01-01T18:00:00Z","EventID":4634,"Computer":"ws-01.corp.example.com","TargetUserName":"alice","TargetDomainName":"CORP","TargetUserSid":"S-1-5-21-1000-2000-3000-1104","LogonType":10}
]"#;

const LOGON_MS: i64 = 1_767_261_600_000; // 2026-01-01T10:00:00Z
const LOGOFF_MS: i64 = 1_767_290_400_000; // 2026-01-01T18:00:00Z
const H: i64 = 3_600_000;

/// Points the journal at a fresh temp dir. Both tests in this binary call
/// it under `ENV_LOCK` and keep the guard for their whole run.
fn fresh_data_dir() -> (std::sync::MutexGuard<'static, ()>, tempfile::TempDir) {
    let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let data = tempfile::tempdir().unwrap();
    // SAFETY: `edition = "2024"` requires `unsafe` around env mutation;
    // `ENV_LOCK` serialises the two tests of this binary.
    unsafe {
        std::env::set_var("XDG_DATA_HOME", data.path());
        std::env::set_var("GRAPHHUNTER_JOURNAL", "1");
    }
    (guard, data)
}

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn identities() -> serde_json::Value {
    json!({
        "domains": {"CORP": "corp.example.com"},
        "hosts": ["ws-01.corp.example.com"],
        "system_accounts": ["SYSTEM"]
    })
}

#[test]
fn security_events_become_attack_edges_through_the_journal() {
    let (_guard, _data) = fresh_data_dir();

    let parser = graph_hunter_api::format_registry::make_parser_for_format("sentinel").unwrap();
    let (events, stats) = parser.parse_raw_with_stats(SECURITY_EVENTS);
    let store =
        JournalStore::open(graph_hunter_api::journal::ingest_journal_dir().unwrap()).unwrap();
    let (_, err) = graph_hunter_api::journal::journal_batch_keyed(
        Some(&store),
        "ds-e2e",
        "siem",
        "ds-e2e",
        "sentinel",
        &events,
        &stats.skipped_samples,
        0,
    );
    assert!(err.is_none());

    let api = GraphHunterApi::new_noop();
    let identities = identities();
    let at = |watermark_ms| {
        api.attack_edges(AttackEdgesRequest {
            identities: identities.clone(),
            watermark_ms: Some(watermark_ms),
            ..Default::default()
        })
        .unwrap()
    };

    // Before the logoff's grace period runs out alice's session is live,
    // with the logoff as its expiry anchor; bob's network logon creates no
    // session; mallory's domain is unknown and is reported, not guessed.
    let r = at(LOGOFF_MS + H);
    assert_eq!(r.envelopes, 4);
    let session = r
        .edges
        .iter()
        .find(|e| e.kind == "HasSession")
        .expect("alice's RDP logon is a session");
    assert_eq!(session.src, "ws-01.corp.example.com");
    assert_eq!(session.dst, SID_ALICE);
    assert_eq!(session.confidence.as_deref(), Some("confirmed"));
    assert_eq!(session.expires_at, Some(LOGOFF_MS + 8 * H));
    assert!(r.edges.iter().all(|e| !e.dst.starts_with("bob")));
    assert_eq!(r.unresolved.get("domain_unknown"), Some(&1));

    // After the grace period nothing transient is left.
    let r = at(LOGOFF_MS + 8 * H + 1);
    assert!(r.edges.iter().all(|e| e.kind != "HasSession"), "{r:?}");

    // The journal is the state: asking twice gives the same answer.
    assert_eq!(
        serde_json::to_value(at(LOGON_MS + H)).unwrap(),
        serde_json::to_value(at(LOGON_MS + H)).unwrap()
    );
}

#[test]
fn file_ingest_of_security_events_reaches_no_attack_edge() {
    let (_guard, _data) = fresh_data_dir();
    let mut f = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
    f.write_all(SECURITY_EVENTS.as_bytes()).unwrap();
    let api = GraphHunterApi::new_noop();
    api.create_session(CreateSessionRequest {
        name: Some("attack-graph-file".into()),
    })
    .unwrap();
    api.load_data(
        LoadDataRequest {
            session: None,
            path: f.path().to_string_lossy().into_owned(),
            format: "sentinel".into(),
        },
        &graph_hunter_api::paths::PathPolicy::LocalTrusted,
    )
    .unwrap();
    let r = api
        .attack_edges(AttackEdgesRequest {
            identities: identities(),
            ..Default::default()
        })
        .unwrap();
    // Journaled, but by the heuristic mapping: no logon type, no domain.
    assert!(r.envelopes > 0);
    assert!(r.edges.is_empty(), "{r:?}");
}
