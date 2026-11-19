//! End to end: Windows Security events → Sysmon/Security parser → journal
//! envelopes → projector. Synthetic values only (corp.example).

use graph_hunter_attack_projection::ingest::{apply_envelopes, to_millis};
use graph_hunter_attack_projection::{AttackDelta, Confidence, Identities, Params, Projector};
use graph_hunter_canonical::{CanonicalEnvelope, ProvenanceCtx};
use graph_hunter_core::SysmonJsonParser;
use graph_hunter_core::parser::LogParser;
use serde_json::json;

fn envelopes(json: &str) -> Vec<CanonicalEnvelope> {
    SysmonJsonParser
        .parse_raw(json)
        .iter()
        .map(|ev| {
            let raw = serde_json::to_string(ev).unwrap();
            let prov = ProvenanceCtx::for_builtin_parser("sysmon", "ds-test", raw.as_bytes());
            CanonicalEnvelope::new_insert(
                "test".into(),
                "sysmon".into(),
                ev.timestamp,
                0,
                raw,
                prov,
            )
        })
        .collect()
}

fn projector() -> Projector {
    let ids = Identities::from_json(&json!({
        "domains": {"CORP": "corp.example"},
        "hosts": ["ws01.corp.example", "srv01.corp.example"],
        "system_accounts": ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"],
        "machine_account_suffix": "$"
    }));
    Projector::new(ids, Params::default())
}

#[test]
fn rdp_logon_process_and_logoff_flow_into_the_attack_graph() {
    let log = r#"[
      {"EventID": 4624, "EventTime": "2026-01-01 10:00:00", "Computer": "ws01.corp.example",
       "TargetUserName": "alice", "TargetDomainName": "CORP", "LogonType": 10, "IpAddress": "192.0.2.10"},
      {"EventID": 4688, "EventTime": "2026-01-01 10:05:00", "Computer": "ws01.corp.example",
       "NewProcessName": "C:\\Windows\\System32\\cmd.exe", "SubjectUserName": "bob", "SubjectDomainName": "CORP",
       "ParentProcessName": "C:\\Windows\\explorer.exe"},
      {"EventID": 4688, "EventTime": "2026-01-01 10:06:00", "Computer": "ws01.corp.example",
       "NewProcessName": "C:\\Windows\\System32\\svchost.exe", "SubjectUserName": "SYSTEM", "SubjectDomainName": "NT AUTHORITY",
       "ParentProcessName": "C:\\Windows\\System32\\services.exe"},
      {"EventID": 4625, "EventTime": "2026-01-01 10:07:00", "Computer": "srv01.corp.example",
       "TargetUserName": "carol", "TargetDomainName": "CORP", "LogonType": 2},
      {"EventID": 4634, "EventTime": "2026-01-01 12:00:00", "Computer": "ws01.corp.example",
       "TargetUserName": "alice", "TargetDomainName": "CORP", "LogonType": 10}
    ]"#;
    let mut p = projector();
    let deltas = apply_envelopes(&mut p, &envelopes(log));

    let asserts: Vec<_> = deltas
        .iter()
        .filter_map(|d| match d {
            AttackDelta::Assert {
                edge, confidence, ..
            } => Some((
                edge.src.as_str(),
                edge.kind.as_str(),
                edge.dst.as_str(),
                *confidence,
            )),
            _ => None,
        })
        .collect();
    assert!(asserts.contains(&(
        "ws01.corp.example",
        "HasSession",
        "alice@corp.example",
        Confidence::Confirmed
    )));
    assert!(asserts.contains(&(
        "alice@corp.example",
        "CanRDP",
        "ws01.corp.example",
        Confidence::Confirmed
    )));
    assert!(asserts.contains(&(
        "ws01.corp.example",
        "HasSession",
        "bob@corp.example",
        Confidence::Inferred
    )));
    assert!(
        !asserts.iter().any(|a| a.2.contains("system")),
        "system account excluded"
    );
    assert!(
        !asserts.iter().any(|a| a.2.contains("carol")),
        "failed logon projects nothing"
    );

    let close = deltas.iter().find_map(|d| match d {
        AttackDelta::Close {
            edge, expires_at, ..
        } if edge.dst == "alice@corp.example" => Some(*expires_at),
        _ => None,
    });
    let logoff_ms = to_millis(1_767_268_800); // 2026-01-01 12:00:00 UTC
    assert_eq!(close, Some(logoff_ms + Params::default().session_grace_ms));
    assert!(
        !deltas
            .iter()
            .any(|d| matches!(d, AttackDelta::Unresolved { .. })),
        "{deltas:?}"
    );
}

#[test]
fn replaying_the_journal_is_a_no_op() {
    let log = r#"[{"EventID": 4624, "EventTime": "2026-01-01 10:00:00", "Computer": "ws01.corp.example",
       "TargetUserName": "alice", "TargetDomainName": "CORP", "LogonType": 2}]"#;
    let envs = envelopes(log);
    let mut p = projector();
    assert_eq!(apply_envelopes(&mut p, &envs).len(), 1);
    assert!(apply_envelopes(&mut p, &envs).is_empty());
}

#[test]
fn seconds_and_millis() {
    assert_eq!(to_millis(1_767_261_600), 1_767_261_600_000);
    assert_eq!(to_millis(1_767_261_600_000), 1_767_261_600_000);
}
