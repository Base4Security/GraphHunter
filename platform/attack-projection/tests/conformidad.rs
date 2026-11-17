//! Runs every case of docs/unificacion/conformidad/proyeccion.json; the Python
//! reference (research/gtdin/test_conformidad.py) runs the same file.

use graph_hunter_attack_projection::{Edge, Identities, Params, Projector};
use serde_json::{Value, json};

fn load() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/unificacion/conformidad/proyeccion.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("conformance file"))
        .expect("valid JSON")
}

#[test]
fn all_conformance_cases_pass() {
    let doc = load();
    let cases = doc["cases"].as_array().expect("cases");
    assert!(cases.len() >= 17);
    for case in cases {
        let id = case["id"].as_str().unwrap_or("?");
        let mut p = Projector::new(
            Identities::from_json(&doc["identities"]),
            Params::from_json(&doc["params"]),
        );
        for (i, step) in case["steps"].as_array().expect("steps").iter().enumerate() {
            let got = serde_json::to_value(p.apply(&step["input"])).expect("serialise");
            assert_eq!(got, step["expect"], "case {id}, step {i}");
        }
        for want in case
            .get("final_state")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let e = &want["edge"];
            let edge = Edge {
                src: e["src"].as_str().unwrap().into(),
                kind: e["kind"].as_str().unwrap().into(),
                dst: e["dst"].as_str().unwrap().into(),
            };
            let s = p
                .edges
                .get(&edge)
                .unwrap_or_else(|| panic!("case {id}: missing final edge"));
            let got = json!({
                "edge": e, "origins": s.origins, "support": s.support, "first_seen": s.first_seen,
                "last_seen": s.last_seen, "expires_at": s.expires_at, "confidence": s.confidence,
            });
            assert_eq!(&got, want, "case {id}: final state");
        }
    }
}

#[test]
fn snapshot_edges_never_expire_and_sessions_do() {
    let doc = load();
    let mut p = Projector::new(
        Identities::from_json(&doc["identities"]),
        Params::from_json(&doc["params"]),
    );
    p.load_snapshot([Edge {
        src: "ws01.corp.example".into(),
        kind: "HasSession".into(),
        dst: "bob@corp.example".into(),
    }]);
    let first = &doc["cases"][0]["steps"][0]["input"];
    p.apply(first);
    let t = first["ocsf"]["time"].as_i64().unwrap();
    let ttl = doc["params"]["session_ttl_ms"].as_i64().unwrap();
    assert_eq!(p.live(t + ttl - 1).count(), 2);
    assert_eq!(p.live(t + ttl).count(), 1);
}
