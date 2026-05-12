//! Integration smoke test for the full PCAP flow ingest path.
//!
//! Runs `pcap_ingest_streaming` against a real capture on the
//! operator's machine. Gated behind the `GH_PCAP_FIXTURE` env var so
//! CI / other devs don't blow up when the file isn't present.
//!
//! Run with:
//!   $env:GH_PCAP_FIXTURE = 'C:\Users\lsotomayor\Downloads\evo_telecarga_externa.pcap'
//!   cargo test --test pcap_ingest_real_file -- --nocapture

use std::sync::Arc;

use graph_hunter_api::dto::session::CreateSessionRequest;
use graph_hunter_api::pcap::pcap_ingest_streaming;
use graph_hunter_api::{GraphHunterApi, NoopEmitter};

#[test]
fn ingest_real_world_pcap() {
    let path = match std::env::var("GH_PCAP_FIXTURE") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("skipping: GH_PCAP_FIXTURE not set");
            return;
        }
    };
    if !std::path::Path::new(&path).exists() {
        eprintln!("skipping: fixture missing at {path}");
        return;
    }

    // Bootstrap a fresh API + session so the ingest has somewhere to
    // land. We don't need any of the other API features (GeoIP, GNN);
    // the canonical Session is enough.
    let api = GraphHunterApi::new_noop();
    let _info = api
        .create_session(CreateSessionRequest {
            name: Some("pcap-real-file-test".to_string()),
        })
        .expect("session create");
    let session = api
        .sessions()
        .current_session()
        .expect("current session set after create_session");

    let emitter: Arc<dyn graph_hunter_api::EventEmitter> = Arc::new(NoopEmitter);
    let dataset_id = "test-dataset";

    let started = std::time::Instant::now();
    let (new_entities, new_relations) =
        pcap_ingest_streaming(&path, &session, dataset_id, &emitter, "test-job")
            .expect("pcap_ingest_streaming");
    let elapsed = started.elapsed();

    eprintln!("\n──────── PCAP flow ingest ────────");
    eprintln!("file:             {path}");
    eprintln!("new_entities:     {new_entities}");
    eprintln!("new_relations:    {new_relations}");
    eprintln!("elapsed:          {elapsed:?}");

    let graph = session.graph.read().expect("graph read lock");
    eprintln!("total entities:   {}", graph.entity_count());
    eprintln!("total relations:  {}", graph.relation_count());
    // Surface entity-type breakdown so the test output shows whether
    // L7 produced any Domain nodes alongside the L3/L4 IP nodes.
    let counts = graph.entity_type_counts();
    eprintln!("entities by type:");
    for (t, n) in &counts {
        eprintln!("  {t:<10} {n}");
    }
    eprintln!("──────────────────────────────────\n");

    assert!(new_entities > 0, "expected at least one IP entity");
    assert!(new_relations > 0, "expected at least one Connect edge");
}
