//! Reproduction probe for the frontend "se queda ingestando" hang on the
//! MDE portal timeline CSV. Drives the SAME path the Tauri UI uses
//! (`load_data_streaming` → auto FieldConfig → ConfigurableParser →
//! journal/graphdelta), with stage timings, against the real export.
//!
//! Ignored by default: needs the real CSV on disk. Run with
//!   GRAPHHUNTER_MDE_CSV=<path> cargo test --test mde_ingest_probe -- --ignored --nocapture

use std::time::{Duration, Instant};

use graph_hunter_api::GraphHunterApi;
use graph_hunter_api::dto::ingestion::LoadDataStreamingRequest;
use graph_hunter_api::dto::session::CreateSessionRequest;

#[test]
#[ignore]
fn mde_csv_streaming_ingest_probe() {
    let path = std::env::var("GRAPHHUNTER_MDE_CSV")
        .expect("set GRAPHHUNTER_MDE_CSV to the MDE timeline CSV path");

    let api = GraphHunterApi::new_noop();
    api.create_session(CreateSessionRequest {
        name: Some("mde-probe".to_string()),
    })
    .expect("create_session");

    let t0 = Instant::now();
    let started = api
        .load_data_streaming(LoadDataStreamingRequest {
            session: None,
            path: path.clone(),
            format: "csv".into(),
            config: None,
            date_from: None,
            date_to: None,
        }, &graph_hunter_api::paths::PathPolicy::LocalTrusted)
        .expect("load_data_streaming should start");
    println!("job started in {:?}: {:?}", t0.elapsed(), started.job_id);

    // Poll the dataset record until counts land or we time out. The
    // background thread patches entity_count/relation_count on success and
    // the emitter (noop) swallows progress events, so dataset counts are the
    // only completion signal visible from here.
    let deadline = Instant::now() + Duration::from_secs(600);
    loop {
        std::thread::sleep(Duration::from_secs(5));
        let datasets = api
            .list_datasets(graph_hunter_api::dto::dataset::ListDatasetsRequest { session: None })
            .expect("list_datasets");
        let ds = datasets
            .iter()
            .find(|d| d.id == started.dataset_id)
            .expect("dataset registered");
        println!(
            "t={:?} entities={} relations={}",
            t0.elapsed(),
            ds.entity_count,
            ds.relation_count
        );
        if ds.entity_count > 0 || ds.relation_count > 0 {
            println!("INGEST COMPLETED in {:?}", t0.elapsed());
            break;
        }
        if Instant::now() > deadline {
            panic!(
                "HANG REPRODUCED: streaming ingest made no progress in 600s (t={:?})",
                t0.elapsed()
            );
        }
    }
}
