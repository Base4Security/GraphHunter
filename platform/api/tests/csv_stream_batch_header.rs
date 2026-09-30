//! Every streamed CSV batch — the first one included — must be parsed
//! against the file's header.
//!
//! The streaming path cuts a CSV into 50k-record batches and splits each
//! batch across rayon workers. Batch 1 used to carry the header only in its
//! first sub-chunk, so the other workers took a data row as column names:
//! on a 1M-row Auth0 export the first batch produced 19k events instead of
//! 230k, with no error. Nothing but a count catches this, so this test
//! ingests a file whose every row mints a distinct user and checks that all
//! of them arrive.
//!
//! Own test binary: it disables the journal through the environment, which
//! is process-wide.

use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use graph_hunter_api::dto::ingestion::LoadDataStreamingRequest;
use graph_hunter_api::dto::session::CreateSessionRequest;
use graph_hunter_api::events::FnEmitter;
use graph_hunter_api::GraphHunterApi;

/// Spans three batches of the streaming path's 50k records.
const ROWS: usize = 120_000;

#[test]
fn every_batch_parses_against_the_header() {
    // SAFETY: this binary holds a single test; nothing reads env concurrently.
    unsafe { std::env::set_var("GRAPHHUNTER_JOURNAL", "0") };

    let dir = std::env::temp_dir().join(format!("gh-csv-batch-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("auth.csv");
    let mut csv = String::from("timestamp,user_name,ip\n");
    for i in 0..ROWS {
        csv.push_str(&format!(
            "2026-08-01T00:{:02}:{:02}Z,user{i},10.{}.{}.{}\n",
            (i / 60) % 60,
            i % 60,
            (i >> 16) & 255,
            (i >> 8) & 255,
            i & 255
        ));
    }
    std::fs::write(&path, csv).unwrap();

    let (tx, rx) = mpsc::channel();
    let tx = std::sync::Mutex::new(tx);
    let emitter = FnEmitter(move |event: &str, payload: serde_json::Value| {
        if event == "ingest-complete" || event == "ingest-error" {
            let _ = tx.lock().unwrap().send((event.to_string(), payload));
        }
    });
    let api = GraphHunterApi::new(Arc::new(emitter));
    api.create_session(CreateSessionRequest { name: Some("t".into()) })
        .unwrap();
    api.load_data_streaming(
        LoadDataStreamingRequest {
            session: None,
            path: path.to_string_lossy().into_owned(),
            format: "csv".into(),
            config: None,
            date_from: None,
            date_to: None,
        },
        &graph_hunter_api::paths::PathPolicy::LocalTrusted,
    )
    .unwrap();

    let (event, payload) = rx.recv_timeout(Duration::from_secs(300)).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(event, "ingest-complete", "{payload}");

    let users = api
        .get_entities_by_type(graph_hunter_api::dto::entity::EntitiesByTypeRequest {
            session: None,
            type_name: "User".into(),
        })
        .unwrap();
    let parsed: std::collections::HashSet<_> = users.into_iter().collect();
    let missing: Vec<usize> = (0..ROWS)
        .filter(|i| !parsed.contains(&format!("user{i}")))
        .collect();
    assert!(
        missing.is_empty(),
        "{} of {ROWS} rows never became a User (first missing: {:?})",
        missing.len(),
        &missing[..missing.len().min(5)]
    );
}
