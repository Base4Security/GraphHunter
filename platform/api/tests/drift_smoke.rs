//! Drift smoke test (Win 3 D7).
//!
//! Baseline ingest sends `{"src": "<ip>"}` events; mutated ingest sends
//! `{"src": "<domain>"}`. The aggregated drift snapshot must carry BOTH
//! type tags for the `src` field, which is the signal the Prometheus
//! scrape and the future schema-drift detector rely on.
//!
//! Note on tag choice: the classifier is *semantic*, not JSON-structural
//! (e.g. the string `"1000"` still gets the `integer` tag). We use an
//! IP→domain shift because those tags cannot alias under the classifier.

use graph_hunter_api::GraphHunterApi;
use graph_hunter_core::drift::{DriftCollector, DriftStore};
use serde_json::json;

fn collect_snapshot(events: &[serde_json::Value]) -> graph_hunter_core::drift::DriftSnapshot {
    let mut c = DriftCollector::new();
    for ev in events {
        c.observe_event(ev);
    }
    c.into_snapshot()
}

#[test]
fn drift_snapshot_captures_type_shift_on_mutated_field() {
    // Plug an in-memory DriftStore into the API surface.
    let api = GraphHunterApi::new_noop();
    {
        let handle = api.drift_store_handle();
        let store = DriftStore::open_in_memory().expect("in-memory drift store");
        *handle.lock().unwrap() = Some(store);
    }

    // Baseline: src field carries IPs.
    let baseline: Vec<_> = (0..100)
        .map(|i| json!({ "user": format!("user-{}", i % 5), "src": format!("10.0.0.{}", (i % 250) + 1) }))
        .collect();
    api.record_drift("ds-smoke", &collect_snapshot(&baseline));

    // Mutated: same shape, `src` is now a domain.
    let mutated: Vec<_> = (0..100)
        .map(|i| json!({ "user": format!("user-{}", i % 5), "src": format!("host{}.example.com", i) }))
        .collect();
    api.record_drift("ds-smoke", &collect_snapshot(&mutated));

    // Emit Prometheus metrics for the past 24h (covers both snapshots we
    // just recorded).
    let text = api.drift_metrics_text(86_400);

    // Sanity — the dataset showed up and rows_observed sums over both batches.
    assert!(
        text.contains("graphhunter_drift_rows_observed{dataset_id=\"ds-smoke\"} 200"),
        "missing rows_observed; got:\n{text}"
    );
    // The signal we care about: `src` has both ip AND domain tags.
    assert!(
        text.contains(
            "graphhunter_drift_type_count{dataset_id=\"ds-smoke\",field=\"src\",type_tag=\"ip\"} 100"
        ),
        "src/ip tag missing; got:\n{text}"
    );
    assert!(
        text.contains(
            "graphhunter_drift_type_count{dataset_id=\"ds-smoke\",field=\"src\",type_tag=\"domain\"} 100"
        ),
        "src/domain tag missing (drift signal absent); got:\n{text}"
    );
    // `user` stayed string across both batches — should NOT show type drift.
    assert!(
        !text.contains(
            "graphhunter_drift_type_count{dataset_id=\"ds-smoke\",field=\"user\",type_tag=\"ip\"}"
        ),
        "user unexpectedly flagged with ip tag; got:\n{text}"
    );
}

#[test]
fn drift_metrics_text_is_empty_when_store_is_unconfigured() {
    let api = GraphHunterApi::new_noop();
    // Intentionally leave drift_store unconfigured.
    assert_eq!(api.drift_metrics_text(60).trim(), "");
    // record_drift should still be a no-op that doesn't panic.
    api.record_drift("ds-x", &collect_snapshot(&[json!({"k": "v"})]));
}
