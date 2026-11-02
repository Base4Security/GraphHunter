//! Witness test for the `provenance_stability` / `mapping_edit` SOT audit
//! channel (the LAST witness on `loss_reconstruction`).
//!
//! Contract under test: editing a mapping after ingest must NOT
//! retroactively change an already-ingested edge's EXPORTED provenance.
//! `export_ocsf` must derive `provenance.mapping_hash` from the FROZEN
//! per-dataset `DatasetInfo` recorded at ingest time — never from a
//! "current"/global mapping — so:
//!   1. the hash is a real content hash (not a static placeholder),
//!   2. two datasets with different mappings get different hashes
//!      (distinguishable),
//!   3. re-exporting the same session yields the SAME hash (frozen).
//! Datasets ingested through a hand-written (non-FieldConfig) parser must
//! get a real `builtin:{parser}` identity, not the useless `builtin:unknown`.

use graph_hunter_api::GraphHunterApi;
use graph_hunter_api::dto::export::ExportOcsfRequest;
use graph_hunter_api::dto::ingestion::{LoadDataRequest, LoadDataWithConfigRequest};
use graph_hunter_api::dto::session::CreateSessionRequest;
use graph_hunter_core::field_preview::{FieldConfig, FieldMapping, FieldRole};
use serde_json::Value;
use std::io::Write;

/// Small CSV fixture: two canonical columns so `ConfigurableParser`
/// produces at least one edge under either config below, regardless of
/// how `host`/`service` gets mapped.
const CSV_BODY: &str = "user,host\nalice,server1\n";

fn write_csv(dir: &tempfile::TempDir, name: &str) -> String {
    let path = dir.path().join(name);
    let mut f = std::fs::File::create(&path).expect("create csv");
    f.write_all(CSV_BODY.as_bytes()).expect("write csv");
    path.to_string_lossy().to_string()
}

fn config_with_host_type(host_entity_type: &str) -> FieldConfig {
    FieldConfig {
        mappings: vec![
            FieldMapping {
                raw_name: "user".into(),
                role: FieldRole::Node,
                entity_type: Some("User".into()),
                timestamp_format: None,
                locale: None,
            },
            FieldMapping {
                raw_name: "host".into(),
                role: FieldRole::Node,
                entity_type: Some(host_entity_type.into()),
                timestamp_format: None,
                locale: None,
            },
        ],
    }
}

/// Collect `(source_dataset_id -> Vec<mapping_hash>)` from an OCSF ndjson
/// export, skipping the leading `_meta` line.
fn mapping_hashes_by_dataset(ndjson: &str) -> std::collections::HashMap<String, Vec<String>> {
    let mut out: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for line in ndjson.lines() {
        let v: Value = serde_json::from_str(line).expect("each line is JSON");
        if v.get("_meta").is_some() {
            continue;
        }
        let prov = &v["provenance"];
        let dataset = prov["source_dataset_id"]
            .as_str()
            .expect("source_dataset_id present")
            .to_string();
        let hash = prov["mapping_hash"]
            .as_str()
            .expect("mapping_hash present")
            .to_string();
        out.entry(dataset).or_default().push(hash);
    }
    out
}

#[test]
fn provenance_mapping_hash_is_frozen_and_distinguishes_configs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let api = GraphHunterApi::new_noop();
    api.create_session(CreateSessionRequest {
        name: Some("provenance-stability".into()),
    })
    .expect("create_session");

    let path_a = write_csv(&dir, "a.csv");
    let path_b = write_csv(&dir, "b.csv");

    let cfg_a = config_with_host_type("Host");
    let cfg_b = config_with_host_type("Service");

    let result_a = api
        .load_data_with_config(
            LoadDataWithConfigRequest {
                session: None,
                path: path_a,
                config: cfg_a,
            },
            &graph_hunter_api::paths::PathPolicy::LocalTrusted,
        )
        .expect("load_data_with_config A");
    assert!(result_a.new_relations > 0, "dataset A must produce edges");

    let result_b = api
        .load_data_with_config(
            LoadDataWithConfigRequest {
                session: None,
                path: path_b,
                config: cfg_b,
            },
            &graph_hunter_api::paths::PathPolicy::LocalTrusted,
        )
        .expect("load_data_with_config B");
    assert!(result_b.new_relations > 0, "dataset B must produce edges");

    let export_once = |api: &GraphHunterApi| {
        api.export_ocsf(ExportOcsfRequest {
            session: None,
            dataset_id: None,
            format: "ndjson".into(),
            page_size: None,
            offset: None,
        })
        .expect("export_ocsf")
    };

    let out1 = export_once(&api);
    let by_dataset_1 = mapping_hashes_by_dataset(&out1);
    assert_eq!(
        by_dataset_1.len(),
        2,
        "expected exactly 2 datasets in the export, got {:?}",
        by_dataset_1.keys().collect::<Vec<_>>()
    );

    let mut hash_a: Option<String> = None;
    let mut hash_b: Option<String> = None;
    for (_dataset_id, hashes) in &by_dataset_1 {
        let first = hashes.first().expect("at least one event").clone();
        assert!(
            hashes.iter().all(|h| *h == first),
            "every event in the same dataset must share one mapping_hash: {:?}",
            hashes
        );
        // Real content hash, not a static placeholder.
        assert!(
            !first.eq("builtin:configurable") && !first.eq("builtin:unknown"),
            "mapping_hash must not be a static placeholder, got: {first}"
        );
        assert!(
            first.starts_with("cfg:") || first.starts_with("vrl-") || first.starts_with("vrl:"),
            "FieldConfig dataset must carry a real content-hash mapping_hash \
             (cfg:/vrl- prefix), got: {first}"
        );
        if hash_a.is_none() {
            hash_a = Some(first);
        } else {
            hash_b = Some(first);
        }
    }
    let hash_a = hash_a.expect("hash A");
    let hash_b = hash_b.expect("hash B");
    assert_ne!(
        hash_a, hash_b,
        "dataset A and dataset B have different FieldConfigs and must get \
         different mapping_hash values (distinguishable)"
    );

    // Re-export: the identity must be FROZEN — unaffected by anything that
    // happened between the two exports (nothing did here, but this is the
    // shape of the regression the witness closes: editing the session's
    // "current" mapping after ingest must not retroactively change an
    // already-ingested edge's exported provenance).
    let out2 = export_once(&api);
    let by_dataset_2 = mapping_hashes_by_dataset(&out2);
    let mut hashes_2: Vec<&String> = by_dataset_2.values().flatten().collect();
    hashes_2.sort();
    let mut hashes_1: Vec<&String> = by_dataset_1.values().flatten().collect();
    hashes_1.sort();
    assert_eq!(
        hashes_1, hashes_2,
        "mapping_hash must be frozen across repeated exports of the same session"
    );
}

/// THE REAL WITNESS: an actual mapping edit performed *between* two
/// exports of the *same* dataset, proving the freeze survives it.
///
/// The previous version of this file only re-exported a session that was
/// never touched between exports — a tautology that could never fail,
/// because nothing ever tried to change anything. The real regression
/// this channel exists to close is `promote_field_config_to_latest_dataset`
/// (`agentic_review.rs`, reachable via `agentic_review_approve`)
/// overwriting `DatasetInfo.field_config` post-ingest. Before the freeze,
/// export derived `provenance.mapping_hash` from that same (now mutated)
/// `field_config`, so approving a renegotiated mapping retroactively
/// relabeled every edge the dataset had already produced under the OLD
/// config — contaminating already-ingested evidence with a hash it was
/// never actually processed under.
///
/// This test ingests under configA, exports and captures the frozen
/// hash, then performs the exact mutation `promote_field_config_to_latest_
/// dataset` performs (`datasets.last_mut().field_config = Some(configB)`)
/// — simulating an `agentic_review_approve` on a negotiated draft without
/// having to drive the full negotiate/draft/approve machinery — and
/// re-exports. The OLD edges must still carry configA's hash.
#[test]
fn mapping_edit_after_ingest_does_not_contaminate_already_exported_provenance() {
    let dir = tempfile::tempdir().expect("tempdir");
    let api = GraphHunterApi::new_noop();
    api.create_session(CreateSessionRequest {
        name: Some("provenance-stability-real-witness".into()),
    })
    .expect("create_session");

    let path = write_csv(&dir, "witness.csv");
    let cfg_a = config_with_host_type("Host");
    let cfg_b = config_with_host_type("Service");

    let result = api
        .load_data_with_config(
            LoadDataWithConfigRequest {
                session: None,
                path,
                config: cfg_a.clone(),
            },
            &graph_hunter_api::paths::PathPolicy::LocalTrusted,
        )
        .expect("load_data_with_config (configA)");
    assert!(
        result.new_relations > 0,
        "ingest under configA must produce edges"
    );

    let export_once = |api: &GraphHunterApi| {
        api.export_ocsf(ExportOcsfRequest {
            session: None,
            dataset_id: None,
            format: "ndjson".into(),
            page_size: None,
            offset: None,
        })
        .expect("export_ocsf")
    };

    // Export #1: capture the hash the OLD edges are stamped with. Must be
    // configA's content hash.
    let out1 = export_once(&api);
    let by_dataset_1 = mapping_hashes_by_dataset(&out1);
    assert_eq!(
        by_dataset_1.len(),
        1,
        "expected exactly 1 dataset before the edit"
    );
    let hashes_1 = by_dataset_1.values().next().expect("dataset's hashes");
    let hash_before = hashes_1.first().expect("at least one edge").clone();
    let expected_a =
        graph_hunter_canonical::ProvenanceCtx::for_configurable(&cfg_a, "x", &[]).mapping_hash;
    assert_eq!(
        hash_before, expected_a,
        "before any edit, the exported hash must be configA's content hash"
    );

    // THE CONTAMINATION, reproduced directly: this is exactly what
    // `promote_field_config_to_latest_dataset` (agentic_review.rs) does to
    // the most-recently-ingested dataset when a negotiated draft is
    // approved via `agentic_review_approve` — it stamps a NEW FieldConfig
    // onto `DatasetInfo.field_config` for UI/replay display. No new data is
    // ingested; the dataset's edges are untouched. Only the *mutable*
    // display copy of the mapping changes.
    let session = api.sessions().current_session().expect("current session");
    {
        let mut datasets = session.datasets.write().expect("datasets lock");
        let target = datasets.last_mut().expect("dataset exists");
        target.field_config = Some(cfg_b.clone());
        // Deliberately NOT touching `mapping_hash` — this is the freeze
        // `promote_field_config_to_latest_dataset` relies on.
    }

    // Export #2: the SAME edges, re-exported after the mapping edit. If
    // export derived `mapping_hash` from `field_config` (the pre-fix
    // bug), this would now show configB's hash — contaminating the old
    // edges' provenance with a mapping they were never processed under.
    let out2 = export_once(&api);
    let by_dataset_2 = mapping_hashes_by_dataset(&out2);
    assert_eq!(
        by_dataset_2.len(),
        1,
        "expected exactly 1 dataset after the edit"
    );
    let hashes_2 = by_dataset_2.values().next().expect("dataset's hashes");
    let hash_after = hashes_2.first().expect("at least one edge").clone();

    let contaminated_b =
        graph_hunter_canonical::ProvenanceCtx::for_configurable(&cfg_b, "x", &[]).mapping_hash;
    assert_eq!(
        hash_after, hash_before,
        "mapping_hash must stay frozen at configA's hash after a post-ingest \
         field_config edit — got {hash_after}, expected the frozen {hash_before} \
         (contaminated with configB's {contaminated_b} would mean the witness is OPEN)"
    );
    assert_ne!(
        hash_after, contaminated_b,
        "the re-exported hash must NOT be configB's hash — that would be exactly \
         the mapping_edit contamination this channel exists to close"
    );
}

#[test]
fn builtin_parser_dataset_gets_real_parser_identity_not_unknown() {
    let dir = tempfile::tempdir().expect("tempdir");
    let api = GraphHunterApi::new_noop();
    api.create_session(CreateSessionRequest {
        name: Some("provenance-stability-builtin".into()),
    })
    .expect("create_session");

    // FortiGate KV log line: a real hand-written-parser format that is
    // NOT in ingestion.rs's `auto_field_config_for` allow-list, so
    // `DatasetInfo.field_config` stays `None` and the dataset must fall
    // back to the builtin-parser identity path.
    let line = r#"date=2026-05-28 time=14:14:20 devname="FW-CORE-01" srcip="10.0.1.31" dstip="10.0.1.32" dstport="443" action="dropped""#;
    let path = dir.path().join("fw.log");
    std::fs::write(&path, line).expect("write fortigate log");

    let result = api
        .load_data(
            LoadDataRequest {
                session: None,
                path: path.to_string_lossy().to_string(),
                format: "fortigate".into(),
            },
            &graph_hunter_api::paths::PathPolicy::LocalTrusted,
        )
        .expect("load_data fortigate");
    assert!(
        result.new_relations > 0,
        "fortigate line must produce edges"
    );

    let out = api
        .export_ocsf(ExportOcsfRequest {
            session: None,
            dataset_id: None,
            format: "ndjson".into(),
            page_size: None,
            offset: None,
        })
        .expect("export_ocsf");

    let by_dataset = mapping_hashes_by_dataset(&out);
    assert_eq!(by_dataset.len(), 1, "expected exactly 1 dataset");
    let hashes = by_dataset.values().next().expect("one dataset's hashes");
    for h in hashes {
        assert_eq!(
            h, "builtin:fortigate",
            "builtin (no-FieldConfig) dataset must carry the real resolved \
             parser identity, not a generic/unknown placeholder"
        );
    }
}
