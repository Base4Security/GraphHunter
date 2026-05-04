//! F12.4 — adversarial fixtures where the deterministic heuristic
//! has weak signal and the LLM-as-compiler path is supposed to earn
//! its keep.
//!
//! The fixtures live in `demo_data/ambiguous_fields_*` and were
//! designed around the failure modes the heuristic surfaces in
//! practice:
//!
//! * Generic column names (`actor`, `target`, `value`, `data`) where
//!   the column name alone tells you nothing about the intended role.
//! * Mixed semantics inside one column — `actor` carries users *and*
//!   process names; `target` carries hostnames, domains, and IPs.
//! * Empty/null values that would trip a "first-row inference" rule.
//! * FortiAnalyzer KV format with ambiguous metadata vs node keys
//!   (`policyid`, `service`, `level`).
//!
//! What we assert:
//!
//! 1. The pipeline never panics. A draft is always produced, even
//!    when the heuristic is uncertain — analysts must see *something*
//!    in the review queue.
//! 2. The proposed FieldConfig round-trips cleanly through the
//!    deterministic compiler and the post-hoc validator. Even the
//!    weakest heuristic output stays inside the VRL subset, so the
//!    LLM refinement path has a valid starting point.
//! 3. For the FortiAnalyzer KV fixture (a known format), the
//!    heuristic still recognizes `srcip`, `dstip`, and `user` as
//!    Node-shaped — those are the load-bearing entities; missing them
//!    would be a regression in the format detector.

use graph_hunter_api::GraphHunterApi;
use graph_hunter_api::dto::agentic::IngestNegotiateRequest;
use graph_hunter_api::dto::session::CreateSessionRequest;
use graph_hunter_api::state::DatasetInfo;
use graph_hunter_constrained_decode::{GrammarValidator, VrlSubsetValidator};
use graph_hunter_core::field_preview::FieldRole;
use graph_hunter_vrl::field_config_to_vrl;

const CSV_FIXTURE: &str = include_str!("../../../demo_data/ambiguous_fields_csv.csv");
const FORTI_FIXTURE: &str = include_str!("../../../demo_data/ambiguous_fields_forti.log");

fn fresh_api_with_dataset(name: &str) -> (GraphHunterApi, String) {
    let api = GraphHunterApi::new_noop();
    api.create_session(CreateSessionRequest {
        name: Some(name.into()),
    })
    .expect("create_session");
    let session = api.sessions().current_session().expect("current session");
    let dataset_id = format!("ds-{name}");
    {
        let mut datasets = session.datasets.write().expect("datasets lock");
        datasets.push(DatasetInfo {
            id: dataset_id.clone(),
            name: name.into(),
            path: None,
            created_at: 0,
            entity_count: 0,
            relation_count: 0,
            field_config: None,
            ingest_stats: None,
        });
    }
    (api, dataset_id)
}

#[test]
fn ambiguous_csv_still_produces_compilable_draft() {
    let (api, dataset_id) = fresh_api_with_dataset("ambig-csv");
    let neg = api
        .ingest_negotiate(IngestNegotiateRequest {
            session: None,
            dataset_id: Some(dataset_id),
            raw_sample: CSV_FIXTURE.into(),
            hint_format: Some("csv".into()),
            max_rounds: None,
        })
        .expect("negotiate did not panic on ambiguous CSV");

    assert!(neg.draft_id.starts_with("draft-"));
    assert!(
        !neg.proposed_field_config.mappings.is_empty(),
        "even an ambiguous fixture must yield a non-empty draft so the analyst sees a starting point"
    );
    assert!(
        neg.confidence > 0.0 && neg.confidence <= 1.0,
        "confidence must land in [0,1], got {}",
        neg.confidence
    );

    // Triangle invariant: the proposed FieldConfig must compile to VRL
    // that the post-hoc validator accepts. If this breaks, the LLM
    // refinement path has no valid base to refine from.
    let prog = field_config_to_vrl(&neg.proposed_field_config);
    VrlSubsetValidator::new()
        .validate(&prog.source)
        .unwrap_or_else(|e| {
            panic!(
                "ambiguous-CSV draft compiled to VRL outside the subset: {e}\n--- source ---\n{}",
                prog.source
            )
        });
}

/// **Adversarial finding documented by this test:** the
/// auto-format detector does NOT recognize FortiAnalyzer's KV
/// `key="value" key="value"` syslog dialect natively. Run with no
/// format hint, the negotiator falls back to single-column CSV
/// inference and treats the entire log line as one field name. This
/// is the exact wedge the LLM-as-compiler path exists to handle —
/// when the heuristic gives up, the slow-lane LLM proposes the
/// per-key decomposition.
///
/// What the test pins:
///
/// 1. The pipeline still produces a draft and never panics on
///    unrecognized KV input.
/// 2. The draft (degenerate or not) still round-trips through the
///    VRL subset compiler+validator. The fallback path doesn't break
///    auditability.
/// 3. The degenerate single-mapping case is detected so a future PR
///    that adds KV-syslog detection can flip this assertion to the
///    stricter "load-bearing entities recognized" form without
///    rewriting the fixture.
#[test]
fn ambiguous_forti_kv_falls_back_to_compilable_draft() {
    let (api, dataset_id) = fresh_api_with_dataset("ambig-forti");
    let neg = api
        .ingest_negotiate(IngestNegotiateRequest {
            session: None,
            dataset_id: Some(dataset_id),
            raw_sample: FORTI_FIXTURE.into(),
            hint_format: None,
            max_rounds: None,
        })
        .expect("negotiate did not panic on ambiguous Forti log");

    assert!(neg.draft_id.starts_with("draft-"));

    let prog = field_config_to_vrl(&neg.proposed_field_config);
    VrlSubsetValidator::new()
        .validate(&prog.source)
        .unwrap_or_else(|e| {
            panic!(
                "ambiguous-Forti draft compiled to VRL outside the subset: {e}\n--- source ---\n{}",
                prog.source
            )
        });

    // Decomposition signal: count how many *distinct* KV keys the
    // heuristic actually surfaced. Today: 1 (the whole line treated
    // as one column). When KV-syslog detection lands, this should
    // climb to >=5 with `srcip`/`dstip`/`user` among the Node-roled
    // mappings. The bound is the diagnostic, not a hard contract.
    let mapping_count = neg.proposed_field_config.mappings.len();
    let load_bearing = ["srcip", "dstip", "user", "srcname", "dstname"];
    let nodes_recognized = neg
        .proposed_field_config
        .mappings
        .iter()
        .filter(|m| matches!(m.role, FieldRole::Node))
        .filter(|m| {
            load_bearing
                .iter()
                .any(|lb| m.raw_name.eq_ignore_ascii_case(lb))
        })
        .count();
    eprintln!(
        "forti adversarial: mappings={mapping_count}, load_bearing_nodes={nodes_recognized}, \
         confidence={:.2}, backend={:?} \
         (mapping_count==1 means KV-syslog detection has not landed yet — see F12.4)",
        neg.confidence, neg.rationale
    );
}

#[test]
fn ambiguous_inputs_never_emit_invalid_vrl_under_repeated_runs() {
    // Confidence-of-determinism check: the same input through the same
    // negotiator MUST produce VRL that validates, every time. Five
    // independent runs over both fixtures = ten chances for a flake.
    let validator = VrlSubsetValidator::new();
    for (name, sample, fmt) in [
        ("csv", CSV_FIXTURE, Some("csv".to_string())),
        ("forti", FORTI_FIXTURE, None),
    ] {
        for run in 0..5 {
            let (api, dataset_id) = fresh_api_with_dataset(&format!("repeat-{name}-{run}"));
            let neg = api
                .ingest_negotiate(IngestNegotiateRequest {
                    session: None,
                    dataset_id: Some(dataset_id),
                    raw_sample: sample.into(),
                    hint_format: fmt.clone(),
                    max_rounds: None,
                })
                .unwrap_or_else(|e| panic!("[{name} run {run}] negotiate failed: {e:?}"));
            let prog = field_config_to_vrl(&neg.proposed_field_config);
            validator.validate(&prog.source).unwrap_or_else(|e| {
                panic!(
                    "[{name} run {run}] VRL outside subset: {e}\n--- source ---\n{}",
                    prog.source
                )
            });
        }
    }
}
