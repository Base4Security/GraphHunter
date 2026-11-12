//! Attack-chain reconstruction endpoints (TPCSA).
//!
//! `POST /tpcsa/export` → the loaded graph as a solver instance.
//! `POST /reconstruct_chain` → ranked, verified trees; with `certify: true`
//! the handler also asks the certification sidecar (HiGHS, out of process)
//! for an optimality certificate and attaches it verbatim. The sidecar's
//! absence is reported as `status: "Unavailable"`, never as a failure of
//! the reconstruction itself.

use std::sync::Arc;
use std::time::Duration;

use axum::{Json, extract::State, response::Response};

use graph_hunter_api::GraphHunterApi;
use graph_hunter_api::dto::tpcsa::{
    Certificate, ExportTpcsaInstanceRequest, ReconstructChainRequest, ReconstructChainResponse,
};

use super::helpers::{api_err_response, api_response, ok_json};

/// Where the certification sidecar listens. Override with
/// `TPCSA_CERTIFY_URL` (full URL of the `/certify` endpoint).
pub(crate) const DEFAULT_CERTIFY_URL: &str = "http://127.0.0.1:37892/certify";
const DEFAULT_TIME_LIMIT_S: f64 = 120.0;
const DEFAULT_GAP: f64 = 0.005;

pub(super) async fn handler_export_instance(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<ExportTpcsaInstanceRequest>,
) -> Response {
    api_response(api.export_tpcsa_instance(body))
}

pub(super) async fn handler_reconstruct_chain(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<ReconstructChainRequest>,
) -> Response {
    let certify = body.certify.unwrap_or(false);
    let k = body
        .k
        .unwrap_or(graph_hunter_api::operations::tpcsa::DEFAULT_K);
    let time_limit = body.certify_time_limit_s.unwrap_or(DEFAULT_TIME_LIMIT_S);
    let gap = body.certify_gap.unwrap_or(DEFAULT_GAP);
    let mut resp: ReconstructChainResponse = match api.reconstruct_chain(body) {
        Ok(r) => r,
        Err(e) => return api_err_response(e),
    };
    if certify {
        let pruned = resp.pruned_instance.take();
        resp.certificate = Some(match pruned {
            Some(inst) => certify_with_sidecar(&inst, &resp, k, time_limit, gap).await,
            None => Certificate {
                status: "Error".into(),
                message: Some("no pruned instance to certify".into()),
                ..empty_certificate()
            },
        });
    }
    ok_json(resp)
}

fn empty_certificate() -> Certificate {
    Certificate {
        status: String::new(),
        objective: None,
        dual_bound: None,
        gap: None,
        solve_seconds: None,
        message: None,
        greedy_objective: None,
    }
}

/// Posts the pruned instance plus the greedy forest (as a warm start) to
/// the sidecar and returns whatever it says, tagged with the greedy
/// objective for comparison.
async fn certify_with_sidecar(
    inst: &graph_hunter_api::dto::tpcsa::Instance,
    resp: &ReconstructChainResponse,
    k: usize,
    time_limit: f64,
    gap: f64,
) -> Certificate {
    let url =
        std::env::var("TPCSA_CERTIFY_URL").unwrap_or_else(|_| DEFAULT_CERTIFY_URL.to_string());
    let warm_start = serde_json::json!({
        "roots": resp.trees.iter().map(|t| t.root.node.clone()).collect::<Vec<_>>(),
        "arcs": resp
            .trees
            .iter()
            .flat_map(|t| t.arcs.iter())
            .map(|a| serde_json::json!({"tail": a.tail, "head": a.head, "etype": a.etype, "t": a.t}))
            .collect::<Vec<_>>(),
    });
    let payload = serde_json::json!({
        "instance": inst,
        "k": k,
        "time_limit": time_limit,
        "gap": gap,
        "warm_start": warm_start,
    });
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs_f64(time_limit + 30.0))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return Certificate {
                status: "Error".into(),
                message: Some(format!("http client: {e}")),
                greedy_objective: Some(resp.objective),
                ..empty_certificate()
            };
        }
    };
    let mut cert = match client.post(&url).json(&payload).send().await {
        Ok(r) => match r.json::<Certificate>().await {
            Ok(c) => c,
            Err(e) => Certificate {
                status: "Error".into(),
                message: Some(format!("sidecar returned a non-certificate body: {e}")),
                ..empty_certificate()
            },
        },
        Err(e) => Certificate {
            status: "Unavailable".into(),
            message: Some(format!(
                "certification sidecar unreachable at {url}: {e}. Start it with `python sidecar/tpcsa-certify/server.py`."
            )),
            ..empty_certificate()
        },
    };
    cert.greedy_objective = Some(resp.objective);
    cert
}
