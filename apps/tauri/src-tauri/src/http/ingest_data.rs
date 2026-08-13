//! File-ingest endpoints: preview a log file and load it into the graph.
//!
//! These wrap `GraphHunterApi`'s ingest operations, which until now were
//! reachable only as Tauri commands — a non-desktop client could not
//! ingest anything. They add no business logic.
//!
//! Every handler resolves a [`PathPolicy`] from the environment first.
//! That policy is `Rooted`, i.e. deny-by-default: with
//! `GRAPHHUNTER_INGEST_ROOT` unset these routes return 403 and read
//! nothing, so deploying this build changes no existing exposure until an
//! operator opts in. See `graph_hunter_api::paths`.
//!
//! HTTP 200 is not the same as a useful ingest: check `zero_triples`
//! (the parser saw rows but produced no triples — usually a bad mapping)
//! and `stopped_early` (truncated by the memory guard) on `LoadResult`.

use axum::{extract::State, response::Response, Json};
use std::sync::Arc;
use std::time::Duration;

use graph_hunter_api::paths::PathPolicy;
use graph_hunter_api::GraphHunterApi;

use super::helpers::{api_err_response, ok_json};

/// Whole-file ingest reads and parses synchronously; 300s matches the
/// ceiling the desktop path tolerates for a large EVTX.
const LOAD_TIMEOUT: Duration = Duration::from_secs(300);
/// Preview only samples the head of the file.
const PREVIEW_TIMEOUT: Duration = Duration::from_secs(60);

/// Runs a blocking ingest op under a timeout, mapping the three failure
/// modes (op error, join panic, timeout) onto responses.
///
/// A timeout here abandons the *response*, not the work: `spawn_blocking`
/// cannot be cancelled, so an ingest that outruns the deadline still
/// lands in the graph. Callers with large files should use the streaming
/// route instead of retrying.
async fn blocking_op<T, F>(timeout: Duration, f: F) -> Response
where
    T: serde::Serialize + Send + 'static,
    F: FnOnce() -> graph_hunter_api::ApiResult<T> + Send + 'static,
{
    match tokio::time::timeout(timeout, tokio::task::spawn_blocking(f)).await {
        Ok(Ok(Ok(v))) => ok_json(v),
        Ok(Ok(Err(e))) => api_err_response(e),
        Ok(Err(join)) => api_err_response(graph_hunter_api::ApiError::Internal(format!(
            "ingest task failed: {join}"
        ))),
        Err(_) => api_err_response(graph_hunter_api::ApiError::Internal(format!(
            "ingest exceeded {}s; the work may still be running — poll /datasets \
             before retrying, and prefer POST /ingest/stream for large files",
            timeout.as_secs()
        ))),
    }
}

fn policy_or_err() -> Result<PathPolicy, Response> {
    PathPolicy::from_env().map_err(api_err_response)
}

pub(super) async fn handler_preview_ingest(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<graph_hunter_api::dto::ingestion::PreviewIngestRequest>,
) -> Response {
    let policy = match policy_or_err() {
        Ok(p) => p,
        Err(r) => return r,
    };
    blocking_op(PREVIEW_TIMEOUT, move || api.preview_ingest(body, &policy)).await
}

pub(super) async fn handler_load_data(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<graph_hunter_api::dto::ingestion::LoadDataRequest>,
) -> Response {
    let policy = match policy_or_err() {
        Ok(p) => p,
        Err(r) => return r,
    };
    blocking_op(LOAD_TIMEOUT, move || api.load_data(body, &policy)).await
}

pub(super) async fn handler_load_data_with_config(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<graph_hunter_api::dto::ingestion::LoadDataWithConfigRequest>,
) -> Response {
    let policy = match policy_or_err() {
        Ok(p) => p,
        Err(r) => return r,
    };
    blocking_op(LOAD_TIMEOUT, move || {
        api.load_data_with_config(body, &policy)
    })
    .await
}

#[cfg(test)]
mod tests {
    use crate::http::hunt::tests_support::seeded_hunt_fixture;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use tower::ServiceExt;

    fn body_for(path: &str) -> Body {
        Body::from(format!(r#"{{"path":"{path}","format":"auto"}}"#))
    }

    async fn post_ingest(auth: Option<&str>) -> StatusCode {
        let (app_state, api, _sid, _dsl) = seeded_hunt_fixture();
        let app = crate::http::build_app(app_state, Arc::new(api));
        let mut req = Request::builder()
            .method("POST")
            .uri("/ingest/load")
            .header("content-type", "application/json");
        if let Some(token) = auth {
            req = req.header("authorization", format!("Bearer {token}"));
        }
        let resp = app
            .oneshot(req.body(body_for("C:/anywhere/x.csv")).expect("request"))
            .await
            .expect("router response");
        resp.status()
    }

    /// The ingest routes are not in `auth_middleware`'s skip list.
    #[tokio::test]
    async fn ingest_load_requires_auth() {
        assert_eq!(post_ingest(None).await, StatusCode::UNAUTHORIZED);
    }

    /// Deny-by-default: authenticated but with no `GRAPHHUNTER_INGEST_ROOT`
    /// configured, the route must refuse with 403 and read nothing. This
    /// is what makes shipping the route safe — it proves the policy is
    /// actually wired into the handler, not merely available.
    ///
    /// Depends on the env var being absent, which is the default; it is
    /// never set by this suite.
    #[tokio::test]
    async fn ingest_load_denies_when_no_root_configured() {
        if std::env::var("GRAPHHUNTER_INGEST_ROOT").is_ok() {
            eprintln!("skipped: GRAPHHUNTER_INGEST_ROOT is set in this environment");
            return;
        }
        assert_eq!(post_ingest(Some("test-token")).await, StatusCode::FORBIDDEN);
    }
}
