//! Minimal HTTP API for MCP / external tools. Bind to localhost; requires a loaded session.
//!
//! The module is split into per-domain files (graph, hunt, notes, etc.);
//! this root owns `HttpState`, the auth middleware, and router assembly.

use axum::{
    body::{to_bytes, Body, Bytes, HttpBody},
    extract::{FromRef, Request, State},
    http::{header::CONTENT_LENGTH, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;
use std::time::Instant;
use subtle::ConstantTimeEq;
use tower_http::cors::{CorsLayer, Any};

use crate::journal::event::GraphCounts;
use crate::AppState;
use graph_hunter_api::GraphHunterApi;

mod agentic;
mod anomaly;
mod catalog;
mod dlq;
mod export;
mod graph;
mod graph_meta;
mod helpers;
mod hunt;
mod ingest;
mod invariants;
mod journal;
mod misc;
mod notes;
mod siem;
mod tags;

/// Combined axum state. Handlers extract `Arc<AppState>` or
/// `Arc<GraphHunterApi>` (or both) via `FromRef` — no handler signature
/// changes beyond replacing one for the other.
#[derive(Clone)]
pub struct HttpState {
    pub app: Arc<AppState>,
    pub api: Arc<GraphHunterApi>,
}

impl FromRef<HttpState> for Arc<AppState> {
    fn from_ref(s: &HttpState) -> Self {
        s.app.clone()
    }
}

impl FromRef<HttpState> for Arc<GraphHunterApi> {
    fn from_ref(s: &HttpState) -> Self {
        s.api.clone()
    }
}

/// Log each request to stderr so app logs show whether /health (etc.) is hit.
async fn log_requests(request: axum::extract::Request, next: Next) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let response = next.run(request).await;
    tracing::debug!("HTTP API {} {} -> {}", method, uri, response.status());
    response
}

/// Bearer token auth middleware. Skips `/` and `/health` routes.
async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    // Skip auth for root, health, and Prometheus metrics endpoints.
    // /metrics is exempt because Prometheus scrapers typically don't send bearer tokens,
    // and the server binds to localhost by default.
    if path == "/" || path == "/health" || path == "/metrics" || path == "/v1/schema" {
        return next.run(request).await;
    }

    let expected = &state.api_token;
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(val) if val.starts_with("Bearer ") && {
            let token = val[7..].as_bytes();
            let expect = expected.as_bytes();
            token.len() == expect.len() && token.ct_eq(expect).into()
        } => {
            next.run(request).await
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Unauthorized. Provide Authorization: Bearer <token> header." })),
        )
            .into_response(),
    }
}

/// Paths the mandatory journal capture skips: free-standing/liveness
/// endpoints and the journal's own read API (capturing reads of the
/// journal would just spam the journal with itself).
fn journal_capture_skips(path: &str) -> bool {
    path == "/" || path == "/health" || path == "/metrics" || path.starts_with("/journal")
}

/// Cap on how many bytes `capture` will buffer from a *request* body via
/// `to_bytes`. Matches the `DefaultBodyLimit` cap applied lower in the
/// stack (see `build_app`) — `to_bytes` requires its own explicit limit
/// regardless of that layer. When a request exceeds this, `capture`
/// rejects it with `413 Payload Too Large` up front instead of forwarding
/// a truncated body to the handler (see `capture`).
const CAPTURE_BODY_LIMIT: usize = 10 * 1024 * 1024;

/// Cap on how many bytes `capture` will buffer from a *response* body when
/// it does decide to buffer one (see `capture`). Comfortably above any
/// real graph/OCSF export produced by this app. Responses whose declared
/// size (`Content-Length`, or the body's own size hint) already exceeds
/// this limit are never buffered at all — they are forwarded to the
/// client completely untouched, since truncating an already-produced
/// response to empty would be silent data loss.
const RESP_CAPTURE_LIMIT: usize = 64 * 1024 * 1024;

/// Above this size, skip JSON-parsing the response body for the
/// interpreter (`extract_touched`/`row_count`/etc). The raw bytes are
/// still forwarded to the client untouched; only the journal's view of
/// a huge response degrades to `Value::Null`, per the task brief.
const CAPTURE_PARSE_LIMIT: usize = 2 * 1024 * 1024;

/// Cheap current-session graph fingerprint (entity/relation counts).
/// Returns zeros if no session is loaded or the graph lock is poisoned —
/// the journal's mandatory core (path, kind, redacted params, status,
/// est_tokens) does not depend on this being accurate.
fn graph_counts(api: &GraphHunterApi) -> GraphCounts {
    api.sessions()
        .current_session()
        .and_then(|s| {
            s.graph.read().ok().map(|g| GraphCounts {
                entities: g.entity_count() as u64,
                relations: g.relation_count() as u64,
            })
        })
        .unwrap_or_default()
}

/// Mandatory hunt-journal capture middleware (Task A4). Buffers the
/// request body (rebuilding the request so the real handler still sees
/// it), reads graph counts before/after, runs the handler, buffers the
/// response body when it's safe to do so (rebuilding the response so the
/// client still sees it), and appends a redacted `HuntEvent` to the
/// current hunt.
///
/// Buffered bodies must reach their downstream consumer (handler or
/// client) *unchanged*. `to_bytes` returns `Err` when a body exceeds the
/// limit passed to it — silently substituting an empty `Bytes` in that
/// case (via `unwrap_or_default`) would forward a corrupted, zero-byte
/// body to whichever side is downstream. `capture` never does that:
/// an over-limit *request* is rejected with `413` before the handler
/// runs, and an over-limit *response* is forwarded completely untouched
/// (buffering is skipped up front, before the body is ever consumed).
///
/// Registered *inside* `auth_middleware` (see `build_app`) so it only
/// runs for authenticated, resolved requests — unauthorized probes never
/// get journaled.
async fn capture(
    State(app): State<Arc<AppState>>,
    State(api): State<Arc<GraphHunterApi>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    if journal_capture_skips(&path) {
        return next.run(request).await;
    }
    let method = request.method().to_string();

    // Buffer the request body; best-effort JSON (non-JSON/undecodable ->
    // Null). Rebuild the request from the buffered bytes so the real
    // handler downstream still gets a fully-formed body.
    //
    // If the body exceeds CAPTURE_BODY_LIMIT, `to_bytes` returns `Err`.
    // Reject with 413 here instead of substituting an empty body: an
    // empty body would reach the handler as a confusing, silently-wrong
    // request instead of the clean 413 a >limit request used to get from
    // `DefaultBodyLimit` before `capture` sat in front of it.
    let (parts, body) = request.into_parts();
    let req_bytes = match to_bytes(body, CAPTURE_BODY_LIMIT).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(serde_json::json!({
                    "error": format!(
                        "Request body exceeds the {}-byte limit.",
                        CAPTURE_BODY_LIMIT
                    )
                })),
            )
                .into_response();
        }
    };
    let req_json: serde_json::Value =
        serde_json::from_slice(&req_bytes).unwrap_or(serde_json::Value::Null);
    let request = Request::from_parts(parts, Body::from(req_bytes));

    let before = graph_counts(&api);
    let started = Instant::now();
    let response = next.run(request).await;
    let dur_ms = started.elapsed().as_millis() as u64;
    let after = graph_counts(&api);
    let status = response.status().as_u16();

    // Decide whether the response is safe to buffer *before* touching its
    // body. The handler already produced a valid response; `capture` must
    // never corrupt it. Prefer the declared `Content-Length`, falling
    // back to the body's own size hint (exact for the `Bytes`-backed
    // bodies this app's `Json(...)` handlers produce).
    let declared_len = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    let hinted_len = HttpBody::size_hint(response.body()).upper();
    let known_len = declared_len.or(hinted_len);

    if known_len.is_some_and(|n| n as usize > RESP_CAPTURE_LIMIT) {
        // Oversized: skip buffering entirely and forward the original
        // response untouched — this is the fix for the data-loss bug.
        // The journal still gets an event; row_count/touched are skipped
        // (Null resp_json) since the body was never inspected.
        let resp_json = serde_json::Value::Null;
        // detail_ref is resolved here, post-handler (after `next.run` above),
        // so the window between naming a hunt and `append()` landing the
        // event in it is only two fast lock ops with no await in between —
        // a concurrent /journal/close can no longer race a slow handler and
        // make this event land in the wrong hunt. current_hunt_id() is
        // idempotent/lazy: it just returns the already-open hunt or lazily
        // opens one, same as append() below would. Used as the summary's
        // detail_ref so an LLM reading a compact summary knows which hunt
        // to pull the full detail from via the journal API.
        let detail_ref = app.journal.current_hunt_id();
        let mut event = crate::journal::capture::build_event(
            &path, &method, status, dur_ms, &req_json, &resp_json, before, after, &detail_ref,
        );
        event.result.body_bytes = known_len.unwrap_or(0);
        // IMPORTANT fix: build_event derived est_tokens from resp_json
        // (Null here, since the body was never inspected) which collapses
        // to ~1 token regardless of true size — silently under-counting the
        // largest responses in cumulative_est_tokens. Recompute it from the
        // real wire size now that body_bytes has been corrected above.
        event.result.est_tokens = event.result.body_bytes / 4;
        let event_body_bytes = event.result.body_bytes;
        app.journal.append(event);

        tracing::debug!(
            "journal: captured {} {} -> {} ({} ms, oversized response {} bytes, buffering skipped)",
            method, path, status, dur_ms, event_body_bytes
        );
        return response;
    }

    // Normal-sized (or unknown-length, under the buffering cap) response:
    // buffer and rebuild as before. Cap JSON parsing separately from the
    // buffering limit: a large-but-under-cap response still gets
    // forwarded to the client byte-for-byte, it just isn't interpreted
    // for row_count/touched in the journal.
    let (resp_parts, resp_body) = response.into_parts();
    let resp_bytes = match to_bytes(resp_body, RESP_CAPTURE_LIMIT).await {
        Ok(bytes) => bytes,
        Err(e) => {
            // The size pre-check above should route anything over
            // RESP_CAPTURE_LIMIT away from this branch for every handler
            // in this app (all `Json(...)`, which always sets
            // Content-Length). Getting here means a body streamed past
            // the cap without a usable size hint — not a real case
            // today, and unrecoverable once `to_bytes` has already
            // consumed the stream: there's no original response left to
            // forward. Log loudly and fall back to an empty body as the
            // last resort.
            tracing::warn!(
                "journal: response body for {} {} exceeded {} bytes with no usable \
                 Content-Length/size hint; forwarding EMPTY body to client — \
                 this is unrecoverable data loss for this one response: {}",
                method, path, RESP_CAPTURE_LIMIT, e
            );
            Bytes::new()
        }
    };
    let resp_json: serde_json::Value = if resp_bytes.len() <= CAPTURE_PARSE_LIMIT {
        serde_json::from_slice(&resp_bytes).unwrap_or(serde_json::Value::Null)
    } else {
        serde_json::Value::Null
    };

    // detail_ref is resolved here, post-handler (after `next.run` above), so
    // the window between naming a hunt and `append()` landing the event in
    // it is only two fast lock ops with no await in between — a concurrent
    // /journal/close can no longer race a slow handler and make this event
    // land in the wrong hunt. See the oversized branch above for the full
    // rationale.
    let detail_ref = app.journal.current_hunt_id();
    let mut event = crate::journal::capture::build_event(
        &path, &method, status, dur_ms, &req_json, &resp_json, before, after, &detail_ref,
    );
    // build_event derives body_bytes/est_tokens from resp_json, which is
    // Null for oversized bodies; correct body_bytes to the real wire size
    // regardless (est_tokens stays a best-effort estimate in that case).
    event.result.body_bytes = resp_bytes.len() as u64;
    // I-1 fix: when the body exceeded CAPTURE_PARSE_LIMIT above, resp_json
    // was left Null and build_event computed est_tokens from
    // `len("null")/4 ≈ 1` — silently under-reporting exactly the large raw
    // responses (e.g. a multi-MB raw /kql dump) in
    // journal_stats.cumulative_est_tokens, which can invert the "tool <
    // raw" token guarantee the journal exists to prove. Recompute from the
    // corrected body_bytes, symmetric to the oversized-response branch
    // above. Small responses (resp_json parsed normally) are untouched:
    // their est_tokens already came from `summarize`/body_bytes via
    // build_event.
    if resp_bytes.len() > CAPTURE_PARSE_LIMIT {
        event.result.est_tokens = event.result.body_bytes / 4;
    }
    app.journal.append(event);

    tracing::debug!("journal: captured {} {} -> {} ({} ms)", method, path, status, dur_ms);
    Response::from_parts(resp_parts, Body::from(resp_bytes))
}

/// Build the API router (shared by run and run_async).
/// POST routes are also registered with trailing slash so /notes/ and /notes both work.
fn build_app(app_state: Arc<AppState>, api: Arc<GraphHunterApi>) -> Router {
    let state = HttpState { app: app_state, api };
    Router::new()
        .route("/", get(misc::handler_api_root))
        .route("/health", get(misc::handler_health))
        .route("/v1/schema", get(misc::handler_schema))
        .route("/entity_types", get(graph::handler_entity_types))
        .route("/relation_schema", get(graph::handler_relation_schema))
        .route("/explain_score", get(hunt::handler_explain_score))
        .route("/search", get(graph::handler_search))
        .route("/expand", get(graph::handler_expand))
        .route("/node_details", get(graph::handler_node_details))
        .route("/subgraph", post(graph::handler_subgraph))
        .route("/subgraph/", post(graph::handler_subgraph))
        .route("/events_for_node", get(graph::handler_events_for_node))
        .route("/run_hunt", post(hunt::handler_run_hunt))
        .route("/run_hunt/", post(hunt::handler_run_hunt))
        .route("/hunt_results", get(hunt::handler_hunt_results))
        .route("/diff_hunts", post(hunt::handler_diff_hunts))
        .route("/notes", post(notes::handler_create_note))
        .route("/notes/", post(notes::handler_create_note))
        .route("/notes/list", get(notes::handler_list_notes))
        .route("/notes/:id", get(notes::handler_get_note_by_id))
        .route("/graph_summary", get(graph::handler_graph_summary))
        .route("/graph/summary", get(graph_meta::handler_graph_summary))
        .route("/graph/overlap", post(graph_meta::handler_graph_overlap))
        .route("/entity_type_counts", get(graph::handler_entity_type_counts))
        .route("/temporal_heatmap", get(anomaly::handler_temporal_heatmap))
        .route("/subnet_analysis", get(anomaly::handler_subnet_analysis))
        .route("/enrich_ip", post(anomaly::handler_enrich_ip))
        .route("/catalog", get(catalog::handler_catalog))
        .route("/catalog/status", get(catalog::handler_catalog_with_status))
        .route("/catalog/diagnostics", get(catalog::handler_catalog_diagnostics))
        .route("/tag", post(tags::handler_tag_entity))
        .route("/untag", post(tags::handler_untag_entity))
        .route("/tags", get(tags::handler_list_tagged))
        .route("/export_iocs", post(export::handler_export_iocs))
        .route("/publish_iocs_to_sentinel", post(export::handler_publish_iocs_to_sentinel))
        .route("/save_hypothesis_as_sigma", post(export::handler_save_hypothesis_as_sigma))
        .route("/file_ticket", post(export::handler_file_ticket))
        .route("/datasets", get(misc::handler_list_datasets))
        .route("/path_nodes", get(graph::handler_path_nodes))
        .route("/export_subgraph", post(export::handler_export_subgraph))
        .route("/export_ocsf", post(export::handler_export_ocsf))
        .route("/check_invariants", post(invariants::handler_check_invariants))
        .route("/ingest_negotiate", post(ingest::handler_ingest_negotiate))
        .route("/pcap_preview", post(ingest::handler_pcap_preview))
        .route("/canonical_map", post(ingest::handler_canonical_map))
        .route("/parser_generate", post(ingest::handler_parser_generate))
        .route("/schema_drift_detect", post(ingest::handler_schema_drift_detect))
        .route("/mapping_regression_test", post(ingest::handler_mapping_regression_test))
        .route("/invariant_check_hypothetical", post(invariants::handler_invariant_check_hypothetical))
        .route("/agentic_review_list", post(agentic::handler_agentic_review_list))
        .route("/agentic_review_approve", post(agentic::handler_agentic_review_approve))
        .route("/agentic_review_reject", post(agentic::handler_agentic_review_reject))
        .route("/list_dead_letters", post(dlq::handler_list_dead_letters))
        .route("/reingest_dead_letter", post(dlq::handler_reingest_dead_letter))
        .route("/purge_dead_letters", post(dlq::handler_purge_dead_letters))
        .route("/publish_mapping", post(ingest::handler_publish_mapping))
        .route("/fetch_shared_mappings", post(ingest::handler_fetch_shared_mappings))
        .route("/parse_dsl", post(hunt::handler_parse_dsl))
        .route("/events_paginated", get(graph::handler_events_paginated))
        .route("/expand_grouped", get(graph::handler_expand_grouped))
        .route("/heavy_edges", get(graph::handler_heavy_edges))
        .route("/channel_behavior", get(graph::handler_channel_behavior))
        .route("/export_hunt_results", post(export::handler_export_hunt_results))
        .route("/enable_anomaly_scoring", post(anomaly::handler_enable_anomaly_scoring))
        .route("/compute_scores", post(anomaly::handler_compute_scores))
        .route("/kql", post(siem::handler_run_kql))
        .route("/kql/", post(siem::handler_run_kql))
        .route("/node/enrich", post(siem::handler_node_enrich))
        .route("/sentinel/seed", post(siem::handler_seed_from_ioc))
        .route("/sentinel/schema", post(siem::handler_discover_schema))
        .route("/graph/propose", post(siem::handler_graph_propose))
        .route("/graph/build", post(siem::handler_graph_build))
        .route("/graph/neighbors", post(graph::handler_graph_neighbors))
        .route("/graph/path", post(graph::handler_graph_path))
        .route("/graph/anomaly", post(graph::handler_graph_anomaly))
        .route("/sentinel/resume", post(siem::handler_sentinel_resume))
        .route("/sentinel/pause", post(siem::handler_sentinel_pause))
        .route("/sentinel_status", get(siem::handler_sentinel_status))
        .route("/metrics", get(misc::handler_metrics))
        .route("/journal/start", post(journal::handler_start))
        .route("/journal/close", post(journal::handler_close))
        .route("/journal/list", get(journal::handler_list))
        .route("/journal/export", post(journal::handler_export))
        .route("/journal/:id", get(journal::handler_get))
        .route("/journal/:id/stats", get(journal::handler_stats))
        .route("/journal/:id/expand", post(journal::handler_expand))
        .fallback(misc::fallback_404)
        // 10 MB cap on request bodies. Hunt payloads are small (a DSL string
        // plus maybe a note); anything larger is almost certainly malformed
        // or hostile. Without this, a POST with a 1 GB JSON body would OOM
        // the whole process before a handler ever runs.
        .layer(axum::extract::DefaultBodyLimit::max(10 * 1024 * 1024))
        .layer(CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any))
        // `capture` is added *before* `auth_middleware` here, which makes
        // it the layer auth's `next.run()` calls into — i.e. capture only
        // sees requests that already passed authentication. Needs the
        // full `HttpState` (not just `Arc<AppState>`) so it can also pull
        // `Arc<GraphHunterApi>` for the graph-count fingerprint.
        .layer(axum::middleware::from_fn_with_state(state.clone(), capture))
        .layer(axum::middleware::from_fn_with_state(state.app.clone(), auth_middleware))
        .layer(axum::middleware::from_fn(log_requests))
        .with_state(state)
}

/// Run the HTTP API on Tauri's async runtime. Use this from lib.rs via
/// `tauri::async_runtime::spawn(async move { http::run_async(state, api, port).await })`
/// so the server shares Tauri's executor and avoids cross-runtime lock contention.
pub async fn run_async(state: Arc<AppState>, api: Arc<GraphHunterApi>, port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let host = std::env::var("GRAPHHUNTER_API_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let addr = format!("{}:{}", host, port);
    tracing::info!("GraphHunter HTTP API: binding to {} ...", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(
        "GraphHunter HTTP API listening on http://{} (health: /health)",
        addr
    );
    tracing::info!("GraphHunter HTTP API: ready to accept connections.");
    if host == "0.0.0.0" {
        tracing::info!("Use http://127.0.0.1:{}/ in browser (localhost may fail on Windows due to IPv6)", port);
    }

    let app = build_app(state, api);
    axum::serve(listener, app).await?;
    Ok(())
}

/// Legacy: run the HTTP API in a dedicated thread with its own Tokio runtime.
/// Prefer run_async on Tauri's runtime to avoid cross-runtime lock issues.
#[allow(dead_code)]
pub fn run(state: Arc<AppState>, api: Arc<GraphHunterApi>, port: u16) {
    let host = std::env::var("GRAPHHUNTER_API_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    tracing::info!("GraphHunter HTTP API: binding to {}:{} ...", host, port);
    let addr = (host.as_str(), port);
    let listener = std::net::TcpListener::bind(addr).unwrap_or_else(|e| {
        tracing::error!("GraphHunter HTTP API: failed to bind to {}:{}: {}", host, port, e);
        std::process::exit(1);
    });
    tracing::info!("GraphHunter HTTP API: bind OK, building router ...");
    let app = build_app(state, api);
    tracing::info!("GraphHunter HTTP API: creating tokio runtime (multi_thread, 8 workers) ...");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async {
        let listener = tokio::net::TcpListener::from_std(listener).expect("tcp listener");
        tracing::info!(
            "GraphHunter HTTP API listening on http://{}:{}/ (health: /health)",
            host, port
        );
        tracing::info!("GraphHunter HTTP API: ready to accept connections.");
        if host == "0.0.0.0" {
            tracing::info!("Use http://127.0.0.1:{}/ in browser (localhost may fail on Windows due to IPv6)", port);
        }
        axum::serve(listener, app).await.expect("serve");
    });
}
