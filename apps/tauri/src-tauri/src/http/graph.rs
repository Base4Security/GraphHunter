//! Graph query endpoints: search, expand, subgraph, events, schema lookups.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use crate::AppState;
use graph_hunter_api::GraphHunterApi;

use super::helpers::{
    api_response, build_subgraph_for_ids, err_json, mcp_emit_view, neighborhood_to_subgraph,
    ok_json,
};

pub(super) async fn handler_entity_types(State(api): State<Arc<GraphHunterApi>>) -> Response {
    api_response(api.get_entity_types_in_graph(
        graph_hunter_api::dto::entity::SessionOnly::default(),
    ))
}

pub(super) async fn handler_relation_schema(State(api): State<Arc<GraphHunterApi>>) -> Response {
    // Response shape:
    //   { "entries": [...], "_meta": { "compute_ms": N, "cache_hit": bool } }
    // Wall-clock is measured here (at the transport edge) so the number
    // reflects what a client would observe; `cache_hit` comes from the
    // core and is authoritative. Used by the MCP transport to let
    // Claude distinguish cached from uncached calls without having to
    // run the request twice.
    let start = std::time::Instant::now();
    match api.get_relation_schema_with_cache_info(
        graph_hunter_api::dto::entity::SessionOnly::default(),
    ) {
        Ok((entries, cache_hit)) => {
            let compute_ms = start.elapsed().as_millis() as u64;
            ok_json(serde_json::json!({
                "entries": entries,
                "_meta": {
                    "compute_ms": compute_ms,
                    "cache_hit": cache_hit,
                },
            }))
        }
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct SearchQuery {
    // `q` is optional on the wire so a missing param produces our own
    // structured 400 JSON instead of axum's plain-text "failed to
    // deserialize query string" response — which the MCP client
    // surfaces as "did not return JSON" and looks like a transport break.
    #[serde(default)]
    q: Option<String>,
    #[serde(rename = "type")]
    type_filter: Option<String>,
    limit: Option<usize>,
}

pub(super) async fn handler_search(
    State(state): State<Arc<AppState>>,
    State(api): State<Arc<GraphHunterApi>>,
    Query(q): Query<SearchQuery>,
) -> Response {
    match api.search_entities(graph_hunter_api::dto::graph_ops::SearchEntitiesRequest {
        session: None,
        query: q.q.unwrap_or_default(),
        type_filter: q.type_filter,
        limit: q.limit,
    }) {
        Ok(v) => {
            let node_ids: Vec<String> = v.iter().map(|r| r.id.clone()).collect();
            if !node_ids.is_empty() {
                if let Ok(sg) = build_subgraph_for_ids(api.as_ref(), &node_ids) {
                    mcp_emit_view(state.as_ref(), sg);
                }
            }
            ok_json(v)
        }
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct ExpandQuery {
    node_id: String,
    max_hops: Option<usize>,
    max_nodes: Option<usize>,
    #[serde(default)]
    pub live: bool,
    /// Lookback preset for hydration window: "1h" | "6h" | "24h" | "7d" | "30d".
    #[serde(default)]
    pub lookback: Option<String>,
}

pub(super) fn lookback_to_window(
    lookback: Option<&str>,
) -> Option<graph_hunter_api::dto::sentinel::TimeWindow> {
    use graph_hunter_api::dto::sentinel::{LookbackPreset, TimeWindow};
    let preset = match lookback? {
        "1h" => LookbackPreset::H1,
        "6h" => LookbackPreset::H6,
        "24h" => LookbackPreset::H24,
        "7d" => LookbackPreset::D7,
        "30d" => LookbackPreset::D30,
        _ => return None,
    };
    Some(TimeWindow::Preset { lookback: preset })
}

pub(super) async fn handler_expand(
    State(state): State<Arc<AppState>>,
    State(api): State<Arc<GraphHunterApi>>,
    Query(q): Query<ExpandQuery>,
) -> Response {
    if q.live {
        let req = graph_hunter_api::dto::graph_ops::ExpandNodeRequest {
            session: None,
            node_id: q.node_id.clone(),
            max_hops: q.max_hops,
            max_nodes: q.max_nodes,
            filter: None,
            live: true,
            time_window: lookback_to_window(q.lookback.as_deref()),
        };
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(90),
            api.expand_node_live(req),
        )
        .await
        .unwrap_or_else(|_| Err(graph_hunter_api::ApiError::Internal("expand (live) timed out".into())));
        return match result {
            Ok(hood) => {
                let sg = neighborhood_to_subgraph(&hood);
                mcp_emit_view(state.as_ref(), sg);
                ok_json(hood)
            }
            Err(e) => {
                let code = StatusCode::from_u16(e.status_code())
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
            }
        };
    }
    let api_clone = api.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::task::spawn_blocking(move || {
            api_clone.expand_node(graph_hunter_api::dto::graph_ops::ExpandNodeRequest {
                session: None,
                node_id: q.node_id,
                max_hops: q.max_hops,
                max_nodes: q.max_nodes,
                filter: None,
                live: false,
                time_window: None,
            })
        }),
    )
    .await;
    match result {
        Ok(Ok(Ok(hood))) => {
            let sg = neighborhood_to_subgraph(&hood);
            mcp_emit_view(state.as_ref(), sg);
            ok_json(hood)
        }
        Ok(Ok(Err(e))) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
        Ok(Err(e)) => err_json(format!("Task error: {}", e)),
        Err(_) => err_json("Expand timed out after 60 seconds"),
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct NodeDetailsQuery {
    node_id: String,
}

/// §4.5 graph_neighbors — immediate neighborhood of an entity, reshaped to the
/// design-doc contract. Read-only graph traversal; no SIEM round-trip.
pub(super) async fn handler_graph_neighbors(
    State(api): State<Arc<GraphHunterApi>>,
    Json(req): Json<graph_hunter_api::dto::graph_ops::GraphNeighborsRequest>,
) -> Response {
    api_response(api.graph_neighbors(req))
}

/// §4.4 graph_path — paths between two entities (or all outbound paths).
/// Read-only graph traversal; no SIEM round-trip.
pub(super) async fn handler_graph_path(
    State(api): State<Arc<GraphHunterApi>>,
    Json(req): Json<graph_hunter_api::dto::graph_ops::GraphPathRequest>,
) -> Response {
    api_response(api.graph_path(req))
}

/// §4.6 graph_anomaly — structural anomalies (degree/betweenness/isolation).
pub(super) async fn handler_graph_anomaly(
    State(api): State<Arc<GraphHunterApi>>,
    Json(req): Json<graph_hunter_api::dto::graph_ops::GraphAnomalyRequest>,
) -> Response {
    api_response(api.graph_anomaly(req))
}

pub(super) async fn handler_node_details(
    State(api): State<Arc<GraphHunterApi>>,
    Query(q): Query<NodeDetailsQuery>,
) -> Response {
    let api_clone = api.clone();
    let node_id = q.node_id.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || {
            api_clone.get_node_details(graph_hunter_api::dto::entity::NodeScopedRequest {
                session: None,
                node_id,
            })
        }),
    )
    .await;
    match result {
        Ok(Ok(Ok(v))) => ok_json(v),
        Ok(Ok(Err(e))) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        },
        Ok(Err(e)) => err_json(format!("Task error: {}", e)),
        Err(_) => err_json("Node details timed out after 30 seconds"),
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct SubgraphBody {
    node_ids: Vec<String>,
    #[serde(default)]
    page_size: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
}

pub(super) async fn handler_subgraph(
    State(state): State<Arc<AppState>>,
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<SubgraphBody>,
) -> Response {
    let api_clone = api.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::task::spawn_blocking(move || {
            api_clone.get_subgraph(graph_hunter_api::dto::graph_ops::SubgraphRequest {
                session: None,
                node_ids: body.node_ids,
                page_size: body.page_size,
                offset: body.offset,
            })
        }),
    )
    .await;
    match result {
        Ok(Ok(Ok(sg))) => {
            mcp_emit_view(state.as_ref(), sg.clone());
            ok_json(sg)
        }
        Ok(Ok(Err(e))) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
        Ok(Err(e)) => err_json(format!("Task error: {}", e)),
        Err(_) => err_json("Subgraph query timed out after 60 seconds"),
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct EventsQuery {
    node_id: String,
}

pub(super) async fn handler_events_for_node(
    State(state): State<Arc<AppState>>,
    State(api): State<Arc<GraphHunterApi>>,
    Query(q): Query<EventsQuery>,
) -> Response {
    let api_clone = api.clone();
    let node_id = q.node_id.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::task::spawn_blocking(move || {
            let edges = api_clone.get_events_for_node(
                graph_hunter_api::dto::graph_ops::EventsForNodeRequest {
                    session: None,
                    node_id: node_id.clone(),
                },
            )?;
            // Build subgraph for the event participants to update the frontend map
            let mut ids: HashSet<String> = HashSet::new();
            ids.insert(node_id);
            for e in &edges {
                ids.insert(e.source.clone());
                ids.insert(e.target.clone());
            }
            let node_ids: Vec<String> = ids.into_iter().collect();
            let sg = if !node_ids.is_empty() {
                build_subgraph_for_ids(api_clone.as_ref(), &node_ids).ok()
            } else {
                None
            };
            Ok::<_, graph_hunter_api::ApiError>((edges, sg))
        }),
    )
    .await;
    match result {
        Ok(Ok(Ok((edges, sg)))) => {
            if let Some(sg) = sg {
                mcp_emit_view(state.as_ref(), sg);
            }
            ok_json(edges)
        }
        Ok(Ok(Err(e))) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
        Ok(Err(e)) => err_json(format!("Task error: {}", e)),
        Err(_) => err_json("Events query timed out after 60 seconds"),
    }
}

pub(super) async fn handler_graph_summary(State(api): State<Arc<GraphHunterApi>>) -> Response {
    api_response(api.get_graph_summary(
        graph_hunter_api::dto::geoip::GraphSummaryRequest::default(),
    ))
}

pub(super) async fn handler_entity_type_counts(State(api): State<Arc<GraphHunterApi>>) -> Response {
    api_response(api.get_entity_type_counts(
        graph_hunter_api::dto::entity::SessionOnly::default(),
    ))
}

pub(super) async fn handler_path_nodes(State(api): State<Arc<GraphHunterApi>>) -> Response {
    api_response(api.get_path_nodes(
        graph_hunter_api::dto::entity::SessionOnly::default(),
    ))
}

#[derive(Debug, Deserialize)]
pub(super) struct EventsPaginatedQuery {
    node_id: String,
    page: Option<usize>,
    page_size: Option<usize>,
    sort_by: Option<String>,
}

pub(super) async fn handler_events_paginated(
    State(api): State<Arc<GraphHunterApi>>,
    Query(q): Query<EventsPaginatedQuery>,
) -> Response {
    let api_clone = api.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::task::spawn_blocking(move || {
            api_clone.get_events_paginated(
                graph_hunter_api::dto::graph_ops::EventsPaginatedRequest {
                    session: None,
                    node_id: q.node_id,
                    page: q.page.unwrap_or(0),
                    page_size: q.page_size,
                    sort_by: q.sort_by,
                },
            )
        }),
    )
    .await;
    match result {
        Ok(Ok(Ok(v))) => ok_json(v),
        Ok(Ok(Err(e))) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
        Ok(Err(e)) => err_json(format!("Task error: {e}")),
        Err(_) => err_json("Events query timed out"),
    }
}

#[derive(serde::Deserialize)]
pub(super) struct HeavyEdgesQuery {
    #[serde(default)]
    pub top_n: Option<usize>,
    #[serde(default)]
    pub min_count: Option<usize>,
    #[serde(default)]
    pub rel_type: Option<String>,
}

pub(super) async fn handler_heavy_edges(
    State(api): State<Arc<GraphHunterApi>>,
    Query(q): Query<HeavyEdgesQuery>,
) -> Response {
    api_response(api.graph_heavy_edges(graph_hunter_api::dto::graph_ops::HeavyEdgesRequest {
        session: None,
        top_n: q.top_n,
        min_count: q.min_count,
        rel_type: q.rel_type,
    }))
}

#[derive(serde::Deserialize)]
pub(super) struct ChannelBehaviorQuery {
    #[serde(default)]
    pub top_n: Option<usize>,
    #[serde(default)]
    pub min_count: Option<usize>,
    #[serde(default)]
    pub window_secs: Option<u64>,
    #[serde(default)]
    pub rel_type: Option<String>,
    #[serde(default)]
    pub sort_by: Option<String>,
}

pub(super) async fn handler_channel_behavior(
    State(api): State<Arc<GraphHunterApi>>,
    Query(q): Query<ChannelBehaviorQuery>,
) -> Response {
    api_response(api.graph_channel_behavior(
        graph_hunter_api::dto::graph_ops::ChannelBehaviorRequest {
            session: None,
            top_n: q.top_n,
            min_count: q.min_count,
            window_secs: q.window_secs,
            rel_type: q.rel_type,
            sort_by: q.sort_by,
        },
    ))
}

pub(super) async fn handler_expand_grouped(
    State(api): State<Arc<GraphHunterApi>>,
    Query(q): Query<ExpandQuery>,
) -> Response {
    let api_clone = api.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::task::spawn_blocking(move || {
            api_clone.expand_node_grouped(graph_hunter_api::dto::graph_ops::ExpandNodeRequest {
                session: None,
                node_id: q.node_id,
                max_hops: q.max_hops,
                max_nodes: q.max_nodes,
                filter: None,
                live: false,
                time_window: None,
            })
        }),
    )
    .await;
    match result {
        Ok(Ok(Ok(v))) => ok_json(v),
        Ok(Ok(Err(e))) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
        Ok(Err(e)) => err_json(format!("Task error: {e}")),
        Err(_) => err_json("Expand grouped timed out"),
    }
}
