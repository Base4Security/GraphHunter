// `ai` module moved to `graph_hunter_api::ai` in P1 Fase 2.
pub mod commands;
pub mod error;
pub mod evtx;
pub mod format_registry;
pub mod helpers;
mod http_api;
pub mod scoring;
pub mod sentinel_connector;
pub mod state;
pub mod tauri_emitter;
pub mod types;

// Re-exports for backward compatibility. The `with_current_*` helpers
// are no longer needed by any external consumer after P1 Fase 2 —
// only `http_api.rs::build_subgraph_for_ids` still uses the
// `with_current_graph` form internally, which it imports directly.
pub use helpers::parse_entity_type;
pub use state::AppState;
pub use types::{PaginatedHuntResults, Subgraph, SubgraphEdge, SubgraphNode};

use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// Entry point for the Tauri application.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Load .env: walk up from CWD until we find one
    {
        let mut dir = std::env::current_dir().ok();
        let mut loaded = false;
        while let Some(d) = dir {
            let candidate = d.join(".env");
            if candidate.is_file() {
                if dotenvy::from_path(&candidate).is_ok() {
                    tracing::info!(".env loaded from {}", candidate.display());
                    loaded = true;
                    break;
                }
            }
            dir = d.parent().map(|p| p.to_path_buf());
        }
        if !loaded {
            tracing::warn!(".env not found in any parent directory");
        }
    }

    let api_token = std::env::var("GRAPHHUNTER_API_TOKEN")
        .unwrap_or_else(|_| Uuid::new_v4().to_string());
    let masked = if api_token.len() > 4 {
        format!("{}...{}", &api_token[..4], &api_token[api_token.len() - 4..])
    } else {
        "****".to_string()
    };
    tracing::debug!("GRAPHHUNTER_API_TOKEN={}", masked);
    // Shared AppHandle slot: the Tauri `setup()` callback populates it;
    // both `AppState` and the canonical `TauriEventEmitter` read from
    // this same `Arc<RwLock<_>>`, so canonical API emissions reach the
    // frontend through the same path as legacy `AppHandle::emit` calls.
    let app_handle_slot: Arc<RwLock<Option<tauri::AppHandle>>> = Arc::new(RwLock::new(None));
    let emitter: Arc<dyn graph_hunter_api::EventEmitter> = Arc::new(
        tauri_emitter::TauriEventEmitter::new(app_handle_slot.clone()),
    );
    // Canonical API façade, shared across Tauri commands, the HTTP API,
    // and (eventually) any other transport. AppState pulls its sessions
    // / current / hunt_cache handles from the API so legacy helpers and
    // the canonical operations see the exact same state.
    let api = Arc::new(graph_hunter_api::GraphHunterApi::new(emitter));
    // Populate the API's GeoIP slot at startup (MaxMind from disk).
    // AppState no longer holds this handle directly — all GeoIP
    // ops go through the canonical API.
    {
        let handle = api.geoip_provider_handle();
        let provider = dirs::data_dir()
            .map(|d| d.join("GraphHunter").join("geoip"))
            .and_then(|dir| {
                graph_hunter_core::geoip::maxmind::MaxMindProvider::from_directory(&dir).ok()
            })
            .filter(|p| p.is_available());
        if provider.is_some() {
            tracing::info!("MaxMind GeoIP databases loaded");
        }
        if let Ok(mut g) = handle.lock() {
            *g = provider;
        }
    }

    let app_state = Arc::new(state::AppState {
        sessions: api.sessions().map_handle(),
        current_session_id: api.sessions().current_handle(),
        app_handle: app_handle_slot.clone(),
        last_mcp_subgraph: RwLock::new(None),
        api_token,
    });
    let http_port = std::env::var("GRAPHHUNTER_API_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(37891);
    let state_for_http = Arc::clone(&app_state);
    let api_for_http = Arc::clone(&api);
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(app_state)
        .manage(api)
        .setup(move |app| {
            // Write the AppHandle once into the shared slot — visible
            // to both `AppState.app_handle` and the `TauriEventEmitter`.
            if let Ok(mut h) = app_handle_slot.write() {
                *h = Some(app.handle().clone());
            }
            tracing::info!("GraphHunter HTTP API starting on Tauri async runtime (port {})", http_port);
            tauri::async_runtime::spawn(async move {
                if let Err(e) = http_api::run_async(state_for_http, api_for_http, http_port).await {
                    tracing::error!("GraphHunter HTTP API error: {}", e);
                } else {
                    tracing::info!("GraphHunter HTTP API exited (serve returned)");
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Session commands
            commands::session::cmd_create_session,
            commands::session::cmd_list_sessions,
            commands::session::cmd_load_session,
            commands::session::cmd_save_session,
            commands::session::cmd_delete_session,
            commands::session::cmd_get_current_session,
            // Entity, path nodes, and notes commands
            commands::entity::cmd_get_entity_types_in_graph,
            commands::entity::cmd_get_entity_types_for_node_neighbours,
            commands::entity::cmd_get_entity_type_counts,
            commands::entity::cmd_get_relation_schema,
            commands::entity::cmd_explain_score,
            commands::entity::cmd_get_entities_by_type,
            commands::entity::cmd_get_entities_by_type_paginated,
            commands::entity::cmd_get_node_ids_by_relation_type,
            commands::entity::cmd_get_path_nodes,
            commands::entity::cmd_add_path_node,
            commands::entity::cmd_remove_path_node,
            commands::entity::cmd_get_notes,
            commands::entity::cmd_create_note,
            commands::entity::cmd_update_note,
            commands::entity::cmd_delete_note,
            commands::entity::cmd_tag_entity,
            commands::entity::cmd_untag_entity,
            commands::entity::cmd_list_tagged,
            // Ingestion commands
            commands::ingestion::cmd_preview_ingest,
            commands::ingestion::cmd_load_data,
            commands::ingestion::cmd_load_data_streaming,
            commands::ingestion::cmd_ingest_siem,
            // Dataset commands
            commands::dataset::cmd_list_datasets,
            commands::dataset::cmd_remove_dataset,
            commands::dataset::cmd_rename_type_in_dataset,
            commands::dataset::cmd_dataset_entity_types,
            // Graph operation commands
            commands::graph_ops::cmd_preview_fields,
            commands::graph_ops::cmd_load_data_with_config,
            commands::graph_ops::cmd_get_graph_stats,
            commands::graph_ops::cmd_run_hunt,
            commands::graph_ops::cmd_get_hunt_page,
            commands::graph_ops::cmd_diff_hunts,
            commands::graph_ops::cmd_get_subgraph,
            commands::graph_ops::cmd_search_entities,
            commands::graph_ops::cmd_expand_node,
            commands::graph_ops::cmd_get_node_details,
            commands::graph_ops::cmd_get_graph_summary,
            commands::graph_ops::cmd_compute_scores,
            commands::graph_ops::cmd_get_events_for_node,
            commands::graph_ops::cmd_get_events_paginated,
            commands::graph_ops::cmd_expand_node_grouped,
            commands::graph_ops::cmd_get_simd_isa,
            // DSL commands
            commands::dsl::cmd_parse_dsl,
            commands::dsl::cmd_get_catalog,
            commands::dsl::cmd_get_catalog_with_status,
            commands::dsl::cmd_get_catalog_diagnostics,
            commands::dsl::cmd_load_catalog_hypothesis,
            // AI commands
            commands::ai_commands::cmd_ai_check_config,
            commands::ai_commands::cmd_ai_set_key,
            commands::ai_commands::cmd_ai_set_provider,
            commands::ai_commands::cmd_ai_propose_hypothesis,
            commands::ai_commands::cmd_ai_analyze_graph,
            commands::ai_commands::cmd_ai_analyze_graph_conversation,
            commands::ai_commands::cmd_ai_chat,
            commands::ai_commands::cmd_ai_clear_conversation,
            commands::ai_commands::cmd_ai_get_conversation,
            // Analytics commands
            commands::analytics::cmd_get_temporal_heatmap,
            commands::analytics::cmd_get_timeline_data,
            commands::analytics::cmd_compute_betweenness,
            commands::analytics::cmd_compute_pagerank,
            commands::analytics::cmd_compute_composite_scores,
            commands::analytics::cmd_compact,
            commands::analytics::cmd_test_http_api,
            commands::analytics::cmd_enable_anomaly_scoring,
            commands::analytics::cmd_update_anomaly_weights,
            commands::analytics::cmd_get_anomaly_config,
            commands::analytics::cmd_load_gnn_model,
            commands::analytics::cmd_compute_gnn_scores,
            commands::analytics::cmd_gnn_model_status,
            // Export commands
            commands::export::cmd_export_subgraph,
            commands::export::cmd_export_hunt_results,
            commands::export::cmd_export_iocs,
            commands::sentinel_publish::cmd_publish_iocs_to_sentinel,
            commands::sigma_save::cmd_save_hypothesis_as_sigma,
            commands::ticket_file::cmd_file_ticket,
            // Sentinel real-time connector commands
            commands::sentinel::cmd_sentinel_connect,
            commands::sentinel::cmd_sentinel_disconnect,
            commands::sentinel::cmd_sentinel_status,
            commands::sentinel::cmd_sentinel_check_env,
            commands::sentinel::cmd_run_kql,
            // Azure streaming plan smoke test (Phase 5-9 core validation)
            #[allow(deprecated)]
            commands::azure_streaming_smoke::cmd_azure_streaming_smoke_test,
            // IP enrichment & subnet analysis
            commands::enrichment::cmd_enrich_ip,
            commands::enrichment::cmd_get_subnet_analysis,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Graph Hunter");
}
