mod ai;
pub mod commands;
pub mod evtx;
pub mod format_registry;
pub mod helpers;
mod http_api;
pub mod scoring;
pub mod sentinel_connector;
pub mod state;
pub mod types;

// Re-exports for backward compatibility (used by http_api.rs and external consumers).
pub use helpers::{
    create_note_impl, parse_entity_type, with_current_graph, with_current_graph_mut,
    with_current_session_and_graph,
};
pub use state::AppState;
pub use types::{PaginatedHuntResults, Subgraph, SubgraphEdge, SubgraphNode};

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// Entry point for the Tauri application.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Load .env: walk up from CWD until we find one
    {
        let mut dir = std::env::current_dir().ok();
        let mut loaded = false;
        while let Some(d) = dir {
            let candidate = d.join(".env");
            if candidate.is_file() {
                if dotenvy::from_path(&candidate).is_ok() {
                    eprintln!(".env loaded from {}", candidate.display());
                    loaded = true;
                    break;
                }
            }
            dir = d.parent().map(|p| p.to_path_buf());
        }
        if !loaded {
            eprintln!(".env not found in any parent directory");
        }
    }

    let api_token = std::env::var("GRAPHHUNTER_API_TOKEN")
        .unwrap_or_else(|_| Uuid::new_v4().to_string());
    eprintln!("GRAPHHUNTER_API_TOKEN={}", api_token);
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let app_state = Arc::new(state::AppState {
        sessions: RwLock::new(HashMap::new()),
        current_session_id: RwLock::new(None),
        cached_hunt_paths: RwLock::new(Vec::new()),
        app_handle: RwLock::new(None),
        last_mcp_subgraph: RwLock::new(None),
        ai_config: RwLock::new(None),
        ai_conversation: RwLock::new(ai::AiConversation::new()),
        api_token,
        npu_scorer: RwLock::new(None),
        sentinel_connector: RwLock::new(None),
    });
    let http_port = std::env::var("GRAPHHUNTER_API_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(37891);
    let state_for_http = Arc::clone(&app_state);
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(app_state)
        .setup(move |app| {
            use tauri::Manager;
            if let Some(state) = app.try_state::<Arc<state::AppState>>() {
                if let Ok(mut h) = state.app_handle.write() {
                    *h = Some(app.handle().clone());
                }
            }
            eprintln!("GraphHunter HTTP API starting on Tauri async runtime (port {})", http_port);
            let _ = std::io::Write::flush(&mut std::io::stderr());
            tauri::async_runtime::spawn(async move {
                if let Err(e) = http_api::run_async(state_for_http, http_port).await {
                    eprintln!("GraphHunter HTTP API error: {}", e);
                } else {
                    eprintln!("GraphHunter HTTP API exited (serve returned)");
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
            commands::graph_ops::cmd_get_subgraph,
            commands::graph_ops::cmd_search_entities,
            commands::graph_ops::cmd_expand_node,
            commands::graph_ops::cmd_get_node_details,
            commands::graph_ops::cmd_get_graph_summary,
            commands::graph_ops::cmd_compute_scores,
            commands::graph_ops::cmd_get_events_for_node,
            // DSL commands
            commands::dsl::cmd_parse_dsl,
            commands::dsl::cmd_get_catalog,
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
            // Sentinel real-time connector commands
            commands::sentinel::cmd_sentinel_connect,
            commands::sentinel::cmd_sentinel_disconnect,
            commands::sentinel::cmd_sentinel_status,
            commands::sentinel::cmd_sentinel_check_env,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Graph Hunter");
}
