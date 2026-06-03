// `ai` module moved to `graph_hunter_api::ai` in P1 Fase 2.
pub mod commands;
pub mod error;
pub mod evtx;
pub mod format_registry;
pub mod helpers;
mod http;
pub mod scoring;
pub mod sentinel_connector;
pub mod state;
pub mod tauri_emitter;
pub mod types;

// Re-exports for backward compatibility. The `with_current_*` helpers
// are no longer needed by any external consumer after P1 Fase 2 —
// only `http::helpers::build_subgraph_for_ids` still uses the
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

    // M-track perf flags: default-on for the Tauri app so the
    // frontend automatically benefits from the structural K_4 LFTJ
    // dispatch (M1) and the name-marker S3 detector when the user
    // runs `npm run tauri dev`. Both are conservative — the
    // dispatcher inspects each hypothesis and falls back to the
    // legacy DFS for any shape that does not match. Users can
    // override with `GRAPHHUNTER_LFTJ_PLANNER=0` /
    // `GRAPHHUNTER_K4_LFTJ=0` if they want the legacy path. AMAC
    // and SEMIJOIN remain opt-in (they have parity tests but are
    // newer and rewrite the DFS hot loop) — flip those manually
    // once your bench shows the lift you expect.
    for (key, default) in [
        ("GRAPHHUNTER_LFTJ_PLANNER", "1"),
        ("GRAPHHUNTER_K4_LFTJ", "1"),
        ("GRAPHHUNTER_YANNAKAKIS", "1"),
        // GRAPHHUNTER_LLM_INGEST was the silent-dispatcher kill-switch
        // when Phase C ran the LLM on every ambiguous ingest. Phase G
        // demoted that path to a manual "Probar mapeo IA" button on
        // `DatasetCard`, so there's no env-var to default-on anymore —
        // the AI runs only when the analyst clicks. The env var is
        // still honored if set (for future re-enablement of the
        // silent path), just not flipped at startup.
    ] {
        if std::env::var(key).is_err() {
            // SAFETY: set_var is unsafe in 2024 edition because env
            // mutation can race with other threads reading env. Here
            // we are still single-threaded — Tauri's runtime spawns
            // workers later in `setup()`. The matcher reads these
            // flags lazily on first hunt, well after `run()` returns.
            unsafe { std::env::set_var(key, default) };
            tracing::info!("perf flag default-on: {}={}", key, default);
        } else {
            tracing::debug!("perf flag honored from env: {}", key);
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
    // Initialize the drift store on disk. Placed beside other GraphHunter
    // runtime state. If the directory is unavailable (no HOME?) or SQLite
    // refuses to open the file, log and leave the slot empty — ingest will
    // run fine, only /metrics and drift_report will be empty.
    {
        let handle = api.drift_store_handle();
        let store = dirs::data_dir()
            .map(|d| d.join("GraphHunter").join("sessions"))
            .and_then(|dir| {
                std::fs::create_dir_all(&dir).ok()?;
                let path = dir.join("drift.sqlite");
                match graph_hunter_core::drift::DriftStore::open(&path) {
                    Ok(s) => Some(s),
                    Err(e) => {
                        tracing::warn!("DriftStore open failed at {}: {}", path.display(), e);
                        None
                    }
                }
            });
        if store.is_some() {
            tracing::info!("Drift store initialized");
        }
        if let Ok(mut g) = handle.lock() {
            *g = store;
        }
    }

    // DLQ store: JSONL shards under `<data>/GraphHunter/sessions/dlq/`.
    // Same graceful-degradation contract as drift — failures leave the
    // slot `None` and the DLQ API ops return empty.
    {
        let handle = api.dlq_store_handle();
        let store = dirs::data_dir()
            .map(|d| d.join("GraphHunter").join("sessions").join("dlq"))
            .and_then(|dir| match graph_hunter_core::dlq::DlqStore::open(&dir) {
                Ok(s) => Some(std::sync::Arc::new(s)),
                Err(e) => {
                    tracing::warn!("DlqStore open failed at {}: {}", dir.display(), e);
                    None
                }
            });
        if store.is_some() {
            tracing::info!("Dead-letter queue initialized");
        }
        if let Ok(mut g) = handle.lock() {
            *g = store;
        }
    }

    // Mapping library: JSONL catalog under
    // `<data>/GraphHunter/mapping_library/`. Populated by the
    // review-queue approval hook; read by future RAG lookups.
    {
        let handle = api.mapping_library_handle();
        let store = dirs::data_dir()
            .map(|d| d.join("GraphHunter").join("mapping_library"))
            .and_then(|dir| {
                match graph_hunter_core::mapping_library::MappingLibraryStore::open(&dir) {
                    Ok(s) => Some(std::sync::Arc::new(s)),
                    Err(e) => {
                        tracing::warn!(
                            "MappingLibraryStore open failed at {}: {}",
                            dir.display(),
                            e
                        );
                        None
                    }
                }
            });
        if store.is_some() {
            tracing::info!("Mapping library initialized");
        }
        if let Ok(mut g) = handle.lock() {
            *g = store;
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
                if let Err(e) = http::run_async(state_for_http, api_for_http, http_port).await {
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
            commands::ingestion::cmd_pcap_preview,
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
            commands::graph_ops::cmd_run_hunt_batch,
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
            commands::export::cmd_export_ocsf,
            commands::invariants::cmd_check_invariants,
            commands::sentinel_publish::cmd_publish_iocs_to_sentinel,
            commands::sigma_save::cmd_save_hypothesis_as_sigma,
            commands::ticket_file::cmd_file_ticket,
            // Perf-flag introspection (M-track plug-and-play surface)
            commands::perf::cmd_get_perf_status,
            // Ingest-engine introspection (RawIngestEvent + VRL/LLM compiler badge)
            commands::ingest_status::cmd_get_ingest_engine_status,
            commands::ingest_status::cmd_debug_emit_synthetic_llm_proposal,
            commands::ingest_status::cmd_request_llm_proposal,
            // Heavy-logs #4: soft-memory-ceiling telemetry
            commands::memory::cmd_get_memory_status,
            // Sentinel real-time connector commands
            commands::sentinel::cmd_sentinel_connect,
            commands::sentinel::cmd_sentinel_disconnect,
            commands::sentinel::cmd_sentinel_status,
            commands::sentinel::cmd_sentinel_resume,
            commands::sentinel::cmd_sentinel_pause,
            commands::sentinel::cmd_sentinel_check_env,
            commands::sentinel::cmd_run_kql,
            commands::sentinel::cmd_run_hunting_template,
            commands::sentinel::cmd_preview_hunting_template,
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
