use std::collections::HashSet;
use std::sync::Arc;

use graph_hunter_core::{
    ConfigurableParser, FieldConfig, FieldInfo, GenericParser, Hypothesis,
    NeighborEdge, NeighborNode, Neighborhood,
    preview_fields,
};
use tauri::State;

use crate::error::CommandError;
use crate::helpers::{
    parse_entity_type, to_core_filter, with_current_graph, with_current_graph_mut,
    with_current_session_and_graph,
};
use crate::scoring::run_full_scoring;
use crate::state::AppState;
use crate::types::{
    ExpandFilter, GraphStats, HuntResults, LoadResult, PaginatedHuntResults,
    SubgraphEdge, SubgraphNode, Subgraph,
};
use crate::evtx::{evtx_to_sysmon_ndjson, path_is_evtx, file_looks_like_evtx};

/// Returns current graph statistics (node and edge counts).
#[tauri::command]
pub fn cmd_get_graph_stats(state: State<Arc<AppState>>) -> Result<GraphStats, CommandError> {
    with_current_graph(state.as_ref(), |graph| {
        Ok(GraphStats {
            entity_count: graph.entity_count(),
            relation_count: graph.relation_count(),
        })
    })
}

/// Executes a temporal pattern search using the provided hypothesis.
#[tauri::command]
pub fn cmd_run_hunt(
    state: State<Arc<AppState>>,
    hypothesis_json: String,
    time_window: Option<(i64, i64)>,
) -> Result<HuntResults, CommandError> {
    let hypothesis: Hypothesis = serde_json::from_str(&hypothesis_json)
        .map_err(|e| CommandError::ParseError(format!("Invalid hypothesis JSON: {}", e)))?;

    let (paths, truncated) = with_current_graph(state.as_ref(), |graph| {
        let scorer_ready = graph
            .anomaly_scorer
            .as_ref()
            .map(|s| s.is_finalized())
            .unwrap_or(false);
        if scorer_ready {
            graph.search_temporal_pattern_smart(&hypothesis, time_window, 10_000)
                .map_err(|e| CommandError::Internal(format!("Search failed: {}", e)))
        } else {
            graph.search_temporal_pattern(&hypothesis, time_window, Some(10_000))
                .map_err(|e| CommandError::Internal(format!("Search failed: {}", e)))
        }
    })?;

    let path_count = paths.len();

    let mut cache = state
        .cached_hunt_paths
        .write()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;

    if path_count <= 100 {
        let result = HuntResults {
            paths: paths.clone(),
            path_count,
            truncated,
        };
        *cache = paths;
        Ok(result)
    } else {
        *cache = paths;
        Ok(HuntResults {
            paths: Vec::new(),
            path_count,
            truncated,
        })
    }
}

/// Returns a paginated, scored, and optionally filtered page of cached hunt results.
#[tauri::command]
pub fn cmd_get_hunt_page(
    state: State<Arc<AppState>>,
    page: usize,
    page_size: usize,
    min_score: Option<f64>,
) -> Result<PaginatedHuntResults, CommandError> {
    let cache = state
        .cached_hunt_paths
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
    let total_paths = cache.len();

    with_current_graph(state.as_ref(), |graph| {
        let (scored_page, filtered_count) =
            graph.score_and_paginate_paths(&cache, page, page_size, min_score);
        Ok(PaginatedHuntResults {
            total_paths,
            filtered_paths: filtered_count,
            page,
            page_size,
            paths: scored_page,
        })
    })
}

/// Returns all relations (events) where the given node is source or target.
#[tauri::command]
pub fn cmd_get_events_for_node(state: State<Arc<AppState>>, node_id: String) -> Result<Vec<SubgraphEdge>, CommandError> {
    with_current_graph(state.as_ref(), |graph| {
        const MAX_EVENTS: usize = 500;
        let mut edges: Vec<SubgraphEdge> = Vec::new();

        for compact in graph.get_compact_relations(&node_id) {
            if edges.len() >= MAX_EVENTS { break; }
            edges.push(SubgraphEdge {
                source: graph.interner.resolve(compact.source_sid).to_string(),
                target: graph.interner.resolve(compact.dest_sid).to_string(),
                rel_type: format!("{}", compact.rel_type()),
                timestamp: compact.timestamp,
                metadata: graph.meta_store.get(compact.metadata_offset),
                dataset_id: graph.resolve_dataset_tag(compact.dataset_tag).map(|s| s.to_string()),
            });
        }

        let target_sid = graph.interner.get(&node_id);
        for &source_sid in graph.get_reverse_source_sids(&node_id).iter().take(MAX_EVENTS) {
            if edges.len() >= MAX_EVENTS { break; }
            for compact in graph.get_relations_by_sid(source_sid) {
                if Some(compact.dest_sid) == target_sid {
                    edges.push(SubgraphEdge {
                        source: graph.interner.resolve(compact.source_sid).to_string(),
                        target: graph.interner.resolve(compact.dest_sid).to_string(),
                        rel_type: format!("{}", compact.rel_type()),
                        timestamp: compact.timestamp,
                        metadata: graph.meta_store.get(compact.metadata_offset),
                        dataset_id: graph.resolve_dataset_tag(compact.dataset_tag).map(|s| s.to_string()),
                    });
                    break;
                }
            }
        }

        edges.sort_by_key(|e| e.timestamp);
        Ok(edges)
    })
}

/// Returns paginated events for a node, avoiding sending all events at once.
#[tauri::command]
pub fn cmd_get_events_paginated(
    state: State<Arc<AppState>>,
    node_id: String,
    page: usize,
    page_size: Option<usize>,
    sort_by: Option<String>,
) -> Result<crate::types::PaginatedEvents, String> {
    with_current_graph(state.as_ref(), |graph| {
        let page_size = page_size.unwrap_or(100);

        // Collect all events for this node (outgoing + incoming)
        let mut all_edges: Vec<SubgraphEdge> = Vec::new();

        for compact in graph.get_compact_relations(&node_id) {
            all_edges.push(SubgraphEdge {
                source: graph.interner.resolve(compact.source_sid).to_string(),
                target: graph.interner.resolve(compact.dest_sid).to_string(),
                rel_type: format!("{}", compact.rel_type()),
                timestamp: compact.timestamp,
                metadata: graph.meta_store.get(compact.metadata_offset),
                dataset_id: graph.resolve_dataset_tag(compact.dataset_tag).map(|s| s.to_string()),
            });
        }

        let target_sid = graph.interner.get(&node_id);
        for &source_sid in graph.get_reverse_source_sids(&node_id) {
            for compact in graph.get_relations_by_sid(source_sid) {
                if Some(compact.dest_sid) == target_sid {
                    all_edges.push(SubgraphEdge {
                        source: graph.interner.resolve(compact.source_sid).to_string(),
                        target: graph.interner.resolve(compact.dest_sid).to_string(),
                        rel_type: format!("{}", compact.rel_type()),
                        timestamp: compact.timestamp,
                        metadata: graph.meta_store.get(compact.metadata_offset),
                        dataset_id: graph.resolve_dataset_tag(compact.dataset_tag).map(|s| s.to_string()),
                    });
                }
            }
        }

        // Sort
        match sort_by.as_deref() {
            Some("rel_type") => all_edges.sort_by(|a, b| a.rel_type.cmp(&b.rel_type)),
            Some("source") => all_edges.sort_by(|a, b| a.source.cmp(&b.source)),
            Some("target") => all_edges.sort_by(|a, b| a.target.cmp(&b.target)),
            _ => all_edges.sort_by_key(|e| e.timestamp),
        }

        let total_count = all_edges.len();
        let start = (page * page_size).min(total_count);
        let end = (start + page_size).min(total_count);
        let events = all_edges[start..end].to_vec();

        Ok(crate::types::PaginatedEvents {
            events,
            total_count,
            page,
            page_size,
        })
    })
}

/// Returns the complete subgraph (nodes + edges) for the given entity IDs.
#[tauri::command]
pub fn cmd_get_subgraph(state: State<Arc<AppState>>, node_ids: Vec<String>) -> Result<Subgraph, CommandError> {
    with_current_graph(state.as_ref(), |graph| {
        let id_set: HashSet<&str> =
            node_ids.iter().map(|s| s.as_str()).collect();

        let nodes: Vec<SubgraphNode> = node_ids
            .iter()
            .filter_map(|id| graph.get_entity(id))
            .map(|e| SubgraphNode {
                id: e.id.clone(),
                entity_type: format!("{}", e.entity_type),
                score: e.score,
                metadata: e.metadata.clone(),
            })
            .collect();

        const MAX_SUBGRAPH_EDGES: usize = 5000;
        let mut edges: Vec<SubgraphEdge> = Vec::new();
        'outer: for source_id in &node_ids {
            for compact in graph.get_compact_relations(source_id) {
                if edges.len() >= MAX_SUBGRAPH_EDGES { break 'outer; }
                let dest_str = graph.interner.resolve(compact.dest_sid);
                if id_set.contains(dest_str) {
                    edges.push(SubgraphEdge {
                        source: graph.interner.resolve(compact.source_sid).to_string(),
                        target: dest_str.to_string(),
                        rel_type: format!("{}", compact.rel_type()),
                        timestamp: compact.timestamp,
                        metadata: graph.meta_store.get(compact.metadata_offset),
                        dataset_id: graph.resolve_dataset_tag(compact.dataset_tag).map(|s| s.to_string()),
                    });
                }
            }
        }

        Ok(Subgraph { nodes, edges })
    })
}

/// Searches entities by substring match.
#[tauri::command]
pub fn cmd_search_entities(
    state: State<Arc<AppState>>,
    query: String,
    type_filter: Option<String>,
    limit: Option<usize>,
) -> Result<Vec<graph_hunter_core::SearchResult>, CommandError> {
    with_current_graph(state.as_ref(), |graph| {
        let et = type_filter.as_deref().and_then(parse_entity_type);
        Ok(graph.search_entities(&query, et.as_ref(), limit.unwrap_or(50)))
    })
}

/// Expands a node's neighborhood for interactive exploration.
#[tauri::command]
pub fn cmd_expand_node(
    state: State<Arc<AppState>>,
    node_id: String,
    max_hops: Option<usize>,
    max_nodes: Option<usize>,
    filter: Option<ExpandFilter>,
) -> Result<Neighborhood, CommandError> {
    with_current_session_and_graph(state.as_ref(), |session, graph| {
        let core_filter = filter.as_ref().map(to_core_filter);
        let mut hood = graph
            .get_neighborhood(
                &node_id,
                max_hops.unwrap_or(1),
                max_nodes.unwrap_or(50),
                core_filter.as_ref(),
            )
            .ok_or_else(|| CommandError::InvalidInput(format!("Entity not found: {}", node_id)))?;

        let path_ids: Vec<String> = session
            .path_node_ids
            .read()
            .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?
            .clone();
        let mut in_hood: HashSet<String> = hood.nodes.iter().map(|n| n.id.clone()).collect();

        for path_id in path_ids {
            if in_hood.contains(&path_id) {
                continue;
            }
            let Some(entity) = graph.get_entity(&path_id) else {
                continue;
            };
            hood.nodes.push(NeighborNode {
                id: entity.id.clone(),
                entity_type: format!("{}", entity.entity_type),
                score: entity.score,
                metadata: entity.metadata.clone(),
            });
            in_hood.insert(path_id.clone());

            for compact in graph.get_compact_relations(&path_id) {
                let dest_str = graph.interner.resolve(compact.dest_sid);
                if in_hood.contains(dest_str) {
                    hood.edges.push(NeighborEdge {
                        source: graph.interner.resolve(compact.source_sid).to_string(),
                        target: dest_str.to_string(),
                        rel_type: format!("{}", compact.rel_type()),
                        timestamp: compact.timestamp,
                        metadata: graph.meta_store.get(compact.metadata_offset),
                    });
                }
            }
            let target_sid = graph.interner.get(&path_id);
            for &source_sid in graph.get_reverse_source_sids(&path_id) {
                let source_str = graph.interner.resolve(source_sid);
                if !in_hood.contains(source_str) {
                    continue;
                }
                for compact in graph.get_relations_by_sid(source_sid) {
                    if Some(compact.dest_sid) == target_sid {
                        hood.edges.push(NeighborEdge {
                            source: graph.interner.resolve(compact.source_sid).to_string(),
                            target: graph.interner.resolve(compact.dest_sid).to_string(),
                            rel_type: format!("{}", compact.rel_type()),
                            timestamp: compact.timestamp,
                            metadata: graph.meta_store.get(compact.metadata_offset),
                        });
                        break;
                    }
                }
            }
        }

        Ok(hood)
    })
}

/// Expands a node's neighborhood with grouped edges (for high-degree nodes).
/// Collapses parallel edges into summary entries with count and time range.
#[tauri::command]
pub fn cmd_expand_node_grouped(
    state: State<Arc<AppState>>,
    node_id: String,
    max_hops: Option<usize>,
    max_nodes: Option<usize>,
    filter: Option<ExpandFilter>,
) -> Result<graph_hunter_core::GroupedNeighborhood, String> {
    with_current_graph(state.as_ref(), |graph| {
        let core_filter = filter.as_ref().map(to_core_filter);
        graph
            .get_neighborhood_grouped(
                &node_id,
                max_hops.unwrap_or(1),
                max_nodes.unwrap_or(50),
                core_filter.as_ref(),
            )
            .ok_or_else(|| format!("Entity not found: {}", node_id))
    })
}

/// Returns detailed information about a specific node.
#[tauri::command]
pub fn cmd_get_node_details(
    state: State<Arc<AppState>>,
    node_id: String,
) -> Result<graph_hunter_core::NodeDetails, CommandError> {
    with_current_graph(state.as_ref(), |graph| {
        graph
            .get_node_details(&node_id)
            .ok_or_else(|| CommandError::InvalidInput(format!("Entity not found: {}", node_id)))
    })
}

/// Returns a summary of the entire graph.
#[tauri::command]
pub fn cmd_get_graph_summary(
    state: State<Arc<AppState>>,
) -> Result<graph_hunter_core::GraphSummary, CommandError> {
    with_current_graph(state.as_ref(), |graph| Ok(graph.get_graph_summary()))
}

/// Recalculates scores for all entities.
#[tauri::command]
pub fn cmd_compute_scores(state: State<Arc<AppState>>) -> Result<(), CommandError> {
    with_current_graph_mut(state.as_ref(), |graph| {
        graph.compute_scores();
        Ok(())
    })
}

/// Previews all fields in a log file by sampling the first N events.
#[tauri::command]
pub fn cmd_preview_fields(path: String, sample_size: Option<usize>) -> Result<Vec<FieldInfo>, CommandError> {
    let limit = sample_size.unwrap_or(500);

    let file = std::fs::File::open(&path)
        .map_err(|e| CommandError::IoError(format!("Failed to open file '{}': {}", path, e)))?;
    let mut reader = std::io::BufReader::new(file);
    let mut buf = vec![0u8; 10 * 1024 * 1024]; // 10MB
    use std::io::Read;
    let bytes_read = reader.read(&mut buf)
        .map_err(|e| CommandError::IoError(format!("Failed to read file: {}", e)))?;
    buf.truncate(bytes_read);

    let contents = String::from_utf8_lossy(&buf).to_string();
    Ok(preview_fields(&contents, limit))
}

/// Ingests logs using a user-configured field mapping.
#[tauri::command]
pub fn cmd_load_data_with_config(
    state: State<Arc<AppState>>,
    path: String,
    config: FieldConfig,
) -> Result<LoadResult, CommandError> {
    let use_evtx = path_is_evtx(&path) || file_looks_like_evtx(&path);
    let contents = if use_evtx {
        evtx_to_sysmon_ndjson(&path).map_err(|e| CommandError::IoError(e))?
    } else {
        std::fs::read_to_string(&path)
            .map_err(|e| CommandError::IoError(format!("Failed to read file '{}': {}", path, e)))?
    };

    with_current_graph_mut(state.as_ref(), |graph| {
        let (new_entities, new_relations) = if use_evtx {
            graph.ingest_logs(&contents, &GenericParser, None)
                .map_err(|e| e.to_string())?
        } else {
            let parser = ConfigurableParser::new(config);
            graph.ingest_logs(&contents, &parser, None)
                .map_err(|e| e.to_string())?
        };
        run_full_scoring(graph);

        Ok(LoadResult {
            new_entities,
            new_relations,
            total_entities: graph.entity_count(),
            total_relations: graph.relation_count(),
        })
    })
}
