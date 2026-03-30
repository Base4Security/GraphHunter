use std::sync::Arc;

use tauri::State;

use graph_hunter_core::export::{
    ExportSubgraphEdge, ExportSubgraphNode, export_hunt_results_csv, export_hunt_results_json,
    export_subgraph_csv, export_subgraph_json,
};

use crate::helpers::with_current_graph;
use crate::state::AppState;

/// Builds a subgraph from the given node IDs and exports it as CSV or JSON.
#[tauri::command]
pub fn cmd_export_subgraph(
    state: State<Arc<AppState>>,
    format: String,
    nodes: Vec<String>,
) -> Result<String, String> {
    with_current_graph(state.as_ref(), |graph| {
        use ahash::HashSet;
        let id_set: HashSet<&str> = nodes.iter().map(|s| s.as_str()).collect();

        // Collect owned strings so export node/edge borrows have a stable owner.
        struct OwnedNode {
            id: String,
            entity_type: String,
            score: f64,
        }
        struct OwnedEdge {
            source: String,
            target: String,
            rel_type: String,
            timestamp: i64,
        }

        let owned_nodes: Vec<OwnedNode> = nodes
            .iter()
            .filter_map(|id| graph.get_entity(id))
            .map(|e| OwnedNode {
                id: e.id.clone(),
                entity_type: format!("{}", e.entity_type),
                score: e.score,
            })
            .collect();

        const MAX_EDGES: usize = 10_000;
        let mut owned_edges: Vec<OwnedEdge> = Vec::new();
        'outer: for source_id in &nodes {
            for compact in graph.get_compact_relations(source_id) {
                if owned_edges.len() >= MAX_EDGES {
                    break 'outer;
                }
                let dest_str = graph.interner.resolve(compact.dest_sid);
                if id_set.contains(dest_str) {
                    owned_edges.push(OwnedEdge {
                        source: graph.interner.resolve(compact.source_sid).to_string(),
                        target: dest_str.to_string(),
                        rel_type: format!("{}", compact.rel_type()),
                        timestamp: compact.timestamp,
                    });
                }
            }
        }

        let export_nodes: Vec<ExportSubgraphNode<'_>> = owned_nodes
            .iter()
            .map(|n| ExportSubgraphNode {
                id: &n.id,
                entity_type: &n.entity_type,
                score: n.score,
            })
            .collect();
        let export_edges: Vec<ExportSubgraphEdge<'_>> = owned_edges
            .iter()
            .map(|e| ExportSubgraphEdge {
                source: &e.source,
                target: &e.target,
                rel_type: &e.rel_type,
                timestamp: e.timestamp,
            })
            .collect();

        let mut buf = Vec::new();
        match format.as_str() {
            "csv" => export_subgraph_csv(&export_nodes, &export_edges, &mut buf)
                .map_err(|e| e.to_string())?,
            "json" => export_subgraph_json(&export_nodes, &export_edges, &mut buf)
                .map_err(|e| e.to_string())?,
            _ => return Err(format!("Unsupported format: {format}. Use 'csv' or 'json'.")),
        }
        String::from_utf8(buf).map_err(|e| format!("UTF-8 encoding error: {e}"))
    })
}

/// Exports cached hunt results as CSV or JSON.
#[tauri::command]
pub fn cmd_export_hunt_results(
    state: State<Arc<AppState>>,
    format: String,
) -> Result<String, String> {
    // Clone the cache and drop the guard before acquiring the graph lock.
    let cache = {
        let guard = state
            .cached_hunt_paths
            .read()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        if guard.is_empty() {
            return Err("No hunt results to export. Run a hunt first.".to_string());
        }
        guard.clone()
    };

    let scored = with_current_graph(state.as_ref(), |graph| {
        let (all_scored, _) = graph.score_and_paginate_paths(&cache, 0, cache.len(), None);
        Ok(all_scored)
    })?;

    let mut buf = Vec::new();
    match format.as_str() {
        "csv" => export_hunt_results_csv(&scored, &mut buf).map_err(|e| e.to_string())?,
        "json" => export_hunt_results_json(&scored, &mut buf).map_err(|e| e.to_string())?,
        _ => return Err(format!("Unsupported format: {format}. Use 'csv' or 'json'.")),
    }
    String::from_utf8(buf).map_err(|e| format!("UTF-8 encoding error: {e}"))
}
