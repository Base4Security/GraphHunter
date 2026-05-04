//! Scoring pipelines used by ingest / sentinel connector paths.
//!
//! Moved from `app/src-tauri/src/scoring.rs`. Pure over
//! `graph_hunter_core::GraphHunter`; no Tauri state involved, so the
//! relocation is a straight copy.

use graph_hunter_core::GraphHunter;

const PAGERANK_RELATION_THRESHOLD: usize = 500_000;
const ADAPTIVE_PAGERANK_ITERATIONS: usize = 10;
const BETWEENNESS_ENTITY_THRESHOLD: usize = 2_000;
const ADAPTIVE_BETWEENNESS_SAMPLE: usize = 200;

/// Full scoring pipeline: degree + temporal PageRank + betweenness +
/// composite with equal weights. Use for explicit analyst-driven
/// rescoring or at dataset load time.
pub fn run_full_scoring(graph: &mut GraphHunter) {
    graph.compute_scores();
    graph.compute_temporal_pagerank(None, None, None, None, None);
    graph.compute_betweenness(None);
    graph.compute_composite_score_hunt_default();
    graph.finalize_anomaly_scorer();
}

/// Adaptive scoring: skips PageRank for graphs >500K relations and
/// betweenness for graphs >2K entities. Used during ingest when graph
/// size is uncertain.
pub fn run_scoring_adaptive(graph: &mut GraphHunter) -> Result<(), String> {
    graph.sort_edges_by_timestamp().map_err(|e| e.to_string())?;

    let n = graph.entity_count();
    let m = graph.relation_count();
    tracing::info!("SCORING: {} entities, {} relations", n, m);

    graph.compute_scores();

    if m <= PAGERANK_RELATION_THRESHOLD {
        graph.compute_temporal_pagerank(None, None, Some(ADAPTIVE_PAGERANK_ITERATIONS), None, None);
    } else {
        tracing::info!("SCORING: skipping PageRank ({}M relations)", m / 1_000_000);
    }

    if n <= BETWEENNESS_ENTITY_THRESHOLD {
        graph.compute_betweenness(Some(ADAPTIVE_BETWEENNESS_SAMPLE));
    } else {
        tracing::info!("SCORING: skipping betweenness ({} entities)", n);
    }

    graph.compute_composite_score_hunt_default();
    graph.finalize_anomaly_scorer();
    tracing::info!("SCORING: complete");
    Ok(())
}

/// Lightweight scoring for real-time incremental updates. Only
/// recomputes degree + composite; PageRank/betweenness are deferred
/// until explicit `run_full_scoring` or disconnect.
pub fn run_scoring_incremental(graph: &mut GraphHunter) {
    graph.compute_scores();
    graph.compute_composite_score_hunt_default();
}
