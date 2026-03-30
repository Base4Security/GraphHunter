use graph_hunter_core::GraphHunter;

/// Maximum relation count before PageRank is skipped in adaptive scoring.
const PAGERANK_RELATION_THRESHOLD: usize = 500_000;

/// Reduced PageRank iteration count used in adaptive scoring.
const ADAPTIVE_PAGERANK_ITERATIONS: usize = 10;

/// Maximum entity count before betweenness centrality is skipped.
const BETWEENNESS_ENTITY_THRESHOLD: usize = 2_000;

/// Betweenness sample size used in adaptive scoring.
const ADAPTIVE_BETWEENNESS_SAMPLE: usize = 200;

/// Runs the full scoring pipeline: degree centrality, temporal PageRank,
/// betweenness centrality, then composite score with equal weights.
pub fn run_full_scoring(graph: &mut GraphHunter) {
    graph.compute_scores();
    graph.compute_temporal_pagerank(None, None, None, None, None);
    graph.compute_betweenness(None);
    graph.compute_composite_score(1.0, 1.0, 1.0);
    graph.finalize_anomaly_scorer();
}

/// Adaptive scoring: skips expensive betweenness for large graphs.
pub fn run_scoring_adaptive(graph: &mut GraphHunter) -> Result<(), String> {
    // Sort edges once so searches can use &self (read lock) instead of &mut self
    graph.sort_edges_by_timestamp().map_err(|e| e.to_string())?;

    let n = graph.entity_count();
    let m = graph.relation_count();
    tracing::info!("SCORING: {} entities, {} relations", n, m);

    // Degree centrality is always fast (O(n))
    graph.compute_scores();

    // PageRank: skip for very large graphs
    if m <= PAGERANK_RELATION_THRESHOLD {
        graph.compute_temporal_pagerank(None, None, Some(ADAPTIVE_PAGERANK_ITERATIONS), None, None);
    } else {
        tracing::info!("SCORING: skipping PageRank ({}M relations)", m / 1_000_000);
    }

    // Betweenness: very expensive O(n*m), only for small graphs
    if n <= BETWEENNESS_ENTITY_THRESHOLD {
        graph.compute_betweenness(Some(ADAPTIVE_BETWEENNESS_SAMPLE));
    } else {
        tracing::info!("SCORING: skipping betweenness ({} entities)", n);
    }

    graph.compute_composite_score(1.0, 1.0, 1.0);
    graph.finalize_anomaly_scorer();
    tracing::info!("SCORING: complete");
    Ok(())
}

/// Lightweight scoring for real-time incremental updates.
/// Only recomputes degree centrality (O(n), always fast) and composite score.
/// Full PageRank/betweenness are deferred until explicit request or disconnect.
pub fn run_scoring_incremental(graph: &mut GraphHunter) {
    graph.compute_scores();
    graph.compute_composite_score(1.0, 1.0, 1.0);
}
