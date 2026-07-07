//! Analytics operations: heatmap, timeline, centrality, compaction.
//!
//! Read-only methods use [`GraphHunterApi::with_graph_read`]; the three
//! centrality / score ops mutate entity score fields so they go through
//! [`GraphHunterApi::with_graph_write`]. `compact_before` also mutates.

use graph_hunter_core::CompactionStats;

use crate::dto::analytics::{
    CompactRequest, ComputeBetweennessRequest, ComputeCompositeScoresRequest,
    ComputePagerankRequest, HeatmapRow, TemporalHeatmapRequest, TimelineDataRequest, TimelineRow,
};
use crate::{ApiError, ApiResult, GraphHunterApi};

impl GraphHunterApi {
    pub fn get_temporal_heatmap(&self, req: TemporalHeatmapRequest) -> ApiResult<Vec<HeatmapRow>> {
        self.with_graph_read(req.session.as_ref(), |graph| {
            Ok(graph
                .temporal_heatmap(req.bucket_size_seconds)
                .into_iter()
                .map(|(relation_type, bins, bucket_size_seconds)| HeatmapRow {
                    relation_type,
                    bins,
                    bucket_size_seconds,
                })
                .collect())
        })
    }

    pub fn get_timeline_data(&self, req: TimelineDataRequest) -> ApiResult<Vec<TimelineRow>> {
        self.with_graph_read(req.session.as_ref(), |graph| {
            Ok(graph
                .timeline_data()
                .into_iter()
                .map(|(entity_type, min_time, max_time, bins)| TimelineRow {
                    entity_type,
                    min_time,
                    max_time,
                    bins,
                })
                .collect())
        })
    }

    /// Compute betweenness centrality (Brandes algorithm). Writes into
    /// each entity's `betweenness` field; blocks reads for the duration.
    pub fn compute_betweenness(&self, req: ComputeBetweennessRequest) -> ApiResult<()> {
        self.with_graph_write(req.session.as_ref(), |g| {
            g.compute_betweenness(req.sample_limit);
            Ok(())
        })
    }

    /// Temporal PageRank with exponential decay.
    pub fn compute_pagerank(&self, req: ComputePagerankRequest) -> ApiResult<()> {
        self.with_graph_write(req.session.as_ref(), |g| {
            g.compute_temporal_pagerank(
                req.lambda,
                req.damping,
                req.max_iter,
                None,
                req.reference_time,
            );
            Ok(())
        })
    }

    /// Weighted combination of degree, pagerank, and betweenness.
    pub fn compute_composite_scores(&self, req: ComputeCompositeScoresRequest) -> ApiResult<()> {
        self.with_graph_write(req.session.as_ref(), |g| {
            g.compute_composite_score(
                req.degree_weight,
                req.pagerank_weight,
                req.betweenness_weight,
                req.rarity_weight,
            );
            Ok(())
        })
    }

    /// Compact old edges before a cutoff timestamp to reclaim memory.
    pub fn compact(&self, req: CompactRequest) -> ApiResult<CompactionStats> {
        self.with_graph_write(req.session.as_ref(), |g| {
            g.compact_before(req.cutoff_timestamp)
                .map_err(|e| ApiError::Internal(e.to_string()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Session;
    use graph_hunter_core::GraphHunter;
    use std::sync::Arc;

    fn api_with_empty_session() -> GraphHunterApi {
        let api = GraphHunterApi::new_noop();
        let s = Arc::new(Session::new("s1", "t", GraphHunter::new(), 0));
        api.sessions().insert(s);
        api.sessions().set_current(Some("s1".into()));
        api
    }

    #[test]
    fn heatmap_empty() {
        let api = api_with_empty_session();
        let rows = api
            .get_temporal_heatmap(TemporalHeatmapRequest::default())
            .unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn timeline_empty() {
        let api = api_with_empty_session();
        let rows = api
            .get_timeline_data(TimelineDataRequest::default())
            .unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn compute_betweenness_empty_ok() {
        let api = api_with_empty_session();
        api.compute_betweenness(ComputeBetweennessRequest::default())
            .unwrap();
    }
}
