/// Configuration constants for the graph hunter engine.
///
/// Constants here are either used across multiple modules or are likely
/// to be tuned by operators. Module-private constants live next to their
/// usage instead.

// ── Neighborhood / node-detail query limits ──

/// Maximum edges to scan when computing time ranges for a single node.
pub const MAX_SCAN_EDGES: usize = 50_000;

/// Maximum neighbor entries returned in a node-details response.
pub const MAX_NEIGHBORS_RETURNED: usize = 200;

/// Maximum edges sampled when building the graph-wide time range in summaries.
pub const MAX_SUMMARY_EDGE_SCAN: usize = 100_000;

/// Multiplier applied to `max_nodes` to derive the edge cap in neighborhood queries.
pub const NEIGHBORHOOD_EDGE_RATIO: usize = 10;

// ── Betweenness centrality ──

/// Default number of source nodes sampled for betweenness centrality (Brandes).
pub const DEFAULT_BETWEENNESS_SAMPLE: usize = 500;

// ── Temporal PageRank defaults ──

/// Default exponential decay rate for temporal PageRank.
pub const DEFAULT_PAGERANK_LAMBDA: f64 = 0.001;

/// Default damping factor for temporal PageRank.
pub const DEFAULT_PAGERANK_DAMPING: f64 = 0.85;

/// Default maximum iterations for temporal PageRank convergence.
pub const DEFAULT_PAGERANK_MAX_ITER: usize = 30;

/// Default convergence threshold (epsilon) for temporal PageRank.
pub const DEFAULT_PAGERANK_EPSILON: f64 = 1e-6;

// ── Graph summary ──

/// Number of top-scoring entities shown in the graph summary.
pub const TOP_ANOMALIES_COUNT: usize = 10;

// ── Spill / LRU cache ──

/// Number of nodes whose edge lists are cached in the LRU after finalization.
pub const LRU_CACHE_CAPACITY: usize = 10_000;

/// Default memory budget (bytes) for the spillable edge store (2 GB).
pub const DEFAULT_SPILL_BUDGET: usize = 2 * 1024 * 1024 * 1024;
