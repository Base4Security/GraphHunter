//! Thin Rust forwarder kept for API stability.
//!
//! This crate previously bridged to the C++ `libgraphmatch` static
//! library and exposed `build_gm_graph` / `run_simd_search` plus the
//! RAII handle types (`GmGraph`, `GmMatcher`, `GmResults`). The C++
//! tree was removed because the pure-Rust DFS in `graph_hunter_core`
//! out-performed it by 3-25× on every measured workload (see
//! `docs/perf/2026-05-07-pre-libgraphmatch-removal.md`).
//!
//! Only `search_temporal_pattern_simd` survives, now as a one-line
//! delegate to the engine. The crate is a candidate for deletion
//! once downstream callers (`platform/api`) drop the dependency.

use graph_hunter_core::errors::GraphError;
use graph_hunter_core::graph::{GraphHunter, HuntResult};
use graph_hunter_core::hypothesis::Hypothesis;

/// Temporal pattern search. Delegates to the engine's
/// `search_temporal_pattern_smart` when an anomaly scorer has been
/// finalized, otherwise to `search_temporal_pattern`.
pub fn search_temporal_pattern_simd(
    hunter: &GraphHunter,
    hypothesis: &Hypothesis,
    time_window: Option<(i64, i64)>,
    max_results: Option<usize>,
) -> Result<(Vec<HuntResult>, bool), GraphError> {
    let scorer_ready = hunter
        .anomaly_scorer
        .as_ref()
        .map(|s| s.is_finalized())
        .unwrap_or(false);
    if scorer_ready {
        let cap = max_results.unwrap_or(10_000);
        hunter.search_temporal_pattern_smart(hypothesis, time_window, cap)
    } else {
        hunter.search_temporal_pattern(hypothesis, time_window, max_results)
    }
}
