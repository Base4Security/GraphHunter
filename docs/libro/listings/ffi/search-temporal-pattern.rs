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
