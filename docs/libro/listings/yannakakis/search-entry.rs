pub fn search_temporal_pattern_yannakakis(
    graph: &GraphHunter,
    hypothesis: &Hypothesis,
    time_window: Option<(i64, i64)>,
    max_results: Option<usize>,
) -> (Vec<HuntResult>, bool) {
    let cap = max_results.unwrap_or(10_000);
    let n = hypothesis.steps.len();
    if n == 0 || cap == 0 {
        return (Vec::new(), false);
    }
    let (t_lo, t_hi) = time_window.unwrap_or((i64::MIN, i64::MAX));
    let bags: Vec<Bag> = hypothesis
        .steps
        .iter()
        .map(|step| materialize_bag(graph, step, t_lo, t_hi))
        .collect();
    search_temporal_pattern_yannakakis_with_bags(graph, hypothesis, bags, max_results)
}
