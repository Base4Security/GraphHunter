#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Hypothesis {
    pub name: String,
    pub steps: Vec<HypothesisStep>,
    /// Maximum times a vertex can appear in a path. k=1 = simple path (default).
    #[serde(default = "default_k")]
    pub k_simplicity: usize,
    /// `HAVING` clauses applied after the raw matcher runs. Paths are grouped
    /// by their first node and each group must satisfy every clause or it
    /// is dropped. Empty = no aggregation (backwards-compatible).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aggregations: Vec<AggClause>,
    /// `WITHIN N` clause in seconds — requires every path in a first-node
    /// group to span no more than `window_seconds` between its first and
    /// last edge timestamp. `None` = no window constraint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_seconds: Option<i64>,
    /// Structural connectivity model. See [`HypothesisShape`].
    /// Defaults to `Chain` for backward compatibility.
    #[serde(default)]
    pub shape: HypothesisShape,
}
