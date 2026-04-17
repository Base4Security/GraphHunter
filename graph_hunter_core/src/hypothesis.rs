use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::{EntityType, RelationType, entity_type_matches};

/// A filter on edge (or dest-node) metadata that must hold for a
/// `HypothesisStep` to match. Evaluated by the non-SIMD DFS path — the
/// SIMD engine does not carry metadata through FFI yet, so any hypothesis
/// carrying predicates transparently falls back to the non-SIMD matcher.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "op", content = "arg")]
pub enum Predicate {
    /// `key = "value"` — exact string equality (case-sensitive).
    Eq { key: String, value: String },
    /// `key != "value"`
    Neq { key: String, value: String },
    /// `key ~ "value"` — case-insensitive substring.
    Match { key: String, value: String },
    /// `key in ["a", "b", "c"]`
    In { key: String, values: Vec<String> },
    /// `key not in ["a", "b"]`
    NotIn { key: String, values: Vec<String> },
}

impl Predicate {
    /// Evaluates this predicate against an edge/node metadata map.
    /// A missing key is treated as non-matching for positive ops and
    /// as matching for negative ops (`Neq`, `NotIn`) — this is what
    /// analysts expect when filtering SIEM data, where the absence of a
    /// field usually means "not the value we're filtering against".
    pub fn eval(&self, metadata: &HashMap<String, String>) -> bool {
        match self {
            Predicate::Eq { key, value } => metadata.get(key).map(|v| v == value).unwrap_or(false),
            Predicate::Neq { key, value } => metadata.get(key).map(|v| v != value).unwrap_or(true),
            Predicate::Match { key, value } => {
                let needle = value.to_ascii_lowercase();
                metadata
                    .get(key)
                    .map(|v| v.to_ascii_lowercase().contains(&needle))
                    .unwrap_or(false)
            }
            Predicate::In { key, values } => metadata
                .get(key)
                .map(|v| values.iter().any(|x| x == v))
                .unwrap_or(false),
            Predicate::NotIn { key, values } => metadata
                .get(key)
                .map(|v| values.iter().all(|x| x != v))
                .unwrap_or(true),
        }
    }
}

/// Returns `true` if *every* predicate in `preds` holds for `metadata`.
/// Empty slice is vacuously true — preserves old behavior for callers
/// that don't know about predicates.
pub fn all_predicates_match(preds: &[Predicate], metadata: &HashMap<String, String>) -> bool {
    preds.iter().all(|p| p.eval(metadata))
}

/// A single step in a threat hunting hypothesis.
///
/// Describes an expected transition: an entity of `origin_type` connects
/// via `relation_type` to an entity of `dest_type`.
///
/// Example: `IP -[Connect]-> Host` represents a network connection step.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HypothesisStep {
    pub origin_type: EntityType,
    pub relation_type: RelationType,
    pub dest_type: EntityType,
    /// Optional predicates that the edge's metadata must satisfy.
    /// Backwards-compat: defaults to empty on deserialize.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edge_predicates: Vec<Predicate>,
    /// Optional predicates that the DESTINATION entity's metadata must
    /// satisfy. Written in DSL as `Process {name~"certutil"}`. LOLBAS and
    /// EDR-tampering catalog entries rely on this.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dest_predicates: Vec<Predicate>,
    /// Optional variable binding on the ORIGIN node position, e.g. the
    /// `u` in `User u -[Auth]-> IP`. Used by HAVING aggregations to refer
    /// to a specific step unambiguously when the same entity type appears
    /// at multiple positions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_binding: Option<String>,
    /// Optional variable binding on the DESTINATION node position.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dest_binding: Option<String>,
}

impl HypothesisStep {
    pub fn new(
        origin_type: EntityType,
        relation_type: RelationType,
        dest_type: EntityType,
    ) -> Self {
        Self {
            origin_type,
            relation_type,
            dest_type,
            edge_predicates: Vec::new(),
            dest_predicates: Vec::new(),
            origin_binding: None,
            dest_binding: None,
        }
    }

    /// Same as `new` but with an explicit predicate vector — useful for
    /// tests and for the DSL parser.
    pub fn with_predicates(
        origin_type: EntityType,
        relation_type: RelationType,
        dest_type: EntityType,
        edge_predicates: Vec<Predicate>,
    ) -> Self {
        Self {
            origin_type,
            relation_type,
            dest_type,
            edge_predicates,
            dest_predicates: Vec::new(),
            origin_binding: None,
            dest_binding: None,
        }
    }

    pub fn with_all_predicates(
        origin_type: EntityType,
        relation_type: RelationType,
        dest_type: EntityType,
        edge_predicates: Vec<Predicate>,
        dest_predicates: Vec<Predicate>,
    ) -> Self {
        Self {
            origin_type,
            relation_type,
            dest_type,
            edge_predicates,
            dest_predicates,
            origin_binding: None,
            dest_binding: None,
        }
    }
}

/// A threat hunting hypothesis expressed as an ordered sequence of steps.
///
/// The hypothesis represents an attack pattern to search for in the graph.
/// Each step must be temporally ordered (causal monotonicity):
/// the timestamp of step N+1 must be >= the timestamp of step N.
///
/// Example lateral movement hypothesis:
/// ```text
/// IP -[Connect]-> Host -[Auth]-> User -[Execute]-> Process -[Write]-> File
/// ```
fn default_k() -> usize { 1 }

/// Which path position to pull values from for aggregation.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub enum AggColumn {
    #[default]
    /// The first node of the path (the anchor — e.g. `User` in a
    /// `User -[Auth]-> IP` hunt).
    First,
    /// The last node of the path (e.g. `IP` in the same hunt —
    /// the "distinct target" count).
    Last,
    /// A named binding (e.g. `u` in `User u -[Auth]-> IP i`). The
    /// resolver walks the hypothesis steps looking for a matching
    /// origin_binding or dest_binding at plan time.
    Named(String),
}

/// A `HAVING count(distinct <col>) <op> <N>` clause.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AggClause {
    /// Which column to count distinct values of.
    pub column: AggColumn,
    /// Required count — interpreted as `count(distinct) >= threshold`.
    pub min_distinct: usize,
}

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
}

impl Hypothesis {
    /// Creates a new empty hypothesis with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            steps: Vec::new(),
            k_simplicity: 1,
            aggregations: Vec::new(),
            window_seconds: None,
        }
    }

    /// Sets the k-simplicity parameter (max vertex visits in a path).
    pub fn with_k_simplicity(mut self, k: usize) -> Self {
        self.k_simplicity = k;
        self
    }

    /// Appends a step to the hypothesis, returning self for builder-pattern chaining.
    pub fn add_step(mut self, step: HypothesisStep) -> Self {
        self.steps.push(step);
        self
    }

    /// Returns the number of steps in the hypothesis.
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Returns true if the hypothesis has no steps.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Validates that consecutive steps have matching entity types
    /// (the dest_type of step N must match the origin_type of step N+1).
    pub fn validate(&self) -> Result<(), String> {
        if self.steps.is_empty() {
            return Err("Hypothesis must have at least one step".into());
        }

        for window in self.steps.windows(2) {
            let current = &window[0];
            let next = &window[1];
            // Allow wildcard (Any) to match any type in chain validation
            if !entity_type_matches(&current.dest_type, &next.origin_type)
                && !entity_type_matches(&next.origin_type, &current.dest_type)
            {
                return Err(format!(
                    "Type mismatch: step ends with {} but next step starts with {}",
                    current.dest_type, next.origin_type
                ));
            }
        }

        Ok(())
    }
}
