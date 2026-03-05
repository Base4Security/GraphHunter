use serde::{Deserialize, Serialize};

use crate::types::{EntityType, RelationType, entity_type_matches};

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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Hypothesis {
    pub name: String,
    pub steps: Vec<HypothesisStep>,
    /// Maximum times a vertex can appear in a path. k=1 = simple path (default).
    #[serde(default = "default_k")]
    pub k_simplicity: usize,
}

impl Hypothesis {
    /// Creates a new empty hypothesis with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            steps: Vec::new(),
            k_simplicity: 1,
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
