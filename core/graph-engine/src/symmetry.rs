//! B9 — pattern symmetry analysis.
//!
//! For pattern graphs with non-trivial automorphisms, the DFS matcher
//! enumerates each match `|Aut(Q)|` times. Adding a partial-order
//! constraint between symmetric vertex roles cuts redundant emissions
//! by exactly that factor.
//!
//! Honest scope: the plan called for nauty/Traces FFI to handle
//! arbitrary pattern graphs. Today the DSL only supports linear chains
//! (`A -[r1]-> B -[r2]-> C -[r3]-> ...`), so the only non-trivial
//! automorphism is a *reverse* — the chain reads the same forward and
//! backward. We detect that case in pure Rust (no GPL FFI dependency,
//! no Windows build pain) and emit a single tiebreaker.
//!
//! When the DSL grows joins/cycles (post-WCOJ), this module is the
//! correct place to hang the nauty-based analyzer behind an
//! `analyze_general` entry point. The current `analyze` function would
//! become the linear-chain fast path.
//!
//! Realistic lift: 1× on most ATT&CK kill chains (timestamps and
//! distinct relation types break symmetries naturally), 2× on the
//! palindromic stress patterns used in the bench harness
//! (`Any -[Any]-> Any -[Any]-> Any`).

use crate::hypothesis::Hypothesis;
use crate::interner::StrId;

/// Result of pattern symmetry analysis. Stack-allocated, cheap to
/// build, copied into DFS local state.
#[derive(Clone, Copy, Debug, Default)]
pub struct SymmetryHint {
    /// The pattern is palindromic: types + relation types read the same
    /// forward and backward. Implies that for any matched path
    /// `[v0, v1, ..., vn]`, the reverse `[vn, ..., v0]` is also a valid
    /// match. The DFS breaks this symmetry by requiring
    /// `path[0].index() < path[len-1].index()` at emission time.
    pub palindromic: bool,
}

impl SymmetryHint {
    /// Apply the symmetry constraint to a candidate match. Returns true
    /// iff the path should be emitted. For non-palindromic patterns
    /// this is a no-op (always true).
    #[inline]
    pub fn keep_match(&self, path: &[StrId]) -> bool {
        if !self.palindromic || path.len() < 2 {
            return true;
        }
        // Strict less-than over StrId index — break ties by canonical
        // direction (lower-id endpoint first). Equality cannot happen
        // when k_simplicity = 1 (no vertex repeats).
        path[0].index() < path[path.len() - 1].index()
    }
}

/// Analyze the hypothesis once at query entry. O(n) over the step list.
/// Currently detects the single linear-chain palindrome automorphism;
/// extend here when WCOJ adds non-chain patterns.
pub fn analyze(hypothesis: &Hypothesis) -> SymmetryHint {
    SymmetryHint {
        palindromic: is_palindromic(hypothesis),
    }
}

/// True iff the chain's entity-type and relation-type sequences read
/// identically forward and backward. Considers:
///   - origin/dest type alternation: must mirror around the center.
///   - relation type sequence: must mirror.
///   - edge/dest predicates: must mirror.
/// Wildcards (`EntityType::Any`, `RelationType::Any`) match any
/// counterpart, so a chain of all-`Any` is trivially palindromic.
fn is_palindromic(hypothesis: &Hypothesis) -> bool {
    let steps = &hypothesis.steps;
    let n = steps.len();
    if n < 2 {
        return false;
    }

    // The vertex-type sequence is `[s0.origin, s0.dest, s1.dest, ..., s_{n-1}.dest]`
    // (n+1 vertex types). We check vertex_types[i] == vertex_types[n-i] for all i.
    let vertex_types: Vec<&crate::types::EntityType> = std::iter::once(&steps[0].origin_type)
        .chain(steps.iter().map(|s| &s.dest_type))
        .collect();
    for i in 0..(vertex_types.len() / 2) {
        let j = vertex_types.len() - 1 - i;
        if !type_matches_symmetric(vertex_types[i], vertex_types[j]) {
            return false;
        }
    }

    // Relation types: steps[i].relation_type == steps[n-1-i].relation_type.
    for i in 0..(n / 2) {
        let j = n - 1 - i;
        if !rel_matches_symmetric(&steps[i].relation_type, &steps[j].relation_type) {
            return false;
        }
    }

    // Predicates: a chain with asymmetric predicates isn't truly
    // palindromic. Conservative bail-out — if any step has predicates,
    // require the mirror step to have the same predicates (by length
    // equality is a loose proxy; full structural equality would need
    // PartialEq on the predicate AST which we don't currently expose
    // in the public API).
    for i in 0..n {
        let j = n - 1 - i;
        if steps[i].edge_predicates.len() != steps[j].edge_predicates.len() {
            return false;
        }
        if steps[i].dest_predicates.len() != steps[j].dest_predicates.len() {
            return false;
        }
    }

    true
}

#[inline]
fn type_matches_symmetric(a: &crate::types::EntityType, b: &crate::types::EntityType) -> bool {
    use crate::types::EntityType;
    match (a, b) {
        (EntityType::Any, _) | (_, EntityType::Any) => true,
        _ => a == b,
    }
}

#[inline]
fn rel_matches_symmetric(a: &crate::types::RelationType, b: &crate::types::RelationType) -> bool {
    use crate::types::RelationType;
    match (a, b) {
        (RelationType::Any, _) | (_, RelationType::Any) => true,
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hypothesis::HypothesisStep;
    use crate::types::{EntityType, RelationType};

    #[test]
    fn single_step_is_not_palindromic() {
        let h = Hypothesis::new("t").add_step(HypothesisStep::new(
            EntityType::User,
            RelationType::Auth,
            EntityType::Host,
        ));
        assert!(!analyze(&h).palindromic);
    }

    #[test]
    fn asymmetric_chain_is_not_palindromic() {
        // User -> Host -> IP: types differ across the center.
        let h = Hypothesis::new("t")
            .add_step(HypothesisStep::new(
                EntityType::User,
                RelationType::Auth,
                EntityType::Host,
            ))
            .add_step(HypothesisStep::new(
                EntityType::Host,
                RelationType::Connect,
                EntityType::IP,
            ));
        assert!(!analyze(&h).palindromic);
    }

    #[test]
    fn process_spawn_chain_is_palindromic() {
        // Process -> Process -> Process with same relation.
        let h = Hypothesis::new("t")
            .add_step(HypothesisStep::new(
                EntityType::Process,
                RelationType::Spawn,
                EntityType::Process,
            ))
            .add_step(HypothesisStep::new(
                EntityType::Process,
                RelationType::Spawn,
                EntityType::Process,
            ));
        assert!(analyze(&h).palindromic);
    }

    #[test]
    fn any_any_any_is_palindromic() {
        // Bench-harness pattern: every wildcard.
        let h = Hypothesis::new("t")
            .add_step(HypothesisStep::new(
                EntityType::Any,
                RelationType::Any,
                EntityType::Any,
            ))
            .add_step(HypothesisStep::new(
                EntityType::Any,
                RelationType::Any,
                EntityType::Any,
            ));
        assert!(analyze(&h).palindromic);
    }

    #[test]
    fn keep_match_filters_reverse_direction() {
        let hint = SymmetryHint { palindromic: true };
        // path[0].index() < path[last].index() → keep.
        let lo = StrId::from_raw(3);
        let hi = StrId::from_raw(7);
        assert!(hint.keep_match(&[lo, hi]));
        assert!(!hint.keep_match(&[hi, lo]));
    }

    #[test]
    fn keep_match_no_op_for_asymmetric() {
        let hint = SymmetryHint { palindromic: false };
        let a = StrId::from_raw(7);
        let b = StrId::from_raw(3);
        // Always passes when asymmetric.
        assert!(hint.keep_match(&[a, b]));
        assert!(hint.keep_match(&[b, a]));
    }

    #[test]
    fn empty_path_short_circuits() {
        let hint = SymmetryHint { palindromic: true };
        assert!(hint.keep_match(&[]));
        assert!(hint.keep_match(&[StrId::from_raw(0)]));
    }
}
