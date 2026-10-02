//! Arc costs from event-type rarity.
//!
//! `c_t = 1 + (κ−1) · ln(n_t / n_min) / ln(n_max / n_min)`: the rarest event
//! type costs 1, the commonest costs κ, the rest interpolate on a log
//! scale. Only the *order* "rare = cheap" matters for the optimum (the paper
//! shows κ ∈ {1.5, 3, 6, 12} leaves it unchanged); κ = 3 is the default.

use std::collections::HashMap;

pub const DEFAULT_KAPPA: f64 = 3.0;

/// Per-type cost from per-type counts. Types with a zero count are
/// ignored; when every type has the same count (or there is one type)
/// every cost is 1.
pub fn rarity_costs(counts: &HashMap<String, usize>, kappa: f64) -> HashMap<String, f64> {
    let present: Vec<(&String, usize)> = counts
        .iter()
        .filter(|(_, c)| **c > 0)
        .map(|(k, c)| (k, *c))
        .collect();
    let n_min = present.iter().map(|(_, c)| *c).min().unwrap_or(1) as f64;
    let n_max = present.iter().map(|(_, c)| *c).max().unwrap_or(1) as f64;
    let denom = (n_max / n_min).ln();
    present
        .into_iter()
        .map(|(k, c)| {
            let cost = if denom > 0.0 {
                1.0 + (kappa - 1.0) * (c as f64 / n_min).ln() / denom
            } else {
                1.0
            };
            (k.clone(), cost)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(pairs: &[(&str, usize)]) -> HashMap<String, usize> {
        pairs.iter().map(|(k, c)| (k.to_string(), *c)).collect()
    }

    #[test]
    fn rarest_costs_one_commonest_costs_kappa() {
        let c = rarity_costs(
            &counts(&[("start", 10), ("read", 1000), ("write", 100)]),
            3.0,
        );
        assert!((c["start"] - 1.0).abs() < 1e-12);
        assert!((c["read"] - 3.0).abs() < 1e-12);
        // log-midpoint between 10 and 1000 is 100 → midpoint cost 2.
        assert!((c["write"] - 2.0).abs() < 1e-12);
    }

    #[test]
    fn uniform_counts_cost_one() {
        let c = rarity_costs(&counts(&[("a", 5), ("b", 5)]), 3.0);
        assert_eq!(c["a"], 1.0);
        assert_eq!(c["b"], 1.0);
        let one = rarity_costs(&counts(&[("only", 42)]), 3.0);
        assert_eq!(one["only"], 1.0);
    }

    #[test]
    fn zero_counts_are_ignored() {
        let c = rarity_costs(&counts(&[("a", 0), ("b", 2), ("c", 8)]), 3.0);
        assert!(!c.contains_key("a"));
        assert!((c["b"] - 1.0).abs() < 1e-12);
        assert!((c["c"] - 3.0).abs() < 1e-12);
    }
}
