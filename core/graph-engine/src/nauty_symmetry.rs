//! M3 — pattern-graph automorphism analysis via nauty/Traces FFI.
//!
//! B9 (`crate::symmetry`) covers the linear-chain palindrome case in
//! pure Rust. M3 generalizes the symmetry analyzer to arbitrary
//! pattern graphs by delegating to nauty's `densenauty` routine when
//! the build target supports it. The result is a list of orbit-based
//! partial-order constraints (`f(u_i) < f(u_j)`) the matcher can
//! enforce as O(1) emission predicates, cutting redundant matches by
//! `|Aut(Q)|`.
//!
//! Build-time gating
//! -----------------
//! nauty is written for POSIX and includes `<unistd.h>` unconditionally;
//! that breaks MSVC. The crate is therefore target-gated to `cfg(unix)`
//! in `Cargo.toml`, and this module's FFI entry point is feature- and
//! target-gated below. Windows builds (and any non-feature build) get
//! a no-op stub that returns an empty constraint list. Callers must
//! treat M3 as advisory: a missing constraint costs a perf factor of
//! `|Aut|`, never correctness.
//!
//! Today's value
//! -------------
//! The DSL only emits linear chains, whose automorphism group has
//! order ≤ 2 (identity + reverse, when palindromic). For those, B9's
//! pure-Rust detector produces the same constraint nauty would. M3 is
//! infrastructure for **L1/L2**: when the DSL grows clique/cycle/star
//! shapes, the LFTJ enumerators we already have for K4/K5/C6 can
//! consume orbit constraints to prune symmetric tuples. The plan
//! document (`docs/perf/latex/cambios-perf-2026-04.tex`, M3 chapter)
//! tracks this dependency.
//!
//! Honest scope of this commit
//! ---------------------------
//! - The FFI plumbing is in place and tested on Linux/macOS.
//! - `compute_orbit_constraints` is a pure function: pattern
//!   adjacency in, constraints out. No coupling to `Hypothesis` yet —
//!   that mapping happens in L1 once the DSL emits non-chain graphs.
//! - Nothing in the matcher hot path consults this module today.

/// A partial-order constraint between two pattern-vertex roles.
/// `lo` and `ro` are indices into the pattern's vertex list; the
/// matcher enforces `match[lo].index() < match[ro].index()` at
/// emission time, breaking one direction of an orbit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrbitConstraint {
    pub lo: usize,
    pub ro: usize,
}

/// True iff this build was compiled with `symmetry-nauty` feature on
/// a `unix` target. Callers can branch on this for diagnostics; the
/// constraint computation falls back gracefully regardless.
pub const HAS_NAUTY: bool = cfg!(all(unix, feature = "symmetry-nauty"));

/// Compute orbit-based partial-order constraints for an undirected
/// pattern graph given by its adjacency-matrix view.
///
/// `n` is the number of pattern vertices. `edges` is a list of
/// `(u, v)` pairs with `u, v < n` and `u != v`; pairs are treated as
/// undirected (duplicate `(v, u)` is harmless). Returns a vector of
/// `OrbitConstraint`s suitable for the matcher's emission predicate.
///
/// Behavior on builds without nauty support:
///   - Returns an empty `Vec` (no constraints).
///   - Documented as a soundness-preserving no-op: the matcher will
///     emit |Aut|× more matches but each match is still correct.
///
/// Behavior with nauty support:
///   - Calls `densenauty` with `getcanon=TRUE` to obtain the
///     canonical labelling and the orbit partition.
///   - For each orbit of size `k ≥ 2`, emits a **chain** of `k-1`
///     constraints `v_0 < v_1 < … < v_{k-1}` where `v_i` are the
///     orbit members in ascending vertex-index order.
///   - The total number of constraints is `n - num_orbits`, the
///     classical Grochow-Kellis (RECOMB 2007) bound on
///     symmetry-breaking constraints needed to enumerate each match
///     exactly once.
///
/// Why chain, not star?
/// --------------------
/// A "star" encoding (`rep < x` for every non-rep `x` in the orbit)
/// also has `n - num_orbits` constraints, but only fixes the
/// representative's image — the remaining `(k-1)!` permutations
/// among the non-reps still satisfy the predicate. For K_4 with
/// |Aut|=24 the star cuts emission by a factor of 4 (fixing one
/// vertex) instead of the full 24. The chain enforces a unique
/// ordering across the whole orbit and recovers the |Aut|× cut.
pub fn compute_orbit_constraints(n: usize, edges: &[(usize, usize)]) -> Vec<OrbitConstraint> {
    nauty_impl::compute(n, edges)
}

#[cfg(all(unix, feature = "symmetry-nauty"))]
mod nauty_impl {
    use super::OrbitConstraint;
    use nauty_Traces_sys::{
        ADDONEEDGE, SETWORDSNEEDED, densenauty, empty_graph, optionblk, statsblk,
    };
    use std::os::raw::c_int;

    pub fn compute(n: usize, edges: &[(usize, usize)]) -> Vec<OrbitConstraint> {
        if n == 0 {
            return Vec::new();
        }
        let m = SETWORDSNEEDED(n);
        let mut options = optionblk::default();
        options.getcanon = 1;
        let mut stats = statsblk::default();

        let mut lab = vec![0i32; n];
        let mut ptn = vec![0i32; n];
        let mut orbits = vec![0i32; n];

        let mut g = empty_graph(m, n);
        for &(u, v) in edges {
            debug_assert!(u < n && v < n && u != v, "out-of-range or self-loop edge");
            ADDONEEDGE(&mut g, u, v, m);
        }

        // SAFETY: all buffers are sized correctly for `n` and `m`; the
        // nauty C routine only writes within their bounds. `options`
        // and `stats` are exclusively borrowed for the duration of
        // the call. The graph buffer `g` is constructed via
        // `empty_graph` and mutated through `ADDONEEDGE` from the
        // crate, so its layout matches `densenauty`'s expectation.
        unsafe {
            densenauty(
                g.as_mut_ptr(),
                lab.as_mut_ptr(),
                ptn.as_mut_ptr(),
                orbits.as_mut_ptr(),
                &mut options,
                &mut stats,
                m as c_int,
                n as c_int,
                std::ptr::null_mut(),
            );
        }

        // `orbits[i]` holds the representative vertex of the orbit
        // containing `i`. Bucket vertices by representative, then
        // within each bucket of size k emit a chain of k-1 strict-less
        // constraints between consecutive members in ascending order.
        // The chain (rather than star) is what fully canonicalises an
        // orbit — see the function-level docstring for the K_4 example.
        let mut buckets: std::collections::BTreeMap<usize, Vec<usize>> =
            std::collections::BTreeMap::new();
        for i in 0..n {
            let rep = orbits[i] as usize;
            buckets.entry(rep).or_default().push(i);
        }
        let mut constraints = Vec::new();
        for members in buckets.values() {
            // BTreeMap iteration order is by key, but bucket members
            // were appended in order of `i` (already ascending), so we
            // can chain directly without re-sorting.
            for w in members.windows(2) {
                constraints.push(OrbitConstraint { lo: w[0], ro: w[1] });
            }
        }
        constraints
    }
}

#[cfg(not(all(unix, feature = "symmetry-nauty")))]
mod nauty_impl {
    use super::OrbitConstraint;

    pub fn compute(_n: usize, _edges: &[(usize, usize)]) -> Vec<OrbitConstraint> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_graph_has_no_constraints() {
        assert!(compute_orbit_constraints(0, &[]).is_empty());
    }

    #[test]
    fn single_vertex_has_no_constraints() {
        assert!(compute_orbit_constraints(1, &[]).is_empty());
    }

    #[test]
    fn windows_or_no_feature_returns_empty() {
        // The 4-cycle has |Aut|=8 with two orbits of size 4 each.
        // Without nauty support this is a no-op fallback.
        let edges = [(0, 1), (1, 2), (2, 3), (3, 0)];
        let cs = compute_orbit_constraints(4, &edges);
        if !HAS_NAUTY {
            assert!(cs.is_empty(), "stub must return empty when nauty absent");
        }
    }

    #[cfg(all(unix, feature = "symmetry-nauty"))]
    fn pairs(cs: &[OrbitConstraint]) -> Vec<(usize, usize)> {
        let mut p: Vec<(usize, usize)> = cs.iter().map(|c| (c.lo, c.ro)).collect();
        p.sort();
        p
    }

    #[cfg(all(unix, feature = "symmetry-nauty"))]
    #[test]
    fn cycle_4_emits_chain_within_orbit() {
        // C_4 has one orbit (all 4 vertices). The chain encoding is
        // 0<1, 1<2, 2<3 — three constraints that fix the labelling
        // uniquely (the 8 D_4 automorphisms collapse to identity).
        let edges = [(0, 1), (1, 2), (2, 3), (3, 0)];
        let cs = compute_orbit_constraints(4, &edges);
        assert_eq!(pairs(&cs), vec![(0, 1), (1, 2), (2, 3)]);
    }

    #[cfg(all(unix, feature = "symmetry-nauty"))]
    #[test]
    fn k_4_emits_chain_within_orbit() {
        // K_4: |Aut|=24, one orbit {0,1,2,3}. Chain 0<1<2<3 fully
        // canonicalises (the 24 S_4 permutations collapse to identity).
        // The earlier star encoding (0<1, 0<2, 0<3) only fixed vertex 0
        // and left (k-1)! = 6 permutations of {1,2,3} satisfying the
        // predicate — a 4× cut instead of the full 24×.
        let mut edges = Vec::new();
        for u in 0..4 {
            for v in (u + 1)..4 {
                edges.push((u, v));
            }
        }
        let cs = compute_orbit_constraints(4, &edges);
        assert_eq!(pairs(&cs), vec![(0, 1), (1, 2), (2, 3)]);
    }

    #[cfg(all(unix, feature = "symmetry-nauty"))]
    #[test]
    fn path_4_emits_one_chain_per_orbit() {
        // P_4 has two orbits under reversal: {0,3} and {1,2}. Each
        // contributes one chain edge, total 2 constraints.
        let edges = [(0, 1), (1, 2), (2, 3)];
        let cs = compute_orbit_constraints(4, &edges);
        let p = pairs(&cs);
        assert_eq!(p.len(), 2);
        // Both expected pairs must appear; order between buckets is
        // BTreeMap-stable (by orbit-rep ascending) but we sort here
        // to keep the assertion robust.
        assert!(p.contains(&(0, 3)));
        assert!(p.contains(&(1, 2)));
    }

    #[cfg(all(unix, feature = "symmetry-nauty"))]
    #[test]
    fn k_5_emits_chain_within_orbit() {
        // K_5: |Aut|=120, one orbit {0..5}. Chain 0<1<2<3<4 → 4
        // constraints. Star would give (0,1)(0,2)(0,3)(0,4), same
        // count but only fixes vertex 0; 4! = 24 permutations of
        // {1..4} would still satisfy.
        let mut edges = Vec::new();
        for u in 0..5 {
            for v in (u + 1)..5 {
                edges.push((u, v));
            }
        }
        let cs = compute_orbit_constraints(5, &edges);
        assert_eq!(pairs(&cs), vec![(0, 1), (1, 2), (2, 3), (3, 4)]);
    }
}
