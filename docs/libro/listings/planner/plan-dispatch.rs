pub fn plan(hypothesis: &Hypothesis) -> DispatchPlan {
    if triangle_name_marker_dispatch(hypothesis) {
        return DispatchPlan::TriangleLftj;
    }
    if triangle_structural_dispatch(hypothesis) {
        return DispatchPlan::TriangleLftj;
    }
    // C6 must dispatch *before* K4 — both shapes have exactly 6
    // homogeneous steps, but a user marking the hypothesis with
    // `6-cycle` / `c6-cycle` wants the cycle path, not the clique.
    // Only the name marker disambiguates; the structural route
    // (6 homogeneous steps) defaults to K4 below.
    if c6_name_marker_dispatch(hypothesis) {
        return DispatchPlan::C6Lftj;
    }
    if k5_name_marker_dispatch(hypothesis) {
        return DispatchPlan::K5Lftj;
    }
    if k5_structural_dispatch(hypothesis) {
        return DispatchPlan::K5Lftj;
    }
    if name_marker_dispatch(hypothesis) {
        return DispatchPlan::K4Lftj;
    }
    if structural_dispatch(hypothesis) {
        return DispatchPlan::K4Lftj;
    }
    if yannakakis_dispatch(hypothesis) {
        return DispatchPlan::Yannakakis;
    }
    DispatchPlan::DfsMatch
}
