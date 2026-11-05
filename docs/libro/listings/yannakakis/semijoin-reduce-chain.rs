pub fn semijoin_reduce_chain(bags: &mut [Bag]) {
    let n = bags.len();
    if n <= 1 {
        return;
    }
    use std::collections::HashSet;

    // Bottom-up pass: each bag[i] keeps only rows whose dest is
    // some origin in bag[i+1].
    for i in (0..n - 1).rev() {
        let live_origins: HashSet<StrId> =
            bags[i + 1].rows.iter().map(|r| r.origin).collect();
        bags[i].rows.retain(|r| live_origins.contains(&r.dest));
    }

    // Top-down pass: each bag[i] keeps only rows whose origin is
    // some dest in bag[i-1].
    for i in 1..n {
        let live_dests: HashSet<StrId> = bags[i - 1].rows.iter().map(|r| r.dest).collect();
        bags[i].rows.retain(|r| live_dests.contains(&r.origin));
    }
}
