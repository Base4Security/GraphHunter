pub fn gyo_reduce(g: &Hypergraph) -> Option<Vec<usize>> {
    if g.edges.is_empty() {
        return Some(Vec::new());
    }

    let n_edges = g.edges.len();
    let mut alive = vec![true; n_edges];
    let mut order: Vec<usize> = Vec::with_capacity(n_edges);

    loop {
        let alive_edges: Vec<usize> = (0..n_edges).filter(|&i| alive[i]).collect();
        if alive_edges.is_empty() {
            break;
        }

        // Vertex degree count over the alive edges.
        let mut degree: std::collections::HashMap<VarId, usize> =
            std::collections::HashMap::new();
        for &i in &alive_edges {
            let (a, b) = g.edges[i].endpoints();
            *degree.entry(a).or_insert(0) += 1;
            *degree.entry(b).or_insert(0) += 1;
        }

        // Find an "ear": an alive edge with at least one endpoint
        // of degree 1. Pick the smallest step index for
        // determinism.
        let ear = alive_edges.iter().copied().find(|&i| {
            let (a, b) = g.edges[i].endpoints();
            degree.get(&a) == Some(&1) || degree.get(&b) == Some(&1)
        });

        match ear {
            Some(idx) => {
                order.push(idx);
                alive[idx] = false;
            }
            None => return None,
        }
    }

    Some(order)
}
