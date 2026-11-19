pub fn enumerate_triangles_naive(
    graph: &GraphHunter,
    trie: &MaterializedCsrTrie,
    ts_map: &MinTimestampMap,
    max_results: usize,
) -> Vec<HuntResult> {
    let mut out: Vec<HuntResult> = Vec::new();
    'outer: for ai in 0..trie.src_keys.len() {
        let a = trie.src_keys[ai];
        let a_sid = StrId::from_raw(a);
        let a_dsts =
            &trie.dst_keys[trie.dst_offsets[ai] as usize..trie.dst_offsets[ai + 1] as usize];
        for &b in a_dsts {
            let b_sid = StrId::from_raw(b);
            let bi = match trie.src_keys.binary_search(&b) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let t_ab = match ts_map.get(trie, ai, b) {
                Some(t) => t,
                None => continue,
            };
            let b_dsts = &trie.dst_keys
                [trie.dst_offsets[bi] as usize..trie.dst_offsets[bi + 1] as usize];
            for &c in b_dsts {
                if a_dsts.binary_search(&c).is_err() {
                    continue;
                }
                let c_sid = StrId::from_raw(c);
                let t_bc = match ts_map.get(trie, bi, c) {
                    Some(t) => t,
                    None => continue,
                };
                if t_bc <= t_ab {
                    continue;
                }
                let t_ac = match ts_map.get(trie, ai, c) {
                    Some(t) => t,
                    None => continue,
                };
                if t_ac <= t_bc {
                    continue;
                }
                out.push(vec![
                    graph.interner.resolve_arc(a_sid),
                    graph.interner.resolve_arc(b_sid),
                    graph.interner.resolve_arc(c_sid),
                ]);
                if out.len() >= max_results {
                    break 'outer;
                }
            }
        }
    }
    out
}
