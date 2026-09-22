pub fn enumerate_4cliques_lftj_simd(
    graph: &GraphHunter,
    trie: &MaterializedCsrTrie,
    ts_map: &MinTimestampMap,
    t_lo: i64,
    t_hi: i64,
    max_results: usize,
) -> Vec<HuntResult> {
    let mut out: Vec<HuntResult> = Vec::new();
    let mut ab_isect: Vec<u32> = Vec::new();
    let mut abc_isect: Vec<u32> = Vec::new();
    'outer: for ai in 0..trie.src_keys.len() {
        let a = trie.src_keys[ai];
        let a_sid = StrId::from_raw(a);
        let a_off = trie.dst_offsets[ai] as usize;
        let a_end = trie.dst_offsets[ai + 1] as usize;
        let a_dsts = &trie.dst_keys[a_off..a_end];
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
            if t_ab < t_lo || t_ab >= t_hi {
                continue;
            }
            let b_off = trie.dst_offsets[bi] as usize;
            let b_end = trie.dst_offsets[bi + 1] as usize;
            let b_dsts = &trie.dst_keys[b_off..b_end];

            ab_isect.clear();
            crate::simd_rust::intersect_sorted_u32_collect(a_dsts, b_dsts, &mut ab_isect);
            if ab_isect.is_empty() {
                continue;
            }

            for c_idx in 0..ab_isect.len() {
                let c = ab_isect[c_idx];
                let ci = match trie.src_keys.binary_search(&c) {
                    Ok(i) => i,
                    Err(_) => continue,
                };
                let t_ac = match ts_map.get(trie, ai, c) {
                    Some(t) => t,
                    None => continue,
                };
                if t_ac <= t_ab {
                    continue;
                }
                let t_bc = match ts_map.get(trie, bi, c) {
                    Some(t) => t,
                    None => continue,
                };
                if t_ac >= t_bc {
                    continue;
                }
                let c_sid = StrId::from_raw(c);
                let c_off = trie.dst_offsets[ci] as usize;
                let c_end = trie.dst_offsets[ci + 1] as usize;
                let c_dsts = &trie.dst_keys[c_off..c_end];

                abc_isect.clear();
                crate::simd_rust::intersect_sorted_u32_collect(
                    &ab_isect[..],
                    c_dsts,
                    &mut abc_isect,
                );

                for &d in abc_isect.iter() {
                    let t_ad = match ts_map.get(trie, ai, d) {
                        Some(t) => t,
                        None => continue,
                    };
                    if t_ad <= t_ac || t_ad >= t_bc {
                        continue;
                    }
                    let t_bd = match ts_map.get(trie, bi, d) {
                        Some(t) => t,
                        None => continue,
                    };
                    if t_bd <= t_bc {
                        continue;
                    }
                    let t_cd = match ts_map.get(trie, ci, d) {
                        Some(t) => t,
                        None => continue,
                    };
                    if t_cd <= t_bd {
                        continue;
                    }
                    let d_sid = StrId::from_raw(d);
                    out.push(vec![
                        graph.interner.resolve_arc(a_sid),
                        graph.interner.resolve_arc(b_sid),
                        graph.interner.resolve_arc(c_sid),
                        graph.interner.resolve_arc(d_sid),
                    ]);
                    if out.len() >= max_results {
                        break 'outer;
                    }
                }
            }
        }
    }
    out
}
