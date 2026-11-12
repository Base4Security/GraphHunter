    pub fn build(graph: &crate::graph::GraphHunter) -> Self {
        let n = graph.entity_type_tags.len();
        let counts = crate::index_storage::IndexBacking::build_with_writer(
            n,
            [0u32; NLF_TYPE_COUNT],
            |counts| {
                for sid in graph.entities.keys().copied() {
                    let s_idx = sid.index();
                    if s_idx >= counts.len() {
                        continue;
                    }
                    let arc = match graph.streaming.neighbors_arc(sid) {
                        Some(a) => a,
                        None => continue,
                    };
                    let guard = arc.read();
                    for edge in guard.as_slice() {
                        let dst_idx = edge.dest_sid.index();
                        let tag = match graph.entity_type_tags.get(dst_idx) {
                            Some(&t) => t,
                            None => continue,
                        };
                        if (tag as usize) < NLF_TYPE_COUNT {
                            let row = &mut counts[s_idx];
                            row[tag as usize] = row[tag as usize].saturating_add(1);
                        }
                    }
                }
            },
        )
        .expect("temp file for NLF index");
        Self { counts }
    }
