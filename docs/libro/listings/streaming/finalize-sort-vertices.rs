    pub fn finalize(&self) {
        let outer = self
            .vertices
            .read();
        for slot in outer.values() {
            let mut guard = slot.write();
            match &mut *guard {
                NeighborList::Inline(sv) => sv.sort_unstable_by_key(|e| e.timestamp),
                NeighborList::Vec(v) => v.sort_unstable_by_key(|e| e.timestamp),
                // Already spilled; the file is sorted by construction
                // (consolidate writes runs in their current order, and
                // production today calls finalize() before consolidate()).
                NeighborList::Mmap { .. } => {}
            }
        }
    }
