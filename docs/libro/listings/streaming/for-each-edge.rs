    pub fn for_each_edge<F>(&self, mut f: F)
    where
        F: FnMut(StrId, &StreamEdge),
    {
        let outer = self.vertices.read();
        for (&src, slot) in outer.iter() {
            let guard = slot.read();
            for edge in guard.as_slice() {
                f(src, edge);
            }
        }
    }
