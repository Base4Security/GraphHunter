    pub fn try_record_edge(&mut self, src_sid: StrId, dst_tag: u8) -> bool {
        let tag = dst_tag as usize;
        if tag >= NLF_TYPE_COUNT {
            // Out-of-range tag has no NLF slot — treat as a no-op
            // success (no rebuild needed).
            return true;
        }
        let counts = match self.counts.heap_slice_mut() {
            Some(s) => s,
            None => return false,
        };
        if let Some(row) = counts.get_mut(src_sid.index()) {
            row[tag] = row[tag].saturating_add(1);
        }
        true
    }
