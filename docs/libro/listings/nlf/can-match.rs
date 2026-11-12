    #[inline]
    pub fn can_match(&self, sid: StrId, requirement: &[u32; NLF_TYPE_COUNT]) -> bool {
        let counts = self.counts.as_slice();
        let row = match counts.get(sid.index()) {
            Some(r) => r,
            None => return requirement.iter().all(|&c| c == 0),
        };
        for i in 0..NLF_TYPE_COUNT {
            if row[i] < requirement[i] {
                return false;
            }
        }
        true
    }
