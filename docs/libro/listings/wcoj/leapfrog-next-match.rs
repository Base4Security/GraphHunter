    pub fn next_match(&mut self) -> Option<u64> {
        if self.done {
            return None;
        }
        let k = self.iters.len();
        loop {
            // After sort_order, iters[order[0]] has the smallest key,
            // iters[order[k-1]] has the largest.
            let min_i = self.order[0];
            let max_i = self.order[k - 1];
            let min_key = self.iters[min_i].key();
            let max_key = self.iters[max_i].key();

            if min_key == max_key {
                // All k keys equal — emit. Advance the first iterator
                // (any one would do; advancing the smallest preserves
                // the sorted-ish-order for the next iteration).
                let emitted = min_key;
                self.iters[min_i].next();
                if self.iters[min_i].at_end() {
                    self.done = true;
                } else {
                    self.sort_order();
                }
                return Some(emitted);
            }

            // Smallest seeks past the largest.
            self.iters[min_i].seek(max_key);
            if self.iters[min_i].at_end() {
                self.done = true;
                return None;
            }
            self.sort_order();
        }
    }
