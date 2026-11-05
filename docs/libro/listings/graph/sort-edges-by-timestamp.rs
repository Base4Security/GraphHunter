    pub fn sort_edges_by_timestamp(&mut self) -> Result<(), GraphError> {
        if self.edges_sorted {
            return Ok(());
        }
        self.streaming.finalize();
        self.edges_sorted = true;
        // Heavy-logs #3.5: index builds (NLF + khop_reach) are
        // *lazy* now. Resetting the OnceLocks here ensures any
        // post-finalize matcher call rebuilds against the freshly
        // sorted edge layout. The build itself happens inside the
        // first `ensure_nlf` / `ensure_khop_reach` call — typically
        // the first hunt — so opening a 28 GB session is bounded
        // by the streaming reader, not by the multi-GB index
        // build.
        self.nlf = std::sync::OnceLock::new();
        self.khop_reach = std::sync::OnceLock::new();
        // The streaming outer-table snapshot is built lazily on
        // first matcher invocation; reset so the next hunt sees
        // the freshly-sorted vertex set.
        self.streaming_snapshot = std::sync::OnceLock::new();
        Ok(())
    }
