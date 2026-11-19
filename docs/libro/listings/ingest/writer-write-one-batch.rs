    async fn write_one_batch(&self, batch: ParsedBatch, cancel: &CancellationToken) {
        // Record the priority for metrics. The writer doesn't actually
        // reorder batches — this counter just lets operators see
        // whether enrichment is flowing through.
        if matches!(batch.priority, Priority::Enrichment) {
            self.metrics
                .enrichment_batches
                .fetch_add(1, Ordering::Relaxed);
        }

        let mut pending = batch.events;
        let dataset_id = batch.dataset_id.clone();
        let mut cancelled_mid_batch = false;

        while !pending.is_empty() {
            if cancel.is_cancelled() {
                cancelled_mid_batch = true;
                break;
            }

            match self
                .access
                .insert_raw_chunk(&mut pending, dataset_id.as_deref(), self.chunk_size)
                .await
            {
                Ok(n) => {
                    self.metrics.chunks_written.fetch_add(1, Ordering::Relaxed);
                    self.metrics
                        .triples_inserted
                        .fetch_add(n as u64, Ordering::Relaxed);
                    if n == 0 {
                        // Defensive: a correctly-implemented `GraphAccess`
                        // never returns `Ok(0)` from a non-empty pending
                        // vec. If we see this, bail out to avoid an
                        // infinite loop.
                        break;
                    }
                }
                Err(_) => {
                    self.metrics.errors.fetch_add(1, Ordering::Relaxed);
                    // Abandon the rest of this batch. A more
                    // sophisticated policy (retry, dead-letter queue)
                    // is a Phase 5 concern.
                    return;
                }
            }

            // Yield between chunks so readers can grab the lock.
            tokio::task::yield_now().await;
        }

        if cancelled_mid_batch {
            self.metrics
                .batches_cancelled
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.metrics
                .batches_processed
                .fetch_add(1, Ordering::Relaxed);
        }
    }
