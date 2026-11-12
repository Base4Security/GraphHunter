    pub async fn run(
        self,
        mut raw_rx: RawReceiver,
        parsed_tx: ParsedSender,
        cancel: CancellationToken,
    ) -> ParserMetricsSnapshot {
        while let Some(result) = raw_rx.recv().await {
            if cancel.is_cancelled() {
                break;
            }
            self.metrics.chunks_received.fetch_add(1, Ordering::Relaxed);
            match result {
                Ok(chunk) => {
                    if let Some(batch) = self.parse_chunk(chunk) {
                        if !batch.events.is_empty() {
                            self.metrics.chunks_parsed.fetch_add(1, Ordering::Relaxed);
                        }
                        self.metrics
                            .triples_forwarded
                            .fetch_add(batch.events.len() as u64, Ordering::Relaxed);
                        if parsed_tx.send(batch).await.is_err() {
                            // Writer dropped the receiver — no point
                            // continuing. Exit cleanly.
                            break;
                        }
                    } else {
                        self.metrics.chunks_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(_err) => {
                    // SourceError is handled at the poller level
                    // (retry/backoff/strike counter). We just count it
                    // in metrics and keep consuming.
                    self.metrics.source_errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        self.metrics.snapshot()
    }
