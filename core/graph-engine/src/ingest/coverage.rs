//! Data coverage tracker — answers "do I actually have data from
//! source X between T1 and T2?" without scanning the graph's edge
//! store.
//!
//! Purpose (plan §5 / §9 "data coverage"): when a hunt returns zero
//! results, the analyst needs to know whether the hypothesis genuinely
//! didn't match OR whether we never ingested data in the target window.
//! Without this distinction, an empty hunt result is ambiguous and the
//! analyst wastes time questioning their hypothesis when the real
//! cause is an ingestion gap.
//!
//! ## Data structure
//!
//! One 1-minute bucket per source per minute. Stored as a `BTreeMap`
//! so queries are O(log N + bucket_count) and the "gaps" query can
//! walk the map in order without sorting.
//!
//! Buckets are keyed by `start_epoch_s` (the lower bound of the
//! 1-minute window, rounded down to the minute). Row counts are
//! incremented via `record(source, epoch_s, rows)` at insert time.
//!
//! ## Memory footprint
//!
//! At 1 bucket / minute / source × 24 hours × 16 bytes per entry,
//! one source consumes ~23 KB per day. The default `max_buckets`
//! caps it at 1440 (24 h), after which older buckets are evicted.
//!
//! ## Accuracy caveats
//!
//! - Buckets are populated at graph-insert time, so the tracker
//!   reflects ingestion, not query-time reality. If a bucket was
//!   ingested and then the dataset was deleted, the tracker doesn't
//!   notice.
//! - `record` batches rows by timestamp; callers should pass the
//!   event's own `timestamp` (not `now`) so coverage lines up with
//!   the hunt's time filter, not with when the ingest happened.
//! - The tracker is per-source, not per-table. If a source emits
//!   multiple tables with different volumes, coverage reflects the
//!   aggregate. A future refinement can add per-table histograms.

use std::collections::BTreeMap;
use std::sync::RwLock;
use std::time::Duration;

/// Default bucket duration — 1 minute.
pub const DEFAULT_BUCKET_SECONDS: i64 = 60;

/// Default ring-buffer capacity per source. 1 440 = 24 hours at
/// 1-minute buckets.
pub const DEFAULT_MAX_BUCKETS: usize = 1440;

/// One coverage bucket as returned by query APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverageBucket {
    /// Epoch-seconds timestamp of the start of the bucket (inclusive).
    pub start_epoch_s: i64,
    /// Number of rows ingested into this bucket.
    pub row_count: u64,
}

/// Gap in coverage — an interval `[start, end)` where no rows were
/// recorded for a source. Returned by [`DataCoverage::gaps`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverageGap {
    pub start_epoch_s: i64,
    pub end_epoch_s: i64,
}

impl CoverageGap {
    pub fn duration_secs(&self) -> i64 {
        self.end_epoch_s.saturating_sub(self.start_epoch_s)
    }
}

/// Multi-source data coverage tracker. Thread-safe; designed to be
/// held as an `Arc<DataCoverage>` by the ingest pipeline and queried
/// by hunt / diagnostic code paths.
pub struct DataCoverage {
    bucket_seconds: i64,
    max_buckets: usize,
    sources: RwLock<BTreeMap<String, SourceHistogram>>,
}

impl Default for DataCoverage {
    fn default() -> Self {
        Self::new(
            Duration::from_secs(DEFAULT_BUCKET_SECONDS as u64),
            DEFAULT_MAX_BUCKETS,
        )
    }
}

impl DataCoverage {
    pub fn new(bucket_duration: Duration, max_buckets: usize) -> Self {
        let bucket_seconds = bucket_duration.as_secs() as i64;
        let bs = if bucket_seconds == 0 {
            60
        } else {
            bucket_seconds
        };
        Self {
            bucket_seconds: bs,
            max_buckets: max_buckets.max(1),
            sources: RwLock::new(BTreeMap::new()),
        }
    }

    /// Records that `rows` rows were ingested for `source_id` at the
    /// given epoch-seconds timestamp. Rolls into the appropriate
    /// 1-minute bucket; if that bucket is the oldest one evicted by
    /// the ring, the record is silently dropped.
    pub fn record(&self, source_id: &str, event_epoch_s: i64, rows: u64) {
        if rows == 0 {
            return;
        }
        let bucket_start = bucket_floor(event_epoch_s, self.bucket_seconds);
        let mut sources = self.sources.write().unwrap();
        let hist = sources
            .entry(source_id.to_string())
            .or_insert_with(|| SourceHistogram::new(self.max_buckets));
        hist.record(bucket_start, rows);
    }

    /// Returns the total number of rows ingested for `source_id`
    /// whose event timestamps fall in `[t1_epoch_s, t2_epoch_s]`
    /// (inclusive).
    pub fn count_in_range(&self, source_id: &str, t1_epoch_s: i64, t2_epoch_s: i64) -> u64 {
        if t2_epoch_s < t1_epoch_s {
            return 0;
        }
        let sources = self.sources.read().unwrap();
        let Some(hist) = sources.get(source_id) else {
            return 0;
        };
        hist.count_in_range(
            bucket_floor(t1_epoch_s, self.bucket_seconds),
            bucket_floor(t2_epoch_s, self.bucket_seconds),
        )
    }

    /// Returns the list of buckets for `source_id` that overlap
    /// `[t1_epoch_s, t2_epoch_s]`, in chronological order.
    pub fn buckets_in_range(
        &self,
        source_id: &str,
        t1_epoch_s: i64,
        t2_epoch_s: i64,
    ) -> Vec<CoverageBucket> {
        if t2_epoch_s < t1_epoch_s {
            return Vec::new();
        }
        let sources = self.sources.read().unwrap();
        let Some(hist) = sources.get(source_id) else {
            return Vec::new();
        };
        hist.buckets_in_range(
            bucket_floor(t1_epoch_s, self.bucket_seconds),
            bucket_floor(t2_epoch_s, self.bucket_seconds),
        )
    }

    /// Returns the `(min, max)` event timestamps for `source_id`
    /// present in the histogram, or `None` if the source has no data.
    pub fn source_range(&self, source_id: &str) -> Option<(i64, i64)> {
        let sources = self.sources.read().unwrap();
        sources.get(source_id).and_then(|h| h.range())
    }

    /// Returns gaps in coverage for `source_id` within
    /// `[t1_epoch_s, t2_epoch_s]`. A gap is a contiguous run of
    /// bucket-start timestamps inside the query window where the
    /// source has no recorded rows.
    ///
    /// Gaps are returned at bucket resolution (multiples of
    /// `bucket_seconds`) in chronological order. If the source has no
    /// data at all within the range, the entire range is returned as
    /// a single gap.
    pub fn gaps(&self, source_id: &str, t1_epoch_s: i64, t2_epoch_s: i64) -> Vec<CoverageGap> {
        if t2_epoch_s < t1_epoch_s {
            return Vec::new();
        }
        let bs = self.bucket_seconds;
        let t1_floor = bucket_floor(t1_epoch_s, bs);
        let t2_floor = bucket_floor(t2_epoch_s, bs);

        let sources = self.sources.read().unwrap();
        let hist = match sources.get(source_id) {
            Some(h) => h,
            None => {
                // No source → entire range is a gap.
                return vec![CoverageGap {
                    start_epoch_s: t1_floor,
                    end_epoch_s: t2_floor + bs,
                }];
            }
        };
        hist.gaps_in_range(t1_floor, t2_floor, bs)
    }

    /// Drops all buckets for a source. Used when the source is
    /// disconnected so the coverage map doesn't grow unbounded.
    pub fn forget_source(&self, source_id: &str) {
        let mut sources = self.sources.write().unwrap();
        sources.remove(source_id);
    }

    /// Returns how many sources are currently tracked. For metrics.
    pub fn source_count(&self) -> usize {
        self.sources.read().unwrap().len()
    }
}

// ---------------------------------------------------------------------------
// Per-source inner histogram
// ---------------------------------------------------------------------------

struct SourceHistogram {
    /// Map keyed by bucket-start epoch-seconds. `u64` is the row count.
    buckets: BTreeMap<i64, u64>,
    max_buckets: usize,
}

impl SourceHistogram {
    fn new(max_buckets: usize) -> Self {
        Self {
            buckets: BTreeMap::new(),
            max_buckets,
        }
    }

    fn record(&mut self, bucket_start: i64, rows: u64) {
        *self.buckets.entry(bucket_start).or_insert(0) += rows;
        // Evict the oldest entries until we're under the cap.
        while self.buckets.len() > self.max_buckets {
            // pop_first is stable since 1.66.
            self.buckets.pop_first();
        }
    }

    fn count_in_range(&self, t1_floor: i64, t2_floor: i64) -> u64 {
        self.buckets
            .range(t1_floor..=t2_floor)
            .map(|(_, v)| *v)
            .sum()
    }

    fn buckets_in_range(&self, t1_floor: i64, t2_floor: i64) -> Vec<CoverageBucket> {
        self.buckets
            .range(t1_floor..=t2_floor)
            .map(|(&start, &count)| CoverageBucket {
                start_epoch_s: start,
                row_count: count,
            })
            .collect()
    }

    fn range(&self) -> Option<(i64, i64)> {
        let min = *self.buckets.keys().next()?;
        let max = *self.buckets.keys().next_back()?;
        Some((min, max))
    }

    /// Walks the range, collecting contiguous runs of missing buckets.
    fn gaps_in_range(&self, t1_floor: i64, t2_floor: i64, bs: i64) -> Vec<CoverageGap> {
        let mut gaps = Vec::new();
        let mut cursor = t1_floor;
        // Iterate present buckets in the range.
        for (&bucket_start, _) in self.buckets.range(t1_floor..=t2_floor) {
            if bucket_start > cursor {
                gaps.push(CoverageGap {
                    start_epoch_s: cursor,
                    end_epoch_s: bucket_start,
                });
            }
            cursor = bucket_start + bs;
        }
        // Tail gap (after the last present bucket up to the end).
        if cursor <= t2_floor {
            gaps.push(CoverageGap {
                start_epoch_s: cursor,
                end_epoch_s: t2_floor + bs,
            });
        }
        gaps
    }
}

fn bucket_floor(epoch_s: i64, bucket_seconds: i64) -> i64 {
    if bucket_seconds <= 0 {
        return epoch_s;
    }
    // Floor division that works for negative timestamps too (we don't
    // expect negatives, but be defensive).
    epoch_s.div_euclid(bucket_seconds) * bucket_seconds
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_floor_rounds_down_to_minute() {
        assert_eq!(bucket_floor(0, 60), 0);
        assert_eq!(bucket_floor(59, 60), 0);
        assert_eq!(bucket_floor(60, 60), 60);
        assert_eq!(bucket_floor(61, 60), 60);
        assert_eq!(bucket_floor(3_599, 60), 3_540);
        assert_eq!(bucket_floor(3_600, 60), 3_600);
    }

    #[test]
    fn record_and_query_single_bucket() {
        let cov = DataCoverage::default();
        cov.record("la:ws-1", 1_700_000_042, 5);
        cov.record("la:ws-1", 1_700_000_055, 7);
        // Both events fall in the same minute bucket (1_700_000_040).
        assert_eq!(
            cov.count_in_range("la:ws-1", 1_700_000_040, 1_700_000_059),
            12
        );
    }

    #[test]
    fn record_across_multiple_minutes() {
        let cov = DataCoverage::default();
        for minute in 0..5 {
            let ts = 1_700_000_040 + minute * 60 + 10;
            cov.record("la:ws-1", ts, 10);
        }
        // 5 buckets × 10 rows.
        assert_eq!(
            cov.count_in_range("la:ws-1", 1_700_000_040, 1_700_000_040 + 5 * 60 - 1),
            50
        );
        // Narrower range — only first 3 buckets.
        assert_eq!(
            cov.count_in_range("la:ws-1", 1_700_000_040, 1_700_000_040 + 3 * 60 - 1),
            30
        );
    }

    #[test]
    fn query_unknown_source_returns_zero() {
        let cov = DataCoverage::default();
        cov.record("la:ws-1", 1_700_000_040, 42);
        assert_eq!(cov.count_in_range("xdr:other", 0, i64::MAX), 0);
    }

    #[test]
    fn sources_are_independent() {
        let cov = DataCoverage::default();
        cov.record("la:ws-1", 1_700_000_040, 10);
        cov.record("xdr:tenant-a", 1_700_000_040, 20);
        assert_eq!(cov.count_in_range("la:ws-1", 0, i64::MAX), 10);
        assert_eq!(cov.count_in_range("xdr:tenant-a", 0, i64::MAX), 20);
    }

    #[test]
    fn max_buckets_evicts_oldest() {
        let cov = DataCoverage::new(Duration::from_secs(60), 5);
        for minute in 0..10 {
            let ts = 1_700_000_040 + minute * 60;
            cov.record("la:ws-1", ts, 1);
        }
        // Only the last 5 buckets (minutes 5..9) should remain.
        let total = cov.count_in_range("la:ws-1", 0, i64::MAX);
        assert_eq!(total, 5);
        let buckets = cov.buckets_in_range("la:ws-1", 0, i64::MAX);
        assert_eq!(buckets.len(), 5);
        assert_eq!(buckets[0].start_epoch_s, 1_700_000_040 + 5 * 60);
    }

    #[test]
    fn zero_rows_skipped() {
        let cov = DataCoverage::default();
        cov.record("la:ws-1", 1_700_000_040, 0);
        assert_eq!(cov.source_count(), 0);
        assert_eq!(cov.count_in_range("la:ws-1", 0, i64::MAX), 0);
    }

    #[test]
    fn inverted_range_returns_zero() {
        let cov = DataCoverage::default();
        cov.record("la:ws-1", 1_700_000_040, 5);
        assert_eq!(
            cov.count_in_range("la:ws-1", 2_000_000_000, 1_700_000_040),
            0
        );
    }

    #[test]
    fn gaps_full_range_when_source_missing() {
        let cov = DataCoverage::default();
        // t1 = 1_700_000_040 (minute boundary), t2 = 1_700_000_280.
        // bucket_floor(1_700_000_280, 60) = 1_700_000_280 (since
        // 1_700_000_280 = 28333338 × 60).
        let gaps = cov.gaps("unknown", 1_700_000_040, 1_700_000_280);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].start_epoch_s, 1_700_000_040);
        assert_eq!(gaps[0].end_epoch_s, 1_700_000_280 + 60);
    }

    #[test]
    fn gaps_between_sparse_buckets() {
        let cov = DataCoverage::default();
        // Minute boundaries from base 1_700_000_040:
        //   minute 0 → 1_700_000_040
        //   minute 1 → 1_700_000_100
        //   minute 2 → 1_700_000_160
        //   minute 3 → 1_700_000_220
        //   minute 4 → 1_700_000_280
        // Record events in minutes 0, 2, 3 (skipping 1 and 4).
        cov.record("la:ws-1", 1_700_000_040, 1); // minute 0
        cov.record("la:ws-1", 1_700_000_160, 1); // minute 2
        cov.record("la:ws-1", 1_700_000_220, 1); // minute 3

        // Query minutes 0..4 (inclusive).
        let gaps = cov.gaps("la:ws-1", 1_700_000_040, 1_700_000_280);
        // Expected: minute 1 gap + minute 4 gap.
        assert_eq!(gaps.len(), 2);
        assert_eq!(gaps[0].start_epoch_s, 1_700_000_100);
        assert_eq!(gaps[0].end_epoch_s, 1_700_000_160);
        assert_eq!(gaps[1].start_epoch_s, 1_700_000_280);
        assert_eq!(gaps[1].end_epoch_s, 1_700_000_340);
    }

    #[test]
    fn gaps_none_when_every_bucket_populated() {
        let cov = DataCoverage::default();
        for minute in 0..5 {
            cov.record("la:ws-1", 1_700_000_040 + minute * 60, 1);
        }
        let gaps = cov.gaps("la:ws-1", 1_700_000_040, 1_700_000_240);
        assert!(gaps.is_empty(), "expected no gaps, got {gaps:?}");
    }

    #[test]
    fn source_range_tracks_min_and_max() {
        let cov = DataCoverage::default();
        // minute 0 → 1_700_000_040
        // minute 2 → 1_700_000_160
        // minute 5 → 1_700_000_340
        cov.record("la:ws-1", 1_700_000_160, 1); // minute 2
        cov.record("la:ws-1", 1_700_000_040, 1); // minute 0
        cov.record("la:ws-1", 1_700_000_340, 1); // minute 5
        let (min, max) = cov.source_range("la:ws-1").unwrap();
        assert_eq!(min, 1_700_000_040);
        assert_eq!(max, 1_700_000_340);
    }

    #[test]
    fn source_range_none_for_unknown() {
        let cov = DataCoverage::default();
        assert!(cov.source_range("unknown").is_none());
    }

    #[test]
    fn forget_source_removes_from_map() {
        let cov = DataCoverage::default();
        cov.record("la:ws-1", 1_700_000_040, 1);
        assert_eq!(cov.source_count(), 1);
        cov.forget_source("la:ws-1");
        assert_eq!(cov.source_count(), 0);
        assert_eq!(cov.count_in_range("la:ws-1", 0, i64::MAX), 0);
    }

    #[test]
    fn buckets_in_range_returns_ordered() {
        let cov = DataCoverage::default();
        // Base is 1_700_000_040 (= 28333334 × 60). Minute boundaries
        // starting from the base are 040, 100, 160, 220, 280, 340, ...
        // Record events in minutes 3, 1, 2 (out of order).
        cov.record("la:ws-1", 1_700_000_220, 3); // minute 3 bucket
        cov.record("la:ws-1", 1_700_000_100, 1); // minute 1 bucket
        cov.record("la:ws-1", 1_700_000_160, 2); // minute 2 bucket
        let buckets = cov.buckets_in_range("la:ws-1", 1_700_000_040, 1_700_000_280);
        assert_eq!(buckets.len(), 3);
        assert_eq!(buckets[0].start_epoch_s, 1_700_000_100);
        assert_eq!(buckets[0].row_count, 1);
        assert_eq!(buckets[1].start_epoch_s, 1_700_000_160);
        assert_eq!(buckets[1].row_count, 2);
        assert_eq!(buckets[2].start_epoch_s, 1_700_000_220);
        assert_eq!(buckets[2].row_count, 3);
    }
}
