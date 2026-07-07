//! LRU + TTL cache for on-demand enrichment results.
//!
//! When an analyst clicks an entity to drill down, the `EnrichmentEngine`
//! checks this cache before hitting Azure. If the same entity was
//! enriched within the last 15 minutes for the same source, the cache
//! returns the earlier result and we skip the network round-trip.
//!
//! Keying: `(source_id, entity_type, entity_value, time_bucket_start)`.
//! The time bucket is a 15-minute-aligned epoch-seconds floor so a
//! click on the same entity within a 15-minute window is deduplicated,
//! but clicks across boundaries still trigger a fresh fetch.
//!
//! Eviction: plain LRU with a configurable capacity. TTL is enforced
//! at read time (stale entries are returned as misses and evicted
//! in-place). The cache does NOT run a background sweeper — TTL
//! enforcement is lazy, which is fine because the entries are tiny
//! (a few counters, no Vec<CompactRelation>) and the LRU eviction
//! caps memory regardless.
//!
//! Invalidation: the cache exposes `invalidate_source(source_id)`
//! so when new data arrives for a source (e.g., the streaming poller
//! advances a watermark past a time bucket), the enrichment cache
//! drops stale entries for that source. See plan §5 "Cache
//! invalidation".
//!
//! PII notes: entity values are stored as plain strings. The cache
//! lives entirely in RAM and is never persisted, logged, or emitted
//! over an event boundary, so plaintext is acceptable. When Phase 5
//! Tauri-layer wiring adds the `enrichment_audit` sqlite table,
//! that table uses SHA-256 hashed values instead (plan §9).

use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::Duration;

/// Default cache capacity — 1 024 entries. At ~128 bytes per
/// `CachedResult` this is ~128 KB of resident RAM.
pub const DEFAULT_MAX_ENTRIES: usize = 1024;

/// Default TTL for a cache entry — 15 minutes. An analyst
/// who clicks the same entity again within this window gets the
/// cached result without a network round-trip.
pub const DEFAULT_TTL_SECONDS: i64 = 15 * 60;

/// Default time-bucket width for the cache key — 15 minutes.
/// Matches the TTL so a "live" click on the same entity in the
/// same bucket is deduplicated exactly once.
pub const DEFAULT_BUCKET_SECONDS: i64 = 15 * 60;

/// Composite cache key. Two enrichment requests with identical
/// keys are considered the same query.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EnrichmentCacheKey {
    pub source_id: String,
    pub entity_type: String,
    pub entity_value: String,
    /// Epoch-seconds floor of the query's time range onto the
    /// configured bucket width. Two queries whose time ranges share
    /// the same bucket map to the same key.
    pub time_bucket_start_epoch_s: i64,
}

impl EnrichmentCacheKey {
    /// Constructs a key for a given entity + time range. Floors the
    /// time range start onto the configured bucket width.
    pub fn for_query(
        source_id: impl Into<String>,
        entity_type: impl Into<String>,
        entity_value: impl Into<String>,
        time_range_start_epoch_s: i64,
        bucket_seconds: i64,
    ) -> Self {
        let bucket_start = floor_to_bucket(time_range_start_epoch_s, bucket_seconds);
        Self {
            source_id: source_id.into(),
            entity_type: entity_type.into(),
            entity_value: entity_value.into(),
            time_bucket_start_epoch_s: bucket_start,
        }
    }
}

/// Cached result of a previous enrichment query. Intentionally
/// small — the actual triples are in the graph already, we just
/// remember the summary counters so the UI can show "we already
/// fetched this" without re-querying Azure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachedEnrichment {
    /// Epoch seconds at which the entry was cached. Used for TTL
    /// enforcement on read.
    pub cached_at_epoch_s: i64,
    pub rows_fetched: usize,
    pub rows_inserted: usize,
    pub truncated: bool,
}

/// LRU + TTL cache for enrichment results.
pub struct EnrichmentCache {
    inner: Mutex<LruCache<EnrichmentCacheKey, CachedEnrichment>>,
    ttl_seconds: i64,
    bucket_seconds: i64,
}

impl EnrichmentCache {
    /// Constructs a new cache with the given capacity, TTL, and
    /// bucket width. Capacity is clamped to >= 1.
    pub fn new(max_entries: usize, ttl: Duration, bucket: Duration) -> Self {
        let cap = NonZeroUsize::new(max_entries.max(1)).unwrap();
        Self {
            inner: Mutex::new(LruCache::new(cap)),
            ttl_seconds: ttl.as_secs() as i64,
            bucket_seconds: bucket.as_secs() as i64,
        }
    }

    /// Bucket width in seconds — useful so callers can align their
    /// own time ranges consistently with the cache's bucketing.
    pub fn bucket_seconds(&self) -> i64 {
        self.bucket_seconds
    }

    /// Looks up an entry. Returns `None` if missing or expired.
    /// Expired entries are evicted on read.
    pub fn get(&self, key: &EnrichmentCacheKey, now_epoch_s: i64) -> Option<CachedEnrichment> {
        let mut inner = self.inner.lock().unwrap();
        // `get` bumps the LRU recency.
        let entry = inner.get(key).copied()?;
        if self.is_expired(&entry, now_epoch_s) {
            inner.pop(key);
            return None;
        }
        Some(entry)
    }

    /// Inserts (or overwrites) an entry. `now_epoch_s` sets
    /// `cached_at_epoch_s` on the stored value — usually the current
    /// wall clock, but configurable so tests can control TTL.
    pub fn put(&self, key: EnrichmentCacheKey, mut entry: CachedEnrichment, now_epoch_s: i64) {
        entry.cached_at_epoch_s = now_epoch_s;
        let mut inner = self.inner.lock().unwrap();
        inner.put(key, entry);
    }

    /// Drops every entry for a source. Called when new data arrives
    /// for the source via the streaming pipeline (the poller advances
    /// a watermark past a previously-cached time bucket).
    pub fn invalidate_source(&self, source_id: &str) {
        let mut inner = self.inner.lock().unwrap();
        // LruCache has no retain-style API; iterate + collect keys to
        // drop. The caller is expected to call this sparingly (once
        // per polling cycle, not per row).
        let keys_to_drop: Vec<EnrichmentCacheKey> = inner
            .iter()
            .filter_map(|(k, _)| {
                if k.source_id == source_id {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();
        for k in keys_to_drop {
            inner.pop(&k);
        }
    }

    /// Drops every entry, regardless of source or freshness.
    pub fn clear(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.clear();
    }

    /// Current entry count (post-LRU-eviction, post-TTL). Note that
    /// TTL-expired entries are counted until they're next accessed.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn is_expired(&self, entry: &CachedEnrichment, now_epoch_s: i64) -> bool {
        now_epoch_s.saturating_sub(entry.cached_at_epoch_s) >= self.ttl_seconds
    }
}

impl Default for EnrichmentCache {
    fn default() -> Self {
        Self::new(
            DEFAULT_MAX_ENTRIES,
            Duration::from_secs(DEFAULT_TTL_SECONDS as u64),
            Duration::from_secs(DEFAULT_BUCKET_SECONDS as u64),
        )
    }
}

fn floor_to_bucket(epoch_s: i64, bucket_seconds: i64) -> i64 {
    if bucket_seconds <= 0 {
        return epoch_s;
    }
    epoch_s.div_euclid(bucket_seconds) * bucket_seconds
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_entry() -> CachedEnrichment {
        CachedEnrichment {
            cached_at_epoch_s: 0,
            rows_fetched: 100,
            rows_inserted: 95,
            truncated: false,
        }
    }

    fn mk_key(source: &str, entity_val: &str, ts_start: i64) -> EnrichmentCacheKey {
        EnrichmentCacheKey::for_query(source, "IpAddress", entity_val, ts_start, 900)
    }

    #[test]
    fn put_and_get_roundtrip() {
        let cache = EnrichmentCache::default();
        let key = mk_key("la:ws-1", "10.0.0.1", 1_700_000_000);
        cache.put(key.clone(), mk_entry(), 1_700_000_100);
        let got = cache.get(&key, 1_700_000_200).unwrap();
        assert_eq!(got.rows_fetched, 100);
        assert_eq!(got.rows_inserted, 95);
        assert_eq!(got.cached_at_epoch_s, 1_700_000_100);
    }

    #[test]
    fn get_missing_returns_none() {
        let cache = EnrichmentCache::default();
        let key = mk_key("la:ws-1", "10.0.0.1", 1_700_000_000);
        assert!(cache.get(&key, 1_700_000_000).is_none());
    }

    #[test]
    fn ttl_expiry_evicts_on_read() {
        // TTL = 60s for this test.
        let cache = EnrichmentCache::new(10, Duration::from_secs(60), Duration::from_secs(900));
        let key = mk_key("la:ws-1", "10.0.0.1", 1_700_000_000);
        cache.put(key.clone(), mk_entry(), 1_700_000_000);
        // 30s later — still fresh.
        assert!(cache.get(&key, 1_700_000_030).is_some());
        // 60s later — boundary, expired.
        assert!(cache.get(&key, 1_700_000_060).is_none());
        // Entry was evicted on the expired read.
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn same_entity_same_bucket_dedups() {
        let cache = EnrichmentCache::default();
        // Two queries 60 seconds apart, both within the same 15-min bucket.
        let key_a = EnrichmentCacheKey::for_query("la:ws-1", "User", "alice", 1_700_000_000, 900);
        let key_b = EnrichmentCacheKey::for_query("la:ws-1", "User", "alice", 1_700_000_060, 900);
        assert_eq!(
            key_a, key_b,
            "queries within the same bucket should produce identical keys"
        );

        cache.put(key_a, mk_entry(), 1_700_000_000);
        assert!(cache.get(&key_b, 1_700_000_100).is_some());
    }

    #[test]
    fn cross_bucket_queries_are_independent() {
        let cache = EnrichmentCache::default();
        // Queries in different 15-min buckets.
        let key_a = EnrichmentCacheKey::for_query("la:ws-1", "User", "alice", 1_700_000_000, 900);
        let key_b =
            EnrichmentCacheKey::for_query("la:ws-1", "User", "alice", 1_700_000_000 + 900, 900);
        assert_ne!(key_a, key_b);

        cache.put(key_a, mk_entry(), 1_700_000_000);
        assert!(cache.get(&key_b, 1_700_000_100).is_none());
    }

    #[test]
    fn different_entities_independent() {
        let cache = EnrichmentCache::default();
        cache.put(
            mk_key("la:ws-1", "10.0.0.1", 1_700_000_000),
            mk_entry(),
            1_700_000_000,
        );
        assert!(
            cache
                .get(&mk_key("la:ws-1", "10.0.0.2", 1_700_000_000), 1_700_000_100)
                .is_none()
        );
    }

    #[test]
    fn different_sources_independent() {
        let cache = EnrichmentCache::default();
        cache.put(
            mk_key("la:ws-1", "10.0.0.1", 1_700_000_000),
            mk_entry(),
            1_700_000_000,
        );
        assert!(
            cache
                .get(
                    &mk_key("xdr:tenant-a", "10.0.0.1", 1_700_000_000),
                    1_700_000_100
                )
                .is_none()
        );
    }

    #[test]
    fn lru_evicts_oldest_when_full() {
        // Small cache — 2 entries.
        let cache = EnrichmentCache::new(2, Duration::from_secs(3600), Duration::from_secs(900));
        let k1 = mk_key("la:ws-1", "e1", 1_700_000_000);
        let k2 = mk_key("la:ws-1", "e2", 1_700_000_000);
        let k3 = mk_key("la:ws-1", "e3", 1_700_000_000);

        cache.put(k1.clone(), mk_entry(), 1_700_000_000);
        cache.put(k2.clone(), mk_entry(), 1_700_000_000);
        assert_eq!(cache.len(), 2);

        // Inserting a third should evict the oldest (k1).
        cache.put(k3.clone(), mk_entry(), 1_700_000_000);
        assert_eq!(cache.len(), 2);
        assert!(cache.get(&k1, 1_700_000_100).is_none());
        assert!(cache.get(&k2, 1_700_000_100).is_some());
        assert!(cache.get(&k3, 1_700_000_100).is_some());
    }

    #[test]
    fn get_bumps_lru_recency() {
        let cache = EnrichmentCache::new(2, Duration::from_secs(3600), Duration::from_secs(900));
        let k1 = mk_key("la:ws-1", "e1", 1_700_000_000);
        let k2 = mk_key("la:ws-1", "e2", 1_700_000_000);
        let k3 = mk_key("la:ws-1", "e3", 1_700_000_000);

        cache.put(k1.clone(), mk_entry(), 1_700_000_000);
        cache.put(k2.clone(), mk_entry(), 1_700_000_000);
        // Touching k1 marks it as more recently used than k2.
        let _ = cache.get(&k1, 1_700_000_100);
        // Inserting k3 should now evict k2, not k1.
        cache.put(k3.clone(), mk_entry(), 1_700_000_100);
        assert!(cache.get(&k1, 1_700_000_200).is_some());
        assert!(cache.get(&k2, 1_700_000_200).is_none());
        assert!(cache.get(&k3, 1_700_000_200).is_some());
    }

    #[test]
    fn invalidate_source_drops_matching_entries_only() {
        let cache = EnrichmentCache::default();
        cache.put(
            mk_key("la:ws-1", "10.0.0.1", 1_700_000_000),
            mk_entry(),
            1_700_000_000,
        );
        cache.put(
            mk_key("la:ws-1", "10.0.0.2", 1_700_000_000),
            mk_entry(),
            1_700_000_000,
        );
        cache.put(
            mk_key("xdr:tenant-a", "10.0.0.1", 1_700_000_000),
            mk_entry(),
            1_700_000_000,
        );
        assert_eq!(cache.len(), 3);

        cache.invalidate_source("la:ws-1");
        assert_eq!(cache.len(), 1);
        assert!(
            cache
                .get(
                    &mk_key("xdr:tenant-a", "10.0.0.1", 1_700_000_000),
                    1_700_000_100
                )
                .is_some()
        );
    }

    #[test]
    fn clear_empties_cache() {
        let cache = EnrichmentCache::default();
        for i in 0..10 {
            cache.put(
                mk_key("la:ws-1", &format!("e{i}"), 1_700_000_000),
                mk_entry(),
                1_700_000_000,
            );
        }
        assert_eq!(cache.len(), 10);
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn put_overwrites_existing() {
        let cache = EnrichmentCache::default();
        let key = mk_key("la:ws-1", "10.0.0.1", 1_700_000_000);

        cache.put(
            key.clone(),
            CachedEnrichment {
                cached_at_epoch_s: 0,
                rows_fetched: 50,
                rows_inserted: 50,
                truncated: false,
            },
            1_700_000_000,
        );
        cache.put(
            key.clone(),
            CachedEnrichment {
                cached_at_epoch_s: 0,
                rows_fetched: 200,
                rows_inserted: 200,
                truncated: true,
            },
            1_700_000_100,
        );

        let got = cache.get(&key, 1_700_000_200).unwrap();
        assert_eq!(got.rows_fetched, 200);
        assert!(got.truncated);
        assert_eq!(got.cached_at_epoch_s, 1_700_000_100);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn floor_to_bucket_aligns_correctly() {
        assert_eq!(floor_to_bucket(1_700_000_000, 900), 1_700_000_000 - 800);
        assert_eq!(floor_to_bucket(1_700_000_900, 900), 1_700_000_100);
        assert_eq!(floor_to_bucket(0, 900), 0);
        assert_eq!(floor_to_bucket(899, 900), 0);
        assert_eq!(floor_to_bucket(900, 900), 900);
    }
}
