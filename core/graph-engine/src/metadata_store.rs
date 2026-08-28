use std::collections::HashMap;

/// Append-only store for relation metadata. Each metadata set is serialized
/// as a flat byte sequence: [num_pairs:u32][key_len:u16,key_bytes,val_len:u16,val_bytes]...
/// An offset of 0 means "no metadata".
pub struct MetadataStore {
    data: Vec<u8>,
    /// Already-written records, keyed by their serialized bytes, so
    /// identical metadata sets share one copy. Capped: metadata that is
    /// genuinely high-cardinality (command lines, request bodies) would
    /// otherwise grow this map without ever scoring a hit.
    dedup: HashMap<Box<[u8]>, u64>,
}

/// Ceiling on distinct records tracked for sharing. Sized to comfortably
/// cover low-cardinality telemetry metadata (method × status × backend is a
/// few hundred combinations) while bounding the map on corpora where every
/// record differs.
const MAX_DEDUP_RECORDS: usize = 65_536;

impl MetadataStore {
    pub fn new() -> Self {
        // Reserve offset 0 as "no metadata" sentinel
        Self {
            data: vec![0; 4],
            dedup: HashMap::new(),
        }
    }

    /// Appends metadata and returns the offset. Returns 0 if metadata is empty.
    ///
    /// Identical metadata sets share a single copy. Security telemetry is
    /// full of low-cardinality metadata — an HTTP access log has a handful
    /// of methods, status codes and backends repeated across every request
    /// — so without sharing the arena stores the same few hundred byte
    /// sequences tens of millions of times, and this arena does not spill
    /// to disk. Readers address records by offset and never assume an
    /// offset is unique to one relation, so sharing is invisible to `get`
    /// and `visit_keys`.
    pub fn append(&mut self, metadata: &HashMap<String, String>) -> u64 {
        if metadata.is_empty() {
            return 0;
        }
        // Canonical (sorted) order. `HashMap` iteration order differs
        // between instances, so the same logical metadata would otherwise
        // serialize to different byte sequences and never match.
        let mut pairs: Vec<(&str, &str)> = metadata
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        pairs.sort_unstable_by_key(|(k, _)| *k);

        let start = self.data.len();
        // Compute the exact byte size up front so we grow the backing Vec
        // once per append instead of letting `extend_from_slice` double-grow
        // across 4 (count) + N × (2 + key_len + 2 + val_len) writes. At 200M
        // relations this is the difference between amortized O(N) and
        // log-factor thrash on the allocator.
        let mut needed = 4usize; // count: u32
        for (k, v) in &pairs {
            needed += 2 + k.len() + 2 + v.len();
        }
        self.data.reserve(needed);
        self.data
            .extend_from_slice(&(pairs.len() as u32).to_le_bytes());
        for (k, v) in &pairs {
            self.data.extend_from_slice(&(k.len() as u16).to_le_bytes());
            self.data.extend_from_slice(k.as_bytes());
            self.data.extend_from_slice(&(v.len() as u16).to_le_bytes());
            self.data.extend_from_slice(v.as_bytes());
        }

        // Written first so the record can be hashed in place rather than
        // built into a scratch buffer on every call; rolled back when an
        // identical record already exists.
        if let Some(prev) = self.dedup.get(&self.data[start..]).copied() {
            self.data.truncate(start);
            return prev;
        }
        if self.dedup.len() < MAX_DEDUP_RECORDS {
            let key: Box<[u8]> = self.data[start..].into();
            self.dedup.insert(key, start as u64);
        }
        start as u64
    }

    /// Reads metadata from the given offset.
    pub fn get(&self, offset: u64) -> HashMap<String, String> {
        if offset == 0 || offset as usize >= self.data.len() {
            return HashMap::new();
        }
        let mut pos = offset as usize;
        if pos + 4 > self.data.len() {
            return HashMap::new();
        }
        let count = u32::from_le_bytes([
            self.data[pos],
            self.data[pos + 1],
            self.data[pos + 2],
            self.data[pos + 3],
        ]) as usize;
        pos += 4;
        // A single metadata entry occupies at least 4 bytes (two u16 lens
        // for key and value with empty content). If `count` claims more
        // pairs than could physically fit in the remaining bytes, the
        // offset is corrupt / out of sync. Return empty instead of
        // letting `HashMap::with_capacity` request gigabytes.
        if count.saturating_mul(4) > self.data.len().saturating_sub(pos) {
            return HashMap::new();
        }
        let mut map = HashMap::with_capacity(count);
        for _ in 0..count {
            if pos + 2 > self.data.len() {
                break;
            }
            let klen = u16::from_le_bytes([self.data[pos], self.data[pos + 1]]) as usize;
            pos += 2;
            if pos + klen > self.data.len() {
                break;
            }
            let key = String::from_utf8_lossy(&self.data[pos..pos + klen]).to_string();
            pos += klen;
            if pos + 2 > self.data.len() {
                break;
            }
            let vlen = u16::from_le_bytes([self.data[pos], self.data[pos + 1]]) as usize;
            pos += 2;
            if pos + vlen > self.data.len() {
                break;
            }
            let val = String::from_utf8_lossy(&self.data[pos..pos + vlen]).to_string();
            pos += vlen;
            map.insert(key, val);
        }
        map
    }

    /// Walks only the keys at the given offset, handing each as a borrowed
    /// `&str` into the backing bytes without allocating. Values are skipped
    /// by advancing past their bytes. Used by aggregation paths (schema
    /// discovery, stat counters) that need key names but not values —
    /// `get()` would allocate a full `HashMap<String, String>` per call
    /// and throw away the values, which dominates wall-clock on large
    /// graphs.
    pub fn visit_keys<F: FnMut(&str)>(&self, offset: u64, mut f: F) {
        if offset == 0 || offset as usize >= self.data.len() {
            return;
        }
        let mut pos = offset as usize;
        if pos + 4 > self.data.len() {
            return;
        }
        let count = u32::from_le_bytes([
            self.data[pos],
            self.data[pos + 1],
            self.data[pos + 2],
            self.data[pos + 3],
        ]) as usize;
        pos += 4;
        if count.saturating_mul(4) > self.data.len().saturating_sub(pos) {
            return;
        }
        for _ in 0..count {
            if pos + 2 > self.data.len() {
                return;
            }
            let klen = u16::from_le_bytes([self.data[pos], self.data[pos + 1]]) as usize;
            pos += 2;
            if pos + klen > self.data.len() {
                return;
            }
            let key = std::str::from_utf8(&self.data[pos..pos + klen]).unwrap_or("");
            f(key);
            pos += klen;
            if pos + 2 > self.data.len() {
                return;
            }
            let vlen = u16::from_le_bytes([self.data[pos], self.data[pos + 1]]) as usize;
            pos += 2 + vlen;
        }
    }

    /// Current size in bytes.
    pub fn size_bytes(&self) -> usize {
        self.data.len()
    }
}

impl Default for MetadataStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for MetadataStore {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            // Carried over so a cloned graph keeps sharing records instead
            // of re-appending one copy per distinct set from scratch.
            dedup: self.dedup.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn identical_sets_share_one_record() {
        let mut s = MetadataStore::new();
        let a = s.append(&meta(&[("method", "GET"), ("status", "200")]));
        let size_after_first = s.size_bytes();
        let b = s.append(&meta(&[("method", "GET"), ("status", "200")]));
        assert_eq!(a, b, "the same metadata must reuse the same offset");
        assert_eq!(
            s.size_bytes(),
            size_after_first,
            "the arena must not grow for a repeat"
        );
    }

    #[test]
    fn source_map_ordering_does_not_defeat_sharing() {
        // Two HashMaps holding the same pairs iterate in unrelated orders.
        // Without a canonical serialization they would be stored twice.
        let mut s = MetadataStore::new();
        let a = s.append(&meta(&[("a", "1"), ("b", "2"), ("c", "3")]));
        let b = s.append(&meta(&[("c", "3"), ("b", "2"), ("a", "1")]));
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_sets_stay_distinct_and_round_trip() {
        let mut s = MetadataStore::new();
        let ok = s.append(&meta(&[("status", "200")]));
        let denied = s.append(&meta(&[("status", "403")]));
        assert_ne!(ok, denied);
        assert_eq!(s.get(ok).get("status").map(String::as_str), Some("200"));
        assert_eq!(s.get(denied).get("status").map(String::as_str), Some("403"));
    }

    #[test]
    fn empty_metadata_keeps_the_zero_sentinel() {
        let mut s = MetadataStore::new();
        assert_eq!(s.append(&HashMap::new()), 0);
        assert!(s.get(0).is_empty());
    }

    #[test]
    fn shared_records_survive_a_clone() {
        let mut s = MetadataStore::new();
        let a = s.append(&meta(&[("method", "POST")]));
        let mut c = s.clone();
        assert_eq!(c.append(&meta(&[("method", "POST")])), a);
        assert_eq!(c.get(a).get("method").map(String::as_str), Some("POST"));
    }

    #[test]
    fn visit_keys_reads_shared_records() {
        let mut s = MetadataStore::new();
        let off = s.append(&meta(&[("method", "GET"), ("status", "200")]));
        let _ = s.append(&meta(&[("method", "GET"), ("status", "200")]));
        let mut keys = Vec::new();
        s.visit_keys(off, |k| keys.push(k.to_string()));
        keys.sort();
        assert_eq!(keys, vec!["method".to_string(), "status".to_string()]);
    }
}
