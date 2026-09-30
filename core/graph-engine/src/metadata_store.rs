use std::collections::HashMap;

/// Append-only store for relation metadata.
///
/// Relation metadata is the largest thing a big ingest keeps in RAM (edges
/// spill to disk, this arena does not), so records are stored compressed
/// while keeping O(1) random access by offset — hunts read metadata edge by
/// edge, so block compression that must inflate a whole block per read is
/// not an option here. Three techniques, measured on a 1M-row Auth0 CSV
/// (4.6 edges per row, a unique `log_id` per row):
///
/// * **Record sharing.** Identical metadata sets share one record. The
///   previous record is always checked, which catches the fan-out case —
///   every edge minted from one source row carries that row's metadata —
///   even after the capped global map has stopped admitting new records.
/// * **Dictionary encoding.** Keys, and values of low-cardinality keys, are
///   written as small integer ids instead of repeated strings. Each key's
///   value dictionary is capped, so a high-cardinality key (a per-row id)
///   falls back to inline values without growing the dictionary.
/// * **Segmented arena.** Fixed-size pages instead of one `Vec<u8>`: no 2×
///   capacity slack and no multi-GB reallocation copy when it grows.
///
/// Record layout: `varint(pair_count)` then per pair a key ref and a value
/// ref, each `varint(id << 1 | 1)` for a dictionary entry or
/// `varint(len << 1)` followed by `len` UTF-8 bytes. Pairs are sorted by key
/// so the same logical set always encodes to the same bytes.
///
/// Offsets are `segment << 32 | position`. Offset 0 means "no metadata".
pub struct MetadataStore {
    segments: Vec<Vec<u8>>,
    /// Bytes of record data written (excludes the sentinel byte).
    used: usize,
    /// Already-written records, keyed by their encoded bytes, so identical
    /// metadata sets share one copy. Capped: metadata that is genuinely
    /// high-cardinality (command lines, request bodies) would otherwise grow
    /// this map without ever scoring a hit.
    dedup: HashMap<Box<[u8]>, u64>,
    /// Offset and length of the most recent record, for the fan-out check.
    last: Option<(u64, usize)>,
    key_ids: HashMap<Box<str>, u32>,
    keys: Vec<Box<str>>,
    /// Per key id: that key's value dictionary.
    values: Vec<ValueDict>,
    dict_values_total: usize,
    scratch: Vec<u8>,
}

#[derive(Clone, Default)]
struct ValueDict {
    ids: HashMap<Box<str>, u32>,
    vals: Vec<Box<str>>,
}

/// Ceiling on distinct records tracked for sharing. Sized to comfortably
/// cover low-cardinality telemetry metadata (method × status × backend is a
/// few hundred combinations) while bounding the map on corpora where every
/// record differs.
const MAX_DEDUP_RECORDS: usize = 65_536;
/// Page size of the arena. Commit grows in steps of this, never by doubling.
const SEGMENT_BYTES: usize = 8 << 20;
/// Distinct keys that get a dictionary id; later ones are written inline.
const MAX_DICT_KEYS: usize = 4_096;
/// Distinct values per key that get a dictionary id. A key past this is
/// high-cardinality (ids, hashes, timestamps): its new values go inline.
const MAX_DICT_VALUES_PER_KEY: usize = 4_096;
/// Global bound on dictionary values across all keys.
const MAX_DICT_VALUES_TOTAL: usize = 1 << 20;
/// Longer values are always inline: they rarely repeat and would bloat the
/// dictionary.
const MAX_DICT_VALUE_LEN: usize = 256;

impl MetadataStore {
    pub fn new() -> Self {
        // One sentinel byte so no record ever lives at offset 0.
        let mut first = Vec::with_capacity(SEGMENT_BYTES);
        first.push(0);
        Self {
            segments: vec![first],
            used: 0,
            dedup: HashMap::new(),
            last: None,
            key_ids: HashMap::new(),
            keys: Vec::new(),
            values: Vec::new(),
            dict_values_total: 0,
            scratch: Vec::new(),
        }
    }

    /// Appends metadata and returns the offset. Returns 0 if metadata is empty.
    ///
    /// Readers address records by offset and never assume an offset is
    /// unique to one relation, so sharing is invisible to `get` and
    /// `visit_keys`.
    pub fn append(&mut self, metadata: &HashMap<String, String>) -> u64 {
        if metadata.is_empty() {
            return 0;
        }
        // Canonical (sorted) order. `HashMap` iteration order differs
        // between instances, so the same logical metadata would otherwise
        // encode to different byte sequences and never match.
        let mut pairs: Vec<(&str, &str)> = metadata
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        pairs.sort_unstable_by_key(|(k, _)| *k);

        let mut buf = std::mem::take(&mut self.scratch);
        buf.clear();
        put_varint(&mut buf, pairs.len() as u64);
        for (k, v) in &pairs {
            let key_id = self.key_id(k);
            match key_id {
                Some(id) => put_varint(&mut buf, (u64::from(id) << 1) | 1),
                None => put_inline(&mut buf, k),
            }
            match key_id.and_then(|id| self.value_id(id, v)) {
                Some(id) => put_varint(&mut buf, (u64::from(id) << 1) | 1),
                None => put_inline(&mut buf, v),
            }
        }

        let offset = self.place(&buf);
        self.scratch = buf;
        offset
    }

    /// Stores an encoded record, sharing an identical earlier one if found.
    fn place(&mut self, rec: &[u8]) -> u64 {
        if let Some((off, len)) = self.last {
            if len == rec.len() && self.record_bytes(off, len) == Some(rec) {
                return off;
            }
        }
        if let Some(&off) = self.dedup.get(rec) {
            self.last = Some((off, rec.len()));
            return off;
        }

        let fits = self
            .segments
            .last()
            .is_some_and(|s| s.capacity() - s.len() >= rec.len());
        if !fits {
            self.segments
                .push(Vec::with_capacity(SEGMENT_BYTES.max(rec.len())));
        }
        let seg_idx = self.segments.len() - 1;
        let seg = &mut self.segments[seg_idx];
        let pos = seg.len();
        seg.extend_from_slice(rec);
        self.used += rec.len();
        let off = ((seg_idx as u64) << 32) | pos as u64;

        if self.dedup.len() < MAX_DEDUP_RECORDS {
            self.dedup.insert(rec.into(), off);
        }
        self.last = Some((off, rec.len()));
        off
    }

    fn record_bytes(&self, off: u64, len: usize) -> Option<&[u8]> {
        let seg = self.segments.get((off >> 32) as usize)?;
        let pos = (off & 0xFFFF_FFFF) as usize;
        seg.get(pos..pos.checked_add(len)?)
    }

    fn key_id(&mut self, k: &str) -> Option<u32> {
        if let Some(&id) = self.key_ids.get(k) {
            return Some(id);
        }
        if self.keys.len() >= MAX_DICT_KEYS {
            return None;
        }
        let id = self.keys.len() as u32;
        self.keys.push(k.into());
        self.key_ids.insert(k.into(), id);
        self.values.push(ValueDict::default());
        Some(id)
    }

    fn value_id(&mut self, key_id: u32, v: &str) -> Option<u32> {
        let dict = &mut self.values[key_id as usize];
        if let Some(&id) = dict.ids.get(v) {
            return Some(id);
        }
        if v.len() > MAX_DICT_VALUE_LEN
            || dict.vals.len() >= MAX_DICT_VALUES_PER_KEY
            || self.dict_values_total >= MAX_DICT_VALUES_TOTAL
        {
            return None;
        }
        let id = dict.vals.len() as u32;
        dict.vals.push(v.into());
        dict.ids.insert(v.into(), id);
        self.dict_values_total += 1;
        Some(id)
    }

    /// Decodes the record at `offset`, handing each pair to `f`. Stops at
    /// the first malformed byte: a corrupt or out-of-range offset yields
    /// nothing (or a prefix), never a panic or a huge allocation.
    fn visit<'a, F: FnMut(&'a str, Option<&'a str>)>(&'a self, offset: u64, want_values: bool, mut f: F) {
        if offset == 0 {
            return;
        }
        let Some(seg) = self.segments.get((offset >> 32) as usize) else {
            return;
        };
        let pos = (offset & 0xFFFF_FFFF) as usize;
        if pos >= seg.len() {
            return;
        }
        let mut r = Reader { buf: seg, pos };
        let Some(count) = r.varint() else { return };
        // Each pair takes at least two bytes; a larger count is corruption.
        if count > (seg.len() - r.pos) as u64 / 2 {
            return;
        }
        for _ in 0..count {
            let Some((key_id, key)) = r.str_ref(|id| self.keys.get(id).map(|s| &**s)) else {
                return;
            };
            let val = if want_values {
                match r.str_ref(|id| {
                    key_id
                        .and_then(|k| self.values.get(k))
                        .and_then(|d| d.vals.get(id))
                        .map(|s| &**s)
                }) {
                    Some((_, v)) => Some(v),
                    None => return,
                }
            } else {
                if r.skip_ref().is_none() {
                    return;
                }
                None
            };
            f(key, val);
        }
    }

    /// Reads metadata from the given offset.
    pub fn get(&self, offset: u64) -> HashMap<String, String> {
        let mut map = HashMap::new();
        self.visit(offset, true, |k, v| {
            map.insert(k.to_string(), v.unwrap_or_default().to_string());
        });
        map
    }

    /// Walks only the keys at the given offset, handing each as a borrowed
    /// `&str` without allocating. Values are skipped. Used by aggregation
    /// paths (schema discovery, stat counters) that need key names but not
    /// values — `get()` would allocate a full `HashMap<String, String>` per
    /// call and throw away the values, which dominates wall-clock on large
    /// graphs.
    pub fn visit_keys<F: FnMut(&str)>(&self, offset: u64, mut f: F) {
        self.visit(offset, false, |k, _| f(k));
    }

    /// Bytes of encoded record data held (excluding dictionaries).
    pub fn size_bytes(&self) -> usize {
        self.used
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn varint(&mut self) -> Option<u64> {
        let mut out = 0u64;
        for shift in (0..64).step_by(7) {
            let b = *self.buf.get(self.pos)?;
            self.pos += 1;
            out |= u64::from(b & 0x7F) << shift;
            if b & 0x80 == 0 {
                return Some(out);
            }
        }
        None
    }

    /// A key or value ref: a dictionary id resolved through `dict` (returned
    /// alongside the string), or inline UTF-8 bytes borrowed from the arena.
    fn str_ref(
        &mut self,
        dict: impl FnOnce(usize) -> Option<&'a str>,
    ) -> Option<(Option<usize>, &'a str)> {
        let tag = self.varint()?;
        if tag & 1 == 1 {
            let id = usize::try_from(tag >> 1).ok()?;
            return dict(id).map(|s| (Some(id), s));
        }
        let len = usize::try_from(tag >> 1).ok()?;
        let bytes = self.buf.get(self.pos..self.pos.checked_add(len)?)?;
        self.pos += len;
        std::str::from_utf8(bytes).ok().map(|s| (None, s))
    }

    fn skip_ref(&mut self) -> Option<()> {
        let tag = self.varint()?;
        if tag & 1 == 0 {
            let len = usize::try_from(tag >> 1).ok()?;
            self.pos = self.pos.checked_add(len)?;
            if self.pos > self.buf.len() {
                return None;
            }
        }
        Some(())
    }
}

fn put_varint(buf: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        buf.push((v as u8) | 0x80);
        v >>= 7;
    }
    buf.push(v as u8);
}

fn put_inline(buf: &mut Vec<u8>, s: &str) {
    put_varint(buf, (s.len() as u64) << 1);
    buf.extend_from_slice(s.as_bytes());
}

impl Default for MetadataStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for MetadataStore {
    fn clone(&self) -> Self {
        Self {
            // `Vec::clone` allocates exactly `len`, which would leave every
            // cloned segment full; restore page capacity on the tail only,
            // the one that still receives appends.
            segments: self
                .segments
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    if i + 1 == self.segments.len() {
                        let mut v = Vec::with_capacity(s.capacity());
                        v.extend_from_slice(s);
                        v
                    } else {
                        s.clone()
                    }
                })
                .collect(),
            used: self.used,
            // Carried over so a cloned graph keeps sharing records instead
            // of re-appending one copy per distinct set from scratch.
            dedup: self.dedup.clone(),
            last: self.last,
            key_ids: self.key_ids.clone(),
            keys: self.keys.clone(),
            values: self.values.clone(),
            dict_values_total: self.dict_values_total,
            scratch: Vec::new(),
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

    /// The fan-out case: every edge from one source row carries the row's
    /// metadata, and each row has a unique id. Once the global map is full
    /// only the previous-record check can share these — without it the
    /// arena stored one copy per edge.
    #[test]
    fn row_fanout_shares_after_the_global_map_is_full() {
        let mut s = MetadataStore::new();
        for i in 0..MAX_DEDUP_RECORDS + 10 {
            s.append(&meta(&[("log_id", &format!("{i:056}"))]));
        }
        let row = meta(&[("log_id", "unique-row"), ("scope", "openid")]);
        let a = s.append(&row);
        let size = s.size_bytes();
        for _ in 0..4 {
            assert_eq!(s.append(&row), a);
        }
        assert_eq!(s.size_bytes(), size);
    }

    /// A per-row id must not grow the value dictionary without bound, and
    /// must still round-trip once past the cap.
    #[test]
    fn high_cardinality_values_fall_back_to_inline() {
        let mut s = MetadataStore::new();
        let mut offs = Vec::new();
        for i in 0..MAX_DICT_VALUES_PER_KEY + 100 {
            offs.push((i, s.append(&meta(&[("log_id", &i.to_string()), ("type", "sepft")]))));
        }
        assert!(s.dict_values_total <= MAX_DICT_VALUES_PER_KEY + 1);
        for (i, off) in offs {
            let m = s.get(off);
            assert_eq!(m.get("log_id"), Some(&i.to_string()));
            assert_eq!(m.get("type").map(String::as_str), Some("sepft"));
        }
    }

    /// Repeated keys and low-cardinality values cost ids, not bytes.
    #[test]
    fn dictionary_encoding_shrinks_repetitive_records() {
        let mut s = MetadataStore::new();
        let row = |i: usize| {
            meta(&[
                ("client_id", "RDJAkcTmOhU6SnZ0jzPjECXmV3nj7TjS"),
                ("scope", "openid profile email read:current_user"),
                ("log_id", &format!("9002026082202595762685800000000000000122337218437{i:07}")),
            ])
        };
        s.append(&row(0));
        let before = s.size_bytes();
        s.append(&row(1));
        let per_record = s.size_bytes() - before;
        // log_id (56 B) inline + ~8 B of ids and tags; the two repeated
        // values (70 B) and all three keys are dictionary refs.
        assert!(per_record < 70, "record took {per_record} bytes");
    }

    #[test]
    fn records_never_straddle_segments_and_offsets_stay_valid() {
        let mut s = MetadataStore::new();
        let big = "x".repeat(60_000); // inline: above MAX_DICT_VALUE_LEN
        let mut offs = Vec::new();
        for i in 0..(SEGMENT_BYTES / 60_000) * 3 {
            offs.push((i, s.append(&meta(&[("body", &big), ("n", &i.to_string())]))));
        }
        assert!(s.segments.len() >= 3);
        for (i, off) in offs {
            let m = s.get(off);
            assert_eq!(m.get("n"), Some(&i.to_string()));
            assert_eq!(m.get("body").map(String::len), Some(60_000));
        }
    }

    #[test]
    fn garbage_offsets_read_as_empty() {
        let mut s = MetadataStore::new();
        s.append(&meta(&[("a", "1")]));
        for off in [1u64 << 32, (7u64 << 32) | 3, 0xFFFF_FFFF, 1_000_000] {
            assert!(s.get(off).is_empty(), "offset {off:#x}");
        }
    }
}
