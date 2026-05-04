use std::collections::HashMap;

/// Append-only store for relation metadata. Each metadata set is serialized
/// as a flat byte sequence: [num_pairs:u32][key_len:u16,key_bytes,val_len:u16,val_bytes]...
/// An offset of 0 means "no metadata".
pub struct MetadataStore {
    data: Vec<u8>,
}

impl MetadataStore {
    pub fn new() -> Self {
        // Reserve offset 0 as "no metadata" sentinel
        Self { data: vec![0; 4] }
    }

    /// Appends metadata and returns the offset. Returns 0 if metadata is empty.
    pub fn append(&mut self, metadata: &HashMap<String, String>) -> u64 {
        if metadata.is_empty() {
            return 0;
        }
        let offset = self.data.len() as u64;
        // Compute the exact byte size up front so we grow the backing Vec
        // once per append instead of letting `extend_from_slice` double-grow
        // across 4 (count) + N × (2 + key_len + 2 + val_len) writes. At 200M
        // relations this is the difference between amortized O(N) and
        // log-factor thrash on the allocator.
        let mut needed = 4usize; // count: u32
        for (k, v) in metadata {
            needed += 2 + k.len() + 2 + v.len();
        }
        self.data.reserve(needed);
        let count = metadata.len() as u32;
        self.data.extend_from_slice(&count.to_le_bytes());
        for (k, v) in metadata {
            let klen = k.len() as u16;
            self.data.extend_from_slice(&klen.to_le_bytes());
            self.data.extend_from_slice(k.as_bytes());
            let vlen = v.len() as u16;
            self.data.extend_from_slice(&vlen.to_le_bytes());
            self.data.extend_from_slice(v.as_bytes());
        }
        offset
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
        }
    }
}
