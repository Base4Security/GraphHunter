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
            self.data[pos], self.data[pos+1], self.data[pos+2], self.data[pos+3]
        ]) as usize;
        pos += 4;
        let mut map = HashMap::with_capacity(count);
        for _ in 0..count {
            if pos + 2 > self.data.len() { break; }
            let klen = u16::from_le_bytes([self.data[pos], self.data[pos+1]]) as usize;
            pos += 2;
            if pos + klen > self.data.len() { break; }
            let key = String::from_utf8_lossy(&self.data[pos..pos+klen]).to_string();
            pos += klen;
            if pos + 2 > self.data.len() { break; }
            let vlen = u16::from_le_bytes([self.data[pos], self.data[pos+1]]) as usize;
            pos += 2;
            if pos + vlen > self.data.len() { break; }
            let val = String::from_utf8_lossy(&self.data[pos..pos+vlen]).to_string();
            pos += vlen;
            map.insert(key, val);
        }
        map
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
        Self { data: self.data.clone() }
    }
}
