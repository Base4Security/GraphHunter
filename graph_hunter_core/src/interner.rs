use ahash::{HashMap, HashMapExt};

/// A compact handle representing an interned string.
/// Copy-friendly 4-byte identifier instead of heap-allocated String.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StrId(u32);

impl StrId {
    /// Returns the raw index.
    #[inline]
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// Bidirectional string interner: O(1) amortized intern, O(1) resolve.
///
/// Stores each unique string exactly once. Returns a StrId handle
/// that can be used in HashMaps and other data structures for minimal memory.
#[derive(Clone, Debug)]
pub struct StringInterner {
    map: HashMap<String, StrId>,
    strings: Vec<String>,
}

impl StringInterner {
    /// Creates a new empty interner.
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            strings: Vec::new(),
        }
    }

    /// Creates a new interner with pre-allocated capacity.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            map: HashMap::with_capacity(cap),
            strings: Vec::with_capacity(cap),
        }
    }

    /// Interns a string, returning its StrId. O(1) amortized.
    /// If the string was already interned, returns the existing StrId.
    pub fn intern(&mut self, s: &str) -> StrId {
        if let Some(&id) = self.map.get(s) {
            return id;
        }
        let id = StrId(self.strings.len() as u32);
        self.strings.push(s.to_string());
        self.map.insert(s.to_string(), id);
        id
    }

    /// Resolves a StrId back to its string. O(1).
    /// Returns `"<invalid>"` if the StrId is out of bounds.
    #[inline]
    pub fn resolve(&self, id: StrId) -> &str {
        self.try_resolve(id).unwrap_or("<invalid>")
    }

    /// Tries to resolve a StrId back to its string. O(1).
    /// Returns None if the StrId is out of bounds (e.g. from a different interner).
    #[inline]
    pub fn try_resolve(&self, id: StrId) -> Option<&str> {
        self.strings.get(id.0 as usize).map(|s| s.as_str())
    }

    /// Tries to get the StrId for a string without interning it.
    /// Returns None if the string was never interned.
    #[inline]
    pub fn get(&self, s: &str) -> Option<StrId> {
        self.map.get(s).copied()
    }

    /// Returns the number of interned strings.
    pub fn len(&self) -> usize {
        self.strings.len()
    }

    /// Returns true if no strings have been interned.
    pub fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }

    /// Pre-allocate capacity for additional strings.
    pub fn reserve(&mut self, additional: usize) {
        self.map.reserve(additional);
        self.strings.reserve(additional);
    }
}

impl Default for StringInterner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intern_and_resolve() {
        let mut interner = StringInterner::new();
        let id1 = interner.intern("hello");
        let id2 = interner.intern("world");
        let id3 = interner.intern("hello"); // duplicate

        assert_eq!(id1, id3);
        assert_ne!(id1, id2);
        assert_eq!(interner.resolve(id1), "hello");
        assert_eq!(interner.resolve(id2), "world");
        assert_eq!(interner.len(), 2);
    }

    #[test]
    fn get_without_intern() {
        let mut interner = StringInterner::new();
        assert_eq!(interner.get("foo"), None);
        let id = interner.intern("foo");
        assert_eq!(interner.get("foo"), Some(id));
    }

    #[test]
    fn str_id_copy_and_size() {
        assert_eq!(std::mem::size_of::<StrId>(), 4);
        let id = StrId(42);
        let id2 = id; // Copy
        assert_eq!(id, id2);
    }
}
