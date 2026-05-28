use std::sync::Arc;

use ahash::{HashMap, HashMapExt};
use serde::{Deserialize, Serialize};

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

    /// Creates a StrId from a raw u32 value.
    /// Used by the SIMD bridge to reconstruct StrIds from C++ node IDs.
    #[inline]
    pub fn from_raw(n: u32) -> Self {
        StrId(n)
    }
}

/// Bidirectional string interner: O(1) amortized intern, O(1) resolve.
///
/// Stores each unique string exactly once. Returns a StrId handle
/// that can be used in HashMaps and other data structures for minimal memory.
///
/// Both `map` and `strings` hold `Arc<str>` so a new intern allocates the
/// string bytes once (the initial `Arc::from(&str)`) and then only bumps
/// refcounts when inserting into both containers. At 100M+ interns this
/// halves the allocator pressure compared to the previous `String`-per-side
/// layout.
#[derive(Clone, Debug)]
pub struct StringInterner {
    map: HashMap<Arc<str>, StrId>,
    strings: Vec<Arc<str>>,
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
        let arc: Arc<str> = Arc::from(s);
        self.strings.push(arc.clone());
        self.map.insert(arc, id);
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
        self.strings.get(id.0 as usize).map(|s| &**s)
    }

    /// Resolves a StrId to a refcounted handle (O(1) refcount bump, no
    /// allocation). Used by hot paths (the DFS result emission) that
    /// need to ship owned-shaped values out of a borrow scope without
    /// paying for `String::from`.
    #[inline]
    pub fn resolve_arc(&self, id: StrId) -> Arc<str> {
        self.strings
            .get(id.0 as usize)
            .cloned()
            .unwrap_or_else(|| Arc::from("<invalid>"))
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

    /// Snapshot of interner memory usage (unique strings + approx
    /// byte total). Callers that hold a concrete `StringInterner`
    /// can read this without importing
    /// [`StringInternerBackend`]; the inherent method delegates to
    /// the trait impl.
    pub fn metrics(&self) -> InternerMetrics {
        <Self as StringInternerBackend>::metrics(self)
    }
}

impl Default for StringInterner {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of interner memory / capacity used — surfaced via
/// [`StringInternerBackend::metrics`] so operators can decide when to
/// switch to a different impl (generational or partitioned) per the
/// P2-F plan. Keep the fields additive — adding a new one is a minor
/// release, removing one is a major one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InternerMetrics {
    /// Number of unique strings currently interned.
    pub unique_strings: usize,
    /// Approximate total bytes held by the string content (sum of
    /// `Arc<str>` lengths). Excludes allocator overhead and the
    /// hashmap index, which would roughly double this figure — as a
    /// trigger metric it's close enough to the real RAM impact.
    pub approx_bytes: usize,
}

/// The seam (P2-F foundation).
///
/// `StringInterner` is currently the only impl; when production
/// workload evidence justifies it, [`Generational`](#future-impls)
/// and partitioned variants drop in behind this trait without
/// touching the 121+ `&StringInterner` references scattered across
/// the engine.
///
/// # Future impls
///
/// * **Generational** — hot strings in RAM, cold strings on disk;
///   re-hydrate on `resolve`. Trigger: long-running streaming
///   session where unique_strings > 10M.
/// * **Partitioned** — one interner per session/tenant; cross-tenant
///   lookups explicit. Trigger: MSSP multi-tenant deployment.
pub trait StringInternerBackend {
    fn intern(&mut self, s: &str) -> StrId;
    fn resolve(&self, id: StrId) -> &str;
    fn try_resolve(&self, id: StrId) -> Option<&str>;
    fn get(&self, s: &str) -> Option<StrId>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool;
    fn reserve(&mut self, additional: usize);
    fn metrics(&self) -> InternerMetrics;
}

impl StringInternerBackend for StringInterner {
    fn intern(&mut self, s: &str) -> StrId {
        StringInterner::intern(self, s)
    }
    fn resolve(&self, id: StrId) -> &str {
        StringInterner::resolve(self, id)
    }
    fn try_resolve(&self, id: StrId) -> Option<&str> {
        StringInterner::try_resolve(self, id)
    }
    fn get(&self, s: &str) -> Option<StrId> {
        StringInterner::get(self, s)
    }
    fn len(&self) -> usize {
        StringInterner::len(self)
    }
    fn is_empty(&self) -> bool {
        StringInterner::is_empty(self)
    }
    fn reserve(&mut self, additional: usize) {
        StringInterner::reserve(self, additional)
    }
    fn metrics(&self) -> InternerMetrics {
        InternerMetrics {
            unique_strings: self.strings.len(),
            approx_bytes: self.strings.iter().map(|s| s.len()).sum(),
        }
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

    #[test]
    fn metrics_track_unique_strings_and_bytes() {
        let mut interner = StringInterner::new();
        assert_eq!(
            interner.metrics(),
            InternerMetrics {
                unique_strings: 0,
                approx_bytes: 0,
            }
        );
        interner.intern("hello");
        interner.intern("world");
        interner.intern("hello"); // dup — must not double-count bytes
        let m = interner.metrics();
        assert_eq!(m.unique_strings, 2);
        assert_eq!(m.approx_bytes, 5 + 5);
    }

    #[test]
    fn trait_methods_delegate_to_concrete_impl() {
        // Callers that hold a `&mut dyn StringInternerBackend` (e.g.
        // a future swappable interner) must see the same semantics as
        // the concrete struct. If this test fails, the trait impl
        // drifted away from the inherent methods.
        let mut concrete = StringInterner::new();
        let id_concrete = concrete.intern("foo");
        let direct_resolve = concrete.resolve(id_concrete).to_string();

        let dyn_ref: &dyn StringInternerBackend = &concrete;
        assert_eq!(dyn_ref.resolve(id_concrete), direct_resolve);
        assert_eq!(dyn_ref.get("foo"), Some(id_concrete));
        assert_eq!(dyn_ref.len(), 1);
        assert_eq!(dyn_ref.metrics().unique_strings, 1);
    }
}
