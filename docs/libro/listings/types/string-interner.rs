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
