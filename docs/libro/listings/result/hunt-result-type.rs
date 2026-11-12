/// Result of a successful pattern match: an ordered list of entity IDs
/// representing the attack path through the graph.
///
/// Each element is an `Arc<str>` cloned directly from the
/// `StringInterner` storage — a refcount bump, not a string allocation.
/// On cap-saturated benches this is the difference between
/// `path.len() × String::from(...)` allocations per result (~60% of
/// `ba-any-2hop` time) and a single 4-byte refcount increment per
/// path step. Callers that need an owned `String` can `.to_string()`
/// per element; serde serialization is identical to `Vec<String>`
/// because `Arc<str>: Serialize` produces the same JSON.
pub type HuntResult = Vec<std::sync::Arc<str>>;
