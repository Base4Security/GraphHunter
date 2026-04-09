use crate::entity::Entity;
use crate::relation::Relation;

/// A triple produced by parsing a single log event:
/// (source entity, relation, destination entity).
pub type ParsedTriple = (Entity, Relation, Entity);

/// Trait for log format parsers.
///
/// Implementors convert raw log text into a vector of graph triples.
/// Each event may produce one or more triples (e.g., a process creation
/// event yields a User->Execute->Process triple AND a Process->Execute->Process
/// parent-child triple).
///
/// Parsers are expected to be stateless — all context comes from the input data.
pub trait LogParser: Send + Sync {
    /// Parses raw log data and returns extracted triples.
    ///
    /// Malformed or unrecognized events are silently skipped (logged in metadata)
    /// to allow best-effort ingestion of real-world, often messy, log sources.
    fn parse(&self, data: &str) -> Vec<ParsedTriple>;

    /// Parses pre-decoded JSON event objects directly, skipping the
    /// `string → simd_json` round-trip that `parse(&str)` performs.
    ///
    /// This exists to fix the double-parse identified in plan §3:
    /// `graph_hunter_cli::siem::sentinel_streaming::normalize_response`
    /// currently turns a Log Analytics response into a
    /// `Vec<Map<String, Value>>`, then serializes that back to a JSON
    /// string via `serde_json::to_string`, then hands it to
    /// `parse(&str)` — which immediately parses the JSON a second time.
    /// At tera-scale this round-trip is a GB-scale allocation per poll.
    ///
    /// Parsers that can be efficient should override this. The default
    /// implementation rebuilds a JSON array and delegates to `parse` so
    /// every existing parser keeps working without code changes.
    ///
    /// Added in Phase 4 of the Azure streaming plan. First real
    /// override lives on `SentinelJsonParser`.
    fn parse_rows(&self, rows: &[serde_json::Value]) -> Vec<ParsedTriple> {
        if rows.is_empty() {
            return Vec::new();
        }
        // Default fallback: serialize back to a JSON array and delegate.
        // This preserves every existing parser's behavior unchanged.
        match serde_json::to_string(&serde_json::Value::Array(rows.to_vec())) {
            Ok(s) => self.parse(&s),
            Err(_) => Vec::new(),
        }
    }
}
