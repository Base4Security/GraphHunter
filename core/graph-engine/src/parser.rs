use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::drift::DriftSnapshot;
use crate::entity::Entity;
use crate::relation::Relation;

/// A triple produced by parsing a single log event:
/// (source entity, relation, destination entity).
pub type ParsedTriple = (Entity, Relation, Entity);

/// Aggregate per-ingest parsing statistics. Populated by parsers that
/// override [`LogParser::parse_with_stats`]. The default implementation
/// returns an empty `ParseStats` so legacy parsers keep working — the
/// UI treats empty stats as "unknown" rather than "zero".
///
/// Zero-triple detection and per-field coverage reporting both read off
/// this struct.
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ParseStats {
    /// Total number of input events/rows the parser actually saw. Zero
    /// means the format detector couldn't split the input at all.
    pub rows_seen: usize,
    /// Rows that produced at least one triple.
    pub rows_with_triples: usize,
    /// Rows that produced no triples. `rows_seen = rows_with_triples + rows_skipped`.
    pub rows_skipped: usize,
    /// How many sampled rows contained each raw field name. Parsers that
    /// don't emit per-field data return an empty map.
    #[serde(default)]
    pub per_field_occurrence: HashMap<String, usize>,
    /// Why rows were skipped, aggregated by reason. Keys are short machine
    /// tags like `empty_row`, `no_canonical_fields`, `no_anchor`. Sum of
    /// values equals `rows_skipped` for parsers that categorise skips;
    /// empty map for parsers that don't.
    #[serde(default)]
    pub skip_reasons: HashMap<String, usize>,
    /// Up to `N` reservoir-sampled raw JSON snippets from skipped rows,
    /// each paired with its classified reason. Capped so huge ingests
    /// don't blow up memory. Empty for parsers that don't categorise skips.
    #[serde(default)]
    pub skipped_samples: Vec<(String, String)>,
    /// Per-batch schema drift snapshot — type-tag histogram + null rate
    /// per field. Populated by parsers that iterate JSON events; `None`
    /// for parsers that cannot surface per-field shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drift: Option<DriftSnapshot>,
}

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

    /// Parses raw log data and also returns aggregate statistics about the
    /// parse (rows seen, rows producing triples, per-field occurrence).
    ///
    /// Default implementation wraps `parse(&str)` and returns an empty
    /// [`ParseStats`] — parsers that want real stats must override this.
    /// The UI treats empty stats as "not reported" rather than "all zero",
    /// so silence from a legacy parser does not trigger a false zero-triple
    /// warning.
    fn parse_with_stats(&self, data: &str) -> (Vec<ParsedTriple>, ParseStats) {
        (self.parse(data), ParseStats::default())
    }
}
