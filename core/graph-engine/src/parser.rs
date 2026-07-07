use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use graph_hunter_dsl::types::{EntityType, RelationType};

use crate::drift::DriftSnapshot;
use crate::entity::Entity;
use crate::relation::Relation;

// Re-export ParseError so call sites can write `use graph_hunter_core::parser::ParseError;`
// alongside the trait, matching the existing ergonomics of `ParsedTriple` /
// `ParseStats` / `RawIngestEvent`.
pub use crate::parse_error::ParseError;

/// A triple produced by parsing a single log event:
/// (source entity, relation, destination entity).
pub type ParsedTriple = (Entity, Relation, Entity);

/// Flat representation of a single (src, rel, dst) triple emitted by a
/// parser, sized to skip the Entity/Relation struct overhead that the
/// legacy `ParsedTriple` carries.
///
/// Why: per process_create the legacy path allocates ~5 structs (2-3
/// `Entity`, 1-2 `Relation`) plus a deep `child.clone()` of the
/// child-process Entity (HashMap deep-copy). At 700K ev/s that's
/// 3–4M struct allocations and a HashMap clone/sec — visible budget
/// in the 1.5× gap between the parse-only ceiling (~1.05M ev/s) and
/// the full ingest path (~700K ev/s).
///
/// `RawIngestEvent` keeps the data flat: each event is one triple,
/// metadata is held on whichever side it belongs to, and there is no
/// nested `Entity`/`Relation` struct or wrapper allocation. Parsers
/// that want the perf path emit `Vec<RawIngestEvent>` directly via
/// [`LogParser::parse_raw`]; the consumer is
/// `GraphHunter::insert_raw_events`.
///
/// Existing callers of `parse(&str) -> Vec<ParsedTriple>` continue to
/// work unchanged — `parse_raw` has a default implementation that
/// goes through `parse` and converts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RawIngestEvent {
    pub src_id: String,
    pub src_type: EntityType,
    pub src_metadata: HashMap<String, String>,
    pub dst_id: String,
    pub dst_type: EntityType,
    pub dst_metadata: HashMap<String, String>,
    pub rel_type: RelationType,
    pub rel_metadata: HashMap<String, String>,
    pub timestamp: i64,
}

impl RawIngestEvent {
    /// Lift a legacy `ParsedTriple` into the flat shape. Used by the
    /// default `LogParser::parse_raw` implementation so parsers that
    /// haven't been migrated still flow through the new ingest path.
    pub fn from_parsed_triple((src, rel, dst): ParsedTriple) -> Self {
        Self {
            src_id: src.id,
            src_type: src.entity_type,
            src_metadata: src.metadata,
            dst_id: dst.id,
            dst_type: dst.entity_type,
            dst_metadata: dst.metadata,
            rel_type: rel.rel_type,
            rel_metadata: rel.metadata,
            timestamp: rel.timestamp,
        }
    }
}

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
    ///
    /// **Silent-drop note (RH-P1-012).** Implementations of this method
    /// drop malformed rows on the floor. That made DLQ routing impossible
    /// because there was no failure channel — Unit 18 / `audit-findings/
    /// F-ingest.md` flagged it as the root cause of silent ingest
    /// failures. New code should call [`try_parse`](Self::try_parse)
    /// instead, which surfaces per-row [`ParseError`] variants that the
    /// ingest pipeline routes to the DLQ surface. `parse` remains
    /// unchanged so existing impls keep compiling.
    fn parse(&self, data: &str) -> Vec<ParsedTriple>;

    /// Per-row Result variant of [`parse`](Self::parse): each entry is
    /// either a valid triple or a [`ParseError`] explaining why that row
    /// failed.
    ///
    /// The default implementation wraps `parse(...)` and lifts every
    /// produced triple into `Ok(_)` — that preserves backward compatibility
    /// for the 13 existing `impl LogParser` sites without code changes.
    /// Parsers that want to surface real malformed-row errors should
    /// override this with row-by-row error emission so callers can route
    /// failures to the DLQ instead of silently dropping them.
    ///
    /// **Callers.** `platform/api/src/operations/ingestion.rs` (Phase 7
    /// migration) inspects each result and:
    /// - `Ok(triple)` → inserted into the graph as before;
    /// - `Err(ParseError::...)` → enqueued into the parse-DLQ table with
    ///   the `Display` rendering as the human reason.
    ///
    /// Added in the release-handoff cycle (RH-P1-012). See
    /// `core/graph-engine/src/parse_error.rs` for the variant catalogue.
    fn try_parse(&self, data: &str) -> Vec<Result<ParsedTriple, ParseError>> {
        // Default: lift every produced triple into Ok. Parsers that have
        // been migrated to surface real errors override this.
        self.parse(data).into_iter().map(Ok).collect()
    }

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

    /// Like [`parse`] but emits flat [`RawIngestEvent`]s, one per
    /// triple. Default implementation delegates to `parse` and lifts
    /// each tuple — parsers that want the allocation savings must
    /// override.
    fn parse_raw(&self, data: &str) -> Vec<RawIngestEvent> {
        self.parse(data)
            .into_iter()
            .map(RawIngestEvent::from_parsed_triple)
            .collect()
    }

    /// Raw-event variant of [`parse_with_stats`]. Default impl wraps
    /// `parse_with_stats` and lifts each `ParsedTriple` to a
    /// `RawIngestEvent` (an O(n) struct move with no allocations).
    /// Parsers that want the parser-side allocation savings should
    /// override this with a typed-fast-path implementation.
    ///
    /// **Stats fidelity tradeoff.** Native overrides typically use
    /// the typed scratch fast-path (e.g. `SysmonEventTyped` for
    /// SysmonJsonParser) which doesn't materialize a
    /// `serde_json::Value` per event. Without a `Value`, the
    /// `per_field_occurrence`, `skip_reasons`, and
    /// `skipped_samples` fields can't be populated cheaply — those
    /// inspections rely on `Value::as_object()` / cell-by-cell
    /// scanning. Native overrides may leave those fields empty and
    /// only populate `rows_seen`, `rows_with_triples`,
    /// `rows_skipped`, and `drift`. The UI gracefully degrades:
    /// empty maps render as "not reported", not "all zero".
    /// Callers that need full per-field stats should call
    /// `parse_with_stats` instead.
    fn parse_raw_with_stats(&self, data: &str) -> (Vec<RawIngestEvent>, ParseStats) {
        let (triples, stats) = self.parse_with_stats(data);
        let events: Vec<RawIngestEvent> = triples
            .into_iter()
            .map(RawIngestEvent::from_parsed_triple)
            .collect();
        (events, stats)
    }
}
