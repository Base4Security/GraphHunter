# Adding a log parser

A `LogParser` converts raw log text (or pre-decoded JSON) into
graph triples `(source, relation, destination)`. Register one and
GraphHunter can ingest the format end-to-end: detection, preview,
ingest, scoring, export.

Contract of reference: `core/graph-engine/src/parser.rs::LogParser`.

## When to reach for this

- A SIEM, EDR, or cloud service emits a format GraphHunter doesn't
  already understand (check `platform/parsers/src/` for the stock
  list: Cognito, FortiAnalyzer, IIS W3C).
- You want parse-time stats (rows seen / skipped, drift snapshot)
  surfaced in the ingest dialog.
- The stock `GenericParser` heuristics don't produce useful triples
  for your source.

If your format is close to a stock one (e.g. IIS W3C variant), start
by preprocessing the input and feeding it to the existing parser
before writing a new one.

## The trait

```rust
pub trait LogParser: Send + Sync {
    fn parse(&self, data: &str) -> Vec<ParsedTriple>;

    fn parse_rows(&self, rows: &[serde_json::Value]) -> Vec<ParsedTriple> {
        // default: re-serialize and call parse(&str)
    }

    fn parse_with_stats(&self, data: &str) -> (Vec<ParsedTriple>, ParseStats) {
        // default: (self.parse(data), ParseStats::default())
    }
}
```

- `parse` is mandatory — the minimum surface.
- `parse_rows` exists to skip the `String → simd_json → String →
  simd_json` round-trip when rows are already decoded (see the
  Sentinel streaming path). Override when your parser can accept
  `serde_json::Value` directly.
- `parse_with_stats` populates the ingest UI. Override when you can
  produce `rows_seen`, `rows_skipped`, per-field occurrence, and
  `DriftSnapshot`. The UI treats an empty `ParseStats` as "not
  reported" — a legacy parser stays silent rather than fires a false
  zero-triple warning.

## Worked example: `OktaAuditParser`

### 1. Create the parser file

```
platform/parsers/src/okta_audit.rs
```

```rust
use graph_hunter_core::entity::{Entity, EntityType};
use graph_hunter_core::parser::{LogParser, ParseStats, ParsedTriple};
use graph_hunter_core::relation::{Relation, RelationType};

pub struct OktaAuditParser;

impl LogParser for OktaAuditParser {
    fn parse(&self, data: &str) -> Vec<ParsedTriple> {
        let mut triples = Vec::new();
        for line in data.lines() {
            let Ok(ev) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let actor = ev["actor"]["alternateId"].as_str().unwrap_or_default();
            let target = ev["target"][0]["alternateId"].as_str().unwrap_or_default();
            let action = ev["eventType"].as_str().unwrap_or("unknown");
            if actor.is_empty() || target.is_empty() {
                continue;
            }
            triples.push((
                Entity::new(actor, EntityType::User),
                Relation::new(RelationType::Auth).with_action(action),
                Entity::new(target, EntityType::Service),
            ));
        }
        triples
    }

    fn parse_with_stats(&self, data: &str) -> (Vec<ParsedTriple>, ParseStats) {
        let mut stats = ParseStats::default();
        let triples = self.parse(data);
        stats.rows_seen = data.lines().count();
        stats.rows_with_triples = triples.len();
        stats.rows_skipped = stats.rows_seen.saturating_sub(stats.rows_with_triples);
        (triples, stats)
    }
}
```

### 2. Export from `platform/parsers`

```
platform/parsers/src/lib.rs
```

```rust
pub mod okta_audit;
pub use okta_audit::OktaAuditParser;
```

### 3. Register with the format detector

If the parser should be picked automatically, register it in
`core/graph-engine/src/format_detector.rs` (or the app's format
registry wiring — follow the pattern of existing parsers). At
minimum, provide a `detect(sample: &str) -> bool` hook.

For user-driven selection the frontend's ingest preview already lists
every registered parser by name; no additional wiring.

### 4. Add a test

```
platform/parsers/tests/okta_audit.rs
```

```rust
use graph_hunter_parsers::OktaAuditParser;
use graph_hunter_core::parser::LogParser;

#[test]
fn parses_single_audit_line() {
    let p = OktaAuditParser;
    let data = r#"{"actor":{"alternateId":"alice@ex.com"},"target":[{"alternateId":"app"}],"eventType":"user.session.start"}"#;
    let (triples, _) = p.parse_with_stats(data);
    assert_eq!(triples.len(), 1);
    assert_eq!(triples[0].0.id, "alice@ex.com");
}
```

### 5. Verify

```
cargo test -p graph_hunter_parsers okta
```

Green? Ship it.

## Rules and invariants

### Parsers must be stateless

The ingest pipeline fans out across rayon workers and will call
`parse` concurrently. Keep implementations pure functions over the
input; no `RefCell`, no global mutation.

### Skip malformed rows silently — don't panic

Real logs have malformed lines. Skipping is the right call; panicking
aborts the whole ingest. If the skip is **unexpected** (e.g. missing
mandatory field in a well-formed record), record the reason in
`ParseStats::skip_reasons` so the UI can surface it.

### One event → one or more triples

The convention for multi-triple events: `ProcessCreate` emits a
`User -Execute-> Process` triple **and** a
`Process -Execute-> Process` parent-child triple. Check stock parsers
for the pattern.

### Don't inline field normalization

Normalization (lowercasing hostnames, stripping domain suffixes,
canonicalizing IPs) lives in `platform/canonical`, not the parser.
Emit whatever the log contains; the ingest pipeline canonicalizes
downstream.

### Report drift when you can

Parsers that iterate JSON events have the shape data to populate
`ParseStats::drift`. Populating it turns on schema-drift detection
over time — a 2-minute cost per parser that pays off every ingest.

## When a parser isn't the right tool

- The format is structured CSV with stable headers → use
  `GenericParser` + a per-source `FieldConfig` in
  `platform/canonical`.
- The format is VRL-mappable → write a VRL program under
  `platform/vrl/`; no Rust needed.
- The format needs LLM-assisted field inference → the M4 agentic
  path (`operations/agentic.rs`) covers this at ingest time.

Write a `LogParser` when: (a) the structure is fixed enough to
hard-code, and (b) throughput matters (rayon-parallel, no LLM latency
in the hot path).

## Reference

- Trait + stats shape:
  [`core/graph-engine/src/parser.rs`](../../core/graph-engine/src/parser.rs)
- Stock implementations:
  [`platform/parsers/src/`](../../platform/parsers/src/)
- Drift shape:
  [`core/graph-engine/src/drift.rs`](../../core/graph-engine/src/drift.rs)
