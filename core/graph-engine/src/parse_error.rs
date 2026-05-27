//! `ParseError` — per-row failure surface for [`crate::parser::LogParser::try_parse`].
//!
//! # Why this exists (RH-P1-012)
//!
//! The original `LogParser::parse(&str) -> Vec<ParsedTriple>` signature has
//! no failure channel — every implementation silently drops malformed rows.
//! Unit 18 (PR #75, `audit-findings/F-ingest.md`) tagged that as the root
//! cause of silent ingest failures: malformed rows never reached the DLQ
//! surface, which only handles INSERTION failures, not parse failures.
//!
//! `try_parse` (added in the same release-handoff cycle) returns
//! `Vec<Result<ParsedTriple, ParseError>>` so callers in
//! `platform/api/src/operations/ingestion.rs` can route `Err(_)` to the
//! DLQ instead of dropping them on the floor. The legacy `parse` signature
//! remains unchanged — `try_parse` has a default implementation that lifts
//! every `parse` result into `Ok(_)`, so the 13 existing `impl LogParser`
//! sites keep compiling without modification. Per-source overrides
//! (currently `IisW3cParser`, `GenericLogParser`, plus tests in
//! `SentinelJsonParser`) surface real `Err` variants.
//!
//! # Variants — design intent
//!
//! - `MalformedRow { line, reason }` — row split or shape failed; the most
//!   common per-row failure across line-oriented parsers (IIS W3C, CSV,
//!   FortiAnalyzer, generic CSV/TSV).
//! - `FieldType { field, expected, got }` — a field was present but couldn't
//!   be coerced to the expected type (e.g. timestamp, IP, integer). Lets
//!   the DLQ explain "got `'abc'` where IP was expected" instead of just
//!   "malformed".
//! - `MissingField(String)` — a required canonical field was absent. Used by
//!   JSON-shape parsers (Sentinel, Sysmon) where the field exists in the
//!   schema but the event omitted it.
//! - `Encoding(String)` — non-UTF8, invalid base64, etc.
//! - `SourceSpecific(Box<dyn Error>)` — escape hatch for one-off failures
//!   that don't fit the canonical variants (e.g. quick-xml errors from
//!   `FortiAnalyzerParser`). The `Box<dyn Error + Send + Sync + 'static>`
//!   bound lets the DLQ entry surface the underlying error via
//!   `Display`/`source()` without each parser inventing its own enum.

use thiserror::Error;

/// Per-row parse failure surfaced by [`crate::parser::LogParser::try_parse`].
///
/// See module-level docs for the design rationale (RH-P1-012). The variants
/// are intentionally coarse — they exist to give the DLQ enough context to
/// classify drop reasons, not to enable parser-side recovery.
#[derive(Debug, Error)]
pub enum ParseError {
    /// Row split or shape failed (wrong field count, missing delimiters,
    /// unexpected line prefix). The `line` is 0-based as emitted by
    /// `str::lines().enumerate()`.
    #[error("malformed row at line {line}: {reason}")]
    MalformedRow {
        /// 0-based line index within the input passed to `try_parse`.
        line: usize,
        /// Short human-readable explanation. Kept under ~120 chars so the
        /// DLQ table renders cleanly.
        reason: String,
    },

    /// A field was present but couldn't be coerced to the expected type
    /// (e.g. invalid IP, non-numeric port, malformed timestamp).
    #[error("unexpected field type at {field}: expected {expected}, got {got}")]
    FieldType {
        /// Canonical or raw field name where coercion failed.
        field: String,
        /// What the parser was trying to parse it as ("ip", "timestamp", "u16").
        expected: String,
        /// Truncated representation of what was actually there.
        got: String,
    },

    /// A field required by the parser's contract was absent from the row.
    /// Distinct from `MalformedRow` because the row's overall shape was
    /// valid — just one expected field was missing.
    #[error("missing required field: {0}")]
    MissingField(String),

    /// Non-UTF8 bytes, invalid base64, gzip header corruption, etc. — any
    /// failure before the row could be split into fields.
    #[error("encoding error: {0}")]
    Encoding(String),

    /// Escape hatch for source-specific errors (e.g. quick-xml parse error
    /// from FortiAnalyzer). The boxed `Error` lets the DLQ surface the
    /// underlying error chain without each parser inventing its own enum.
    #[error("source-specific error: {0}")]
    SourceSpecific(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl ParseError {
    /// Extract the line number if this is a `MalformedRow`. Callers
    /// (typically the DLQ formatter) use this to build a `parse_error:42`
    /// pointer back into the original input.
    pub fn line(&self) -> Option<usize> {
        match self {
            ParseError::MalformedRow { line, .. } => Some(*line),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_shapes_match_expected() {
        let e = ParseError::MalformedRow {
            line: 7,
            reason: "expected 3 tabs, got 1".into(),
        };
        assert_eq!(
            format!("{}", e),
            "malformed row at line 7: expected 3 tabs, got 1"
        );

        let e = ParseError::FieldType {
            field: "src_ip".into(),
            expected: "ip".into(),
            got: "abc".into(),
        };
        assert_eq!(
            format!("{}", e),
            "unexpected field type at src_ip: expected ip, got abc"
        );

        let e = ParseError::MissingField("timestamp".into());
        assert_eq!(format!("{}", e), "missing required field: timestamp");
    }

    #[test]
    fn line_extracts_malformed_row_line() {
        let e = ParseError::MalformedRow {
            line: 42,
            reason: "x".into(),
        };
        assert_eq!(e.line(), Some(42));

        let e = ParseError::MissingField("t".into());
        assert_eq!(e.line(), None);
    }
}
