use rayon::prelude::*;
use serde_json::{Map, Value};

use crate::generic::GenericParser;
use crate::parser::{LogParser, ParsedTriple};

/// CSV log parser.
///
/// Parses CSV files with headers. Each row is converted to a JSON object
/// (header→value mapping) and then delegated to `GenericParser::parse_event()`
/// for field normalization and relationship inference.
///
/// Handles:
/// - Standard CSV with header row
/// - Quoted fields (including commas inside quotes)
/// - Multi-line quoted fields (newline inside `"..."` doesn't end the row)
/// - Alternate delimiters: auto-detects `,`, `\t`, `;`, `|` from the header
///   and first few data rows. A single explicit delimiter can be forced via
///   [`CsvParser::parse_with_delimiter`].
/// - UTF-8 BOM at the start of the file
/// - Duplicate headers (flagged via `ParseStats.skip_reasons["duplicate_header"]`;
///   the second occurrence silently overwrites, so downstream triples come
///   from the last column, matching prior behavior — the flag is purely
///   diagnostic so the UI can surface the problem)
/// - Empty fields
/// - Mismatched column counts (extra columns ignored, missing filled with empty)
pub struct CsvParser;

/// Candidate single-byte delimiters, ordered by heuristic prior. Tab beats
/// comma when the header consistently has more tabs, semicolon beats the
/// rest on European exports, pipe on Zoho and some SaaS exports.
const CANDIDATE_DELIMITERS: &[char] = &[',', '\t', ';', '|'];

impl CsvParser {
    /// Strips the UTF-8 byte-order mark (`\u{FEFF}`) from the start of `s`
    /// if present. A leading BOM corrupts the first header name, which then
    /// fails canonical matching and tanks the whole file silently.
    fn strip_bom(s: &str) -> &str {
        s.strip_prefix('\u{feff}').unwrap_or(s)
    }

    /// Splits a single logical CSV line (already joined across quoted
    /// newlines) into fields using `delim` as the separator. Handles
    /// doubled-quote escapes (`""` → literal `"`).
    fn split_line(line: &str, delim: char) -> Vec<String> {
        let mut fields = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let mut chars = line.chars().peekable();

        while let Some(ch) = chars.next() {
            if in_quotes {
                if ch == '"' {
                    if chars.peek() == Some(&'"') {
                        current.push('"');
                        chars.next();
                    } else {
                        in_quotes = false;
                    }
                } else {
                    current.push(ch);
                }
            } else if ch == '"' {
                in_quotes = true;
            } else if ch == delim {
                fields.push(current.trim().to_string());
                current = String::new();
            } else {
                current.push(ch);
            }
        }

        fields.push(current.trim().to_string());
        fields
    }

    /// Splits `data` into *logical* CSV rows, joining lines that fall
    /// inside an unclosed `"..."` block. Works byte-by-byte so multi-line
    /// quoted fields survive intact.
    fn logical_rows(data: &str) -> Vec<String> {
        let mut rows: Vec<String> = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let mut chars = data.chars().peekable();
        while let Some(ch) = chars.next() {
            match ch {
                '"' => {
                    // Track escaped quotes ("") so they don't flip the flag.
                    if in_quotes && chars.peek() == Some(&'"') {
                        current.push('"');
                        current.push('"');
                        chars.next();
                    } else {
                        current.push('"');
                        in_quotes = !in_quotes;
                    }
                }
                '\n' if !in_quotes => {
                    // Strip optional preceding \r for CRLF files.
                    if current.ends_with('\r') {
                        current.pop();
                    }
                    if !current.trim().is_empty() {
                        rows.push(std::mem::take(&mut current));
                    } else {
                        current.clear();
                    }
                }
                _ => current.push(ch),
            }
        }
        if !current.trim().is_empty() {
            rows.push(current);
        }
        rows
    }

    /// Scores each candidate delimiter against the header + up to 3 data
    /// rows and returns the one with the most consistent column count
    /// (≥2 columns). Falls back to `,` when nothing scores.
    fn detect_delimiter(rows: &[String]) -> char {
        if rows.is_empty() {
            return ',';
        }
        let sample_count = rows.len().min(4);
        let mut best: Option<(char, usize, usize)> = None;
        for &d in CANDIDATE_DELIMITERS {
            // Split the header against this delimiter; record the column
            // count and how many of the next (sample_count - 1) rows agree.
            let header_cols = Self::split_line(&rows[0], d).len();
            if header_cols < 2 {
                continue;
            }
            let mut agreeing = 1usize;
            for row in rows.iter().take(sample_count).skip(1) {
                if Self::split_line(row, d).len() == header_cols {
                    agreeing += 1;
                }
            }
            let score = agreeing * 100 + header_cols;
            match best {
                None => best = Some((d, header_cols, score)),
                Some((_, _, best_score)) if score > best_score => {
                    best = Some((d, header_cols, score));
                }
                _ => {}
            }
        }
        best.map(|(d, _, _)| d).unwrap_or(',')
    }

    /// Returns up to `limit` CSV rows as JSON objects. Used by preview flows
    /// that need sample values per column, not just headers.
    pub fn sample_events(data: &str, limit: usize) -> Vec<Value> {
        let stripped = Self::strip_bom(data);
        let trimmed = stripped.trim();
        if trimmed.is_empty() || limit == 0 {
            return Vec::new();
        }
        let logical = Self::logical_rows(trimmed);
        if logical.is_empty() {
            return Vec::new();
        }
        let delim = Self::detect_delimiter(&logical);
        let headers = Self::split_line(&logical[0], delim);
        if headers.is_empty() || headers.iter().all(|h| h.is_empty()) {
            return Vec::new();
        }
        logical
            .iter()
            .skip(1)
            .take(limit)
            .map(|row| {
                let values = Self::split_line(row, delim);
                Self::row_to_json(&headers, &values)
            })
            .collect()
    }

    /// Converts a CSV row (with headers) into a serde_json::Value object.
    fn row_to_json(headers: &[String], values: &[String]) -> Value {
        let mut map = Map::new();
        for (i, header) in headers.iter().enumerate() {
            if header.is_empty() {
                continue;
            }
            let val = values.get(i).map(|s| s.as_str()).unwrap_or("");
            if !val.is_empty() {
                // Duplicate headers silently overwrite — matches prior
                // behavior. The diagnostic is surfaced separately via
                // `collect_rows_with_diagnostics`.
                map.insert(header.clone(), Value::String(val.to_string()));
            }
        }
        Value::Object(map)
    }

    /// Counts duplicate header names (case-sensitive). Returns 0 when all
    /// names are unique. Blank headers are ignored.
    fn count_duplicate_headers(headers: &[String]) -> usize {
        use std::collections::HashMap;
        let mut seen: HashMap<&str, usize> = HashMap::new();
        for h in headers {
            if !h.is_empty() {
                *seen.entry(h.as_str()).or_insert(0) += 1;
            }
        }
        seen.values().filter(|&&n| n > 1).map(|&n| n - 1).sum()
    }

    /// Shared row-collection helper used by both `parse` and
    /// `parse_with_stats`. Returns (rows, detected_delimiter,
    /// duplicate_header_count, headers).
    fn collect_rows_with_diagnostics(
        data: &str,
        override_delim: Option<char>,
    ) -> (Vec<Value>, char, usize, Vec<String>) {
        let stripped = Self::strip_bom(data);
        let trimmed = stripped.trim();
        if trimmed.is_empty() {
            return (Vec::new(), ',', 0, Vec::new());
        }
        let logical = Self::logical_rows(trimmed);
        if logical.is_empty() {
            return (Vec::new(), ',', 0, Vec::new());
        }
        let delim = override_delim.unwrap_or_else(|| Self::detect_delimiter(&logical));
        let headers = Self::split_line(&logical[0], delim);
        if headers.is_empty() || headers.iter().all(|h| h.is_empty()) {
            return (Vec::new(), delim, 0, Vec::new());
        }
        let dup_count = Self::count_duplicate_headers(&headers);
        let rows = logical
            .iter()
            .skip(1)
            .map(|row| {
                let values = Self::split_line(row, delim);
                Self::row_to_json(&headers, &values)
            })
            .collect();
        (rows, delim, dup_count, headers)
    }

    fn collect_rows(data: &str) -> Vec<Value> {
        Self::collect_rows_with_diagnostics(data, None).0
    }

    /// Parse with an explicit delimiter override. The API layer uses this
    /// when the user picks a delimiter in the preview UI.
    pub fn parse_with_delimiter(data: &str, delim: char) -> Vec<ParsedTriple> {
        let (rows, _, _, _) = Self::collect_rows_with_diagnostics(data, Some(delim));
        if rows.is_empty() {
            return Vec::new();
        }
        rows.par_iter()
            .flat_map(|row| GenericParser::parse_event(row))
            .collect()
    }

    /// Parse with an explicit delimiter override, returning stats.
    pub fn parse_with_delimiter_stats(
        data: &str,
        delim: char,
    ) -> (Vec<ParsedTriple>, crate::parser::ParseStats) {
        let (rows, _, dup_count, _) = Self::collect_rows_with_diagnostics(data, Some(delim));
        let (triples, mut stats) =
            crate::generic::parse_events_with_stats(&rows, |ev| GenericParser::parse_event(ev));
        if dup_count > 0 {
            stats
                .skip_reasons
                .insert("duplicate_header".to_string(), dup_count);
        }
        (triples, stats)
    }

    /// Auto-detects the delimiter used in `data`. Returns `,` for empty
    /// input or ambiguous content.
    pub fn detect_delimiter_for(data: &str) -> char {
        let stripped = Self::strip_bom(data);
        let trimmed = stripped.trim();
        if trimmed.is_empty() {
            return ',';
        }
        let logical = Self::logical_rows(trimmed);
        if logical.is_empty() {
            return ',';
        }
        Self::detect_delimiter(&logical)
    }
}

impl LogParser for CsvParser {
    fn parse(&self, data: &str) -> Vec<ParsedTriple> {
        let rows = Self::collect_rows(data);
        if rows.is_empty() {
            return Vec::new();
        }
        rows.par_iter()
            .flat_map(|row| GenericParser::parse_event(row))
            .collect()
    }

    fn parse_with_stats(&self, data: &str) -> (Vec<ParsedTriple>, crate::parser::ParseStats) {
        let (rows, _, dup_count, _) = Self::collect_rows_with_diagnostics(data, None);
        let (triples, mut stats) =
            crate::generic::parse_events_with_stats(&rows, |ev| GenericParser::parse_event(ev));
        if dup_count > 0 {
            // `duplicate_header` is purely diagnostic — it does not
            // represent a skipped row (the row still parsed; one column
            // was overwritten). Parsed separately so the invariant
            // `sum(skip_reasons) == rows_skipped` still holds for the
            // skip-bucketing caller: we keep duplicate_header in a
            // parallel channel by NOT adding it to rows_skipped.
            stats
                .skip_reasons
                .insert("duplicate_header".to_string(), dup_count);
        }
        (triples, stats)
    }
}
