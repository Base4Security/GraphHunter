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
    ///
    /// Also strips a literal two-character `\n` / `\r` escape (backslash + letter)
    /// ahead of the BOM or header. An Auth0 export re-sorted by a script arrived as
    /// `\n` + BOM + `timestamp,...`: the first column became `\n\u{feff}timestamp`,
    /// and 2.2 GB of rows lost their event time without a single error. A real
    /// header cell never starts with a backslash escape, so this is safe.
    fn strip_bom(s: &str) -> &str {
        let mut s = s;
        loop {
            let next = s
                .strip_prefix('\u{feff}')
                .or_else(|| s.strip_prefix("\\r\\n"))
                .or_else(|| s.strip_prefix("\\n"))
                .or_else(|| s.strip_prefix("\\r"));
            match next {
                Some(rest) => s = rest,
                None => return s,
            }
        }
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

    /// Detects and unwraps a *double-encoded* CSV: the header row is normal,
    /// but every data row was re-serialized as a single quoted CSV field
    /// (each `"` doubled), so a standard parser sees one giant cell per row.
    /// Keycloak user-event exports arrive this way; the pattern also shows
    /// up when any tool CSV-escapes rows that were already CSV.
    ///
    /// A row is only unwrapped when its single field's *content* splits into
    /// exactly the header's column count — a plain CSV whose data rows split
    /// normally never qualifies, so false positives require a 1-column row
    /// that coincidentally contains a full width-matching CSV row, which a
    /// well-formed file can't produce. Returns the rows plus how many were
    /// unwrapped (surfaced as a diagnostic in `ParseStats`).
    fn unwrap_double_encoded(mut rows: Vec<String>) -> (Vec<String>, usize) {
        if rows.len() < 2 {
            return (rows, 0);
        }
        let mut chosen: Option<(char, usize)> = None;
        'candidates: for &d in CANDIDATE_DELIMITERS {
            let header_cols = Self::split_line(&rows[0], d).len();
            if header_cols < 2 {
                continue;
            }
            for row in rows.iter().skip(1).take(3) {
                if !row.trim_start().starts_with('"') {
                    continue 'candidates;
                }
                let fields = Self::split_line(row, d);
                if fields.len() != 1 || Self::split_line(&fields[0], d).len() != header_cols {
                    continue 'candidates;
                }
            }
            chosen = Some((d, header_cols));
            break;
        }
        let Some((d, header_cols)) = chosen else {
            return (rows, 0);
        };
        let mut unwrapped = 0usize;
        for row in rows.iter_mut().skip(1) {
            if !row.trim_start().starts_with('"') {
                continue;
            }
            let mut fields = Self::split_line(row, d);
            if fields.len() == 1 && Self::split_line(&fields[0], d).len() == header_cols {
                *row = std::mem::take(&mut fields[0]);
                unwrapped += 1;
            }
        }
        (rows, unwrapped)
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
        let (logical, _) = Self::unwrap_double_encoded(logical);
        let delim = Self::detect_delimiter(&logical);
        let headers = Self::split_line(&logical[0], delim);
        if headers.is_empty() || headers.iter().all(|h| h.is_empty()) {
            return Vec::new();
        }
        // Row → JSON fans out over rayon: `ConfigurableParser::collect_events`
        // funnels WHOLE files through here (limit = usize::MAX), and the
        // per-row work (quote-aware split + details-JSON expansion) was the
        // single-threaded floor of CSV ingest once the triple parse went
        // parallel. For the 200-row preview the fan-out overhead is noise.
        let data_rows = &logical[1..];
        let n = data_rows.len().min(limit);
        data_rows[..n]
            .par_iter()
            .map(|row| {
                let values = Self::split_line(row, delim);
                Self::row_to_json(&headers, &values)
            })
            .collect()
    }

    /// Converts a CSV row (with headers) into a serde_json::Value object.
    ///
    /// A cell whose value is a JSON *object* (Keycloak `details`, MDE
    /// `AdditionalFields`) is expanded into flat sibling keys instead of
    /// being kept as an opaque blob: canonical field matching is by exact
    /// name (`username` → `source_user`), so neither the raw blob nor
    /// dotted keys (`details.username`) would ever surface those entities.
    /// A key that collides with a real header (or an already-inserted key)
    /// is prefixed with the cell's header (`details_error`) so it can't
    /// shadow a real column.
    fn row_to_json(headers: &[String], values: &[String]) -> Value {
        let mut map = Map::new();
        for (i, header) in headers.iter().enumerate() {
            if header.is_empty() {
                continue;
            }
            let val = values.get(i).map(|s| s.as_str()).unwrap_or("");
            if val.is_empty() {
                continue;
            }
            if val.starts_with('{') && val.ends_with('}') {
                if let Ok(Value::Object(inner)) = serde_json::from_str::<Value>(val) {
                    if !inner.is_empty() {
                        for (k, v) in inner {
                            let key = if headers.contains(&k) || map.contains_key(&k) {
                                format!("{}_{}", header, k)
                            } else {
                                k
                            };
                            let sval = match v {
                                Value::String(s) => s,
                                Value::Null => continue,
                                // Nested objects/arrays stay as compact JSON
                                // strings — deep expansion would mint dotted
                                // keys canonical matching can't use anyway.
                                other => other.to_string(),
                            };
                            if !sval.is_empty() {
                                map.insert(key, Value::String(sval));
                            }
                        }
                        continue;
                    }
                }
            }
            // Duplicate headers silently overwrite — matches prior
            // behavior. The diagnostic is surfaced separately via
            // `collect_rows_with_diagnostics`.
            map.insert(header.clone(), Value::String(val.to_string()));
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
    /// duplicate_header_count, unwrapped_double_encoded_count, headers).
    fn collect_rows_with_diagnostics(
        data: &str,
        override_delim: Option<char>,
    ) -> (Vec<Value>, char, usize, usize, Vec<String>) {
        let stripped = Self::strip_bom(data);
        let trimmed = stripped.trim();
        if trimmed.is_empty() {
            return (Vec::new(), ',', 0, 0, Vec::new());
        }
        let logical = Self::logical_rows(trimmed);
        if logical.is_empty() {
            return (Vec::new(), ',', 0, 0, Vec::new());
        }
        let (logical, unwrapped) = Self::unwrap_double_encoded(logical);
        let delim = override_delim.unwrap_or_else(|| Self::detect_delimiter(&logical));
        let headers = Self::split_line(&logical[0], delim);
        if headers.is_empty() || headers.iter().all(|h| h.is_empty()) {
            return (Vec::new(), delim, 0, unwrapped, Vec::new());
        }
        let dup_count = Self::count_duplicate_headers(&headers);
        // Parallel for the same reason as `sample_events`: this is the
        // whole-file row materialization, not a bounded preview.
        let rows = logical[1..]
            .par_iter()
            .map(|row| {
                let values = Self::split_line(row, delim);
                Self::row_to_json(&headers, &values)
            })
            .collect();
        (rows, delim, dup_count, unwrapped, headers)
    }

    fn collect_rows(data: &str) -> Vec<Value> {
        Self::collect_rows_with_diagnostics(data, None).0
    }

    /// Parse with an explicit delimiter override. The API layer uses this
    /// when the user picks a delimiter in the preview UI.
    pub fn parse_with_delimiter(data: &str, delim: char) -> Vec<ParsedTriple> {
        let (rows, _, _, _, _) = Self::collect_rows_with_diagnostics(data, Some(delim));
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
        let (rows, _, dup_count, unwrapped, _) =
            Self::collect_rows_with_diagnostics(data, Some(delim));
        let (triples, mut stats) =
            crate::generic::parse_events_with_stats(&rows, |ev| GenericParser::parse_event(ev));
        Self::insert_diagnostics(&mut stats, dup_count, unwrapped);
        (triples, stats)
    }

    /// Records the purely-diagnostic counters in `skip_reasons`. Neither
    /// entry represents a skipped row (the rows still parsed), so — like
    /// `duplicate_header` before it — `double_encoded_row` is deliberately
    /// NOT added to `rows_skipped`; it's a parallel channel for the UI.
    fn insert_diagnostics(stats: &mut crate::parser::ParseStats, dup_count: usize, unwrapped: usize) {
        if dup_count > 0 {
            stats
                .skip_reasons
                .insert("duplicate_header".to_string(), dup_count);
        }
        if unwrapped > 0 {
            stats
                .skip_reasons
                .insert("double_encoded_row".to_string(), unwrapped);
        }
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
        let (logical, _) = Self::unwrap_double_encoded(logical);
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
        let (rows, _, dup_count, unwrapped, _) = Self::collect_rows_with_diagnostics(data, None);
        let (triples, mut stats) =
            crate::generic::parse_events_with_stats(&rows, |ev| GenericParser::parse_event(ev));
        Self::insert_diagnostics(&mut stats, dup_count, unwrapped);
        (triples, stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EntityType;

    /// Keycloak user-events export shape: normal header, every data row
    /// re-serialized as ONE quoted CSV field, `details` JSON inside with
    /// quadruple-quote escaping. Mirrors the real export byte-for-byte.
    const KEYCLOAK_DOUBLE_ENCODED: &str = concat!(
        "time,type,realmId,clientId,userId,sessionId,ipAddress,error,details\n",
        r#""1785553172951,LOGIN,realm1,cliente-externo,u-123,sess-1,181.9.227.140,,""{""""auth_method"""":""""openid-connect"""",""""username"""":""""ana@example.com"""",""""error"""":""""none""""}""""#,
        "\n",
        r#""1785553134347,LOGIN_ERROR,realm1,cliente-externo,u-456,sess-2,181.228.57.40,invalid_grant,""{""""username"""":""""bob@example.com""""}""""#,
        "\n",
    );

    #[test]
    fn double_encoded_rows_unwrap_to_header_width() {
        let events = CsvParser::sample_events(KEYCLOAK_DOUBLE_ENCODED, 10);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["type"], "LOGIN");
        assert_eq!(events[0]["ipAddress"], "181.9.227.140");
        assert_eq!(events[1]["error"], "invalid_grant");
    }

    #[test]
    fn json_details_cell_expands_to_flat_keys() {
        let events = CsvParser::sample_events(KEYCLOAK_DOUBLE_ENCODED, 10);
        // Flat sibling keys so canonical matching sees them...
        assert_eq!(events[0]["username"], "ana@example.com");
        assert_eq!(events[0]["auth_method"], "openid-connect");
        // ...the raw blob is gone...
        assert!(events[0].get("details").is_none());
        // ...and a key colliding with a real header gets prefixed.
        assert_eq!(events[0]["details_error"], "none");
        assert!(events[0].get("error").is_none()); // header cell was empty
    }

    #[test]
    fn double_encoded_parse_produces_user_auth_ip_triples() {
        let triples = CsvParser.parse(KEYCLOAK_DOUBLE_ENCODED);
        let user_to_ip = triples.iter().any(|(src, _, dst)| {
            src.entity_type == EntityType::User
                && src.id.contains("ana@example.com")
                && dst.entity_type == EntityType::IP
                && dst.id == "181.9.227.140"
        });
        assert!(
            user_to_ip,
            "expected User(ana@example.com) -> IP triple, got: {:?}",
            triples
                .iter()
                .map(|(s, r, d)| (s.id.clone(), r.rel_type.clone(), d.id.clone()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn double_encoded_rows_surface_diagnostic_not_skips() {
        let (triples, stats) = CsvParser.parse_with_stats(KEYCLOAK_DOUBLE_ENCODED);
        assert!(!triples.is_empty());
        assert_eq!(stats.skip_reasons.get("double_encoded_row"), Some(&2));
    }

    #[test]
    fn detect_delimiter_sees_through_double_encoding() {
        assert_eq!(
            CsvParser::detect_delimiter_for(KEYCLOAK_DOUBLE_ENCODED),
            ','
        );
    }

    /// A well-formed CSV with quoted fields (commas + escaped quotes inside)
    /// must pass through untouched — its data rows split to the header
    /// width, so the unwrap precondition never holds.
    #[test]
    fn normal_quoted_csv_is_not_unwrapped() {
        let data = concat!(
            "name,description,city\n",
            r#"ana,"says ""hi"", loudly",rosario"#,
            "\n",
        );
        let events = CsvParser::sample_events(data, 10);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["name"], "ana");
        assert_eq!(events[0]["description"], r#"says "hi", loudly"#);
        assert_eq!(events[0]["city"], "rosario");
        let (_, stats) = CsvParser.parse_with_stats(data);
        assert!(stats.skip_reasons.get("double_encoded_row").is_none());
    }

    /// A re-sorted Auth0 export arrived as literal `\n` + BOM + header. The
    /// first column must still be `timestamp`, or every row loses its time.
    #[test]
    fn literal_newline_escape_and_bom_before_header_are_stripped() {
        let data = "\\n\u{feff}timestamp,user\n2026-08-01T00:00:00Z,ana\n";
        let events = CsvParser::sample_events(data, 10);
        assert_eq!(events[0]["timestamp"], "2026-08-01T00:00:00Z");
        assert_eq!(events[0]["user"], "ana");
    }

    /// JSON-object cells expand on ordinary (single-encoded) CSVs too —
    /// e.g. MDE timeline `AdditionalFields` — not only on unwrapped ones.
    #[test]
    fn json_cell_expands_on_plain_csv() {
        let data = concat!(
            "time,user,extra\n",
            r#"2026-08-01T00:00:00Z,ana,"{""department"":""fraud"",""mfa"":true}""#,
            "\n",
        );
        let events = CsvParser::sample_events(data, 10);
        assert_eq!(events[0]["department"], "fraud");
        // Non-string scalars are stringified to keep CSV cell semantics.
        assert_eq!(events[0]["mfa"], "true");
        assert!(events[0].get("extra").is_none());
    }
}
