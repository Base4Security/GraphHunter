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
/// - Empty fields
/// - Mismatched column counts (extra columns ignored, missing filled with empty)
pub struct CsvParser;

impl CsvParser {
    /// Splits a CSV line respecting quoted fields.
    fn split_csv_line(line: &str) -> Vec<String> {
        let mut fields = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let mut chars = line.chars().peekable();

        while let Some(ch) = chars.next() {
            if in_quotes {
                if ch == '"' {
                    // Check for escaped quote ("")
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
            } else if ch == ',' {
                fields.push(current.trim().to_string());
                current = String::new();
            } else {
                current.push(ch);
            }
        }

        fields.push(current.trim().to_string());
        fields
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
                map.insert(header.clone(), Value::String(val.to_string()));
            }
        }
        Value::Object(map)
    }
}

impl LogParser for CsvParser {
    fn parse(&self, data: &str) -> Vec<ParsedTriple> {
        let trimmed = data.trim();
        if trimmed.is_empty() {
            return Vec::new();
        }

        let mut lines = trimmed.lines();

        // First line = headers
        let header_line = match lines.next() {
            Some(l) => l,
            None => return Vec::new(),
        };
        let headers = CsvParser::split_csv_line(header_line);

        if headers.is_empty() || headers.iter().all(|h| h.is_empty()) {
            return Vec::new();
        }

        // Collect data rows into JSON objects
        let rows: Vec<Value> = lines
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let values = CsvParser::split_csv_line(line);
                CsvParser::row_to_json(&headers, &values)
            })
            .collect();

        if rows.is_empty() {
            return Vec::new();
        }

        rows.par_iter()
            .flat_map(|row| GenericParser::parse_event(row))
            .collect()
    }
}
