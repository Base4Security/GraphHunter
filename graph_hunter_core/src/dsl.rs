//! Hypothesis DSL parser.
//!
//! Parses arrow-chain syntax into a `Hypothesis`:
//!
//! ```text
//! User -[Auth]-> Host -[Execute]-> Process -[Spawn]-> Process
//! ```
//!
//! Supports `*` as wildcard for any entity or relation type:
//!
//! ```text
//! * -[Execute]-> Process
//! User -[*]-> *
//! ```

use crate::hypothesis::{Hypothesis, HypothesisStep};
use crate::types::{EntityType, RelationType};
use serde::Serialize;
use std::str::FromStr;

/// DSL parse error with position information.
#[derive(Debug, Clone, Serialize)]
pub struct DslError {
    pub message: String,
    pub position: usize,
}

impl std::fmt::Display for DslError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "at position {}: {}", self.position, self.message)
    }
}

/// Result of a successful DSL parse.
#[derive(Debug, Clone, Serialize)]
pub struct DslParseResult {
    pub hypothesis: Hypothesis,
    pub formatted: String,
}

/// Parses a DSL string into a Hypothesis.
///
/// Syntax: `EntityType -[RelationType]-> EntityType -[RelationType]-> EntityType ...`
///
/// Entity types: IP, Host, User, Process, File, Domain, Registry, URL, Service, *
/// Relation types: Auth, Connect, Execute, Read, Write, DNS, Modify, Spawn, Delete, *
pub fn parse_dsl(input: &str, name: Option<&str>) -> Result<DslParseResult, DslError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(DslError {
            message: "Empty chain".to_string(),
            position: 0,
        });
    }

    let mut parser = DslParser::new(input);
    let hypothesis = parser.parse(name.unwrap_or("DSL Hypothesis"))?;
    let formatted = format_hypothesis(&hypothesis);

    Ok(DslParseResult {
        hypothesis,
        formatted,
    })
}

/// Formats a Hypothesis back into DSL arrow-chain syntax.
/// Appends `{k=N}` suffix when k_simplicity > 1.
pub fn format_hypothesis(h: &Hypothesis) -> String {
    if h.steps.is_empty() {
        return String::new();
    }
    let mut out = format!("{}", h.steps[0].origin_type);
    for step in &h.steps {
        out.push_str(&format!(" -[{}]-> {}", step.relation_type, step.dest_type));
    }
    if h.k_simplicity > 1 {
        out.push_str(&format!(" {{k={}}}", h.k_simplicity));
    }
    out
}

struct DslParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> DslParser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len() {
            let ch = self.input.as_bytes()[self.pos];
            if ch == b' ' || ch == b'\t' || ch == b'\n' || ch == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        if self.pos < self.input.len() {
            Some(self.input.as_bytes()[self.pos])
        } else {
            None
        }
    }

    fn expect_str(&mut self, s: &str) -> Result<(), DslError> {
        if self.input[self.pos..].starts_with(s) {
            self.pos += s.len();
            Ok(())
        } else {
            Err(DslError {
                message: format!("Expected '{}'", s),
                position: self.pos,
            })
        }
    }

    fn parse_identifier(&mut self) -> Result<&'a str, DslError> {
        self.skip_whitespace();
        let start = self.pos;

        // Handle wildcard
        if self.peek() == Some(b'*') {
            self.pos += 1;
            return Ok("*");
        }

        while self.pos < self.input.len() {
            let ch = self.input.as_bytes()[self.pos];
            if ch.is_ascii_alphanumeric() || ch == b'_' {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err(DslError {
                message: "Expected type name or '*'".to_string(),
                position: self.pos,
            });
        }
        Ok(&self.input[start..self.pos])
    }

    fn parse_entity_type(&mut self) -> Result<EntityType, DslError> {
        let pos = self.pos;
        let name = self.parse_identifier()?;
        EntityType::from_str(name).map_err(|_| DslError {
            message: format!("Unknown entity type: '{}'. Valid: IP, Host, User, Process, File, Domain, Registry, URL, Service, *", name),
            position: pos,
        })
    }

    fn parse_relation_type(&mut self) -> Result<RelationType, DslError> {
        let pos = self.pos;
        let name = self.parse_identifier()?;
        RelationType::from_str(name).map_err(|_| DslError {
            message: format!("Unknown relation type: '{}'. Valid: Auth, Connect, Execute, Read, Write, DNS, Modify, Spawn, Delete, *", name),
            position: pos,
        })
    }

    /// Parses: `-[RelationType]->`
    fn parse_arrow(&mut self) -> Result<RelationType, DslError> {
        self.skip_whitespace();
        self.expect_str("-[")?;
        self.skip_whitespace();
        let rel = self.parse_relation_type()?;
        self.skip_whitespace();
        self.expect_str("]->")?;
        Ok(rel)
    }

    /// Tries to parse an optional `{k=N}` suffix. Returns 1 if not present.
    fn try_parse_k_suffix(&mut self) -> Result<usize, DslError> {
        self.skip_whitespace();
        if self.pos >= self.input.len() || self.peek() != Some(b'{') {
            return Ok(1);
        }
        let start = self.pos;
        self.pos += 1; // consume '{'
        self.skip_whitespace();

        // Expect 'k'
        if self.peek() != Some(b'k') {
            return Err(DslError {
                message: "Expected 'k' after '{'".to_string(),
                position: self.pos,
            });
        }
        self.pos += 1;
        self.skip_whitespace();

        // Expect '='
        if self.peek() != Some(b'=') {
            return Err(DslError {
                message: "Expected '=' after 'k'".to_string(),
                position: self.pos,
            });
        }
        self.pos += 1;
        self.skip_whitespace();

        // Parse number
        let num_start = self.pos;
        while self.pos < self.input.len() && self.input.as_bytes()[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        if self.pos == num_start {
            return Err(DslError {
                message: "Expected number after 'k='".to_string(),
                position: self.pos,
            });
        }
        let k: usize = self.input[num_start..self.pos].parse().map_err(|_| DslError {
            message: "Invalid k value".to_string(),
            position: num_start,
        })?;
        if k == 0 {
            return Err(DslError {
                message: "k must be >= 1".to_string(),
                position: start,
            });
        }
        self.skip_whitespace();

        // Expect '}'
        if self.peek() != Some(b'}') {
            return Err(DslError {
                message: "Expected '}' to close k-simplicity".to_string(),
                position: self.pos,
            });
        }
        self.pos += 1;

        Ok(k)
    }

    fn parse(&mut self, name: &str) -> Result<Hypothesis, DslError> {
        let first_entity = self.parse_entity_type()?;
        let mut steps = Vec::new();
        let mut prev_type = first_entity;

        loop {
            self.skip_whitespace();
            if self.pos >= self.input.len() {
                break;
            }

            // Check if next token is a {k=N} suffix (not another arrow step)
            if self.peek() == Some(b'{') {
                break;
            }

            // Check if next char starts an arrow
            if self.peek() != Some(b'-') {
                return Err(DslError {
                    message: format!("Expected '-[' or end of input, found '{}'", &self.input[self.pos..self.pos + 1]),
                    position: self.pos,
                });
            }

            let rel = self.parse_arrow()?;
            self.skip_whitespace();
            let dest = self.parse_entity_type()?;

            steps.push(HypothesisStep::new(
                prev_type.clone(),
                rel,
                dest.clone(),
            ));
            prev_type = dest;
        }

        if steps.is_empty() {
            return Err(DslError {
                message: "Chain must have at least one step (e.g., 'User -[Auth]-> Host')".to_string(),
                position: 0,
            });
        }

        // Parse optional {k=N} suffix for k-simplicity
        let k_simplicity = self.try_parse_k_suffix()?;

        Ok(Hypothesis {
            name: name.to_string(),
            steps,
            k_simplicity,
        })
    }
}
