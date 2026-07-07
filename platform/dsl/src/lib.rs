//! Hypothesis DSL parser + the `types` / `hypothesis` modules it parses
//! into. Lifted out of `graph_hunter_core` per F2.12. The three files
//! moved together because the dependency arrows form a tight unit:
//! `types` is self-contained, `hypothesis` consumes `types`, and the
//! DSL parser below consumes both. Separating them would have required
//! a shared foundation crate that adds more structure than the shearing
//! goal justifies.
//!
//! Everything in `graph_hunter_core` that used to reference
//! `crate::types::X`, `crate::hypothesis::Y`, or `crate::dsl::Z` keeps
//! resolving via re-exports at core's lib root
//! (`pub use graph_hunter_dsl::{types, hypothesis}` + direct item
//! re-exports for the DSL functions). The migration is therefore
//! source-compatible for the ~140 call sites inside core.
//!
//! ## DSL grammar (unchanged from pre-extraction)
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

//! # DSL v1 — stable grammar
//!
//! The arrow-chain grammar described above is **stable as of
//! 2026-04-24**. The formal semantics — match definition, WITHIN
//! window inclusivity, HAVING column resolution priority, predicate
//! absence rules — are pinned in
//! [`docs/spec/dsl-v1-semantics.md`](../../../docs/spec/dsl-v1-semantics.md).
//! Changes that would break a v1 hypothesis parse must go through an
//! ADR + spec revision.
//!
//! v2 features (strict unknown-type mode, regex predicates, richer
//! HAVING aggregations) live behind `#[cfg(feature = "dsl-v2-experimental")]`
//! when they land; v1 does not ship them.

pub mod extension;
pub mod hypothesis;
pub mod types;

use crate::extension::{DslExtension, EntityTypeRegistry, PredicateRegistry, RelationTypeRegistry};
use crate::hypothesis::{AggClause, AggColumn, Hypothesis, HypothesisStep, Predicate};
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
    DslParser::v1().parse(input, name)
}

/// Stateful DSL parser holding the three extension registries
/// (entity types, relation types, predicates). Construct with
/// [`DslParser::v1`] for the stable grammar, then chain
/// [`DslParser::with_extension`] to install custom types/predicates.
/// Parsing is `&self` — a single `DslParser` is reusable across calls
/// and cheap to clone via [`std::sync::Arc`] when shared across threads.
///
/// This is F4.3 structural wiring: the registries ride along with the
/// parser but unknown `Other(_)` entity/relation names still parse
/// successfully, preserving the pre-F4 grammar. A later phase may add
/// a strict mode that rejects unknown names.
pub struct DslParser {
    entity_types: EntityTypeRegistry,
    relation_types: RelationTypeRegistry,
    predicates: PredicateRegistry,
}

impl DslParser {
    /// Returns a parser for the v1 grammar with no extensions installed.
    /// Built-in entity and relation types are always available.
    pub fn v1() -> Self {
        Self {
            entity_types: EntityTypeRegistry::new(),
            relation_types: RelationTypeRegistry::new(),
            predicates: PredicateRegistry::new(),
        }
    }

    /// Installs a [`DslExtension`]'s entity types, relation types, and
    /// predicate evaluators into this parser. Chainable.
    pub fn with_extension<E: DslExtension>(mut self, ext: E) -> Self {
        ext.register_entity_types(&mut self.entity_types);
        ext.register_relation_types(&mut self.relation_types);
        ext.register_predicates(&mut self.predicates);
        self
    }

    /// Parses a DSL hypothesis string. Equivalent to the free
    /// [`parse_dsl`] when the parser has no extensions installed.
    pub fn parse(&self, input: &str, name: Option<&str>) -> Result<DslParseResult, DslError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(DslError {
                message: "Empty chain".to_string(),
                position: 0,
            });
        }
        let mut cursor = Cursor::new(input);
        let hypothesis = cursor.parse(name.unwrap_or("DSL Hypothesis"))?;
        let formatted = format_hypothesis(&hypothesis);
        Ok(DslParseResult {
            hypothesis,
            formatted,
        })
    }

    pub fn entity_types(&self) -> &EntityTypeRegistry {
        &self.entity_types
    }

    pub fn relation_types(&self) -> &RelationTypeRegistry {
        &self.relation_types
    }

    pub fn predicates(&self) -> &PredicateRegistry {
        &self.predicates
    }
}

impl Default for DslParser {
    fn default() -> Self {
        Self::v1()
    }
}

/// Formats a Hypothesis back into DSL arrow-chain syntax.
///
/// Emits, in order:
/// 1. The entity chain with inlined edge/dest predicates and bindings.
/// 2. `HAVING count(distinct <col>) >= N` clauses, one per aggregation,
///    in declaration order.
/// 3. `WITHIN <N>s` when a window is set.
/// 4. `{k=N}` when `k_simplicity > 1`.
///
/// The output is canonical: two `Hypothesis` values that are equivalent
/// under the roundtrip property in `platform/dsl/tests/roundtrip.rs`
/// render to byte-identical strings.
pub fn format_hypothesis(h: &Hypothesis) -> String {
    if h.steps.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    let first = &h.steps[0];
    out.push_str(&format_entity(
        &first.origin_type,
        first.origin_binding.as_deref(),
    ));
    for step in &h.steps {
        if step.edge_predicates.is_empty() {
            out.push_str(&format!(" -[{}]->", step.relation_type));
        } else {
            out.push_str(&format!(
                " -[{} {}]->",
                step.relation_type,
                format_predicates(&step.edge_predicates),
            ));
        }
        out.push(' ');
        out.push_str(&format_entity(
            &step.dest_type,
            step.dest_binding.as_deref(),
        ));
        if !step.dest_predicates.is_empty() {
            out.push_str(&format!(" {}", format_predicates(&step.dest_predicates)));
        }
    }
    for agg in &h.aggregations {
        out.push_str(&format!(
            " HAVING count(distinct {}) >= {}",
            format_agg_column(&agg.column, h),
            agg.min_distinct
        ));
    }
    if let Some(secs) = h.window_seconds {
        out.push_str(&format!(" WITHIN {}s", secs));
    }
    if h.k_simplicity > 1 {
        out.push_str(&format!(" {{k={}}}", h.k_simplicity));
    }
    out
}

/// Render an entity slot: `User` alone, `User u` when a binding is set.
fn format_entity(t: &EntityType, binding: Option<&str>) -> String {
    match binding {
        Some(b) => format!("{} {}", t, b),
        None => format!("{}", t),
    }
}

/// Render an AggColumn as a parseable token. `FIRST` / `LAST` literals
/// are used for endpoint columns because they are unambiguous even when
/// the first and last entity types coincide (e.g. `User -[Auth]-> User`);
/// rendering the type name would otherwise short-circuit re-parse to
/// `First` regardless of the original variant (§4 rule 2 of
/// `dsl-v1-semantics.md`).
fn format_agg_column(col: &AggColumn, _h: &Hypothesis) -> String {
    match col {
        AggColumn::Named(name) => name.clone(),
        AggColumn::First => "FIRST".to_string(),
        AggColumn::Last => "LAST".to_string(),
    }
}

fn format_predicates(preds: &[Predicate]) -> String {
    let items: Vec<String> = preds
        .iter()
        .map(|p| match p {
            Predicate::Eq { key, value } => format!("{key}=\"{value}\""),
            Predicate::Neq { key, value } => format!("{key}!=\"{value}\""),
            Predicate::Match { key, value } => format!("{key}~\"{value}\""),
            Predicate::In { key, values } => format!(
                "{key} in [{}]",
                values
                    .iter()
                    .map(|v| format!("\"{v}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Predicate::NotIn { key, values } => format!(
                "{key} not in [{}]",
                values
                    .iter()
                    .map(|v| format!("\"{v}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        })
        .collect();
    format!("{{{}}}", items.join(", "))
}

struct Cursor<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Cursor<'a> {
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

    /// Parse an entity type followed by an optional variable binding:
    /// `User u`, `IP i`, `Process`. Returns `(type, binding)` where
    /// `binding` is `Some("u")` when written and `None` when omitted.
    /// The binding is a lower-case-starting identifier that would not
    /// itself be a valid EntityType name — a strong disambiguator
    /// against the next step's relation-type token.
    fn parse_entity_type_with_binding(&mut self) -> Result<(EntityType, Option<String>), DslError> {
        let et = self.parse_entity_type()?;
        // Binding is optional. Peek ahead after whitespace for an
        // identifier that's NOT the start of a new arrow (`-[`), NOT
        // the k-suffix (`{`), and NOT a trailing keyword (HAVING /
        // WITHIN). A bare identifier in this slot is the binding.
        let save = self.pos;
        self.skip_whitespace();
        // Peek without consuming the keyword candidate
        if self.pos >= self.input.len() {
            self.pos = save;
            return Ok((et, None));
        }
        let ch = self.input.as_bytes()[self.pos];
        if !(ch.is_ascii_alphabetic() || ch == b'_') {
            self.pos = save;
            return Ok((et, None));
        }
        let ident_start = self.pos;
        while self.pos < self.input.len() {
            let b = self.input.as_bytes()[self.pos];
            if b.is_ascii_alphanumeric() || b == b'_' {
                self.pos += 1;
            } else {
                break;
            }
        }
        let candidate = &self.input[ident_start..self.pos];
        // If the identifier is a reserved trailing keyword, it's NOT a
        // binding — rewind and let the outer parser handle it.
        let up = candidate.to_ascii_uppercase();
        if up == "HAVING" || up == "WITHIN" {
            self.pos = save;
            return Ok((et, None));
        }
        // Canonical entity-type names that signal the NEXT step's
        // origin rather than a binding. We must NOT use
        // `EntityType::from_str` here because it accepts any non-empty
        // string as `Other(_)` — every identifier would look like a
        // type. Hard-code the built-ins; user-defined Other types shadow
        // bindings of the same name by deliberate user choice (document
        // with a parser warning once we add one).
        const BUILTIN_TYPES: &[&str] = &[
            "IP", "Host", "User", "Process", "File", "Domain", "Registry", "URL", "Service",
        ];
        if BUILTIN_TYPES.contains(&candidate) {
            self.pos = save;
            return Ok((et, None));
        }
        Ok((et, Some(candidate.to_string())))
    }

    fn parse_relation_type(&mut self) -> Result<RelationType, DslError> {
        let pos = self.pos;
        let name = self.parse_identifier()?;
        RelationType::from_str(name).map_err(|_| DslError {
            message: format!("Unknown relation type: '{}'. Valid: Auth, Connect, Execute, Read, Write, DNS, Modify, Spawn, Delete, *", name),
            position: pos,
        })
    }

    /// Parses: `-[RelationType {predicates}?]->`
    /// Returns the relation type and the (possibly empty) predicate list.
    fn parse_arrow(&mut self) -> Result<(RelationType, Vec<Predicate>), DslError> {
        self.skip_whitespace();
        self.expect_str("-[")?;
        self.skip_whitespace();
        let rel = self.parse_relation_type()?;
        self.skip_whitespace();
        let predicates = if self.peek() == Some(b'{') {
            self.parse_predicates()?
        } else {
            Vec::new()
        };
        self.skip_whitespace();
        self.expect_str("]->")?;
        Ok((rel, predicates))
    }

    /// Peek inside a `{...}` block to decide whether it's a predicate
    /// list or the `{k=N}` k-simplicity suffix. Predicate blocks contain
    /// at least one of `"`, `[`, `~`, `!`; k-suffix is pure `k=<digits>`.
    fn looks_like_predicate_block(&self) -> bool {
        debug_assert_eq!(self.peek(), Some(b'{'));
        let bytes = self.input.as_bytes();
        let mut p = self.pos + 1;
        while p < bytes.len() && bytes[p] != b'}' {
            match bytes[p] {
                b'"' | b'[' | b'~' | b'!' => return true,
                _ => p += 1,
            }
        }
        false
    }

    /// Parses a `{key=value, key~"regex", key in ["a","b"]}` block. The
    /// opening `{` must already be the current byte. Returns the parsed
    /// predicate list.
    fn parse_predicates(&mut self) -> Result<Vec<Predicate>, DslError> {
        self.expect_str("{")?;
        let mut out = Vec::new();
        loop {
            self.skip_whitespace();
            if self.peek() == Some(b'}') {
                self.pos += 1;
                return Ok(out);
            }
            let key = self.parse_identifier()?.to_string();
            self.skip_whitespace();

            // Operator
            let p = match self.peek() {
                Some(b'=') => {
                    self.pos += 1;
                    self.skip_whitespace();
                    let value = self.parse_string_literal()?;
                    Predicate::Eq { key, value }
                }
                Some(b'!') => {
                    self.pos += 1;
                    if self.peek() != Some(b'=') {
                        return Err(DslError {
                            message: "Expected '!=' operator".into(),
                            position: self.pos,
                        });
                    }
                    self.pos += 1;
                    self.skip_whitespace();
                    let value = self.parse_string_literal()?;
                    Predicate::Neq { key, value }
                }
                Some(b'~') => {
                    self.pos += 1;
                    self.skip_whitespace();
                    let value = self.parse_string_literal()?;
                    Predicate::Match { key, value }
                }
                Some(b'i') | Some(b'n') => {
                    // Try "in [..]" or "not in [..]".
                    let word_start = self.pos;
                    let word = self.parse_identifier()?;
                    let (negated, word) = if word == "not" {
                        self.skip_whitespace();
                        let w = self.parse_identifier()?;
                        (true, w)
                    } else {
                        (false, word)
                    };
                    if word != "in" {
                        return Err(DslError {
                            message: format!("Expected 'in' or 'not in', got '{word}'"),
                            position: word_start,
                        });
                    }
                    self.skip_whitespace();
                    let values = self.parse_string_list()?;
                    if negated {
                        Predicate::NotIn { key, values }
                    } else {
                        Predicate::In { key, values }
                    }
                }
                _ => {
                    return Err(DslError {
                        message: "Expected operator (=, !=, ~, in, not in)".into(),
                        position: self.pos,
                    });
                }
            };
            out.push(p);

            self.skip_whitespace();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    continue;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(out);
                }
                _ => {
                    return Err(DslError {
                        message: "Expected ',' or '}' in predicate list".into(),
                        position: self.pos,
                    });
                }
            }
        }
    }

    /// Parse `"..."` (double-quoted) or a bare identifier (for convenience).
    fn parse_string_literal(&mut self) -> Result<String, DslError> {
        self.skip_whitespace();
        if self.peek() == Some(b'"') {
            self.pos += 1;
            let start = self.pos;
            while self.pos < self.input.len() && self.input.as_bytes()[self.pos] != b'"' {
                self.pos += 1;
            }
            if self.peek() != Some(b'"') {
                return Err(DslError {
                    message: "Unterminated string literal".into(),
                    position: start,
                });
            }
            let s = self.input[start..self.pos].to_string();
            self.pos += 1;
            Ok(s)
        } else {
            Ok(self.parse_identifier()?.to_string())
        }
    }

    /// Parse `["a", "b", ...]` — at least one element required.
    fn parse_string_list(&mut self) -> Result<Vec<String>, DslError> {
        self.skip_whitespace();
        self.expect_str("[")?;
        let mut out = Vec::new();
        loop {
            self.skip_whitespace();
            if self.peek() == Some(b']') {
                break;
            }
            out.push(self.parse_string_literal()?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    continue;
                }
                Some(b']') => break,
                _ => {
                    return Err(DslError {
                        message: "Expected ',' or ']' in list".into(),
                        position: self.pos,
                    });
                }
            }
        }
        self.expect_str("]")?;
        if out.is_empty() {
            return Err(DslError {
                message: "Empty list — provide at least one value".into(),
                position: self.pos,
            });
        }
        Ok(out)
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
        let k: usize = self.input[num_start..self.pos]
            .parse()
            .map_err(|_| DslError {
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
        // First clause head is always a fresh `Type binding` declaration.
        let (first_entity, first_binding) = self.parse_entity_type_with_binding()?;
        let mut steps = Vec::new();
        let mut prev_type = first_entity;
        let mut prev_binding = first_binding;
        // L1 stage 3c: clauses separated by `;` produce a Graph-shape
        // hypothesis. Stays Chain when the input is a single clause
        // (every legacy DSL hypothesis), so back-compat is exact.
        let mut shape = crate::hypothesis::HypothesisShape::Chain;

        loop {
            // Inner loop: arrow-chain steps off the current
            // (prev_type, prev_binding). Modeled as a helper-shaped
            // closure so we can re-enter it after a `;` clause break
            // with a different starting (prev_type, prev_binding).
            self.parse_chain_steps(&mut steps, &mut prev_type, &mut prev_binding)?;

            // After exhausting the current arrow chain: check for a
            // `;` clause separator. If present, the next clause head
            // can either declare a fresh `Type binding` OR refer to
            // an earlier binding by name (e.g. `c -[Auth]-> Host h2`
            // where `c` is the User declared in the first clause).
            self.skip_whitespace();
            if self.peek() != Some(b';') {
                break;
            }
            self.pos += 1; // consume `;`
            shape = crate::hypothesis::HypothesisShape::Graph;
            self.skip_whitespace();
            // Build the binding -> type lookup table from steps so far,
            // for bare-binding-ref clause heads. Re-built per `;` so a
            // clause can reference any binding declared up to this
            // point. The first occurrence wins (matches the matcher's
            // existing semantics for shared bindings).
            let mut binding_to_type: std::collections::HashMap<String, crate::types::EntityType> =
                std::collections::HashMap::new();
            for step in &steps {
                if let Some(b) = &step.origin_binding {
                    binding_to_type
                        .entry(b.clone())
                        .or_insert_with(|| step.origin_type.clone());
                }
                if let Some(b) = &step.dest_binding {
                    binding_to_type
                        .entry(b.clone())
                        .or_insert_with(|| step.dest_type.clone());
                }
            }
            let (clause_type, clause_binding) =
                self.parse_clause_head(&binding_to_type)?;
            prev_type = clause_type;
            prev_binding = clause_binding;
        }

        if steps.is_empty() {
            return Err(DslError {
                message: "Chain must have at least one step (e.g., 'User -[Auth]-> Host')"
                    .to_string(),
                position: 0,
            });
        }

        // Optional `HAVING` / `WITHIN` clauses BEFORE the k-simplicity suffix.
        // Grammar note: these are whitespace-separated and may appear in either
        // order; we peek for the keyword and consume it if present.
        let (aggregations, window_seconds) = self.parse_trailing_clauses(&steps)?;

        // Parse optional {k=N} suffix for k-simplicity
        let k_simplicity = self.try_parse_k_suffix()?;

        Ok(Hypothesis {
            name: name.to_string(),
            steps,
            k_simplicity,
            aggregations,
            window_seconds,
            shape,
        })
    }

    /// Inner-loop helper extracted from `parse`. Walks zero or more
    /// `-[rel]-> Type binding` steps off the current `(prev_type,
    /// prev_binding)` cursor, accumulating into `steps`. Stops when
    /// the next non-whitespace input is one of:
    ///   * end of input,
    ///   * `{` (start of `{k=N}` or destination predicate block,
    ///     handled by the caller),
    ///   * `;` (L1 stage 3c clause separator),
    ///   * an alphabetic identifier (HAVING / WITHIN trailing clause).
    fn parse_chain_steps(
        &mut self,
        steps: &mut Vec<HypothesisStep>,
        prev_type: &mut crate::types::EntityType,
        prev_binding: &mut Option<String>,
    ) -> Result<(), DslError> {
        loop {
            self.skip_whitespace();
            if self.pos >= self.input.len() {
                return Ok(());
            }

            // Check if next token is a {k=N} suffix (not another arrow step)
            if self.peek() == Some(b'{') {
                return Ok(());
            }

            // L1 stage 3c clause separator — caller handles it.
            if self.peek() == Some(b';') {
                return Ok(());
            }

            // Next char might start a trailing HAVING/WITHIN clause. Break
            // so the caller can dispatch `parse_trailing_clauses`. The
            // arrow character is the only one that keeps the loop going.
            if self.peek() != Some(b'-') {
                if self
                    .peek()
                    .map(|b| b.is_ascii_alphabetic())
                    .unwrap_or(false)
                {
                    return Ok(());
                }
                return Err(DslError {
                    message: format!(
                        "Expected '-[' or end of input, found '{}'",
                        &self.input[self.pos..self.pos + 1]
                    ),
                    position: self.pos,
                });
            }

            let (rel, edge_predicates) = self.parse_arrow()?;
            self.skip_whitespace();
            let (dest, dest_binding) = self.parse_entity_type_with_binding()?;
            // Optional destination-node predicate block, e.g.
            // `Process {name~"certutil"}`.
            self.skip_whitespace();
            let dest_predicates = if self.peek() == Some(b'{') && self.looks_like_predicate_block()
            {
                self.parse_predicates()?
            } else {
                Vec::new()
            };

            let mut step = HypothesisStep::with_all_predicates(
                prev_type.clone(),
                rel,
                dest.clone(),
                edge_predicates,
                dest_predicates,
            );
            step.origin_binding = prev_binding.clone();
            step.dest_binding = dest_binding.clone();
            steps.push(step);
            *prev_type = dest;
            *prev_binding = dest_binding;
        }
    }

    /// L1 stage 3c — parse a clause head that follows a `;`
    /// separator. Two valid forms:
    ///
    ///   1. **Bare binding reference**: a single identifier matching
    ///      a binding declared in an earlier clause. The clause's
    ///      `prev_type` is taken from that binding's recorded type
    ///      and `prev_binding` is the identifier itself. Example:
    ///      `c -[Auth]-> Host h2` after a clause that declared
    ///      `User c`.
    ///
    ///   2. **Fresh `Type binding` declaration**: same form as the
    ///      first clause head; introduces a brand-new vertex. Useful
    ///      for hypotheses with disconnected components, though those
    ///      don't currently match anything by themselves — they make
    ///      sense in combination with explicit cross-binding via
    ///      `HAVING` / `WITHIN`.
    ///
    /// The disambiguation rule: try (1) first, fall back to (2) if
    /// the leading identifier doesn't match any known binding. A
    /// builtin type name (`User`, `Host`, etc.) goes to (2)
    /// regardless — built-in types shadow bindings of the same name
    /// (the canonical entity-type names take precedence; document
    /// users who use lowercase like `user` for bindings).
    fn parse_clause_head(
        &mut self,
        binding_to_type: &std::collections::HashMap<String, crate::types::EntityType>,
    ) -> Result<(crate::types::EntityType, Option<String>), DslError> {
        let save = self.pos;
        self.skip_whitespace();
        // Peek the leading identifier.
        if self.pos >= self.input.len() {
            return Err(DslError {
                message: "Expected clause head after ';'".to_string(),
                position: self.pos,
            });
        }
        let ch = self.input.as_bytes()[self.pos];
        if !(ch.is_ascii_alphabetic() || ch == b'_') {
            return Err(DslError {
                message: format!(
                    "Expected identifier after ';', found '{}'",
                    &self.input[self.pos..self.pos + 1]
                ),
                position: self.pos,
            });
        }
        let ident_start = self.pos;
        while self.pos < self.input.len() {
            let b = self.input.as_bytes()[self.pos];
            if b.is_ascii_alphanumeric() || b == b'_' {
                self.pos += 1;
            } else {
                break;
            }
        }
        let candidate = self.input[ident_start..self.pos].to_string();

        // Builtin-type name? Rewind and parse as a fresh
        // `Type binding`. Keeps `;User u` working as "new chain
        // rooted at a fresh User vertex".
        const BUILTIN_TYPES: &[&str] = &[
            "IP", "Host", "User", "Process", "File", "Domain", "Registry", "URL", "Service",
        ];
        if BUILTIN_TYPES.contains(&candidate.as_str()) {
            self.pos = save;
            return self.parse_entity_type_with_binding();
        }

        // Bare binding reference: look up the binding's type.
        if let Some(existing_type) = binding_to_type.get(&candidate) {
            return Ok((existing_type.clone(), Some(candidate)));
        }

        // Unknown identifier — error with a hint about the two
        // valid forms. Don't fall through to `Other(...)` parsing
        // because that would silently swallow typos in binding
        // names (the analyst meant to reference a binding but
        // misspelled it).
        Err(DslError {
            message: format!(
                "After ';', expected a fresh `Type binding` or a known binding reference; \
                 '{}' is neither (declared bindings: {:?})",
                candidate,
                binding_to_type.keys().collect::<Vec<_>>()
            ),
            position: ident_start,
        })
    }

    /// Parse zero or more `HAVING ...` / `WITHIN ...` clauses appearing
    /// after the arrow-chain but before any `{k=N}` suffix. The order is
    /// not fixed — analysts write what feels natural.
    fn parse_trailing_clauses(
        &mut self,
        steps: &[HypothesisStep],
    ) -> Result<(Vec<AggClause>, Option<i64>), DslError> {
        let mut aggregations = Vec::new();
        let mut window_seconds: Option<i64> = None;

        loop {
            self.skip_whitespace();
            if self.pos >= self.input.len() || self.peek() == Some(b'{') {
                break;
            }
            // Peek the keyword without consuming it.
            let save = self.pos;
            let kw = match self.parse_identifier() {
                Ok(s) => s.to_string(),
                Err(_) => {
                    self.pos = save;
                    break;
                }
            };
            match kw.to_ascii_uppercase().as_str() {
                "HAVING" => {
                    aggregations.push(self.parse_having_clause(steps)?);
                }
                "WITHIN" => {
                    if window_seconds.is_some() {
                        return Err(DslError {
                            message: "Duplicate WITHIN clause".into(),
                            position: save,
                        });
                    }
                    window_seconds = Some(self.parse_duration_seconds()?);
                }
                _ => {
                    // Not a known keyword — rewind so `try_parse_k_suffix`
                    // (or the outer error path) can deal with it.
                    self.pos = save;
                    break;
                }
            }
        }

        Ok((aggregations, window_seconds))
    }

    /// Parse `count(distinct <col>) [>=|>] <N>`. Only `count(distinct ...)`
    /// is supported for this first cut; other aggregations (sum, avg) can
    /// be added later.
    fn parse_having_clause(&mut self, steps: &[HypothesisStep]) -> Result<AggClause, DslError> {
        self.skip_whitespace();
        let count_word = self.parse_identifier()?;
        if !count_word.eq_ignore_ascii_case("count") {
            return Err(DslError {
                message: format!("HAVING only supports count(distinct X), got '{count_word}'"),
                position: self.pos,
            });
        }
        self.skip_whitespace();
        self.expect_str("(")?;
        self.skip_whitespace();
        let distinct_word = self.parse_identifier()?;
        if !distinct_word.eq_ignore_ascii_case("distinct") {
            return Err(DslError {
                message: "Expected 'distinct' inside count(...)".into(),
                position: self.pos,
            });
        }
        self.skip_whitespace();
        let col_name = self.parse_identifier()?.to_string();
        self.skip_whitespace();
        self.expect_str(")")?;
        self.skip_whitespace();

        // Operator: accept `>=` and `>`. Treat `>` as `>= (n+1)` for simplicity.
        let (consume, operator_positive) = if self.input[self.pos..].starts_with(">=") {
            (2, true)
        } else if self.peek() == Some(b'>') {
            (1, false)
        } else {
            return Err(DslError {
                message: "Expected '>=' or '>' in HAVING clause".into(),
                position: self.pos,
            });
        };
        self.pos += consume;
        self.skip_whitespace();

        let num_start = self.pos;
        while self.pos < self.input.len() && self.input.as_bytes()[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        if self.pos == num_start {
            return Err(DslError {
                message: "Expected number in HAVING clause".into(),
                position: self.pos,
            });
        }
        let raw: usize = self.input[num_start..self.pos]
            .parse()
            .map_err(|_| DslError {
                message: "Invalid number in HAVING clause".into(),
                position: num_start,
            })?;
        let min_distinct = if operator_positive { raw } else { raw + 1 };

        // Resolve col_name in precedence order:
        //   (1) A named binding declared on any step (B.3).
        //   (2) The literal `FIRST` / `LAST` keywords.
        //   (3) A bare entity type name matching the chain's endpoints.
        let has_binding = steps.iter().any(|s| {
            s.origin_binding.as_deref() == Some(col_name.as_str())
                || s.dest_binding.as_deref() == Some(col_name.as_str())
        });
        let first_type = format!("{}", steps.first().unwrap().origin_type);
        let last_type = format!("{}", steps.last().unwrap().dest_type);
        let column = if has_binding {
            AggColumn::Named(col_name.clone())
        } else if col_name.eq_ignore_ascii_case("first") || col_name == first_type {
            AggColumn::First
        } else if col_name.eq_ignore_ascii_case("last") || col_name == last_type {
            AggColumn::Last
        } else {
            return Err(DslError {
                message: format!(
                    "HAVING column '{col_name}' is not a declared binding and does not match the first type '{first_type}' or the last type '{last_type}'"
                ),
                position: self.pos,
            });
        };

        Ok(AggClause {
            column,
            min_distinct,
        })
    }

    /// Parse a duration like `24h`, `15m`, `1d`, `3600s`, `2w`. Returns seconds.
    fn parse_duration_seconds(&mut self) -> Result<i64, DslError> {
        self.skip_whitespace();
        let num_start = self.pos;
        while self.pos < self.input.len() && self.input.as_bytes()[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        if self.pos == num_start {
            return Err(DslError {
                message: "Expected number in WITHIN clause".into(),
                position: self.pos,
            });
        }
        let n: i64 = self.input[num_start..self.pos]
            .parse()
            .map_err(|_| DslError {
                message: "Invalid number in WITHIN clause".into(),
                position: num_start,
            })?;
        // Optional unit. Default to seconds if no unit follows.
        let unit_start = self.pos;
        while self.pos < self.input.len() && self.input.as_bytes()[self.pos].is_ascii_alphabetic() {
            self.pos += 1;
        }
        let unit = &self.input[unit_start..self.pos];
        let multiplier: i64 = match unit.to_ascii_lowercase().as_str() {
            "" | "s" | "sec" | "secs" | "second" | "seconds" => 1,
            "m" | "min" | "mins" | "minute" | "minutes" => 60,
            "h" | "hr" | "hrs" | "hour" | "hours" => 3600,
            "d" | "day" | "days" => 86_400,
            "w" | "week" | "weeks" => 604_800,
            other => {
                return Err(DslError {
                    message: format!("Unknown duration unit '{other}'"),
                    position: unit_start,
                });
            }
        };
        Ok(n.saturating_mul(multiplier))
    }
}

#[cfg(test)]
mod parser_tests {
    use super::*;
    use crate::extension::{EntityTypeDef, RelationTypeDef};

    struct K8sExt;

    impl DslExtension for K8sExt {
        fn name(&self) -> &str {
            "k8s-ext"
        }
        fn version(&self) -> u32 {
            1
        }
        fn register_entity_types(&self, reg: &mut EntityTypeRegistry) {
            reg.register(EntityTypeDef {
                name: "Container".into(),
                description: "A container workload.".into(),
            });
        }
        fn register_relation_types(&self, reg: &mut RelationTypeRegistry) {
            reg.register(RelationTypeDef {
                name: "Mount".into(),
                description: "A container mounts a volume.".into(),
            });
        }
    }

    #[test]
    fn free_function_and_v1_parser_agree() {
        let direct = parse_dsl("User -[Auth]-> Host", None).unwrap();
        let via_struct = DslParser::v1().parse("User -[Auth]-> Host", None).unwrap();
        assert_eq!(direct.formatted, via_struct.formatted);
        assert_eq!(
            direct.hypothesis.steps.len(),
            via_struct.hypothesis.steps.len()
        );
    }

    #[test]
    fn parser_with_extension_exposes_registries() {
        let parser = DslParser::v1().with_extension(K8sExt);
        assert!(parser.entity_types().contains("Container"));
        assert!(parser.relation_types().contains("Mount"));
        assert!(parser.entity_types().contains("IP"), "builtins present");
    }

    #[test]
    fn parser_accepts_extension_types_as_other() {
        // Extension names come back as `Other(name)` today; registries
        // are informational at F4.3. The parse succeeds because
        // `EntityType::from_str` is permissive.
        let parser = DslParser::v1().with_extension(K8sExt);
        let r = parser.parse("Container -[Mount]-> File", None).unwrap();
        assert_eq!(r.hypothesis.steps.len(), 1);
        let step = &r.hypothesis.steps[0];
        assert_eq!(format!("{}", step.origin_type), "Container");
        assert_eq!(format!("{}", step.relation_type), "Mount");
        assert_eq!(format!("{}", step.dest_type), "File");
    }

    #[test]
    fn parser_without_extension_still_permissive() {
        // Backward-compat: unknown names still parse as Other(_).
        // The pre-F4 grammar behavior is preserved when no extension
        // is installed.
        let parser = DslParser::v1();
        let r = parser
            .parse("ServiceAccount -[Assume]-> Role", None)
            .unwrap();
        assert_eq!(r.hypothesis.steps.len(), 1);
        assert!(!parser.entity_types().contains("ServiceAccount"));
    }

    #[test]
    fn default_is_v1() {
        let p: DslParser = DslParser::default();
        let r = p.parse("User -[Auth]-> Host", None).unwrap();
        assert_eq!(r.hypothesis.steps.len(), 1);
    }

    // L1 stage 3c — clause-separator (`;`) DSL grammar tests.

    #[test]
    fn legacy_chain_stays_chain_shape() {
        let r = parse_dsl("User u -[Auth]-> Host h -[Connect]-> IP i", None).unwrap();
        assert_eq!(r.hypothesis.shape, crate::hypothesis::HypothesisShape::Chain);
        assert_eq!(r.hypothesis.steps.len(), 2);
    }

    #[test]
    fn star_via_semicolon_emits_graph_shape() {
        // `User c -[Auth]-> Host h1; c -[Auth]-> Host h2; c -[Auth]-> Host h3`
        // is a 3-leaf star centered on `c`.
        let r = parse_dsl(
            "User c -[Auth]-> Host h1; c -[Auth]-> Host h2; c -[Auth]-> Host h3",
            None,
        )
        .unwrap();
        assert_eq!(r.hypothesis.shape, crate::hypothesis::HypothesisShape::Graph);
        assert_eq!(r.hypothesis.steps.len(), 3);
        // Every step's origin_binding is "c" (declared in clause 1, referenced in 2 and 3).
        for (i, step) in r.hypothesis.steps.iter().enumerate() {
            assert_eq!(
                step.origin_binding.as_deref(),
                Some("c"),
                "step {i} origin should reference center binding c"
            );
        }
        // The three leaves are distinct: h1, h2, h3.
        assert_eq!(r.hypothesis.steps[0].dest_binding.as_deref(), Some("h1"));
        assert_eq!(r.hypothesis.steps[1].dest_binding.as_deref(), Some("h2"));
        assert_eq!(r.hypothesis.steps[2].dest_binding.as_deref(), Some("h3"));
    }

    #[test]
    fn semicolon_clause_inherits_referenced_binding_type() {
        // The second clause's bare `c` reference resolves to `User`
        // because clause 1 declared `User c`.
        let r = parse_dsl(
            "User c -[Auth]-> Host h1; c -[Auth]-> Process p",
            None,
        )
        .unwrap();
        assert_eq!(r.hypothesis.shape, crate::hypothesis::HypothesisShape::Graph);
        assert_eq!(r.hypothesis.steps.len(), 2);
        assert_eq!(r.hypothesis.steps[1].origin_type, EntityType::User);
        assert_eq!(r.hypothesis.steps[1].dest_type, EntityType::Process);
    }

    #[test]
    fn semicolon_unknown_binding_errors_with_hint() {
        let err = parse_dsl(
            "User c -[Auth]-> Host h1; q -[Auth]-> Process p",
            None,
        )
        .unwrap_err();
        assert!(
            err.message.contains("'q'") && err.message.contains("declared bindings"),
            "error should name the unknown binding and list known ones: {}",
            err.message
        );
    }

    #[test]
    fn semicolon_with_fresh_type_starts_new_chain() {
        // `;User u` after a `;` is allowed: declares a brand-new
        // User vertex with binding `u`, distinct from anything in
        // the prior clause.
        let r = parse_dsl(
            "User c -[Auth]-> Host h1; User u -[Auth]-> Host h2",
            None,
        )
        .unwrap();
        assert_eq!(r.hypothesis.shape, crate::hypothesis::HypothesisShape::Graph);
        assert_eq!(r.hypothesis.steps.len(), 2);
        assert_eq!(r.hypothesis.steps[1].origin_binding.as_deref(), Some("u"));
        // u was declared fresh in clause 2 — it's NOT the same vertex
        // as c.
        assert_ne!(
            r.hypothesis.steps[1].origin_binding,
            r.hypothesis.steps[0].origin_binding,
        );
    }
}
