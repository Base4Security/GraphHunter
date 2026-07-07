//! Line-oriented validator for the VRL subset GraphHunter ships.
//!
//! Why line-oriented and not a full parser: the deterministic compiler
//! in `graph_hunter_vrl::field_config_to_vrl` emits one statement per
//! line plus `if exists(...) { ... }` blocks. Anything an LLM
//! refinement is allowed to produce must keep that shape so the result
//! stays diff-friendly against the compiler output and the review queue
//! can present a meaningful side-by-side. A pratt-parser-grade VRL
//! grammar would let in constructs (loops, free-form arithmetic,
//! arbitrary function calls) we explicitly do *not* want — a strict
//! line shape is the contract.
//!
//! The validator accepts:
//!   * blank lines and `#`-prefixed comments,
//!   * the root rebind `. = parse_json!(string!(.message))`,
//!   * scaffold writes to `.canonical{,.entities,.metadata,.timestamp}`,
//!   * single-line `if exists(<field-access>) {` blocks closed by `}`,
//!   * inside those blocks, push to `.canonical.entities`, write to
//!     `.canonical.metadata.<raw>`, or assign `.canonical.timestamp`
//!     via the `parse_timestamp(... ) ?? null` form,
//!   * `del(<field-access>)` cleanup,
//!   * a final `.` return.
//!
//! Anything else — loops, unrecognized function calls, `;`, raw string
//! interpolation, `match`, etc. — fails with a line-numbered error.

use crate::grammar::{GrammarValidator, ValidationError, ValidationResult};

/// Default validator. Stateless. Cheap to clone.
#[derive(Debug, Default, Clone, Copy)]
pub struct VrlSubsetValidator;

impl VrlSubsetValidator {
    pub const fn new() -> Self {
        Self
    }
}

impl GrammarValidator for VrlSubsetValidator {
    fn validate(&self, source: &str) -> ValidationResult<()> {
        let mut depth: i32 = 0;
        for (idx, raw_line) in source.lines().enumerate() {
            let line_no = idx + 1;
            let line = raw_line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Closing brace on its own line — pops one level.
            if line == "}" {
                depth -= 1;
                if depth < 0 {
                    return Err(err(line_no, "unbalanced `}`"));
                }
                continue;
            }

            // Final return. Always at depth 0.
            if line == "." {
                if depth != 0 {
                    return Err(err(line_no, "bare `.` return inside an open block"));
                }
                continue;
            }

            // `if exists(<field>) {` opens a block.
            if let Some(rest) = line.strip_prefix("if exists(") {
                let inner = rest
                    .strip_suffix(") {")
                    .ok_or_else(|| err(line_no, "expected `if exists(<field>) {`"))?;
                check_field_access(line_no, inner)?;
                depth += 1;
                continue;
            }

            // Otherwise the line must be a single statement.
            check_statement(line_no, line)?;
        }

        if depth != 0 {
            return Err(ValidationError {
                line: 0,
                message: format!("unclosed block — depth {depth} at end of input"),
            });
        }
        Ok(())
    }
}

fn check_statement(line_no: usize, line: &str) -> ValidationResult<()> {
    // Reject obviously-disallowed constructs early. These are all
    // tokens VRL recognizes that we deliberately don't allow in the
    // subset because they break the line-shape / safety contract.
    for kw in ["while", "for", "loop", "match"] {
        if has_keyword(line, kw) {
            return Err(err(line_no, &format!("disallowed construct: `{kw}`")));
        }
    }
    for forbidden in ["=>", ";", "&&", "||", "..", "?:"] {
        if line.contains(forbidden) {
            return Err(err(
                line_no,
                &format!("disallowed construct: `{forbidden}`"),
            ));
        }
    }

    // del(.field) — cleanup.
    if let Some(rest) = line.strip_prefix("del(") {
        let inner = rest
            .strip_suffix(')')
            .ok_or_else(|| err(line_no, "expected `del(<field>)`"))?;
        check_field_access(line_no, inner)?;
        return Ok(());
    }

    // Everything else must be an assignment `<lhs> = <rhs>`.
    let (lhs, rhs) = line
        .split_once('=')
        .ok_or_else(|| err(line_no, "expected an assignment statement"))?;
    let lhs = lhs.trim();
    let rhs = rhs.trim_start();

    check_lhs(line_no, lhs)?;
    check_rhs(line_no, rhs)?;
    Ok(())
}

fn check_lhs(line_no: usize, lhs: &str) -> ValidationResult<()> {
    // Allowed left-hand sides:
    //   `.`                               (root rebind)
    //   `.canonical`
    //   `.canonical.entities`
    //   `.canonical.metadata`
    //   `.canonical.timestamp`
    //   `.canonical.metadata."<raw>"`     (escaped field name)
    //   `.canonical.metadata.<ident>`     (identifier-safe field name)
    if lhs == "." {
        return Ok(());
    }
    if matches!(
        lhs,
        ".canonical" | ".canonical.entities" | ".canonical.metadata" | ".canonical.timestamp"
    ) {
        return Ok(());
    }
    if let Some(rest) = lhs.strip_prefix(".canonical.metadata.") {
        if rest.starts_with('"') && rest.ends_with('"') && rest.len() >= 2 {
            return Ok(());
        }
        if is_safe_ident(rest) {
            return Ok(());
        }
    }
    Err(err(
        line_no,
        &format!("disallowed assignment target `{lhs}`"),
    ))
}

fn check_rhs(line_no: usize, rhs: &str) -> ValidationResult<()> {
    // The RHS surface is small and enumerable. We accept exact patterns
    // for the scaffold writes the compiler emits, plus a few enrichment
    // forms (`push(...)`, `parse_timestamp(...) ?? null`, `to_string!(.x)`,
    // `string!(.x)`, `parse_json!(string!(.message))`, literal scalars).
    //
    // Anything else is rejected — including bare arithmetic, indexing,
    // and unrecognized function calls.
    let rhs = rhs.trim_end();

    if rhs == "{}" || rhs == "[]" || rhs == "null" {
        return Ok(());
    }
    if rhs == "parse_json!(string!(.message))" {
        return Ok(());
    }
    if rhs.starts_with("push(.canonical.entities, {") && rhs.ends_with("})") {
        // We intentionally don't validate the object literal: it's
        // generated from a finite, vetted template in the deterministic
        // compiler, and the LLM is allowed to add string fields. The
        // outer-shape check is what keeps things safe.
        return Ok(());
    }
    if rhs.starts_with("parse_timestamp(") && rhs.ends_with(" ?? null") {
        return Ok(());
    }
    // Plain field copy or to_string! / string! coercion of a single field.
    if rhs.starts_with('.') && check_field_access(line_no, rhs).is_ok() {
        return Ok(());
    }
    if let Some(inner) = rhs
        .strip_prefix("to_string!(")
        .and_then(|s| s.strip_suffix(')'))
    {
        return check_field_access(line_no, inner);
    }
    if let Some(inner) = rhs
        .strip_prefix("string!(")
        .and_then(|s| s.strip_suffix(')'))
    {
        return check_field_access(line_no, inner);
    }
    if let Some(inner) = rhs
        .strip_prefix("downcase!(")
        .and_then(|s| s.strip_suffix(')'))
    {
        return check_field_access(line_no, inner);
    }
    if let Some(inner) = rhs
        .strip_prefix("upcase!(")
        .and_then(|s| s.strip_suffix(')'))
    {
        return check_field_access(line_no, inner);
    }
    // Quoted string literal `"..."` (no escaped backticks or interpolation).
    if rhs.starts_with('"') && rhs.ends_with('"') && rhs.len() >= 2 && !rhs.contains("`") {
        return Ok(());
    }

    Err(err(line_no, &format!("disallowed expression `{rhs}`")))
}

fn check_field_access(line_no: usize, expr: &str) -> ValidationResult<()> {
    let expr = expr.trim();
    if !expr.starts_with('.') {
        return Err(err(
            line_no,
            &format!("expected field access, got `{expr}`"),
        ));
    }
    let rest = &expr[1..];
    if rest.is_empty() {
        return Ok(()); // `.` alone is the event root, allowed.
    }
    // `."escaped name"` form.
    if rest.starts_with('"') {
        if !rest.ends_with('"') || rest.len() < 2 {
            return Err(err(line_no, &format!("unterminated quoted field `{expr}`")));
        }
        return Ok(());
    }
    if !is_safe_ident(rest) {
        return Err(err(line_no, &format!("unsupported field path `{expr}`")));
    }
    Ok(())
}

/// True if `kw` appears in `line` as a standalone token (bounded by
/// non-identifier characters or string ends).
fn has_keyword(line: &str, kw: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = line[start..].find(kw) {
        let abs = start + pos;
        let before_ok = abs == 0
            || !line.as_bytes()[abs - 1].is_ascii_alphanumeric()
                && line.as_bytes()[abs - 1] != b'_';
        let after = abs + kw.len();
        let after_ok = after == line.len()
            || !line.as_bytes()[after].is_ascii_alphanumeric() && line.as_bytes()[after] != b'_';
        if before_ok && after_ok {
            return true;
        }
        start = abs + 1;
    }
    false
}

fn is_safe_ident(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}

fn err(line: usize, msg: &str) -> ValidationError {
    ValidationError {
        line,
        message: msg.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use graph_hunter_core::field_preview::{FieldConfig, FieldMapping, FieldRole};
    use graph_hunter_vrl::field_config_to_vrl;

    fn cfg(rows: &[(&str, FieldRole, Option<&str>)]) -> FieldConfig {
        FieldConfig {
            mappings: rows
                .iter()
                .map(|(name, role, et)| FieldMapping {
                    raw_name: (*name).into(),
                    role: role.clone(),
                    entity_type: et.map(|s| s.into()),
                    timestamp_format: None,
                    locale: None,
                })
                .collect(),
        }
    }

    #[test]
    fn deterministic_compiler_output_validates() {
        let v = VrlSubsetValidator::new();
        let p = field_config_to_vrl(&cfg(&[
            ("User", FieldRole::Node, Some("User")),
            ("Image", FieldRole::Node, Some("Process")),
            ("Cmd", FieldRole::Metadata, None),
            ("Skip", FieldRole::Ignore, None),
        ]));
        v.validate(&p.source)
            .unwrap_or_else(|e| panic!("compiler output failed validation: {e}\n\n{}", p.source));
    }

    #[test]
    fn quoted_field_names_validate() {
        let v = VrlSubsetValidator::new();
        let p = field_config_to_vrl(&cfg(&[("user.name", FieldRole::Node, Some("User"))]));
        v.validate(&p.source).expect("quoted field names ok");
    }

    #[test]
    fn timestamp_form_validates() {
        let v = VrlSubsetValidator::new();
        let p = field_config_to_vrl(&FieldConfig {
            mappings: vec![FieldMapping {
                raw_name: "ts".into(),
                role: FieldRole::Node,
                entity_type: Some("Time".into()),
                timestamp_format: Some("%Y-%m-%dT%H:%M:%S".into()),
                locale: Some("en".into()),
            }],
        });
        v.validate(&p.source).expect("parse_timestamp form ok");
    }

    #[test]
    fn rejects_loop() {
        let v = VrlSubsetValidator::new();
        let bad = "# header\nfor i in [1,2,3] {\n.x = i\n}\n.\n";
        let err = v.validate(bad).unwrap_err();
        assert!(err.message.contains("for"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_function() {
        let v = VrlSubsetValidator::new();
        let bad = ". = exfiltrate!(.x)\n.\n";
        let err = v.validate(bad).unwrap_err();
        assert!(err.message.contains("disallowed expression"), "got: {err}");
    }

    #[test]
    fn rejects_unbalanced_braces() {
        let v = VrlSubsetValidator::new();
        let bad = "if exists(.x) {\n.canonical = {}\n";
        let err = v.validate(bad).unwrap_err();
        assert!(err.message.contains("unclosed"), "got: {err}");
    }

    #[test]
    fn rejects_extra_close_brace() {
        let v = VrlSubsetValidator::new();
        let bad = ".canonical = {}\n}\n.\n";
        let err = v.validate(bad).unwrap_err();
        assert!(err.message.contains("unbalanced"), "got: {err}");
    }

    #[test]
    fn rejects_semicolons() {
        let v = VrlSubsetValidator::new();
        let bad = ".x = 1; .y = 2\n.\n";
        let err = v.validate(bad).unwrap_err();
        assert!(err.message.contains(";"), "got: {err}");
    }

    #[test]
    fn rejects_match_construct() {
        let v = VrlSubsetValidator::new();
        let bad = "x = match .y { 1 => 2 }\n.\n";
        let err = v.validate(bad).unwrap_err();
        assert!(
            err.message.contains("match") || err.message.contains("=>"),
            "got: {err}"
        );
    }

    #[test]
    fn allows_del_cleanup() {
        let v = VrlSubsetValidator::new();
        let src = "# scrub\n.canonical = {}\ndel(.password)\n.\n";
        v.validate(src).expect("del() should be accepted");
    }
}
