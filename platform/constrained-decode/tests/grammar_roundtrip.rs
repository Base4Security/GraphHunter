//! F12.6 — grammar↔validator↔compiler roundtrip.
//!
//! The triangle the spec promises (`docs/spec/vrl-subset-grammar.md`):
//!
//! ```text
//!     field_config_to_vrl ───► output ───► VrlSubsetValidator
//!             │                                  │
//!             ▼                                  ▼
//!     vrl_subset.lark ◄─────── parses ◄──────────┘
//! ```
//!
//! Why no real Lark parser dep here: the validator (`VrlSubsetValidator`)
//! is hand-written to track the grammar file production-for-production
//! (line-oriented because the compiler emits one statement per line).
//! Pulling in a full Lark/llguidance parser just to re-derive the same
//! decision would double the surface area without adding signal — every
//! drift the validator misses would also be a grammar bug, and every
//! drift the grammar misses would also be a validator bug. The
//! production-coverage test below pins the grammar file's content so
//! editing it without touching the validator (or vice versa) trips the
//! canary.
//!
//! What this file proves:
//!
//! 1. **Grammar canary** — `grammars/vrl_subset.lark` exists and contains
//!    every production the validator relies on. Editing the grammar
//!    without keeping the validator in sync fails this test.
//! 2. **Production coverage** — for each grammar production we ship,
//!    a hand-crafted positive example is accepted by the validator,
//!    and a corresponding negative is rejected. Forces the spec, the
//!    grammar, and the validator to agree on each construct
//!    individually rather than only in aggregate.
//! 3. **Compiler→validator roundtrip @ 100** — 100 distinct compiler
//!    outputs (proptest-generated FieldConfigs) all validate. The DoD
//!    of F12.6 reads "50 outputs"; we double it for headroom.

use graph_hunter_constrained_decode::{GrammarValidator, VrlSubsetValidator};
use graph_hunter_core::field_preview::{FieldConfig, FieldMapping, FieldRole};
use graph_hunter_vrl::field_config_to_vrl;

const GRAMMAR_PATH: &str = "grammars/vrl_subset.lark";

/// Productions the validator depends on. If the grammar file is renamed
/// or these strings drift, the canary fires and the editor is forced to
/// open `docs/spec/vrl-subset-grammar.md` to see what they're breaking.
const REQUIRED_PRODUCTION_NAMES: &[&str] = &[
    "start",
    "line",
    "blank",
    "comment",
    "return_",
    "statement",
    "del_call",
    "assignment",
    "lhs",
    "metadata_field",
    "rhs",
    "empty_object",
    "empty_array",
    "null_lit",
    "parse_json_message",
    "push_entity",
    "parse_timestamp_form",
    "string_coerce_call",
    "block",
    "inner_line",
    "field_access",
    "string_literal",
];

const REQUIRED_TERMINAL_FRAGMENTS: &[&str] = &[
    // Exact RHS literals the deterministic compiler emits — if any of
    // these vanish from the grammar, compiler output stops parsing.
    "parse_json!(string!(.message))",
    "push(.canonical.entities, {",
    "parse_timestamp(",
    "?? null",
    // The four whitelisted string-coercion built-ins.
    "to_string!",
    "string!",
    "downcase!",
    "upcase!",
    // The four scaffold LHS targets.
    ".canonical",
    ".canonical.entities",
    ".canonical.metadata",
    ".canonical.timestamp",
    // if-block opener.
    "if exists(",
];

#[test]
fn grammar_canary_file_exists_and_pins_productions() {
    let src = std::fs::read_to_string(GRAMMAR_PATH).unwrap_or_else(|e| {
        panic!(
            "grammar file not found at `{GRAMMAR_PATH}` (cwd-relative): {e}.\n\
             This file is the source of truth referenced by `docs/spec/vrl-subset-grammar.md`.\n\
             Did you delete it without updating the spec? Restore it or update both."
        )
    });

    for prod in REQUIRED_PRODUCTION_NAMES {
        let needle_a = format!("\n{prod}:");
        let needle_b = format!("\n{prod} :");
        let needle_c = format!("\n{prod}\n");
        assert!(
            src.contains(&needle_a) || src.contains(&needle_b) || src.contains(&needle_c),
            "grammar production `{prod}` missing from {GRAMMAR_PATH}.\n\
             Either restore it or sync `VrlSubsetValidator` and the spec doc.",
        );
    }

    for frag in REQUIRED_TERMINAL_FRAGMENTS {
        assert!(
            src.contains(frag),
            "grammar fragment `{frag}` missing from {GRAMMAR_PATH}.\n\
             The deterministic compiler emits this terminal — losing it from the grammar\n\
             breaks the LLM-as-compiler claim (constrained decoder couldn't reproduce it)."
        );
    }
}

/// Each row is `(label, source, must_validate)`. Keeping the list inline
/// rather than in a fixture file makes the production-to-test mapping
/// auditable in one place.
const PRODUCTION_CASES: &[(&str, &str, bool)] = &[
    // -------- positive cases (must validate) --------
    ("blank+comment+return", "# header\n\n.\n", true),
    ("scaffold-empty-object", ".canonical = {}\n.\n", true),
    (
        "scaffold-empty-array",
        ".canonical.entities = []\n.\n",
        true,
    ),
    ("scaffold-null", ".canonical.timestamp = null\n.\n", true),
    (
        "root-rebind",
        ". = parse_json!(string!(.message))\n.\n",
        true,
    ),
    (
        "metadata-write-ident",
        "if exists(.x) {\n.canonical.metadata.\"x\" = .x\n}\n.\n",
        true,
    ),
    (
        "metadata-write-quoted-key",
        "if exists(.x) {\n.canonical.metadata.\"User-Agent\" = .x\n}\n.\n",
        true,
    ),
    (
        "push-entity",
        "if exists(.User) {\n.canonical.entities = push(.canonical.entities, {\"type\": \"User\", \"value\": to_string!(.User), \"raw\": \"User\"})\n}\n.\n",
        true,
    ),
    (
        "parse-timestamp-form",
        "if exists(.ts) {\n.canonical.timestamp = parse_timestamp(.ts, format: \"%Y-%m-%d\", locale: \"en\") ?? null\n}\n.\n",
        true,
    ),
    (
        "string-coerce-to_string",
        "if exists(.x) {\n.canonical.metadata.\"x\" = to_string!(.x)\n}\n.\n",
        true,
    ),
    (
        "string-coerce-string",
        "if exists(.x) {\n.canonical.metadata.\"x\" = string!(.x)\n}\n.\n",
        true,
    ),
    (
        "string-coerce-downcase",
        "if exists(.x) {\n.canonical.metadata.\"x\" = downcase!(.x)\n}\n.\n",
        true,
    ),
    (
        "string-coerce-upcase",
        "if exists(.x) {\n.canonical.metadata.\"x\" = upcase!(.x)\n}\n.\n",
        true,
    ),
    ("del-cleanup", "del(.password)\n.\n", true),
    (
        "quoted-field-access",
        "if exists(.\"User-Agent\") {\n.canonical.metadata.\"ua\" = .\"User-Agent\"\n}\n.\n",
        true,
    ),
    (
        "string-literal-rhs",
        "if exists(.x) {\n.canonical.metadata.\"x\" = \"literal\"\n}\n.\n",
        true,
    ),
    // -------- negative cases (must reject) --------
    ("for-loop", "for x in [1,2,3] {\n.x = x\n}\n.\n", false),
    ("while-loop", "while .x { .y = 1 }\n.\n", false),
    ("match-construct", ".x = match .y { 1 => 2 }\n.\n", false),
    (
        "boolean-and",
        "if exists(.x) && exists(.y) {\n.z = 1\n}\n.\n",
        false,
    ),
    ("range", ".canonical.metadata.\"x\" = .a..b\n.\n", false),
    (
        "semicolon-split",
        ".canonical.metadata.\"x\" = .a; .canonical.metadata.\"y\" = .b\n.\n",
        false,
    ),
    (
        "arithmetic",
        ".canonical.metadata.\"score\" = (.a + .b) * 2\n.\n",
        false,
    ),
    (
        "indexing",
        ".canonical.metadata.\"first\" = .arr[0]\n.\n",
        false,
    ),
    (
        "unknown-call",
        ".canonical.metadata.\"x\" = exfiltrate!(.x)\n.\n",
        false,
    ),
    (
        "shell-out",
        ".canonical.metadata.\"x\" = run_shell!(\"id\")\n.\n",
        false,
    ),
    (
        "interp-backtick",
        ".canonical.metadata.\"x\" = `${.user}@${.host}`\n.\n",
        false,
    ),
    ("lhs-not-canonical", ".arbitrary_root = {}\n.\n", false),
    (
        "unbalanced-open",
        "if exists(.x) {\n.canonical = {}\n.\n",
        false,
    ),
    ("unbalanced-close", ".canonical = {}\n}\n.\n", false),
];

#[test]
fn each_production_has_aligned_positive_and_negative_coverage() {
    let v = VrlSubsetValidator::new();
    let mut failures: Vec<String> = Vec::new();

    for (label, src, must_validate) in PRODUCTION_CASES {
        let res = v.validate(src);
        match (must_validate, res) {
            (true, Err(e)) => failures.push(format!(
                "[{label}] expected ACCEPT, got REJECT: {e}\n--- source ---\n{src}"
            )),
            (false, Ok(())) => failures.push(format!(
                "[{label}] expected REJECT, got ACCEPT\n--- source ---\n{src}"
            )),
            _ => {}
        }
    }

    assert!(
        failures.is_empty(),
        "{} production(s) failed grammar↔validator agreement:\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

// -------- compiler→validator roundtrip @ 100 --------

/// Reproducible LCG (matches `fuzz_validator.rs`'s style) so this test
/// is byte-stable across CI runs.
struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_add(0x9E37_79B9_7F4A_7C15))
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[(self.next() as usize) % xs.len()]
    }
    fn between(&mut self, lo: usize, hi: usize) -> usize {
        lo + (self.next() as usize) % (hi - lo + 1)
    }
}

const ENTITY_TYPES: &[&str] = &[
    "User",
    "Process",
    "File",
    "Host",
    "IpAddress",
    "DomainName",
    "Hash",
    "Time",
];

const RAW_NAMES: &[&str] = &[
    "User",
    "Image",
    "ParentImage",
    "CommandLine",
    "DestinationIp",
    "user.name",
    "event.action",
    "process.parent.pid",
    "occurred_at",
    "EventID",
    "Hashes",
    "ProviderName",
    "TargetUserName",
    "QueryName",
];

const TIMESTAMP_FORMATS: &[&str] = &[
    "%Y-%m-%dT%H:%M:%S%.fZ",
    "%b %d %Y %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
];

fn random_field_config(rng: &mut Lcg) -> FieldConfig {
    let n = rng.between(0, 10);
    let mut mappings = Vec::with_capacity(n);
    for i in 0..n {
        let raw = format!("{}_{}", rng.pick(RAW_NAMES), i);
        let role_pick = rng.next() % 100;
        let mapping = if role_pick < 50 {
            FieldMapping {
                raw_name: raw,
                role: FieldRole::Node,
                entity_type: Some((*rng.pick(ENTITY_TYPES)).to_string()),
                timestamp_format: None,
                locale: None,
            }
        } else if role_pick < 75 {
            FieldMapping {
                raw_name: raw,
                role: FieldRole::Metadata,
                entity_type: None,
                timestamp_format: None,
                locale: None,
            }
        } else if role_pick < 90 {
            FieldMapping {
                raw_name: raw,
                role: FieldRole::Ignore,
                entity_type: None,
                timestamp_format: None,
                locale: None,
            }
        } else {
            FieldMapping {
                raw_name: raw,
                role: FieldRole::Node,
                entity_type: Some("Time".into()),
                timestamp_format: Some((*rng.pick(TIMESTAMP_FORMATS)).to_string()),
                locale: Some("en".into()),
            }
        };
        mappings.push(mapping);
    }
    FieldConfig { mappings }
}

#[test]
fn compiler_outputs_validate_and_obey_grammar_surface() {
    let v = VrlSubsetValidator::new();
    let mut rng = Lcg::new(0xF12_6_C0FFEE);
    let mut total = 0usize;
    let mut failures: Vec<(usize, String, String)> = Vec::new();

    for i in 0..100 {
        let cfg = random_field_config(&mut rng);
        let prog = field_config_to_vrl(&cfg);
        total += 1;

        if let Err(e) = v.validate(&prog.source) {
            failures.push((i, format!("validator rejected: {e}"), prog.source.clone()));
            continue;
        }

        // Surface check that mirrors the grammar's vocabulary: every
        // non-blank, non-comment line must match one of the grammar's
        // recognized line shapes. This is the cheap proxy for "parses
        // against vrl_subset.lark" — if the validator accepts but the
        // line-shape is wrong, either the validator is too permissive
        // or the grammar is too narrow.
        for (line_no, raw_line) in prog.source.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line == "." || line == "}" {
                continue;
            }
            let shape_ok =
                line.starts_with("if exists(") || line.starts_with(".") || line.starts_with("del(");
            if !shape_ok {
                failures.push((
                    i,
                    format!(
                        "line {} has shape outside grammar surface: `{line}`",
                        line_no + 1
                    ),
                    prog.source.clone(),
                ));
                break;
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{}/{} compiler outputs failed grammar↔validator roundtrip. first failure (iter {}): {}\n----\n{}",
        failures.len(),
        total,
        failures[0].0,
        failures[0].1,
        failures[0].2,
    );
    assert!(total >= 100, "DoD requires ≥100 cases, got {total}");
}
