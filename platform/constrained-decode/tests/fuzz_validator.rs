//! Fuzz suite backing §10/A3 of the paper: "a malicious LLM output is
//! either rejected by the grammar or silently no-ops". We prove the
//! first half of that disjunction here.
//!
//! Two bodies of work:
//!
//!   1. **Compiler-output coverage.** Generate a wide cross-section of
//!      `FieldConfig`s (varying field counts, role mixes, entity types,
//!      timestamp formats, dotted/special raw names) and assert that
//!      *every* program the deterministic compiler emits validates. If
//!      this ever fails, the wedge is broken: the validator would be
//!      rejecting source the trusted compiler produces, and the
//!      `parser_generator` round-trip would have no fixed point.
//!
//!   2. **LLM-drift rejection.** Take a known-good compiler output,
//!      apply each of seven canonical drift mutations (insert a `for`
//!      loop, rename a function to a non-whitelist call, drop a closing
//!      brace, append a stray `;`, splice in a `match` block, append a
//!      free-form arithmetic line, swap an allowed RHS for an inline
//!      shell-out), and assert each mutation is caught.
//!
//! The reported rejection rate is `(2)`'s denominator over its passes.
//! The deterministic LCG keeps results reproducible across CI runs.

use graph_hunter_constrained_decode::{GrammarValidator, VrlSubsetValidator};
use graph_hunter_core::field_preview::{FieldConfig, FieldMapping, FieldRole};
use graph_hunter_vrl::field_config_to_vrl;

/// Tiny deterministic LCG so the suite is reproducible without pulling
/// in `rand`. Numerical Recipes constants.
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
    "RegistryKey",
    "NetFlow",
    "Module",
    "Time",
    "Email",
];

const RAW_NAME_FRAGMENTS: &[&str] = &[
    "user",
    "host",
    "process",
    "image",
    "parent_image",
    "command_line",
    "src_ip",
    "dst_ip",
    "domain",
    "hash",
    "ts",
    "occurred_at",
    "event.action",
    "event.category",
    "user.name",
    "process.pid",
    "AccountName",
    "TargetUser",
    "DestinationHostname",
    "QueryName",
    "EventID",
    "ProviderName",
    "Hashes",
    "ParentCommandLine",
];

const TIMESTAMP_FORMATS: &[&str] = &[
    "%Y-%m-%dT%H:%M:%S%.fZ",
    "%b %d %Y %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%d-%m-%Y %I:%M %p",
];

fn random_field_config(rng: &mut Lcg) -> FieldConfig {
    let n = rng.between(0, 12);
    let mut mappings = Vec::with_capacity(n);
    for i in 0..n {
        let raw = format!("{}_{}", rng.pick(RAW_NAME_FRAGMENTS), i);
        let role_pick = rng.next() % 100;
        let (role, entity_type, ts, locale) = if role_pick < 50 {
            (
                FieldRole::Node,
                Some((*rng.pick(ENTITY_TYPES)).to_string()),
                None,
                None,
            )
        } else if role_pick < 70 {
            (FieldRole::Metadata, None, None, None)
        } else if role_pick < 90 {
            (FieldRole::Ignore, None, None, None)
        } else {
            (
                FieldRole::Node,
                Some("Time".to_string()),
                Some((*rng.pick(TIMESTAMP_FORMATS)).to_string()),
                Some("en".into()),
            )
        };
        mappings.push(FieldMapping {
            raw_name: raw,
            role,
            entity_type,
            timestamp_format: ts,
            locale,
        });
    }
    FieldConfig { mappings }
}

#[test]
fn fuzz_compiler_outputs_all_validate() {
    let v = VrlSubsetValidator::new();
    let mut rng = Lcg::new(0xC0FFEE);
    let mut total = 0usize;
    let mut failures: Vec<(usize, String, String)> = Vec::new();
    for i in 0..2_000 {
        let cfg = random_field_config(&mut rng);
        let prog = field_config_to_vrl(&cfg);
        total += 1;
        if let Err(e) = v.validate(&prog.source) {
            failures.push((i, e.to_string(), prog.source.clone()));
        }
    }
    assert!(
        failures.is_empty(),
        "{}/{} compiler outputs failed validation. first failure on iter {}: {}\n----\n{}",
        failures.len(),
        total,
        failures[0].0,
        failures[0].1,
        failures[0].2,
    );
}

/// Each mutation rewrites `source` into something an LLM-drift might
/// plausibly emit. Returns the mutated source. None means the mutation
/// wasn't applicable to this particular source (skip without counting).
type Mutation = fn(&str) -> Option<String>;

fn mut_insert_for_loop(src: &str) -> Option<String> {
    let mut lines: Vec<&str> = src.lines().collect();
    let pos = lines
        .iter()
        .position(|l| l.trim_start().starts_with("if exists"))?;
    lines.insert(pos, "for x in [1, 2, 3] {");
    lines.insert(pos + 2, "}");
    Some(lines.join("\n"))
}

fn mut_unwhitelisted_call(src: &str) -> Option<String> {
    // Replace the first `string!(.x)` style call with `exfiltrate!(.x)`.
    let needle = "string!(";
    let pos = src.find(needle)?;
    let mut out = String::with_capacity(src.len() + 8);
    out.push_str(&src[..pos]);
    out.push_str("exfiltrate!(");
    out.push_str(&src[pos + needle.len()..]);
    Some(out)
}

fn mut_drop_closing_brace(src: &str) -> Option<String> {
    let pos = src.rfind("\n}\n")?;
    let mut out = String::with_capacity(src.len() - 1);
    out.push_str(&src[..pos]);
    out.push_str(&src[pos + 2..]);
    Some(out)
}

fn mut_append_stray_semicolon(src: &str) -> Option<String> {
    // Inject a `;`-separated double-statement line before the trailing `.`.
    let trailing = "\n.\n";
    let pos = src.rfind(trailing)?;
    let mut out = String::with_capacity(src.len() + 24);
    out.push_str(&src[..pos]);
    out.push_str("\n.x = 1; .y = 2");
    out.push_str(&src[pos..]);
    Some(out)
}

fn mut_splice_match(src: &str) -> Option<String> {
    let trailing = "\n.\n";
    let pos = src.rfind(trailing)?;
    let mut out = String::with_capacity(src.len() + 32);
    out.push_str(&src[..pos]);
    out.push_str("\n.x = match .y { 1 => 2 }");
    out.push_str(&src[pos..]);
    Some(out)
}

fn mut_freeform_arith(src: &str) -> Option<String> {
    let trailing = "\n.\n";
    let pos = src.rfind(trailing)?;
    let mut out = String::with_capacity(src.len() + 24);
    out.push_str(&src[..pos]);
    out.push_str("\n.canonical.metadata.score = (.a + .b) * 2");
    out.push_str(&src[pos..]);
    Some(out)
}

fn mut_inline_shell(src: &str) -> Option<String> {
    let trailing = "\n.\n";
    let pos = src.rfind(trailing)?;
    let mut out = String::with_capacity(src.len() + 32);
    out.push_str(&src[..pos]);
    out.push_str("\n.canonical.metadata.x = run_shell!(\"id\")");
    out.push_str(&src[pos..]);
    Some(out)
}

const MUTATIONS: &[(&str, Mutation)] = &[
    ("insert_for_loop", mut_insert_for_loop),
    ("unwhitelisted_call", mut_unwhitelisted_call),
    ("drop_closing_brace", mut_drop_closing_brace),
    ("append_stray_semicolon", mut_append_stray_semicolon),
    ("splice_match", mut_splice_match),
    ("freeform_arith", mut_freeform_arith),
    ("inline_shell", mut_inline_shell),
];

#[test]
fn fuzz_llm_drift_rejection_rate() {
    let v = VrlSubsetValidator::new();
    let mut rng = Lcg::new(0xBADC0DE);

    // Pre-build a corpus of valid base programs so each mutation has a
    // realistic substrate. We need configs rich enough that the drift
    // mutations have something to bite.
    let mut bases: Vec<String> = Vec::with_capacity(200);
    while bases.len() < 200 {
        let cfg = random_field_config(&mut rng);
        if cfg.mappings.is_empty() {
            continue;
        }
        let p = field_config_to_vrl(&cfg);
        if v.validate(&p.source).is_ok() {
            bases.push(p.source);
        }
    }

    let mut total = 0usize;
    let mut rejected = 0usize;
    let mut survivors: Vec<(&'static str, String)> = Vec::new();

    for (label, mutation) in MUTATIONS {
        for base in &bases {
            let Some(mutated) = mutation(base) else {
                continue;
            };
            total += 1;
            if v.validate(&mutated).is_err() {
                rejected += 1;
            } else if survivors.len() < 5 {
                survivors.push((label, mutated));
            }
        }
    }

    let rate = rejected as f64 / total as f64;
    eprintln!(
        "drift mutations: rejected {}/{} = {:.4} (1.0 == every drift caught)",
        rejected, total, rate
    );

    assert_eq!(
        rejected,
        total,
        "{} mutated programs slipped past the validator. first survivor [{}]:\n{}",
        total - rejected,
        survivors[0].0,
        survivors[0].1,
    );
}
