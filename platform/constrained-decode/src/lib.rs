//! Grammar validator + constrained decoder for the VRL subset
//! GraphHunter ships.
//!
//! The deterministic compiler in `graph_hunter_vrl::field_config_to_vrl`
//! emits a small, well-shaped VRL sublanguage. The agentic
//! `parser_generator` optionally lets a local LLM refine that source
//! under the `optimization_hint = "fidelity"` path. Without a strict
//! grammar gate that refinement could drift into VRL features we don't
//! otherwise emit (loops, unconstrained stdlib calls, free-form
//! expressions), and any drift breaks the auditability story: the
//! whole point of the deterministic compiler is that the *shape* of
//! the program is predictable.
//!
//! This crate is the gate. The post-hoc [`VrlSubsetValidator`]
//! recognizes the exact constructs the compiler emits plus a small
//! enrichment subset (string built-ins, coalescing, conditional
//! metadata writes). Refinements that pass the validator are accepted;
//! everything else is rejected and the caller falls back to the
//! deterministic source.
//!
//! Generation-time constraint: the `xgrammar` feature wires the same
//! grammar into the candle decoder so the LLM emits VRL that parses
//! against the subset *by construction*. The trait surface is additive
//! — callers depend on [`GrammarValidator::validate`] regardless of
//! which path is active.

pub mod grammar;
pub mod vrl_subset;

#[cfg(feature = "xgrammar")]
pub mod xgrammar_backend;

pub use grammar::{GrammarValidator, ValidationError, ValidationResult};
pub use vrl_subset::VrlSubsetValidator;

#[cfg(feature = "xgrammar")]
pub use xgrammar_backend::{ConstrainedSampler, SamplerError, SamplerResult};
