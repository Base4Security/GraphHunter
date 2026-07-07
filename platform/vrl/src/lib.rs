//! Fast-lane VRL compiler + minimal interpreter (M3 wedge).
//!
//! This crate is the *deterministic* half of the slow-lane / fast-lane
//! split: it takes a [`FieldConfig`](graph_hunter_core::field_preview::FieldConfig)
//! and emits a textual VRL program that maps raw events into the canonical
//! shape the rest of GraphHunter consumes. The program is purely a function
//! of the FieldConfig — no LLM, no I/O, no nondeterminism — so its
//! `mapping_hash = sha256(source)` is a stable identity for the
//! `ProvenanceCtx` stamp.
//!
//! M3 ships the compiler and a minimal in-process interpreter that
//! understands the subset the compiler emits today. Embedding the upstream
//! `vrl` crate as the runtime is M3 follow-up work; the interpreter exists
//! so golden tests can exercise the compile-then-execute path without
//! pulling 5 MB of binary into the default build.

pub mod compiler;
pub mod interpreter;
pub mod sink;

pub use compiler::{VrlProgram, field_config_to_vrl};
pub use interpreter::{InterpretError, run_program};
pub use sink::{SinkRecord, SinkWriteStats};
