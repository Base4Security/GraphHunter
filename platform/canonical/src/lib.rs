//! OCSF v1.4 + Provenance Extension canonical view for Graph Hunter.
//!
//! This crate does not introduce a second graph representation. It exposes
//! pure projection functions between the in-memory `(Entity, Relation, Entity)`
//! triple and an OCSF-shaped event tagged with a `ProvenanceCtx` audit trail.
//! The intent is that every hunt, score, and MCP tool keeps operating on the
//! existing graph model while exports, cold-store sinks, and mapping audits
//! speak OCSF.
//!
//! Boundaries:
//!   * `ocsf::*`  — strongly-typed subset of OCSF v1.4 classes actually
//!     emitted by the seven shipping parsers today.
//!   * `provenance::*` — `ProvenanceCtx` carried alongside every emitted event.
//!   * `project::*` — `triple_to_ocsf` / `ocsf_to_triple`. Pure, deterministic.

pub mod ocsf;
pub mod project;
pub mod provenance;

pub use ocsf::OcsfEvent;
pub use project::{ocsf_to_triple, triple_to_ocsf};
pub use provenance::ProvenanceCtx;

/// Checked-in OCSF v1.4 subset schema. Compile-time asset so tests and
/// runtime validators read the same bytes.
pub const OCSF_V1_4_SCHEMA: &str = include_str!("schema/ocsf_v1_4.json");
