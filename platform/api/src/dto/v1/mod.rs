//! DTO v1 — the current stable shape of every request/response type.
//!
//! Frozen at `platform/api` v1.0.0 (see F4.11). Breaking changes go to
//! `dto::v2` as a parallel namespace; callers opt in per endpoint.
//!
//! Adding a field: must be `#[serde(default)]` and additive. Removing
//! a field, renaming one, or changing its type requires a v2 module.

pub mod agentic;
pub mod ai;
pub mod analytics;
pub mod anomaly;
pub mod dataset;
pub mod dlq;
pub mod dsl;
pub mod enrichment;
pub mod entity;
pub mod export;
pub mod geoip;
pub mod graph_meta;
pub mod graph_ops;
pub mod health;
pub mod hunt;
pub mod ingestion;
pub mod invariants;
pub mod mapping_library;
pub mod schema;
pub mod sentinel;
pub mod session;
pub mod sigma;
pub mod ticket;
