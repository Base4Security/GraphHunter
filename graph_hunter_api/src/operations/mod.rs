//! Per-category operation implementations.
//!
//! Each submodule here contains `impl GraphHunterApi { … }` blocks that
//! add methods for one command category (session, hunt, entity, analytics,
//! …). Splitting by category keeps a single `GraphHunterApi` struct
//! without bloating any single file beyond a few hundred lines.

pub mod ai;
pub mod analytics;
pub mod anomaly;
pub mod dataset;
pub mod dsl;
pub mod enrichment;
pub mod entity;
pub mod export;
pub mod geoip;
pub mod graph_ops;
pub mod hunt;
pub mod ingestion;
pub mod sentinel;
pub mod sentinel_publish;
pub mod session;
pub mod sigma;
pub mod ticket;
