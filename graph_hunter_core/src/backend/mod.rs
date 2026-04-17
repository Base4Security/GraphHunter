//! Graph backend traits (P2-B).
//!
//! The concrete [`crate::GraphHunter`] struct is an in-memory SoA
//! (type tags, interner, spillable edge store, reverse adjacency).
//! These traits define the semantic API so consumers — anomaly
//! scorer, GNN bridge, ingestion writer — work against
//! `&dyn GraphRead` / `&mut dyn GraphWrite` and don't know or care
//! about the representation.
//!
//! # What goes on the trait
//!
//! Semantic read/write of entities and relations. Anything a future
//! remote backend (Neo4j, a streaming MVCC store, …) would need to
//! reimplement.
//!
//! # What stays on [`crate::GraphHunter`]
//!
//! * `search_temporal_pattern_*` — the DFS matcher is the in-memory
//!   engine. A remote backend would have its own.
//! * `search_temporal_pattern_simd` — wired through `libgraphmatch`,
//!   InMemory-specific. `GraphRead::supports_simd()` is the capability
//!   hint.
//! * Analytics (`betweenness`, `pagerank`) — InMemory-only in MVP.
//!
//! # Migration story
//!
//! This session defines the traits and implements them for
//! `GraphHunter`. Downstream consumers (`AnomalyScorer::finalize` /
//! `score_path`, `gnn_bridge::extract_subgraph_features`,
//! `ingest::writer::GraphWriter`) keep their concrete `&GraphHunter`
//! parameters for now; a follow-up session switches them to
//! `&dyn GraphRead` one file at a time so each commit stays
//! bisectable.

use std::borrow::Cow;

use crate::entity::Entity;
use crate::errors::GraphError;
use crate::relation::{CompactRelation, Relation};
use crate::types::EntityType;

pub mod in_memory;

/// Read-only semantic view of a graph.
///
/// Every method is side-effect-free and cheap-when-backed-by-InMemory.
/// Remote backends may pay network I/O; if you're writing hot-path
/// code, prefer concrete `&GraphHunter` until the perf story for the
/// target backend is understood.
pub trait GraphRead {
    /// Total number of entities currently in the graph.
    fn entity_count(&self) -> usize;

    /// Total number of outgoing relations across all entities.
    fn relation_count(&self) -> usize;

    /// Retrieve a single entity by its string id, or `None` if the id
    /// isn't present.
    fn get_entity(&self, id: &str) -> Option<&Entity>;

    /// Outgoing relations for a source entity, in their compact wire
    /// form. Borrowed when the backend holds them in memory, owned
    /// when the backend has to build the list on the fly (e.g. a
    /// remote impl paging results).
    fn get_compact_relations(&self, source_id: &str) -> Cow<'_, [CompactRelation]>;

    /// String ids of every entity that has an edge pointing *into*
    /// the given id. The return is owned rather than borrowed because
    /// InMemory stores reverse adjacency as `StrId`s and has to
    /// resolve them back to strings; remote backends would have the
    /// same allocation either way.
    fn get_reverse_source_ids(&self, id: &str) -> Vec<String>;

    /// Every entity id present of the given type, or `None` if the
    /// type isn't observed in the graph at all.
    fn entity_ids_for_type(&self, entity_type: &EntityType) -> Option<Vec<String>>;

    /// Every entity-type name present, sorted lexicographically.
    /// Convenience for UIs and catalog compatibility checks.
    fn entity_types_in_graph(&self) -> Vec<String>;

    /// Re-hydrate a compact wire relation into its owned `Relation`
    /// form (resolves dataset tags, string ids, etc.).
    fn materialize_relation(&self, compact: &CompactRelation) -> Relation;

    /// Capability hint — `true` iff the backend has a SIMD search
    /// path that the hunt engine can use instead of the Rust DFS
    /// matcher. Defaults to `false`; only the InMemory impl overrides
    /// it when the `simd` feature is on.
    fn supports_simd(&self) -> bool {
        false
    }
}

/// Writable extension of [`GraphRead`]. Any backend that can ingest
/// data implements this; read-only backends (e.g. a frozen snapshot
/// file) don't.
pub trait GraphWrite: GraphRead {
    /// Insert a new entity. Idempotent on duplicate id (the existing
    /// entity stays — current `GraphHunter::add_entity` semantics).
    fn add_entity(&mut self, entity: Entity) -> Result<(), GraphError>;

    /// Insert a new relation. Source + destination entities must
    /// already exist (see `crate::GraphHunter::add_relation` for
    /// exact behaviour, which this impl delegates to).
    fn add_relation(&mut self, relation: Relation) -> Result<(), GraphError>;
}
