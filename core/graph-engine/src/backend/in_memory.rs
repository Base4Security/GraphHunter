//! `GraphRead` / `GraphWrite` impls for [`crate::GraphHunter`].
//!
//! Pure delegation — every trait method forwards to an existing
//! inherent method. Kept in its own file so the trait definitions
//! (`mod.rs`) stay free of in-memory-specific details and a future
//! remote backend can live alongside (`remote.rs`) without cluttering
//! either.

use std::borrow::Cow;

use super::{GraphRead, GraphWrite};
use crate::entity::Entity;
use crate::errors::GraphError;
use crate::graph::GraphHunter;
use crate::relation::{CompactRelation, Relation};
use crate::types::EntityType;

impl GraphRead for GraphHunter {
    fn entity_count(&self) -> usize {
        GraphHunter::entity_count(self)
    }

    fn relation_count(&self) -> usize {
        GraphHunter::relation_count(self)
    }

    fn get_entity(&self, id: &str) -> Option<&Entity> {
        GraphHunter::get_entity(self, id)
    }

    fn get_compact_relations(&self, source_id: &str) -> Cow<'_, [CompactRelation]> {
        Cow::Owned(GraphHunter::get_compact_relations(self, source_id))
    }

    fn get_reverse_source_ids(&self, id: &str) -> Vec<String> {
        let sids = GraphHunter::get_reverse_source_sids(self, id);
        sids.iter()
            .map(|&sid| self.interner.resolve(sid).to_string())
            .collect()
    }

    fn entity_ids_for_type(&self, entity_type: &EntityType) -> Option<Vec<String>> {
        GraphHunter::entity_ids_for_type(self, entity_type)
    }

    fn entity_types_in_graph(&self) -> Vec<String> {
        GraphHunter::entity_types_in_graph(self)
    }

    fn materialize_relation(&self, compact: &CompactRelation) -> Relation {
        GraphHunter::materialize_relation(self, compact)
    }

    fn supports_simd(&self) -> bool {
        // The SIMD path now lives in `graph_hunter_matcher_ffi` per F2.13
        // (ADR-002). Core no longer owns the `simd` feature, so this
        // trait method — which callers use as a *backend capability*
        // hint — reports `false` from core's vantage point. Consumers
        // that want to dispatch to the C++ matcher check the feature
        // flag on the matcher-ffi crate directly.
        false
    }
}

impl GraphWrite for GraphHunter {
    fn add_entity(&mut self, entity: Entity) -> Result<(), GraphError> {
        GraphHunter::add_entity(self, entity)
    }

    fn add_relation(&mut self, relation: Relation) -> Result<(), GraphError> {
        GraphHunter::add_relation(self, relation)
    }
}
