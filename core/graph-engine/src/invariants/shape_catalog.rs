//! Type-shape catalog — the canonical set of `(src_type, rel_type, dst_type)`
//! triples emitted by the 7 built-in parsers, plus a whitelist of
//! legitimate self-loop shapes.
//!
//! The catalog is compiled in via `include_str!` from the sibling
//! `catalog/builtin/shape_rules.yaml`. A `OnceLock` keeps a single
//! parsed copy per process.

use std::collections::HashSet;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::types::{EntityType, RelationType};

const SHAPE_RULES_YAML: &str = include_str!("../catalog/builtin/shape_rules.yaml");

#[derive(Debug, Deserialize)]
struct RawShape {
    src: String,
    rel: String,
    dst: String,
}

#[derive(Debug, Deserialize)]
struct RawSingleton {
    entity: String,
    rel: String,
}

#[derive(Debug, Deserialize)]
struct RawCatalog {
    #[serde(default)]
    rules: Vec<RawShape>,
    #[serde(default)]
    singletons: Vec<RawSingleton>,
}

/// A compiled catalog of allowed type-shape triples and self-loop
/// shapes. Both sets key on `(EntityType, RelationType, EntityType)` /
/// `(EntityType, RelationType)` using their `Display` form so the
/// `Other(String)` variants match exactly.
#[derive(Debug)]
pub struct ShapeCatalog {
    rules: HashSet<(String, String, String)>,
    singletons: HashSet<(String, String)>,
}

impl ShapeCatalog {
    fn from_raw(raw: RawCatalog) -> Self {
        let rules = raw
            .rules
            .into_iter()
            .map(|s| (s.src, s.rel, s.dst))
            .collect();
        let singletons = raw
            .singletons
            .into_iter()
            .map(|s| (s.entity, s.rel))
            .collect();
        Self { rules, singletons }
    }

    /// Parse from a YAML string. Used by tests and by
    /// [`default_shape_catalog`] on first access.
    pub fn from_yaml(src: &str) -> Result<Self, serde_yaml::Error> {
        let raw: RawCatalog = serde_yaml::from_str(src)?;
        Ok(Self::from_raw(raw))
    }

    /// Does `(src, rel, dst)` appear in the non-singleton rules?
    pub fn has_rule(&self, src: &EntityType, rel: &RelationType, dst: &EntityType) -> bool {
        self.rules
            .contains(&(src.to_string(), rel.to_string(), dst.to_string()))
    }

    /// Is `(entity, rel)` allowed as a same-timestamp self-loop?
    pub fn has_singleton(&self, entity: &EntityType, rel: &RelationType) -> bool {
        self.singletons
            .contains(&(entity.to_string(), rel.to_string()))
    }

    /// True when the rel_type is one we never enforce shape against
    /// (wildcard or user-defined).
    pub fn rel_type_is_free(rel: &RelationType) -> bool {
        matches!(rel, RelationType::Any | RelationType::Other(_))
    }

    /// True when an entity type is free-form (wildcard or user-defined).
    pub fn entity_type_is_free(t: &EntityType) -> bool {
        matches!(t, EntityType::Any | EntityType::Other(_))
    }

    /// Total number of concrete triples in the catalog.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl Default for ShapeCatalog {
    fn default() -> Self {
        ShapeCatalog::from_yaml(SHAPE_RULES_YAML)
            .expect("built-in shape_rules.yaml must parse at compile time")
    }
}

/// Shared process-wide default catalog.
pub fn default_shape_catalog() -> &'static ShapeCatalog {
    static CATALOG: OnceLock<ShapeCatalog> = OnceLock::new();
    CATALOG.get_or_init(ShapeCatalog::default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_catalog_parses_and_has_content() {
        let cat = default_shape_catalog();
        assert!(
            cat.rule_count() >= 20,
            "sanity: got {} rules",
            cat.rule_count()
        );
        assert!(cat.has_rule(&EntityType::User, &RelationType::Auth, &EntityType::Host));
        assert!(cat.has_rule(
            &EntityType::Process,
            &RelationType::Spawn,
            &EntityType::Process
        ));
        assert!(cat.has_rule(
            &EntityType::Process,
            &RelationType::Modify,
            &EntityType::Registry
        ));
    }

    #[test]
    fn singletons_are_recognised() {
        let cat = default_shape_catalog();
        assert!(cat.has_singleton(&EntityType::Host, &RelationType::Connect));
        assert!(cat.has_singleton(&EntityType::Process, &RelationType::Execute));
        assert!(!cat.has_singleton(&EntityType::Process, &RelationType::Auth));
    }

    #[test]
    fn free_forms_bypass_the_catalog() {
        assert!(ShapeCatalog::rel_type_is_free(&RelationType::Any));
        assert!(ShapeCatalog::rel_type_is_free(&RelationType::Other(
            "Consent".into()
        )));
        assert!(!ShapeCatalog::rel_type_is_free(&RelationType::Auth));

        assert!(ShapeCatalog::entity_type_is_free(&EntityType::Any));
        assert!(ShapeCatalog::entity_type_is_free(&EntityType::Other(
            "AppId".into()
        )));
        assert!(!ShapeCatalog::entity_type_is_free(&EntityType::User));
    }
}
