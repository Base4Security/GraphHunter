//! ATT&CK Hypothesis Catalog — pre-built detection patterns mapped to MITRE techniques.
//!
//! # Sources
//!
//! Catalog entries are loaded at first access from three ordered
//! sources (later sources override earlier ones by `id`):
//!
//! 1. **Built-in** — 30 YAML files embedded via `include_str!` from
//!    `catalog/builtin/*.yaml`. Always available, never user-editable.
//! 2. **User file** — `*.yaml` under either
//!    `$GRAPHHUNTER_CATALOG_DIR` or `$USERPROFILE/.graphhunter/catalog/`.
//!    Silent if the dir is missing. Malformed files log + skip, they do
//!    NOT break startup.
//!
//! The merged snapshot is cached in a process-wide `OnceLock`.
//! Hot-reload is out of scope for MVP — restart to pick up new entries.
//!
//! # API
//!
//! Callers that just want the list should keep using
//! [`get_catalog()`] which returns a static slice and is cheap to call
//! many times. Callers that also want diagnostics (malformed user YAMLs,
//! etc.) should use [`get_catalog_snapshot()`] and read `load_errors`.

use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

use crate::analytics::RelSchemaEntry;
use crate::dsl::parse_dsl;

mod loader;

pub use loader::{CatalogLoadError, CatalogSnapshot};

/// A catalog entry: a named hypothesis pattern with MITRE ATT&CK mapping.
///
/// Strings are owned (`String` rather than `&'static str`) because
/// entries can come from runtime-loaded YAML files, not just the
/// embedded built-ins.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CatalogEntry {
    pub id: String,
    pub name: String,
    pub mitre_id: String,
    pub description: String,
    pub dsl_pattern: String,
    /// k-simplicity: max times a vertex can appear in a path. 1 = simple path (default).
    pub k_simplicity: usize,
    /// Where this entry was loaded from. Set by the loader, not the
    /// YAML file. Skipped on serialize so the JSON wire shape the
    /// transports see matches the pre-P2-C contract; callers that need
    /// provenance consume [`CatalogEntryWithStatus::source`].
    #[serde(skip, default)]
    pub source: CatalogSource,
}

/// Where a [`CatalogEntry`] was loaded from.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CatalogSource {
    #[default]
    BuiltIn,
    UserFile {
        /// Absolute path of the source YAML. Displayed verbatim in
        /// diagnostics so analysts can find the file that contributed
        /// or overrode an entry.
        path: String,
    },
}

/// A catalog entry paired with a compatibility report against the currently
/// loaded graph. `compatible=true` means every step of the DSL pattern has
/// at least one matching edge in the relation schema. When false, the two
/// `missing_*` fields enumerate what the dataset is lacking so the UI can
/// gray out the entry and explain why.
///
/// This closes the single biggest productivity gap from the post-hunt
/// feedback: running a cat-001..cat-016 pattern against a cloud-identity
/// dataset and getting `path_count=0` with no indication that the pattern
/// was never going to match in the first place.
#[derive(Clone, Debug, Serialize)]
pub struct CatalogEntryWithStatus {
    #[serde(flatten)]
    pub entry: CatalogEntry,
    pub compatible: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub missing_entity_types: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub missing_rel_types: Vec<String>,
    /// For each step in the pattern, the index that first had no matching
    /// triple in the schema. `None` when `compatible=true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_step_index: Option<usize>,
    /// Where the entry came from. Duplicates `entry.source` (which is
    /// `#[serde(skip)]`) but is surfaced here so the UI can render a
    /// "built-in" vs "user override" badge without a second round-trip.
    pub source: CatalogSource,
}

/// Cross-reference a catalog entry against the graph's relation schema.
///
/// The entry is compatible iff every step's `(origin_type, relation_type,
/// dest_type)` triple has at least one observed edge in the schema. Wildcards
/// (`*`) in the pattern make the corresponding axis match anything.
pub fn check_catalog_compatibility(
    entry: &CatalogEntry,
    schema: &[RelSchemaEntry],
) -> CatalogEntryWithStatus {
    // Parse the pattern once. If the pattern itself is malformed (shouldn't
    // happen for built-ins but cheap to guard), mark as incompatible.
    let parsed = match parse_dsl(&entry.dsl_pattern, Some(&entry.name)) {
        Ok(r) => r.hypothesis,
        Err(_) => {
            return CatalogEntryWithStatus {
                source: entry.source.clone(),
                entry: entry.clone(),
                compatible: false,
                missing_entity_types: Vec::new(),
                missing_rel_types: Vec::new(),
                failed_step_index: Some(0),
            };
        }
    };

    let mut missing_entity_types = std::collections::BTreeSet::new();
    let mut missing_rel_types = std::collections::BTreeSet::new();
    let mut failed_step_index: Option<usize> = None;

    for (idx, step) in parsed.steps.iter().enumerate() {
        let origin_s = format!("{}", step.origin_type);
        let rel_s = format!("{}", step.relation_type);
        let dest_s = format!("{}", step.dest_type);
        let matches = schema.iter().any(|r| {
            (origin_s == "*" || r.source_type == origin_s)
                && (rel_s == "*" || r.rel_type == rel_s)
                && (dest_s == "*" || r.target_type == dest_s)
        });
        if !matches {
            if failed_step_index.is_none() {
                failed_step_index = Some(idx);
            }
            // Only flag the individual missing axes that the dataset lacks.
            if origin_s != "*" && !schema.iter().any(|r| r.source_type == origin_s) {
                missing_entity_types.insert(origin_s.clone());
            }
            if dest_s != "*" && !schema.iter().any(|r| r.target_type == dest_s) {
                missing_entity_types.insert(dest_s.clone());
            }
            if rel_s != "*" && !schema.iter().any(|r| r.rel_type == rel_s) {
                missing_rel_types.insert(rel_s.clone());
            }
        }
    }

    let compatible = failed_step_index.is_none();
    CatalogEntryWithStatus {
        source: entry.source.clone(),
        entry: entry.clone(),
        compatible,
        missing_entity_types: missing_entity_types.into_iter().collect(),
        missing_rel_types: missing_rel_types.into_iter().collect(),
        failed_step_index,
    }
}

/// Process-wide cached catalog snapshot. Lazily built on first access.
static CATALOG_SNAPSHOT: OnceLock<CatalogSnapshot> = OnceLock::new();

/// Returns the full ATT&CK hypothesis catalog.
///
/// Backward-compatible signature — returns `&'static [CatalogEntry]` so
/// existing callers (`catalog.iter()`, `catalog.len()`, etc.) compile
/// unchanged. Underneath, the slice lives inside a process-wide
/// [`OnceLock`] so the snapshot is built once and never moves.
pub fn get_catalog() -> &'static [CatalogEntry] {
    &get_catalog_snapshot().entries
}

/// Returns the full catalog snapshot, including any errors encountered
/// while loading user-supplied YAML files.
///
/// Use this (instead of [`get_catalog()`]) when you need to surface
/// load diagnostics to the UI — e.g. the `cmd_get_catalog_diagnostics`
/// / `api.get_catalog_diagnostics()` call paths.
pub fn get_catalog_snapshot() -> &'static CatalogSnapshot {
    CATALOG_SNAPSHOT.get_or_init(loader::build_snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_catalog_has_30_entries() {
        let entries = get_catalog();
        assert_eq!(
            entries.len(),
            30,
            "built-in catalog should have exactly 30 entries"
        );
    }

    #[test]
    fn all_builtin_ids_unique() {
        let entries = get_catalog();
        let ids: std::collections::BTreeSet<&str> = entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(
            ids.len(),
            entries.len(),
            "duplicate ids in built-in catalog"
        );
    }

    #[test]
    fn all_builtin_patterns_parse() {
        for entry in get_catalog() {
            let result = parse_dsl(&entry.dsl_pattern, Some(&entry.name));
            assert!(
                result.is_ok(),
                "entry {} pattern fails to parse: {:?}",
                entry.id,
                result.err()
            );
        }
    }

    #[test]
    fn all_builtin_sources_marked_builtin() {
        for entry in get_catalog() {
            assert_eq!(
                entry.source,
                CatalogSource::BuiltIn,
                "entry {} should be marked BuiltIn (was {:?})",
                entry.id,
                entry.source
            );
        }
    }

    #[test]
    fn snapshot_load_errors_empty_for_builtin_only() {
        let snap = get_catalog_snapshot();
        // Developer machine may have user YAMLs — this just asserts
        // that none of the built-ins themselves produce errors.
        for err in &snap.load_errors {
            assert!(
                err.source_path.is_some(),
                "built-in load errors would have source_path=None, got: {err:?}"
            );
        }
    }
}
