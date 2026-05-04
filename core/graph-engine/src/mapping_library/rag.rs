//! Fingerprint-similarity lookup over the mapping library.
//!
//! M5.e starting point. Similarity is token-Jaccard over the set of
//! lowercased field names — cheap and good enough as a warm-start
//! heuristic. M6 swaps this for sentence embeddings once the field-role
//! classifier checkpoint is in place; the signature here is designed so
//! the swap is a drop-in.
//!
//! Exact-fingerprint hits score 1.0. Partial shape overlap scores the
//! Jaccard of the field-name sets. Role-only differences (same names,
//! different Node/Metadata split) still cluster near 1.0 because the
//! field names match, which is the right bias for a warm-start.

use std::collections::HashSet;

use crate::field_preview::FieldConfig;
use crate::mapping_library::{
    MappingLibraryError, MappingLibraryStore, PublishedMapping, fingerprint,
};

#[derive(Debug, Clone)]
pub struct RagMatch {
    pub mapping: PublishedMapping,
    /// Similarity score in `[0.0, 1.0]`. Exact fingerprint match scores
    /// 1.0; partial shape overlap scores below 1.0.
    pub score: f32,
    /// Whether the match is fingerprint-exact. Callers that only want
    /// to warm-start on safe hits should gate on this.
    pub exact: bool,
}

/// Return up to `k` published mappings most similar to `cfg`, sorted
/// by descending similarity. Entries below `min_score` are dropped.
///
/// Returns an empty list when the store is empty. Propagates I/O
/// errors from the store so callers can distinguish "no matches" from
/// "lookup failed".
pub fn lookup(
    store: &MappingLibraryStore,
    cfg: &FieldConfig,
    k: usize,
    min_score: f32,
) -> Result<Vec<RagMatch>, MappingLibraryError> {
    if k == 0 {
        return Ok(Vec::new());
    }
    let fp = fingerprint(cfg);
    let query_tokens = tokens(cfg);
    let all = store.list()?;
    let mut scored: Vec<RagMatch> = all
        .into_iter()
        .map(|m| {
            let exact = m.fingerprint == fp;
            let score = if exact {
                1.0
            } else {
                jaccard(&query_tokens, &tokens(&m.field_config))
            };
            RagMatch {
                mapping: m,
                score,
                exact,
            }
        })
        .filter(|m| m.score >= min_score)
        .collect();

    scored.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.mapping.published_at.cmp(&a.mapping.published_at))
    });
    scored.truncate(k);
    Ok(scored)
}

fn tokens(cfg: &FieldConfig) -> HashSet<String> {
    cfg.mappings
        .iter()
        .map(|m| m.raw_name.to_ascii_lowercase())
        .collect()
}

fn jaccard(a: &HashSet<String>, b: &HashSet<String>) -> f32 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let intersect = a.intersection(b).count() as f32;
    let union = a.union(b).count() as f32;
    if union == 0.0 { 0.0 } else { intersect / union }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field_preview::{FieldMapping, FieldRole};
    use crate::mapping_library::PublishSource;

    fn cfg(names: &[&str]) -> FieldConfig {
        FieldConfig {
            mappings: names
                .iter()
                .map(|n| FieldMapping {
                    raw_name: (*n).into(),
                    role: FieldRole::Node,
                    entity_type: Some("User".into()),
                    timestamp_format: None,
                    locale: None,
                })
                .collect(),
        }
    }

    fn publish(store: &MappingLibraryStore, names: &[&str], hash: &str, published_at: i64) {
        store
            .publish(PublishedMapping {
                mapping_id: String::new(),
                fingerprint: String::new(),
                field_config: cfg(names),
                vrl_source: None,
                mapping_hash: Some(hash.into()),
                ocsf_category: None,
                source: PublishSource::IngestNegotiator,
                origin_draft_id: None,
                published_at,
            })
            .unwrap();
    }

    #[test]
    fn exact_fingerprint_scores_one() {
        let dir = tempfile::tempdir().unwrap();
        let store = MappingLibraryStore::open(dir.path()).unwrap();
        publish(&store, &["User", "Image"], "h1", 1);

        let query = cfg(&["user", "image"]); // case-insensitive → same fp
        let hits = lookup(&store, &query, 5, 0.0).unwrap();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].exact);
        assert!((hits[0].score - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn partial_shape_scores_below_one() {
        let dir = tempfile::tempdir().unwrap();
        let store = MappingLibraryStore::open(dir.path()).unwrap();
        publish(&store, &["User", "Image", "ParentImage"], "h1", 1);

        // Shares User+Image, misses ParentImage, adds Host → Jaccard = 2/4
        let query = cfg(&["User", "Image", "Host"]);
        let hits = lookup(&store, &query, 5, 0.0).unwrap();
        assert_eq!(hits.len(), 1);
        assert!(!hits[0].exact);
        assert!((hits[0].score - 0.5).abs() < 0.01, "got: {}", hits[0].score);
    }

    #[test]
    fn min_score_filters_low_overlap() {
        let dir = tempfile::tempdir().unwrap();
        let store = MappingLibraryStore::open(dir.path()).unwrap();
        publish(&store, &["User", "Image"], "h1", 1);

        let query = cfg(&["SourceIP", "DestIP"]); // zero overlap
        let hits = lookup(&store, &query, 5, 0.1).unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn top_k_is_sorted_by_score_then_recency() {
        let dir = tempfile::tempdir().unwrap();
        let store = MappingLibraryStore::open(dir.path()).unwrap();
        // Two entries with identical fingerprint but different publish
        // time — the later publication should come first.
        publish(&store, &["User", "Image"], "older", 1);
        publish(&store, &["User", "Image"], "newer", 2);
        // One entry with partial overlap.
        publish(&store, &["User", "Host"], "partial", 3);

        let hits = lookup(&store, &cfg(&["User", "Image"]), 3, 0.0).unwrap();
        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0].mapping.mapping_hash.as_deref(), Some("newer"));
        assert_eq!(hits[1].mapping.mapping_hash.as_deref(), Some("older"));
        assert_eq!(hits[2].mapping.mapping_hash.as_deref(), Some("partial"));
    }

    #[test]
    fn empty_store_returns_no_matches() {
        let dir = tempfile::tempdir().unwrap();
        let store = MappingLibraryStore::open(dir.path()).unwrap();
        let hits = lookup(&store, &cfg(&["any"]), 5, 0.0).unwrap();
        assert!(hits.is_empty());
    }
}
