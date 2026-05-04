//! Mapping library — on-disk store of approved (FieldConfig, VRL, provenance)
//! artefacts, keyed by **fingerprints** derived from the FieldConfig's field
//! names + roles.
//!
//! Two paths write to it:
//!
//! - The review queue's `approve` hook publishes IngestNegotiator and
//!   ParserGenerator drafts as they clear the human gate.
//! - M7's `publish_mapping` MCP tool explicitly re-publishes a draft for
//!   cross-session sharing.
//!
//! Two paths read from it:
//!
//! - M5.e RAG lookup (fingerprint similarity) consults the library to
//!   warm-start `ingest_negotiate`.
//! - `export_ocsf` will prefer a library-resolved `mapping_hash` when
//!   the FieldConfig fingerprint hits a published entry (M6+).
//!
//! Storage: a single append-only JSONL file under `<data>/mapping_library/
//! mappings.jsonl`. One `PublishedMapping` per line. The library is
//! small (human-gated publications), so "read the whole file" is fine
//! for all operations today. If it ever gets hot, we can add an in-mem
//! index keyed by fingerprint without changing the on-disk format.
//!
//! The graceful-degradation contract from `dlq` / `drift` applies: if
//! the directory isn't writeable, `open` returns an error and the API
//! layer leaves the slot empty; calls then no-op.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::field_preview::{FieldConfig, FieldRole};

pub mod library_classifier;
pub mod rag;
pub use library_classifier::MappingLibraryClassifier;
pub use rag::{RagMatch, lookup};

#[derive(Debug)]
pub enum MappingLibraryError {
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for MappingLibraryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MappingLibraryError::Io(e) => write!(f, "mapping library I/O error: {e}"),
            MappingLibraryError::Json(e) => write!(f, "mapping library json error: {e}"),
        }
    }
}

impl std::error::Error for MappingLibraryError {}

impl From<std::io::Error> for MappingLibraryError {
    fn from(e: std::io::Error) -> Self {
        MappingLibraryError::Io(e)
    }
}

impl From<serde_json::Error> for MappingLibraryError {
    fn from(e: serde_json::Error) -> Self {
        MappingLibraryError::Json(e)
    }
}

/// Where a published mapping originated. Plumbs through to audit.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PublishSource {
    /// Approved via `agentic_review_approve` on an IngestNegotiator draft.
    IngestNegotiator,
    /// Approved via `agentic_review_approve` on a ParserGenerator draft.
    ParserGenerator,
    /// Explicit `publish_mapping` MCP call (M7).
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishedMapping {
    /// Deterministic id derived from the FieldConfig fingerprint +
    /// `published_at`. Stable per publication event.
    pub mapping_id: String,
    /// Stable fingerprint of the FieldConfig (`fp-<hex>`). Two configs
    /// that agree on field names + roles hash to the same fingerprint,
    /// which is what RAG lookup relies on.
    pub fingerprint: String,
    pub field_config: FieldConfig,
    /// VRL source when the draft was a ParserGenerator output. IngestNegotiator
    /// drafts carry only a FieldConfig, so this is `None` for those.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vrl_source: Option<String>,
    /// `sha256(vrl_source)` when `vrl_source` is set. Mirrors the
    /// `mapping_hash` stamped into OCSF provenance so downstream
    /// consumers can cross-reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapping_hash: Option<String>,
    /// OCSF class the mapping was approved against, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ocsf_category: Option<String>,
    pub source: PublishSource,
    /// Draft id from the review queue (when applicable) — lets audit
    /// trace every published mapping back to its human approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_draft_id: Option<String>,
    /// Unix seconds.
    pub published_at: i64,
}

/// Stable fingerprint over a FieldConfig: sorted `(raw_name, role)`
/// pairs hashed with FNV-1a (64-bit), hex-encoded. Case-insensitive on
/// `raw_name` so `User` and `user` land on the same shelf.
///
/// Ignores `entity_type`, `timestamp_format`, and `locale` — those
/// are tweaks on top of the structural shape; the shape is what
/// determines whether two log sources "look alike".
///
/// FNV-1a is not cryptographic — this is a bucketing hash, and the
/// library is expected to hold at most a few thousand entries. If
/// collisions ever matter in practice the readers can disambiguate by
/// full `(fingerprint, mapping_id)` tuples.
pub fn fingerprint(cfg: &FieldConfig) -> String {
    let mut pairs: Vec<(String, u8)> = cfg
        .mappings
        .iter()
        .map(|m| (m.raw_name.to_ascii_lowercase(), role_tag(&m.role)))
        .collect();
    pairs.sort();
    let mut h: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    for (name, role) in &pairs {
        for b in name.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(PRIME);
        }
        h ^= 0;
        h = h.wrapping_mul(PRIME);
        h ^= *role as u64;
        h = h.wrapping_mul(PRIME);
        h ^= 0;
        h = h.wrapping_mul(PRIME);
    }
    format!("fp-{h:016x}")
}

fn role_tag(role: &FieldRole) -> u8 {
    match role {
        FieldRole::Node => 1,
        FieldRole::Metadata => 2,
        FieldRole::Ignore => 3,
    }
}

/// On-disk store.
pub struct MappingLibraryStore {
    path: PathBuf,
    writer: Mutex<File>,
}

impl MappingLibraryStore {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, MappingLibraryError> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir)?;
        let path = dir.join("mappings.jsonl");
        let writer = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            writer: Mutex::new(writer),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append a published mapping to the library. Returns the
    /// mapping_id stamped on the entry (caller can persist it alongside
    /// the draft for round-trip).
    pub fn publish(&self, mut entry: PublishedMapping) -> Result<String, MappingLibraryError> {
        if entry.fingerprint.is_empty() {
            entry.fingerprint = fingerprint(&entry.field_config);
        }
        if entry.mapping_id.is_empty() {
            entry.mapping_id = format!("ml-{}-{}", entry.fingerprint, entry.published_at);
        }
        let line = serde_json::to_string(&entry)?;
        let mut w = self.writer.lock().expect("mapping library writer poisoned");
        writeln!(w, "{line}")?;
        w.flush()?;
        Ok(entry.mapping_id)
    }

    /// Return every published mapping, oldest first.
    pub fn list(&self) -> Result<Vec<PublishedMapping>, MappingLibraryError> {
        let file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<PublishedMapping>(&line) {
                Ok(m) => out.push(m),
                Err(e) => {
                    eprintln!("mapping_library: skipping malformed row: {e}");
                }
            }
        }
        Ok(out)
    }

    /// Return all mappings whose fingerprint equals `fp`. Most recent
    /// publication last.
    pub fn find_by_fingerprint(
        &self,
        fp: &str,
    ) -> Result<Vec<PublishedMapping>, MappingLibraryError> {
        Ok(self
            .list()?
            .into_iter()
            .filter(|m| m.fingerprint == fp)
            .collect())
    }

    /// Return the first mapping whose `mapping_hash` equals `hash`, if
    /// any. Used by export paths that want to surface the original
    /// approver's VRL when a dataset's FieldConfig still matches.
    pub fn find_by_hash(
        &self,
        hash: &str,
    ) -> Result<Option<PublishedMapping>, MappingLibraryError> {
        Ok(self
            .list()?
            .into_iter()
            .find(|m| m.mapping_hash.as_deref() == Some(hash)))
    }

    pub fn count(&self) -> Result<usize, MappingLibraryError> {
        Ok(self.list()?.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field_preview::{FieldConfig, FieldMapping, FieldRole};

    fn cfg_a() -> FieldConfig {
        FieldConfig {
            mappings: vec![
                FieldMapping {
                    raw_name: "User".into(),
                    role: FieldRole::Node,
                    entity_type: Some("User".into()),
                    timestamp_format: None,
                    locale: None,
                },
                FieldMapping {
                    raw_name: "Image".into(),
                    role: FieldRole::Node,
                    entity_type: Some("Process".into()),
                    timestamp_format: None,
                    locale: None,
                },
            ],
        }
    }

    fn cfg_a_reorder() -> FieldConfig {
        // Same fields, reversed order, different entity_type annotation —
        // fingerprint must stay stable.
        FieldConfig {
            mappings: vec![
                FieldMapping {
                    raw_name: "image".into(),
                    role: FieldRole::Node,
                    entity_type: Some("Binary".into()),
                    timestamp_format: None,
                    locale: None,
                },
                FieldMapping {
                    raw_name: "USER".into(),
                    role: FieldRole::Node,
                    entity_type: None,
                    timestamp_format: None,
                    locale: None,
                },
            ],
        }
    }

    fn cfg_b() -> FieldConfig {
        FieldConfig {
            mappings: vec![FieldMapping {
                raw_name: "host".into(),
                role: FieldRole::Node,
                entity_type: Some("Host".into()),
                timestamp_format: None,
                locale: None,
            }],
        }
    }

    #[test]
    fn fingerprint_is_order_and_case_insensitive() {
        let a = fingerprint(&cfg_a());
        let b = fingerprint(&cfg_a_reorder());
        assert_eq!(a, b);
        assert_ne!(a, fingerprint(&cfg_b()));
        assert!(a.starts_with("fp-"), "got: {a}");
    }

    #[test]
    fn fingerprint_changes_on_role_change() {
        let a = fingerprint(&cfg_a());
        let mut mutated = cfg_a();
        mutated.mappings[0].role = FieldRole::Metadata;
        let c = fingerprint(&mutated);
        assert_ne!(a, c);
    }

    #[test]
    fn publish_and_list_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = MappingLibraryStore::open(dir.path()).unwrap();

        let cfg = cfg_a();
        let entry = PublishedMapping {
            mapping_id: String::new(),
            fingerprint: String::new(),
            field_config: cfg.clone(),
            vrl_source: Some("# stub".into()),
            mapping_hash: Some("abc123".into()),
            ocsf_category: Some("process_activity".into()),
            source: PublishSource::ParserGenerator,
            origin_draft_id: Some("draft-x".into()),
            published_at: 1_000,
        };
        let id = store.publish(entry).unwrap();
        assert!(id.starts_with("ml-fp-"), "got: {id}");

        let all = store.list().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].mapping_id, id);
        assert_eq!(all[0].fingerprint, fingerprint(&cfg));
        assert_eq!(all[0].ocsf_category.as_deref(), Some("process_activity"));
        assert_eq!(all[0].origin_draft_id.as_deref(), Some("draft-x"));
    }

    #[test]
    fn find_by_fingerprint_filters_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let store = MappingLibraryStore::open(dir.path()).unwrap();
        for (cfg, hash) in [(cfg_a(), "h1"), (cfg_b(), "h2"), (cfg_a(), "h3")] {
            store
                .publish(PublishedMapping {
                    mapping_id: String::new(),
                    fingerprint: String::new(),
                    field_config: cfg,
                    vrl_source: None,
                    mapping_hash: Some(hash.into()),
                    ocsf_category: None,
                    source: PublishSource::IngestNegotiator,
                    origin_draft_id: None,
                    published_at: 1,
                })
                .unwrap();
        }
        let fp_a = fingerprint(&cfg_a());
        let hits = store.find_by_fingerprint(&fp_a).unwrap();
        assert_eq!(hits.len(), 2);
        let by_hash = store.find_by_hash("h2").unwrap().unwrap();
        assert_eq!(by_hash.fingerprint, fingerprint(&cfg_b()));
    }

    #[test]
    fn open_creates_missing_directory() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("nested").join("lib");
        let store = MappingLibraryStore::open(&dir).unwrap();
        assert_eq!(store.count().unwrap(), 0);
        assert!(dir.join("mappings.jsonl").exists());
    }
}
