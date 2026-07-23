//! ProvenanceCtx: the audit trail carried alongside every OCSF event.
//!
//! Every canonical event emitted by any mapping — legacy parser, VRL
//! program, or agentic draft — carries this context so the forensic
//! question "what raw log produced this node?" has a deterministic answer.

use graph_hunter_core::FieldConfig;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Canonical provenance context. All fields non-optional except where
/// explicitly marked; the mapping layer is responsible for populating them
/// at projection time.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ProvenanceCtx {
    /// Schema version of the canonical view (e.g. "ocsf-1.4+gh-prov-0.1").
    pub schema_version: String,
    /// Human-readable identifier of the dataset this event belongs to.
    pub source_dataset_id: String,
    /// Stable id of the mapping that produced this event. A mapping is the
    /// `(FieldConfig | VRL program | hand-written parser)` tuple; the id is
    /// chosen by the mapping registry.
    pub mapping_id: String,
    /// Monotonically-increasing version of that mapping.
    pub mapping_version: u32,
    /// Content hash of the mapping artefact: bare `sha256(vrl_source)` for
    /// VRL programs; `"cfg:" + sha256(serde_json(FieldConfig))` for
    /// declarative field-mapping configs — hashed directly from the frozen
    /// `FieldConfig` recorded on the dataset at ingest time, independent of
    /// any VRL/compiler representation of it, so the identity survives a
    /// change to the VRL generator; constant `"builtin:<parser>"` tag for
    /// hand-written parsers where no source artefact exists.
    pub mapping_hash: String,
    /// Name of the parser family that produced the triple. One of the
    /// seven shipping names or `"vrl"` / `"configurable"`.
    pub parser_name: String,
    /// Optional confidence estimate in [0.0, 1.0]. Hand-written parsers set
    /// 1.0; heuristic auto-config sets a fractional value; agentic drafts
    /// set the LLM-reported confidence.
    pub confidence: f32,
    /// sha256 of the raw event bytes. Omitted from the wire entirely
    /// when the raw bytes are not retained (e.g. streamed sources
    /// with no replay buffer). Consumers that validate `64-hex` no
    /// longer have to whitelist `""` — a missing key is the
    /// canonical "not stamped" signal.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub raw_event_sha256: String,
    /// Ids of upstream events that contributed to this one. Empty for
    /// one-to-one mappings; populated for derived edges (e.g. a transitive
    /// `wasInformedBy` computed across two original events).
    #[serde(default)]
    pub upstream_ids: Vec<String>,
}

impl ProvenanceCtx {
    /// Canonical schema tag for the v0.1 provenance extension riding on
    /// top of OCSF v1.4.
    pub const SCHEMA_TAG: &'static str = "ocsf-1.4+gh-prov-0.1";

    /// Construct a provenance context for a hand-written parser. The
    /// mapping hash uses the constant `"builtin:<parser_name>"` tag, since
    /// no source artefact exists to hash.
    pub fn for_builtin_parser(
        parser_name: impl Into<String>,
        source_dataset_id: impl Into<String>,
        raw_event: &[u8],
    ) -> Self {
        let parser_name = parser_name.into();
        let mapping_hash = format!("builtin:{}", parser_name);
        Self {
            schema_version: Self::SCHEMA_TAG.to_string(),
            source_dataset_id: source_dataset_id.into(),
            mapping_id: format!("builtin:{}", parser_name),
            mapping_version: 1,
            mapping_hash,
            parser_name,
            confidence: 1.0,
            raw_event_sha256: hash_or_empty(raw_event),
            upstream_ids: Vec::new(),
        }
    }

    /// Construct a provenance context for a declarative field-mapping
    /// config. The mapping hash is `"cfg:" + sha256(serde_json(field_config))`
    /// — hashed directly from the frozen config, not from any downstream
    /// VRL/compiler representation of it. This is what makes the identity
    /// *frozen*: editing the session's current mapping after ingest cannot
    /// retroactively change an already-ingested edge's provenance, because
    /// the hash is derived from the `FieldConfig` recorded on the dataset at
    /// ingest time, not from whatever mapping is active "now".
    ///
    /// `serde_json::to_vec` is used (not a `Debug`/`Hash` derive) because
    /// `FieldConfig` is Vec-only (no `HashMap`), so its JSON serialization
    /// is already deterministic and stable across process runs.
    pub fn for_configurable(
        field_config: &FieldConfig,
        dataset_id: impl Into<String>,
        raw_event: &[u8],
    ) -> Self {
        let bytes = serde_json::to_vec(field_config).unwrap_or_default();
        let mapping_hash = format!("cfg:{}", sha256_hex(&bytes));
        Self {
            schema_version: Self::SCHEMA_TAG.to_string(),
            source_dataset_id: dataset_id.into(),
            mapping_id: mapping_hash.clone(),
            mapping_version: 1,
            mapping_hash,
            parser_name: "configurable".to_string(),
            confidence: 1.0,
            raw_event_sha256: hash_or_empty(raw_event),
            upstream_ids: Vec::new(),
        }
    }

    /// Construct a provenance context for a VRL program identified by its
    /// source bytes. The mapping hash is `sha256(vrl_source)`.
    pub fn for_vrl(
        mapping_id: impl Into<String>,
        mapping_version: u32,
        vrl_source: &[u8],
        source_dataset_id: impl Into<String>,
        raw_event: &[u8],
        confidence: f32,
    ) -> Self {
        Self {
            schema_version: Self::SCHEMA_TAG.to_string(),
            source_dataset_id: source_dataset_id.into(),
            mapping_id: mapping_id.into(),
            mapping_version,
            mapping_hash: sha256_hex(vrl_source),
            parser_name: "vrl".to_string(),
            confidence,
            raw_event_sha256: hash_or_empty(raw_event),
            upstream_ids: Vec::new(),
        }
    }
}

/// Hash the raw event bytes, but return `""` when the caller passed an
/// empty slice — that's the contract for "raw bytes not retained" and
/// it must be visually distinct from an actual zero-byte payload. The
/// previous behaviour (`sha256_hex(&[])`) emitted the famous
/// `e3b0c442…` constant for every export-time relation that lost its
/// raw bytes, fooling consumers into believing a real digest was
/// stamped.
fn hash_or_empty(raw_event: &[u8]) -> String {
    if raw_event.is_empty() {
        String::new()
    } else {
        sha256_hex(raw_event)
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02x}", byte);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_ctx_is_deterministic() {
        let a = ProvenanceCtx::for_builtin_parser("sysmon", "ds1", b"{\"EventID\":1}");
        let b = ProvenanceCtx::for_builtin_parser("sysmon", "ds1", b"{\"EventID\":1}");
        assert_eq!(a, b);
        assert_eq!(a.mapping_hash, "builtin:sysmon");
        assert_eq!(a.raw_event_sha256.len(), 64);
    }

    #[test]
    fn empty_raw_event_yields_empty_hash() {
        // 2026-05-06 (N1 fix): exports that don't retain raw bytes
        // pass &[] and must not get the SHA-256 of the empty string
        // (e3b0c442…), which would mislead consumers into thinking a
        // real digest was computed.
        let ctx = ProvenanceCtx::for_builtin_parser("sysmon", "ds1", &[]);
        assert!(ctx.raw_event_sha256.is_empty());
        let vrl_ctx = ProvenanceCtx::for_vrl("map-1", 1, b"src", "ds1", &[], 1.0);
        assert!(vrl_ctx.raw_event_sha256.is_empty());
    }

    #[test]
    fn vrl_ctx_hashes_source() {
        let src = b"parse_json!(.message)";
        let a = ProvenanceCtx::for_vrl("map-1", 1, src, "ds1", b"{}", 0.9);
        let b = ProvenanceCtx::for_vrl("map-1", 1, src, "ds1", b"{}", 0.9);
        assert_eq!(a.mapping_hash, b.mapping_hash);
        assert_ne!(a.mapping_hash, "builtin:vrl");
    }

    fn mapping(raw_name: &str, entity_type: &str) -> FieldConfig {
        use graph_hunter_core::{FieldMapping, FieldRole};
        FieldConfig {
            mappings: vec![FieldMapping {
                raw_name: raw_name.to_string(),
                role: FieldRole::Node,
                entity_type: Some(entity_type.to_string()),
                timestamp_format: None,
                locale: None,
            }],
        }
    }

    #[test]
    fn configurable_ctx_hashes_field_config_directly() {
        let cfg = mapping("User", "User");
        let a = ProvenanceCtx::for_configurable(&cfg, "ds1", b"{}");
        let b = ProvenanceCtx::for_configurable(&cfg, "ds1", b"{}");
        assert_eq!(a.mapping_hash, b.mapping_hash, "same config -> same hash");
        assert!(
            a.mapping_hash.starts_with("cfg:"),
            "got: {}",
            a.mapping_hash
        );
        assert_eq!(a.mapping_hash.len(), "cfg:".len() + 64);
        assert_eq!(a.parser_name, "configurable");
    }

    #[test]
    fn configurable_ctx_distinguishes_different_configs() {
        let cfg_a = mapping("User", "User");
        let cfg_b = mapping("User", "Process");
        let a = ProvenanceCtx::for_configurable(&cfg_a, "ds1", b"{}");
        let b = ProvenanceCtx::for_configurable(&cfg_b, "ds1", b"{}");
        assert_ne!(
            a.mapping_hash, b.mapping_hash,
            "different FieldConfig must yield different mapping_hash"
        );
    }
}
