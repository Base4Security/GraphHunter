use graph_hunter_core::field_preview::{FieldConfig, FieldMapping, FieldRole};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Compiler version. Bump when the emitted source layout changes so the
/// resulting `mapping_hash` cleanly partitions across schema revisions and
/// the `ProvenanceCtx.mapping_version` can be derived from it.
pub const COMPILER_VERSION: u32 = 1;

/// Output of [`field_config_to_vrl`].
///
/// `source` is the textual VRL program. `mapping_hash` is
/// `sha256(source)` and is what the canonical projection stamps into
/// `ProvenanceCtx.mapping_hash`. `mapping_version` is the compiler's
/// own version and is *not* the user-controlled FieldConfig version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VrlProgram {
    pub source: String,
    pub mapping_hash: String,
    pub mapping_version: u32,
}

impl VrlProgram {
    /// Stable string for the provenance stamp:
    /// `"vrl-v{compiler_version}:{mapping_hash}"`. Suitable as both
    /// `mapping_id` and as a cache key.
    pub fn provenance_id(&self) -> String {
        format!("vrl-v{}:{}", self.mapping_version, self.mapping_hash)
    }
}

/// Compile a `FieldConfig` into a deterministic VRL program.
///
/// The output is purely a function of the input — same FieldConfig in,
/// byte-identical source out, identical `mapping_hash`. This is the
/// invariant that makes the hash usable as a provenance fingerprint.
pub fn field_config_to_vrl(cfg: &FieldConfig) -> VrlProgram {
    let mut out = String::new();
    let header = format!(
        "# graph_hunter_vrl compiler v{COMPILER_VERSION}\n\
         # Generated from FieldConfig with {} mapping(s).\n\
         # Pure function of FieldConfig: rerunning the compiler must yield\n\
         # byte-identical output — that is what makes the mapping_hash a\n\
         # stable identity for ProvenanceCtx.\n\n",
        cfg.mappings.len()
    );
    out.push_str(&header);
    out.push_str(". = parse_json!(string!(.message))\n");
    out.push_str(".canonical = {}\n");
    out.push_str(".canonical.entities = []\n");
    out.push_str(".canonical.metadata = {}\n");
    out.push_str(".canonical.timestamp = null\n\n");

    // Stable iteration order: sort by raw_name. The compiler's whole
    // point is determinism; map iteration order is not.
    let mut sorted: Vec<&FieldMapping> = cfg.mappings.iter().collect();
    sorted.sort_by(|a, b| a.raw_name.cmp(&b.raw_name));

    for m in sorted {
        match m.role {
            FieldRole::Ignore => {
                out.push_str(&format!("# ignore: {}\n", esc_comment(&m.raw_name)));
            }
            FieldRole::Metadata => {
                out.push_str(&emit_metadata(&m.raw_name));
            }
            FieldRole::Node => {
                let et = m.entity_type.as_deref().unwrap_or("Unknown");
                out.push_str(&emit_node(&m.raw_name, et));
                if let Some(fmt) = m.timestamp_format.as_deref() {
                    out.push_str(&emit_timestamp(&m.raw_name, fmt, m.locale.as_deref()));
                }
            }
        }
    }

    out.push_str("\n.\n");

    let mut hasher = Sha256::new();
    hasher.update(out.as_bytes());
    let mapping_hash = hex_lower(&hasher.finalize());

    VrlProgram {
        source: out,
        mapping_hash,
        mapping_version: COMPILER_VERSION,
    }
}

fn emit_node(raw: &str, entity_type: &str) -> String {
    let key = vrl_field_access(raw);
    format!(
        "# node: {raw} -> {et}\n\
         if exists({key}) {{\n  \
         .canonical.entities = push(.canonical.entities, {{\"type\": \"{et}\", \"value\": to_string!({key}), \"raw\": \"{raw}\"}})\n\
         }}\n",
        raw = esc_comment(raw),
        key = key,
        et = entity_type,
    )
}

fn emit_metadata(raw: &str) -> String {
    let key = vrl_field_access(raw);
    format!(
        "# metadata: {raw}\n\
         if exists({key}) {{\n  \
         .canonical.metadata.\"{raw}\" = {key}\n\
         }}\n",
        raw = esc_comment(raw),
        key = key,
    )
}

fn emit_timestamp(raw: &str, fmt: &str, locale: Option<&str>) -> String {
    let key = vrl_field_access(raw);
    let loc = locale.unwrap_or("en");
    format!(
        "# timestamp: {raw} (fmt={fmt}, locale={loc})\n\
         if exists({key}) {{\n  \
         .canonical.timestamp = parse_timestamp({key}, format: \"{fmt}\", locale: \"{loc}\") ?? null\n\
         }}\n",
        raw = esc_comment(raw),
        key = key,
        fmt = fmt,
        loc = loc,
    )
}

/// Quote a field name for VRL field access. VRL allows `.foo` for
/// identifiers, but anything with non-alphanumerics must be `."..."`.
fn vrl_field_access(raw: &str) -> String {
    let safe = raw.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if safe {
        format!(".{raw}")
    } else {
        let escaped = raw.replace('\\', "\\\\").replace('"', "\\\"");
        format!(".\"{escaped}\"")
    }
}

fn esc_comment(s: &str) -> String {
    s.replace('\n', " ").replace('\r', " ")
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(name: &str, role: FieldRole, et: Option<&str>) -> FieldConfig {
        FieldConfig {
            mappings: vec![FieldMapping {
                raw_name: name.to_string(),
                role,
                entity_type: et.map(|s| s.to_string()),
                timestamp_format: None,
                locale: None,
            }],
        }
    }

    #[test]
    fn deterministic_for_identical_config() {
        let a = field_config_to_vrl(&cfg("User", FieldRole::Node, Some("User")));
        let b = field_config_to_vrl(&cfg("User", FieldRole::Node, Some("User")));
        assert_eq!(a.source, b.source);
        assert_eq!(a.mapping_hash, b.mapping_hash);
    }

    #[test]
    fn hash_changes_when_role_changes() {
        let n = field_config_to_vrl(&cfg("User", FieldRole::Node, Some("User")));
        let m = field_config_to_vrl(&cfg("User", FieldRole::Metadata, None));
        assert_ne!(n.mapping_hash, m.mapping_hash);
    }

    #[test]
    fn order_independent_via_sorting() {
        let c1 = FieldConfig {
            mappings: vec![
                FieldMapping {
                    raw_name: "B".into(),
                    role: FieldRole::Node,
                    entity_type: Some("X".into()),
                    timestamp_format: None,
                    locale: None,
                },
                FieldMapping {
                    raw_name: "A".into(),
                    role: FieldRole::Node,
                    entity_type: Some("Y".into()),
                    timestamp_format: None,
                    locale: None,
                },
            ],
        };
        let c2 = FieldConfig {
            mappings: vec![
                FieldMapping {
                    raw_name: "A".into(),
                    role: FieldRole::Node,
                    entity_type: Some("Y".into()),
                    timestamp_format: None,
                    locale: None,
                },
                FieldMapping {
                    raw_name: "B".into(),
                    role: FieldRole::Node,
                    entity_type: Some("X".into()),
                    timestamp_format: None,
                    locale: None,
                },
            ],
        };
        assert_eq!(
            field_config_to_vrl(&c1).mapping_hash,
            field_config_to_vrl(&c2).mapping_hash
        );
    }

    #[test]
    fn quotes_non_identifier_field_names() {
        let p = field_config_to_vrl(&cfg("user.name", FieldRole::Node, Some("User")));
        assert!(p.source.contains(".\"user.name\""));
    }

    #[test]
    fn provenance_id_format() {
        let p = field_config_to_vrl(&cfg("U", FieldRole::Node, Some("User")));
        assert!(
            p.provenance_id()
                .starts_with(&format!("vrl-v{COMPILER_VERSION}:"))
        );
        assert_eq!(
            p.provenance_id().len(),
            format!("vrl-v{COMPILER_VERSION}:").len() + 64
        );
    }
}
