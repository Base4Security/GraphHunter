//! Catalog YAML loader — built-in and user-supplied entries.
//!
//! Precedence (later wins):
//!
//! 1. Built-in YAMLs (`catalog/builtin/*.yaml`, embedded at compile time)
//! 2. User YAMLs under `$GRAPHHUNTER_CATALOG_DIR` (if set) or
//!    `$USERPROFILE/.graphhunter/catalog/` (Windows) /
//!    `$HOME/.graphhunter/catalog/` (Unix). Silent if missing.
//!
//! Validation per entry:
//!   * `id` is non-empty and `[a-zA-Z0-9\-_]+`
//!   * `mitre_id` matches `T\d{4}(\.\d{3})?`
//!   * `dsl_pattern` parses successfully via [`parse_dsl`]
//!   * `k_simplicity >= 1`
//!
//! Entries that fail validation are skipped and an error is appended
//! to [`CatalogSnapshot::load_errors`] — they do NOT panic or break
//! startup, so a single malformed user file can't take GraphHunter
//! down.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::dsl::parse_dsl;

use super::{CatalogEntry, CatalogSource};

/// Embedded built-in catalog YAMLs. Order matches `cat-NNN` numbering
/// but load order doesn't determine precedence (user files always
/// override built-ins by `id`).
const BUILTIN_YAMLS: &[(&str, &str)] = &[
    ("cat-001", include_str!("builtin/cat-001.yaml")),
    ("cat-002", include_str!("builtin/cat-002.yaml")),
    ("cat-003", include_str!("builtin/cat-003.yaml")),
    ("cat-004", include_str!("builtin/cat-004.yaml")),
    ("cat-005", include_str!("builtin/cat-005.yaml")),
    ("cat-006", include_str!("builtin/cat-006.yaml")),
    ("cat-007", include_str!("builtin/cat-007.yaml")),
    ("cat-008", include_str!("builtin/cat-008.yaml")),
    ("cat-009", include_str!("builtin/cat-009.yaml")),
    ("cat-010", include_str!("builtin/cat-010.yaml")),
    ("cat-011", include_str!("builtin/cat-011.yaml")),
    ("cat-012", include_str!("builtin/cat-012.yaml")),
    ("cat-013", include_str!("builtin/cat-013.yaml")),
    ("cat-014", include_str!("builtin/cat-014.yaml")),
    ("cat-015", include_str!("builtin/cat-015.yaml")),
    ("cat-016", include_str!("builtin/cat-016.yaml")),
    ("cat-017", include_str!("builtin/cat-017.yaml")),
    ("cat-018", include_str!("builtin/cat-018.yaml")),
    ("cat-019", include_str!("builtin/cat-019.yaml")),
    ("cat-020", include_str!("builtin/cat-020.yaml")),
    ("cat-021", include_str!("builtin/cat-021.yaml")),
    ("cat-022", include_str!("builtin/cat-022.yaml")),
    ("cat-023", include_str!("builtin/cat-023.yaml")),
    ("cat-024", include_str!("builtin/cat-024.yaml")),
    ("cat-025", include_str!("builtin/cat-025.yaml")),
    ("cat-026", include_str!("builtin/cat-026.yaml")),
    ("cat-027", include_str!("builtin/cat-027.yaml")),
    ("cat-028", include_str!("builtin/cat-028.yaml")),
    ("cat-029", include_str!("builtin/cat-029.yaml")),
    ("cat-030", include_str!("builtin/cat-030.yaml")),
];

/// A diagnostic emitted when a YAML file (built-in or user) failed to
/// parse or failed validation. Collected in [`CatalogSnapshot::load_errors`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CatalogLoadError {
    /// Path of the offending file. `None` for embedded built-ins
    /// (shouldn't ever produce errors; if it happens, the entry id
    /// is carried in `message` instead).
    pub source_path: Option<PathBuf>,
    /// Id of the entry, when we got far enough to know it. Helpful
    /// when the same `id` shows up in two files.
    pub entry_id: Option<String>,
    pub message: String,
}

/// The loaded catalog together with any diagnostics from the load.
///
/// `entries` is always non-empty in practice — the built-ins either
/// all parse (they're embedded and ship with the binary) or the build
/// failed at compile time. User files contribute additively.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CatalogSnapshot {
    pub entries: Vec<CatalogEntry>,
    pub load_errors: Vec<CatalogLoadError>,
}

/// Minimal on-disk schema. Separate from [`CatalogEntry`] so the public
/// struct can carry runtime-only fields (`source`) without requiring
/// them in the YAML.
#[derive(Debug, Deserialize)]
struct YamlEntry {
    id: String,
    name: String,
    mitre_id: String,
    description: String,
    dsl_pattern: String,
    k_simplicity: usize,
}

impl YamlEntry {
    fn into_catalog_entry(self, source: CatalogSource) -> CatalogEntry {
        CatalogEntry {
            id: self.id,
            name: self.name,
            mitre_id: self.mitre_id,
            description: self.description,
            dsl_pattern: self.dsl_pattern,
            k_simplicity: self.k_simplicity,
            source,
        }
    }
}

/// Build the merged snapshot. Called once by the `OnceLock` in the
/// parent module; callers should use
/// [`super::get_catalog_snapshot`] instead of this.
pub(super) fn build_snapshot() -> CatalogSnapshot {
    build_snapshot_with_dir(resolve_user_catalog_dir().as_deref())
}

/// Test-facing version of [`build_snapshot`] that takes the user dir
/// explicitly so integration tests can stage a tempdir without
/// depending on process-wide env vars.
pub(super) fn build_snapshot_with_dir(user_dir: Option<&std::path::Path>) -> CatalogSnapshot {
    let mut entries: Vec<CatalogEntry> = Vec::with_capacity(BUILTIN_YAMLS.len());
    let mut errors: Vec<CatalogLoadError> = Vec::new();

    // Built-ins first.
    for (id_hint, yaml) in BUILTIN_YAMLS {
        match load_from_str(yaml, CatalogSource::BuiltIn, None) {
            Ok(entry) => entries.push(entry),
            Err(msg) => errors.push(CatalogLoadError {
                source_path: None,
                entry_id: Some((*id_hint).to_string()),
                message: format!("built-in {id_hint}: {msg}"),
            }),
        }
    }

    // Then user files (later files override earlier by id).
    if let Some(dir) = user_dir {
        load_user_dir(dir, &mut entries, &mut errors);
    }

    CatalogSnapshot {
        entries,
        load_errors: errors,
    }
}

/// Discover the user catalog directory, honouring precedence:
///   1. `GRAPHHUNTER_CATALOG_DIR` env var (absolute path, wins outright)
///   2. `$USERPROFILE/.graphhunter/catalog` on Windows
///   3. `$HOME/.graphhunter/catalog` on Unix
///
/// Returns `None` when neither is set — we don't try to create the
/// directory just to look inside it.
fn resolve_user_catalog_dir() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("GRAPHHUNTER_CATALOG_DIR") {
        if !explicit.trim().is_empty() {
            return Some(PathBuf::from(explicit));
        }
    }
    let home = if cfg!(windows) {
        std::env::var("USERPROFILE").ok()
    } else {
        std::env::var("HOME").ok()
    }?;
    let dir = PathBuf::from(home).join(".graphhunter").join("catalog");
    if dir.exists() { Some(dir) } else { None }
}

/// Walk the user dir, merging any `*.yaml` / `*.yml` into `entries`.
/// Malformed files produce [`CatalogLoadError`]s but do not abort the
/// load.
fn load_user_dir(
    dir: &std::path::Path,
    entries: &mut Vec<CatalogEntry>,
    errors: &mut Vec<CatalogLoadError>,
) {
    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            errors.push(CatalogLoadError {
                source_path: Some(dir.to_path_buf()),
                entry_id: None,
                message: format!("read_dir failed: {e}"),
            });
            return;
        }
    };

    // Deterministic order: collect then sort by file name.
    let mut files: Vec<PathBuf> = read_dir
        .filter_map(|r| r.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|s| s.to_str())
                .map(|s| matches!(s, "yaml" | "yml"))
                .unwrap_or(false)
        })
        .collect();
    files.sort();

    for path in files {
        let yaml = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                errors.push(CatalogLoadError {
                    source_path: Some(path.clone()),
                    entry_id: None,
                    message: format!("read_to_string failed: {e}"),
                });
                continue;
            }
        };
        let source = CatalogSource::UserFile {
            path: path.to_string_lossy().into_owned(),
        };
        match load_from_str(&yaml, source, Some(&path)) {
            Ok(entry) => {
                if let Some(existing) = entries.iter_mut().find(|e| e.id == entry.id) {
                    *existing = entry;
                } else {
                    entries.push(entry);
                }
            }
            Err(msg) => {
                errors.push(CatalogLoadError {
                    source_path: Some(path.clone()),
                    entry_id: None,
                    message: msg,
                });
            }
        }
    }
}

/// Parse + validate a single YAML document. Returns the constructed
/// [`CatalogEntry`] on success or a one-line error message otherwise.
fn load_from_str(
    yaml: &str,
    source: CatalogSource,
    path: Option<&std::path::Path>,
) -> Result<CatalogEntry, String> {
    let parsed: YamlEntry = serde_yaml::from_str(yaml).map_err(|e| {
        let where_ = path
            .map(|p| format!(" ({})", p.display()))
            .unwrap_or_default();
        format!("yaml parse error{where_}: {e}")
    })?;
    let entry = parsed.into_catalog_entry(source);
    validate(&entry)?;
    Ok(entry)
}

fn validate(entry: &CatalogEntry) -> Result<(), String> {
    if entry.id.is_empty() {
        return Err("id is empty".to_string());
    }
    if !entry
        .id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!(
            "id '{}' must be alphanumeric + dash/underscore only",
            entry.id
        ));
    }
    if !is_valid_mitre_id(&entry.mitre_id) {
        return Err(format!(
            "mitre_id '{}' must match T\\d{{4}}(\\.\\d{{3}})?",
            entry.mitre_id
        ));
    }
    if entry.k_simplicity < 1 {
        return Err(format!(
            "k_simplicity must be >= 1 (got {})",
            entry.k_simplicity
        ));
    }
    if entry.dsl_pattern.trim().is_empty() {
        return Err("dsl_pattern is empty".to_string());
    }
    // Parse the pattern as a final gate. Using the entry name helps the
    // error message read naturally.
    parse_dsl(&entry.dsl_pattern, Some(&entry.name))
        .map_err(|e| format!("dsl_pattern fails to parse: {e}"))?;
    Ok(())
}

/// Validate a MITRE technique id: `T\d{4}` optionally followed by
/// `.\d{3}` for sub-techniques. Hand-rolled to avoid pulling `regex`
/// just for this.
fn is_valid_mitre_id(s: &str) -> bool {
    let bytes = s.as_bytes();
    // T####
    if bytes.len() < 5 || bytes[0] != b'T' {
        return false;
    }
    if !bytes[1..5].iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    match bytes.len() {
        5 => true,
        9 => bytes[5] == b'.' && bytes[6..9].iter().all(|b| b.is_ascii_digit()),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_mitre_ids() {
        for id in ["T1078", "T1078.004", "T1003", "T1562.001"] {
            assert!(is_valid_mitre_id(id), "{id} should be valid");
        }
    }

    #[test]
    fn invalid_mitre_ids() {
        for id in [
            "",
            "T",
            "T123",
            "T12345",
            "t1078",
            "T1078.",
            "T1078.01",
            "T1078.0044",
            "1078",
            "T1078-004",
        ] {
            assert!(!is_valid_mitre_id(id), "{id} should be invalid");
        }
    }

    #[test]
    fn validate_rejects_bad_id() {
        let e = CatalogEntry {
            id: "spaces in id".into(),
            name: "n".into(),
            mitre_id: "T1078".into(),
            description: "d".into(),
            dsl_pattern: "User -[Auth]-> Host".into(),
            k_simplicity: 1,
            source: CatalogSource::BuiltIn,
        };
        assert!(validate(&e).unwrap_err().contains("alphanumeric"));
    }

    #[test]
    fn validate_rejects_zero_k_simplicity() {
        let e = CatalogEntry {
            id: "cat-test".into(),
            name: "n".into(),
            mitre_id: "T1078".into(),
            description: "d".into(),
            dsl_pattern: "User -[Auth]-> Host".into(),
            k_simplicity: 0,
            source: CatalogSource::BuiltIn,
        };
        assert!(validate(&e).unwrap_err().contains("k_simplicity"));
    }

    #[test]
    fn validate_rejects_unparseable_pattern() {
        let e = CatalogEntry {
            id: "cat-test".into(),
            name: "n".into(),
            mitre_id: "T1078".into(),
            description: "d".into(),
            dsl_pattern: "nonsense without any arrow".into(),
            k_simplicity: 1,
            source: CatalogSource::BuiltIn,
        };
        assert!(validate(&e).unwrap_err().contains("fails to parse"));
    }

    #[test]
    fn load_from_str_happy_path() {
        let yaml = r#"
id: cat-test
name: Test Entry
mitre_id: T1078
description: test only
dsl_pattern: "User -[Auth]-> Host"
k_simplicity: 1
"#;
        let e = load_from_str(yaml, CatalogSource::BuiltIn, None).unwrap();
        assert_eq!(e.id, "cat-test");
        assert_eq!(e.k_simplicity, 1);
    }

    #[test]
    fn user_override_replaces_builtin_by_id() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let yaml = r#"
id: cat-001
name: OVERRIDDEN
mitre_id: T9999
description: replaced by user
dsl_pattern: "User -[Auth]-> Host"
k_simplicity: 1
"#;
        std::fs::write(tmp.path().join("cat-001.yaml"), yaml).unwrap();

        let snap = build_snapshot_with_dir(Some(tmp.path()));
        assert!(snap.load_errors.is_empty(), "{:?}", snap.load_errors);
        let overridden = snap.entries.iter().find(|e| e.id == "cat-001").unwrap();
        assert_eq!(overridden.name, "OVERRIDDEN");
        assert_eq!(overridden.mitre_id, "T9999");
        assert!(matches!(&overridden.source, CatalogSource::UserFile { .. }));
        // Other built-ins remain untouched.
        assert!(snap.entries.iter().any(|e| e.id == "cat-002"));
    }

    #[test]
    fn user_new_id_extends_catalog() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let yaml = r#"
id: cat-custom
name: Custom Hypothesis
mitre_id: T0042
description: analyst-supplied
dsl_pattern: "User -[Auth]-> Host"
k_simplicity: 1
"#;
        std::fs::write(tmp.path().join("custom.yaml"), yaml).unwrap();

        let snap = build_snapshot_with_dir(Some(tmp.path()));
        assert!(snap.load_errors.is_empty());
        let new_entry = snap
            .entries
            .iter()
            .find(|e| e.id == "cat-custom")
            .expect("custom entry should be appended");
        assert_eq!(new_entry.name, "Custom Hypothesis");
        // Total count is 30 built-in + 1 user.
        assert_eq!(snap.entries.len(), 31);
    }

    #[test]
    fn user_malformed_yaml_is_skipped_not_fatal() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Two files: one malformed, one valid. The valid one must still load.
        std::fs::write(tmp.path().join("broken.yaml"), "not: [valid yaml").unwrap();
        let good = r#"
id: cat-good
name: Good
mitre_id: T0001
description: d
dsl_pattern: "User -[Auth]-> Host"
k_simplicity: 1
"#;
        std::fs::write(tmp.path().join("good.yaml"), good).unwrap();

        let snap = build_snapshot_with_dir(Some(tmp.path()));
        assert_eq!(snap.load_errors.len(), 1);
        assert!(
            snap.load_errors[0]
                .source_path
                .as_ref()
                .unwrap()
                .ends_with("broken.yaml")
        );
        assert!(snap.entries.iter().any(|e| e.id == "cat-good"));
    }

    #[test]
    fn missing_user_dir_is_noop() {
        // `None` user dir → snapshot is just the built-ins.
        let snap = build_snapshot_with_dir(None);
        assert_eq!(snap.entries.len(), 30);
        assert!(snap.load_errors.is_empty());
    }

    #[test]
    fn load_from_str_missing_required_field_errors() {
        // `description` is missing.
        let yaml = r#"
id: cat-broken
name: Broken
mitre_id: T1078
dsl_pattern: "User -[Auth]-> Host"
k_simplicity: 1
"#;
        let err = load_from_str(yaml, CatalogSource::BuiltIn, None).unwrap_err();
        assert!(err.contains("description"), "got: {err}");
    }
}
