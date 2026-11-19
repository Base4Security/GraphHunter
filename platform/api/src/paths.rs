//! Path containment for the ingest operations.
//!
//! `preview_ingest`, `load_data`, `load_data_with_config`,
//! `load_data_streaming` and `pcap_preview` all open a caller-supplied
//! path. Over Tauri that is fine — the path came from a native file
//! dialog the user drove. Over HTTP it is an arbitrary-file-read
//! primitive: the bearer token becomes "read any file this process can",
//! with the error string doubling as an existence oracle.
//!
//! The guard therefore lives here, in the same crate as the operations,
//! rather than in the HTTP handlers. A handler-layer convention is not an
//! invariant — the seventh path-taking route added six months from now
//! silently skips it. [`ResolvedPath`] is the only way to obtain a
//! `&Path` inside those operations, so adding one cannot compile without
//! threading a [`PathPolicy`] in, which forces the author to choose
//! between [`PathPolicy::LocalTrusted`] and [`PathPolicy::Rooted`].
//!
//! The policy is a **per-call argument, not process state**: one
//! `GraphHunterApi` is shared between the Tauri webview and the HTTP
//! server in the same process, so a global setting could not tell a
//! file-picker call apart from a remote one.
//!
//! ## Residual TOCTOU
//!
//! [`PathPolicy::resolve`] canonicalizes and validates, then the
//! operation opens the returned path. An attacker who can swap a symlink
//! inside an allowed root between those two steps can still redirect the
//! read. Closing that needs open-then-verify on a file handle
//! (`O_NOFOLLOW` / `FILE_FLAG_OPEN_REPARSE_POINT`), which the operations'
//! current `File::open` / `read_to_string` / `mmap` shapes do not
//! express. It is documented rather than fixed because it requires write
//! access inside a directory the operator deliberately exposed.

use std::path::{Component, Path, PathBuf};

use crate::error::ApiError;

/// Comma-separated list of absolute directories remote callers may read.
pub const INGEST_ROOT_ENV: &str = "GRAPHHUNTER_INGEST_ROOT";
/// Cap for the synchronous ingest ops, which read whole files into RAM.
pub const INGEST_MAX_BYTES_ENV: &str = "GRAPHHUNTER_INGEST_MAX_BYTES";
/// 2 GiB. `load_data` does `read_to_string` of the entire file, so an
/// uncapped 40 GB EVTX inside an allowed root would OOM the process.
pub const DEFAULT_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Windows reserved device names. Opening `CON`/`NUL`/`COM1` succeeds and
/// reads a device, never a file, so they are rejected by name.
const WINDOWS_DEVICE_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Who is asking, and therefore what they may open.
#[derive(Debug, Clone)]
pub enum PathPolicy {
    /// The path came from a native file dialog in the user's own desktop
    /// session. Tauri command handlers only. Deliberately not
    /// constructible from anything deserialized off the wire.
    LocalTrusted,
    /// An untrusted remote caller: confined to operator-configured roots.
    Rooted {
        /// Already-canonicalized allowed roots. Never empty.
        roots: Vec<PathBuf>,
        max_bytes: u64,
    },
}

/// A path that has passed [`PathPolicy::resolve`].
///
/// Exposes no `Deref`, no `as_str`, and no way to build one from a raw
/// string — the operations can only reach the filesystem through
/// [`ResolvedPath::as_path`].
#[derive(Debug, Clone)]
pub struct ResolvedPath {
    path: PathBuf,
    hint: String,
}

impl ResolvedPath {
    pub fn as_path(&self) -> &Path {
        &self.path
    }

    /// The caller's **original** string, for error messages.
    ///
    /// Never the resolved absolute path: `"read '{path}': {e}"` combined
    /// with the OS error text ("access denied" versus "not found") is a
    /// usable existence oracle for paths outside the root.
    pub fn display_hint(&self) -> &str {
        &self.hint
    }
}

impl PathPolicy {
    /// Builds the remote-caller policy from the environment.
    ///
    /// Deny by default: with [`INGEST_ROOT_ENV`] unset this returns a 403
    /// rather than silently allowing the whole filesystem, so merging the
    /// HTTP ingest routes changes no existing deployment's exposure until
    /// an operator opts in. Mirrors the flag-gated boundary in
    /// `http::escape_hatch`.
    pub fn from_env() -> Result<Self, ApiError> {
        let raw = std::env::var(INGEST_ROOT_ENV).unwrap_or_default();
        let declared: Vec<&str> = raw
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        if declared.is_empty() {
            return Err(Self::root_not_configured());
        }

        let mut roots = Vec::new();
        for d in declared {
            match std::fs::canonicalize(d) {
                Ok(p) => roots.push(p),
                Err(e) => tracing::warn!("{INGEST_ROOT_ENV}: ignoring unreadable root '{d}': {e}"),
            }
        }
        if roots.is_empty() {
            return Err(Self::root_not_configured());
        }

        let max_bytes = std::env::var(INGEST_MAX_BYTES_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_MAX_BYTES);

        Ok(PathPolicy::Rooted { roots, max_bytes })
    }

    fn root_not_configured() -> ApiError {
        ApiError::FeatureDisabled {
            feature: "remote_path_ingest".to_string(),
            hint: format!(
                "Set {INGEST_ROOT_ENV} to a comma-separated list of absolute directories \
                 holding ingestable logs. Remote path ingest is disabled until you do."
            ),
        }
    }

    /// Validates `raw` under this policy.
    ///
    /// [`PathPolicy::LocalTrusted`] passes the path through untouched:
    /// the desktop file picker legitimately opens anything the user
    /// selected, and the operations already surface I/O errors.
    pub fn resolve(&self, raw: &str) -> Result<ResolvedPath, ApiError> {
        let (roots, max_bytes) = match self {
            PathPolicy::LocalTrusted => {
                return Ok(ResolvedPath {
                    path: PathBuf::from(raw),
                    hint: raw.to_string(),
                });
            }
            PathPolicy::Rooted { roots, max_bytes } => (roots, *max_bytes),
        };

        // ---- Rejections that must happen before touching the FS ----
        if raw.trim().is_empty() {
            return Err(ApiError::InvalidInput("path is empty".into()));
        }
        if raw.contains('\0') {
            return Err(ApiError::InvalidInput("path contains a NUL byte".into()));
        }
        // UNC and extended-length prefixes reach remote hosts or bypass
        // normalization. A caller inside a root never needs either.
        if raw.starts_with("\\\\") || raw.starts_with("//") {
            return Err(ApiError::InvalidInput("UNC paths are not accepted".into()));
        }
        for comp in Path::new(raw).components() {
            if let Component::Normal(os) = comp {
                let name = os.to_string_lossy();
                let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
                if WINDOWS_DEVICE_NAMES.contains(&stem.as_str()) {
                    return Err(ApiError::InvalidInput(
                        "path names a reserved device".into(),
                    ));
                }
            }
        }

        // ---- Canonicalize, then contain ----
        // Resolves symlinks, `..`, and Windows 8.3 short names, so the
        // comparison below is against what will actually be opened.
        let canonical =
            std::fs::canonicalize(raw).map_err(|_| ApiError::NotFound("path not found".into()))?;

        // A path outside the root and a path that does not exist return
        // the SAME error on purpose — distinguishing them leaks the
        // layout of the host filesystem.
        let contained = roots.iter().any(|r| starts_with_components(&canonical, r));
        if !contained {
            return Err(ApiError::NotFound("path not found".into()));
        }

        let meta = std::fs::metadata(&canonical)
            .map_err(|_| ApiError::NotFound("path not found".into()))?;
        if !meta.is_file() {
            return Err(ApiError::InvalidInput("path is not a regular file".into()));
        }
        if meta.len() > max_bytes {
            return Err(ApiError::PayloadTooLarge(format!(
                "file is {} bytes, limit is {} ({INGEST_MAX_BYTES_ENV}); use POST /ingest/stream",
                meta.len(),
                max_bytes
            )));
        }

        Ok(ResolvedPath {
            // `canonicalize` yields a `\\?\`-prefixed path on Windows.
            // Some parser crates mishandle it, and the rejection above
            // would refuse it if a client ever echoed one back.
            path: strip_verbatim_prefix(canonical),
            hint: raw.to_string(),
        })
    }
}

/// True when `candidate` lies inside `root`, compared component by
/// component.
///
/// A string `starts_with` would accept `C:\logsEVIL` for root `C:\logs`.
/// Comparison is case-insensitive on Windows, where the filesystem is.
fn starts_with_components(candidate: &Path, root: &Path) -> bool {
    let mut cand = candidate.components();
    for rc in root.components() {
        match cand.next() {
            Some(cc) if components_eq(&cc, &rc) => {}
            _ => return false,
        }
    }
    true
}

fn components_eq(a: &Component<'_>, b: &Component<'_>) -> bool {
    if cfg!(windows) {
        a.as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(b.as_os_str().to_string_lossy().as_ref())
    } else {
        a == b
    }
}

/// Strips the Windows `\\?\` extended-length prefix that
/// `fs::canonicalize` adds, including the `\\?\UNC\` form.
fn strip_verbatim_prefix(p: PathBuf) -> PathBuf {
    if !cfg!(windows) {
        return p;
    }
    let s = p.to_string_lossy().to_string();
    match s.strip_prefix(r"\\?\") {
        Some(rest) => match rest.strip_prefix("UNC\\") {
            Some(unc) => PathBuf::from(format!(r"\\{unc}")),
            None => PathBuf::from(rest),
        },
        None => p,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn rooted(dir: &Path) -> PathPolicy {
        PathPolicy::Rooted {
            roots: vec![std::fs::canonicalize(dir).expect("canonicalize root")],
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }

    fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).expect("create");
        f.write_all(bytes).expect("write");
        p
    }

    #[test]
    fn local_trusted_passes_anything_through() {
        let r = PathPolicy::LocalTrusted
            .resolve("C:/anywhere/at/all.csv")
            .expect("LocalTrusted must not validate");
        assert_eq!(r.display_hint(), "C:/anywhere/at/all.csv");
    }

    #[test]
    fn accepts_a_file_inside_the_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let f = write_file(dir.path(), "log.csv", b"a,b\n1,2\n");
        let policy = rooted(dir.path());
        let resolved = policy
            .resolve(f.to_str().expect("utf8"))
            .expect("file inside root must resolve");
        assert!(resolved.as_path().ends_with("log.csv"));
        // Never hands back a \\?\-prefixed path.
        assert!(!resolved.as_path().to_string_lossy().starts_with(r"\\?\"));
    }

    #[test]
    fn rejects_traversal_out_of_the_root() {
        let parent = tempfile::tempdir().expect("tempdir");
        let root = parent.path().join("allowed");
        std::fs::create_dir(&root).expect("mkdir");
        let secret = write_file(parent.path(), "secret.txt", b"top secret");
        let policy = rooted(&root);

        let escape = root.join("..").join("secret.txt");
        let err = policy
            .resolve(escape.to_str().expect("utf8"))
            .expect_err("traversal must be refused");
        assert_eq!(err.status_code(), 404, "got {err}");
        // And the direct absolute path is refused identically.
        let err2 = policy
            .resolve(secret.to_str().expect("utf8"))
            .expect_err("outside-root must be refused");
        assert_eq!(err2.status_code(), 404);
    }

    /// A sibling directory whose name merely *starts with* the root's
    /// name must not pass — the bug a string `starts_with` would have.
    #[test]
    fn rejects_sibling_root_prefix_collision() {
        let parent = tempfile::tempdir().expect("tempdir");
        let root = parent.path().join("logs");
        let evil = parent.path().join("logsEVIL");
        std::fs::create_dir(&root).expect("mkdir root");
        std::fs::create_dir(&evil).expect("mkdir evil");
        let target = write_file(&evil, "x.csv", b"x");

        let err = rooted(&root)
            .resolve(target.to_str().expect("utf8"))
            .expect_err("prefix collision must be refused");
        assert_eq!(err.status_code(), 404);
    }

    #[test]
    fn rejects_directories_and_missing_files_alike() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = rooted(dir.path());

        let d = policy
            .resolve(dir.path().to_str().expect("utf8"))
            .expect_err("a directory is not ingestable");
        assert_eq!(d.status_code(), 400);

        let missing = policy
            .resolve(dir.path().join("nope.csv").to_str().expect("utf8"))
            .expect_err("missing file");
        assert_eq!(missing.status_code(), 404);
    }

    #[test]
    fn enforces_the_size_cap() {
        let dir = tempfile::tempdir().expect("tempdir");
        let f = write_file(dir.path(), "big.csv", &vec![b'x'; 4096]);
        let policy = PathPolicy::Rooted {
            roots: vec![std::fs::canonicalize(dir.path()).expect("canon")],
            max_bytes: 1024,
        };
        let err = policy
            .resolve(f.to_str().expect("utf8"))
            .expect_err("over-cap file must be refused");
        assert_eq!(err.status_code(), 413, "got {err}");
    }

    #[test]
    fn rejects_nul_unc_and_device_names() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = rooted(dir.path());
        for bad in [
            "",
            "  ",
            "with\0nul",
            r"\\server\share\f.csv",
            "//server/share",
        ] {
            assert!(policy.resolve(bad).is_err(), "must reject {bad:?}");
        }
        let dev = policy
            .resolve(dir.path().join("NUL").to_str().expect("utf8"))
            .expect_err("reserved device name");
        assert_eq!(dev.status_code(), 400);
    }

    /// The caller's own string comes back in errors and hints — never the
    /// canonical absolute path, which would be an existence oracle.
    #[test]
    fn hint_is_the_callers_string_not_the_canonical_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_file(dir.path(), "log.csv", b"x");
        let raw = format!("{}/./log.csv", dir.path().display());
        let resolved = rooted(dir.path()).resolve(&raw).expect("resolves");
        assert_eq!(resolved.display_hint(), raw);
        assert_ne!(
            resolved.display_hint(),
            resolved.as_path().to_string_lossy()
        );
    }

    #[test]
    fn from_env_denies_by_default() {
        // Not using the real env here (tests share a process); assert the
        // shape of the refusal the empty case produces.
        let err = PathPolicy::root_not_configured();
        assert_eq!(err.status_code(), 403);
        assert!(err.to_string().contains(INGEST_ROOT_ENV));
    }
}
