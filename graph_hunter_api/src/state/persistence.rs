//! Session persistence helpers.
//!
//! These helpers resolve the per-user session data directory and validate
//! session IDs used as filename components. Moved from
//! `app/src-tauri/src/state.rs` so the canonical API owns disk layout;
//! Tauri re-exports them.

use std::fs;
use std::path::PathBuf;

/// `~/.local/share/GraphHunter/sessions` on Linux,
/// `%APPDATA%\GraphHunter\sessions` on Windows, etc. Resolved via the
/// `dirs` crate.
pub fn session_data_dir() -> Result<PathBuf, String> {
    dirs::data_dir()
        .ok_or_else(|| "Could not resolve app data directory".to_string())
        .map(|p| p.join("GraphHunter").join("sessions"))
}

/// Resolve the session directory and `mkdir -p` it. Useful as a startup
/// guard.
pub fn ensure_session_dir() -> Result<PathBuf, String> {
    let dir = session_data_dir()?;
    fs::create_dir_all(&dir).map_err(|e| format!("Failed to create session dir: {}", e))?;
    Ok(dir)
}

/// Validates that a session_id is safe to use as a filename component.
///
/// Session IDs are generated server-side as UUIDs, but we accept them from
/// the frontend over IPC, so a compromised frontend could send
/// `../../etc/passwd` or similar. Restrict to `[A-Za-z0-9_-]` to neutralize
/// path traversal and NUL-byte injection at the boundary.
pub fn validate_session_id(session_id: &str) -> Result<(), String> {
    if session_id.is_empty() || session_id.len() > 128 {
        return Err(format!(
            "session_id must be 1..=128 chars; got {}",
            session_id.len()
        ));
    }
    if !session_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err("session_id must contain only [A-Za-z0-9_-]".into());
    }
    Ok(())
}

/// Full path to the session file for the given validated id.
pub fn session_file_path(session_id: &str) -> Result<PathBuf, String> {
    validate_session_id(session_id)?;
    Ok(ensure_session_dir()?.join(format!("{}.json", session_id)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_uuid_style() {
        assert!(validate_session_id("550e8400-e29b-41d4-a716-446655440000").is_ok());
    }

    #[test]
    fn valid_alphanumeric_underscore() {
        assert!(validate_session_id("my_session_01").is_ok());
    }

    #[test]
    fn valid_single_char() {
        assert!(validate_session_id("a").is_ok());
    }

    #[test]
    fn valid_max_length() {
        let id = "a".repeat(128);
        assert!(validate_session_id(&id).is_ok());
    }

    #[test]
    fn reject_empty() {
        assert!(validate_session_id("").is_err());
    }

    #[test]
    fn reject_too_long() {
        let id = "a".repeat(129);
        assert!(validate_session_id(&id).is_err());
    }

    #[test]
    fn reject_path_traversal() {
        assert!(validate_session_id("../../etc/passwd").is_err());
        assert!(validate_session_id("..").is_err());
    }

    #[test]
    fn reject_dots() {
        assert!(validate_session_id("session.json").is_err());
    }

    #[test]
    fn reject_spaces() {
        assert!(validate_session_id("my session").is_err());
    }

    #[test]
    fn reject_nul_byte() {
        assert!(validate_session_id("session\0id").is_err());
    }

    #[test]
    fn reject_slashes() {
        assert!(validate_session_id("a/b").is_err());
        assert!(validate_session_id("a\\b").is_err());
    }

    #[test]
    fn reject_special_chars() {
        assert!(validate_session_id("session;rm -rf").is_err());
        assert!(validate_session_id("<script>").is_err());
        assert!(validate_session_id("id&cmd").is_err());
    }

    #[test]
    fn accept_hyphens_and_underscores() {
        assert!(validate_session_id("a-b_c-d").is_ok());
    }

    #[test]
    fn reject_unicode() {
        assert!(validate_session_id("sesion_\u{00e9}").is_err());
        assert!(validate_session_id("\u{1F600}").is_err());
    }
}
