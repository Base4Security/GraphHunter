//! Fase G: flag readers for the two residual analytic-ish KQL surfaces —
//! one-click hunting templates (`run_hunting_template`) and the raw-KQL
//! escape hatch (`POST /kql` at the HTTP boundary, `apps/tauri`). Both
//! default ON (zero production behavior change); an explicit falsy env
//! value gates the surface off and steers callers to the local graph
//! tools (`hunt_run`, the hypothesis catalog, `sentinel_seed` /
//! `node_enrich` / `graph_path` / `graph_neighbors`).
//!
//! Semantics are copied exactly from the original raw-KQL escape hatch at
//! `apps/tauri/src-tauri/src/http/escape_hatch.rs`: only an explicit
//! `0`/`false`/`no`/`off` (case-insensitive, trimmed) disables; any other
//! value, or the var being unset, leaves the surface enabled.

/// Whether one-click hunting templates (`run_hunting_template`) are
/// enabled. Default: enabled. Only an explicit falsy value
/// ("0"/"false"/"no"/"off", case-insensitive) disables it.
pub fn hunting_templates_enabled() -> bool {
    match std::env::var("GRAPHHUNTER_HUNTING_TEMPLATES") {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ),
        Err(_) => true,
    }
}

/// Whether the raw-KQL escape hatch is enabled. Default: enabled. Only an
/// explicit falsy value ("0"/"false"/"no"/"off", case-insensitive)
/// disables it.
///
/// This is the canonical reader for `GRAPHHUNTER_KQL_ESCAPE_HATCH`. The
/// `apps/tauri` copy at `http/escape_hatch.rs` currently duplicates this
/// logic inline; a later task collapses it to delegate here so there is a
/// single source of truth for the flag's semantics.
pub fn kql_escape_hatch_enabled() -> bool {
    match std::env::var("GRAPHHUNTER_KQL_ESCAPE_HATCH") {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ),
        Err(_) => true,
    }
}

/// Process-wide lock guarding tests that mutate `GRAPHHUNTER_HUNTING_TEMPLATES`
/// / `GRAPHHUNTER_KQL_ESCAPE_HATCH`. `std::env::var`/`set_var` are
/// process-global, so two such tests running concurrently under the default
/// multi-threaded test runner can race (one test's assert can observe
/// another's in-flight value). `pub(crate)` so `operations::sentinel`'s gate
/// test and env-status test can share it.
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    // These tests mutate process-global env vars; serialize via ENV_LOCK to
    // avoid cross-test races under the default multi-threaded runner.
    #[test]
    fn hunting_templates_flag_defaults_on_and_respects_falsy() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Rust 2024 (this crate's edition) marks `env::set_var`/`remove_var`
        // unsafe (process-global mutation); wrap each call.
        unsafe {
            std::env::remove_var("GRAPHHUNTER_HUNTING_TEMPLATES");
        }
        assert!(hunting_templates_enabled(), "default must be enabled");

        for off in ["0", "false", "FALSE", "no", "off", " off "] {
            unsafe {
                std::env::set_var("GRAPHHUNTER_HUNTING_TEMPLATES", off);
            }
            assert!(!hunting_templates_enabled(), "{off:?} should disable");
        }
        for on in ["1", "true", "yes", "on", "anything"] {
            unsafe {
                std::env::set_var("GRAPHHUNTER_HUNTING_TEMPLATES", on);
            }
            assert!(hunting_templates_enabled(), "{on:?} should enable");
        }
        unsafe {
            std::env::remove_var("GRAPHHUNTER_HUNTING_TEMPLATES");
        }
    }

    #[test]
    fn kql_escape_hatch_flag_defaults_on_and_respects_falsy() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::remove_var("GRAPHHUNTER_KQL_ESCAPE_HATCH");
        }
        assert!(kql_escape_hatch_enabled(), "default must be enabled");

        for off in ["0", "false", "FALSE", "no", "off", " off "] {
            unsafe {
                std::env::set_var("GRAPHHUNTER_KQL_ESCAPE_HATCH", off);
            }
            assert!(!kql_escape_hatch_enabled(), "{off:?} should disable");
        }
        for on in ["1", "true", "yes", "on", "anything"] {
            unsafe {
                std::env::set_var("GRAPHHUNTER_KQL_ESCAPE_HATCH", on);
            }
            assert!(kql_escape_hatch_enabled(), "{on:?} should enable");
        }
        unsafe {
            std::env::remove_var("GRAPHHUNTER_KQL_ESCAPE_HATCH");
        }
    }
}
