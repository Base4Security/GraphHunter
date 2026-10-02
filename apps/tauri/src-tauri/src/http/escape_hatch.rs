//! The raw-KQL escape hatch: a feature-flagged, audited boundary for
//! analyst-supplied free-text KQL. Enabled by default (no external behavior
//! change); set GRAPHHUNTER_KQL_ESCAPE_HATCH to a falsy value to disable the
//! raw /kql path and steer callers to the graph tools. This gate lives at the
//! HTTP boundary so system-internal callers of `api.run_kql` (journal expand)
//! and system-generated collection KQL (graph_build/graph_propose) are
//! unaffected — only free-text analyst KQL entering via POST /kql is gated.

use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

/// Whether the raw-KQL escape hatch is enabled. Default: enabled. Only an
/// explicit falsy value ("0"/"false"/"no"/"off", case-insensitive) disables it.
///
/// Delegates to `graph_hunter_api::kql_flags::kql_escape_hatch_enabled()`,
/// the canonical reader for `GRAPHHUNTER_KQL_ESCAPE_HATCH`, so this crate and
/// `platform/api` never diverge on the flag's semantics.
pub fn kql_escape_hatch_enabled() -> bool {
    graph_hunter_api::kql_flags::kql_escape_hatch_enabled()
}

/// Structured response returned by POST /kql when the escape hatch is
/// disabled. Names the disabled feature and steers to the graph tools.
pub fn disabled_response() -> (StatusCode, Json<Value>) {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": "kql_escape_hatch_disabled",
            "hint": "Raw KQL is disabled (GRAPHHUNTER_KQL_ESCAPE_HATCH). Use the \
                     graph tools (sentinel_seed, node_enrich, hunt_run, graph_path, \
                     graph_neighbors) — the correlated graph, not raw source rows.",
            "source_tabular": true
        })),
    )
}

/// Process-wide lock guarding tests that mutate the `GRAPHHUNTER_KQL_ESCAPE_HATCH`
/// env var. `std::env::var`/`set_var` are process-global, so two such tests
/// running concurrently under the default multi-threaded test runner can race
/// (one test's assert can observe the other's in-flight value). Both
/// `flag_defaults_enabled_and_respects_explicit_falsy` (this module) and
/// `kql_gate_blocks_when_flag_disabled` (`http::siem`) acquire this lock
/// before touching the env var. `pub(crate)` so `siem.rs` can reach it.
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    // These tests mutate a process-global env var; serialize via ENV_LOCK to
    // avoid cross-test races under the default multi-threaded runner.
    #[test]
    fn flag_defaults_enabled_and_respects_explicit_falsy() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Rust 2024 (this crate's edition) marks `env::set_var`/`remove_var`
        // unsafe (process-global mutation); wrap each call, matching the
        // pattern already used in `lib.rs`.
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

    #[test]
    fn disabled_response_shape() {
        let (status, body) = disabled_response();
        assert_eq!(status, StatusCode::FORBIDDEN);
        let v: Value = body.0;
        assert_eq!(v["error"], "kql_escape_hatch_disabled");
        assert!(v["hint"].as_str().unwrap().contains("graph"));
    }
}
