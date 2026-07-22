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
pub fn kql_escape_hatch_enabled() -> bool {
    match std::env::var("GRAPHHUNTER_KQL_ESCAPE_HATCH") {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ),
        Err(_) => true,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    // These tests mutate a process-global env var; keep them in one test to
    // avoid cross-test races under the default multi-threaded runner.
    #[test]
    fn flag_defaults_enabled_and_respects_explicit_falsy() {
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
