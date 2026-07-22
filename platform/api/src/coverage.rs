//! Coverage/completeness metadata: surfaces ingest-time incompleteness
//! (stopped_early, whole-file rejection) up to a session marker and onto query
//! answers as possibly_incomplete + a coverage time span. Behind
//! GRAPHHUNTER_COVERAGE (default off): with the flag off, answers are never
//! marked (current behavior). Closes ingest_completeness + completeness_flag
//! (design spec §17). source_watermarks/missing_sources need the streaming
//! poller (Fase F) and are NOT produced here.

use serde::{Deserialize, Serialize};

/// GRAPHHUNTER_COVERAGE: mark query answers with completeness metadata.
/// Default off. Truthy-to-enable (env_flag convention).
pub fn coverage_enabled() -> bool {
    std::env::var("GRAPHHUNTER_COVERAGE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Running completeness state for a session: set when any ingest into it did
/// not consume all its input.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct IngestCoverage {
    pub possibly_incomplete: bool,
    pub incomplete_reasons: Vec<String>,
}

impl IngestCoverage {
    /// Fold one ingest's completeness signals in. Monotonic: once incomplete,
    /// stays incomplete (a later clean ingest doesn't make past loss recoverable).
    pub fn observe(&mut self, stopped_early: bool, whole_file_rejected: bool) {
        if stopped_early {
            self.possibly_incomplete = true;
            let r = "stopped_early: ingest cut short (memory pressure)".to_string();
            if !self.incomplete_reasons.contains(&r) {
                self.incomplete_reasons.push(r);
            }
        }
        if whole_file_rejected {
            self.possibly_incomplete = true;
            let r = "whole_file_rejected: file exceeded parse limit".to_string();
            if !self.incomplete_reasons.contains(&r) {
                self.incomplete_reasons.push(r);
            }
        }
    }
}

/// Completeness metadata attached to a query answer.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AnswerCoverage {
    pub possibly_incomplete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage_start: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage_end: Option<i64>,
    pub incomplete_reasons: Vec<String>,
}

/// Build answer coverage from the session's ingest coverage and the graph's
/// edge-timestamp span. Off => all-clear (no marking, no span leaked).
pub fn answer_coverage(
    ic: &IngestCoverage,
    edge_ts_min: Option<i64>,
    edge_ts_max: Option<i64>,
) -> AnswerCoverage {
    if !coverage_enabled() {
        return AnswerCoverage::default();
    }
    AnswerCoverage {
        possibly_incomplete: ic.possibly_incomplete,
        coverage_start: edge_ts_min,
        coverage_end: edge_ts_max,
        incomplete_reasons: ic.incomplete_reasons.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Process-wide mutex for the `GRAPHHUNTER_COVERAGE`-mutating tests
    /// below. Cargo runs tests in parallel by default, so two tests setting/
    /// clearing the same env var would race. Mirrors the `ENV_LOCK`
    /// convention used in `journal.rs` / `operations/hunt.rs`.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn coverage_flag_defaults_off() {
        let _guard = lock_env();
        unsafe { std::env::remove_var("GRAPHHUNTER_COVERAGE") };
        assert!(!coverage_enabled());
        unsafe { std::env::set_var("GRAPHHUNTER_COVERAGE", "1") };
        assert!(coverage_enabled());
        unsafe { std::env::remove_var("GRAPHHUNTER_COVERAGE") };
    }

    #[test]
    fn observe_folds_incompleteness_signals() {
        let mut ic = IngestCoverage::default();
        assert!(!ic.possibly_incomplete);
        ic.observe(false, false); // a clean ingest
        assert!(!ic.possibly_incomplete);
        ic.observe(true, false); // one that stopped early
        assert!(ic.possibly_incomplete);
        assert!(ic
            .incomplete_reasons
            .iter()
            .any(|r| r.contains("stopped_early")));
    }

    #[test]
    fn answer_coverage_off_is_all_clear() {
        let _guard = lock_env();
        unsafe { std::env::remove_var("GRAPHHUNTER_COVERAGE") };
        let ic = IngestCoverage {
            possibly_incomplete: true,
            incomplete_reasons: vec!["stopped_early".into()],
        };
        let ac = answer_coverage(&ic, Some(100), Some(200));
        // flag off: no marking, no coverage span leaked.
        assert!(!ac.possibly_incomplete);
        assert!(ac.coverage_start.is_none());
    }

    #[test]
    fn answer_coverage_on_reflects_incompleteness_and_span() {
        let _guard = lock_env();
        unsafe { std::env::set_var("GRAPHHUNTER_COVERAGE", "1") };
        let ic = IngestCoverage {
            possibly_incomplete: true,
            incomplete_reasons: vec!["stopped_early".into()],
        };
        let ac = answer_coverage(&ic, Some(100), Some(200));
        unsafe { std::env::remove_var("GRAPHHUNTER_COVERAGE") };
        assert!(ac.possibly_incomplete);
        assert_eq!(ac.coverage_start, Some(100));
        assert_eq!(ac.coverage_end, Some(200));
        assert!(ac
            .incomplete_reasons
            .iter()
            .any(|r| r.contains("stopped_early")));
    }
}
