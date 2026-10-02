//! Coverage/completeness metadata: surfaces ingest-time incompleteness
//! (stopped_early, whole-file rejection) up to a session marker and onto query
//! answers as possibly_incomplete + a coverage time span. Behind
//! GRAPHHUNTER_COVERAGE (default off): with the flag off, answers are never
//! marked (current behavior). Closes ingest_completeness + completeness_flag
//! (design spec §17). `answer_coverage` also carries source_watermarks/
//! missing_sources through to `AnswerCoverage`; call sites (see
//! `operations::hunt::session_answer_coverage`) pass real values sourced
//! from `SourceCoverage::snapshot`, populated by the one-shot `ingest_siem`
//! probe-every-call path (Fase F, Task 4) — not by a streaming poller, which
//! remains dormant/unwired (see `docs/architecture/source-independent-
//! ingestion.md` §5 for the standing walk-back condition on that gap).

use serde::{Deserialize, Serialize};

/// GRAPHHUNTER_COVERAGE: mark query answers with completeness metadata.
/// Default ON (falsy-to-disable) as of the enable-defaults fase; the journal
/// is bounded by GRAPHHUNTER_JOURNAL_MAX_BYTES rotation (Task 1).
pub fn coverage_enabled() -> bool {
    match std::env::var("GRAPHHUNTER_COVERAGE") {
        Ok(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off"),
        Err(_) => true,
    }
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
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub source_watermarks: std::collections::BTreeMap<String, i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_sources: Vec<String>,
}

/// Build answer coverage from the session's ingest coverage and the graph's
/// edge-timestamp span. Off => all-clear (no marking, no span leaked).
pub fn answer_coverage(
    ic: &IngestCoverage,
    edge_ts_min: Option<i64>,
    edge_ts_max: Option<i64>,
    source_watermarks: std::collections::BTreeMap<String, i64>,
    missing_sources: Vec<String>,
) -> AnswerCoverage {
    if !coverage_enabled() {
        return AnswerCoverage::default();
    }
    let possibly_incomplete = ic.possibly_incomplete || !missing_sources.is_empty();
    let mut incomplete_reasons = ic.incomplete_reasons.clone();
    if !missing_sources.is_empty() {
        incomplete_reasons.push(format!(
            "missing_sources: {} source(s) blind in the queried window",
            missing_sources.len()
        ));
    }
    AnswerCoverage {
        possibly_incomplete,
        coverage_start: edge_ts_min,
        coverage_end: edge_ts_max,
        incomplete_reasons,
        source_watermarks,
        missing_sources,
    }
}

/// GRAPHHUNTER_SOURCE_COVERAGE: track per-source watermarks + a circuit
/// breaker for the streaming poller's session marker. Default ON
/// (falsy-to-disable) as of the enable-defaults fase; the journal is bounded
/// by GRAPHHUNTER_JOURNAL_MAX_BYTES rotation (Task 1).
pub fn source_coverage_enabled() -> bool {
    match std::env::var("GRAPHHUNTER_SOURCE_COVERAGE") {
        Ok(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off"),
        Err(_) => true,
    }
}

/// Per-source coverage/breaker state tracked by [`SourceCoverage`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct PerSource {
    last_covered_ts: Option<i64>,
    consecutive_failures: u32,
    open: bool,
    missing: bool,
}

/// Session marker: per-source watermark + circuit breaker, keyed by
/// `source_id`. Closes the `circuit_breaker` context (design spec Fase F,
/// Task 3): tracks how far each source has been successfully covered and
/// whether repeated poll failures should stop further polling of it.
///
/// Deliberately a **replicated, minimal** breaker rather than a reuse of
/// `graph_hunter_core::ingest::source_poller::CircuitBreaker`: that type is
/// private to `source_poller`, is wired to `PollerMetrics` atomics, and uses
/// a monotonic-clock-based backoff window (`circuit_open_until`). Exposing
/// it as `pub(crate)` would couple this `api` crate to a core-internal
/// runtime type just to reuse the failure-counting arithmetic. The contract
/// here only needs a deterministic consecutive-failure counter — open when
/// `consecutive_failures >= max_failures` — which is what's implemented
/// below; it is intentionally clock-free so it's trivially unit-testable.
/// Temporal backoff (re-closing the breaker after some time has passed) is
/// NOT implemented here; a later task can layer it on top by injecting a
/// clock, reusing the same counter semantics.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SourceCoverage {
    sources: std::collections::BTreeMap<String, PerSource>,
}

impl SourceCoverage {
    pub fn new() -> Self {
        Self::default()
    }

    /// A successful pull covering up to `window_end_ts` for `source_id`:
    /// advances the watermark and closes the breaker.
    pub fn record_covered(&mut self, source_id: &str, window_end_ts: i64) {
        let entry = self.sources.entry(source_id.to_string()).or_default();
        entry.last_covered_ts = Some(window_end_ts);
        entry.consecutive_failures = 0;
        entry.open = false;
        entry.missing = false;
    }

    /// A failed pull for `source_id`. Increments the consecutive-failure
    /// counter; once it reaches `max_failures` the breaker opens (and stays
    /// open until the next [`Self::record_covered`]). Returns the resulting
    /// open state.
    pub fn record_failure(&mut self, source_id: &str, max_failures: u32) -> bool {
        let entry = self.sources.entry(source_id.to_string()).or_default();
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        if entry.consecutive_failures >= max_failures {
            entry.open = true;
        }
        entry.open
    }

    /// Is the source's breaker currently open? A **reporting** signal only
    /// — it does not gate anything here. `ingest_siem`'s probe-every-call
    /// design (see [`record_siem_outcome`]) deliberately never checks this
    /// to decide whether to skip a pull: skipping would leave a source
    /// blind forever, since nothing else would call `record_covered` to
    /// close it again. Surfaced on answers via `SourceCoverage::snapshot`
    /// so callers can see it, recoverable on the very next successful call.
    pub fn is_open(&self, source_id: &str) -> bool {
        self.sources.get(source_id).map(|s| s.open).unwrap_or(false)
    }

    /// Mark a window as not covered (breaker-skipped or errored) for
    /// `source_id`.
    pub fn record_missing(&mut self, source_id: &str) {
        self.sources.entry(source_id.to_string()).or_default().missing = true;
    }

    /// Snapshot for the answer: `(source -> last_covered_ts` where known`,
    /// sorted list of sources currently missing coverage or breaker-open)`.
    pub fn snapshot(&self) -> (std::collections::BTreeMap<String, i64>, Vec<String>) {
        let watermarks = self
            .sources
            .iter()
            .filter_map(|(id, s)| s.last_covered_ts.map(|ts| (id.clone(), ts)))
            .collect();
        // BTreeMap iteration is already key-sorted, so `missing` comes out sorted.
        let missing = self
            .sources
            .iter()
            .filter(|(_, s)| s.missing || s.open)
            .map(|(id, _)| id.clone())
            .collect();
        (watermarks, missing)
    }
}

/// Probe-every-call outcome recorder for `ingest_siem` (Fase F, Task 4).
///
/// `ingest_siem` is a one-shot on-demand pull, not a polling loop — there is
/// no future tick that would retry a source once its breaker opens. Skipping
/// the pull on `is_open` (as a naive breaker-consumer might) would leave that
/// source blind *forever*: nothing ever calls `record_covered` again to
/// close it. So this function does NOT check `is_open` and never skips —
/// every call is treated as an attempted probe of the source:
///   * `success == true`  -> `record_covered` (advances the watermark,
///     resets the failure counter, closes the breaker if it was open).
///   * `success == false` -> `record_failure` (may open the breaker) then
///     `record_missing` (marks this window blind for the answer surface).
/// `is_open`/`missing` remain purely a *reporting* signal surfaced on
/// answers — recoverable on the very next successful call.
pub fn record_siem_outcome(
    sc: &mut SourceCoverage,
    source_id: &str,
    success: bool,
    window_end_ts: i64,
    max_failures: u32,
) {
    if success {
        sc.record_covered(source_id, window_end_ts);
    } else {
        sc.record_failure(source_id, max_failures);
        sc.record_missing(source_id);
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
    fn coverage_flag_defaults_on_and_respects_explicit_falsy() {
        let _guard = lock_env();
        unsafe { std::env::remove_var("GRAPHHUNTER_COVERAGE") };
        assert!(coverage_enabled(), "unset env must default coverage on");

        for off in ["0", "false", "FALSE", "no", "off", " off "] {
            unsafe { std::env::set_var("GRAPHHUNTER_COVERAGE", off) };
            assert!(!coverage_enabled(), "{off:?} should disable coverage");
        }
        for on in ["1", "true", "yes", "on", "anything"] {
            unsafe { std::env::set_var("GRAPHHUNTER_COVERAGE", on) };
            assert!(coverage_enabled(), "{on:?} should leave coverage enabled");
        }
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
        // Coverage now defaults ON; this test exercises the explicit-off path.
        unsafe { std::env::set_var("GRAPHHUNTER_COVERAGE", "0") };
        let ic = IngestCoverage {
            possibly_incomplete: true,
            incomplete_reasons: vec!["stopped_early".into()],
        };
        let ac = answer_coverage(
            &ic,
            Some(100),
            Some(200),
            std::collections::BTreeMap::new(),
            vec![],
        );
        unsafe { std::env::remove_var("GRAPHHUNTER_COVERAGE") };
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
        let ac = answer_coverage(
            &ic,
            Some(100),
            Some(200),
            std::collections::BTreeMap::new(),
            vec![],
        );
        unsafe { std::env::remove_var("GRAPHHUNTER_COVERAGE") };
        assert!(ac.possibly_incomplete);
        assert_eq!(ac.coverage_start, Some(100));
        assert_eq!(ac.coverage_end, Some(200));
        assert!(ac
            .incomplete_reasons
            .iter()
            .any(|r| r.contains("stopped_early")));
    }

    #[test]
    fn answer_coverage_off_omits_source_fields() {
        let _g = lock_env();
        // Both flags now default ON; exercise the explicit-off path.
        unsafe { std::env::set_var("GRAPHHUNTER_SOURCE_COVERAGE", "0") };
        unsafe { std::env::set_var("GRAPHHUNTER_COVERAGE", "0") };
        let ic = IngestCoverage::default();
        let ac = answer_coverage(
            &ic,
            Some(1),
            Some(2),
            std::collections::BTreeMap::from([("la:ws".into(), 100i64)]),
            vec!["xdr".into()],
        );
        unsafe { std::env::remove_var("GRAPHHUNTER_SOURCE_COVERAGE") };
        unsafe { std::env::remove_var("GRAPHHUNTER_COVERAGE") };
        assert!(ac.source_watermarks.is_empty());
        assert!(ac.missing_sources.is_empty());
    }

    #[test]
    fn answer_coverage_on_carries_source_watermarks_and_missing() {
        let _g = lock_env();
        unsafe { std::env::set_var("GRAPHHUNTER_COVERAGE", "1") };
        let ic = IngestCoverage::default();
        let ac = answer_coverage(
            &ic,
            Some(1),
            Some(2),
            std::collections::BTreeMap::from([("la:ws".into(), 100i64)]),
            vec!["xdr".into()],
        );
        unsafe { std::env::remove_var("GRAPHHUNTER_COVERAGE") };
        assert_eq!(ac.source_watermarks.get("la:ws"), Some(&100));
        assert_eq!(ac.missing_sources, vec!["xdr".to_string()]);
        // a missing source makes the answer possibly_incomplete.
        assert!(ac.possibly_incomplete);
    }

    // Uses lock_env/ENV_LOCK defined above in this same module.

    #[test]
    fn source_coverage_flag_defaults_on_and_respects_explicit_falsy() {
        let _g = lock_env();
        unsafe { std::env::remove_var("GRAPHHUNTER_SOURCE_COVERAGE") };
        assert!(
            source_coverage_enabled(),
            "unset env must default source coverage on"
        );

        for off in ["0", "false", "FALSE", "no", "off", " off "] {
            unsafe { std::env::set_var("GRAPHHUNTER_SOURCE_COVERAGE", off) };
            assert!(!source_coverage_enabled(), "{off:?} should disable source coverage");
        }
        for on in ["1", "true", "yes", "on", "anything"] {
            unsafe { std::env::set_var("GRAPHHUNTER_SOURCE_COVERAGE", on) };
            assert!(
                source_coverage_enabled(),
                "{on:?} should leave source coverage enabled"
            );
        }
        unsafe { std::env::remove_var("GRAPHHUNTER_SOURCE_COVERAGE") };
    }

    #[test]
    fn breaker_opens_after_consecutive_failures_and_marks_missing() {
        let mut sc = SourceCoverage::new();
        // a good pull records the watermark, breaker closed.
        sc.record_covered("la:ws", 1000);
        assert!(!sc.is_open("la:ws"));
        // 3 consecutive failures (max_failures = 3) opens the breaker.
        assert!(!sc.record_failure("la:ws", 3));
        assert!(!sc.record_failure("la:ws", 3));
        assert!(sc.record_failure("la:ws", 3)); // now open
        assert!(sc.is_open("la:ws"));
        // an open breaker's window is recorded missing.
        sc.record_missing("la:ws");
        let (wms, missing) = sc.snapshot();
        assert_eq!(wms.get("la:ws"), Some(&1000)); // last good watermark
        assert!(missing.contains(&"la:ws".to_string()));
    }

    #[test]
    fn success_resets_failures() {
        let mut sc = SourceCoverage::new();
        sc.record_failure("la:ws", 3);
        sc.record_failure("la:ws", 3);
        sc.record_covered("la:ws", 2000); // success resets the counter
        assert!(!sc.record_failure("la:ws", 3)); // 1 failure again, not open
        assert!(!sc.is_open("la:ws"));
    }

    // -- record_siem_outcome (ingest_siem probe-every-call wiring, Task 4) --

    #[test]
    fn record_siem_outcome_success_records_watermark_and_closes() {
        let mut sc = SourceCoverage::new();
        record_siem_outcome(&mut sc, "sentinel:ws1", true, 1000, 3);
        assert!(!sc.is_open("sentinel:ws1"));
        let (watermarks, missing) = sc.snapshot();
        assert_eq!(watermarks.get("sentinel:ws1"), Some(&1000));
        assert!(missing.is_empty());
    }

    #[test]
    fn record_siem_outcome_opens_breaker_after_max_failures_and_marks_missing() {
        let mut sc = SourceCoverage::new();
        record_siem_outcome(&mut sc, "sentinel:ws1", false, 100, 3);
        record_siem_outcome(&mut sc, "sentinel:ws1", false, 200, 3);
        assert!(!sc.is_open("sentinel:ws1"));
        record_siem_outcome(&mut sc, "sentinel:ws1", false, 300, 3);
        assert!(sc.is_open("sentinel:ws1"));
        let (_watermarks, missing) = sc.snapshot();
        assert!(missing.contains(&"sentinel:ws1".to_string()));
    }

    #[test]
    fn record_siem_outcome_probe_every_call_recovers_after_failures() {
        // DESIGN CORRECTION regression test: ingest_siem is one-shot, so the
        // breaker must NOT be a "skip while open" gate — the very next call
        // (a probe, not a skip) has to be able to recover it via success.
        let mut sc = SourceCoverage::new();
        record_siem_outcome(&mut sc, "sentinel:ws1", false, 100, 3);
        record_siem_outcome(&mut sc, "sentinel:ws1", false, 200, 3);
        record_siem_outcome(&mut sc, "sentinel:ws1", false, 300, 3);
        assert!(sc.is_open("sentinel:ws1"));
        record_siem_outcome(&mut sc, "sentinel:ws1", true, 400, 3);
        assert!(!sc.is_open("sentinel:ws1"));
        let (watermarks, missing) = sc.snapshot();
        assert_eq!(watermarks.get("sentinel:ws1"), Some(&400));
        assert!(missing.is_empty());
    }
}
