//! In-memory registry of background ingest jobs.
//!
//! `load_data_streaming` returns a `job_id` and does the real work on a
//! detached thread, reporting progress only through
//! [`crate::events::EventEmitter`]. That is fire-and-forget: the desktop
//! build routes it to the Tauri webview and a headless build drops it,
//! so an HTTP or MCP client that started an ingest had no completion
//! signal at all — not even a failure.
//!
//! This store is the tee. [`JobScopedEmitter`] wraps whatever emitter the
//! process already has, records the ingest lifecycle events here, and
//! **always forwards** to the inner emitter, so the desktop UI behaves
//! exactly as before. Clients then poll `/ingest/status`.
//!
//! Polling rather than SSE: MCP's client surface is `get`/`post` only, so
//! a stream would serve HTTP alone, and the mandatory journal-capture
//! middleware buffers whole response bodies, which a long-lived stream
//! breaks. An SSE endpoint stays strictly additive later — this store
//! already holds the state such a handler would replay.
//!
//! State is in memory and lost on restart. That is correct rather than a
//! limitation: a restart also kills the detached ingest thread, so a
//! surviving record would describe a job that is no longer running.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::dto::ingestion::{IngestJobSnapshot, LoadResult};
use crate::events::EventEmitter;
use crate::events::events::{INGEST_COMPLETE, INGEST_ERROR, INGEST_PROGRESS};
use crate::util::now_secs;

/// Hard cap on retained job records.
const MAX_JOBS: usize = 64;

/// A running job is never evicted. Safe because the number of concurrent
/// ingests is capped well below [`MAX_JOBS`] at the HTTP boundary.
pub const MAX_RUNNING_INGEST_JOBS: usize = 6;

/// A client that sees `state == "running"` with no update for this long
/// should presume the process restarted — the only genuine orphan case,
/// since every terminal path in the background thread (including the
/// `catch_unwind` panic handler) emits through the scoped emitter.
pub const STALE_AFTER_SECS: i64 = 300;

#[derive(Clone, Default)]
pub struct IngestJobStore {
    inner: Arc<RwLock<HashMap<String, IngestJobSnapshot>>>,
}

impl IngestJobStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a job as running. Called before `load_data_streaming`
    /// returns, so a status poll issued immediately after the response
    /// finds it.
    pub fn register(&self, job_id: &str, dataset_id: &str) {
        let now = now_secs();
        let snap = IngestJobSnapshot {
            job_id: job_id.to_string(),
            dataset_id: dataset_id.to_string(),
            state: "running".to_string(),
            phase: None,
            bytes_read: 0,
            bytes_total: 0,
            entities: 0,
            relations: 0,
            started_at: now,
            updated_at: now,
            result: None,
            error: None,
        };
        if let Ok(mut jobs) = self.inner.write() {
            Self::evict_if_needed(&mut jobs);
            jobs.insert(job_id.to_string(), snap);
        }
    }

    /// Drops the oldest *finished* record when at capacity. Running jobs
    /// are never evicted — losing one would strand a client polling for a
    /// result that is still coming.
    fn evict_if_needed(jobs: &mut HashMap<String, IngestJobSnapshot>) {
        if jobs.len() < MAX_JOBS {
            return;
        }
        let oldest = jobs
            .values()
            .filter(|j| j.state != "running")
            .min_by_key(|j| j.updated_at)
            .map(|j| j.job_id.clone());
        if let Some(id) = oldest {
            jobs.remove(&id);
        }
    }

    fn with_job<F: FnOnce(&mut IngestJobSnapshot)>(&self, job_id: &str, f: F) {
        if let Ok(mut jobs) = self.inner.write()
            && let Some(j) = jobs.get_mut(job_id)
        {
            f(j);
            j.updated_at = now_secs();
        }
    }

    pub fn update_progress(&self, job_id: &str, payload: &serde_json::Value) {
        self.with_job(job_id, |j| {
            if let Some(p) = payload.get("phase").and_then(|v| v.as_str()) {
                j.phase = Some(p.to_string());
            }
            if let Some(v) = payload.get("bytes_read").and_then(|v| v.as_u64()) {
                j.bytes_read = v;
            }
            if let Some(v) = payload.get("bytes_total").and_then(|v| v.as_u64()) {
                j.bytes_total = v;
            }
            if let Some(v) = payload.get("entities").and_then(|v| v.as_u64()) {
                j.entities = v as usize;
            }
            if let Some(v) = payload.get("relations").and_then(|v| v.as_u64()) {
                j.relations = v as usize;
            }
        });
    }

    pub fn finish_ok(&self, job_id: &str, payload: &serde_json::Value) {
        let result: Option<LoadResult> = payload
            .get("result")
            .cloned()
            .and_then(|v| serde_json::from_value(v).ok());
        self.with_job(job_id, |j| {
            j.state = "complete".to_string();
            j.phase = None;
            if let Some(r) = &result {
                j.entities = r.new_entities;
                j.relations = r.new_relations;
            }
            j.result = result.clone();
        });
    }

    pub fn finish_err(&self, job_id: &str, payload: &serde_json::Value) {
        let msg = payload
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("ingest failed")
            .to_string();
        self.with_job(job_id, |j| {
            j.state = "error".to_string();
            j.phase = None;
            j.error = Some(msg.clone());
        });
    }

    pub fn get(&self, job_id: &str) -> Option<IngestJobSnapshot> {
        self.inner.read().ok()?.get(job_id).cloned()
    }

    /// Most recently updated first.
    pub fn list(&self, limit: usize) -> Vec<IngestJobSnapshot> {
        let Ok(jobs) = self.inner.read() else {
            return Vec::new();
        };
        let mut all: Vec<IngestJobSnapshot> = jobs.values().cloned().collect();
        all.sort_by_key(|x| std::cmp::Reverse(x.updated_at));
        all.truncate(limit);
        all
    }

    pub fn running_count(&self) -> usize {
        self.inner
            .read()
            .map(|j| j.values().filter(|j| j.state == "running").count())
            .unwrap_or(0)
    }
}

/// Records one job's lifecycle into an [`IngestJobStore`] and forwards
/// every event to the emitter the process already had.
///
/// Per-job rather than global on purpose: `ingest-progress` payloads
/// carry no `job_id`, so a single shared recorder could not attribute
/// events when two ingests run concurrently. Because the background
/// thread threads this same emitter through `IngestContext`, every
/// progress site — including the registry ingestors for EVTX, Zeek and
/// PCAP — is captured without touching any emit call.
pub struct JobScopedEmitter {
    job_id: String,
    jobs: IngestJobStore,
    inner: Arc<dyn EventEmitter>,
}

impl JobScopedEmitter {
    pub fn new(job_id: String, jobs: IngestJobStore, inner: Arc<dyn EventEmitter>) -> Self {
        Self {
            job_id,
            jobs,
            inner,
        }
    }
}

impl EventEmitter for JobScopedEmitter {
    fn emit(&self, event: &str, payload: serde_json::Value) {
        match event {
            INGEST_PROGRESS => self.jobs.update_progress(&self.job_id, &payload),
            INGEST_COMPLETE => self.jobs.finish_ok(&self.job_id, &payload),
            INGEST_ERROR => self.jobs.finish_err(&self.job_id, &payload),
            _ => {}
        }
        // Always forward: the desktop webview must keep seeing every
        // event exactly as it did before this store existed.
        self.inner.emit(event, payload);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::NoopEmitter;

    fn store_with_job() -> (IngestJobStore, JobScopedEmitter) {
        let jobs = IngestJobStore::new();
        jobs.register("job-1", "ds-1");
        let em = JobScopedEmitter::new("job-1".into(), jobs.clone(), Arc::new(NoopEmitter));
        (jobs, em)
    }

    #[test]
    fn progress_events_land_on_the_snapshot() {
        let (jobs, em) = store_with_job();
        em.emit(
            INGEST_PROGRESS,
            serde_json::json!({"phase":"parsing","bytes_read":50,"bytes_total":100,
                               "entities":3,"relations":7}),
        );
        let snap = jobs.get("job-1").expect("job registered");
        assert_eq!(snap.state, "running");
        assert_eq!(snap.phase.as_deref(), Some("parsing"));
        assert_eq!(snap.bytes_read, 50);
        assert_eq!(snap.relations, 7);
    }

    #[test]
    fn completion_carries_the_load_result() {
        let (jobs, em) = store_with_job();
        em.emit(
            INGEST_COMPLETE,
            serde_json::json!({"job_id":"job-1","dataset_id":"ds-1","result":{
                "new_entities":4,"new_relations":9,"total_entities":4,
                "total_relations":9,"zero_triples":false}}),
        );
        let snap = jobs.get("job-1").expect("job");
        assert_eq!(snap.state, "complete");
        let r = snap.result.expect("result recorded");
        assert_eq!(r.new_relations, 9);
        assert!(!r.zero_triples);
    }

    /// A zero-triple ingest still "completes" — the client has to read
    /// the flag, which is exactly why it must survive into the snapshot.
    #[test]
    fn zero_triples_survives_into_the_snapshot() {
        let (jobs, em) = store_with_job();
        em.emit(
            INGEST_COMPLETE,
            serde_json::json!({"result":{"new_entities":0,"new_relations":0,
                "total_entities":0,"total_relations":0,"zero_triples":true}}),
        );
        let r = jobs.get("job-1").expect("job").result.expect("result");
        assert!(r.zero_triples);
    }

    #[test]
    fn errors_are_recorded_and_terminal() {
        let (jobs, em) = store_with_job();
        em.emit(INGEST_ERROR, serde_json::json!({"error":"mmap failed"}));
        let snap = jobs.get("job-1").expect("job");
        assert_eq!(snap.state, "error");
        assert_eq!(snap.error.as_deref(), Some("mmap failed"));
    }

    #[test]
    fn unknown_job_ids_are_ignored_not_created() {
        let jobs = IngestJobStore::new();
        let em = JobScopedEmitter::new("ghost".into(), jobs.clone(), Arc::new(NoopEmitter));
        em.emit(INGEST_PROGRESS, serde_json::json!({"phase":"parsing"}));
        assert!(jobs.get("ghost").is_none(), "must not resurrect a job");
    }

    /// Two concurrent ingests must not cross-contaminate. This is why the
    /// emitter is per-job: the payloads carry no job_id of their own.
    #[test]
    fn concurrent_jobs_are_attributed_separately() {
        let jobs = IngestJobStore::new();
        jobs.register("a", "ds-a");
        jobs.register("b", "ds-b");
        let ea = JobScopedEmitter::new("a".into(), jobs.clone(), Arc::new(NoopEmitter));
        let eb = JobScopedEmitter::new("b".into(), jobs.clone(), Arc::new(NoopEmitter));

        ea.emit(INGEST_PROGRESS, serde_json::json!({"entities":10}));
        eb.emit(INGEST_PROGRESS, serde_json::json!({"entities":99}));

        assert_eq!(jobs.get("a").expect("a").entities, 10);
        assert_eq!(jobs.get("b").expect("b").entities, 99);
    }

    /// Eviction must never drop a job someone is still waiting on.
    #[test]
    fn eviction_spares_running_jobs() {
        let jobs = IngestJobStore::new();
        jobs.register("keep-me", "ds");
        for i in 0..MAX_JOBS + 8 {
            let id = format!("done-{i}");
            jobs.register(&id, "ds");
            jobs.finish_ok(&id, &serde_json::json!({}));
        }
        assert!(
            jobs.get("keep-me").is_some(),
            "a running job must survive eviction pressure"
        );
        assert!(jobs.list(usize::MAX).len() <= MAX_JOBS);
    }

    #[test]
    fn list_is_newest_first_and_running_count_tracks() {
        let jobs = IngestJobStore::new();
        jobs.register("one", "ds");
        jobs.register("two", "ds");
        assert_eq!(jobs.running_count(), 2);
        jobs.finish_ok("one", &serde_json::json!({}));
        assert_eq!(jobs.running_count(), 1);
        assert_eq!(jobs.list(1).len(), 1);
    }

    /// The wrapped emitter still sees everything — the desktop UI is a
    /// consumer of these same events and must not regress.
    #[test]
    fn always_forwards_to_the_inner_emitter() {
        use crate::events::FnEmitter;
        use std::sync::Mutex;
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        let inner = Arc::new(FnEmitter(move |ev: &str, _p: serde_json::Value| {
            seen2.lock().expect("lock").push(ev.to_string());
        }));
        let jobs = IngestJobStore::new();
        jobs.register("j", "ds");
        let em = JobScopedEmitter::new("j".into(), jobs, inner);
        em.emit(INGEST_PROGRESS, serde_json::json!({}));
        em.emit("some-unrelated-event", serde_json::json!({}));
        em.emit(INGEST_COMPLETE, serde_json::json!({}));
        assert_eq!(
            seen.lock().expect("lock").as_slice(),
            &[
                INGEST_PROGRESS.to_string(),
                "some-unrelated-event".to_string(),
                INGEST_COMPLETE.to_string()
            ]
        );
    }
}
