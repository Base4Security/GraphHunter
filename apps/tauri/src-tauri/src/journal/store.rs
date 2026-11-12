//! Append-only per-hunt journal store (Task A2).
//!
//! Each hunt gets its own directory under a base path:
//!   `<base>/<hunt_id>/events.jsonl`  — one `HuntEvent` per line, append-only.
//!   `<base>/<hunt_id>/meta.json`     — `HuntMeta` summary, rewritten on every append.
//!
//! `JournalStore` is a thin `Arc<Mutex<Inner>>` handle so it can be cloned
//! into Tauri command handlers / shared app state. All file I/O happens
//! under the mutex — simple and synchronous, per the task brief.

use crate::journal::event::HuntEvent;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Per-hunt summary, mirrored to `meta.json` and returned by `list`/`read`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntMeta {
    pub id: String,
    pub label: Option<String>,
    pub started_at: i64,
    pub closed_at: Option<i64>,
    pub event_count: u64,
    pub cumulative_est_tokens: u64,
    pub entities_added: u64,
    pub relations_added: u64,
}

impl HuntMeta {
    fn new(id: String, label: Option<String>) -> Self {
        HuntMeta {
            id,
            label,
            started_at: now_millis(),
            closed_at: None,
            event_count: 0,
            cumulative_est_tokens: 0,
            entities_added: 0,
            relations_added: 0,
        }
    }
}

struct Inner {
    base: PathBuf,
    current: Option<String>,
}

/// Thread-safe handle to the journal store. Cheap to clone (wraps an `Arc`).
#[derive(Clone)]
pub struct JournalStore(Arc<Mutex<Inner>>);

// Monotonic counter appended to the millisecond timestamp so hunts started
// within the same millisecond (e.g. in tests) still get distinct ids.
// `std::time::SystemTime` is used instead of `chrono` because this crate
// does not depend on `chrono` directly (only transitively) — see task brief.
static HUNT_SEQ: AtomicU64 = AtomicU64::new(0);

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn new_hunt_id() -> String {
    let n = HUNT_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("hunt-{}-{}", now_millis(), n)
}

/// Hunt ids arrive from HTTP (`/journal/:id`, `/journal/export`) and are
/// joined onto `base`, so `../x` or an absolute path would escape it.
/// Same rule as `validate_session_id`: `[A-Za-z0-9_-]`, 1..=128 chars,
/// which every `new_hunt_id` satisfies.
fn is_valid_hunt_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

impl JournalStore {
    pub fn new(base: PathBuf) -> Self {
        JournalStore(Arc::new(Mutex::new(Inner {
            base,
            current: None,
        })))
    }

    /// Creates a new hunt dir + `meta.json`, sets it current, returns the id.
    pub fn start_hunt(&self, label: Option<String>) -> String {
        // I-3: recover from a poisoned mutex instead of propagating the
        // panic. Capture is best-effort audit trail, not the source of
        // truth — a prior panic under this lock (e.g. a filesystem fault)
        // must not brick every subsequent journal call for the rest of the
        // process lifetime and take the whole capture middleware down with
        // it. The recovered guard may reflect a partially-updated `Inner`,
        // but `Inner` only holds `base`/`current`, which are never
        // partially mutated mid-operation.
        let mut inner = self.0.lock().unwrap_or_else(|e| e.into_inner());
        Self::start_hunt_locked(&mut inner, label)
    }

    fn start_hunt_locked(inner: &mut Inner, label: Option<String>) -> String {
        let id = new_hunt_id();
        let dir = inner.base.join(&id);
        fs::create_dir_all(&dir).expect("journal: create hunt dir");
        let meta = HuntMeta::new(id.clone(), label);
        Self::write_meta(&dir, &meta);
        inner.current = Some(id.clone());
        id
    }

    /// Fallible twin of `start_hunt_locked`, used only from `append`'s lazy
    /// hunt-start path (I-3). `append` is best-effort: a filesystem fault
    /// while lazily opening a hunt must be logged and dropped, not panic
    /// under the `Inner` lock like the eager `start_hunt`/`current_hunt_id`
    /// paths still do (those are explicit, infrequent user/API actions
    /// where surfacing the failure is acceptable).
    fn try_start_hunt_locked(inner: &mut Inner, label: Option<String>) -> std::io::Result<String> {
        let id = new_hunt_id();
        let dir = inner.base.join(&id);
        fs::create_dir_all(&dir)?;
        let meta = HuntMeta::new(id.clone(), label);
        Self::try_write_meta(&dir, &meta)?;
        inner.current = Some(id.clone());
        Ok(id)
    }

    /// Current hunt id, lazily creating an anonymous hunt if none is open.
    pub fn current_hunt_id(&self) -> String {
        // I-3: recover from a poisoned mutex instead of propagating the
        // panic. Capture is best-effort audit trail, not the source of
        // truth — a prior panic under this lock (e.g. a filesystem fault)
        // must not brick every subsequent journal call for the rest of the
        // process lifetime and take the whole capture middleware down with
        // it. The recovered guard may reflect a partially-updated `Inner`,
        // but `Inner` only holds `base`/`current`, which are never
        // partially mutated mid-operation.
        let mut inner = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(id) = &inner.current {
            return id.clone();
        }
        Self::start_hunt_locked(&mut inner, None)
    }

    /// Appends one JSON line to the current hunt's `events.jsonl` and bumps
    /// `meta.json` counters. Lazily starts an anonymous hunt if none is open.
    ///
    /// I-3: best-effort by design. Hunt availability wins over audit
    /// completeness on this single-analyst desktop app — the capture
    /// middleware runs this with no panic guard, so any I/O failure here is
    /// logged via `tracing::error!` and the event is dropped, never
    /// propagated as a panic. A poisoned mutex is recovered from rather
    /// than repanicking (see the lock comment below), and every fallible
    /// filesystem step (lazy hunt dir creation, opening/appending to
    /// `events.jsonl`, writing `meta.json`) returns early on error instead
    /// of `.expect()`-ing. The happy path is unchanged. `meta`'s counters
    /// are only bumped in memory after the event line is durably written,
    /// so a failed write never inflates `cumulative_est_tokens`/
    /// `event_count`.
    pub fn append(&self, mut ev: HuntEvent) {
        // I-3: recover from a poisoned mutex instead of propagating the
        // panic. Capture is best-effort audit trail, not the source of
        // truth — a prior panic under this lock (e.g. a filesystem fault)
        // must not brick every subsequent journal call for the rest of the
        // process lifetime and take the whole capture middleware down with
        // it. The recovered guard may reflect a partially-updated `Inner`,
        // but `Inner` only holds `base`/`current`, which are never
        // partially mutated mid-operation.
        let mut inner = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let id = match &inner.current {
            Some(id) => id.clone(),
            None => match Self::try_start_hunt_locked(&mut inner, None) {
                Ok(id) => id,
                Err(e) => {
                    tracing::error!("journal: append failed: {e}");
                    return;
                }
            },
        };
        let dir = inner.base.join(&id);

        let mut meta = Self::read_meta(&dir).unwrap_or_else(|| HuntMeta::new(id.clone(), None));

        ev.seq = meta.event_count;
        let line = match serde_json::to_string(&ev) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("journal: append failed: {e}");
                return;
            }
        };

        if let Err(e) = Self::try_append_line(&dir, &line) {
            tracing::error!("journal: append failed: {e}");
            return;
        }

        meta.event_count += 1;
        meta.cumulative_est_tokens += ev.result.est_tokens;
        meta.entities_added += ev.result.new_entities.unwrap_or(0);
        meta.relations_added += ev.result.new_relations.unwrap_or(0);
        if let Err(e) = Self::try_write_meta(&dir, &meta) {
            // The event line above is already durably appended; only the
            // meta.json summary (counts) failed to update. Log and move on
            // rather than panic — a stale meta.json is far better than a
            // bricked API.
            tracing::error!("journal: append failed: {e}");
        }
    }

    /// Opens (creating if needed) `events.jsonl` and appends one line.
    /// Fallible twin of the inline open+writeln! `append` used to do
    /// directly (I-3) — propagates I/O errors instead of `.expect()`-ing.
    fn try_append_line(dir: &Path, line: &str) -> std::io::Result<()> {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("events.jsonl"))?;
        writeln!(f, "{}", line)
    }

    /// All known hunts (unordered), read from `meta.json` per subdirectory.
    pub fn list(&self) -> Vec<HuntMeta> {
        let inner = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let entries = match fs::read_dir(&inner.base) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };
        entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .filter_map(|dir| Self::read_meta(&dir))
            .collect()
    }

    /// Marks the current hunt closed (sets `closed_at`, clears `current` so
    /// the next `append`/`current_hunt_id` starts a fresh hunt). No-op
    /// (returns `None`) if no hunt is currently active.
    pub fn close_hunt(&self) -> Option<String> {
        // I-3: recover from a poisoned mutex instead of propagating the
        // panic. Capture is best-effort audit trail, not the source of
        // truth — a prior panic under this lock (e.g. a filesystem fault)
        // must not brick every subsequent journal call for the rest of the
        // process lifetime and take the whole capture middleware down with
        // it. The recovered guard may reflect a partially-updated `Inner`,
        // but `Inner` only holds `base`/`current`, which are never
        // partially mutated mid-operation.
        let mut inner = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let id = inner.current.take()?;
        let dir = inner.base.join(&id);
        if let Some(mut meta) = Self::read_meta(&dir) {
            meta.closed_at = Some(now_millis());
            Self::write_meta(&dir, &meta);
        }
        Some(id)
    }

    /// Reads a hunt's meta + full event log. `None` if the hunt is unknown.
    pub fn read(&self, id: &str) -> Option<(HuntMeta, Vec<HuntEvent>)> {
        if !is_valid_hunt_id(id) {
            return None;
        }
        let inner = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let dir = inner.base.join(id);
        let meta = Self::read_meta(&dir)?;
        let events = Self::read_events(&dir);
        Some((meta, events))
    }

    /// Per-hunt token accounting (Task B2): cumulative estimated tokens,
    /// event count, and a per-`kind` breakdown — the measured proof that
    /// journaling summaries instead of full bodies is cheaper. `None` if
    /// the hunt is unknown.
    pub fn stats(&self, id: &str) -> Option<serde_json::Value> {
        let (meta, events) = self.read(id)?;
        let mut by_kind: std::collections::BTreeMap<String, u64> =
            std::collections::BTreeMap::new();
        for ev in &events {
            *by_kind.entry(ev.kind.clone()).or_insert(0) += 1;
        }
        Some(serde_json::json!({
            "hunt_id": id,
            "cumulative_est_tokens": meta.cumulative_est_tokens,
            "event_count": meta.event_count,
            "by_kind": by_kind,
        }))
    }

    fn meta_path(dir: &Path) -> PathBuf {
        dir.join("meta.json")
    }

    fn read_meta(dir: &Path) -> Option<HuntMeta> {
        let data = fs::read_to_string(Self::meta_path(dir)).ok()?;
        serde_json::from_str(&data).ok()
    }

    fn write_meta(dir: &Path, meta: &HuntMeta) {
        Self::try_write_meta(dir, meta).expect("journal: write meta.json");
    }

    /// Fallible twin of `write_meta` (I-3), used by `append`'s best-effort
    /// path so a filesystem fault is logged and dropped rather than
    /// panicking under the store's lock.
    fn try_write_meta(dir: &Path, meta: &HuntMeta) -> std::io::Result<()> {
        let data = serde_json::to_string_pretty(meta).map_err(std::io::Error::other)?;
        fs::write(Self::meta_path(dir), data)
    }

    /// Reads `events.jsonl`, tolerating a partial/unparseable last line.
    fn read_events(dir: &Path) -> Vec<HuntEvent> {
        let file = match fs::File::open(dir.join("events.jsonl")) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<HuntEvent>(&l).ok())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::event::{EventResult, HuntEvent};

    fn tmp() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("ghj-{}", uuid_like()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
    // small helper to avoid rand: use a nanosecond counter
    fn uuid_like() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    #[test]
    fn append_and_read_round_trip_under_current_hunt() {
        let store = JournalStore::new(tmp());
        let id = store.start_hunt(Some("cycle-A".into()));
        let ev = HuntEvent {
            seq: 0,
            kind: "query".into(),
            endpoint: "/kql".into(),
            result: EventResult {
                est_tokens: 42,
                ..Default::default()
            },
            ..Default::default()
        };
        store.append(ev.clone());
        let (meta, events) = store.read(&id).expect("hunt exists");
        assert_eq!(meta.label.as_deref(), Some("cycle-A"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].endpoint, "/kql");
        assert_eq!(meta.event_count, 1);
        assert_eq!(meta.cumulative_est_tokens, 42);
    }

    #[test]
    fn append_two_events_sums_cumulative_est_tokens_and_stats_matches() {
        let store = JournalStore::new(tmp());
        let id = store.start_hunt(Some("cycle-B".into()));

        store.append(HuntEvent {
            kind: "query".into(),
            endpoint: "/kql".into(),
            result: EventResult {
                est_tokens: 42,
                ..Default::default()
            },
            ..Default::default()
        });

        store.append(HuntEvent {
            kind: "traverse".into(),
            endpoint: "/graph/neighbors".into(),
            result: EventResult {
                est_tokens: 17,
                ..Default::default()
            },
            ..Default::default()
        });

        let (meta, _) = store.read(&id).expect("hunt exists");
        assert_eq!(meta.cumulative_est_tokens, 42 + 17);
        assert_eq!(meta.event_count, 2);

        let stats = store.stats(&id).expect("stats for known hunt");
        assert_eq!(stats["hunt_id"], serde_json::json!(id));
        assert_eq!(stats["cumulative_est_tokens"], serde_json::json!(59));
        assert_eq!(stats["event_count"], serde_json::json!(2));
        assert_eq!(stats["by_kind"]["query"], serde_json::json!(1));
        assert_eq!(stats["by_kind"]["traverse"], serde_json::json!(1));
    }

    #[test]
    fn stats_returns_none_for_unknown_hunt() {
        let store = JournalStore::new(tmp());
        assert!(store.stats("no-such-hunt").is_none());
    }

    #[test]
    fn read_rejects_ids_that_escape_the_base_dir() {
        // A real hunt dir next to the store's base: reachable only via `..`.
        let root = tmp();
        let base = root.join("journals");
        std::fs::create_dir_all(&base).unwrap();
        let outside = JournalStore::new(root.clone());
        let outside_id = outside.start_hunt(None);
        let store = JournalStore::new(base);

        assert!(store.read(&format!("../{outside_id}")).is_none());
        assert!(
            store
                .read(root.join(&outside_id).to_str().unwrap())
                .is_none()
        );
        assert!(store.read("").is_none());
        assert!(outside.read(&outside_id).is_some());
    }

    #[test]
    fn append_without_start_lazily_creates_current_hunt() {
        let store = JournalStore::new(tmp());
        store.append(HuntEvent {
            endpoint: "/graph/neighbors".into(),
            ..Default::default()
        });
        assert_eq!(store.list().len(), 1); // one lazily-created hunt
    }

    #[test]
    fn close_hunt_sets_closed_at_and_next_append_starts_new_hunt() {
        let store = JournalStore::new(tmp());
        let id1 = store.start_hunt(Some("first".into()));

        let closed_id = store.close_hunt();
        assert_eq!(closed_id, Some(id1.clone()));
        let (meta1, _) = store.read(&id1).expect("hunt exists");
        assert!(meta1.closed_at.is_some());

        // close_hunt on an already-closed store (no current hunt) is a no-op.
        assert_eq!(store.close_hunt(), None);

        // The next append lazily starts a brand-new hunt, not id1.
        store.append(HuntEvent {
            endpoint: "/search".into(),
            ..Default::default()
        });
        let id2 = store.current_hunt_id();
        assert_ne!(id2, id1);
        let (meta2, events2) = store.read(&id2).expect("hunt exists");
        assert_eq!(events2.len(), 1);
        assert!(meta2.closed_at.is_none());
    }
}
