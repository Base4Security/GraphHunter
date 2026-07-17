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

impl JournalStore {
    pub fn new(base: PathBuf) -> Self {
        JournalStore(Arc::new(Mutex::new(Inner {
            base,
            current: None,
        })))
    }

    /// Creates a new hunt dir + `meta.json`, sets it current, returns the id.
    pub fn start_hunt(&self, label: Option<String>) -> String {
        let mut inner = self.0.lock().unwrap();
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

    /// Current hunt id, lazily creating an anonymous hunt if none is open.
    pub fn current_hunt_id(&self) -> String {
        let mut inner = self.0.lock().unwrap();
        if let Some(id) = &inner.current {
            return id.clone();
        }
        Self::start_hunt_locked(&mut inner, None)
    }

    /// Appends one JSON line to the current hunt's `events.jsonl` and bumps
    /// `meta.json` counters. Lazily starts an anonymous hunt if none is open.
    pub fn append(&self, mut ev: HuntEvent) {
        let mut inner = self.0.lock().unwrap();
        let id = match &inner.current {
            Some(id) => id.clone(),
            None => Self::start_hunt_locked(&mut inner, None),
        };
        let dir = inner.base.join(&id);

        let mut meta = Self::read_meta(&dir).unwrap_or_else(|| HuntMeta::new(id.clone(), None));

        ev.seq = meta.event_count;
        let line = serde_json::to_string(&ev).expect("journal: serialize HuntEvent");

        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("events.jsonl"))
            .expect("journal: open events.jsonl");
        writeln!(f, "{}", line).expect("journal: append event line");

        meta.event_count += 1;
        meta.cumulative_est_tokens += ev.result.est_tokens;
        meta.entities_added += ev.result.new_entities.unwrap_or(0);
        meta.relations_added += ev.result.new_relations.unwrap_or(0);
        Self::write_meta(&dir, &meta);
    }

    /// All known hunts (unordered), read from `meta.json` per subdirectory.
    pub fn list(&self) -> Vec<HuntMeta> {
        let inner = self.0.lock().unwrap();
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
        let mut inner = self.0.lock().unwrap();
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
        let inner = self.0.lock().unwrap();
        let dir = inner.base.join(id);
        let meta = Self::read_meta(&dir)?;
        let events = Self::read_events(&dir);
        Some((meta, events))
    }

    fn meta_path(dir: &Path) -> PathBuf {
        dir.join("meta.json")
    }

    fn read_meta(dir: &Path) -> Option<HuntMeta> {
        let data = fs::read_to_string(Self::meta_path(dir)).ok()?;
        serde_json::from_str(&data).ok()
    }

    fn write_meta(dir: &Path, meta: &HuntMeta) {
        let data = serde_json::to_string_pretty(meta).expect("journal: serialize HuntMeta");
        fs::write(Self::meta_path(dir), data).expect("journal: write meta.json");
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
    use crate::journal::event::HuntEvent;

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
        let mut ev = HuntEvent::default();
        ev.seq = 0;
        ev.kind = "query".into();
        ev.endpoint = "/kql".into();
        ev.result.est_tokens = 42;
        store.append(ev.clone());
        let (meta, events) = store.read(&id).expect("hunt exists");
        assert_eq!(meta.label.as_deref(), Some("cycle-A"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].endpoint, "/kql");
        assert_eq!(meta.event_count, 1);
        assert_eq!(meta.cumulative_est_tokens, 42);
    }

    #[test]
    fn append_without_start_lazily_creates_current_hunt() {
        let store = JournalStore::new(tmp());
        let mut ev = HuntEvent::default();
        ev.endpoint = "/graph/neighbors".into();
        store.append(ev);
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
        let mut ev = HuntEvent::default();
        ev.endpoint = "/search".into();
        store.append(ev);
        let id2 = store.current_hunt_id();
        assert_ne!(id2, id1);
        let (meta2, events2) = store.read(&id2).expect("hunt exists");
        assert_eq!(events2.len(), 1);
        assert!(meta2.closed_at.is_none());
    }
}
