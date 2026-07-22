//! Append-only journal of canonical envelopes. One JSONL record per row that
//! enters ingestion — inserted or skipped — written BEFORE the row touches the
//! graph, so a crash between journal-write and graph-insert is replayable and
//! every row is accounted for (design spec §9, steps 4-9). Mirrors the DLQ's
//! append-only JSONL store (core/graph-engine/src/dlq). Lives in platform/api
//! (not canonical/core) to avoid a crate cycle: it depends on CanonicalEnvelope.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use graph_hunter_canonical::{CanonicalEnvelope, ProvenanceCtx};
use graph_hunter_core::parser::RawIngestEvent;

const JOURNAL_FILE: &str = "journal.jsonl";

pub struct JournalStore {
    path: PathBuf,
}

impl JournalStore {
    /// Open (or create-on-first-append) the journal in `dir`. The filename is
    /// stable per dir, so reopening the same dir sees prior records.
    pub fn open(dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir)?;
        Ok(JournalStore { path: dir.join(JOURNAL_FILE) })
    }

    /// Append one envelope as a JSONL line. Append-only: never rewrites.
    pub fn append(&self, env: &CanonicalEnvelope) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(env)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        line.push(b'\n');
        let mut f = OpenOptions::new().create(true).append(true).open(&self.path)?;
        f.write_all(&line)?;
        Ok(())
    }

    /// Read every record in append order. Missing file → empty.
    pub fn read_all(&self) -> std::io::Result<Vec<CanonicalEnvelope>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let f = File::open(&self.path)?;
        let mut out = Vec::new();
        for line in BufReader::new(f).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let env: CanonicalEnvelope = serde_json::from_str(&line)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            out.push(env);
        }
        Ok(out)
    }

    pub fn count(&self) -> std::io::Result<usize> {
        if !self.path.exists() {
            return Ok(0);
        }
        let f = File::open(&self.path)?;
        Ok(BufReader::new(f).lines().filter(|l| {
            l.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false)
        }).count())
    }
}

/// `GRAPHHUNTER_JOURNAL`: enable the append-only canonical journal on the
/// ingest write path. Default OFF (no-op) — truthy-to-enable, matching the
/// engine's `env_flag` convention (core/graph-engine planner.rs); this is
/// NOT the falsy-to-disable convention some Fase A flags use.
pub fn journal_enabled() -> bool {
    std::env::var("GRAPHHUNTER_JOURNAL")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Journal a parsed batch: one envelope per inserted event (`change_kind
/// Insert`) plus one per skipped sample (`change_kind Skipped`), each with
/// provenance frozen NOW and `ingestion_time = now_ms`. This is steps 4-5 of
/// the 12-step ingest order and MUST run before the caller's graph insert
/// (step 9), so a crash between journal-write and graph-insert is
/// replayable. Pure w.r.t. the caller's state — the only side effect is
/// `store.append` — so it's unit-testable without the API's session
/// machinery.
pub fn journal_batch(
    store: &JournalStore,
    source_id: &str,
    source_kind: &str,
    dataset_id: &str,
    parser_name: &str,
    events: &[RawIngestEvent],
    skipped_samples: &[(String, String)],
    now_ms: i64,
) -> std::io::Result<()> {
    for ev in events {
        let raw = serde_json::to_string(ev).unwrap_or_default();
        let prov = ProvenanceCtx::for_builtin_parser(parser_name, dataset_id, raw.as_bytes());
        let env = CanonicalEnvelope::new_insert(
            source_id.to_string(),
            source_kind.to_string(),
            ev.timestamp,
            now_ms,
            raw,
            prov,
        );
        store.append(&env)?;
    }
    for (raw_row, reason) in skipped_samples {
        let prov = ProvenanceCtx::for_builtin_parser(parser_name, dataset_id, raw_row.as_bytes());
        let env = CanonicalEnvelope::new_insert(
            source_id.to_string(),
            source_kind.to_string(),
            0,
            now_ms,
            raw_row.clone(),
            prov,
        )
        .as_skipped(reason.clone());
        store.append(&env)?;
    }
    Ok(())
}

/// The canonical event set recovered from the journal, split by disposition.
/// This is the reconstruction primitive: Fase C's incremental-vs-rebuild
/// equivalence check will compare a rebuild from here against the live graph.
#[derive(Debug, Clone, PartialEq)]
pub struct JournalReconstruction {
    pub inserted: Vec<CanonicalEnvelope>,
    pub skipped: Vec<CanonicalEnvelope>,
    pub total: usize,
}

/// Replay the whole journal and split records by change kind. Preserves append
/// order within each bucket. (Corrections/tombstones are Fase C — for now they
/// fall through to `inserted`/ignored; documented, not yet applied.)
pub fn rebuild_from_journal(store: &JournalStore) -> std::io::Result<JournalReconstruction> {
    let all = store.read_all()?;
    let total = all.len();
    let mut inserted = Vec::new();
    let mut skipped = Vec::new();
    for env in all {
        match env.change_kind {
            graph_hunter_canonical::ChangeKind::Skipped => skipped.push(env),
            _ => inserted.push(env), // Insert (Correction/Tombstone deferred to Fase C)
        }
    }
    Ok(JournalReconstruction { inserted, skipped, total })
}

#[cfg(test)]
mod tests {
    use super::*;
    use graph_hunter_canonical::{CanonicalEnvelope, ChangeKind, ProvenanceCtx};

    fn env(payload: &str, et: i64, it: i64) -> CanonicalEnvelope {
        let p = ProvenanceCtx::for_builtin_parser("sysmon", "ds-1", payload.as_bytes());
        CanonicalEnvelope::new_insert("la:ws".into(), "la".into(), et, it, payload.into(), p)
    }

    #[test]
    fn append_then_read_all_preserves_order_and_content() {
        let dir = tempfile::tempdir().unwrap();
        let j = JournalStore::open(dir.path()).unwrap();
        j.append(&env("row-a", 1, 10)).unwrap();
        j.append(&env("row-b", 2, 20)).unwrap();
        j.append(&env("row-c", 3, 30)).unwrap();
        let all = j.read_all().unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].raw_payload, "row-a");
        assert_eq!(all[2].event_time, 3);
        assert_eq!(all[1].ingestion_time, 20);
        assert_eq!(j.count().unwrap(), 3);
    }

    #[test]
    fn a_reopened_journal_reads_prior_records() {
        let dir = tempfile::tempdir().unwrap();
        {
            let j = JournalStore::open(dir.path()).unwrap();
            j.append(&env("persisted", 1, 1)).unwrap();
        }
        // A crash-and-restart: reopen the SAME dir, prior records still there.
        let j2 = JournalStore::open(dir.path()).unwrap();
        let all = j2.read_all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].raw_payload, "persisted");
    }

    #[test]
    fn empty_journal_reads_empty() {
        let dir = tempfile::tempdir().unwrap();
        let j = JournalStore::open(dir.path()).unwrap();
        assert_eq!(j.read_all().unwrap().len(), 0);
        assert_eq!(j.count().unwrap(), 0);
    }

    // ── journal_enabled ─────────────────────────────────────────────

    /// Process-wide mutex for the `GRAPHHUNTER_JOURNAL`-mutating tests below.
    /// Cargo runs tests in parallel by default, so two tests setting/
    /// clearing the same env var would race. Mirrors the `ENV_LOCK`
    /// convention already used in `operations/hunt.rs` for
    /// `GRAPHHUNTER_YANNAKAKIS`.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn journal_enabled_defaults_off() {
        let _guard = lock_env();
        unsafe { std::env::remove_var("GRAPHHUNTER_JOURNAL") };
        assert!(!journal_enabled());
    }

    #[test]
    fn journal_enabled_truthy_values_turn_it_on() {
        let _guard = lock_env();
        for v in ["1", "true", "TRUE", "True"] {
            unsafe { std::env::set_var("GRAPHHUNTER_JOURNAL", v) };
            assert!(journal_enabled(), "expected {v:?} to enable the journal");
        }
        unsafe { std::env::remove_var("GRAPHHUNTER_JOURNAL") };
    }

    #[test]
    fn journal_enabled_other_values_stay_off() {
        let _guard = lock_env();
        for v in ["0", "false", "no", ""] {
            unsafe { std::env::set_var("GRAPHHUNTER_JOURNAL", v) };
            assert!(!journal_enabled(), "expected {v:?} to leave the journal off");
        }
        unsafe { std::env::remove_var("GRAPHHUNTER_JOURNAL") };
    }

    // ── journal_batch ────────────────────────────────────────────────

    fn sample_event(ts: i64) -> RawIngestEvent {
        RawIngestEvent {
            src_id: "1.2.3.4".into(),
            src_type: graph_hunter_core::EntityType::IP,
            src_metadata: Default::default(),
            dst_id: "host-1".into(),
            dst_type: graph_hunter_core::EntityType::Host,
            dst_metadata: Default::default(),
            rel_type: graph_hunter_core::RelationType::Connect,
            rel_metadata: Default::default(),
            timestamp: ts,
        }
    }

    #[test]
    fn journal_batch_writes_one_insert_per_event_plus_one_skipped_per_sample() {
        let dir = tempfile::tempdir().unwrap();
        let store = JournalStore::open(dir.path()).unwrap();
        let events = vec![sample_event(100), sample_event(200)];
        let skipped = vec![
            ("malformed-row-1".to_string(), "no_triple".to_string()),
            ("malformed-row-2".to_string(), "missing_field".to_string()),
        ];
        journal_batch(
            &store,
            "ds-1",
            "file",
            "ds-1",
            "generic",
            &events,
            &skipped,
            999_000,
        )
        .unwrap();

        let all = store.read_all().unwrap();
        assert_eq!(all.len(), 4);

        let inserts: Vec<_> = all.iter().filter(|e| e.change_kind == ChangeKind::Insert).collect();
        let skips: Vec<_> = all.iter().filter(|e| e.change_kind == ChangeKind::Skipped).collect();
        assert_eq!(inserts.len(), 2);
        assert_eq!(skips.len(), 2);

        // ingestion_time is populated with the frozen clock for every record.
        assert!(all.iter().all(|e| e.ingestion_time == 999_000));
        // provenance is frozen into each record (non-empty mapping_hash).
        assert!(all.iter().all(|e| !e.provenance.mapping_hash.is_empty()));
        // skipped rows preserve their raw payload and reason.
        assert!(skips.iter().any(|e| e.raw_payload == "malformed-row-1"
            && e.skip_reason.as_deref() == Some("no_triple")));
        assert!(skips.iter().any(|e| e.raw_payload == "malformed-row-2"
            && e.skip_reason.as_deref() == Some("missing_field")));
        // inserted events carry the event's own timestamp as event_time.
        assert!(inserts.iter().any(|e| e.event_time == 100));
        assert!(inserts.iter().any(|e| e.event_time == 200));
    }

    #[test]
    fn journal_batch_is_a_noop_write_with_empty_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let store = JournalStore::open(dir.path()).unwrap();
        journal_batch(&store, "ds-1", "file", "ds-1", "generic", &[], &[], 1).unwrap();
        assert_eq!(store.read_all().unwrap().len(), 0);
    }

    // ── rebuild_from_journal ─────────────────────────────────────────

    #[test]
    fn rebuild_separates_inserted_from_skipped_and_counts_all() {
        let dir = tempfile::tempdir().unwrap();
        let j = JournalStore::open(dir.path()).unwrap();
        j.append(&env("ins-1", 1, 10)).unwrap();
        j.append(&env("skip-1", 0, 11).as_skipped("no_triple".into())).unwrap();
        j.append(&env("ins-2", 2, 12)).unwrap();
        let r = rebuild_from_journal(&j).unwrap();
        assert_eq!(r.total, 3);
        assert_eq!(r.inserted.len(), 2);
        assert_eq!(r.skipped.len(), 1);
        assert_eq!(r.inserted[0].raw_payload, "ins-1");
        assert_eq!(r.skipped[0].skip_reason.as_deref(), Some("no_triple"));
        // Every raw row is recoverable — nothing was silently lost.
        let payloads: Vec<_> = r.inserted.iter().chain(&r.skipped)
            .map(|e| e.raw_payload.clone()).collect();
        assert!(payloads.contains(&"skip-1".to_string()));
    }
}
