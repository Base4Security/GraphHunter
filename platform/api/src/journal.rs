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
use graph_hunter_core::delta::GraphDelta;
use graph_hunter_core::parser::RawIngestEvent;
use graph_hunter_core::{EntityType, RelationType};

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

/// Build the canonical envelopes for a parsed batch — one per inserted event
/// (`change_kind Insert`) plus one per skipped sample (`change_kind
/// Skipped`), each with provenance frozen NOW and `ingestion_time = now_ms`.
/// Pure (no I/O): this is the shared construction path between `journal_batch`
/// (which appends the result to the on-disk journal) and the
/// `GRAPHHUNTER_GRAPHDELTA` apply path in `operations::ingestion`, which
/// applies the SAME envelopes to the graph in-memory instead of re-reading
/// them back off disk. Building them once here keeps the journal-write flag
/// and the apply flag orthogonal without duplicating the envelope-shaping
/// logic.
/// Mirror of `RawIngestEvent` with `BTreeMap` metadata fields instead of
/// `HashMap`, used only to produce a deterministic `raw_payload` string. See
/// `canonical_raw_payload` for why this exists.
#[derive(serde::Serialize)]
struct CanonicalRawIngestEvent<'a> {
    src_id: &'a str,
    src_type: &'a EntityType,
    src_metadata: std::collections::BTreeMap<&'a str, &'a str>,
    dst_id: &'a str,
    dst_type: &'a EntityType,
    dst_metadata: std::collections::BTreeMap<&'a str, &'a str>,
    rel_type: &'a RelationType,
    rel_metadata: std::collections::BTreeMap<&'a str, &'a str>,
    timestamp: i64,
}

/// Serialize a `RawIngestEvent` into the journal's `raw_payload` with
/// deterministic (sorted-key) output, so that re-parsing the SAME source row
/// twice (e.g. a poller crashing and re-polling the same row) always produces
/// byte-identical JSON and therefore the same `canonical_hash` (critical fix,
/// Fase C-1 final review).
///
/// `RawIngestEvent` carries three `HashMap<String, String>` metadata fields
/// (src/dst/rel), and `serde_json::to_string` on a `HashMap` serializes
/// entries in the map's iteration order — which is non-deterministic across
/// separately constructed `HashMap` instances because `HashMap` uses a
/// per-instance `RandomState` hasher. Two freshly-parsed `RawIngestEvent`s
/// with identical logical content can therefore serialize to different JSON
/// strings and hash differently, silently defeating `apply_delta`'s
/// event-identity dedup (`native_id` is never populated by
/// `CanonicalEnvelope::new_insert`, so `canonical_hash` — derived from this
/// very string — is always the actual dedup key).
///
/// First attempt (rejected): round-trip through `serde_json::Value`,
/// relying on `serde_json::Map` being `BTreeMap`-backed when the
/// `preserve_order` feature is off. That assumption does NOT hold in this
/// workspace: no workspace `Cargo.toml` enables `preserve_order` directly,
/// but `evtx` (a transitive dependency reachable from this same build
/// target) does, and Cargo unifies serde_json's features across the whole
/// dependency graph for a given target — so `serde_json::Map` is actually
/// `IndexMap`-backed here (verified via `cargo tree -e features -i
/// serde_json`, which shows `serde_json feature "preserve_order"` pulled in
/// by `evtx`). An `IndexMap`-backed `Value::Object` preserves whatever
/// (random) order the source `HashMap` handed it, so the `Value` round-trip
/// is a no-op and does NOT fix the bug (confirmed empirically: the stability
/// test below still failed with that approach).
///
/// Actual fix: serialize a shadow struct (`CanonicalRawIngestEvent`) whose
/// metadata fields are `BTreeMap`, not `HashMap`. `serde_json::to_string`
/// does not build a `Value`/`Map` for direct string output — it streams
/// each field's entries in whatever order the field's own `Serialize` impl
/// hands them. `BTreeMap`'s `Serialize` impl always iterates in sorted key
/// order (a property of `BTreeMap` itself, independent of serde_json's
/// `preserve_order` feature), so the emitted JSON is deterministic
/// regardless of the source `HashMap`'s iteration order. See
/// `canonical_serialization_is_stable_across_reparse` for the test that
/// pins this down.
pub(crate) fn canonical_raw_payload(ev: &RawIngestEvent) -> String {
    let canon = CanonicalRawIngestEvent {
        src_id: &ev.src_id,
        src_type: &ev.src_type,
        src_metadata: ev.src_metadata.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect(),
        dst_id: &ev.dst_id,
        dst_type: &ev.dst_type,
        dst_metadata: ev.dst_metadata.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect(),
        rel_type: &ev.rel_type,
        rel_metadata: ev.rel_metadata.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect(),
        timestamp: ev.timestamp,
    };
    serde_json::to_string(&canon).unwrap_or_default()
}

pub(crate) fn build_batch_envelopes(
    source_id: &str,
    source_kind: &str,
    dataset_id: &str,
    parser_name: &str,
    events: &[RawIngestEvent],
    skipped_samples: &[(String, String)],
    now_ms: i64,
) -> Vec<CanonicalEnvelope> {
    let mut out = Vec::with_capacity(events.len() + skipped_samples.len());
    for ev in events {
        // Prefer the verbatim source row (field_survival): unmapped fields survive
        // in the journal. Fall back to the canonical triple serialization (C-1)
        // when the parser did not capture a raw line. Both are deterministic, so the
        // canonical_hash / dedup key stays stable across re-parse.
        let raw = match &ev.raw_line {
            Some(line) => line.clone(),
            None => canonical_raw_payload(ev),
        };
        let prov = ProvenanceCtx::for_builtin_parser(parser_name, dataset_id, raw.as_bytes());
        out.push(CanonicalEnvelope::new_insert(
            source_id.to_string(),
            source_kind.to_string(),
            ev.timestamp,
            now_ms,
            raw,
            prov,
        ));
    }
    for (raw_row, reason) in skipped_samples {
        let prov = ProvenanceCtx::for_builtin_parser(parser_name, dataset_id, raw_row.as_bytes());
        out.push(
            CanonicalEnvelope::new_insert(
                source_id.to_string(),
                source_kind.to_string(),
                0,
                now_ms,
                raw_row.clone(),
                prov,
            )
            .as_skipped(reason.clone()),
        );
    }
    out
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
    for env in build_batch_envelopes(
        source_id,
        source_kind,
        dataset_id,
        parser_name,
        events,
        skipped_samples,
        now_ms,
    ) {
        store.append(&env)?;
    }
    Ok(())
}

/// `GRAPHHUNTER_GRAPHDELTA`: apply journal envelopes to the graph idempotently
/// (edge multiplicity keyed on event identity, via `GraphHunter::apply_delta`)
/// instead of the direct, non-deduping `insert_raw_events` path. Default off.
/// Only meaningful when `GRAPHHUNTER_JOURNAL` is also on — the envelopes this
/// applies come from the same in-memory batch the journal write journals.
pub fn graphdelta_enabled() -> bool {
    std::env::var("GRAPHHUNTER_GRAPHDELTA")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Apply a slice of just-journaled envelopes to the graph idempotently.
/// Insert envelopes are turned into `GraphDelta`s (via `envelope_to_delta`)
/// and applied through `GraphHunter::apply_delta`, which dedups on event
/// identity — so replaying the same batch twice (e.g. a crash-and-reingest)
/// applies each envelope at most once. Skipped envelopes and envelopes whose
/// payload doesn't deserialize back into a `RawIngestEvent` yield no delta
/// and are silently ignored (they never produced an edge to begin with). A
/// failed `apply_delta` only warns and moves on — this must never abort the
/// caller's ingest. Returns `(applied, skipped_as_duplicate)`; envelopes that
/// yielded no delta at all count toward neither.
pub fn apply_batch_idempotent(
    graph: &mut graph_hunter_core::graph::GraphHunter,
    envelopes: &[CanonicalEnvelope],
) -> (usize, usize) {
    let mut applied = 0usize;
    let mut dup = 0usize;
    for env in envelopes {
        if let Some(delta) = envelope_to_delta(env) {
            match graph.apply_delta(&delta) {
                Ok(out) if out.applied => applied += 1,
                Ok(_) => dup += 1,
                Err(e) => {
                    tracing::warn!(target: "graphdelta", error = %e, "apply_delta failed; skipping")
                }
            }
        }
    }
    (applied, dup)
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

/// Turn a canonical envelope back into an applicable GraphDelta. Insert
/// envelopes carry a serialized RawIngestEvent in `raw_payload` (written by
/// `journal_batch`); Skipped envelopes carry a raw source row and produce no
/// edge, so they yield None. The event id is the source-native id when present
/// (stable across re-ingest), else the canonical hash. The envelope's
/// provenance dataset is threaded onto the delta so `apply_delta` doesn't
/// drop dataset attribution the way the un-threaded path used to.
pub fn envelope_to_delta(env: &CanonicalEnvelope) -> Option<GraphDelta> {
    use graph_hunter_canonical::ChangeKind;
    if env.change_kind != ChangeKind::Insert {
        return None;
    }
    let event: RawIngestEvent = serde_json::from_str(&env.raw_payload).ok()?;
    let event_id = env.native_id.clone().unwrap_or_else(|| env.canonical_hash.clone());
    let dataset_id = Some(env.provenance.source_dataset_id.clone());
    Some(GraphDelta::new(event, event_id, dataset_id))
}

/// Observable-count comparison between a live incremental graph and a
/// fresh rebuild from the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquivalenceReport {
    pub entity_count_matches: bool,
    pub relation_count_matches: bool,
    pub live_entities: usize,
    pub rebuilt_entities: usize,
    pub live_relations: usize,
    pub rebuilt_relations: usize,
}

/// Rebuild a fresh graph from the journal (idempotent apply of every inserted
/// envelope) and compare observable counts against the live graph. This is the
/// translation-validation check (SOT-VM framing): the from-scratch rebuild is
/// the trusted reference; the live graph is the untrusted incremental artifact.
/// Fase C-1 compares entity/relation counts; richer observable equality (query
/// outputs) is future work.
pub fn check_incremental_equivalence(
    live: &graph_hunter_core::graph::GraphHunter,
    store: &JournalStore,
) -> std::io::Result<EquivalenceReport> {
    let recon = rebuild_from_journal(store)?;
    let mut rebuilt = graph_hunter_core::graph::GraphHunter::new();
    apply_batch_idempotent(&mut rebuilt, &recon.inserted);
    let live_e = live.entity_count();
    let live_r = live.relation_count();
    let reb_e = rebuilt.entity_count();
    let reb_r = rebuilt.relation_count();
    Ok(EquivalenceReport {
        entity_count_matches: live_e == reb_e,
        relation_count_matches: live_r == reb_r,
        live_entities: live_e,
        rebuilt_entities: reb_e,
        live_relations: live_r,
        rebuilt_relations: reb_r,
    })
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
            raw_line: None,
        }
    }

    #[test]
    fn inserted_envelope_uses_raw_line_when_present() {
        let mut ev = sample_event(100); // reuse the module helper
        ev.raw_line = Some("{\"unmapped_field\":\"survives\"}".into());
        let envs = build_batch_envelopes("s", "la", "ds", "p", &[ev], &[], 1000);
        // the inserted envelope's raw_payload is the raw line, not the triple JSON.
        assert_eq!(envs[0].raw_payload, "{\"unmapped_field\":\"survives\"}");
        // and it still round-trips as an Insert.
        assert_eq!(envs[0].change_kind, graph_hunter_canonical::ChangeKind::Insert);
    }

    #[test]
    fn inserted_envelope_falls_back_to_triple_when_no_raw_line() {
        let ev = sample_event(100); // raw_line = None
        let envs = build_batch_envelopes("s", "la", "ds", "p", &[ev], &[], 1000);
        // fallback: raw_payload is the canonical triple serialization (C-1 behavior),
        // which parses back to a RawIngestEvent.
        let back: graph_hunter_core::parser::RawIngestEvent =
            serde_json::from_str(&envs[0].raw_payload).unwrap();
        assert_eq!(back.timestamp, 100);
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

    // ── envelope_to_delta ────────────────────────────────────────────

    #[test]
    fn insert_envelope_becomes_a_delta_keyed_on_identity() {
        // env whose raw_payload is a serialized RawIngestEvent (as journal_batch writes).
        let ev = sample_event(100);
        let raw = serde_json::to_string(&ev).unwrap();
        let prov = ProvenanceCtx::for_builtin_parser("p", "ds", raw.as_bytes());
        let env = CanonicalEnvelope::new_insert(
            "s".into(), "la".into(), 100, 200, raw, prov);
        let d = envelope_to_delta(&env).expect("insert envelope yields a delta");
        // native_id absent -> keyed on canonical_hash
        assert_eq!(d.event_id, env.canonical_hash);
        assert_eq!(d.event.timestamp, 100);
        // dataset attribution flows from the envelope's frozen provenance
        // through to the delta (not dropped the way the un-threaded
        // insert_raw_events(..., None) path used to drop it).
        assert_eq!(d.dataset_id.as_deref(), Some("ds"));
    }

    #[test]
    fn skipped_envelope_yields_no_delta() {
        let prov = ProvenanceCtx::for_builtin_parser("p", "ds", b"x");
        let env = CanonicalEnvelope::new_insert(
            "s".into(), "la".into(), 0, 5, "malformed".into(), prov)
            .as_skipped("no_triple".into());
        assert!(envelope_to_delta(&env).is_none());
    }

    #[test]
    fn native_id_is_preferred_over_canonical_hash_when_present() {
        let ev = sample_event(100);
        let raw = serde_json::to_string(&ev).unwrap();
        let prov = ProvenanceCtx::for_builtin_parser("p", "ds", raw.as_bytes());
        let mut env = CanonicalEnvelope::new_insert(
            "s".into(), "la".into(), 100, 200, raw, prov);
        env.native_id = Some("native-1".into());
        let d = envelope_to_delta(&env).expect("insert envelope yields a delta");
        assert_eq!(d.event_id, "native-1");
    }

    #[test]
    fn insert_envelope_with_malformed_payload_yields_no_delta() {
        let prov = ProvenanceCtx::for_builtin_parser("p", "ds", b"not json");
        let env = CanonicalEnvelope::new_insert(
            "s".into(), "la".into(), 0, 5, "not json".into(), prov);
        assert!(envelope_to_delta(&env).is_none());
    }

    // ── graphdelta_enabled ───────────────────────────────────────────

    #[test]
    fn graphdelta_flag_defaults_off() {
        let _lock = lock_env();
        unsafe { std::env::remove_var("GRAPHHUNTER_GRAPHDELTA") };
        assert!(!graphdelta_enabled());
        unsafe { std::env::set_var("GRAPHHUNTER_GRAPHDELTA", "1") };
        assert!(graphdelta_enabled());
        unsafe { std::env::remove_var("GRAPHHUNTER_GRAPHDELTA") };
    }

    // ── apply_batch_idempotent ───────────────────────────────────────

    /// Build an Insert envelope whose raw_payload is a serialized
    /// `RawIngestEvent` (as `journal_batch`/`build_batch_envelopes` write),
    /// so `envelope_to_delta` can turn it back into a `GraphDelta`.
    fn insert_envelope_for(ev: &RawIngestEvent) -> CanonicalEnvelope {
        let raw = serde_json::to_string(ev).unwrap();
        let prov = ProvenanceCtx::for_builtin_parser("generic", "ds-1", raw.as_bytes());
        CanonicalEnvelope::new_insert("ds-1".into(), "file".into(), ev.timestamp, 1000, raw, prov)
    }

    #[test]
    fn apply_batch_idempotent_dedups_on_replay() {
        use graph_hunter_core::graph::GraphHunter;
        let mut g = GraphHunter::new();
        // Two distinct events (different timestamps -> different serialized
        // payload -> different canonical_hash, since no native_id is set).
        let evs = vec![
            insert_envelope_for(&sample_event(100)),
            insert_envelope_for(&sample_event(200)),
        ];
        let (a1, s1) = apply_batch_idempotent(&mut g, &evs);
        assert_eq!((a1, s1), (2, 0));
        assert_eq!(g.relation_count(), 2);
        // Replay the SAME batch (crash re-ingest): both skipped as duplicates.
        let (a2, s2) = apply_batch_idempotent(&mut g, &evs);
        assert_eq!((a2, s2), (0, 2));
        assert_eq!(g.relation_count(), 2); // no duplication
    }

    // ── canonical_raw_payload (critical fix, Fase C-1 final review) ───
    //
    // `RawIngestEvent` carries 3 `HashMap<String, String>` metadata fields.
    // `serde_json::to_string` on a plain `HashMap` serializes entries in the
    // map's iteration order, which is non-deterministic across separately
    // constructed `HashMap` instances (Rust's `RandomState` hasher). Two
    // `RawIngestEvent`s built from the SAME logical row (e.g. a poller crash
    // that re-polls and re-parses the identical source row into brand-new
    // maps) can therefore serialize to different JSON and hash differently,
    // which silently defeats `apply_delta`'s event-identity dedup — since
    // `native_id` is never populated (`CanonicalEnvelope::new_insert`
    // hardcodes `None`), `canonical_hash` (a function of this very string)
    // is always the real dedup key. These two tests are the ones that would
    // have caught it: run against `serde_json::to_string(ev)` directly
    // (pre-fix) they fail (RED) because `raw1 != raw2` most of the time;
    // against `canonical_raw_payload` (post-fix) they pass (GREEN) because
    // the round-trip through `serde_json::Value` sorts every object's keys
    // (this workspace does not enable serde_json's `preserve_order`
    // feature, so `serde_json::Map` is `BTreeMap`-backed).

    /// One logical event, with its 3 metadata maps built by inserting keys
    /// in one order.
    fn logically_identical_event_variant_a() -> RawIngestEvent {
        let mut src_metadata = std::collections::HashMap::new();
        src_metadata.insert("user".to_string(), "alice".to_string());
        src_metadata.insert("domain".to_string(), "corp".to_string());
        let mut dst_metadata = std::collections::HashMap::new();
        dst_metadata.insert("os".to_string(), "linux".to_string());
        dst_metadata.insert("role".to_string(), "dc".to_string());
        let mut rel_metadata = std::collections::HashMap::new();
        rel_metadata.insert("logon_type".to_string(), "3".to_string());
        RawIngestEvent {
            src_id: "u1".into(),
            src_type: graph_hunter_core::EntityType::User,
            src_metadata,
            dst_id: "h1".into(),
            dst_type: graph_hunter_core::EntityType::Host,
            dst_metadata,
            rel_type: graph_hunter_core::RelationType::Auth,
            rel_metadata,
            timestamp: 500,
            raw_line: None,
        }
    }

    /// The SAME logical event as variant_a — identical ids/types/timestamp
    /// and identical metadata key/value pairs — but every `HashMap` is a
    /// freshly-constructed instance with keys inserted in a DIFFERENT order.
    /// This is what a crash-and-re-poll actually produces: the same source
    /// row, re-parsed into brand-new maps.
    fn logically_identical_event_variant_b() -> RawIngestEvent {
        let mut src_metadata = std::collections::HashMap::new();
        src_metadata.insert("domain".to_string(), "corp".to_string());
        src_metadata.insert("user".to_string(), "alice".to_string());
        let mut dst_metadata = std::collections::HashMap::new();
        dst_metadata.insert("role".to_string(), "dc".to_string());
        dst_metadata.insert("os".to_string(), "linux".to_string());
        let mut rel_metadata = std::collections::HashMap::new();
        rel_metadata.insert("logon_type".to_string(), "3".to_string());
        RawIngestEvent {
            src_id: "u1".into(),
            src_type: graph_hunter_core::EntityType::User,
            src_metadata,
            dst_id: "h1".into(),
            dst_type: graph_hunter_core::EntityType::Host,
            dst_metadata,
            rel_type: graph_hunter_core::RelationType::Auth,
            rel_metadata,
            timestamp: 500,
            raw_line: None,
        }
    }

    #[test]
    fn canonical_serialization_is_stable_across_reparse() {
        let ev1 = logically_identical_event_variant_a();
        let ev2 = logically_identical_event_variant_b();

        let raw1 = canonical_raw_payload(&ev1);
        let raw2 = canonical_raw_payload(&ev2);
        assert_eq!(
            raw1, raw2,
            "canonical_raw_payload must be stable regardless of HashMap \
             construction/iteration order — this is what makes a crash \
             re-poll's re-parse of the same row produce the SAME raw_payload"
        );

        // Same downstream consequence: the canonical_hash the journal
        // actually dedups on is identical too.
        let prov = ProvenanceCtx::for_builtin_parser("generic", "ds-1", raw1.as_bytes());
        let hash1 = CanonicalEnvelope::compute_hash(&raw1, &prov);
        let hash2 = CanonicalEnvelope::compute_hash(&raw2, &prov);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn crash_reingest_reparse_of_the_same_row_does_not_duplicate_the_edge() {
        use graph_hunter_core::graph::GraphHunter;
        // Two envelopes built independently (as journal_batch would for two
        // separate ingest attempts of the SAME source row across a crash),
        // each from a freshly re-parsed RawIngestEvent with its own fresh
        // HashMaps.
        let ev1 = logically_identical_event_variant_a();
        let ev2 = logically_identical_event_variant_b();
        let raw1 = canonical_raw_payload(&ev1);
        let raw2 = canonical_raw_payload(&ev2);
        let prov1 = ProvenanceCtx::for_builtin_parser("generic", "ds-1", raw1.as_bytes());
        let prov2 = ProvenanceCtx::for_builtin_parser("generic", "ds-1", raw2.as_bytes());
        let env1 = CanonicalEnvelope::new_insert(
            "s".into(), "la".into(), ev1.timestamp, 1000, raw1, prov1);
        let env2 = CanonicalEnvelope::new_insert(
            "s".into(), "la".into(), ev2.timestamp, 2000, raw2, prov2);

        let mut g = GraphHunter::new();
        let (applied, dup) = apply_batch_idempotent(&mut g, &[env1, env2]);
        // Idempotent across RE-PARSE, not just across identical-object
        // replay: the second envelope is recognized as the same event
        // despite coming from a separately re-parsed RawIngestEvent.
        assert_eq!((applied, dup), (1, 1));
        assert_eq!(g.relation_count(), 1);
    }

    // ── check_incremental_equivalence ────────────────────────────────

    #[test]
    fn rebuild_from_journal_matches_live_after_idempotent_apply() {
        use graph_hunter_core::graph::GraphHunter;
        let dir = tempfile::tempdir().unwrap();
        let store = JournalStore::open(dir.path()).unwrap();
        // journal 3 distinct insert envelopes + 1 skipped; also feed a live graph
        // by applying the same batch idempotently (once) — plus a crash replay.
        let inserts = vec![
            insert_envelope_for(&sample_event(100)),
            insert_envelope_for(&sample_event(200)),
            insert_envelope_for(&sample_event(300)),
        ];
        for e in &inserts {
            store.append(e).unwrap();
        }
        store.append(&env("skip-1", 0, 11).as_skipped("no_triple".into())).unwrap();
        let mut live = GraphHunter::new();
        apply_batch_idempotent(&mut live, &inserts);
        apply_batch_idempotent(&mut live, &inserts); // crash replay: idempotent
        let rep = check_incremental_equivalence(&live, &store).unwrap();
        assert!(rep.entity_count_matches, "{rep:?}");
        assert!(rep.relation_count_matches, "{rep:?}");
        assert_eq!(rep.live_relations, 3); // multiplicity: 3, not 6
        assert_eq!(rep.rebuilt_relations, 3);
    }
}
