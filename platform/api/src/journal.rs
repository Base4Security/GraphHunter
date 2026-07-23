//! Append-only journal of canonical envelopes. One JSONL record per row that
//! enters ingestion — inserted or skipped — written BEFORE the row touches the
//! graph, so a crash between journal-write and graph-insert is replayable and
//! every row is accounted for (design spec §9, steps 4-9). Mirrors the DLQ's
//! append-only JSONL store (core/graph-engine/src/dlq). Lives in platform/api
//! (not canonical/core) to avoid a crate cycle: it depends on CanonicalEnvelope.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
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
        // raw_payload is ALWAYS the canonical, per-event serialization (C-1):
        // it is what `envelope_to_delta` deserializes back into a
        // `RawIngestEvent` (reconstruction) and what `canonical_hash` is
        // derived from (identity/dedup). It must be distinct per event even
        // when several events share one source row (e.g. a Sentinel 4688
        // row yields 2 events) — using the shared raw line here would
        // collapse their identity and destroy multiplicity (Fase C-2
        // critical-fix wave, whole-phase final review).
        //
        // The verbatim source row (field_survival: unmapped fields survive)
        // is journaled SEPARATELY in `raw_source_row`, which plays no part
        // in identity or reconstruction.
        let raw = canonical_raw_payload(ev);
        let prov = ProvenanceCtx::for_builtin_parser(parser_name, dataset_id, raw.as_bytes());
        out.push(
            CanonicalEnvelope::new_insert(
                source_id.to_string(),
                source_kind.to_string(),
                ev.timestamp,
                now_ms,
                raw,
                prov,
            )
            .with_source_row(ev.raw_line.clone()),
        );
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

/// Split already-read envelopes by change kind. Preserves append order within
/// each bucket. (Corrections/tombstones are Fase C — for now they fall
/// through to `inserted`/ignored; documented, not yet applied.) Factored out
/// of `rebuild_from_journal` so callers that already hold the envelopes
/// in-memory (e.g. `check_incremental_equivalence`, which also needs them for
/// `classify_rebuild_faithfulness`) don't have to pay for a second
/// `store.read_all()` disk read of the same data.
fn reconstruct_from_envelopes(all: Vec<CanonicalEnvelope>) -> JournalReconstruction {
    let total = all.len();
    let mut inserted = Vec::new();
    let mut skipped = Vec::new();
    for env in all {
        match env.change_kind {
            graph_hunter_canonical::ChangeKind::Skipped => skipped.push(env),
            _ => inserted.push(env), // Insert (Correction/Tombstone deferred to Fase C)
        }
    }
    JournalReconstruction { inserted, skipped, total }
}

/// Replay the whole journal and split records by change kind. Preserves append
/// order within each bucket. (Corrections/tombstones are Fase C — for now they
/// fall through to `inserted`/ignored; documented, not yet applied.)
pub fn rebuild_from_journal(store: &JournalStore) -> std::io::Result<JournalReconstruction> {
    Ok(reconstruct_from_envelopes(store.read_all()?))
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

/// Result of comparing one observable dimension between the live graph and
/// the from-scratch journal rebuild.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DimensionResult {
    /// The dimension is identical on both sides.
    Match,
    /// The dimension diverges. `detail` names the first few divergences
    /// (never the whole set — this is a readable summary, not a dump).
    Diff { detail: String },
    /// The dimension could not be compared (e.g. neither graph has any
    /// edges, so there is no temporal window to compare). This is silence,
    /// not agreement — it must never be treated as a `Match`.
    NotComparable { reason: String },
}

impl DimensionResult {
    /// True only for `Match`. `Diff` and `NotComparable` both return false —
    /// callers that want "nothing detectably differs" (tolerating
    /// `NotComparable`) should use `EquivalenceReport::all_comparable_dimensions_match`
    /// instead.
    pub fn is_match(&self) -> bool {
        matches!(self, DimensionResult::Match)
    }
}

/// Multiset key for one observed edge, built entirely from resolved
/// `String`s — never `StrId`s, which are interner-local and meaningless
/// across two independently-built graphs. `rel_type` is the actual
/// `RelationType` VALUE, not its `Display` string: `Display` is not
/// injective (e.g. `RelationType::Connect` and `RelationType::Other("Connect")`
/// both render `"Connect"`), so keying on the printed form could launder a
/// genuine type divergence into a false `Match`. `RelationType` derives
/// `Hash`/`Eq` but not `Ord`, so this key lives in a `HashMap`, not a
/// `BTreeMap` (see `edge_multiset`). Metadata is flattened into a sorted
/// `Vec` so two `HashMap`s holding the same pairs in different iteration
/// order compare equal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EdgeKey {
    source_id: String,
    rel_type: RelationType,
    dest_id: String,
    timestamp: i64,
    meta: Vec<(String, String)>,
    dataset: Option<String>,
}

fn sorted_metadata(meta: &std::collections::HashMap<String, String>) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = meta.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    v.sort();
    v
}

fn edge_key(r: &graph_hunter_core::Relation) -> EdgeKey {
    EdgeKey {
        source_id: r.source_id.clone(),
        rel_type: r.rel_type.clone(),
        dest_id: r.dest_id.clone(),
        timestamp: r.timestamp,
        meta: sorted_metadata(&r.metadata),
        dataset: r.dataset_id.as_ref().map(|s| s.to_string()),
    }
}

fn edge_multiset(relations: &[graph_hunter_core::Relation]) -> HashMap<EdgeKey, usize> {
    let mut map: HashMap<EdgeKey, usize> = HashMap::new();
    for r in relations {
        *map.entry(edge_key(r)).or_insert(0) += 1;
    }
    map
}

/// Compare the edge multisets of `live` vs `rebuilt`. Order across (and even
/// within) vertices is never assumed to match — this is a count-map
/// comparison, not a positional one. `HashMap == HashMap` (used above)
/// compares keys AND counts correctly regardless of either map's internal
/// iteration order, so multiplicity divergences are still caught.
fn compare_edges(
    live: &[graph_hunter_core::Relation],
    rebuilt: &[graph_hunter_core::Relation],
) -> DimensionResult {
    let live_map = edge_multiset(live);
    let rebuilt_map = edge_multiset(rebuilt);
    if live_map == rebuilt_map {
        return DimensionResult::Match;
    }
    // Union of keys from both maps. `HashMap` iteration order is
    // non-deterministic (and can even vary between two runs of the SAME
    // process), so — to keep the "first 5 divergences" detail message
    // deterministic — every divergence is rendered to a string FIRST, and
    // only then sorted and truncated.
    let mut keys: HashSet<&EdgeKey> = live_map.keys().collect();
    keys.extend(rebuilt_map.keys());
    let mut divergences: Vec<String> = Vec::new();
    for k in keys {
        let lc = live_map.get(k).copied().unwrap_or(0);
        let rc = rebuilt_map.get(k).copied().unwrap_or(0);
        if lc != rc {
            divergences.push(format!(
                "(src={}, rel={}, dst={}, ts={}, meta={:?}, dataset={:?}): live={} rebuilt={}",
                k.source_id, k.rel_type, k.dest_id, k.timestamp, k.meta, k.dataset, lc, rc
            ));
        }
    }
    divergences.sort();
    divergences.truncate(5);
    DimensionResult::Diff {
        detail: format!(
            "live: {} distinct edge keys / {} total edges; rebuilt: {} distinct edge keys / {} total edges; first divergences: [{}]",
            live_map.len(),
            live.len(),
            rebuilt_map.len(),
            rebuilt.len(),
            divergences.join(", ")
        ),
    }
}

/// id -> (entity type, dataset_id, sorted metadata) for order-independent
/// per-entity comparison. Keyed on the actual `EntityType` VALUE, not its
/// `Display` string: `Display` is not injective (e.g. `EntityType::IP` and
/// `EntityType::Other("IP")` both render `"IP"`), so comparing printed
/// strings could report `Match` for a genuine type divergence. The outer
/// map stays a `BTreeMap<String, _>` — `id` is a plain `String` (`Ord`),
/// only the VALUE's type field needed to move off `Display`.
///
/// `dataset_id` is included (resolved `Option<Arc<str>>` -> `Option<String>`,
/// since `Arc<str>` pointer identity is meaningless across two
/// independently-built graphs' string interners) so an entity-level dataset
/// misattribution is caught here, not silently ignored. Before this, the
/// entity comparison was blind to `dataset_id` even though it IS observable
/// via `to_snapshot()` and IS stamped by the delta path (Fase C-1's
/// dataset-id fix) — the edge comparison (`EdgeKey.dataset`) already covered
/// it, but entities didn't.
fn entity_map(
    entities: &[graph_hunter_core::Entity],
) -> BTreeMap<String, (EntityType, Option<String>, Vec<(String, String)>)> {
    entities
        .iter()
        .map(|e| {
            (
                e.id.clone(),
                (
                    e.entity_type.clone(),
                    e.dataset_id.as_ref().map(|s| s.to_string()),
                    sorted_metadata(&e.metadata),
                ),
            )
        })
        .collect()
}

/// Compare entity id sets (`entities`) and, over the shared id set, entity
/// type + metadata (`entity_metadata`). Split in two so a metadata typo on
/// one shared entity doesn't get conflated with an outright missing entity.
fn compare_entities(
    live: &[graph_hunter_core::Entity],
    rebuilt: &[graph_hunter_core::Entity],
) -> (DimensionResult, DimensionResult) {
    let live_map = entity_map(live);
    let rebuilt_map = entity_map(rebuilt);
    let live_ids: BTreeSet<&String> = live_map.keys().collect();
    let rebuilt_ids: BTreeSet<&String> = rebuilt_map.keys().collect();

    let entities_result = if live_ids == rebuilt_ids {
        DimensionResult::Match
    } else {
        let only_live: Vec<&&String> = live_ids.difference(&rebuilt_ids).take(5).collect();
        let only_rebuilt: Vec<&&String> = rebuilt_ids.difference(&live_ids).take(5).collect();
        DimensionResult::Diff {
            detail: format!(
                "live has {} entities, rebuilt has {}; only in live (first 5): {:?}; only in rebuilt (first 5): {:?}",
                live_map.len(),
                rebuilt_map.len(),
                only_live,
                only_rebuilt,
            ),
        }
    };

    let mut divergences: Vec<String> = Vec::new();
    for id in live_ids.intersection(&rebuilt_ids) {
        let l = &live_map[*id];
        let r = &rebuilt_map[*id];
        if l != r {
            divergences.push(format!("{id}: live={l:?} rebuilt={r:?}"));
            if divergences.len() >= 5 {
                break;
            }
        }
    }
    let entity_metadata_result = if divergences.is_empty() {
        DimensionResult::Match
    } else {
        DimensionResult::Diff { detail: divergences.join("; ") }
    };

    (entities_result, entity_metadata_result)
}

/// Compare `edge_timestamp_range()` on both sides. `None` on both sides
/// (neither graph has edges) is `NotComparable`, not `Match` — there is
/// nothing to have agreed on.
fn compare_temporal_window(
    live: &graph_hunter_core::graph::GraphHunter,
    rebuilt: &graph_hunter_core::graph::GraphHunter,
) -> DimensionResult {
    match (live.edge_timestamp_range(), rebuilt.edge_timestamp_range()) {
        (None, None) => {
            DimensionResult::NotComparable { reason: "neither graph has any edges".to_string() }
        }
        (Some(l), Some(r)) if l == r => DimensionResult::Match,
        (l, r) => DimensionResult::Diff { detail: format!("live range={l:?}, rebuilt range={r:?}") },
    }
}

/// Normalize a hunt's `Vec<HuntResult>` into an order-independent multiset of
/// paths. Order WITHIN a path is semantic (it's the walk through the graph:
/// step 0 is the origin, step N is N hops downstream) and is preserved
/// verbatim in the `Vec<String>` key; the SET of paths a hunt returns is NOT
/// guaranteed to come back in the same order across two independently-built
/// graphs (traversal order depends on internal edge/vertex layout, which
/// differs between the incrementally-built live graph and the from-scratch
/// rebuild), so the multiset — not the `Vec` — is what gets compared.
/// `Arc<str>` is resolved to owned `String` because `Arc<str>` pointer
/// identity is meaningless across two independently-built string interners.
fn path_multiset(
    paths: &[graph_hunter_core::graph::HuntResult],
) -> BTreeMap<Vec<String>, usize> {
    let mut map: BTreeMap<Vec<String>, usize> = BTreeMap::new();
    for p in paths {
        let owned: Vec<String> = p.iter().map(|id| id.to_string()).collect();
        *map.entry(owned).or_insert(0) += 1;
    }
    map
}

/// Compare hypothesis-result equivalence: run every DSL in `battery` on both
/// `live` and `rebuilt` and check the returned path multisets agree. This is
/// a behavioral dimension, not a structural one — it proves the two build
/// paths (incremental graph vs. from-scratch journal rebuild) *answer
/// hunts* identically, which the entity/edge/temporal dimensions above don't
/// directly establish (they compare storage, not query results).
///
/// **Honesty (deliberate scope limit):** this uses ONLY
/// `search_temporal_pattern` — the structural matcher. It never calls
/// `search_temporal_pattern_smart`. Anomaly/centrality scores are produced by
/// a SEPARATE scoring pass (`run_full_scoring`, invoked by
/// `GraphHunterApi::load_data` right after apply —
/// `platform/api/src/operations/ingestion.rs`) that neither `live` nor
/// `rebuilt` in THIS module's construction path ever runs — both graphs here
/// read a flat 0, so running the smart/anomaly-ranked matcher would compare
/// 0 == 0 and report `Match` without having tested anything about scoring.
/// That would be a dishonest dimension here. (Note this is NOT the same claim
/// as "ingestion never runs scoring" — in production, `load_data` DOES run
/// `run_full_scoring` right after ingest, so a real live post-ingest graph
/// and a from-scratch rebuild genuinely DIVERGE on scores; see
/// `anomaly_scores`'s field doc for that carve-out's accurate wording.) If
/// scoring ever becomes an observable this module's `live`/`rebuilt`
/// construction actually exercises, it belongs in its own
/// `NotComparable`-until-then dimension, not folded silently into this one.
///
/// A battery entry that fails to `parse_dsl`, or whose
/// `search_temporal_pattern` call errors on either graph, surfaces as a
/// `Diff` naming the failure — it is never swallowed into a silent `Match`.
///
/// **Truncation honesty:** `search_temporal_pattern` is called with a
/// `Some(10_000)` path cap and returns `(paths, truncated)`. If EITHER
/// graph's search truncates for a battery entry, the returned path lists are
/// order-dependent PREFIXES of the true result — comparing their multisets
/// could report a false `Diff` (the two graphs' internal traversal orders
/// differ, so they'd keep different prefixes of an otherwise-identical true
/// set) or a false `Match` (two prefixes can coincidentally agree while the
/// untruncated tails diverge). Rather than risk either, a truncated entry
/// immediately turns the WHOLE dimension `NotComparable` for this run — see
/// the truncation branch below.
///
/// **Vacuous-match discipline (mirrors `compare_temporal_window`):** if every
/// battery entry returns zero paths on BOTH graphs, that is silence, not
/// agreement — the battery never actually exercised anything comparable, so
/// this returns `NotComparable` rather than `Match`. `Match` is reserved for
/// the case where the multisets agree AND at least one battery entry
/// produced a non-empty path set on at least one graph.
pub fn compare_hypothesis_results(
    live: &graph_hunter_core::graph::GraphHunter,
    rebuilt: &graph_hunter_core::graph::GraphHunter,
    battery: &[&str],
) -> DimensionResult {
    let mut any_signal = false;
    for dsl in battery {
        let hypothesis = match graph_hunter_core::parse_dsl(dsl, Some("validation")) {
            Ok(parsed) => parsed.hypothesis,
            Err(e) => {
                return DimensionResult::Diff {
                    detail: format!("hypothesis {dsl:?} failed to parse: {e}"),
                };
            }
        };

        let (live_paths, live_truncated) =
            match live.search_temporal_pattern(&hypothesis, None, Some(10_000)) {
                Ok(result) => result,
                Err(e) => {
                    return DimensionResult::Diff {
                        detail: format!("hypothesis {dsl:?} errored on live graph: {e}"),
                    };
                }
            };
        let (rebuilt_paths, rebuilt_truncated) =
            match rebuilt.search_temporal_pattern(&hypothesis, None, Some(10_000)) {
                Ok(result) => result,
                Err(e) => {
                    return DimensionResult::Diff {
                        detail: format!("hypothesis {dsl:?} errored on rebuilt graph: {e}"),
                    };
                }
            };
        if live_truncated || rebuilt_truncated {
            let where_ = match (live_truncated, rebuilt_truncated) {
                (true, true) => "both graphs",
                (true, false) => "the live graph",
                (false, true) => "the rebuilt graph",
                (false, false) => unreachable!(),
            };
            return DimensionResult::NotComparable {
                reason: format!(
                    "hypothesis {dsl:?} search truncated at 10k paths on {where_}; multiset comparison would be an order-dependent prefix, not real evidence of (dis)agreement"
                ),
            };
        }

        let live_multiset = path_multiset(&live_paths);
        let rebuilt_multiset = path_multiset(&rebuilt_paths);
        if live_multiset != rebuilt_multiset {
            return DimensionResult::Diff {
                detail: format!(
                    "hypothesis {dsl:?} diverges: live returned {} paths ({} distinct), rebuilt returned {} paths ({} distinct)",
                    live_paths.len(),
                    live_multiset.len(),
                    rebuilt_paths.len(),
                    rebuilt_multiset.len(),
                ),
            };
        }
        if !live_paths.is_empty() || !rebuilt_paths.is_empty() {
            any_signal = true;
        }
    }
    if any_signal {
        DimensionResult::Match
    } else {
        DimensionResult::NotComparable {
            reason: "hypothesis battery produced no paths on either graph — no evidence of agreement"
                .to_string(),
        }
    }
}

/// Default hunt battery for `compare_observable_equality`'s
/// `hypothesis_results` dimension: a small, fixed set of single/multi-hop
/// patterns spanning the entity/relation types the built-in parsers
/// actually emit (auth, process-execution, network-connect). Callers with a
/// narrower or wider schema should call `compare_hypothesis_results`
/// directly with their own battery instead of relying on this default.
pub const DEFAULT_HYPOTHESIS_BATTERY: &[&str] = &[
    "User -[Auth]-> Host",
    "Host -[Execute]-> Process",
    "IP -[Connect]-> Host",
];

/// Observable-equality comparison between a live incremental graph and a
/// fresh rebuild from the journal. Extends the original count-only fields
/// (kept for backward compatibility) with rich per-dimension structural
/// results covering the full observable surface `to_snapshot()` exposes:
/// entities (id set), entity metadata (type + kv pairs), the edge multiset,
/// and the temporal window — plus the behavioral `hypothesis_results`
/// dimension (do the two graphs answer the SAME hunts the SAME way).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquivalenceReport {
    pub entity_count_matches: bool,
    pub relation_count_matches: bool,
    pub live_entities: usize,
    pub rebuilt_entities: usize,
    pub live_relations: usize,
    pub rebuilt_relations: usize,
    /// Entity id sets match.
    pub entities: DimensionResult,
    /// Over the shared id set, entity type + metadata match.
    pub entity_metadata: DimensionResult,
    /// The edge multiset — keyed on (source, rel_type, dest, timestamp,
    /// sorted metadata, dataset) — matches with full multiplicity.
    pub edges_multiset: DimensionResult,
    /// `edge_timestamp_range()` matches.
    pub temporal_window: DimensionResult,
    /// Running the same fixed DSL battery through `search_temporal_pattern`
    /// on both graphs yields the same path multiset per hypothesis.
    /// Anomaly-ranked (`search_temporal_pattern_smart`) results are
    /// deliberately excluded — see `compare_hypothesis_results`'s doc
    /// comment for why comparing them would be dishonest.
    pub hypothesis_results: DimensionResult,
    /// Design-spec dimension the graph structurally does NOT observe:
    /// beyond `dataset_id`, provenance lives only in the journal envelope
    /// (`mapping_hash`, `raw_event_sha256`, `confidence`, `canonical_hash`),
    /// never on the graph's entities/relations. Always `NotComparable` —
    /// there is nothing on either graph to compare.
    pub provenance: DimensionResult,
    /// Design-spec dimension the graph structurally does NOT observe here:
    /// anomaly/centrality scores are produced by a SEPARATE scoring pass
    /// (`run_full_scoring`, invoked by `GraphHunterApi::load_data` right
    /// after apply — `platform/api/src/operations/ingestion.rs`), not by
    /// ingestion itself. That means in PRODUCTION a live post-ingest graph
    /// and a fresh from-scratch rebuild genuinely DIVERGE on scores (the
    /// rebuild never re-runs scoring) — the `NotComparable` verdict here is
    /// therefore MORE justified than "nothing to compare," not less; the
    /// actual reason is that the comparator does not inspect score fields at
    /// all, so it is `NotComparable`, never `Match`, regardless of whether
    /// the two graphs' scores happen to agree or diverge. (See
    /// `compare_hypothesis_results`'s doc comment for why the smart/
    /// anomaly-ranked matcher is deliberately excluded from
    /// `hypothesis_results` for the related reason.) Always `NotComparable`.
    pub anomaly_scores: DimensionResult,
    /// Design-spec dimension the graph structurally does NOT observe:
    /// `ingested_at` is GraphHunter's receive clock (real wall-clock time at
    /// insert, stamped via `now_seconds()` — see `CompactRelation::ingested_at`
    /// and `Relation::ingested_at`), so a live graph and a from-scratch
    /// rebuild genuinely differ on it (the rebuild is ingested at a later
    /// wall-clock instant than the original live insert). The comparator
    /// does not compare it — `NotComparable`, never a diff. Always
    /// `NotComparable`.
    pub mvcc_ingested_at: DimensionResult,
    /// `true` iff every journal envelope this report's rebuild replayed was
    /// an `Insert` or `Skipped`. `rebuild_from_journal` does not yet
    /// faithfully replay `Correction`/`Tombstone` envelopes (they fall
    /// through to `inserted`/ignored — see `rebuild_from_journal`'s doc
    /// comment), so a journal containing either makes the rebuild an
    /// UNFAITHFUL reference: a comparable-dimensions `Match` in that case
    /// proves incremental-matches-a-stale-rebuild, not
    /// incremental-matches-truth. Callers must check this before trusting
    /// `all_comparable_dimensions_match()`.
    pub rebuild_faithful: bool,
    /// Human-readable caveats explaining why `rebuild_faithful` is `false`
    /// (e.g. naming how many Correction/Tombstone envelopes were skipped).
    /// Empty when `rebuild_faithful` is `true`.
    pub rebuild_caveats: Vec<String>,
}

impl EquivalenceReport {
    /// True when every dimension that *could* be compared agrees — i.e. none
    /// of `entities`, `entity_metadata`, `edges_multiset`, `temporal_window`,
    /// `hypothesis_results` is `Diff`. `NotComparable` dimensions don't
    /// count against equivalence (absence of evidence, not evidence of
    /// absence) but they also don't count for it; they're surfaced for a
    /// human to judge. The always-`NotComparable` honesty dimensions
    /// (`provenance`, `anomaly_scores`, `mvcc_ingested_at`) are deliberately
    /// excluded from this list — they can never be anything but
    /// `NotComparable`, so including them would be a no-op that just
    /// invites confusion.
    pub fn all_comparable_dimensions_match(&self) -> bool {
        [
            &self.entities,
            &self.entity_metadata,
            &self.edges_multiset,
            &self.temporal_window,
            &self.hypothesis_results,
        ]
        .into_iter()
        .all(|d| !matches!(d, DimensionResult::Diff { .. }))
    }
}

/// Render one dimension as a single readable line: `PASS`, `DIFF: <detail>`,
/// or `NOT-COMPARABLE: <reason>`.
fn fmt_dimension(f: &mut std::fmt::Formatter<'_>, name: &str, result: &DimensionResult) -> std::fmt::Result {
    match result {
        DimensionResult::Match => writeln!(f, "  {name}: PASS"),
        DimensionResult::Diff { detail } => writeln!(f, "  {name}: DIFF: {detail}"),
        DimensionResult::NotComparable { reason } => writeln!(f, "  {name}: NOT-COMPARABLE: {reason}"),
    }
}

/// Human-readable diff report — the spec's "reporte de diferencias legible".
/// A header with entity/relation counts and the `rebuild_faithful` verdict,
/// followed by one line per dimension (`PASS` / `DIFF: <detail>` /
/// `NOT-COMPARABLE: <reason>`).
impl std::fmt::Display for EquivalenceReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "EquivalenceReport: live_entities={} rebuilt_entities={} live_relations={} rebuilt_relations={}",
            self.live_entities, self.rebuilt_entities, self.live_relations, self.rebuilt_relations,
        )?;
        if self.rebuild_faithful {
            writeln!(f, "  rebuild_faithful: true")?;
        } else {
            writeln!(f, "  rebuild_faithful: false ({})", self.rebuild_caveats.join("; "))?;
        }
        fmt_dimension(f, "entities", &self.entities)?;
        fmt_dimension(f, "entity_metadata", &self.entity_metadata)?;
        fmt_dimension(f, "edges_multiset", &self.edges_multiset)?;
        fmt_dimension(f, "temporal_window", &self.temporal_window)?;
        fmt_dimension(f, "hypothesis_results", &self.hypothesis_results)?;
        fmt_dimension(f, "provenance", &self.provenance)?;
        fmt_dimension(f, "anomaly_scores", &self.anomaly_scores)?;
        fmt_dimension(f, "mvcc_ingested_at", &self.mvcc_ingested_at)?;
        Ok(())
    }
}

/// Compare the FULL observable surface of `live` against `rebuilt`: entities,
/// entity metadata, the edge multiset, the temporal window, and — via
/// `battery` — hypothesis-result equivalence. Cross-graph identity is
/// established purely through resolved `String` keys from `to_snapshot()`
/// (and, for hypotheses, resolved `Arc<str>` path ids); `StrId`s are never
/// compared across the two graphs (they're interner-local and meaningless
/// across independently-built graphs). Pure function: no I/O, no tracing
/// (metrics land in a later task).
pub fn compare_observable_equality(
    live: &graph_hunter_core::graph::GraphHunter,
    rebuilt: &graph_hunter_core::graph::GraphHunter,
    battery: &[&str],
) -> EquivalenceReport {
    let (live_entities, live_relations) = live.to_snapshot();
    let (rebuilt_entities, rebuilt_relations) = rebuilt.to_snapshot();

    let live_e = live_entities.len();
    let reb_e = rebuilt_entities.len();
    let live_r = live_relations.len();
    let reb_r = rebuilt_relations.len();

    let (entities, entity_metadata) = compare_entities(&live_entities, &rebuilt_entities);
    let edges_multiset = compare_edges(&live_relations, &rebuilt_relations);
    let temporal_window = compare_temporal_window(live, rebuilt);
    let hypothesis_results = compare_hypothesis_results(live, rebuilt, battery);

    EquivalenceReport {
        entity_count_matches: live_e == reb_e,
        relation_count_matches: live_r == reb_r,
        live_entities: live_e,
        rebuilt_entities: reb_e,
        live_relations: live_r,
        rebuilt_relations: reb_r,
        entities,
        entity_metadata,
        edges_multiset,
        temporal_window,
        hypothesis_results,
        provenance: DimensionResult::NotComparable {
            reason: "beyond dataset-id (now compared via both entity_metadata and edges_multiset), provenance is journal-envelope-only (mapping_hash, raw_event_sha256, confidence, canonical_hash); not a graph observable".to_string(),
        },
        anomaly_scores: DimensionResult::NotComparable {
            reason: "anomaly/centrality scores are produced by a separate scoring pass (run_full_scoring in load_data), so a live post-ingest graph and a fresh rebuild genuinely diverge on scores in production; the comparator does not inspect score fields — this dimension is NotComparable, never Match".to_string(),
        },
        mvcc_ingested_at: DimensionResult::NotComparable {
            reason: "ingested_at is GraphHunter's receive clock (wall-clock at insert), so a live graph and a from-scratch rebuild genuinely differ on it; the comparator does not compare it — NotComparable, never a diff".to_string(),
        },
        // The faithful guard depends on the JOURNAL's envelope classification
        // (Correction/Tombstone), which this function never sees — it only
        // gets the two already-built graphs. Callers going through
        // `check_incremental_equivalence` get the real guard computed there;
        // direct callers of this pure comparator (as the existing rich-compare
        // tests do, building `live`/`rebuilt` by hand) get the conservative
        // default of `true` with no caveats, since there is no journal here
        // to have been unfaithful to.
        rebuild_faithful: true,
        rebuild_caveats: Vec::new(),
    }
}

/// Scan a journal's raw envelopes for `Correction`/`Tombstone` records.
/// `rebuild_from_journal` does not yet faithfully replay those — they fall
/// through to `inserted`/ignored (see its doc comment, journal.rs ~310-313)
/// — so their presence means a from-scratch rebuild is NOT a faithful
/// reference: it reflects "as if those corrections/tombstones never
/// happened," not truth. Insert/Skipped-only journals are fully faithful.
/// Exposed (not just inlined into `check_incremental_equivalence`) so the
/// classification itself is directly testable, independent of the full
/// rebuild-and-compare pipeline.
fn classify_rebuild_faithfulness(
    envelopes: &[CanonicalEnvelope],
) -> (bool, Vec<String>) {
    use graph_hunter_canonical::ChangeKind;
    let unfaithful = envelopes
        .iter()
        .filter(|e| matches!(e.change_kind, ChangeKind::Correction | ChangeKind::Tombstone))
        .count();
    if unfaithful == 0 {
        (true, Vec::new())
    } else {
        (
            false,
            vec![format!(
                "{unfaithful} Correction/Tombstone envelope(s) in the journal are not yet faithfully replayed by rebuild_from_journal"
            )],
        )
    }
}

/// Rebuild a fresh graph from the journal (idempotent apply of every inserted
/// envelope) and compare full observable equality against the live graph.
/// This is the translation-validation check (SOT-VM framing): the
/// from-scratch rebuild is the trusted reference; the live graph is the
/// untrusted incremental artifact.
///
/// Also runs the `rebuild_faithful` honesty guard (see
/// `classify_rebuild_faithfulness`) and emits a single structured
/// `tracing::info!(target: "validation", ...)` metric line summarizing the
/// comparison — the §20 observability requirement.
pub fn check_incremental_equivalence(
    live: &graph_hunter_core::graph::GraphHunter,
    store: &JournalStore,
) -> std::io::Result<EquivalenceReport> {
    let all_envelopes = store.read_all()?;
    let (rebuild_faithful, rebuild_caveats) = classify_rebuild_faithfulness(&all_envelopes);

    // Reuse the envelopes already read above instead of a second
    // `store.read_all()` disk read (`rebuild_from_journal` would otherwise
    // re-read the same file for the faithful-classification and the rebuild).
    let recon = reconstruct_from_envelopes(all_envelopes);
    let mut rebuilt = graph_hunter_core::graph::GraphHunter::new();
    apply_batch_idempotent(&mut rebuilt, &recon.inserted);

    let mut report = compare_observable_equality(live, &rebuilt, DEFAULT_HYPOTHESIS_BATTERY);
    report.rebuild_faithful = rebuild_faithful;
    report.rebuild_caveats = rebuild_caveats;

    // `is_match()` alone would collapse `Diff` and `NotComparable` into the
    // same `false` — genuinely different signals (a real divergence vs. an
    // inert/vacuous battery) — so the metric line carries the 3-way status
    // as a string rather than a bool.
    let hypotheses_match = match report.hypothesis_results {
        DimensionResult::Match => "match",
        DimensionResult::Diff { .. } => "diff",
        DimensionResult::NotComparable { .. } => "not_comparable",
    };

    tracing::info!(
        target: "validation",
        live_entities = report.live_entities,
        rebuilt_entities = report.rebuilt_entities,
        live_relations = report.live_relations,
        rebuilt_relations = report.rebuilt_relations,
        edges_match = report.edges_multiset.is_match(),
        hypotheses_match,
        rebuild_faithful = report.rebuild_faithful,
        "incremental-vs-rebuild validation"
    );

    Ok(report)
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
    fn inserted_envelope_carries_raw_line_in_source_row_not_payload() {
        let mut ev = sample_event(100); // reuse the module helper
        ev.raw_line = Some("{\"unmapped_field\":\"survives\"}".into());
        let envs = build_batch_envelopes("s", "la", "ds", "p", &[ev], &[], 1000);
        // raw_source_row carries the verbatim raw line (field_survival)...
        assert_eq!(
            envs[0].raw_source_row.as_deref(),
            Some("{\"unmapped_field\":\"survives\"}")
        );
        // ...while raw_payload stays the canonical per-event serialization
        // (identity + reconstruction), NOT the raw line (Fase C-2 critical
        // fix: raw_payload must never be the shared raw line).
        assert_ne!(envs[0].raw_payload, "{\"unmapped_field\":\"survives\"}");
        let back: graph_hunter_core::parser::RawIngestEvent =
            serde_json::from_str(&envs[0].raw_payload).unwrap();
        assert_eq!(back.timestamp, 100);
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
    fn unmapped_field_is_reconstructable_from_journal() {
        // An inserted event whose raw_line carries a field the triple omits.
        let mut ev = sample_event(100);
        ev.src_metadata.clear(); // triple carries no such field
        ev.raw_line = Some("{\"src\":\"u\",\"dropped_by_mapping\":\"still_here\"}".into());
        let dir = tempfile::tempdir().unwrap();
        let store = JournalStore::open(dir.path()).unwrap();
        for e in build_batch_envelopes("s", "la", "ds", "p", &[ev], &[], 1000) {
            store.append(&e).unwrap();
        }
        // read the journal back and confirm the dropped field is recoverable
        // from raw_source_row (decoupled from raw_payload, which stays the
        // per-event serialization used for identity/reconstruction).
        let all = store.read_all().unwrap();
        let source_row = all[0].raw_source_row.as_deref().unwrap();
        assert!(source_row.contains("dropped_by_mapping"));
        assert!(source_row.contains("still_here"));
        // raw_payload itself must still deserialize back into the event
        // (envelope_to_delta reconstruction is unaffected by field_survival).
        let back: graph_hunter_core::parser::RawIngestEvent =
            serde_json::from_str(&all[0].raw_payload).unwrap();
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

    /// Regression (Fase C-2 critical-fix wave, whole-phase final review):
    /// C-2 Task 4 briefly made `build_batch_envelopes` set `raw_payload =
    /// ev.raw_line` when present — the raw source row, NOT a serialized
    /// `RawIngestEvent`. `envelope_to_delta`'s
    /// `serde_json::from_str::<RawIngestEvent>(&env.raw_payload)` then
    /// failed to parse and silently returned `None`, so
    /// `apply_batch_idempotent` inserted zero edges for any batch whose
    /// events carried a raw_line — with GRAPHHUNTER_JOURNAL +
    /// GRAPHHUNTER_GRAPHDELTA both on, reconstruction/replay went silently
    /// empty. Decoupling raw_source_row from raw_payload fixes this:
    /// raw_payload is once again always the per-event serialization, so
    /// reconstruction succeeds even when raw_line is present.
    #[test]
    fn envelope_to_delta_reconstructs_even_when_raw_line_was_captured() {
        let mut ev = sample_event(100);
        ev.raw_line = Some("{\"src\":\"1.2.3.4\",\"extra\":\"field\"}".into());
        let envs = build_batch_envelopes("s", "la", "ds", "p", &[ev], &[], 1000);
        assert_eq!(envs.len(), 1);
        // raw_source_row is populated (field_survival)...
        assert!(envs[0].raw_source_row.is_some());
        // ...but envelope_to_delta still succeeds (RED before the fix: this
        // returned None because raw_payload held the raw line instead of a
        // serialized RawIngestEvent).
        let delta = envelope_to_delta(&envs[0]);
        assert!(
            delta.is_some(),
            "envelope_to_delta must reconstruct a delta from a raw_line-carrying insert envelope"
        );
        assert_eq!(delta.unwrap().event.timestamp, 100);
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

    /// C-2 guard (Fase C-2 critical-fix wave, whole-phase final review): a
    /// single source row can legitimately produce multiple DISTINCT events
    /// that all share the same raw source line — e.g. a Sentinel 4688
    /// process-create row yields both a User->Execute->Process and a
    /// Parent->Execute->Child event (see
    /// `sentinel_native_parse_shares_raw_line_across_multi_event_rows`).
    /// C-2's broken `raw_payload = ev.raw_line` made both events serialize
    /// to the IDENTICAL `raw_payload`, hence the IDENTICAL `canonical_hash`
    /// (native_id is always None), so `apply_delta`'s identity dedup
    /// silently collapsed the second event and multiplicity was destroyed.
    /// RED before the fix: `relation_count()` would be 1. GREEN after: 2 —
    /// `raw_payload` is per-event again while `raw_source_row` is shared.
    #[test]
    fn multiplicity_is_preserved_across_a_shared_multi_event_source_row() {
        let shared_raw_line = "{\"EventID\":4688,\"row\":\"one-source-row-two-events\"}";
        let mut e1 = sample_event(100);
        e1.raw_line = Some(shared_raw_line.into());
        let mut e2 = sample_event(100);
        e2.dst_id = "host-2".into(); // a genuinely different event
        e2.raw_line = Some(shared_raw_line.into());

        let envs = build_batch_envelopes("s", "la", "ds", "p", &[e1, e2], &[], 1000);
        assert_eq!(envs.len(), 2);
        // Both envelopes share the same raw_source_row (the source row is
        // shared)...
        assert_eq!(envs[0].raw_source_row, envs[1].raw_source_row);
        assert_eq!(envs[0].raw_source_row.as_deref(), Some(shared_raw_line));
        // ...but their raw_payload (and therefore canonical_hash) differ,
        // because they are distinct events.
        assert_ne!(envs[0].raw_payload, envs[1].raw_payload);
        assert_ne!(envs[0].canonical_hash, envs[1].canonical_hash);

        use graph_hunter_core::graph::GraphHunter;
        let mut g = GraphHunter::new();
        let (applied, dup) = apply_batch_idempotent(&mut g, &envs);
        assert_eq!((applied, dup), (2, 0));
        assert_eq!(g.relation_count(), 2); // multiplicity preserved
    }

    /// C-1 guard (Fase C-2 critical-fix wave, whole-phase final review):
    /// with GRAPHHUNTER_JOURNAL + GRAPHHUNTER_GRAPHDELTA both on, a batch of
    /// raw_line-carrying insert envelopes must still reconstruct into graph
    /// edges. RED before the fix: `envelope_to_delta` returned `None` for
    /// every envelope (raw_payload held the raw line, not a serialized
    /// RawIngestEvent), so `apply_batch_idempotent` silently applied 0
    /// edges. GREEN after: raw_payload is the per-event serialization again.
    #[test]
    fn flags_on_reconstruction_is_non_empty_for_raw_line_carrying_batch() {
        let mut e1 = sample_event(100);
        e1.raw_line = Some("{\"row\":1}".into());
        let mut e2 = sample_event(200);
        e2.raw_line = Some("{\"row\":2}".into());
        let envs = build_batch_envelopes("s", "la", "ds", "p", &[e1, e2], &[], 1000);

        use graph_hunter_core::graph::GraphHunter;
        let mut g = GraphHunter::new();
        let (applied, dup) = apply_batch_idempotent(&mut g, &envs);
        assert_eq!(applied, 2);
        assert_eq!(dup, 0);
        assert_eq!(g.relation_count(), 2);
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

    /// Build a `(live, store, _tempdir)` triple whose journal contains only
    /// Insert/Skipped envelopes — same shape as
    /// `rebuild_from_journal_matches_live_after_idempotent_apply` above (3
    /// inserts + 1 skipped + a crash replay on the live side). Shared by the
    /// NotComparable/readable-render test and as the faithful baseline for
    /// the rebuild_faithful guard test. The `TempDir` guard MUST be kept
    /// alive by the caller (its `Drop` deletes the directory `store` reads
    /// from) — `JournalStore` only holds a `PathBuf`, not the guard itself.
    fn build_live_graph_and_its_journal(
    ) -> (graph_hunter_core::graph::GraphHunter, JournalStore, tempfile::TempDir) {
        use graph_hunter_core::graph::GraphHunter;
        let dir = tempfile::tempdir().unwrap();
        let store = JournalStore::open(dir.path()).unwrap();
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
        (live, store, dir)
    }

    /// Step 1/3 of the brief: the design-spec dimensions the graph does NOT
    /// observe (`provenance`, `anomaly_scores`) must surface as
    /// `NotComparable`, never `Match`/`Diff` — this is the honesty
    /// requirement, not an accuracy one. An Insert/Skipped-only journal must
    /// report `rebuild_faithful == true`. And `Display` must render a
    /// readable report: a header mentioning entity counts, plus at least one
    /// `NOT-COMPARABLE` marker for the honesty dimensions.
    #[test]
    fn report_marks_uncomparable_dimensions_and_renders_readably() {
        let (live, store, _dir) = build_live_graph_and_its_journal();
        let report = check_incremental_equivalence(&live, &store).unwrap();

        assert!(
            matches!(report.provenance, DimensionResult::NotComparable { .. }),
            "provenance: {:?}",
            report.provenance
        );
        assert!(
            matches!(report.anomaly_scores, DimensionResult::NotComparable { .. }),
            "anomaly_scores: {:?}",
            report.anomaly_scores
        );
        assert!(
            matches!(report.mvcc_ingested_at, DimensionResult::NotComparable { .. }),
            "mvcc_ingested_at: {:?}",
            report.mvcc_ingested_at
        );
        assert!(report.rebuild_faithful, "journal has only Insert/Skipped -> faithful");
        assert!(report.rebuild_caveats.is_empty());

        let rendered = format!("{}", report);
        assert!(rendered.contains("entities"), "rendered report: {rendered}");
        assert!(
            rendered.contains("NOT-COMPARABLE") || rendered.contains("not comparable"),
            "rendered report: {rendered}"
        );
    }

    /// Step 2 of the brief: the rebuild_faithful guard. A journal containing
    /// a `Correction` envelope (constructed by taking an `Insert` envelope —
    /// there is no dedicated `CanonicalEnvelope::new_correction` constructor
    /// on this branch — and setting its `change_kind` directly; the field is
    /// `pub` and `ChangeKind` is `Copy`, so this is a legitimate way to build
    /// one from the test surface, not a workaround) must flip
    /// `rebuild_faithful` to `false` and record a caveat naming the count.
    /// `rebuild_from_journal` does not yet replay Correction/Tombstone
    /// records faithfully (journal.rs ~310-313: they fall through to
    /// `inserted`/ignored), so a rebuild against such a journal is not a
    /// trustworthy reference — the guard exists precisely to flag that.
    #[test]
    fn journal_with_correction_envelope_marks_rebuild_unfaithful() {
        use graph_hunter_canonical::ChangeKind;
        let (live, store, _dir) = build_live_graph_and_its_journal();

        // One Correction envelope, distinct from every existing Insert (a
        // fresh timestamp keeps its raw_payload/canonical_hash unique).
        let mut correction = insert_envelope_for(&sample_event(400));
        correction.change_kind = ChangeKind::Correction;
        store.append(&correction).unwrap();

        let report = check_incremental_equivalence(&live, &store).unwrap();
        assert!(
            !report.rebuild_faithful,
            "a Correction envelope in the journal must mark the rebuild unfaithful"
        );
        assert_eq!(report.rebuild_caveats.len(), 1, "{:?}", report.rebuild_caveats);
        assert!(
            report.rebuild_caveats[0].contains('1'),
            "caveat should name the count of unfaithful envelopes: {}",
            report.rebuild_caveats[0]
        );

        // The classification helper itself is independently exercised too,
        // decoupled from the full rebuild-and-compare pipeline.
        let all = store.read_all().unwrap();
        let (faithful, caveats) = classify_rebuild_faithfulness(&all);
        assert!(!faithful);
        assert_eq!(caveats.len(), 1);
    }

    // ── compare_observable_equality (rich structural comparator) ─────

    /// Build a `(live, rebuilt)` GraphHunter pair from the same journaled
    /// envelopes. Mirrors
    /// `rebuild_from_journal_matches_live_after_idempotent_apply` above (same
    /// 3 inserts + 1 skipped + a crash replay on the live side) so the rich
    /// comparator tests exercise the identical shape.
    fn build_live_and_rebuilt_from_same_envelopes() -> (
        graph_hunter_core::graph::GraphHunter,
        graph_hunter_core::graph::GraphHunter,
    ) {
        use graph_hunter_core::graph::GraphHunter;
        let dir = tempfile::tempdir().unwrap();
        let store = JournalStore::open(dir.path()).unwrap();
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

        let recon = rebuild_from_journal(&store).unwrap();
        let mut rebuilt = GraphHunter::new();
        apply_batch_idempotent(&mut rebuilt, &recon.inserted);

        (live, rebuilt)
    }

    #[test]
    fn rich_compare_identical_graphs_match_all_structural_dimensions() {
        let (live, rebuilt) = build_live_and_rebuilt_from_same_envelopes();
        let report = compare_observable_equality(&live, &rebuilt, DEFAULT_HYPOTHESIS_BATTERY);
        assert!(matches!(report.entities, DimensionResult::Match), "entities: {:?}", report.entities);
        assert!(
            matches!(report.entity_metadata, DimensionResult::Match),
            "metadata: {:?}",
            report.entity_metadata
        );
        assert!(
            matches!(report.edges_multiset, DimensionResult::Match),
            "edges: {:?}",
            report.edges_multiset
        );
        assert!(
            matches!(report.temporal_window, DimensionResult::Match),
            "window: {:?}",
            report.temporal_window
        );
        assert!(
            matches!(report.hypothesis_results, DimensionResult::Match),
            "hypothesis_results: {:?}",
            report.hypothesis_results
        );
        assert!(report.all_comparable_dimensions_match());
        // Legacy count fields stay populated too — the report is self-contained.
        assert!(report.entity_count_matches);
        assert!(report.relation_count_matches);
    }

    /// Fix 3 (renamed from `rich_compare_catches_injected_edge_and_metadata_divergence`):
    /// this test only ever injected an edge divergence, never a metadata one
    /// — the old name was a misnomer. The metadata-Diff case now has its own
    /// dedicated test below (`rich_compare_catches_entity_metadata_divergence`).
    #[test]
    fn rich_compare_catches_injected_edge_divergence() {
        let (mut live, rebuilt) = build_live_and_rebuilt_from_same_envelopes();
        // Mutate the LIVE graph after the fact so it diverges from the
        // rebuild: one extra edge the journal never recorded. Both endpoints
        // ("1.2.3.4", "host-1") already exist in `live` from the journaled
        // batch (sample_event uses them for all three timestamps), so
        // add_relation succeeds without needing new entities.
        live.add_relation(graph_hunter_core::Relation::new(
            "1.2.3.4",
            "host-1",
            graph_hunter_core::RelationType::Connect,
            999,
        ))
        .expect("both endpoints already exist in the live graph");

        let report = compare_observable_equality(&live, &rebuilt, DEFAULT_HYPOTHESIS_BATTERY);
        assert!(
            matches!(report.edges_multiset, DimensionResult::Diff { .. }),
            "expected edge multiset divergence, got {:?}",
            report.edges_multiset
        );
        assert!(!report.all_comparable_dimensions_match());
    }

    /// Fix 2 — negative control for the `entities` dimension: an entity
    /// present in `live` but absent from the rebuild (the journal never saw
    /// it) must surface as a `Diff` on `entities` specifically, not get
    /// conflated with an `entity_metadata` divergence.
    #[test]
    fn rich_compare_catches_entity_only_in_live() {
        let (mut live, rebuilt) = build_live_and_rebuilt_from_same_envelopes();
        live.add_entity(graph_hunter_core::Entity::new(
            "orphan-entity",
            graph_hunter_core::EntityType::Host,
        ))
        .expect("fresh id, not already present in live");

        let report = compare_observable_equality(&live, &rebuilt, DEFAULT_HYPOTHESIS_BATTERY);
        assert!(
            matches!(report.entities, DimensionResult::Diff { .. }),
            "expected entity id-set divergence, got {:?}",
            report.entities
        );
        assert!(!report.all_comparable_dimensions_match());
    }

    /// Fix 2 — negative control for the `entity_metadata` dimension: same id
    /// present on both sides, but the LIVE side's entity type diverges from
    /// what the journal rebuild produced. Must surface as a `Diff` on
    /// `entity_metadata` while `entities` (the id-set dimension) stays a
    /// `Match`, since both sides still agree on which ids exist.
    #[test]
    fn rich_compare_catches_entity_metadata_divergence() {
        let (mut live, rebuilt) = build_live_and_rebuilt_from_same_envelopes();
        // "1.2.3.4" exists on both sides (sample_event's src, type IP).
        // Flip its type on the live side only — a genuine type divergence,
        // not a Display-string coincidence (Fix 1's false-Match vector).
        let ent = live
            .get_entity_mut("1.2.3.4")
            .expect("entity exists in live from the journaled batch");
        assert_eq!(ent.entity_type, graph_hunter_core::EntityType::IP);
        ent.entity_type = graph_hunter_core::EntityType::Other("IP".to_string());

        let report = compare_observable_equality(&live, &rebuilt, DEFAULT_HYPOTHESIS_BATTERY);
        assert!(
            matches!(report.entities, DimensionResult::Match),
            "id sets still agree, expected Match, got {:?}",
            report.entities
        );
        assert!(
            matches!(report.entity_metadata, DimensionResult::Diff { .. }),
            "expected entity_metadata divergence, got {:?}",
            report.entity_metadata
        );
        assert!(!report.all_comparable_dimensions_match());
    }

    /// Fix 2 — negative control for the `temporal_window` dimension: an edge
    /// with a timestamp outside the journal-rebuilt range pushes `live`'s
    /// `edge_timestamp_range()` away from `rebuilt`'s, without necessarily
    /// changing the entity dimensions.
    #[test]
    fn rich_compare_catches_temporal_window_divergence() {
        let (mut live, rebuilt) = build_live_and_rebuilt_from_same_envelopes();
        // Both endpoints already exist in `live` (see
        // rich_compare_catches_injected_edge_divergence); the journaled
        // batch's timestamps are 100/200/300, so 10_000_000 is well outside
        // the rebuild's range.
        live.add_relation(graph_hunter_core::Relation::new(
            "1.2.3.4",
            "host-1",
            graph_hunter_core::RelationType::Connect,
            10_000_000,
        ))
        .expect("both endpoints already exist in the live graph");

        let report = compare_observable_equality(&live, &rebuilt, DEFAULT_HYPOTHESIS_BATTERY);
        assert!(
            matches!(report.temporal_window, DimensionResult::Diff { .. }),
            "expected temporal window divergence, got {:?}",
            report.temporal_window
        );
        assert!(!report.all_comparable_dimensions_match());
    }

    /// Fix 6 (minor, whole-phase review): the `Display` impl's `Diff` branch
    /// (`fmt_dimension`'s `DimensionResult::Diff { detail } => "DIFF: {detail}"`)
    /// had no direct test — `report_marks_uncomparable_dimensions_and_renders_readably`
    /// only ever exercised the `NotComparable` branch. Reuses the same
    /// divergence-injection as `rich_compare_catches_injected_edge_divergence`
    /// to force a real `Diff` on `edges_multiset`, then asserts the rendered
    /// report contains both the `DIFF` marker and a substring of that
    /// dimension's actual detail message.
    #[test]
    fn display_renders_diff_dimension_with_its_detail() {
        let (mut live, rebuilt) = build_live_and_rebuilt_from_same_envelopes();
        live.add_relation(graph_hunter_core::Relation::new(
            "1.2.3.4",
            "host-1",
            graph_hunter_core::RelationType::Connect,
            999,
        ))
        .expect("both endpoints already exist in the live graph");

        let report = compare_observable_equality(&live, &rebuilt, DEFAULT_HYPOTHESIS_BATTERY);
        assert!(
            matches!(report.edges_multiset, DimensionResult::Diff { .. }),
            "expected edge multiset divergence, got {:?}",
            report.edges_multiset
        );

        let rendered = format!("{report}");
        assert!(rendered.contains("DIFF"), "rendered report: {rendered}");
        assert!(
            rendered.contains("distinct edge keys"),
            "rendered report should carry the Diff's detail text: {rendered}"
        );
    }

    // ── compare_hypothesis_results (hypothesis-result equivalence) ───

    #[test]
    fn rich_compare_hypothesis_results_match_across_incremental_and_rebuild() {
        let (live, rebuilt) = build_live_and_rebuilt_from_same_envelopes();
        // The plan doc's illustrative battery ("User -[Auth]-> Host",
        // "Host -[Execute]-> Process") uses entity/relation types that do
        // NOT exist in this fixture. `build_live_and_rebuilt_from_same_envelopes`
        // journals `sample_event`s, which are IP "1.2.3.4" -[Connect]->
        // Host "host-1" (see `sample_event` above) — so the battery here
        // uses THOSE types, matching the actual fixture schema.
        let battery = ["IP -[Connect]-> Host"];
        let report = compare_hypothesis_results(&live, &rebuilt, &battery);
        assert!(matches!(report, DimensionResult::Match), "hypothesis results: {:?}", report);
    }

    /// Negative control: a battery hypothesis whose path multiset diverges
    /// between `live` and a deliberately-divergent rebuild. Reuses the
    /// divergence-injection style from `rich_compare_catches_injected_edge_divergence`,
    /// but adds a brand-new entity + edge (not a duplicate edge between
    /// already-matched entities) so the extra path is unambiguous in the
    /// multiset regardless of whether the matcher deduplicates multiple
    /// edge instances between the same vertex pair.
    #[test]
    fn rich_compare_hypothesis_results_catches_divergent_rebuild() {
        let (mut live, rebuilt) = build_live_and_rebuilt_from_same_envelopes();
        live.add_entity(graph_hunter_core::Entity::new(
            "host-2",
            graph_hunter_core::EntityType::Host,
        ))
        .expect("fresh id, not already present in live");
        live.add_relation(graph_hunter_core::Relation::new(
            "1.2.3.4",
            "host-2",
            graph_hunter_core::RelationType::Connect,
            400,
        ))
        .expect("both endpoints now exist in the live graph");

        let battery = ["IP -[Connect]-> Host"];
        let report = compare_hypothesis_results(&live, &rebuilt, &battery);
        assert!(
            matches!(report, DimensionResult::Diff { .. }),
            "expected hypothesis-result divergence, got {:?}",
            report
        );

        // Surfaces through the full comparator too, and drags down the
        // overall equivalence verdict.
        let full = compare_observable_equality(&live, &rebuilt, &battery);
        assert!(
            matches!(full.hypothesis_results, DimensionResult::Diff { .. }),
            "expected hypothesis_results Diff in the full report, got {:?}",
            full.hypothesis_results
        );
        assert!(!full.all_comparable_dimensions_match());
    }

    /// Honesty fix: a battery that is entirely inert against the fixture —
    /// every entry returns zero paths on BOTH `live` and `rebuilt` — must
    /// surface as `NotComparable`, never as a silent `Match`. "The whole
    /// battery was inert against this data" and "the graphs genuinely agree
    /// on real, non-empty path sets" are NOT the same signal, and reporting
    /// both as `Match` would be false confidence. The fixture
    /// (`build_live_and_rebuilt_from_same_envelopes` / `sample_event`) only
    /// ever produces IP "1.2.3.4" -[Connect]-> Host "host-1" edges — there is
    /// no `Process` entity or `Execute` relation anywhere in it — so
    /// "Process -[Execute]-> Process" is guaranteed to return zero paths on
    /// both graphs.
    #[test]
    fn rich_compare_hypothesis_results_inert_battery_is_not_comparable() {
        let (live, rebuilt) = build_live_and_rebuilt_from_same_envelopes();
        let battery = ["Process -[Execute]-> Process"];
        let report = compare_hypothesis_results(&live, &rebuilt, &battery);
        match &report {
            DimensionResult::NotComparable { reason } => {
                assert!(!reason.is_empty(), "reason should explain the vacuity");
            }
            other => panic!(
                "expected NotComparable for an all-inert battery, got {:?}",
                other
            ),
        }
        assert!(!report.is_match(), "an inert battery must never report Match");
    }

    /// A battery DSL string that fails to parse must surface honestly as a
    /// `Diff`, never as a silent `Match` — an error is not evidence of
    /// agreement.
    #[test]
    fn rich_compare_hypothesis_results_surfaces_unparseable_battery_entries() {
        let (live, rebuilt) = build_live_and_rebuilt_from_same_envelopes();
        let battery = ["not a valid dsl string"];
        let report = compare_hypothesis_results(&live, &rebuilt, &battery);
        match report {
            DimensionResult::Diff { detail } => {
                assert!(detail.contains("failed to parse"), "detail: {detail}");
            }
            other => panic!("expected Diff surfacing the parse failure, got {:?}", other),
        }
    }
}
