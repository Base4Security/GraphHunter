use ahash::{HashMap, HashMapExt, HashSet, HashSetExt};
use smallvec::SmallVec;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

// DFS scratch path. Cap 8 covers every 2/3/4-hop hypothesis (depth+1 ≤ 5)
// inline; deeper hypotheses spill to heap automatically.
type DfsPath = SmallVec<[StrId; 8]>;

use crate::analytics::RelSchemaEntry;

use rayon::prelude::*;

use crate::anomaly::{AnomalyScorer, ScoringWeights};
use crate::entity::Entity;
use crate::errors::GraphError;
use crate::hypothesis::Hypothesis;
use crate::interner::{StrId, StringInterner};
use crate::metadata_store::MetadataStore;
use crate::relation::{CompactRelation, Relation, encode_ingested_at};
use crate::types::{
    EntityType, MergePolicy, RelationType, entity_type_matches, relation_type_matches,
};

/// Result of a successful pattern match: an ordered list of entity IDs
/// representing the attack path through the graph.
///
/// Each element is an `Arc<str>` cloned directly from the
/// `StringInterner` storage — a refcount bump, not a string allocation.
/// On cap-saturated benches this is the difference between
/// `path.len() × String::from(...)` allocations per result (~60% of
/// `ba-any-2hop` time) and a single 4-byte refcount increment per
/// path step. Callers that need an owned `String` can `.to_string()`
/// per element; serde serialization is identical to `Vec<String>`
/// because `Arc<str>: Serialize` produces the same JSON.
pub type HuntResult = Vec<std::sync::Arc<str>>;

/// Current wall-clock time in epoch seconds. Falls back to the
/// [`crate::relation::INGEST_EPOCH_BASE`] if the system clock is
/// somehow set before 1970 (paranoid; real systems won't hit this).
fn now_seconds() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(crate::relation::INGEST_EPOCH_BASE)
}

/// Iterative DFS frame. Module-level so it can appear in the
/// `dfs_match_iterative` signature (callers pass a reusable scratch stack).
struct DfsFrame {
    sid: StrId,
    step_idx: usize,
    edge_hi: usize,
    edge_cursor: usize,
}

/// Stack frame for the anomaly-pruned DFS. Carries the running path-anomaly
/// sum so the admissible heuristic can be evaluated without re-walking the
/// path. Module-level so it can appear in `dfs_match_smart`'s signature.
struct AnomalyFrame {
    sid: StrId,
    step_idx: usize,
    edge_hi: usize,
    edge_cursor: usize,
    path_anomaly_sum: f64,
}

/// Concrete heap type used by the smart top-K search.
///
/// Min-heap on `(score, path)`: the smallest-score entry sits at the root,
/// so when capacity is exceeded we pop the worst path. Wrapping in `Reverse`
/// inverts `BinaryHeap`'s default max-heap into a min-heap.
type SmartHeap = std::collections::BinaryHeap<
    std::cmp::Reverse<(ordered_float::OrderedFloat<f64>, Vec<std::sync::Arc<str>>)>,
>;

/// Sentinel tag value used by `entity_type_tags` to mean "no entity lives at
/// this StrId slot" (either it was never inserted or it has been removed).
/// 253 is unused by `EntityType::to_u8()` (which allocates 0..=8, 254 for
/// `Any`, and 255 for `Other(_)`) so it can't collide with a real tag.
const TAG_DEAD: u8 = 253;

/// The core threat hunting graph engine.
///
/// Stores entities in a HashMap keyed by interned StrId for memory efficiency.
/// Relations in a spillable edge store that can overflow to disk for large graphs.
/// All string IDs are interned via `StringInterner` — each unique ID stored once.
///
/// A parallel `entity_type_tags` array gives the DFS inner loop a cache-
/// friendly fast path: reading an entity's type becomes a single indexed
/// load into a `Vec<u8>` instead of a HashMap probe that pulls a full
/// `Entity` (≈120 bytes, mostly cold) into cache just to read ~1 byte.
#[derive(Clone)]
pub struct GraphHunter {
    /// String interner: stores each unique entity ID once.
    pub interner: StringInterner,
    pub entities: HashMap<StrId, Entity>,
    /// SoA hot-path index: `entity_type_tags[sid.index()]` holds the u8
    /// tag of the entity's type, or `TAG_DEAD` when the slot is empty
    /// (never populated, or removed). Kept in lockstep with `entities`.
    ///
    /// For `EntityType::Other(String)` the tag is 255 and the actual name
    /// lives in `other_type_names` — we keep custom names off this hot
    /// array so it stays a dense `Vec<u8>` indexable without indirection.
    pub(crate) entity_type_tags: Vec<u8>,
    /// Side table for `EntityType::Other(_)` names, keyed by the same StrId.
    /// Rarely populated — only matters when users add custom types via the
    /// DSL. Kept off the hot array so the common path stays tight.
    pub(crate) other_type_names: HashMap<StrId, String>,
    /// Index: entity type → set of interned entity IDs of that type.
    pub type_index: HashMap<EntityType, HashSet<StrId>>,
    /// Reverse adjacency: dest StrId → vec of source StrIds.
    pub reverse_adj: HashMap<StrId, Vec<StrId>>,
    /// Append-only metadata store for relation metadata.
    pub meta_store: MetadataStore,
    /// Unique dataset IDs. Index 0 = "no dataset".
    pub dataset_tags: Vec<Arc<str>>,
    /// Optional anomaly scorer for path ranking.
    pub anomaly_scorer: Option<AnomalyScorer>,
    /// Whether edges have been sorted by timestamp (avoids re-sorting on every search).
    edges_sorted: bool,
    /// Memoized relation schema. Keyed by the `(edge_count, meta_bytes)`
    /// fingerprint so it auto-invalidates after any ingest that appends
    /// an edge (and any edge with metadata grows `meta_bytes`). Schema
    /// computation is O(E) and dominated by metadata decode; on graphs
    /// with millions of edges the uncached call costs tens of seconds.
    /// Shared via `Arc<Mutex<_>>` so the default `#[derive(Clone)]` on
    /// `GraphHunter` keeps working.
    pub(crate) schema_cache: Arc<Mutex<Option<SchemaCacheEntry>>>,
    /// B2 — NLF (Neighborhood Label Frequency) index. **Lazy**: built
    /// on first matcher invocation via `ensure_nlf()`, not eagerly
    /// inside `sort_edges_by_timestamp`. Heavy-logs #3.5 deferred
    /// the build so opening a 28 GB EVTX session is bounded by the
    /// streaming reader (a few MB) instead of by the index footprint
    /// (~3.6 GB at 100M vertices).
    pub(crate) nlf: std::sync::OnceLock<crate::nlf::NlfTable>,
    /// D5/M2 — k-hop label reachability index. Same lazy contract
    /// as `nlf`: built on demand at first matcher invocation.
    pub(crate) khop_reach: std::sync::OnceLock<crate::khop_reach::KHopReach>,
    /// L3 stage 2c part 2 final — sole canonical edge store.
    /// Replaced the previous `edge_store: SpillableEdgeStore` field
    /// once all readers/writers migrated. The matcher hot path
    /// reads `streaming.neighbors_arc(sid)` directly; admin /
    /// aggregation paths use `streaming.for_each_edge`; spill-to-
    /// disk lives behind `with_memory_budget_edges` (D4 stage 2).
    pub streaming: std::sync::Arc<crate::streaming::InMemoryStreamingBackend>,
    /// Lazy lock-free snapshot of the streaming outer table —
    /// built on first matcher invocation post-finalize, dropped
    /// on `add_relation`. The matcher hot-path reads via
    /// `streaming_snapshot().neighbors_arc(sid)` to skip the
    /// per-frame outer-table `RwLock` acquire that
    /// `streaming.neighbors_arc(sid)` performs.
    pub(crate) streaming_snapshot:
        std::sync::OnceLock<crate::streaming::FrozenSnapshot>,
    /// D3 stage 3 — monotonic mutation counter. Bumped on every
    /// edge / entity ingestion or removal. External caches keyed
    /// on this counter (e.g. the per-Session LFTJ trie cache in
    /// `platform/api/state`) detect graph mutations cheaply
    /// without diffing the whole graph: read the counter, compare
    /// to the cached value, invalidate on mismatch. The clone
    /// derive on `GraphHunter` clones the counter as a fresh
    /// `AtomicU64` with the current value, which is the right
    /// semantics for `compact_before` rebuilds — the cloned graph
    /// gets the same version as the original at the clone moment,
    /// then both diverge as they take subsequent writes.
    pub(crate) mutation_version: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

/// One entry in the schema cache: stores the fingerprint used to validate
/// freshness plus the computed schema.
#[derive(Clone)]
pub(crate) struct SchemaCacheEntry {
    pub edge_count: usize,
    pub meta_bytes: usize,
    pub schema: Vec<RelSchemaEntry>,
}

/// Checks if a relation type tag matches a pattern, treating Any as wildcard.
#[inline]
fn relation_type_tag_matches(pattern: &RelationType, tag: u8) -> bool {
    *pattern == RelationType::Any || pattern.to_u8() == tag
}

// ── Parallel-finalize dispatch ────────────────────────────────────────────────

/// Minimum vertex count above which the parallel sort path is chosen by
/// default.  Below this the rayon scheduler overhead exceeds sorting gains.
const PARALLEL_FINALIZE_VERTEX_THRESHOLD: usize = 50_000;

/// Minimum edge count above which the parallel sort path is chosen by default.
/// A graph with many edges but few vertices (dense hubs) also benefits.
const PARALLEL_FINALIZE_EDGE_THRESHOLD: usize = 1_000_000;

/// Decides whether `finalize_parallel` should be used for a graph of the
/// given shape.
///
/// * `env_override = Some(true)`  — `GRAPHHUNTER_PARALLEL_FINALIZE=1`; force
///   parallel regardless of size.
/// * `env_override = Some(false)` — `GRAPHHUNTER_PARALLEL_FINALIZE=0`; escape
///   hatch for one release if rayon-scheduler regressions appear.
/// * `env_override = None`        — size threshold decides.
pub(crate) fn should_finalize_parallel(
    vertex_count: usize,
    edge_count: usize,
    env_override: Option<bool>,
) -> bool {
    match env_override {
        Some(forced) => forced,
        None => {
            vertex_count > PARALLEL_FINALIZE_VERTEX_THRESHOLD
                || edge_count > PARALLEL_FINALIZE_EDGE_THRESHOLD
        }
    }
}

impl GraphHunter {
    /// Creates a new empty graph.
    pub fn new() -> Self {
        Self {
            interner: StringInterner::new(),
            entities: HashMap::new(),
            entity_type_tags: Vec::new(),
            other_type_names: HashMap::new(),
            type_index: HashMap::new(),
            reverse_adj: HashMap::new(),
            meta_store: MetadataStore::new(),
            dataset_tags: vec![Arc::from("")],
            anomaly_scorer: None,
            edges_sorted: false,
            schema_cache: Arc::new(Mutex::new(None)),
            nlf: std::sync::OnceLock::new(),
            khop_reach: std::sync::OnceLock::new(),
            // Plug-and-play: every fresh GraphHunter ships with
            // auto-spill armed. Budget chosen so a 28 GB EVTX
            // session (~30M edges) hits the threshold a manageable
            // number of times (~30 spill rounds at 1M edges each)
            // and the matcher hot-path mmap reads never have to
            // touch a hot append site. Override via
            // `InMemoryStreamingBackend::with_memory_budget_edges`
            // before the first add_relation if a different budget
            // is needed (e.g. tests set 0 to disable, ingest CLI
            // tools may set lower for early-spill validation).
            streaming: std::sync::Arc::new(
                crate::streaming::InMemoryStreamingBackend::new()
                    .with_memory_budget_edges(1_000_000),
            ),
            streaming_snapshot: std::sync::OnceLock::new(),
            mutation_version: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Test hook: construct a GraphHunter whose streaming backend is armed with
    /// `with_spill_fail(true)` — budget_edges=1, force_fail=true.  The first
    /// `push_to_streaming` call will return `GraphError::Spill(_)`.  Used by
    /// C3a regression tests only; do not call from production code.
    #[cfg(test)]
    fn with_spill_failing_backend() -> Self {
        let mut g = Self::new();
        g.streaming = std::sync::Arc::new(
            crate::streaming::InMemoryStreamingBackend::new().with_spill_fail(true),
        );
        g
    }

    /// D3 stage 3 — current mutation version. Caller-side caches
    /// (Session-level LFTJ trie, NLF/khop indexes that survive
    /// across batches) compare this to a cached snapshot of the
    /// counter to decide whether their data is stale. Invariant:
    /// returning a value V here implies every mutation observed
    /// up to and including the bump that produced V has retired.
    pub fn mutation_version(&self) -> u64 {
        self.mutation_version
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Internal: bump on every successful mutation. The Acquire/
    /// Release pair guarantees that any reader that loads the
    /// post-bump value also sees the writer's prior data.
    fn bump_mutation_version(&self) {
        self.mutation_version
            .fetch_add(1, std::sync::atomic::Ordering::Release);
    }

    /// Lazy NLF accessor (heavy-logs #3.5). Builds the index on
    /// first invocation; subsequent calls return the cached
    /// reference. Concurrent callers are serialized inside
    /// `OnceLock::get_or_init` and only one build runs.
    ///
    /// Public because L2 (`run_hunt_batch`) calls this to pre-warm
    /// the cache before iterating templates so every query sees a
    /// hot index.
    pub fn ensure_nlf(&self) -> &crate::nlf::NlfTable {
        self.nlf.get_or_init(|| crate::nlf::NlfTable::build(self))
    }

    /// Lazy k-hop reachability accessor.
    pub fn ensure_khop_reach(&self) -> &crate::khop_reach::KHopReach {
        self.khop_reach
            .get_or_init(|| crate::khop_reach::KHopReach::build(self))
    }

    /// Whether the NLF cache has been populated. Used by the L2
    /// batch entry point to report whether the batch had to pay
    /// the build cost.
    pub fn nlf_is_built(&self) -> bool {
        self.nlf.get().is_some()
    }

    /// Whether the k-hop reachability cache has been populated.
    pub fn khop_reach_is_built(&self) -> bool {
        self.khop_reach.get().is_some()
    }

    /// Pre-allocates capacity for the internal HashMaps to avoid rehashing during bulk insertion.
    pub fn reserve(&mut self, entity_hint: usize, relation_hint: usize) {
        self.interner.reserve(entity_hint);
        self.entities.reserve(entity_hint);
        self.entity_type_tags.reserve(entity_hint);
        self.type_index.reserve(16);
        self.reverse_adj.reserve(entity_hint);
        let _ = relation_hint;
    }

    /// Ensures `entity_type_tags` has a slot at `sid.index()`, padding any
    /// prior gap with `TAG_DEAD`. Called by every entity insertion site.
    #[inline]
    fn ensure_tag_capacity(&mut self, sid: StrId) {
        let needed = sid.index() + 1;
        if self.entity_type_tags.len() < needed {
            self.entity_type_tags.resize(needed, TAG_DEAD);
        }
    }

    /// Records an entity's type in the SoA hot array. Must be called
    /// whenever `self.entities` is mutated so the two stay in sync.
    #[inline]
    fn set_entity_type_tag(&mut self, sid: StrId, et: &EntityType) {
        self.ensure_tag_capacity(sid);
        self.entity_type_tags[sid.index()] = et.to_u8();
        if let EntityType::Other(name) = et {
            self.other_type_names.insert(sid, name.clone());
        } else {
            // Transitioning away from Other(_) — drop the side-table entry.
            self.other_type_names.remove(&sid);
        }
    }

    /// Marks a slot as empty. Used after `entities.remove(..)`.
    #[inline]
    fn mark_entity_dead(&mut self, sid: StrId) {
        if let Some(slot) = self.entity_type_tags.get_mut(sid.index()) {
            *slot = TAG_DEAD;
        }
        self.other_type_names.remove(&sid);
    }

    /// Fast entity-type check against a pattern, reading only the SoA
    /// hot array (and, for `Other(_)`, a small side table). Semantics
    /// match `self.entities.get(&sid).map_or(false, |e| entity_type_matches(pattern, &e.entity_type))`
    /// but avoids the HashMap probe + full `Entity` deref on every DFS step.
    #[inline]
    pub(crate) fn fast_type_matches(&self, pattern: &EntityType, sid: StrId) -> bool {
        let idx = sid.index();
        let tag = match self.entity_type_tags.get(idx) {
            Some(&t) => t,
            None => return false,
        };
        if tag == TAG_DEAD {
            return false;
        }
        if matches!(pattern, EntityType::Any) {
            return true;
        }
        let pat_tag = pattern.to_u8();
        if pat_tag != tag {
            return false;
        }
        // Same tag; only `Other(_)` needs a string comparison to disambiguate.
        if tag == 255 {
            if let EntityType::Other(pat_name) = pattern {
                return self
                    .other_type_names
                    .get(&sid)
                    .map(|n| n == pat_name)
                    .unwrap_or(false);
            }
            return false;
        }
        true
    }

    /// Returns the number of entities (nodes) in the graph.
    pub fn entity_count(&self) -> usize {
        self.entities.len()
    }

    /// Returns the total number of relations (edges) in the graph.
    /// Reads from the streaming layer (post stage 2c part 2 final
    /// migration); equivalent to `streaming_edge_count`.
    pub fn relation_count(&self) -> usize {
        self.streaming_edge_count()
    }

    /// Adds an entity to the graph.
    pub fn add_entity(&mut self, entity: Entity) -> Result<(), GraphError> {
        let sid = self.interner.intern(&entity.id);
        if self.entities.contains_key(&sid) {
            return Err(GraphError::DuplicateEntity(entity.id.clone()));
        }
        self.type_index
            .entry(entity.entity_type.clone())
            .or_default()
            .insert(sid);
        self.set_entity_type_tag(sid, &entity.entity_type);
        self.entities.insert(sid, entity);
        self.reverse_adj.entry(sid).or_default();
        self.bump_mutation_version();
        Ok(())
    }

    /// Adds a relation (directed edge) to the graph.
    pub fn add_relation(&mut self, relation: Relation) -> Result<(), GraphError> {
        let src_sid = self
            .interner
            .get(&relation.source_id)
            .ok_or_else(|| GraphError::EntityNotFound(relation.source_id.clone()))?;
        let dst_sid = self
            .interner
            .get(&relation.dest_id)
            .ok_or_else(|| GraphError::EntityNotFound(relation.dest_id.clone()))?;

        if !self.entities.contains_key(&src_sid) {
            return Err(GraphError::EntityNotFound(relation.source_id.clone()));
        }
        if !self.entities.contains_key(&dst_sid) {
            return Err(GraphError::EntityNotFound(relation.dest_id.clone()));
        }

        if let Some(ref mut scorer) = self.anomaly_scorer {
            scorer.observe_entity(&relation.source_id, relation.timestamp);
            scorer.observe_entity(&relation.dest_id, relation.timestamp);
            scorer.observe_edge(&relation.source_id, &relation.dest_id);
        }

        // meta_store.append precedes the fallible push_to_streaming below; on a
        // spill failure the offset is orphaned (unreferenced) but harmless — the
        // store is append-only and non-structural. Intentional C3a trade-off.
        let meta_offset = self.append_edge_metadata(&relation.rel_type, &relation.metadata);
        let ds_tag = self.intern_dataset_tag(relation.dataset_id.as_deref());
        let compact = CompactRelation {
            source_sid: src_sid,
            dest_sid: dst_sid,
            rel_type_tag: relation.rel_type.to_u8(),
            timestamp: relation.timestamp,
            metadata_offset: meta_offset,
            dataset_tag: ds_tag,
            ingested_at_delta: encode_ingested_at(now_seconds()),
        };

        // Fallible push first: a spill failure must not leave a dangling reverse edge (C3a).
        self.push_to_streaming(&compact)?;
        self.reverse_adj.entry(dst_sid).or_default().push(src_sid);
        self.on_streaming_edge_appended(src_sid, dst_sid);
        Ok(())
    }

    /// Shared post-append hook: invalidate cached snapshot, try incremental
    /// NLF/k-hop updates, bump mutation version. Used by `add_relation` and
    /// `insert_raw_events` so live-tail appends stay matcher-visible.
    fn on_streaming_edge_appended(&mut self, src_sid: StrId, dst_sid: StrId) {
        self.edges_sorted = false;
        self.streaming_snapshot = std::sync::OnceLock::new();

        // C2 fix: incremental deltas read BASE neighbors only (via
        // `streaming.with_neighbors` / `neighbors_arc`), which does NOT
        // include the post-finalize TAIL buffer. Any delta applied after
        // finalize would silently produce a stale index that misses every
        // tail edge. The only safe action is a full invalidate-and-rebuild:
        // drop the OnceLocks so the next hunt pays the O(E) rebuild cost
        // against the complete base+tail graph.
        //
        // Pre-finalize appends still reach the incremental path below because
        // all edges are in the base at that point and deltas are sound. NOTE:
        // the lazy NLF/k-hop indexes are only built on the first hunt (which
        // requires a finalized graph), so the incremental delta path below is
        // currently dormant in production. Track H revisits it with a
        // tail-aware delta; until then, do not assume it runs.
        if self.streaming.is_finalized() {
            if self.nlf.get().is_some() {
                self.nlf = std::sync::OnceLock::new();
            }
            if self.khop_reach.get().is_some() {
                self.khop_reach = std::sync::OnceLock::new();
            }
            self.bump_mutation_version();
            return;
        }

        let dst_tag = self
            .entity_type_tags
            .get(dst_sid.index())
            .copied()
            .unwrap_or(crate::nlf::NLF_TYPE_COUNT as u8);

        let mut nlf_invalidate = true;
        if let Some(nlf) = self.nlf.get_mut() {
            if nlf.try_record_edge(src_sid, dst_tag) {
                nlf_invalidate = false;
            }
        } else if self.nlf.get().is_none() {
            nlf_invalidate = false;
        }
        if nlf_invalidate {
            self.nlf = std::sync::OnceLock::new();
        }

        const KHOP_DELTA_BUDGET: usize = 100_000;
        let mut khop_invalidate = true;
        let streaming_handle = self.streaming.clone();
        let reverse_adj_view: &ahash::HashMap<StrId, Vec<StrId>> = &self.reverse_adj;
        let reverse_adj_ptr: *const ahash::HashMap<StrId, Vec<StrId>> = reverse_adj_view;
        if let Some(reach) = self.khop_reach.get_mut() {
            let reverse_adj_safe: &ahash::HashMap<StrId, Vec<StrId>> =
                unsafe { &*reverse_adj_ptr };
            if reach.try_record_edge_delta(
                src_sid,
                &streaming_handle,
                reverse_adj_safe,
                KHOP_DELTA_BUDGET,
            ) {
                khop_invalidate = false;
            }
        } else if self.khop_reach.get().is_none() {
            khop_invalidate = false;
        }
        if khop_invalidate {
            self.khop_reach = std::sync::OnceLock::new();
        }
        self.bump_mutation_version();
    }

    /// Whether the streaming backend has finalized base neighbor lists.
    pub fn streaming_is_finalized(&self) -> bool {
        self.streaming.is_finalized()
    }

    /// Edges appended after finalize (tail buffer only).
    pub fn streaming_tail_edge_count(&self) -> u64 {
        self.streaming.tail_edge_count()
    }

    /// Coverage metadata for hunts during live-tail ingest.
    pub fn live_tail_coverage(&self, phase: &str) -> Option<crate::analytics::LiveTailCoverage> {
        if phase != "live_tail" {
            return None;
        }
        let tail = self.streaming.tail_edge_count();
        if tail == 0 {
            return None;
        }
        let total = self.streaming_edge_count().max(1) as f64;
        let index_coverage = 1.0 - (tail as f64 / total).min(0.5);
        Some(crate::analytics::LiveTailCoverage {
            phase: phase.to_string(),
            tail_edge_count: tail,
            index_coverage,
        })
    }

    /// Gets or creates a dataset tag index.
    fn intern_dataset_tag(&mut self, dataset_id: Option<&str>) -> u16 {
        match dataset_id {
            None => 0,
            Some(id) => {
                if let Some(pos) = self.dataset_tags.iter().position(|t| &**t == id) {
                    pos as u16
                } else {
                    let idx = self.dataset_tags.len() as u16;
                    self.dataset_tags.push(Arc::from(id));
                    idx
                }
            }
        }
    }

    /// Resolves a dataset tag to its string.
    pub fn resolve_dataset_tag(&self, tag: u16) -> Option<Arc<str>> {
        if tag == 0 {
            None
        } else {
            self.dataset_tags.get(tag as usize).cloned()
        }
    }

    /// Append edge metadata, injecting the reserved `_rel_type` key when the
    /// relation is a custom `Other(name)` (whose name the 1-byte tag can't
    /// preserve). Built-in types inject nothing — no clone on the common path.
    ///
    /// NOTE: `_rel_type` is a reserved internal key — it is stripped by
    /// `materialize_relation`, but raw metadata readers (DSL edge predicates)
    /// can see it. The `_` prefix marks it as not-a-real-field.
    fn append_edge_metadata(
        &mut self,
        rel_type: &crate::types::RelationType,
        metadata: &std::collections::HashMap<String, String>,
    ) -> u64 {
        if let crate::types::RelationType::Other(name) = rel_type {
            if !name.is_empty() {
                let mut m = metadata.clone();
                m.insert("_rel_type".to_string(), name.clone());
                return self.meta_store.append(&m);
            }
        }
        self.meta_store.append(metadata)
    }

    /// Materializes a CompactRelation into a full Relation.
    /// Recovers the `Other(name)` from the `_rel_type` metadata key (if
    /// present) and strips that internal key before returning.
    pub fn materialize_relation(&self, compact: &CompactRelation) -> Relation {
        let mut metadata = self.meta_store.get(compact.metadata_offset);
        let rel_type = match metadata.remove("_rel_type") {
            Some(name) => crate::types::RelationType::Other(name),
            None => compact.rel_type(),
        };
        Relation {
            source_id: self.interner.resolve(compact.source_sid).to_string(),
            dest_id: self.interner.resolve(compact.dest_sid).to_string(),
            rel_type,
            timestamp: compact.timestamp,
            metadata,
            dataset_id: self.resolve_dataset_tag(compact.dataset_tag),
        }
    }

    /// Resolve a relation's display name from a CompactRelation, recovering
    /// custom `Other(name)` types from the `_rel_type` metadata key (which the
    /// 1-byte tag cannot hold). Built-in types come straight from the tag.
    ///
    /// This is the DRY helper for all export/display paths that need the
    /// human-readable rel-type string — use it instead of `format!("{}", compact.rel_type())`.
    pub fn resolve_rel_type_name(&self, compact: &CompactRelation) -> String {
        self.resolve_rel_type_name_raw(compact.rel_type_tag, compact.metadata_offset)
    }

    /// Same recovery logic as [`resolve_rel_type_name`] but accepts raw tag +
    /// metadata offset. Used by read paths that hold a `StreamEdge` rather than
    /// a `CompactRelation` (both carry the same two fields).
    pub fn resolve_rel_type_name_raw(&self, rel_type_tag: u8, metadata_offset: u64) -> String {
        if rel_type_tag == crate::types::RelationType::Other(String::new()).to_u8() {
            let meta = self.meta_store.get(metadata_offset);
            if let Some(name) = meta.get("_rel_type") {
                if !name.is_empty() {
                    return name.clone();
                }
            }
        }
        format!("{}", crate::types::RelationType::from_u8(rel_type_tag))
    }

    /// Retrieves an entity by its ID.
    pub fn get_entity(&self, id: &str) -> Option<&Entity> {
        let sid = self.interner.get(id)?;
        self.entities.get(&sid)
    }

    /// Retrieves a mutable reference to an entity by its ID.
    pub fn get_entity_mut(&mut self, id: &str) -> Option<&mut Entity> {
        let sid = self.interner.get(id)?;
        self.entities.get_mut(&sid)
    }

    /// Retrieves all outgoing relations from a given entity (materialized).
    pub fn get_relations(&self, source_id: &str) -> Vec<Relation> {
        let Some(sid) = self.interner.get(source_id) else {
            return Vec::new();
        };
        let arc = match self.streaming.neighbors_arc(sid) {
            Some(a) => a,
            None => return Vec::new(),
        };
        let guard = arc.read();
        guard
            .as_slice()
            .iter()
            .map(|edge| {
                // SAFETY: layout-identical with CompactRelation.
                let compact: CompactRelation = unsafe {
                    std::ptr::read(edge as *const _ as *const CompactRelation)
                };
                self.materialize_relation(&compact)
            })
            .collect()
    }

    /// Retrieves outgoing relations of a specific type from a given entity (materialized).
    /// NOTE: returns ALL outgoing edges; callers must filter by rel_type themselves.
    pub fn get_relations_by_type(
        &self,
        source_id: &str,
        _rel_type: &RelationType,
    ) -> Vec<Relation> {
        self.get_relations(source_id)
    }

    /// Returns compact outgoing edges by string ID. Owned Vec —
    /// see `get_relations_by_sid` for the rationale.
    pub fn get_compact_relations(&self, source_id: &str) -> Vec<CompactRelation> {
        let Some(sid) = self.interner.get(source_id) else {
            return Vec::new();
        };
        self.get_relations_by_sid(sid)
    }

    /// Returns the StrIds of entities that have edges pointing TO the given entity.
    /// This is the public API for reverse adjacency lookup.
    pub fn get_reverse_source_sids(&self, id: &str) -> &[StrId] {
        self.interner
            .get(id)
            .and_then(|sid| self.reverse_adj.get(&sid))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Materializes the outgoing-edge slice for `sid` as an owned
    /// `Vec<CompactRelation>` from the streaming layer. Stage 2c
    /// part 2 final migration — every hot-path matcher caller was
    /// already moved to `streaming.neighbors_arc(sid)` directly;
    /// the remaining callers (test fixtures, anomaly path-walk,
    /// public introspection APIs) get an owned Vec so the slice
    /// lifetime escapes the per-vertex read guard. The byte copy
    /// is a transmute (`StreamEdge` is layout-compatible with
    /// `CompactRelation`).
    pub fn get_relations_by_sid(&self, sid: StrId) -> Vec<CompactRelation> {
        let arc = match self.streaming.neighbors_arc(sid) {
            Some(a) => a,
            None => return Vec::new(),
        };
        let guard = arc.read();
        let stream_slice = guard.as_slice();
        // SAFETY: StreamEdge and CompactRelation share #[repr(C)]
        // with identical field order and types. Slice transmute
        // -> owned Vec by element copy.
        let compact_slice: &[CompactRelation] = unsafe {
            std::slice::from_raw_parts(
                stream_slice.as_ptr() as *const CompactRelation,
                stream_slice.len(),
            )
        };
        compact_slice.to_vec()
    }

    /// L3 stage 2c part 2 — streaming-side edge count. Replaces
    /// `edge_store.len()` for consumers that only need the running
    /// total (relation count, schema-cache fingerprint). Walks the
    /// streaming `for_each_edge` once. O(E).
    pub fn streaming_edge_count(&self) -> usize {
        use crate::streaming::StreamingGraphBackend;
        self.streaming.edge_count()
    }

    /// Lazy lock-free snapshot of the streaming outer table.
    /// First call after a finalize/ingest builds the snapshot;
    /// subsequent calls return the cached reference. Reset to
    /// fresh `OnceLock::new()` by `add_relation` and
    /// `sort_edges_by_timestamp` so post-mutation matchers
    /// re-snapshot against the new state.
    ///
    /// The matcher hot path reads via this so the per-frame
    /// `streaming.neighbors_arc(sid)` (which takes an outer-table
    /// read lock each call) collapses to a single snapshot
    /// `HashMap.get` per frame.
    #[inline]
    pub fn streaming_snapshot(&self) -> &crate::streaming::FrozenSnapshot {
        self.streaming_snapshot
            .get_or_init(|| self.streaming.freeze())
    }

    /// Internal helper — push a `CompactRelation` into the streaming
    /// backend. Used by every ingest path (`add_relation`,
    /// `add_relations_batch`, `replay_relations`, `compact_before`'s
    /// rebuild, `remove_entities_and_relations_by_dataset`'s rebuild)
    /// so the streaming write happens in one place. Reuses the
    /// `#[repr(C)]` layout-identity between `CompactRelation` and
    /// `StreamEdge` to byte-copy without per-field translation.
    #[inline]
    fn push_to_streaming(&self, compact: &CompactRelation) -> Result<(), GraphError> {
        // SAFETY: CompactRelation and StreamEdge are both
        // #[repr(C)] with identical field order and types.
        let edge: crate::streaming::StreamEdge = unsafe {
            std::ptr::read(compact as *const _ as *const crate::streaming::StreamEdge)
        };
        self.streaming
            .append_edge_checked(compact.source_sid, edge)
    }

    /// Internal: get compact relations by StrId and type.
    /// Returns ALL outgoing edges; callers filter by type in their loops.
    #[inline]
    #[allow(dead_code)]
    fn get_relations_by_type_sid(
        &self,
        sid: StrId,
        _rel_type: &RelationType,
    ) -> Vec<CompactRelation> {
        self.get_relations_by_sid(sid)
    }

    /// Returns entity type names that exist in the graph.
    pub fn entity_types_in_graph(&self) -> Vec<String> {
        let mut names: Vec<String> = self.type_index.keys().map(|t| format!("{}", t)).collect();
        names.sort();
        names
    }

    /// Returns (type_name, count) for each entity type present in the graph.
    pub fn entity_type_counts(&self) -> Vec<(String, usize)> {
        let mut v: Vec<(String, usize)> = self
            .type_index
            .iter()
            .map(|(k, set)| (format!("{}", k), set.len()))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    /// Returns all entity IDs of the given type, or None if not in graph.
    pub fn entity_ids_for_type(&self, entity_type: &EntityType) -> Option<Vec<String>> {
        self.type_index.get(entity_type).map(|set| {
            set.iter()
                .map(|&sid| self.interner.resolve(sid).to_string())
                .collect()
        })
    }

    /// Returns entity type names among neighbours of the given node.
    pub fn entity_types_of_neighbours(&self, node_id: &str) -> Vec<String> {
        let mut types_set = HashSet::new();
        let Some(sid) = self.interner.get(node_id) else {
            return Vec::new();
        };
        if let Some(arc) = self.streaming.neighbors_arc(sid) {
            let guard = arc.read();
            for edge in guard.as_slice() {
                if let Some(e) = self.entities.get(&edge.dest_sid) {
                    types_set.insert(format!("{}", e.entity_type));
                }
            }
        }
        if let Some(sources) = self.reverse_adj.get(&sid) {
            for &source_sid in sources {
                if let Some(e) = self.entities.get(&source_sid) {
                    types_set.insert(format!("{}", e.entity_type));
                }
            }
        }
        let mut names: Vec<String> = types_set.into_iter().collect();
        names.sort();
        names
    }

    /// Returns compact edges for a hypothesis step: owned Vec —
    /// matcher hot-path callers were migrated off this in stage
    /// 2c part 2; only the naive baseline DFS (verification) and
    /// a couple of test fixtures still call it.
    #[inline]
    #[allow(dead_code)]
    fn get_edges_for_step_sid(
        &self,
        sid: StrId,
        step: &crate::hypothesis::HypothesisStep,
    ) -> Vec<CompactRelation> {
        if step.relation_type != RelationType::Any {
            self.get_relations_by_type_sid(sid, &step.relation_type)
        } else {
            self.get_relations_by_sid(sid)
        }
    }

    /// Returns materialized edges for a hypothesis step using string ID.
    #[inline]
    #[allow(dead_code)]
    fn get_edges_for_step(
        &self,
        node_id: &str,
        step: &crate::hypothesis::HypothesisStep,
    ) -> Vec<Relation> {
        if step.relation_type != RelationType::Any {
            self.get_relations_by_type(node_id, &step.relation_type)
        } else {
            self.get_relations(node_id)
        }
    }

    /// Sorts every per-vertex neighbor list in the streaming
    /// backend by timestamp so the matcher's `partition_point`
    /// binary search bounds time windows in O(log d) per frame.
    /// Call once after ingestion completes. Subsequent calls are
    /// no-ops.
    pub fn sort_edges_by_timestamp(&mut self) -> Result<(), GraphError> {
        if self.edges_sorted {
            return Ok(());
        }
        // Parse the env-var into an explicit opt-in/opt-out (Some(true/false)),
        // or None meaning "use the size threshold".  Keep =0 as a one-release
        // escape hatch in case of rayon-scheduler regressions.
        let env_override: Option<bool> = match std::env::var("GRAPHHUNTER_PARALLEL_FINALIZE") {
            Ok(v) if v == "1" || v.eq_ignore_ascii_case("true") => Some(true),
            Ok(v) if v == "0" || v.eq_ignore_ascii_case("false") => Some(false),
            Ok(v) => {
                // Unrecognized value: fall through to the size threshold rather
                // than silently forcing sequential (which would mask a typo like
                // `=tru` on a large graph the user meant to parallelize).
                eprintln!(
                    "GraphHunter: GRAPHHUNTER_PARALLEL_FINALIZE=\"{v}\" not recognized (expected 1/0/true/false); using size-threshold default"
                );
                None
            }
            Err(_) => None,
        };
        use crate::streaming::StreamingGraphBackend as _;
        let vcount = self.streaming.vertex_count();
        let ecount = self.streaming.edge_count();
        if should_finalize_parallel(vcount, ecount, env_override) {
            self.streaming.finalize_parallel();
        } else {
            self.streaming.finalize();
        }
        self.edges_sorted = true;
        // Heavy-logs #3.5: index builds (NLF + khop_reach) are
        // *lazy* now. Resetting the OnceLocks here ensures any
        // post-finalize matcher call rebuilds against the freshly
        // sorted edge layout. The build itself happens inside the
        // first `ensure_nlf` / `ensure_khop_reach` call — typically
        // the first hunt — so opening a 28 GB session is bounded
        // by the streaming reader, not by the multi-GB index
        // build.
        self.nlf = std::sync::OnceLock::new();
        self.khop_reach = std::sync::OnceLock::new();
        // The streaming outer-table snapshot is built lazily on
        // first matcher invocation; reset so the next hunt sees
        // the freshly-sorted vertex set.
        self.streaming_snapshot = std::sync::OnceLock::new();
        Ok(())
    }

    /// Searches for paths matching a temporal hypothesis pattern.
    /// For best performance, call `sort_edges_by_timestamp()` after ingestion.
    /// The search still works without sorting but binary-search optimizations are disabled.
    pub fn search_temporal_pattern(
        &self,
        hypothesis: &Hypothesis,
        time_window: Option<(i64, i64)>,
        max_results: Option<usize>,
    ) -> Result<(Vec<HuntResult>, bool), GraphError> {
        hypothesis
            .validate()
            .map_err(GraphError::InvalidHypothesis)?;

        // M1 — planner-driven dispatch. The shape-detection logic that
        // used to live inline (S3) now lives in `planner::plan`, which
        // honors both the legacy name-marker route
        // (`GRAPHHUNTER_K4_LFTJ=1` + `k4-clique` in the name) and the
        // new structural route (`GRAPHHUNTER_LFTJ_PLANNER=1` + a
        // homogeneous six-step hypothesis). HAVING/WITHIN compose
        // because the K4 entry point still calls `apply_aggregation`.
        // D1 stage 2 — cost-aware dispatch when GRAPHHUNTER_LFTJ_AUTO=1.
        // `plan_with_hints_lazy` consults graph stats only if AUTO
        // is on; otherwise it short-circuits to the legacy plan().
        // Skipping the graph walk on the default path saves O(V)
        // per-query overhead (~300 us at V=100K).
        match crate::planner::plan_with_hints_lazy(hypothesis, || {
            crate::planner::CostHints::from_graph(self)
        }) {
            crate::planner::DispatchPlan::TriangleLftj => {
                return self.search_temporal_pattern_triangle(
                    hypothesis,
                    time_window,
                    max_results,
                );
            }
            crate::planner::DispatchPlan::K4Lftj => {
                return self.search_temporal_pattern_k4_lftj(hypothesis, time_window, max_results);
            }
            crate::planner::DispatchPlan::K5Lftj => {
                return self.search_temporal_pattern_k5_lftj(hypothesis, time_window, max_results);
            }
            crate::planner::DispatchPlan::C6Lftj => {
                return self.search_temporal_pattern_c6_lftj(hypothesis, time_window, max_results);
            }
            crate::planner::DispatchPlan::Yannakakis => {
                let (paths, truncated) =
                    crate::yannakakis::search_temporal_pattern_yannakakis(
                        self,
                        hypothesis,
                        time_window,
                        max_results,
                    );
                let paths = self.apply_aggregation(paths, hypothesis);
                return Ok((paths, truncated));
            }
            crate::planner::DispatchPlan::DfsMatch => {}
        }

        let cap = max_results.unwrap_or(10_000);

        let first_step = &hypothesis.steps[0];
        let mut start_sids: Vec<StrId> = if first_step.origin_type == EntityType::Any {
            self.entities.keys().copied().collect()
        } else {
            self.type_index
                .get(&first_step.origin_type)
                .map(|ids| ids.iter().copied().collect())
                .unwrap_or_default()
        };

        // B2 — NLF prune: drop starts that can't satisfy the first step's
        // `dest_type` requirement. Skipped when the requirement is trivial
        // (Any / Other dest_type). Heavy-logs #3.5: NLF builds lazily on
        // first non-trivial query — this avoids paying the O(E) index
        // cost for queries that wouldn't use it.
        let nlf_req = crate::nlf::requirement_from_first_step(first_step);
        if self.edges_sorted && !crate::nlf::is_trivial(&nlf_req) {
            let nlf = self.ensure_nlf();
            start_sids.retain(|&sid| nlf.can_match(sid, &nlf_req));
        }

        // D5 — k-hop reachability prune: drop starts that cannot reach
        // a vertex of the hypothesis's *final* dest_type within MAX_DEPTH
        // hops. Multi-hop generalization of NLF — only meaningful when
        // the hypothesis is at least 2 steps deep, since NLF already
        // covers the 1-hop case. M2 — when a `time_window` is supplied,
        // additionally reject starts whose first-edge timestamps to the
        // required label can never fit inside the window. Heavy-logs
        // #3.5: also lazy-built.
        let khop_mask = crate::khop_reach::end_type_mask(hypothesis);
        if self.edges_sorted && !crate::khop_reach::is_trivial(khop_mask, hypothesis) {
            let reach = self.ensure_khop_reach();
            start_sids.retain(|&sid| reach.can_reach_in_window(sid, khop_mask, time_window));
        }

        // D2-lite — bidirectional semi-join. Runs the Yannakakis bottom-up
        // pass over the linear chain to drop start vertices that can't
        // reach the final-step type via the *required relation/type
        // sequence* (NLF only checks 1-hop labels; D5 only checks
        // type-reachability ignoring relations). Skipped for trivial
        // hypotheses (single-step or all-Any). Behind an env gate so
        // it can be A/B'd against the regular path.
        let semijoin_enabled = std::env::var("GRAPHHUNTER_SEMIJOIN")
            .map(|v| !(v == "0" || v.eq_ignore_ascii_case("false")))
            .unwrap_or(true);
        if semijoin_enabled && !crate::semijoin::is_trivial(hypothesis) {
            let mut cands = crate::semijoin::CandidateSets::seed(self, hypothesis);
            crate::semijoin::refine(self, hypothesis, &mut cands);
            crate::semijoin::filter_starts(&mut start_sids, &cands.candidates[0]);
        }

        // B9 — symmetry analysis. Computed once at query entry, applied
        // per-emission inside the DFS. For palindromic chains, halves
        // the result set by enforcing a canonical direction; no-op for
        // asymmetric chains (the common ATT&CK case).
        let symmetry_hint = crate::symmetry::analyze(hypothesis);

        let k = hypothesis.k_simplicity.max(1);
        let result_count = Arc::new(AtomicUsize::new(0));

        // Pre-size scratch buffers based on hypothesis depth.
        let depth = hypothesis.steps.len();
        let visit_cap = (depth * k).max(8);

        // Per-thread scratch state held in TLS so each rayon worker reuses
        // its `path`/`stack` across every start it processes. This
        // eliminates the per-start Vec allocations that used to dominate
        // non-saturation workloads. C0 dropped the visit_count HashMap
        // entirely — a linear scan over `path` is faster at depth ≤ 8.
        let _ = visit_cap;
        thread_local! {
            static DFS_SCRATCH: std::cell::RefCell<(
                DfsPath,
                Vec<DfsFrame>,
            )> = std::cell::RefCell::new((
                SmallVec::new(),
                Vec::new(),
            ));
        }
        let init_buffers = move |s: &mut (DfsPath, Vec<DfsFrame>)| {
            if s.0.capacity() < depth + 1 {
                s.0.reserve(depth + 1 - s.0.capacity());
            }
            if s.1.capacity() < depth + 1 {
                s.1.reserve(depth + 1);
            }
        };

        // C2 — AMAC interleaved DFS. Default ON; opt-out via
        // `GRAPHHUNTER_AMAC=0`. Processes starts in chunks of K
        // contexts that round-robin through the inner edge loop, with
        // cross-context prefetch on the next context's pending edge.
        // Result-set parity with the regular DFS is verified by tests.
        let amac_enabled = std::env::var("GRAPHHUNTER_AMAC")
            .map(|v| !(v == "0" || v.eq_ignore_ascii_case("false")))
            .unwrap_or(true);

        let results: Vec<HuntResult> = if amac_enabled && start_sids.len() >= 8 {
            let rc = Arc::clone(&result_count);
            const AMAC_K: usize = 8;
            start_sids
                .par_chunks(AMAC_K)
                .flat_map_iter(|chunk| {
                    let mut local_results: Vec<HuntResult> = Vec::new();
                    if rc.load(Ordering::Relaxed) >= cap {
                        return local_results;
                    }
                    self.dfs_match_amac_chunk(
                        chunk,
                        &hypothesis.steps,
                        time_window,
                        k,
                        cap,
                        &rc,
                        &mut local_results,
                        symmetry_hint,
                    );
                    local_results
                })
                .collect()
        } else if start_sids.len() >= 64 {
            let rc = Arc::clone(&result_count);
            // flat_map_iter is rayon's preferred shape for many small per-item
            // result lists — its parallel collect is more efficient than the
            // explicit fold/reduce we tried before.
            start_sids
                .par_iter()
                .flat_map_iter(|&start_sid| {
                    let mut local_results: Vec<HuntResult> = Vec::new();
                    if rc.load(Ordering::Relaxed) >= cap {
                        return local_results;
                    }
                    DFS_SCRATCH.with(|cell| {
                        let mut s = cell.borrow_mut();
                        init_buffers(&mut s);
                        let s_ref: &mut (DfsPath, Vec<DfsFrame>) = &mut *s;
                        self.dfs_match_iterative(
                            start_sid,
                            &hypothesis.steps,
                            time_window,
                            k,
                            cap,
                            &rc,
                            &mut local_results,
                            &mut s_ref.0,
                            &mut s_ref.1,
                            symmetry_hint,
                        );
                    });
                    local_results
                })
                .collect()
        } else {
            // Sequential branch: keep one scratch set on the stack and reuse it.
            let mut path: DfsPath = SmallVec::with_capacity(depth + 1);
            let mut stack: Vec<DfsFrame> = Vec::with_capacity(depth + 1);
            let mut results: Vec<HuntResult> = Vec::new();
            for &start_sid in &start_sids {
                if result_count.load(Ordering::Relaxed) >= cap {
                    break;
                }
                self.dfs_match_iterative(
                    start_sid,
                    &hypothesis.steps,
                    time_window,
                    k,
                    cap,
                    &result_count,
                    &mut results,
                    &mut path,
                    &mut stack,
                    symmetry_hint,
                );
            }
            results
        };

        let truncated = result_count.load(Ordering::Relaxed) >= cap;
        let results = self.apply_aggregation(results, hypothesis);
        Ok((results, truncated))
    }

    /// S3 — K4-clique LFTJ entry point. Builds the forward CSR trie +
    /// MinTimestampMap once, delegates enumeration to the rayon-parallel
    /// SIMD enumerator, then runs the regular `apply_aggregation` pass
    /// so HAVING/WITHIN compose with the fast-path. Time-window and cap
    /// semantics match `search_temporal_pattern`.
    pub fn search_temporal_pattern_k4_lftj(
        &self,
        hypothesis: &Hypothesis,
        time_window: Option<(i64, i64)>,
        max_results: Option<usize>,
    ) -> Result<(Vec<HuntResult>, bool), GraphError> {
        let trie = self.build_lftj_trie_for(hypothesis);
        let ts_map = crate::lftj_query::MinTimestampMap::build(self, &trie);
        self.search_temporal_pattern_k4_lftj_with_trie(
            hypothesis, &trie, &ts_map, time_window, max_results,
        )
    }

    /// D3 stage 1 — K4 LFTJ fast path with caller-supplied trie.
    /// `run_hunt_batch` uses this to build the forward trie + ts_map
    /// once per (graph, time_window) and reuse across every
    /// K4-routed hypothesis in the batch. At Sysmon-scale (V≈10^6,
    /// E≈10^7) trie build is ~100s of ms; sharing across N templates
    /// saves N-1 builds.
    pub fn search_temporal_pattern_k4_lftj_with_trie(
        &self,
        hypothesis: &Hypothesis,
        trie: &crate::lftj::MaterializedCsrTrie,
        ts_map: &crate::lftj_query::MinTimestampMap,
        time_window: Option<(i64, i64)>,
        max_results: Option<usize>,
    ) -> Result<(Vec<HuntResult>, bool), GraphError> {
        let cap = max_results.unwrap_or(10_000);
        let (t_lo, t_hi) = time_window.unwrap_or((i64::MIN, i64::MAX));
        let results = crate::lftj_query::enumerate_4cliques_lftj_simd_par(
            self, trie, ts_map, t_lo, t_hi, cap,
        );
        let truncated = results.len() >= cap;
        let results = self.apply_aggregation(results, hypothesis);
        Ok((results, truncated))
    }

    /// D1 stage 4 — directed 6-cycle LFTJ fast path. Builds both
    /// forward and reverse CSR tries (the cycle closure `f → a` is
    /// expressed as predecessors-of-`a`). Inner enumerator hits
    /// AGM bound `m^3` vs DFS's `O(m·deg^5·log d)` — the largest
    /// asymptotic gap in the D1 vertical stack. Canonical APT
    /// lateral-movement shape (User → Host → Host → User → Host →
    /// Host → cycle close).
    pub fn search_temporal_pattern_c6_lftj(
        &self,
        hypothesis: &Hypothesis,
        time_window: Option<(i64, i64)>,
        max_results: Option<usize>,
    ) -> Result<(Vec<HuntResult>, bool), GraphError> {
        let forward = self.build_lftj_trie_for(hypothesis);
        let reverse = self.build_lftj_reverse_trie_for(hypothesis);
        let ts_map = crate::lftj_query::MinTimestampMap::build(self, &forward);
        self.search_temporal_pattern_c6_lftj_with_trie(
            hypothesis, &forward, &reverse, &ts_map, time_window, max_results,
        )
    }

    /// D3 stage 1 — C6 LFTJ fast path with caller-supplied tries.
    /// C6 needs both forward and reverse tries (cycle closure
    /// expressed as predecessors-of-`a`). `run_hunt_batch` builds
    /// both once and reuses across every C6-routed hypothesis.
    pub fn search_temporal_pattern_c6_lftj_with_trie(
        &self,
        hypothesis: &Hypothesis,
        forward: &crate::lftj::MaterializedCsrTrie,
        reverse: &crate::lftj::MaterializedCsrTrie,
        ts_map: &crate::lftj_query::MinTimestampMap,
        time_window: Option<(i64, i64)>,
        max_results: Option<usize>,
    ) -> Result<(Vec<HuntResult>, bool), GraphError> {
        let cap = max_results.unwrap_or(10_000);
        let (t_lo, t_hi) = time_window.unwrap_or((i64::MIN, i64::MAX));
        let results = crate::lftj_query::enumerate_6cycles_lftj_simd_par(
            self, forward, reverse, ts_map, t_lo, t_hi, cap,
        );
        let truncated = results.len() >= cap;
        let results = self.apply_aggregation(results, hypothesis);
        Ok((results, truncated))
    }

    /// D1 stage 3 — K5-clique LFTJ fast path. Mirrors the K4 entry
    /// point: same trie + MinTimestampMap, inner enumerator at AGM
    /// bound `m^{5/2}` vs DFS's `O(m·deg^4)`. Activated when the
    /// planner detects a homogeneous 10-step hypothesis or the name
    /// marker `k5-clique`.
    pub fn search_temporal_pattern_k5_lftj(
        &self,
        hypothesis: &Hypothesis,
        time_window: Option<(i64, i64)>,
        max_results: Option<usize>,
    ) -> Result<(Vec<HuntResult>, bool), GraphError> {
        let trie = self.build_lftj_trie_for(hypothesis);
        let ts_map = crate::lftj_query::MinTimestampMap::build(self, &trie);
        self.search_temporal_pattern_k5_lftj_with_trie(
            hypothesis, &trie, &ts_map, time_window, max_results,
        )
    }

    /// D3 stage 1 — K5 LFTJ fast path with caller-supplied trie.
    pub fn search_temporal_pattern_k5_lftj_with_trie(
        &self,
        hypothesis: &Hypothesis,
        trie: &crate::lftj::MaterializedCsrTrie,
        ts_map: &crate::lftj_query::MinTimestampMap,
        time_window: Option<(i64, i64)>,
        max_results: Option<usize>,
    ) -> Result<(Vec<HuntResult>, bool), GraphError> {
        let cap = max_results.unwrap_or(10_000);
        let (t_lo, t_hi) = time_window.unwrap_or((i64::MIN, i64::MAX));
        let results = crate::lftj_query::enumerate_5cliques_lftj_simd_par(
            self, trie, ts_map, t_lo, t_hi, cap,
        );
        let truncated = results.len() >= cap;
        let results = self.apply_aggregation(results, hypothesis);
        Ok((results, truncated))
    }

    /// D1 stage 1 — triangle (3-clique) LFTJ fast path. Same trie +
    /// MinTimestampMap as the K4 path; the inner enumerator wins
    /// asymptotically over DFS at AGM bound `m^{1.5}` vs DFS's
    /// `O(m·deg^2)`. Used when the planner detects a homogeneous
    /// 3-step hypothesis or the name marker `triangle`/`3-clique`.
    pub fn search_temporal_pattern_triangle(
        &self,
        hypothesis: &Hypothesis,
        time_window: Option<(i64, i64)>,
        max_results: Option<usize>,
    ) -> Result<(Vec<HuntResult>, bool), GraphError> {
        let trie = self.build_lftj_trie_for(hypothesis);
        let ts_map = crate::lftj_query::MinTimestampMap::build(self, &trie);
        self.search_temporal_pattern_triangle_with_trie(
            hypothesis, &trie, &ts_map, time_window, max_results,
        )
    }

    /// D3 stage 1 — triangle LFTJ fast path with caller-supplied trie.
    pub fn search_temporal_pattern_triangle_with_trie(
        &self,
        hypothesis: &Hypothesis,
        trie: &crate::lftj::MaterializedCsrTrie,
        ts_map: &crate::lftj_query::MinTimestampMap,
        time_window: Option<(i64, i64)>,
        max_results: Option<usize>,
    ) -> Result<(Vec<HuntResult>, bool), GraphError> {
        let cap = max_results.unwrap_or(10_000);
        let (t_lo, t_hi) = time_window.unwrap_or((i64::MIN, i64::MAX));
        let results = crate::lftj_query::enumerate_triangles_lftj_simd_window(
            self, trie, ts_map, t_lo, t_hi, cap,
        );
        let truncated = results.len() >= cap;
        let results = self.apply_aggregation(results, hypothesis);
        Ok((results, truncated))
    }

    /// Type-aware LFTJ trie builder. When the hypothesis is a
    /// homogeneous shape (all steps share concrete `relation_type`
    /// and `origin_type == dest_type`), builds a trie filtered to
    /// edges of that (rel_type, vertex_type) pair so the LFTJ
    /// enumerators don't pick up edges of other types. When the
    /// hypothesis is heterogeneous or carries wildcards / Other
    /// (the name-marker dispatch path), falls back to the
    /// type-blind `MaterializedCsrTrie::build`.
    ///
    /// Note that the caller already knows the hypothesis routes
    /// to LFTJ — this helper only decides whether the trie should
    /// be filtered, not whether LFTJ applies.
    pub fn build_lftj_trie_for(
        &self,
        hypothesis: &Hypothesis,
    ) -> crate::lftj::MaterializedCsrTrie {
        if let Some((rel_tag, ent_tag)) = self.homogeneous_lftj_signature(hypothesis) {
            crate::lftj::MaterializedCsrTrie::build_filtered(self, |src_sid, edge| {
                if edge.rel_type_tag != rel_tag {
                    return false;
                }
                let src_ok = self
                    .entity_type_tags
                    .get(src_sid.index())
                    .copied()
                    .map(|t| t == ent_tag)
                    .unwrap_or(false);
                if !src_ok {
                    return false;
                }
                self.entity_type_tags
                    .get(edge.dest_sid.index())
                    .copied()
                    .map(|t| t == ent_tag)
                    .unwrap_or(false)
            })
        } else {
            crate::lftj::MaterializedCsrTrie::build(self)
        }
    }

    /// Type-aware reverse-trie builder for cyclic shapes that need
    /// the predecessor view (today: C6). Filtered to the same
    /// (rel_type, vertex_type) signature as the forward trie so
    /// the cycle-closure intersect doesn't pull in mismatched edges.
    pub fn build_lftj_reverse_trie_for(
        &self,
        hypothesis: &Hypothesis,
    ) -> crate::lftj::MaterializedCsrTrie {
        // The reverse trie groups by destination, but the rel_type
        // and vertex-type filter is symmetric — both endpoints must
        // be the homogeneous vertex type, and the edge type must
        // match. Use build_reverse_filtered if it exists; otherwise
        // build the reverse from a filtered forward by swapping the
        // input. Cleanest path: add a dedicated build_reverse_filtered.
        if let Some((rel_tag, ent_tag)) = self.homogeneous_lftj_signature(hypothesis) {
            crate::lftj::MaterializedCsrTrie::build_reverse_filtered(self, |src_sid, edge| {
                if edge.rel_type_tag != rel_tag {
                    return false;
                }
                let src_ok = self
                    .entity_type_tags
                    .get(src_sid.index())
                    .copied()
                    .map(|t| t == ent_tag)
                    .unwrap_or(false);
                if !src_ok {
                    return false;
                }
                self.entity_type_tags
                    .get(edge.dest_sid.index())
                    .copied()
                    .map(|t| t == ent_tag)
                    .unwrap_or(false)
            })
        } else {
            crate::lftj::MaterializedCsrTrie::build_reverse(self)
        }
    }

    /// Returns `Some((rel_type_tag, vertex_type_tag))` when the
    /// hypothesis is structurally a homogeneous shape — every step
    /// shares the same concrete `relation_type` and the same
    /// `origin_type == dest_type`. Returns `None` otherwise (mixed
    /// types, wildcards, `Other(_)`, name-marker-only paths). The
    /// LFTJ trie builders use this to decide whether to filter.
    /// Public so the API layer can use it as a cache key (D3 stage 4).
    pub fn homogeneous_lftj_signature(&self, hypothesis: &Hypothesis) -> Option<(u8, u8)> {
        let steps = &hypothesis.steps;
        if steps.is_empty() {
            return None;
        }
        let first = &steps[0];
        if matches!(
            first.relation_type,
            crate::types::RelationType::Any | crate::types::RelationType::Other(_)
        ) {
            return None;
        }
        if matches!(
            first.origin_type,
            EntityType::Any | EntityType::Other(_)
        ) {
            return None;
        }
        if first.origin_type != first.dest_type {
            return None;
        }
        let all_match = steps.iter().all(|s| {
            s.relation_type == first.relation_type
                && s.origin_type == first.origin_type
                && s.dest_type == first.dest_type
        });
        if !all_match {
            return None;
        }
        Some((first.relation_type.to_u8(), first.origin_type.to_u8()))
    }

    /// Apply `HAVING` and `WITHIN` clauses to the raw result set. A no-op
    /// when the hypothesis has neither — callers don't need to guard.
    ///
    /// `WITHIN N` drops any individual path whose edge-timestamp span
    /// exceeds `N` seconds. `HAVING count(distinct col) >= N` groups the
    /// remaining paths by their first node and keeps only groups meeting
    /// the threshold. This is where Graph Hunter earns the right to call
    /// itself a behavior analyzer, not just a pattern matcher.
    pub fn apply_aggregation(
        &self,
        paths: Vec<crate::graph::HuntResult>,
        hypothesis: &Hypothesis,
    ) -> Vec<crate::graph::HuntResult> {
        if hypothesis.window_seconds.is_none() && hypothesis.aggregations.is_empty() {
            return paths;
        }

        // Phase 1: filter individual paths by WITHIN.
        let filtered: Vec<crate::graph::HuntResult> =
            if let Some(window) = hypothesis.window_seconds {
                paths
                    .into_iter()
                    .filter(|p| {
                        let span = self.path_time_span(p);
                        span <= window
                    })
                    .collect()
            } else {
                paths
            };

        if hypothesis.aggregations.is_empty() {
            return filtered;
        }

        // Phase 2: group by first node, apply each HAVING clause.
        use std::collections::HashMap;
        let mut groups: HashMap<std::sync::Arc<str>, Vec<crate::graph::HuntResult>> =
            HashMap::new();
        for p in filtered {
            if p.is_empty() {
                continue;
            }
            groups.entry(p[0].clone()).or_default().push(p);
        }
        // Resolve `Named(x)` bindings to a path index ONCE before the
        // hot loop. For each binding, walk hypothesis.steps finding the
        // first `origin_binding` or `dest_binding` match; the index in
        // the chain is path[index_in_chain] — origin_binding on step k
        // refers to path[k], dest_binding on step k refers to path[k+1].
        let resolve_named_index = |binding: &str| -> Option<usize> {
            for (k, step) in hypothesis.steps.iter().enumerate() {
                if step.origin_binding.as_deref() == Some(binding) {
                    return Some(k);
                }
                if step.dest_binding.as_deref() == Some(binding) {
                    return Some(k + 1);
                }
            }
            None
        };

        let mut out = Vec::new();
        for (_anchor, group) in groups {
            let keep = hypothesis.aggregations.iter().all(|agg| {
                let distinct: std::collections::HashSet<&str> = match &agg.column {
                    crate::hypothesis::AggColumn::First => group
                        .iter()
                        .filter_map(|p| p.first().map(|s| &**s))
                        .collect(),
                    crate::hypothesis::AggColumn::Last => group
                        .iter()
                        .filter_map(|p| p.last().map(|s| &**s))
                        .collect(),
                    crate::hypothesis::AggColumn::Named(name) => {
                        match resolve_named_index(name) {
                            Some(idx) => group
                                .iter()
                                .filter_map(|p| p.get(idx).map(|s| &**s))
                                .collect(),
                            // Binding declared nowhere — treat the agg as
                            // always-failing rather than silently matching.
                            None => std::collections::HashSet::new(),
                        }
                    }
                };
                distinct.len() >= agg.min_distinct
            });
            if keep {
                out.extend(group);
            }
        }
        out
    }

    /// Compute the time span (max_ts - min_ts) across all edges used by a path.
    /// 0 if the path has no edges or timestamps are missing. Used only by
    /// the aggregation path, so the per-path scan is acceptable cost.
    fn path_time_span(&self, path: &crate::graph::HuntResult) -> i64 {
        let mut min_ts = i64::MAX;
        let mut max_ts = i64::MIN;
        for i in 0..path.len().saturating_sub(1) {
            let dest_sid = self.interner.get(&path[i + 1]);
            for compact in self.get_compact_relations(&path[i]) {
                if Some(compact.dest_sid) == dest_sid && compact.timestamp != 0 {
                    if compact.timestamp < min_ts {
                        min_ts = compact.timestamp;
                    }
                    if compact.timestamp > max_ts {
                        max_ts = compact.timestamp;
                    }
                }
            }
        }
        if min_ts == i64::MAX || max_ts == i64::MIN {
            0
        } else {
            max_ts - min_ts
        }
    }

    /// Anomaly-guided smart search: uses a top-K min-heap to prune low-anomaly
    /// branches during DFS, eliminating the dependency on the cap for performance.
    ///
    /// When the scorer is finalized, this replaces the brute-force cap-based search
    /// with an A*-like admissible heuristic: it assumes future steps could score 1.0
    /// (max anomaly), so it never prunes a path that *could* end up in the top-K.
    ///
    /// Falls back to `search_temporal_pattern` if no scorer is available.
    pub fn search_temporal_pattern_smart(
        &self,
        hypothesis: &Hypothesis,
        time_window: Option<(i64, i64)>,
        top_k: usize,
    ) -> Result<(Vec<HuntResult>, bool), GraphError> {
        // Fallback if no finalized scorer
        let scorer_ready = self
            .anomaly_scorer
            .as_ref()
            .map(|s| s.is_finalized())
            .unwrap_or(false);
        if !scorer_ready {
            return self.search_temporal_pattern(hypothesis, time_window, Some(top_k));
        }

        hypothesis
            .validate()
            .map_err(GraphError::InvalidHypothesis)?;

        let first_step = &hypothesis.steps[0];
        let mut start_sids: Vec<StrId> = if first_step.origin_type == EntityType::Any {
            self.entities.keys().copied().collect()
        } else {
            self.type_index
                .get(&first_step.origin_type)
                .map(|ids| ids.iter().copied().collect())
                .unwrap_or_default()
        };

        let nlf_req = crate::nlf::requirement_from_first_step(first_step);
        if self.edges_sorted && !crate::nlf::is_trivial(&nlf_req) {
            let nlf = self.ensure_nlf();
            start_sids.retain(|&sid| nlf.can_match(sid, &nlf_req));
        }

        let k = hypothesis.k_simplicity.max(1);
        let total_steps = hypothesis.steps.len();
        let depth = hypothesis.steps.len();
        let visit_cap = (depth * k).max(8);

        use std::cmp::Reverse;
        use std::collections::BinaryHeap;

        // Per-thread state used by both branches: a top-K min-heap plus
        // two DFS scratch buffers. C0 dropped the visit_count HashMap.
        let _ = visit_cap;
        type SmartChunk = (
            SmartHeap,
            Vec<StrId>,
            Vec<AnomalyFrame>,
        );
        let init_chunk = || -> SmartChunk {
            (
                BinaryHeap::with_capacity(top_k + 1),
                Vec::with_capacity(depth + 1),
                Vec::with_capacity(depth + 1),
            )
        };

        // Merges two top-K heaps into the larger one, popping the lowest
        // scores until only `top_k` entries remain. Cost is O((|a|+|b|) log K).
        let merge_into_topk = |mut a: SmartHeap, b: SmartHeap, top_k: usize| -> SmartHeap {
            // Drain `b` into `a`, keeping `a` bounded.
            for entry in b {
                a.push(entry);
                if a.len() > top_k {
                    a.pop();
                }
            }
            a
        };

        let final_heap: SmartHeap = if start_sids.len() >= 64 {
            // Parallel branch: each rayon fold chunk maintains its own heap +
            // scratch buffers. The per-chunk threshold is naturally less
            // aggressive than the global one, but the merge step at the end
            // restores the global top-K invariant.
            //
            // `with_min_len(256)` coalesces work into at most ~N/256 chunks
            // so rayon does not thrash its work-stealing queues on workloads
            // where each start does tiny work (typed first step with zero-
            // result DFS). For heavy workloads (Any first step + deep chain)
            // the per-chunk init cost is amortized over hundreds of starts.
            start_sids
                .par_iter()
                .with_min_len(256)
                .fold(init_chunk, |mut chunk, &start_sid| {
                    let (heap, path, stack) =
                        (&mut chunk.0, &mut chunk.1, &mut chunk.2);
                    self.dfs_match_smart(
                        start_sid,
                        &hypothesis.steps,
                        time_window,
                        k,
                        top_k,
                        total_steps,
                        heap,
                        path,
                        stack,
                    );
                    chunk
                })
                .map(|chunk| chunk.0)
                .reduce(
                    || BinaryHeap::with_capacity(top_k + 1),
                    |a, b| merge_into_topk(a, b, top_k),
                )
        } else {
            // Sequential branch: one heap, one set of scratch buffers, reused
            // across every start. Pruning sees the full global threshold so
            // it is maximally aggressive — best for small start_sids sets.
            let (mut heap, mut path, mut stack) = init_chunk();
            for &start_sid in &start_sids {
                self.dfs_match_smart(
                    start_sid,
                    &hypothesis.steps,
                    time_window,
                    k,
                    top_k,
                    total_steps,
                    &mut heap,
                    &mut path,
                    &mut stack,
                );
            }
            heap
        };

        // Extract results from the final heap, sorted by score descending.
        let mut scored: Vec<(f64, Vec<std::sync::Arc<str>>)> = final_heap
            .into_sorted_vec()
            .into_iter()
            .map(|Reverse((score, path))| (score.into_inner(), path))
            .collect();
        scored.reverse(); // highest score first

        let results: Vec<HuntResult> = scored.into_iter().map(|(_, path)| path).collect();
        let results = self.apply_aggregation(results, hypothesis);
        Ok((results, false))
    }

    /// Anomaly-pruned DFS that maintains a top-K min-heap of best-scoring paths.
    ///
    /// `heap`, `path`, `visit_count` and `stack` are caller-owned scratch
    /// buffers (cleared on entry) so the function can be invoked many times
    /// per search without per-call allocations. The heap is the *only* buffer
    /// that carries information out of the call — the rest is reset.
    fn dfs_match_smart(
        &self,
        start_sid: StrId,
        steps: &[crate::hypothesis::HypothesisStep],
        time_window: Option<(i64, i64)>,
        k: usize,
        top_k: usize,
        total_steps: usize,
        heap: &mut SmartHeap,
        path: &mut Vec<StrId>,
        stack: &mut Vec<AnomalyFrame>,
    ) {
        use ordered_float::OrderedFloat;
        use std::cmp::Reverse;

        let scorer = match self.anomaly_scorer.as_ref() {
            Some(s) => s,
            None => return, // scorer not initialized; skip smart DFS
        };

        // Reset scratch state. Buffers normally drain naturally during
        // backtrack, but a defensive clear keeps the contract explicit.
        path.clear();
        stack.clear();

        path.push(start_sid);

        let start_str = self.interner.resolve(start_sid);
        let start_node_score = scorer.node_anomaly_estimate(start_str);

        let (lo, hi) = if !steps.is_empty() {
            self.edge_range_sid(start_sid, &steps[0], i64::MIN, time_window)
        } else {
            (0, 0)
        };

        stack.push(AnomalyFrame {
            sid: start_sid,
            step_idx: 0,
            edge_hi: hi,
            edge_cursor: lo,
            path_anomaly_sum: start_node_score,
        });

        // Hoist the streaming snapshot above the per-frame loop so
        // the OnceLock::get atomic load happens once per DFS call
        // instead of per frame. Saves ~1 ns × frame_count;
        // measurable on multi-million-frame hunts.
        let snap = self.streaming_snapshot();

        while let Some(frame) = stack.last_mut() {
            // Path complete: all steps matched
            if frame.step_idx >= steps.len() {
                // Total nodes in path = total_steps + 1
                let path_len = total_steps + 1;
                let avg_score = frame.path_anomaly_sum / path_len as f64;

                if heap.len() < top_k || avg_score > heap.peek().unwrap().0.0.into_inner() {
                    let path_strings: Vec<std::sync::Arc<str>> = path
                        .iter()
                        .map(|&sid| self.interner.resolve_arc(sid))
                        .collect();
                    heap.push(Reverse((OrderedFloat(avg_score), path_strings)));
                    if heap.len() > top_k {
                        heap.pop(); // remove lowest
                    }
                }

                path.pop();
                stack.pop();
                continue;
            }

            let step = &steps[frame.step_idx];
            // Stage 2c part 2 — read edges from streaming via the
            // parking_lot::RwLock fast path. Arc taken once per
            // outer-frame iteration; the read guard lives for the
            // duration of the inner edge loop, so the slice is
            // valid for the whole `while frame.edge_cursor` walk
            // (mirrors the long-lived `&[CompactRelation]` borrow
            // that the legacy edge_store path provided).
            let _ = step.relation_type;
            let edges: &[crate::streaming::StreamEdge] = snap
                .neighbors(frame.sid)
                .map(|n| n.as_slice())
                .unwrap_or(&[]);

            let mut found = false;
            while frame.edge_cursor < frame.edge_hi {
                let idx = frame.edge_cursor;
                frame.edge_cursor += 1;
                let edge = &edges[idx];

                // B4: software prefetch of entity_type_tags for dest_sids
                // LOOKAHEAD iterations downstream. The per-edge cache miss
                // is entity_type_tags[edge.dest_sid.index()] inside
                // fast_type_matches; dest_sids are scattered (CSR layout
                // points at arbitrary vertices) so the prefetch target is
                // unpredictable to the HW prefetcher. T0 targets L1.
                #[cfg(target_arch = "x86_64")]
                {
                    const LOOKAHEAD: usize = 8;
                    let probe = idx + LOOKAHEAD;
                    if probe < frame.edge_hi {
                        let probe_dst = edges[probe].dest_sid.index();
                        if probe_dst < self.entity_type_tags.len() {
                            unsafe {
                                use std::arch::x86_64::{_MM_HINT_T0, _mm_prefetch};
                                _mm_prefetch::<_MM_HINT_T0>(
                                    self.entity_type_tags.as_ptr().add(probe_dst) as *const i8,
                                );
                            }
                        }
                    }
                }

                if !relation_type_tag_matches(&step.relation_type, edge.rel_type_tag) {
                    continue;
                }

                let dest_sid = edge.dest_sid;
                if !self.fast_type_matches(&step.dest_type, dest_sid) {
                    continue;
                }

                // Metadata predicates (3.A, smart-pruned DFS path).
                if !step.edge_predicates.is_empty() {
                    let metadata = if edge.metadata_offset != 0 {
                        self.meta_store.get(edge.metadata_offset)
                    } else {
                        std::collections::HashMap::new()
                    };
                    if !crate::hypothesis::all_predicates_match(&step.edge_predicates, &metadata) {
                        continue;
                    }
                }

                // Destination-node predicates (B.2 — e.g. `Process {name~"certutil"}`).
                if !step.dest_predicates.is_empty() {
                    let entity = match self.entities.get(&dest_sid) {
                        Some(e) => e,
                        None => continue,
                    };
                    if !crate::hypothesis::all_predicates_match(
                        &step.dest_predicates,
                        &entity.metadata,
                    ) {
                        continue;
                    }
                }

                // C0: linear scan over `path` replaces the visit_count
                // HashMap (same invariant as the iterative variant).
                // Early-exit once we hit `k` matches.
                let mut count = 0usize;
                for &s in path.iter() {
                    if s == dest_sid {
                        count += 1;
                        if count >= k {
                            break;
                        }
                    }
                }
                if count >= k {
                    continue;
                }

                // Anomaly-based pruning
                let dest_str = self.interner.resolve(dest_sid);
                let current_str = self.interner.resolve(frame.sid);
                let node_score = scorer.node_anomaly_estimate(dest_str);
                let edge_score = scorer.edge_anomaly_estimate(current_str, dest_str);
                let step_score = (node_score + edge_score) / 2.0;
                let new_sum = frame.path_anomaly_sum + step_score;

                // Admissible heuristic: assume remaining steps score 1.0 (max)
                let remaining_steps = total_steps - (frame.step_idx + 1);
                let path_len = total_steps + 1;
                let optimistic_avg = (new_sum + remaining_steps as f64) / path_len as f64;

                // Prune if even the optimistic estimate can't beat the current threshold
                if heap.len() >= top_k {
                    let threshold = heap.peek().unwrap().0.0.into_inner();
                    if optimistic_avg < threshold {
                        continue; // PRUNE
                    }
                }

                path.push(dest_sid);

                let next_step_idx = frame.step_idx + 1;
                let (next_lo, next_hi) = if next_step_idx < steps.len() {
                    self.edge_range_sid(
                        dest_sid,
                        &steps[next_step_idx],
                        edge.timestamp,
                        time_window,
                    )
                } else {
                    (0, 0)
                };

                stack.push(AnomalyFrame {
                    sid: dest_sid,
                    step_idx: next_step_idx,
                    edge_hi: next_hi,
                    edge_cursor: next_lo,
                    path_anomaly_sum: new_sum,
                });
                found = true;
                break;
            }

            if !found {
                path.pop();
                stack.pop();
            }
        }
    }

    /// Iterative stack-based DFS with backtracking.
    ///
    /// Scratch buffers (`path`, `visit_count`, `stack`) are passed in by the
    /// caller so they can be reused across many start nodes — this avoids
    /// thousands of small allocations per search. The function clears them
    /// on entry to make the contract explicit; the buffers are also left
    /// empty by the natural backtrack at the end of the DFS.
    fn dfs_match_iterative(
        &self,
        start_sid: StrId,
        steps: &[crate::hypothesis::HypothesisStep],
        time_window: Option<(i64, i64)>,
        k: usize,
        cap: usize,
        result_count: &AtomicUsize,
        results: &mut Vec<HuntResult>,
        path: &mut DfsPath,
        stack: &mut Vec<DfsFrame>,
        symmetry_hint: crate::symmetry::SymmetryHint,
    ) {
        // Reset scratch state. The DFS leaves them empty on a normal exit, but
        // an early break on `cap` reached can leave residue — clear defensively.
        path.clear();
        stack.clear();

        path.push(start_sid);

        let (lo, hi) = if !steps.is_empty() {
            self.edge_range_sid(start_sid, &steps[0], i64::MIN, time_window)
        } else {
            (0, 0)
        };

        stack.push(DfsFrame {
            sid: start_sid,
            step_idx: 0,
            edge_hi: hi,
            edge_cursor: lo,
        });

        // Hoist the streaming snapshot above the per-frame loop —
        // see dfs_match_smart for rationale.
        let snap = self.streaming_snapshot();

        while let Some(frame) = stack.last_mut() {
            if result_count.load(Ordering::Relaxed) >= cap {
                break;
            }

            if frame.step_idx >= steps.len() {
                // B9 — symmetry-breaking filter at emission. For
                // palindromic patterns we keep only canonical-direction
                // matches (path[0] < path[last]); the reverse path is
                // emitted from the mirror start and would be a duplicate.
                if symmetry_hint.keep_match(path) {
                    let prev = result_count.fetch_add(1, Ordering::Relaxed);
                    if prev < cap {
                        // C2: refcount-bump clone instead of `String::from`.
                        // resolve_arc returns an `Arc<str>` already alive in
                        // the interner's storage; per-result work drops from
                        // path.len() heap allocations to path.len() atomic
                        // increments.
                        results.push(
                            path.iter()
                                .map(|&sid| self.interner.resolve_arc(sid))
                                .collect(),
                        );
                    }
                }
                path.pop();
                stack.pop();
                continue;
            }

            let step = &steps[frame.step_idx];
            // Stage 2c part 2 — same parking_lot fast-path migration
            // as dfs_match_smart: arc + guard + slice live for the
            // inner edge loop, drop on next outer iteration.
            let _ = step.relation_type;
            let edges: &[crate::streaming::StreamEdge] = snap
                .neighbors(frame.sid)
                .map(|n| n.as_slice())
                .unwrap_or(&[]);

            let mut found = false;
            while frame.edge_cursor < frame.edge_hi {
                let idx = frame.edge_cursor;
                frame.edge_cursor += 1;
                let edge = &edges[idx];

                // B4: software prefetch of entity_type_tags for dest_sids
                // LOOKAHEAD iterations downstream. The per-edge cache miss
                // is entity_type_tags[edge.dest_sid.index()] inside
                // fast_type_matches; dest_sids are scattered (CSR layout
                // points at arbitrary vertices) so the prefetch target is
                // unpredictable to the HW prefetcher. T0 targets L1.
                #[cfg(target_arch = "x86_64")]
                {
                    const LOOKAHEAD: usize = 8;
                    let probe = idx + LOOKAHEAD;
                    if probe < frame.edge_hi {
                        let probe_dst = edges[probe].dest_sid.index();
                        if probe_dst < self.entity_type_tags.len() {
                            unsafe {
                                use std::arch::x86_64::{_MM_HINT_T0, _mm_prefetch};
                                _mm_prefetch::<_MM_HINT_T0>(
                                    self.entity_type_tags.as_ptr().add(probe_dst) as *const i8,
                                );
                            }
                        }
                    }
                }

                if !relation_type_tag_matches(&step.relation_type, edge.rel_type_tag) {
                    continue;
                }

                let dest_sid = edge.dest_sid;
                if !self.fast_type_matches(&step.dest_type, dest_sid) {
                    continue;
                }

                // Metadata predicates (3.A, iterative DFS path).
                if !step.edge_predicates.is_empty() {
                    let metadata = if edge.metadata_offset != 0 {
                        self.meta_store.get(edge.metadata_offset)
                    } else {
                        std::collections::HashMap::new()
                    };
                    if !crate::hypothesis::all_predicates_match(&step.edge_predicates, &metadata) {
                        continue;
                    }
                }

                // Destination-node predicates (B.2).
                if !step.dest_predicates.is_empty() {
                    let entity = match self.entities.get(&dest_sid) {
                        Some(e) => e,
                        None => continue,
                    };
                    if !crate::hypothesis::all_predicates_match(
                        &step.dest_predicates,
                        &entity.metadata,
                    ) {
                        continue;
                    }
                }

                // C0: linear scan over `path` replaces the visit_count
                // HashMap. For depth ≤ 8 (DfsPath SmallVec inline cap)
                // the scan fits in one L1 cache line; HashMap.get on
                // the hot path was hash + bucket chase per check, plus
                // entry/insert/remove on every push/pop. Early-exit
                // once we hit `k` matches so the scan cost is bounded
                // regardless of `path` length.
                let mut count = 0usize;
                for &s in path.iter() {
                    if s == dest_sid {
                        count += 1;
                        if count >= k {
                            break;
                        }
                    }
                }
                if count >= k {
                    continue;
                }

                path.push(dest_sid);

                let next_step_idx = frame.step_idx + 1;
                let (next_lo, next_hi) = if next_step_idx < steps.len() {
                    self.edge_range_sid(
                        dest_sid,
                        &steps[next_step_idx],
                        edge.timestamp,
                        time_window,
                    )
                } else {
                    (0, 0)
                };

                stack.push(DfsFrame {
                    sid: dest_sid,
                    step_idx: next_step_idx,
                    edge_hi: next_hi,
                    edge_cursor: next_lo,
                });
                found = true;
                break;
            }

            if !found {
                path.pop();
                stack.pop();
            }
        }
    }

    /// Test/bench entry point that always uses the AMAC path,
    /// regardless of the `GRAPHHUNTER_AMAC` env var. Used by parity
    /// tests to validate result-set equality with the regular DFS.
    /// Honors NLF / D5 prunes and the symmetry hint identically.
    #[doc(hidden)]
    pub fn search_temporal_pattern_amac(
        &self,
        hypothesis: &Hypothesis,
        time_window: Option<(i64, i64)>,
        max_results: Option<usize>,
    ) -> Result<(Vec<HuntResult>, bool), GraphError> {
        hypothesis
            .validate()
            .map_err(GraphError::InvalidHypothesis)?;
        let cap = max_results.unwrap_or(10_000);

        let first_step = &hypothesis.steps[0];
        let mut start_sids: Vec<StrId> = if first_step.origin_type == EntityType::Any {
            self.entities.keys().copied().collect()
        } else {
            self.type_index
                .get(&first_step.origin_type)
                .map(|ids| ids.iter().copied().collect())
                .unwrap_or_default()
        };
        let nlf_req = crate::nlf::requirement_from_first_step(first_step);
        if self.edges_sorted && !crate::nlf::is_trivial(&nlf_req) {
            let nlf = self.ensure_nlf();
            start_sids.retain(|&sid| nlf.can_match(sid, &nlf_req));
        }
        let khop_mask = crate::khop_reach::end_type_mask(hypothesis);
        if self.edges_sorted && !crate::khop_reach::is_trivial(khop_mask, hypothesis) {
            let reach = self.ensure_khop_reach();
            start_sids.retain(|&sid| reach.can_reach_in_window(sid, khop_mask, time_window));
        }
        let symmetry_hint = crate::symmetry::analyze(hypothesis);
        let k = hypothesis.k_simplicity.max(1);
        let result_count = AtomicUsize::new(0);
        let mut results: Vec<HuntResult> = Vec::new();
        const K: usize = 8;
        for chunk in start_sids.chunks(K) {
            if result_count.load(Ordering::Relaxed) >= cap {
                break;
            }
            self.dfs_match_amac_chunk(
                chunk,
                &hypothesis.steps,
                time_window,
                k,
                cap,
                &result_count,
                &mut results,
                symmetry_hint,
            );
        }
        let truncated = result_count.load(Ordering::Relaxed) >= cap;
        let results = self.apply_aggregation(results, hypothesis);
        Ok((results, truncated))
    }

    /// C2 — AMAC interleaved DFS over a chunk of `K=8` start vertices.
    ///
    /// Maintains K independent DFS contexts (`path[i]`, `stack[i]`) and
    /// round-robins through them, advancing one edge probe per context
    /// per outer iteration. Before each probe, emits a software prefetch
    /// for the *next active* context's pending edge target — so by the
    /// time the round-robin returns to that context, the cache line is
    /// resident.
    ///
    /// Correctness is by construction: each per-context state machine
    /// is the same DFS as `dfs_match_iterative`, just sliced one edge at
    /// a time. The result set is identical (modulo emission order, which
    /// callers don't depend on — see `apply_aggregation`).
    ///
    /// Default-off behind `GRAPHHUNTER_AMAC=1` until per-bench validation
    /// confirms the latency-hiding lift on hybrid-core CPUs.
    #[allow(clippy::too_many_arguments)]
    fn dfs_match_amac_chunk(
        &self,
        starts: &[StrId],
        steps: &[crate::hypothesis::HypothesisStep],
        time_window: Option<(i64, i64)>,
        k: usize,
        cap: usize,
        result_count: &AtomicUsize,
        results: &mut Vec<HuntResult>,
        symmetry_hint: crate::symmetry::SymmetryHint,
    ) {
        const K: usize = 8;
        let n = starts.len().min(K);
        if n == 0 {
            return;
        }

        // K independent DFS state slots. SmallVec inline cap covers
        // hypothesis depth ≤ 8 — bench workloads top out at 4-hop.
        let mut paths: [DfsPath; K] = std::array::from_fn(|_| SmallVec::new());
        let mut stacks: [smallvec::SmallVec<[DfsFrame; 8]>; K] =
            std::array::from_fn(|_| SmallVec::new());
        let mut active = [false; K];

        for i in 0..n {
            paths[i].push(starts[i]);
            let (lo, hi) = if !steps.is_empty() {
                self.edge_range_sid(starts[i], &steps[0], i64::MIN, time_window)
            } else {
                (0, 0)
            };
            stacks[i].push(DfsFrame {
                sid: starts[i],
                step_idx: 0,
                edge_hi: hi,
                edge_cursor: lo,
            });
            active[i] = true;
        }

        // Hoist the streaming snapshot above the AMAC scheduler
        // loop so the OnceLock atomic load happens once for the
        // entire round-robin scheduling rather than per cross-context
        // prefetch lookahead and per amac_step_one_edge call.
        let snap = self.streaming_snapshot();

        let mut active_count = n;
        while active_count > 0 {
            if result_count.load(Ordering::Relaxed) >= cap {
                break;
            }
            for i in 0..n {
                if !active[i] {
                    continue;
                }

                // Cross-context prefetch: peek at the NEXT active
                // context's pending edge dest_sid and prefetch its
                // entity_type_tag. By the time we round-robin to that
                // context (~K iterations later) the line should be in L1.
                #[cfg(target_arch = "x86_64")]
                {
                    for off in 1..K {
                        let j = (i + off) % K;
                        if !active[j] {
                            continue;
                        }
                        let f = match stacks[j].last() {
                            Some(f) => f,
                            None => continue,
                        };
                        if f.step_idx >= steps.len() || f.edge_cursor >= f.edge_hi {
                            break;
                        }
                        // Stage 2c part 2 — read from streaming for
                        // the AMAC prefetch lookahead. The guard is
                        // dropped immediately after the slice probe;
                        // the AMAC scheduler handles its own context
                        // switches between calls.
                        let _ = steps[f.step_idx].relation_type;
                        let neighbors = match snap.neighbors(f.sid) {
                            Some(n) => n,
                            None => break,
                        };
                        let edges = neighbors.as_slice();
                        if f.edge_cursor < edges.len() {
                            let dst = edges[f.edge_cursor].dest_sid.index();
                            if dst < self.entity_type_tags.len() {
                                unsafe {
                                    use std::arch::x86_64::{_MM_HINT_T0, _mm_prefetch};
                                    _mm_prefetch::<_MM_HINT_T0>(
                                        self.entity_type_tags.as_ptr().add(dst) as *const i8,
                                    );
                                }
                            }
                        }
                        break;
                    }
                }

                // Advance ctx i by ONE edge probe (or one frame pop).
                let done = self.amac_step_one_edge(
                    snap,
                    &mut paths[i],
                    &mut stacks[i],
                    steps,
                    time_window,
                    k,
                    cap,
                    result_count,
                    results,
                    symmetry_hint,
                );
                if done {
                    active[i] = false;
                    active_count -= 1;
                }
            }
        }
    }

    /// One step of the per-context AMAC state machine.
    ///
    /// Returns `true` when the context is fully unwound (stack empty
    /// or cap reached). The caller must keep calling until `true`.
    /// Each call does at most ONE edge probe — this is the granularity
    /// that lets cross-context prefetch hide DRAM latency.
    #[allow(clippy::too_many_arguments)]
    fn amac_step_one_edge(
        &self,
        snap: &crate::streaming::FrozenSnapshot,
        path: &mut DfsPath,
        stack: &mut smallvec::SmallVec<[DfsFrame; 8]>,
        steps: &[crate::hypothesis::HypothesisStep],
        time_window: Option<(i64, i64)>,
        k: usize,
        cap: usize,
        result_count: &AtomicUsize,
        results: &mut Vec<HuntResult>,
        symmetry_hint: crate::symmetry::SymmetryHint,
    ) -> bool {
        if result_count.load(Ordering::Relaxed) >= cap {
            return true;
        }

        let frame = match stack.last_mut() {
            Some(f) => f,
            None => return true,
        };

        if frame.step_idx >= steps.len() {
            // Match complete — emit (or skip via symmetry filter), then pop.
            if symmetry_hint.keep_match(path) {
                let prev = result_count.fetch_add(1, Ordering::Relaxed);
                if prev < cap {
                    results.push(
                        path.iter()
                            .map(|&sid| self.interner.resolve_arc(sid))
                            .collect(),
                    );
                }
            }
            path.pop();
            stack.pop();
            return stack.is_empty();
        }

        if frame.edge_cursor >= frame.edge_hi {
            // Edges exhausted at this depth — backtrack.
            path.pop();
            stack.pop();
            return stack.is_empty();
        }

        // Inline copy of the per-edge filter chain from
        // `dfs_match_iterative`. Process AT MOST one edge per call so
        // the round-robin scheduler can interleave contexts. Stage 2c
        // part 2: the slice comes from the streaming layer; the guard
        // is held only for the duration of the single-edge probe.
        let step = &steps[frame.step_idx];
        let _ = step.relation_type;
        let neighbors = match snap.neighbors(frame.sid) {
            Some(n) => n,
            None => return false,
        };
        let edges = neighbors.as_slice();
        let idx = frame.edge_cursor;
        frame.edge_cursor += 1;
        let edge = &edges[idx];

        if !relation_type_tag_matches(&step.relation_type, edge.rel_type_tag) {
            return false;
        }
        let dest_sid = edge.dest_sid;
        if !self.fast_type_matches(&step.dest_type, dest_sid) {
            return false;
        }
        if !step.edge_predicates.is_empty() {
            let metadata = if edge.metadata_offset != 0 {
                self.meta_store.get(edge.metadata_offset)
            } else {
                std::collections::HashMap::new()
            };
            if !crate::hypothesis::all_predicates_match(&step.edge_predicates, &metadata) {
                return false;
            }
        }
        if !step.dest_predicates.is_empty() {
            let entity = match self.entities.get(&dest_sid) {
                Some(e) => e,
                None => return false,
            };
            if !crate::hypothesis::all_predicates_match(&step.dest_predicates, &entity.metadata) {
                return false;
            }
        }

        // K-simplicity check.
        let mut count = 0usize;
        for &s in path.iter() {
            if s == dest_sid {
                count += 1;
                if count >= k {
                    break;
                }
            }
        }
        if count >= k {
            return false;
        }

        // Descend.
        path.push(dest_sid);
        let next_step_idx = frame.step_idx + 1;
        let (next_lo, next_hi) = if next_step_idx < steps.len() {
            self.edge_range_sid(dest_sid, &steps[next_step_idx], edge.timestamp, time_window)
        } else {
            (0, 0)
        };
        stack.push(DfsFrame {
            sid: dest_sid,
            step_idx: next_step_idx,
            edge_hi: next_hi,
            edge_cursor: next_lo,
        });
        false
    }

    /// Computes valid edge index range [lo, hi) using binary search
    /// on sorted edges (StrId version). Stage 2c part 2: reads from
    /// the streaming layer instead of edge_store. After
    /// `sort_edges_by_timestamp()` both stores hold the same edge
    /// set sorted by timestamp per-vertex, so partition_point gives
    /// the same answer on either; reading streaming here keeps the
    /// hot path off edge_store entirely so the dual-write
    /// `edge_store.push` becomes safe to remove from `add_relation`.
    #[inline]
    fn edge_range_sid(
        &self,
        sid: StrId,
        step: &crate::hypothesis::HypothesisStep,
        last_timestamp: i64,
        time_window: Option<(i64, i64)>,
    ) -> (usize, usize) {
        let _ = step.relation_type;
        let snap = self.streaming_snapshot();
        let neighbors = match snap.neighbors(sid) {
            Some(n) => n,
            None => return (0, 0),
        };
        let edges = neighbors.as_slice();
        if edges.is_empty() {
            return (0, 0);
        }
        let lo_ts = if let Some((tw_start, _)) = time_window {
            last_timestamp.max(tw_start)
        } else {
            last_timestamp
        };
        let lo = edges.partition_point(|e| e.timestamp < lo_ts);
        let hi = if let Some((_, tw_end)) = time_window {
            edges.partition_point(|e| e.timestamp <= tw_end)
        } else {
            edges.len()
        };
        (lo, hi)
    }

    /// Computes valid edge index range [lo, hi) (string version, kept for get_edges_for_step).
    #[inline]
    #[allow(dead_code)]
    fn edge_range(
        &self,
        node_id: &str,
        step: &crate::hypothesis::HypothesisStep,
        last_timestamp: i64,
        time_window: Option<(i64, i64)>,
    ) -> (usize, usize) {
        // This method uses the StrId-based version internally
        let sid = match self.interner.get(node_id) {
            Some(s) => s,
            None => return (0, 0),
        };
        self.edge_range_sid(sid, step, last_timestamp, time_window)
    }

    /// Merges metadata from `incoming` into `existing` according to the merge policy.
    fn merge_metadata(
        existing: &mut std::collections::HashMap<String, String>,
        incoming: &std::collections::HashMap<String, String>,
        policy: &MergePolicy,
    ) {
        for (k, v) in incoming {
            match policy {
                MergePolicy::FirstWriteWins => {
                    existing.entry(k.clone()).or_insert_with(|| v.clone());
                }
                MergePolicy::LastWriteWins => {
                    existing.insert(k.clone(), v.clone());
                }
                MergePolicy::Append => {
                    existing
                        .entry(k.clone())
                        .and_modify(|old| {
                            old.push_str(", ");
                            old.push_str(v);
                        })
                        .or_insert_with(|| v.clone());
                }
            }
        }
    }

    /// Ingests raw log data using the provided parser.
    pub fn ingest_logs<P: crate::parser::LogParser>(
        &mut self,
        logs: &str,
        parser: &P,
        dataset_id: Option<String>,
    ) -> Result<(usize, usize), GraphError> {
        self.ingest_logs_with_policy(logs, parser, dataset_id, &MergePolicy::default())
    }

    /// Ingests raw log data with a specific merge policy.
    pub fn ingest_logs_with_policy<P: crate::parser::LogParser>(
        &mut self,
        logs: &str,
        parser: &P,
        dataset_id: Option<String>,
        merge_policy: &MergePolicy,
    ) -> Result<(usize, usize), GraphError> {
        let triples = parser.parse(logs);
        let mut new_entities = 0usize;
        let mut new_relations = 0usize;
        let ds: Option<Arc<str>> = dataset_id.map(|s| Arc::from(s.as_str()));
        let ds_tag = self.intern_dataset_tag(ds.as_deref());

        for (mut src, rel, mut dst) in triples {
            if let Some(ref id) = ds {
                src.dataset_id = Some(Arc::clone(id));
                dst.dataset_id = Some(Arc::clone(id));
            }

            // Upsert source entity
            let src_sid = self.interner.intern(&src.id);
            if let Some(existing) = self.entities.get_mut(&src_sid) {
                Self::merge_metadata(&mut existing.metadata, &src.metadata, merge_policy);
            } else {
                let et = src.entity_type.clone();
                self.set_entity_type_tag(src_sid, &et);
                self.entities.insert(src_sid, src);
                self.type_index.entry(et).or_default().insert(src_sid);
                self.reverse_adj.entry(src_sid).or_default();
                new_entities += 1;
            }

            // Upsert destination entity
            let dst_sid = self.interner.intern(&dst.id);
            if let Some(existing) = self.entities.get_mut(&dst_sid) {
                Self::merge_metadata(&mut existing.metadata, &dst.metadata, merge_policy);
            } else {
                let et = dst.entity_type.clone();
                self.set_entity_type_tag(dst_sid, &et);
                self.entities.insert(dst_sid, dst);
                self.type_index.entry(et).or_default().insert(dst_sid);
                self.reverse_adj.entry(dst_sid).or_default();
                new_entities += 1;
            }

            // Feed anomaly scorer if enabled
            if let Some(ref mut scorer) = self.anomaly_scorer {
                scorer.observe_entity(&rel.source_id, rel.timestamp);
                scorer.observe_entity(&rel.dest_id, rel.timestamp);
                scorer.observe_edge(&rel.source_id, &rel.dest_id);
            }

            let meta_offset = self.append_edge_metadata(&rel.rel_type, &rel.metadata);
            let compact = CompactRelation {
                source_sid: src_sid,
                dest_sid: dst_sid,
                rel_type_tag: rel.rel_type.to_u8(),
                timestamp: rel.timestamp,
                metadata_offset: meta_offset,
                dataset_tag: ds_tag,
                ingested_at_delta: 0,
            };

            // Always insert relation
            // Fallible push first: a spill failure must not leave a dangling reverse edge (C3a).
            self.push_to_streaming(&compact)?;
            self.reverse_adj.entry(dst_sid).or_default().push(src_sid);
            new_relations += 1;
        }

        Ok((new_entities, new_relations))
    }

    /// Removes all entities and relations that belong to the given dataset.
    pub fn remove_entities_and_relations_by_dataset(
        &mut self,
        dataset_id: &str,
    ) -> Result<(usize, usize), GraphError> {
        let to_remove: Vec<StrId> = self
            .entities
            .iter()
            .filter(|(_, e)| e.dataset_id.as_deref() == Some(dataset_id))
            .map(|(&sid, _)| sid)
            .collect();

        // Find the dataset tag for this dataset_id
        let ds_tag = self
            .dataset_tags
            .iter()
            .position(|t| &**t == dataset_id)
            .map(|p| p as u16);

        // Rebuild streaming keeping only edges that don't match the dataset tag
        let total_before = self.streaming_edge_count();
        let mut kept: Vec<CompactRelation> = Vec::new();
        self.streaming.for_each_edge(|_src, edge| {
            if ds_tag.map_or(true, |tag| edge.dataset_tag != tag) {
                // SAFETY: layout-identical (#[repr(C)]).
                let compact: CompactRelation = unsafe {
                    std::ptr::read(edge as *const _ as *const CompactRelation)
                };
                kept.push(compact);
            }
        });
        let relations_removed = total_before - kept.len();

        self.streaming.clear();
        for c in &kept {
            self.push_to_streaming(c)?;
        }
        self.streaming.finalize();

        // Rebuild reverse_adj
        self.reverse_adj.clear();
        for compact in &kept {
            self.reverse_adj
                .entry(compact.dest_sid)
                .or_default()
                .push(compact.source_sid);
        }
        for v in self.reverse_adj.values_mut() {
            v.sort_unstable();
            v.dedup();
        }

        // Remove entities
        let entities_removed = to_remove.len();
        for sid in &to_remove {
            if let Some(entity) = self.entities.remove(sid) {
                if let Some(set) = self.type_index.get_mut(&entity.entity_type) {
                    set.remove(sid);
                }
            }
            self.mark_entity_dead(*sid);
            self.reverse_adj.remove(sid);
        }

        self.edges_sorted = true; // finalize() sorted them
        // Heavy-logs #3.5: drop the NLF cache so the next matcher
        // call rebuilds against the post-mutation graph state.
        self.nlf = std::sync::OnceLock::new();
        self.khop_reach = std::sync::OnceLock::new();
        self.bump_mutation_version();
        Ok((entities_removed, relations_removed))
    }

    /// Renames entity types in a dataset.
    pub fn rename_entity_type_in_dataset(
        &mut self,
        dataset_id: &str,
        from_type: EntityType,
        to_type: EntityType,
    ) -> usize {
        let to_rename: Vec<StrId> = self
            .entities
            .iter()
            .filter(|(_, e)| {
                e.dataset_id.as_deref() == Some(dataset_id) && e.entity_type == from_type
            })
            .map(|(&sid, _)| sid)
            .collect();
        let count = to_rename.len();
        for sid in to_rename {
            if let Some(mut entity) = self.entities.remove(&sid) {
                if let Some(set) = self.type_index.get_mut(&from_type) {
                    set.remove(&sid);
                }
                entity.entity_type = to_type.clone();
                self.type_index
                    .entry(to_type.clone())
                    .or_default()
                    .insert(sid);
                self.set_entity_type_tag(sid, &to_type);
                self.entities.insert(sid, entity);
            }
        }
        count
    }

    /// Returns entity type names in the given dataset.
    pub fn entity_types_in_dataset(&self, dataset_id: &str) -> Vec<String> {
        let mut types: HashSet<String> = HashSet::new();
        for e in self.entities.values() {
            if e.dataset_id.as_deref() == Some(dataset_id) {
                types.insert(e.entity_type.to_string());
            }
        }
        let mut v: Vec<String> = types.into_iter().collect();
        v.sort();
        v
    }

    /// Exports the graph as a snapshot for serialization.
    pub fn to_snapshot(&self) -> (Vec<Entity>, Vec<Relation>) {
        let entities: Vec<Entity> = self.entities.values().cloned().collect();
        let mut relations: Vec<Relation> = Vec::new();
        self.streaming.for_each_edge(|_src, edge| {
            // SAFETY: layout-identical with CompactRelation.
            let compact: CompactRelation = unsafe {
                std::ptr::read(edge as *const _ as *const CompactRelation)
            };
            relations.push(self.materialize_relation(&compact));
        });
        (entities, relations)
    }

    /// Builds a graph from a snapshot.
    pub fn load_snapshot(
        entities: Vec<Entity>,
        relations: Vec<Relation>,
    ) -> Result<Self, GraphError> {
        let mut g = GraphHunter::new();
        for entity in entities {
            g.add_entity(entity)?;
        }
        for relation in relations {
            g.add_relation(relation)?;
        }
        Ok(g)
    }

    /// Naive DFS search (baseline for benchmarks).
    pub fn search_naive_dfs(
        &self,
        hypothesis: &Hypothesis,
    ) -> Result<(Vec<HuntResult>, usize), GraphError> {
        hypothesis
            .validate()
            .map_err(GraphError::InvalidHypothesis)?;

        let mut results: Vec<HuntResult> = Vec::new();
        let mut nodes_visited: usize = 0;

        for (&start_sid, _) in &self.entities {
            let mut visited = HashSet::new();
            visited.insert(start_sid);
            let mut path = vec![self.interner.resolve(start_sid).to_string()];

            self.naive_dfs_recurse(
                start_sid,
                &hypothesis.steps,
                0,
                &mut visited,
                &mut path,
                &mut results,
                &mut nodes_visited,
            );
        }

        Ok((results, nodes_visited))
    }

    /// Naive DFS recursive core.
    fn naive_dfs_recurse(
        &self,
        current_sid: StrId,
        steps: &[crate::hypothesis::HypothesisStep],
        step_idx: usize,
        visited: &mut HashSet<StrId>,
        path: &mut Vec<String>,
        results: &mut Vec<HuntResult>,
        nodes_visited: &mut usize,
    ) {
        *nodes_visited += 1;

        if step_idx >= steps.len() {
            let valid = self.verify_path_matches(path, steps);
            if valid {
                results.push(
                    path.iter()
                        .map(|s| std::sync::Arc::from(s.as_str()))
                        .collect(),
                );
            }
            return;
        }

        let edges = self.get_relations_by_sid(current_sid);
        for edge in edges {
            let dest_sid = edge.dest_sid;
            if visited.contains(&dest_sid) {
                continue;
            }

            visited.insert(dest_sid);
            path.push(self.interner.resolve(dest_sid).to_string());

            self.naive_dfs_recurse(
                dest_sid,
                steps,
                step_idx + 1,
                visited,
                path,
                results,
                nodes_visited,
            );

            path.pop();
            visited.remove(&dest_sid);
        }
    }

    /// Verifies that a completed path matches the hypothesis types and temporal order.
    fn verify_path_matches(
        &self,
        path: &[String],
        steps: &[crate::hypothesis::HypothesisStep],
    ) -> bool {
        if path.len() != steps.len() + 1 {
            return false;
        }

        let first_sid = match self.interner.get(&path[0]) {
            Some(s) => s,
            None => return false,
        };
        let first = match self.entities.get(&first_sid) {
            Some(e) => e,
            None => return false,
        };
        if !entity_type_matches(&steps[0].origin_type, &first.entity_type) {
            return false;
        }

        let mut last_timestamp = i64::MIN;

        for (i, step) in steps.iter().enumerate() {
            let src_id = &path[i];
            let dst_id = &path[i + 1];

            let edges = self.get_relations(src_id);
            let mut found = false;
            for edge in edges {
                if edge.dest_id == *dst_id {
                    if relation_type_matches(&step.relation_type, &edge.rel_type) {
                        let dst_sid = match self.interner.get(dst_id) {
                            Some(s) => s,
                            None => continue,
                        };
                        let dest = match self.entities.get(&dst_sid) {
                            Some(e) => e,
                            None => continue,
                        };
                        if entity_type_matches(&step.dest_type, &dest.entity_type)
                            && edge.timestamp >= last_timestamp
                        {
                            last_timestamp = edge.timestamp;
                            found = true;
                            break;
                        }
                    }
                }
            }
            if !found {
                return false;
            }
        }

        true
    }

    /// Ingests log data in chunks with progress callback.
    pub fn ingest_logs_chunked<P, F>(
        &mut self,
        logs: &str,
        parser: &P,
        dataset_id: Option<String>,
        chunk_size: usize,
        mut on_progress: F,
    ) -> Result<(usize, usize), GraphError>
    where
        P: crate::parser::LogParser,
        F: FnMut(usize, usize, usize, usize),
    {
        let merge_policy = MergePolicy::default();
        let triples = parser.parse(logs);
        let total = triples.len();
        let mut new_entities = 0usize;
        let mut new_relations = 0usize;
        let ds: Option<Arc<str>> = dataset_id.map(|s| Arc::from(s.as_str()));
        let ds_tag = self.intern_dataset_tag(ds.as_deref());

        for (i, (mut src, rel, mut dst)) in triples.into_iter().enumerate() {
            if let Some(ref id) = ds {
                src.dataset_id = Some(Arc::clone(id));
                dst.dataset_id = Some(Arc::clone(id));
            }

            let src_sid = self.interner.intern(&src.id);
            if let Some(existing) = self.entities.get_mut(&src_sid) {
                Self::merge_metadata(&mut existing.metadata, &src.metadata, &merge_policy);
            } else {
                let et = src.entity_type.clone();
                self.set_entity_type_tag(src_sid, &et);
                self.entities.insert(src_sid, src);
                self.type_index.entry(et).or_default().insert(src_sid);
                self.reverse_adj.entry(src_sid).or_default();
                new_entities += 1;
            }

            let dst_sid = self.interner.intern(&dst.id);
            if let Some(existing) = self.entities.get_mut(&dst_sid) {
                Self::merge_metadata(&mut existing.metadata, &dst.metadata, &merge_policy);
            } else {
                let et = dst.entity_type.clone();
                self.set_entity_type_tag(dst_sid, &et);
                self.entities.insert(dst_sid, dst);
                self.type_index.entry(et).or_default().insert(dst_sid);
                self.reverse_adj.entry(dst_sid).or_default();
                new_entities += 1;
            }

            if let Some(ref mut scorer) = self.anomaly_scorer {
                scorer.observe_entity(&rel.source_id, rel.timestamp);
                scorer.observe_entity(&rel.dest_id, rel.timestamp);
                scorer.observe_edge(&rel.source_id, &rel.dest_id);
            }

            let meta_offset = self.append_edge_metadata(&rel.rel_type, &rel.metadata);
            let compact = CompactRelation {
                source_sid: src_sid,
                dest_sid: dst_sid,
                rel_type_tag: rel.rel_type.to_u8(),
                timestamp: rel.timestamp,
                metadata_offset: meta_offset,
                dataset_tag: ds_tag,
                ingested_at_delta: 0,
            };

            // Fallible push first: a spill failure must not leave a dangling reverse edge (C3a).
            self.push_to_streaming(&compact)?;
            self.reverse_adj.entry(dst_sid).or_default().push(src_sid);
            new_relations += 1;

            if (i + 1) % chunk_size == 0 || i + 1 == total {
                on_progress(i + 1, total, new_entities, new_relations);
            }
        }

        Ok((new_entities, new_relations))
    }

    /// Processes one chunk of up to `chunk_size` triples from the front
    /// of `pending`, inserting them into the graph.
    ///
    /// Returns the number of triples inserted. The caller (typically the
    /// `GraphWriter` task in `crate::ingest::writer`) is expected to hold
    /// an external write lock only for the duration of this single call
    /// and release it between chunks so readers (hunts, enrichment) can
    /// make progress under concurrent load.
    ///
    /// The input `pending` vector is drained in-place — after the call
    /// returns, the remaining triples sit at positions `0..pending.len()`.
    /// Loop until `pending.is_empty()` on the caller side to flush a
    /// whole batch.
    ///
    /// This is the per-chunk entry point used by the streaming ingest
    /// pipeline (plan §3). The existing `insert_triples` method is kept
    /// as-is for non-streaming callers (file ingest, session load,
    /// single-shot hunts).
    pub fn insert_triples_chunk(
        &mut self,
        pending: &mut Vec<crate::parser::ParsedTriple>,
        dataset_id: Option<&str>,
        chunk_size: usize,
    ) -> Result<usize, GraphError> {
        if pending.is_empty() || chunk_size == 0 {
            return Ok(0);
        }
        let n = pending.len().min(chunk_size);
        // Drain `n` triples from the front. `drain(..n)` leaves the
        // remainder shifted to the beginning of the Vec in O(N) time —
        // acceptable because chunk_size is typically 5K and the Vec is
        // small (one batch at a time).
        let chunk: Vec<crate::parser::ParsedTriple> = pending.drain(..n).collect();
        self.insert_triples(chunk, dataset_id)?;
        Ok(n)
    }

    /// Per-chunk entry point for the raw-event ingest path. Mirrors
    /// [`insert_triples_chunk`] but operates on
    /// [`crate::parser::RawIngestEvent`]. Drains up to `chunk_size`
    /// events from the front of `pending` and forwards them to
    /// [`insert_raw_events`].
    pub fn insert_raw_events_chunk(
        &mut self,
        pending: &mut Vec<crate::parser::RawIngestEvent>,
        dataset_id: Option<&str>,
        chunk_size: usize,
    ) -> Result<usize, GraphError> {
        if pending.is_empty() || chunk_size == 0 {
            return Ok(0);
        }
        let n = pending.len().min(chunk_size);
        let chunk: Vec<crate::parser::RawIngestEvent> = pending.drain(..n).collect();
        self.insert_raw_events(chunk, dataset_id)?;
        Ok(n)
    }

    /// Inserts pre-parsed triples directly (streaming ingestion).
    pub fn insert_triples(
        &mut self,
        triples: Vec<crate::parser::ParsedTriple>,
        dataset_id: Option<&str>,
    ) -> Result<(usize, usize), GraphError> {
        let merge_policy = MergePolicy::default();
        let mut new_entities = 0usize;
        let mut new_relations = 0usize;
        let ds: Option<Arc<str>> = dataset_id.map(Arc::from);
        let ds_tag = self.intern_dataset_tag(dataset_id);

        for (mut src, rel, mut dst) in triples {
            if let Some(ref id) = ds {
                src.dataset_id = Some(Arc::clone(id));
                dst.dataset_id = Some(Arc::clone(id));
            }

            let src_sid = self.interner.intern(&src.id);
            if let Some(existing) = self.entities.get_mut(&src_sid) {
                Self::merge_metadata(&mut existing.metadata, &src.metadata, &merge_policy);
            } else {
                let et = src.entity_type.clone();
                self.set_entity_type_tag(src_sid, &et);
                self.entities.insert(src_sid, src);
                self.type_index.entry(et).or_default().insert(src_sid);
                self.reverse_adj.entry(src_sid).or_default();
                new_entities += 1;
            }

            let dst_sid = self.interner.intern(&dst.id);
            if let Some(existing) = self.entities.get_mut(&dst_sid) {
                Self::merge_metadata(&mut existing.metadata, &dst.metadata, &merge_policy);
            } else {
                let et = dst.entity_type.clone();
                self.set_entity_type_tag(dst_sid, &et);
                self.entities.insert(dst_sid, dst);
                self.type_index.entry(et).or_default().insert(dst_sid);
                self.reverse_adj.entry(dst_sid).or_default();
                new_entities += 1;
            }

            if let Some(ref mut scorer) = self.anomaly_scorer {
                scorer.observe_entity(&rel.source_id, rel.timestamp);
                scorer.observe_entity(&rel.dest_id, rel.timestamp);
                scorer.observe_edge(&rel.source_id, &rel.dest_id);
            }

            let meta_offset = self.append_edge_metadata(&rel.rel_type, &rel.metadata);
            let compact = CompactRelation {
                source_sid: src_sid,
                dest_sid: dst_sid,
                rel_type_tag: rel.rel_type.to_u8(),
                timestamp: rel.timestamp,
                metadata_offset: meta_offset,
                dataset_tag: ds_tag,
                ingested_at_delta: 0,
            };

            // Fallible push first: a spill failure must not leave a dangling reverse edge (C3a).
            self.push_to_streaming(&compact)?;
            self.reverse_adj.entry(dst_sid).or_default().push(src_sid);
            self.on_streaming_edge_appended(src_sid, dst_sid);
            new_relations += 1;
        }

        Ok((new_entities, new_relations))
    }

    /// Like [`insert_triples`] but consumes the flat
    /// [`crate::parser::RawIngestEvent`] form, skipping the
    /// `Entity`/`Relation` struct allocation that the legacy path
    /// pays per-triple in the parser. The `Entity` is materialized
    /// only when the source/dest is genuinely new in this graph;
    /// otherwise we just merge metadata into the existing record.
    pub fn insert_raw_events(
        &mut self,
        events: Vec<crate::parser::RawIngestEvent>,
        dataset_id: Option<&str>,
    ) -> Result<(usize, usize), GraphError> {
        let merge_policy = MergePolicy::default();
        let mut new_entities = 0usize;
        let mut new_relations = 0usize;
        let ds: Option<Arc<str>> = dataset_id.map(Arc::from);
        let ds_tag = self.intern_dataset_tag(dataset_id);

        for ev in events {
            let crate::parser::RawIngestEvent {
                src_id,
                src_type,
                src_metadata,
                dst_id,
                dst_type,
                dst_metadata,
                rel_type,
                rel_metadata,
                timestamp,
            } = ev;

            let src_sid = self.interner.intern(&src_id);
            if let Some(existing) = self.entities.get_mut(&src_sid) {
                Self::merge_metadata(&mut existing.metadata, &src_metadata, &merge_policy);
            } else {
                let mut entity = Entity::new(src_id.clone(), src_type.clone());
                entity.metadata = src_metadata;
                if let Some(ref id) = ds {
                    entity.dataset_id = Some(Arc::clone(id));
                }
                self.set_entity_type_tag(src_sid, &src_type);
                self.entities.insert(src_sid, entity);
                self.type_index.entry(src_type).or_default().insert(src_sid);
                self.reverse_adj.entry(src_sid).or_default();
                new_entities += 1;
            }

            let dst_sid = self.interner.intern(&dst_id);
            if let Some(existing) = self.entities.get_mut(&dst_sid) {
                Self::merge_metadata(&mut existing.metadata, &dst_metadata, &merge_policy);
            } else {
                let mut entity = Entity::new(dst_id.clone(), dst_type.clone());
                entity.metadata = dst_metadata;
                if let Some(ref id) = ds {
                    entity.dataset_id = Some(Arc::clone(id));
                }
                self.set_entity_type_tag(dst_sid, &dst_type);
                self.entities.insert(dst_sid, entity);
                self.type_index.entry(dst_type).or_default().insert(dst_sid);
                self.reverse_adj.entry(dst_sid).or_default();
                new_entities += 1;
            }

            if let Some(ref mut scorer) = self.anomaly_scorer {
                scorer.observe_entity(&src_id, timestamp);
                scorer.observe_entity(&dst_id, timestamp);
                scorer.observe_edge(&src_id, &dst_id);
            }

            let meta_offset = self.append_edge_metadata(&rel_type, &rel_metadata);
            let compact = CompactRelation {
                source_sid: src_sid,
                dest_sid: dst_sid,
                rel_type_tag: rel_type.to_u8(),
                timestamp,
                metadata_offset: meta_offset,
                dataset_tag: ds_tag,
                ingested_at_delta: 0,
            };

            // Fallible push first: a spill failure must not leave a dangling reverse edge (C3a).
            self.push_to_streaming(&compact)?;
            self.reverse_adj.entry(dst_sid).or_default().push(src_sid);
            self.on_streaming_edge_appended(src_sid, dst_sid);
            new_relations += 1;
        }

        Ok((new_entities, new_relations))
    }

    /// Enables anomaly scoring with backfilling from existing data.
    pub fn enable_anomaly_scoring(&mut self, weights: ScoringWeights) {
        let mut scorer = AnomalyScorer::new(weights);
        // Snapshot the strings out of the streaming layer first so
        // we don't hold the interner borrow alongside the read
        // guard inside `for_each_edge`. Order doesn't matter — the
        // scorer aggregates into HashMaps.
        let mut buf: Vec<(StrId, StrId, i64)> = Vec::new();
        self.streaming.for_each_edge(|src, edge| {
            buf.push((src, edge.dest_sid, edge.timestamp));
        });
        for (src_sid, dst_sid, timestamp) in buf {
            let src_str = self.interner.resolve(src_sid);
            let dst_str = self.interner.resolve(dst_sid);
            scorer.observe_entity(src_str, timestamp);
            scorer.observe_entity(dst_str, timestamp);
            scorer.observe_edge(src_str, dst_str);
        }
        scorer.finalize(self);
        self.anomaly_scorer = Some(scorer);
    }

    /// Finalizes the anomaly scorer (call after ingestion completes).
    pub fn finalize_anomaly_scorer(&mut self) {
        if let Some(mut scorer) = self.anomaly_scorer.take() {
            scorer.finalize(self);
            self.anomaly_scorer = Some(scorer);
        }
    }

    /// Returns bucketed relation counts grouped by relation type.
    ///
    /// `bucket_size_seconds` controls the bucket width (default 3600 = 1h).
    /// The output is **densified**: for each relation type, every bucket
    /// between that type's first and last event is emitted, including
    /// zero-count ones, so callers can distinguish "no events in this
    /// window" from "window truncated" without guessing from gaps.
    pub fn temporal_heatmap(
        &self,
        bucket_size_seconds: Option<i64>,
    ) -> Vec<(String, Vec<(i64, usize)>, i64)> {
        use std::collections::BTreeMap;

        // Clamp: 60s minimum (avoid pathological per-second bucketing),
        // 86400s maximum (> 1 day per bucket defeats the purpose).
        let bucket = bucket_size_seconds.unwrap_or(3600).clamp(60, 86_400);

        let mut by_type: HashMap<String, BTreeMap<i64, usize>> = HashMap::new();
        self.streaming.for_each_edge(|_src, edge| {
            let type_name = format!("{}", RelationType::from_u8(edge.rel_type_tag));
            let bkt = edge.timestamp - (edge.timestamp % bucket);
            *by_type
                .entry(type_name)
                .or_default()
                .entry(bkt)
                .or_insert(0) += 1;
        });

        let mut result: Vec<(String, Vec<(i64, usize)>, i64)> = by_type
            .into_iter()
            .map(|(type_name, bins)| {
                // Densify: fill zero buckets between min_key and max_key
                // so the UI sees the full timeline contour, not a sparse
                // BTreeMap that gets misread as "truncated output".
                let bins_vec: Vec<(i64, usize)> =
                    if let (Some(&first), Some(&last)) = (bins.keys().next(), bins.keys().last()) {
                        let mut out = Vec::new();
                        let mut t = first;
                        while t <= last {
                            out.push((t, bins.get(&t).copied().unwrap_or(0)));
                            t += bucket;
                        }
                        out
                    } else {
                        Vec::new()
                    };
                (type_name, bins_vec, bucket)
            })
            .collect();
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    }

    /// Returns timestamp distribution per entity type for sparkline visualization.
    pub fn timeline_data(&self) -> Vec<(String, i64, i64, Vec<(i64, usize)>)> {
        use std::collections::BTreeMap;
        let mut type_data: HashMap<String, BTreeMap<i64, usize>> = HashMap::new();
        let mut type_min: HashMap<String, i64> = HashMap::new();
        let mut type_max: HashMap<String, i64> = HashMap::new();

        self.streaming.for_each_edge(|src_sid, edge| {
            if let Some(src) = self.entities.get(&src_sid) {
                let type_name = format!("{}", src.entity_type);
                let hour = edge.timestamp - (edge.timestamp % 3600);
                *type_data
                    .entry(type_name.clone())
                    .or_default()
                    .entry(hour)
                    .or_insert(0) += 1;
                let min = type_min
                    .entry(type_name.clone())
                    .or_insert(edge.timestamp);
                if edge.timestamp < *min {
                    *min = edge.timestamp;
                }
                let max = type_max
                    .entry(type_name.clone())
                    .or_insert(edge.timestamp);
                if edge.timestamp > *max {
                    *max = edge.timestamp;
                }
            }
        });

        let mut result: Vec<(String, i64, i64, Vec<(i64, usize)>)> = type_data
            .into_iter()
            .map(|(type_name, bins)| {
                let min = *type_min.get(&type_name).unwrap_or(&0);
                let max = *type_max.get(&type_name).unwrap_or(&0);
                let bins_vec: Vec<(i64, usize)> = bins.into_iter().collect();
                (type_name, min, max, bins_vec)
            })
            .collect();
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    }

    /// Compacts old edges before cutoff into summary edges.
    pub fn compact_before(&mut self, cutoff: i64) -> Result<CompactionStats, GraphError> {
        let mut edges_before = 0usize;
        let mut edges_removed = 0usize;
        let mut groups_compacted = 0usize;

        // Materialize all edges into full Relations for grouping.
        // Read from streaming; same edge set as edge_store and we
        // need an owned snapshot anyway (the rebuild below wipes
        // self.edge_store mid-iteration).
        let mut snapshot: Vec<CompactRelation> = Vec::new();
        self.streaming.for_each_edge(|src_sid, edge| {
            // SAFETY: StreamEdge is layout-compatible with
            // CompactRelation; copy by transmute since both are
            // 32-byte #[repr(C)] structs with identical fields.
            let mut compact: CompactRelation = unsafe {
                std::ptr::read(edge as *const _ as *const CompactRelation)
            };
            // for_each_edge gives us the source from the table key;
            // streaming carries source_sid in the StreamEdge too,
            // but assert agreement defensively.
            debug_assert_eq!(compact.source_sid, src_sid);
            compact.source_sid = src_sid;
            snapshot.push(compact);
        });
        let mut groups: HashMap<(String, String, String), Vec<Relation>> = HashMap::new();
        for compact in &snapshot {
            edges_before += 1;
            let rel = self.materialize_relation(compact);
            let key = (
                rel.source_id.clone(),
                rel.dest_id.clone(),
                format!("{}", rel.rel_type),
            );
            groups.entry(key).or_default().push(rel);
        }

        let mut summary_edges: Vec<Relation> = Vec::new();
        let mut keep_edges: Vec<Relation> = Vec::new();

        for ((_src, _dst, _rt), edges) in &groups {
            let all_old = edges.iter().all(|e| e.timestamp < cutoff);
            if all_old && edges.len() > 1 {
                let earliest = edges.iter().map(|e| e.timestamp).min().unwrap();
                let latest = edges.iter().map(|e| e.timestamp).max().unwrap();
                let count = edges.len();
                edges_removed += count - 1;
                groups_compacted += 1;

                let mut summary = edges[0].clone();
                summary.timestamp = earliest;
                summary
                    .metadata
                    .insert("compacted_count".to_string(), count.to_string());
                summary
                    .metadata
                    .insert("compacted_latest".to_string(), latest.to_string());
                summary_edges.push(summary);
            } else {
                keep_edges.extend(edges.iter().cloned());
            }
        }

        // Rebuild with fresh metadata store and streaming backend
        self.streaming.clear();
        self.reverse_adj.clear();
        self.meta_store = MetadataStore::new();

        let all_edges: Vec<Relation> = keep_edges.into_iter().chain(summary_edges).collect();
        for rel in all_edges {
            let src_sid = self.interner.intern(&rel.source_id);
            let dst_sid = self.interner.intern(&rel.dest_id);
            let meta_offset = self.append_edge_metadata(&rel.rel_type, &rel.metadata);
            let ds_tag = self.intern_dataset_tag(rel.dataset_id.as_deref());
            let compact = CompactRelation {
                source_sid: src_sid,
                dest_sid: dst_sid,
                rel_type_tag: rel.rel_type.to_u8(),
                timestamp: rel.timestamp,
                metadata_offset: meta_offset,
                dataset_tag: ds_tag,
                ingested_at_delta: 0,
            };
            // Fallible push first: a spill failure must not leave a dangling reverse edge (C3a).
            self.push_to_streaming(&compact)?;
            self.reverse_adj.entry(dst_sid).or_default().push(src_sid);
        }
        self.streaming.finalize();

        for v in self.reverse_adj.values_mut() {
            v.sort_unstable();
            v.dedup();
        }

        for &&sid in self.entities.keys().collect::<Vec<_>>().iter() {
            self.reverse_adj.entry(sid).or_default();
        }

        self.edges_sorted = true; // finalize() sorted them
        // Heavy-logs #3.5: drop the NLF cache so the next matcher
        // call rebuilds against the post-mutation graph state.
        self.nlf = std::sync::OnceLock::new();
        self.khop_reach = std::sync::OnceLock::new();
        self.bump_mutation_version();
        Ok(CompactionStats {
            edges_before,
            edges_after: edges_before - edges_removed,
            edges_removed,
            groups_compacted,
        })
    }
}

/// Statistics returned by temporal compaction.
#[derive(serde::Serialize, Clone, Debug)]
pub struct CompactionStats {
    pub edges_before: usize,
    pub edges_after: usize,
    pub edges_removed: usize,
    pub groups_compacted: usize,
}

impl Default for GraphHunter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::Entity;
    use crate::hypothesis::{Hypothesis, HypothesisStep};
    use crate::relation::Relation;
    use crate::types::{EntityType, RelationType};

    /// SP-B Task 1: a custom `Other("SNAT")` rel-type name must survive the
    /// insert→materialize roundtrip. Before the fix `from_u8(254)` returns
    /// `Other("")` because the 1-byte tag can't encode the name.
    #[test]
    fn other_rel_type_name_survives_roundtrip() {
        let mut g = GraphHunter::new();
        let rel = Relation::new("a", "b", RelationType::Other("SNAT".to_string()), 100);
        let triple = (
            Entity::new("a", EntityType::IP),
            rel,
            Entity::new("b", EntityType::IP),
        );
        g.insert_triples(vec![triple], None).unwrap();
        let rels = g.get_relations("a");
        let snat = rels
            .iter()
            .find(|r| matches!(&r.rel_type, RelationType::Other(n) if n == "SNAT"))
            .expect("Other(\"SNAT\") must survive ingest");
        assert!(
            !snat.metadata.contains_key("_rel_type"),
            "_rel_type must be stripped from returned metadata"
        );
    }

    /// SP-B Task 1: `Other("")` (empty name) must NOT inject `_rel_type` into
    /// metadata, and must round-trip back to `Other("")` without leaking the
    /// internal key. Complements `other_rel_type_name_survives_roundtrip`.
    #[test]
    fn empty_other_rel_type_roundtrips_without_key() {
        let mut g = GraphHunter::new();
        g.insert_triples(vec![(
            Entity::new("a", EntityType::IP),
            Relation::new("a", "b", RelationType::Other(String::new()), 7),
            Entity::new("b", EntityType::IP),
        )], None).unwrap();
        let rels = g.get_relations("a");
        // Other("") injects no _rel_type; round-trips back to Other("").
        assert!(rels.iter().any(|r| matches!(&r.rel_type, RelationType::Other(n) if n.is_empty())));
        assert!(rels.iter().all(|r| !r.metadata.contains_key("_rel_type")));
    }

    /// SP-B Task 1: built-in rel-types must not be affected by the _rel_type
    /// injection logic — no extra key in returned metadata.
    #[test]
    fn builtin_rel_type_unaffected() {
        let mut g = GraphHunter::new();
        g.insert_triples(
            vec![(
                Entity::new("a", EntityType::IP),
                Relation::new("a", "b", RelationType::Connect, 100),
                Entity::new("b", EntityType::IP),
            )],
            None,
        )
        .unwrap();
        let rels = g.get_relations("a");
        assert!(rels.iter().any(|r| r.rel_type == RelationType::Connect));
        assert!(
            rels.iter().all(|r| !r.metadata.contains_key("_rel_type")),
            "builtin injects no _rel_type"
        );
    }

    /// C2 regression: after indexes are built on a finalized graph, a
    /// post-finalize `add_relation` must INVALIDATE both `nlf` and
    /// `khop_reach` so they rebuild tail-inclusively on the next hunt.
    ///
    /// Before the fix: `on_streaming_edge_appended` runs the incremental
    /// delta path which reads BASE neighbors only and silently succeeds,
    /// leaving both OnceLocks populated with stale (tail-blind) data.
    ///
    /// After the fix: the finalized-gate fires, both OnceLocks are reset
    /// to `OnceLock::new()` (empty), and the function returns early.
    #[test]
    fn post_finalize_tail_edge_is_visible_to_khop() {
        let mut g = GraphHunter::new();

        // Build A(User) --Auth--> B(Host) at t=100
        g.add_entity(Entity::new("A", EntityType::User)).unwrap();
        g.add_entity(Entity::new("B", EntityType::Host)).unwrap();
        g.add_relation(Relation::new("A", "B", RelationType::Auth, 100))
            .unwrap();

        // Finalize: sorts edges and arms the streaming base.
        g.sort_edges_by_timestamp().unwrap();
        assert!(g.streaming.is_finalized(), "should be finalized after sort");

        // Warm-up hunt: use a 2-step hypothesis so both NLF and khop_reach
        // are built (khop is skipped for single-step hypotheses per
        // `khop_reach::is_trivial`). Results may be empty — we only care
        // that the indexes are populated.
        let warmup = Hypothesis::new("warmup")
            .add_step(HypothesisStep::new(
                EntityType::User,
                RelationType::Auth,
                EntityType::Host,
            ))
            .add_step(HypothesisStep::new(
                EntityType::Host,
                RelationType::Auth,
                EntityType::User,
            ));
        let _ = g.search_temporal_pattern(&warmup, None, None);

        // Both indexes must be populated after the hunt.
        assert!(g.nlf.get().is_some(), "NLF must be built after warm-up hunt");
        assert!(
            g.khop_reach.get().is_some(),
            "khop_reach must be built after warm-up hunt"
        );

        // Post-finalize append: add new vertex C and edge B --Auth--> C.
        g.add_entity(Entity::new("C", EntityType::User)).unwrap();
        g.add_relation(Relation::new("B", "C", RelationType::Auth, 200))
            .unwrap();

        // After the fix: both OnceLocks must be invalidated (None) so the
        // next hunt rebuilds them against the full base+tail graph.
        assert!(
            g.nlf.get().is_none(),
            "NLF must be invalidated after post-finalize append (C2 fix)"
        );
        assert!(
            g.khop_reach.get().is_none(),
            "khop_reach must be invalidated after post-finalize append (C2 fix)"
        );
    }

    /// C3a regression: when `push_to_streaming` spills and returns
    /// `GraphError::Spill`, `add_relation` must propagate the error AND
    /// leave no dangling reverse edge for the destination entity.
    ///
    /// Before the fix: `reverse_adj[dst].push(src)` runs first, then the
    /// fallible `push_to_streaming` bails — leaving dst with a phantom
    /// src in its reverse-adjacency list even though the forward edge was
    /// never written.
    ///
    /// After the fix: `push_to_streaming` runs first; on error we return
    /// immediately before touching `reverse_adj`.
    #[test]
    fn spill_failure_leaves_no_dangling_reverse_edge() {
        use crate::errors::GraphError;

        let mut g = GraphHunter::with_spill_failing_backend();

        // Add source and destination entities.
        g.add_entity(Entity::new("A", EntityType::User)).unwrap();
        g.add_entity(Entity::new("B", EntityType::Host)).unwrap();

        // The streaming backend is armed to fail on the first spill.
        let result = g.add_relation(Relation::new("A", "B", RelationType::Auth, 100));

        // Must surface a Spill error.
        assert!(
            matches!(result, Err(GraphError::Spill(_))),
            "expected Err(GraphError::Spill(_)), got {:?}",
            result
        );

        // No dangling reverse edge: B's reverse-adjacency list must NOT
        // contain A.  Before the C3a fix the reverse push happened before
        // push_to_streaming, so a spill failure left dst with a phantom src.
        let b_sid = g.interner.get("B").expect("B was added");
        let dangling = g
            .reverse_adj
            .get(&b_sid)
            .map(|v| v.iter().any(|&s| s == g.interner.get("A").unwrap()))
            .unwrap_or(false);
        assert!(
            !dangling,
            "reverse_adj must not contain A->B after a spill failure (C3a)"
        );
    }

    /// Task 0 (snapshot-ingest prerequisite): `remove_entities_and_relations_by_dataset`
    /// uses `for_each_edge` to rebuild the streaming graph after removal.
    /// Before the `for_each_edge` tail fix, post-finalize tail edges were
    /// invisible: a remove-by-dataset call on a finalized graph silently lost
    /// every tail edge, even for datasets that were NOT being removed.
    ///
    /// This test asserts the "replace dataset" invariant: after calling
    /// `remove_entities_and_relations_by_dataset("ds-a")` on a finalized graph
    /// that also has post-finalize tail edges for "ds-b", the ds-b edges are
    /// fully preserved.
    #[test]
    fn snapshot_replace_by_dataset_is_idempotent() {
        let mut g = GraphHunter::new();

        // Dataset A: two entities + one edge inserted before finalize.
        g.insert_triples(
            vec![(
                Entity::new("a1", EntityType::User),
                Relation::new("a1", "a2", RelationType::Auth, 100),
                Entity::new("a2", EntityType::Host),
            )],
            Some("ds-a"),
        )
        .unwrap();

        // Dataset B: two entities + one edge inserted before finalize.
        g.insert_triples(
            vec![(
                Entity::new("b1", EntityType::User),
                Relation::new("b1", "b2", RelationType::Auth, 200),
                Entity::new("b2", EntityType::Host),
            )],
            Some("ds-b"),
        )
        .unwrap();

        // Finalize: sorts edges, arms streaming base.
        g.sort_edges_by_timestamp().unwrap();
        assert!(g.streaming.is_finalized());

        // Post-finalize: add a second ds-b edge — this lands in tails.
        g.insert_triples(
            vec![(
                Entity::new("b1", EntityType::User),
                Relation::new("b1", "b3", RelationType::Connect, 300),
                Entity::new("b3", EntityType::IP),
            )],
            Some("ds-b"),
        )
        .unwrap();

        // Sanity: 3 total edges (1 ds-a base + 2 ds-b: 1 base + 1 tail).
        assert_eq!(
            g.streaming_edge_count(),
            3,
            "should have 3 edges before removal"
        );

        // Remove ds-a. Before the fix, for_each_edge skipped tails so the
        // ds-b tail edge was silently dropped in the rebuild.
        let (entities_removed, relations_removed) =
            g.remove_entities_and_relations_by_dataset("ds-a").unwrap();
        assert_eq!(relations_removed, 1, "should remove exactly the 1 ds-a edge");
        assert!(entities_removed >= 1, "at least one ds-a entity removed");

        // After removal, ds-b edges must be intact (both base + tail).
        assert_eq!(
            g.streaming_edge_count(),
            2,
            "ds-b edges (base + tail) must survive remove of ds-a"
        );

        // Calling remove again is idempotent — no error, no further loss.
        let (e2, r2) = g.remove_entities_and_relations_by_dataset("ds-a").unwrap();
        assert_eq!(r2, 0, "second remove of ds-a is a no-op");
        assert_eq!(e2, 0, "no more ds-a entities");
        assert_eq!(
            g.streaming_edge_count(),
            2,
            "ds-b edges must still be intact after idempotent remove"
        );
    }

    /// P-2: the dispatch helper must pick the parallel path above the size
    /// threshold by default and respect explicit env overrides in both
    /// directions — all without touching the env var in the test.
    #[test]
    fn parallel_finalize_default_above_threshold() {
        // Large graph → parallel by default.
        assert!(
            should_finalize_parallel(60_000, 2_000_000, None),
            "large graph (vertex+edge both above threshold) should use parallel"
        );
        // Large by vertex count alone.
        assert!(
            should_finalize_parallel(60_000, 500, None),
            "high vertex count alone should trigger parallel"
        );
        // Large by edge count alone.
        assert!(
            should_finalize_parallel(100, 2_000_000, None),
            "high edge count alone should trigger parallel"
        );
        // Small graph → sequential by default.
        assert!(
            !should_finalize_parallel(100, 500, None),
            "small graph should stay sequential"
        );
        // Explicit opt-out wins over large graph.
        assert!(
            !should_finalize_parallel(60_000, 2_000_000, Some(false)),
            "GRAPHHUNTER_PARALLEL_FINALIZE=0 must override threshold"
        );
        // Explicit opt-in wins over small graph.
        assert!(
            should_finalize_parallel(100, 500, Some(true)),
            "GRAPHHUNTER_PARALLEL_FINALIZE=1 must override threshold"
        );
    }

    /// Task 3 — pin the incremental behaviour of `entity_type_counts()`.
    ///
    /// `type_index` is a `HashMap<EntityType, HashSet<StrId>>` maintained by
    /// every node-insertion site in `add_entity` (and the bulk helpers that
    /// call it).  `entity_type_counts()` reads `HashSet::len()` per entry, so
    /// reads are O(distinct types), not O(total nodes).  This test verifies
    /// that the per-type counts and the grand total returned by
    /// `entity_count()` are correct immediately after insertion — no
    /// finalize / compute_scores required.
    #[test]
    fn entity_type_counts_reflects_inserts_incrementally() {
        let mut g = GraphHunter::new();

        // Three IPs, two Hosts, one User.
        for i in 0..3u32 {
            g.add_entity(Entity::new(&format!("ip-{}", i), EntityType::IP))
                .expect("ip insert");
        }
        for i in 0..2u32 {
            g.add_entity(Entity::new(&format!("host-{}", i), EntityType::Host))
                .expect("host insert");
        }
        g.add_entity(Entity::new("user-0", EntityType::User))
            .expect("user insert");

        // Grand-total node counter must equal 6.
        assert_eq!(g.entity_count(), 6, "entity_count() must equal total inserted");

        // Collect the per-type map (sorted by name, so deterministic).
        let counts: std::collections::HashMap<String, usize> =
            g.entity_type_counts().into_iter().collect();

        assert_eq!(counts.get("IP").copied().unwrap_or(0), 3, "IP count");
        assert_eq!(counts.get("Host").copied().unwrap_or(0), 2, "Host count");
        assert_eq!(counts.get("User").copied().unwrap_or(0), 1, "User count");

        // No phantom types must appear.
        assert_eq!(counts.len(), 3, "exactly 3 entity types in graph");

        // Add one more IP and verify the counter updates immediately (O(1) path).
        g.add_entity(Entity::new("ip-99", EntityType::IP))
            .expect("late ip insert");
        let counts2: std::collections::HashMap<String, usize> =
            g.entity_type_counts().into_iter().collect();
        assert_eq!(counts2.get("IP").copied().unwrap_or(0), 4, "IP count after late insert");
        assert_eq!(g.entity_count(), 7, "entity_count() after late insert");
    }
}
