//! FFI bridge to libgraphmatch — SIMD-accelerated temporal graph pattern matching.
//!
//! When the `simd` feature is enabled, this module compiles against the C++
//! `libgraphmatch` static library and provides `build_gm_graph()` and
//! `run_simd_search()` for use by `GraphHunter::search_temporal_pattern_simd()`.
//!
//! When the `simd` feature is disabled, a stub module is provided.
//!
//! # Safety contract with libgraphmatch
//!
//! Every `unsafe` block in this crate is annotated with a `// SAFETY:` line
//! that cites the invariant being relied on. The block-level invariants
//! delegate to two cross-cutting guarantees established by the C ABI
//! (documented in `libgraphmatch/include/graphmatch/graphmatch.h`):
//!
//! 1. **Pointer ownership**: every `gm_*_new()` returns a non-null owning
//!    handle; every `gm_*_free()` accepts such a handle and is the only
//!    legal way to release it. The RAII wrappers `GmGraph`, `GmMatcher`,
//!    `GmResults` enforce single ownership + `Drop`-based release.
//! 2. **ABI version check**: `ensure_abi_compatible()` runs once per
//!    process before any other FFI call. A version mismatch panics
//!    before any pointer layout can drift, so downstream `unsafe` blocks
//!    may assume the C header matches the linked binary.

#![cfg_attr(feature = "simd", warn(clippy::undocumented_unsafe_blocks))]
#![warn(clippy::missing_safety_doc)]

#[cfg(feature = "simd")]
pub mod ffi {
    use std::collections::HashMap;
    use std::ffi::{CStr, c_char, c_void};
    use std::marker::PhantomData;

    use graph_hunter_core::graph::{GraphHunter, HuntResult};
    use graph_hunter_core::hypothesis::Hypothesis;
    use graph_hunter_core::interner::{StrId, StringInterner};
    use graph_hunter_core::types::EntityType;

    // -----------------------------------------------------------------
    // C ABI declarations (from libgraphmatch/include/graphmatch/graphmatch.h)
    // -----------------------------------------------------------------

    // SAFETY (block): these extern "C" declarations must match the C
    // header byte-for-byte. Any drift in parameter types, return types,
    // or function names is caught at runtime by `ensure_abi_compatible`
    // (ABI version bump) or at link time (missing symbol). The header
    // asserts C calling convention + POD argument types, both satisfied.
    unsafe extern "C" {
        fn gm_graph_new() -> *mut c_void;
        fn gm_graph_add_node(g: *mut c_void, id: u32, entity_type: u8);
        fn gm_graph_add_edge(g: *mut c_void, src: u32, dst: u32, rel_type: u8, timestamp: i64);
        fn gm_graph_finalize(g: *mut c_void);
        fn gm_graph_free(g: *mut c_void);
        fn gm_graph_node_count(g: *const c_void) -> u32;
        fn gm_graph_edge_count(g: *const c_void) -> u32;

        fn gm_matcher_new(g: *const c_void) -> *mut c_void;
        fn gm_matcher_set_start_type(m: *mut c_void, entity_type: u8);
        fn gm_matcher_add_step(
            m: *mut c_void,
            entity_type: u8,
            rel_type: u8,
            enforce_causality: i32,
        );
        fn gm_matcher_set_time_window(m: *mut c_void, window_ms: i64);
        fn gm_matcher_run(m: *mut c_void, max_results: u32, min_score: f32) -> *mut c_void;
        fn gm_matcher_free(m: *mut c_void);

        fn gm_results_count(r: *const c_void) -> u32;
        fn gm_results_get_path(r: *const c_void, idx: u32, path_len: *mut u32) -> *const u32;
        fn gm_results_get_timestamps(r: *const c_void, idx: u32) -> *const i64;
        fn gm_results_free(r: *mut c_void);

        fn gm_simd_isa() -> *const c_char;
        fn gm_abi_version() -> u32;
    }

    // -----------------------------------------------------------------
    // ABI version guard (F3.5)
    // -----------------------------------------------------------------

    /// The ABI version this Rust crate was compiled against. Must match
    /// the `GM_ABI_VERSION` in libgraphmatch's C header. Bump both sides
    /// together on breaking ABI changes (new required function, handle
    /// layout change, numeric tag shift, etc).
    const EXPECTED_ABI_VERSION: u32 = 1;

    /// Pure logic of the ABI guard, factored out so tests can exercise
    /// a synthetic mismatch without re-triggering the one-shot `Once` in
    /// [`ensure_abi_compatible`]. Returns an `Err` explaining the drift
    /// when the two versions disagree, `Ok(())` otherwise. Callers that
    /// must not continue on mismatch (the production path) panic on
    /// `Err`; tests inspect the message.
    pub fn check_abi_compat(got: u32, expected: u32) -> Result<(), String> {
        if got == expected {
            Ok(())
        } else {
            Err(format!(
                "libgraphmatch ABI mismatch: linked lib reports v{got}, this \
                 Rust crate was built against v{expected}. Rebuild libgraphmatch \
                 or the `graph_hunter_matcher_ffi` crate so both agree (bump \
                 GM_ABI_VERSION and EXPECTED_ABI_VERSION together)."
            ))
        }
    }

    /// Verifies the dynamically-linked libgraphmatch exports an ABI
    /// version this crate knows how to call. Called from public entry
    /// points on first use via `std::sync::Once`. Panics on mismatch —
    /// better to crash loudly than to let pointer-layout drift silently
    /// corrupt memory. Panicking at init is safe here because the FFI
    /// hasn't touched any state yet.
    fn ensure_abi_compatible() {
        static CHECK: std::sync::Once = std::sync::Once::new();
        CHECK.call_once(|| {
            // SAFETY: gm_abi_version takes no arguments and cannot touch
            // any uninitialized state — it reads a compile-time constant
            // from libgraphmatch and returns it. Safe to call before any
            // other FFI interaction.
            let got = unsafe { gm_abi_version() };
            if let Err(msg) = check_abi_compat(got, EXPECTED_ABI_VERSION) {
                panic!("{msg}");
            }
        });
    }

    // -----------------------------------------------------------------
    // RAII wrappers — typestate per ADR-002
    // -----------------------------------------------------------------

    /// Typestate marker: `GmGraph` is still open for `add_node` /
    /// `add_edge`. Not `Send`/`Sync` because the C++ side mutates
    /// internal structures during population.
    pub struct Building;

    /// Typestate marker: `gm_graph_finalize` has run, the CSR layout is
    /// frozen, and the graph is safe to share across threads for read
    /// access (matcher run).
    pub struct Finalized;

    /// Owning wrapper for `gm_graph_t*` parameterized by construction
    /// state. Calls `gm_graph_free` on drop regardless of state.
    ///
    /// Typestate transitions: `GmGraph::<Building>::new()` →
    /// `.add_node(..)` / `.add_edge(..)` → `.finalize()` consumes the
    /// `Building` and returns `GmGraph<Finalized>`. The compiler
    /// prevents calling mutators on a finalized graph or reads on an
    /// unfinalized one.
    pub struct GmGraph<S> {
        ptr: *mut c_void,
        _state: PhantomData<S>,
    }

    impl GmGraph<Building> {
        fn new() -> Self {
            // SAFETY: gm_graph_new has no preconditions and returns an
            // owning handle. Null means allocation failed — asserted
            // below so downstream blocks may assume non-null `self.ptr`.
            let ptr = unsafe { gm_graph_new() };
            assert!(!ptr.is_null(), "gm_graph_new returned null");
            Self {
                ptr,
                _state: PhantomData,
            }
        }

        fn add_node(&self, id: u32, entity_type: u8) {
            // SAFETY: self.ptr is non-null (established in new()) and
            // still in the Building state (typestate enforced at compile
            // time — finalize() consumes self). id and entity_type are
            // plain u32/u8 with no invariants on the C side.
            unsafe { gm_graph_add_node(self.ptr, id, entity_type) }
        }

        fn add_edge(&self, src: u32, dst: u32, rel_type: u8, timestamp: i64) {
            // SAFETY: same as add_node — Building state, non-null ptr,
            // POD arguments. The C side tolerates src/dst that haven't
            // been registered via add_node (they become dangling until
            // finalize rejects them).
            unsafe { gm_graph_add_edge(self.ptr, src, dst, rel_type, timestamp) }
        }

        /// Consume the builder; the C++ library freezes CSR and sorts
        /// the edge lists. Returns a read-only view safe to share.
        fn finalize(self) -> GmGraph<Finalized> {
            // SAFETY: self.ptr is non-null and still in Building state
            // (we are consuming self). After this call the C graph is
            // immutable; we transfer the same pointer to GmGraph<Finalized>
            // and forget self to avoid the Drop running gm_graph_free
            // while the new wrapper also owns the pointer.
            unsafe { gm_graph_finalize(self.ptr) };
            let ptr = self.ptr;
            std::mem::forget(self);
            GmGraph {
                ptr,
                _state: PhantomData,
            }
        }
    }

    impl GmGraph<Finalized> {
        fn as_const_ptr(&self) -> *const c_void {
            self.ptr as *const c_void
        }
    }

    impl<S> Drop for GmGraph<S> {
        fn drop(&mut self) {
            if !self.ptr.is_null() {
                // SAFETY: Drop runs exactly once per wrapper. self.ptr
                // was either obtained from gm_graph_new() in Building
                // state or moved in from a Building wrapper that was
                // mem::forget'd in finalize() — either way, this is
                // the unique owner releasing the C allocation.
                unsafe { gm_graph_free(self.ptr) }
            }
        }
    }

    // SAFETY (Send): GmGraph<Finalized> holds a *mut c_void that, after
    // finalize(), points to a frozen CSR layout in libgraphmatch. The C
    // side has no remaining internal threads or caches, so transferring
    // the handle across threads is sound.
    unsafe impl Send for GmGraph<Finalized> {}

    // SAFETY (Sync): gm_matcher_new + gm_matcher_run only issue read
    // queries against the finalized graph. The C side documents those
    // reads as thread-safe (no shared mutable state is touched). We
    // never expose &mut GmGraph<Finalized>, so Rust callers cannot
    // mutate either.
    unsafe impl Sync for GmGraph<Finalized> {}

    /// Owning wrapper for `gm_matcher_t*`. Calls `gm_matcher_free` on
    /// drop. Holds a borrow of the finalized graph it was created from
    /// so the graph cannot be dropped while the matcher is live.
    struct GmMatcher<'g> {
        ptr: *mut c_void,
        _graph: PhantomData<&'g GmGraph<Finalized>>,
    }

    impl<'g> GmMatcher<'g> {
        fn new(graph: &'g GmGraph<Finalized>) -> Option<Self> {
            // SAFETY: graph is a valid finalized graph (typestate). The
            // returned pointer is either a valid owning handle or null,
            // which we filter out in the branch below.
            let ptr = unsafe { gm_matcher_new(graph.as_const_ptr()) };
            if ptr.is_null() {
                None
            } else {
                Some(Self {
                    ptr,
                    _graph: PhantomData,
                })
            }
        }

        fn set_start_type(&self, entity_type: u8) {
            // SAFETY: self.ptr is non-null (constructed via new() above,
            // null case filtered out). entity_type is a POD u8.
            unsafe { gm_matcher_set_start_type(self.ptr, entity_type) }
        }

        fn add_step(&self, entity_type: u8, rel_type: u8, enforce_causality: i32) {
            // SAFETY: self.ptr non-null; all arguments are POD with no
            // invariants enforced by the C side (unknown tags are
            // treated as no-match at run time, not UB).
            unsafe { gm_matcher_add_step(self.ptr, entity_type, rel_type, enforce_causality) }
        }

        fn set_time_window(&self, window_ms: i64) {
            // SAFETY: self.ptr non-null; window_ms may be any i64 (the
            // C side clamps negatives to 0).
            unsafe { gm_matcher_set_time_window(self.ptr, window_ms) }
        }

        fn run(&self, max_results: u32, min_score: f32) -> Option<GmResults> {
            // SAFETY: self.ptr non-null; the returned results handle is
            // either owning (we wrap it) or null (we return None). The
            // 'g lifetime prevents the graph from being dropped while
            // the matcher — and therefore the results — is still live.
            let results_ptr = unsafe { gm_matcher_run(self.ptr, max_results, min_score) };
            if results_ptr.is_null() {
                None
            } else {
                Some(GmResults { ptr: results_ptr })
            }
        }
    }

    impl Drop for GmMatcher<'_> {
        fn drop(&mut self) {
            if !self.ptr.is_null() {
                // SAFETY: Drop runs once per matcher. self.ptr was
                // returned by gm_matcher_new() and has not been freed
                // elsewhere (no move-out or clone path exists).
                unsafe { gm_matcher_free(self.ptr) }
            }
        }
    }

    /// Owning wrapper for `gm_results_t*`.
    struct GmResults {
        ptr: *mut c_void,
    }

    impl GmResults {
        fn count(&self) -> u32 {
            // SAFETY: self.ptr is a non-null results handle (only
            // constructed from gm_matcher_run's non-null return). The
            // C side treats the argument as read-only.
            unsafe { gm_results_count(self.ptr as *const c_void) }
        }

        fn get_path(&self, idx: u32) -> Option<&[u32]> {
            let mut len: u32 = 0;
            // SAFETY: self.ptr is a valid results handle; &mut len is a
            // valid out-pointer to a local u32. idx is untrusted — the
            // C side bounds-checks internally and returns null for OOR.
            let ptr = unsafe { gm_results_get_path(self.ptr as *const c_void, idx, &mut len) };
            if ptr.is_null() || len == 0 {
                return None;
            }
            // SAFETY: ptr is non-null (checked); the C side guarantees
            // a contiguous array of `len` u32s, aligned and readable.
            // The slice borrows from &self so the returned reference
            // cannot outlive the GmResults wrapper.
            Some(unsafe { std::slice::from_raw_parts(ptr, len as usize) })
        }

        fn get_timestamps(&self, idx: u32) -> Option<&[i64]> {
            // SAFETY: self.ptr is a valid results handle; idx is
            // bounds-checked internally. Null = no timestamps for idx.
            let ptr = unsafe { gm_results_get_timestamps(self.ptr as *const c_void, idx) };
            if ptr.is_null() {
                return None;
            }
            // Timestamps array length = path_len - 1
            let mut path_len: u32 = 0;
            // SAFETY: same invariants as the get_path call above — we
            // only use the out-parameter `path_len`, discarding the
            // path pointer itself.
            let _ = unsafe { gm_results_get_path(self.ptr as *const c_void, idx, &mut path_len) };
            if path_len <= 1 {
                return None;
            }
            // SAFETY: ptr non-null (checked); path_len > 1 (checked).
            // libgraphmatch guarantees (path_len - 1) valid i64 slots,
            // aligned and readable, living as long as self.
            Some(unsafe { std::slice::from_raw_parts(ptr, (path_len - 1) as usize) })
        }
    }

    impl Drop for GmResults {
        fn drop(&mut self) {
            if !self.ptr.is_null() {
                // SAFETY: Drop runs once per results wrapper. self.ptr
                // was returned by gm_matcher_run and has not been freed
                // elsewhere — no move-out or clone path exists.
                unsafe { gm_results_free(self.ptr) }
            }
        }
    }

    // -----------------------------------------------------------------
    // OtherTypeMap — dynamic tag assignment for EntityType::Other
    // -----------------------------------------------------------------

    /// Maps `EntityType::Other(name)` to unique u8 tags >= 16.
    struct OtherTypeMap {
        name_to_tag: HashMap<String, u8>,
        next_tag: u8,
    }

    impl OtherTypeMap {
        fn new() -> Self {
            Self {
                name_to_tag: HashMap::new(),
                next_tag: 16, // GM_ENTITY_OTHER_BASE
            }
        }

        fn get_or_assign(&mut self, name: &str) -> u8 {
            if let Some(&tag) = self.name_to_tag.get(name) {
                return tag;
            }
            let tag = self.next_tag;
            assert!(
                tag < 254,
                "exhausted EntityType::Other tag space (max 238 custom types)"
            );
            self.next_tag += 1;
            self.name_to_tag.insert(name.to_string(), tag);
            tag
        }

        /// Convert an EntityType to its u8 tag, dynamically assigning tags for Other.
        fn entity_type_to_tag(&mut self, et: &EntityType) -> u8 {
            match et {
                EntityType::Other(name) => self.get_or_assign(name),
                _ => et.to_u8(),
            }
        }

        /// Read-only lookup — returns 254 (Any) if the Other name wasn't registered.
        fn entity_type_to_tag_readonly(&self, et: &EntityType) -> u8 {
            match et {
                EntityType::Other(name) => {
                    self.name_to_tag.get(name.as_str()).copied().unwrap_or(254)
                }
                _ => et.to_u8(),
            }
        }
    }

    // -----------------------------------------------------------------
    // CachedSimdGraph — cached C++ graph for reuse across searches
    // -----------------------------------------------------------------

    /// Holds the compiled C++ graph and its associated metadata.
    /// Rebuilt lazily when the Rust graph mutates.
    ///
    /// # Double-drop impossibility (ADR-002 typestate)
    ///
    /// `CachedSimdGraph` deliberately implements neither [`Clone`] nor
    /// [`Copy`]. Rust's move semantics therefore statically prevent the
    /// same C++ handle from being freed twice — the compiler rejects any
    /// attempt to duplicate the wrapper, which is the only legal path to
    /// the underlying `gm_graph_t*`. The following example is part of
    /// this crate's public contract and is validated by `cargo test`:
    ///
    /// ```compile_fail
    /// # #[cfg(feature = "simd")] fn f() {
    /// use graph_hunter_core::GraphHunter;
    /// use graph_hunter_matcher_ffi::ffi;
    /// let g = GraphHunter::new();
    /// let cached = ffi::build_gm_graph(&g);
    /// let _dup = cached.clone(); // error[E0599]: no method named `clone`
    /// # }
    /// ```
    pub struct CachedSimdGraph {
        graph: GmGraph<Finalized>,
        other_type_map: OtherTypeMap,
    }

    // -----------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------

    /// Returns true if the SIMD matcher is compiled in.
    pub fn simd_available() -> bool {
        true
    }

    /// Returns the SIMD ISA name detected by the C++ library.
    pub fn simd_isa_name() -> &'static str {
        ensure_abi_compatible();
        // SAFETY: gm_simd_isa takes no arguments and returns a pointer
        // to a static null-terminated C string owned by libgraphmatch
        // (compiled-in literal). The pointer is valid for the whole
        // process lifetime, so the 'static return lifetime is sound.
        // Null is treated defensively even though the C side does not
        // document it as a possibility.
        unsafe {
            let ptr = gm_simd_isa();
            if ptr.is_null() {
                return "unknown";
            }
            CStr::from_ptr(ptr).to_str().unwrap_or("unknown")
        }
    }

    /// Exposes the ABI version advertised by the linked libgraphmatch.
    /// Public for diagnostics and tests — `ensure_abi_compatible()` is
    /// already called from the public entry points, so normal callers
    /// don't need to use this directly.
    pub fn abi_version() -> u32 {
        // SAFETY: gm_abi_version takes no arguments and reads a
        // compile-time constant. Always safe regardless of init order.
        unsafe { gm_abi_version() }
    }

    /// The ABI version this Rust crate was built against. Publicly
    /// exposed so tests can `assert_eq!(expected_abi_version(),
    /// abi_version())` without duplicating the constant.
    pub fn expected_abi_version() -> u32 {
        EXPECTED_ABI_VERSION
    }

    /// Build a C++ graph from the current Rust graph state.
    pub fn build_gm_graph(hunter: &GraphHunter) -> CachedSimdGraph {
        ensure_abi_compatible();

        let mut other_map = OtherTypeMap::new();
        let builder = GmGraph::<Building>::new();

        for (&sid, entity) in &hunter.entities {
            let node_id = sid.index() as u32;
            let type_tag = other_map.entity_type_to_tag(&entity.entity_type);
            builder.add_node(node_id, type_tag);
        }

        hunter.streaming.for_each_edge(|src_sid, edge| {
            builder.add_edge(
                src_sid.index() as u32,
                edge.dest_sid.index() as u32,
                edge.rel_type_tag,
                edge.timestamp,
            );
        });

        let gm = builder.finalize();

        // SAFETY (both calls): gm is a finalized graph (typestate
        // enforced — finalize() consumed the Building wrapper). Both
        // functions are documented as const-correct reads over a
        // finalized graph, returning plain u32 counts.
        let nc = unsafe { gm_graph_node_count(gm.as_const_ptr()) };
        let ec = unsafe { gm_graph_edge_count(gm.as_const_ptr()) };
        eprintln!(
            "[simd_matcher] Built C++ graph: {} nodes, {} edges, ISA={}",
            nc,
            ec,
            simd_isa_name()
        );

        CachedSimdGraph {
            graph: gm,
            other_type_map: other_map,
        }
    }

    /// Execute a SIMD-accelerated pattern search.
    pub fn run_simd_search(
        cached: &CachedSimdGraph,
        interner: &StringInterner,
        hypothesis: &Hypothesis,
        time_window: Option<(i64, i64)>,
        max_results: Option<usize>,
    ) -> Vec<HuntResult> {
        let Some(matcher) = GmMatcher::new(&cached.graph) else {
            return Vec::new();
        };

        let start_tag = cached
            .other_type_map
            .entity_type_to_tag_readonly(&hypothesis.steps[0].origin_type);
        matcher.set_start_type(start_tag);

        for step in &hypothesis.steps {
            let dest_tag = cached
                .other_type_map
                .entity_type_to_tag_readonly(&step.dest_type);
            let rel_tag = step.relation_type.to_u8();
            matcher.add_step(dest_tag, rel_tag, 1);
        }

        if let Some((start, end)) = time_window {
            let window_ms = end - start;
            if window_ms > 0 {
                matcher.set_time_window(window_ms);
            }
        }

        let cap = max_results.unwrap_or(10_000) as u32;
        let Some(results) = matcher.run(cap, 0.0) else {
            return Vec::new();
        };
        let count = results.count();

        let mut hunt_results = Vec::with_capacity(count as usize);

        for i in 0..count {
            if let Some(path_ids) = results.get_path(i) {
                let path_strings: Vec<std::sync::Arc<str>> = path_ids
                    .iter()
                    .map(|&node_id| {
                        let sid = StrId::from_raw(node_id);
                        interner.resolve_arc(sid)
                    })
                    .collect();

                // Post-filter: enforce absolute time window bounds
                if let Some((tw_start, tw_end)) = time_window {
                    if let Some(timestamps) = results.get_timestamps(i) {
                        let ts_ok = timestamps.iter().all(|&ts| ts >= tw_start && ts <= tw_end);
                        if !ts_ok {
                            continue;
                        }
                    }
                }

                hunt_results.push(path_strings);
            }
        }

        hunt_results
    }
}

#[cfg(not(feature = "simd"))]
pub mod ffi {
    use graph_hunter_core::graph::{GraphHunter, HuntResult};
    use graph_hunter_core::hypothesis::Hypothesis;
    use graph_hunter_core::interner::StringInterner;

    /// Placeholder — no C++ graph when SIMD is disabled.
    pub struct CachedSimdGraph;

    pub fn simd_available() -> bool {
        false
    }

    pub fn simd_isa_name() -> &'static str {
        "none"
    }

    pub fn build_gm_graph(_hunter: &GraphHunter) -> CachedSimdGraph {
        CachedSimdGraph
    }

    pub fn run_simd_search(
        _cached: &CachedSimdGraph,
        _interner: &StringInterner,
        _hypothesis: &Hypothesis,
        _time_window: Option<(i64, i64)>,
        _max_results: Option<usize>,
    ) -> Vec<HuntResult> {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// Caller-facing entry point. Previously lived as
// `GraphHunter::search_temporal_pattern_simd` inside graph.rs; moved here in
// F2.13 so the graph_hunter_core crate stops naming libgraphmatch. Callers
// that used to write `g.search_temporal_pattern_simd(...)` now write
// `graph_hunter_matcher_ffi::search_temporal_pattern_simd(&g, ...)`.
// ---------------------------------------------------------------------------

use graph_hunter_core::errors::GraphError;
use graph_hunter_core::graph::{GraphHunter, HuntResult};
use graph_hunter_core::hypothesis::Hypothesis;

/// SIMD-accelerated temporal pattern search via the C++ libgraphmatch
/// backend. Falls back to `search_temporal_pattern_smart` (when a
/// finalized scorer is available) or `search_temporal_pattern` whenever
/// the runtime-detected ISA is not an AVX2-or-better SIMD target, or
/// when the hypothesis carries predicates the C++ matcher cannot
/// evaluate yet.
#[cfg(feature = "simd")]
pub fn search_temporal_pattern_simd(
    hunter: &GraphHunter,
    hypothesis: &Hypothesis,
    time_window: Option<(i64, i64)>,
    max_results: Option<usize>,
) -> Result<(Vec<HuntResult>, bool), GraphError> {
    hypothesis
        .validate()
        .map_err(GraphError::InvalidHypothesis)?;

    let cap = max_results.unwrap_or(10_000);

    // D1 stages 1–4: when the planner picks any LFTJ variant
    // (triangle, K4, K5, C6), short-circuit to `search_temporal_pattern`
    // which already routes to the corresponding LFTJ enumerator.
    // Otherwise fall through to the C++ SIMD backend below. The
    // dispatch decision is a pure function of the hypothesis and
    // process env — no graph access — so this is cheap.
    if !matches!(
        graph_hunter_core::planner::plan(hypothesis),
        graph_hunter_core::planner::DispatchPlan::DfsMatch
    ) {
        return hunter.search_temporal_pattern(hypothesis, time_window, max_results);
    }

    let has_predicates = hypothesis
        .steps
        .iter()
        .any(|s| !s.edge_predicates.is_empty() || !s.dest_predicates.is_empty());

    let isa = ffi::simd_isa_name();
    if matches!(isa, "scalar" | "none" | "unknown") || has_predicates {
        let scorer_ready = hunter
            .anomaly_scorer
            .as_ref()
            .map(|s| s.is_finalized())
            .unwrap_or(false);
        return if scorer_ready {
            hunter.search_temporal_pattern_smart(hypothesis, time_window, cap)
        } else {
            hunter.search_temporal_pattern(hypothesis, time_window, max_results)
        };
    }

    let cached = ffi::build_gm_graph(hunter);
    let results = ffi::run_simd_search(
        &cached,
        &hunter.interner,
        hypothesis,
        time_window,
        max_results,
    );
    let truncated = results.len() >= cap;
    let results = hunter.apply_aggregation(results, hypothesis);
    Ok((results, truncated))
}

/// Pure-Rust fallback used when the `simd` feature is disabled.
#[cfg(not(feature = "simd"))]
pub fn search_temporal_pattern_simd(
    hunter: &GraphHunter,
    hypothesis: &Hypothesis,
    time_window: Option<(i64, i64)>,
    max_results: Option<usize>,
) -> Result<(Vec<HuntResult>, bool), GraphError> {
    let scorer_ready = hunter
        .anomaly_scorer
        .as_ref()
        .map(|s| s.is_finalized())
        .unwrap_or(false);
    if scorer_ready {
        let cap = max_results.unwrap_or(10_000);
        hunter.search_temporal_pattern_smart(hypothesis, time_window, cap)
    } else {
        hunter.search_temporal_pattern(hypothesis, time_window, max_results)
    }
}
