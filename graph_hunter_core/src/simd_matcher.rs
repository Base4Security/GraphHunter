//! FFI bridge to libgraphmatch — SIMD-accelerated temporal graph pattern matching.
//!
//! When the `simd` feature is enabled, this module compiles against the C++
//! `libgraphmatch` static library and provides `build_gm_graph()` and
//! `run_simd_search()` for use by `GraphHunter::search_temporal_pattern_simd()`.
//!
//! When the `simd` feature is disabled, a stub module is provided.

#[cfg(feature = "simd")]
pub mod ffi {
    use std::collections::HashMap;
    use std::ffi::{c_char, c_void, CStr};

    use crate::graph::{GraphHunter, HuntResult};
    use crate::hypothesis::Hypothesis;
    use crate::interner::{StrId, StringInterner};
    use crate::types::EntityType;

    // -----------------------------------------------------------------
    // C ABI declarations (from libgraphmatch/include/graphmatch/graphmatch.h)
    // -----------------------------------------------------------------

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
        fn gm_matcher_add_step(m: *mut c_void, entity_type: u8, rel_type: u8, enforce_causality: i32);
        fn gm_matcher_set_time_window(m: *mut c_void, window_ms: i64);
        fn gm_matcher_run(m: *mut c_void, max_results: u32, min_score: f32) -> *mut c_void;
        fn gm_matcher_free(m: *mut c_void);

        fn gm_results_count(r: *const c_void) -> u32;
        fn gm_results_get_path(r: *const c_void, idx: u32, path_len: *mut u32) -> *const u32;
        fn gm_results_get_timestamps(r: *const c_void, idx: u32) -> *const i64;
        fn gm_results_free(r: *mut c_void);

        fn gm_simd_isa() -> *const c_char;
    }

    // -----------------------------------------------------------------
    // RAII wrappers
    // -----------------------------------------------------------------

    /// Owning wrapper for `gm_graph_t*`. Calls `gm_graph_free` on drop.
    /// After `finalize()`, the underlying C++ graph is read-only and safe
    /// for concurrent access (Send + Sync).
    pub struct GmGraph {
        ptr: *mut c_void,
    }

    impl GmGraph {
        fn new() -> Self {
            let ptr = unsafe { gm_graph_new() };
            assert!(!ptr.is_null(), "gm_graph_new returned null");
            Self { ptr }
        }

        fn add_node(&self, id: u32, entity_type: u8) {
            unsafe { gm_graph_add_node(self.ptr, id, entity_type) }
        }

        fn add_edge(&self, src: u32, dst: u32, rel_type: u8, timestamp: i64) {
            unsafe { gm_graph_add_edge(self.ptr, src, dst, rel_type, timestamp) }
        }

        fn finalize(&self) {
            unsafe { gm_graph_finalize(self.ptr) }
        }

        fn as_const_ptr(&self) -> *const c_void {
            self.ptr as *const c_void
        }
    }

    impl Drop for GmGraph {
        fn drop(&mut self) {
            if !self.ptr.is_null() {
                unsafe { gm_graph_free(self.ptr) }
            }
        }
    }

    // After finalize(), the C++ graph is immutable — safe to share.
    unsafe impl Send for GmGraph {}
    unsafe impl Sync for GmGraph {}

    /// Owning wrapper for `gm_results_t*`.
    struct GmResults {
        ptr: *mut c_void,
    }

    impl GmResults {
        fn count(&self) -> u32 {
            unsafe { gm_results_count(self.ptr as *const c_void) }
        }

        fn get_path(&self, idx: u32) -> Option<&[u32]> {
            let mut len: u32 = 0;
            let ptr = unsafe { gm_results_get_path(self.ptr as *const c_void, idx, &mut len) };
            if ptr.is_null() || len == 0 {
                return None;
            }
            Some(unsafe { std::slice::from_raw_parts(ptr, len as usize) })
        }

        fn get_timestamps(&self, idx: u32) -> Option<&[i64]> {
            let ptr = unsafe { gm_results_get_timestamps(self.ptr as *const c_void, idx) };
            if ptr.is_null() {
                return None;
            }
            // Timestamps array length = path_len - 1
            let mut path_len: u32 = 0;
            let _ = unsafe { gm_results_get_path(self.ptr as *const c_void, idx, &mut path_len) };
            if path_len <= 1 {
                return None;
            }
            Some(unsafe { std::slice::from_raw_parts(ptr, (path_len - 1) as usize) })
        }
    }

    impl Drop for GmResults {
        fn drop(&mut self) {
            if !self.ptr.is_null() {
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
            assert!(tag < 254, "exhausted EntityType::Other tag space (max 238 custom types)");
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
    pub struct CachedSimdGraph {
        graph: GmGraph,
        pub generation: u64,
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
        unsafe {
            let ptr = gm_simd_isa();
            if ptr.is_null() {
                return "unknown";
            }
            CStr::from_ptr(ptr).to_str().unwrap_or("unknown")
        }
    }

    /// Build a C++ graph from the current Rust graph state.
    pub fn build_gm_graph(hunter: &GraphHunter) -> CachedSimdGraph {
        let mut other_map = OtherTypeMap::new();
        let gm = GmGraph::new();

        // Add all nodes
        for (&sid, entity) in &hunter.entities {
            let node_id = sid.index() as u32;
            let type_tag = other_map.entity_type_to_tag(&entity.entity_type);
            gm.add_node(node_id, type_tag);
        }

        // Add all edges
        for edge in hunter.edge_store.iter_all() {
            gm.add_edge(
                edge.source_sid.index() as u32,
                edge.dest_sid.index() as u32,
                edge.rel_type_tag,
                edge.timestamp,
            );
        }

        gm.finalize();

        let nc = unsafe { gm_graph_node_count(gm.as_const_ptr()) };
        let ec = unsafe { gm_graph_edge_count(gm.as_const_ptr()) };
        eprintln!(
            "[simd_matcher] Built C++ graph: {} nodes, {} edges, ISA={}",
            nc, ec, simd_isa_name()
        );

        CachedSimdGraph {
            graph: gm,
            generation: 0,
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
        // Create matcher
        let matcher_ptr = unsafe { gm_matcher_new(cached.graph.as_const_ptr()) };
        if matcher_ptr.is_null() {
            return Vec::new();
        }

        // Set start entity type (from first step's origin_type)
        let start_tag = cached.other_type_map.entity_type_to_tag_readonly(
            &hypothesis.steps[0].origin_type,
        );
        unsafe { gm_matcher_set_start_type(matcher_ptr, start_tag) };

        // Add steps
        for step in &hypothesis.steps {
            let dest_tag = cached.other_type_map.entity_type_to_tag_readonly(&step.dest_type);
            let rel_tag = step.relation_type.to_u8();
            unsafe { gm_matcher_add_step(matcher_ptr, dest_tag, rel_tag, 1) };
        }

        // Convert absolute time window to relative duration
        if let Some((start, end)) = time_window {
            let window_ms = end - start;
            if window_ms > 0 {
                unsafe { gm_matcher_set_time_window(matcher_ptr, window_ms) };
            }
        }

        // Run
        let cap = max_results.unwrap_or(10_000) as u32;
        let results_ptr = unsafe { gm_matcher_run(matcher_ptr, cap, 0.0) };

        // Clean up matcher
        unsafe { gm_matcher_free(matcher_ptr) };

        if results_ptr.is_null() {
            return Vec::new();
        }

        let results = GmResults { ptr: results_ptr };
        let count = results.count();

        let mut hunt_results = Vec::with_capacity(count as usize);

        for i in 0..count {
            if let Some(path_ids) = results.get_path(i) {
                let path_strings: Vec<String> = path_ids
                    .iter()
                    .map(|&node_id| {
                        let sid = StrId::from_raw(node_id);
                        interner.resolve(sid).to_string()
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
    use crate::graph::{GraphHunter, HuntResult};
    use crate::hypothesis::Hypothesis;
    use crate::interner::StringInterner;

    /// Placeholder — no C++ graph when SIMD is disabled.
    pub struct CachedSimdGraph {
        pub generation: u64,
    }

    pub fn simd_available() -> bool {
        false
    }

    pub fn simd_isa_name() -> &'static str {
        "none"
    }

    pub fn build_gm_graph(_hunter: &GraphHunter) -> CachedSimdGraph {
        CachedSimdGraph { generation: 0 }
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
