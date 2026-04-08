/// @file graphmatch.h
/// @brief C ABI for libgraphmatch — the interface Rust consumes via FFI.
///
/// All types are C-compatible. No exceptions cross the boundary.
/// All handles are opaque pointers owned by the caller.
///
/// Usage:
///   1. gm_graph_new → add_node/add_edge → finalize → (read-only, thread-safe)
///   2. gm_matcher_new → add_step → set_time_window → run → iterate results
///   3. Free everything with the corresponding _free() call.

#ifndef GRAPHMATCH_H
#define GRAPHMATCH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Opaque handles
// ---------------------------------------------------------------------------

typedef struct gm_graph_t   gm_graph_t;
typedef struct gm_matcher_t gm_matcher_t;
typedef struct gm_results_t gm_results_t;

// ---------------------------------------------------------------------------
// Graph construction
// ---------------------------------------------------------------------------

/// Create a new empty graph. Caller owns the handle.
gm_graph_t* gm_graph_new(void);

/// Add a node with the given numeric ID and entity type tag.
/// Duplicate IDs are silently ignored.
void gm_graph_add_node(gm_graph_t* g, uint32_t id, uint8_t entity_type);

/// Add a directed temporal edge.
void gm_graph_add_edge(gm_graph_t* g, uint32_t src, uint32_t dst,
                        uint8_t rel_type, int64_t timestamp);

/// Finalize the graph: build CSR indices, sort edges.
/// After this call, the graph is read-only and safe for concurrent reads.
void gm_graph_finalize(gm_graph_t* g);

/// Free a graph handle. NULL-safe.
void gm_graph_free(gm_graph_t* g);

// ---------------------------------------------------------------------------
// Graph stats
// ---------------------------------------------------------------------------

uint32_t gm_graph_node_count(const gm_graph_t* g);
uint32_t gm_graph_edge_count(const gm_graph_t* g);

// ---------------------------------------------------------------------------
// Pattern matching
// ---------------------------------------------------------------------------

/// Create a new matcher bound to a finalized graph.
/// The graph must outlive the matcher.
gm_matcher_t* gm_matcher_new(const gm_graph_t* g);

/// Set the starting entity type for the pattern (default: GM_ENTITY_ANY = 254).
void gm_matcher_set_start_type(gm_matcher_t* m, uint8_t entity_type);

/// Add a pattern step: expects an edge of rel_type leading to entity_type.
/// Steps are evaluated in the order they are added.
/// enforce_causality: 1 = require timestamp >= previous, 0 = no constraint.
void gm_matcher_add_step(gm_matcher_t* m, uint8_t entity_type,
                          uint8_t rel_type, int32_t enforce_causality);

/// Set the maximum time window in milliseconds (0 = no window constraint).
void gm_matcher_set_time_window(gm_matcher_t* m, int64_t window_ms);

/// Execute matching. Returns an opaque results handle.
/// max_results: maximum matches to return (0 = unlimited).
/// min_score: minimum anomaly score threshold (0 = no filter).
gm_results_t* gm_matcher_run(gm_matcher_t* m, uint32_t max_results, float min_score);

/// Free a matcher handle. NULL-safe.
void gm_matcher_free(gm_matcher_t* m);

// ---------------------------------------------------------------------------
// Results access
// ---------------------------------------------------------------------------

/// Number of matches in the result set.
uint32_t gm_results_count(const gm_results_t* r);

/// Get the matched node path for result at index `idx`.
/// Sets *path_len to the number of nodes. Returns NULL if idx is invalid.
/// The returned pointer is valid until gm_results_free().
const uint32_t* gm_results_get_path(const gm_results_t* r, uint32_t idx,
                                     uint32_t* path_len);

/// Get the edge timestamps for result at index `idx`.
/// Length is path_len - 1. Returns NULL if idx is invalid.
const int64_t* gm_results_get_timestamps(const gm_results_t* r, uint32_t idx);

/// Get the anomaly score for result at index `idx`.
float gm_results_get_score(const gm_results_t* r, uint32_t idx);

/// Serialize all results to a JSON string.
/// Caller must free the returned string with gm_free_string().
char* gm_results_to_json(const gm_results_t* r);

/// Free a results handle. NULL-safe.
void gm_results_free(gm_results_t* r);

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Free a string allocated by gm_results_to_json(). NULL-safe.
void gm_free_string(char* s);

/// Query the SIMD ISA in use. Returns a static string:
/// "avx512" | "avx2" | "sse42" | "neon" | "scalar"
const char* gm_simd_isa(void);

// ---------------------------------------------------------------------------
// String interning (for resolving node IDs to names)
// ---------------------------------------------------------------------------

/// Intern a string name for a node ID. Returns the node's numeric ID.
/// If the name was already interned, returns the existing ID.
uint32_t gm_graph_intern(gm_graph_t* g, const char* name);

/// Resolve a node ID to its interned name. Returns NULL if not interned.
const char* gm_graph_resolve(const gm_graph_t* g, uint32_t id);

#ifdef __cplusplus
}
#endif

#endif // GRAPHMATCH_H
