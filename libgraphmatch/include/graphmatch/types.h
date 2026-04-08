/// @file types.h
/// @brief Fundamental types for libgraphmatch — C-compatible, SIMD-friendly.
///
/// Mirrors Graph Hunter's Rust types (EntityType, RelationType, StrId)
/// with fixed-width integers suitable for vectorized processing.

#ifndef GRAPHMATCH_TYPES_H
#define GRAPHMATCH_TYPES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Node / Edge identifiers
// ---------------------------------------------------------------------------

/// Interned node identifier — matches Rust StrId (u32).
typedef uint32_t NodeId;

/// Edge index within the CSR edge_list.
typedef uint32_t EdgeId;

/// Unix timestamp in milliseconds.
typedef int64_t  Timestamp;

/// Sentinel: "no node" / invalid.
#define GM_INVALID_NODE  ((NodeId)UINT32_MAX)
#define GM_INVALID_EDGE  ((EdgeId)UINT32_MAX)
#define GM_TS_MIN        INT64_MIN
#define GM_TS_MAX        INT64_MAX

// ---------------------------------------------------------------------------
// Entity types — mirrors graph_hunter_core::types::EntityType
// ---------------------------------------------------------------------------

/// Numeric entity type tags. Values match Rust EntityType ordering.
/// "Other" types get IDs >= GM_ENTITY_OTHER_BASE via the string interner.
enum {
    GM_ENTITY_IP       = 0,
    GM_ENTITY_HOST     = 1,
    GM_ENTITY_USER     = 2,
    GM_ENTITY_PROCESS  = 3,
    GM_ENTITY_FILE     = 4,
    GM_ENTITY_DOMAIN   = 5,
    GM_ENTITY_REGISTRY = 6,
    GM_ENTITY_URL      = 7,
    GM_ENTITY_SERVICE  = 8,
    GM_ENTITY_ANY      = 254,   ///< Wildcard — matches everything.
    GM_ENTITY_OTHER_BASE = 16,  ///< User-defined types start here.
};
typedef uint8_t EntityTypeTag;

// ---------------------------------------------------------------------------
// Relation types — mirrors graph_hunter_core::types::RelationType
// ---------------------------------------------------------------------------

/// Numeric relation type tags. Values match RelationType::to_u8().
enum {
    GM_REL_AUTH    = 0,
    GM_REL_CONNECT = 1,
    GM_REL_EXECUTE = 2,
    GM_REL_READ    = 3,
    GM_REL_WRITE   = 4,
    GM_REL_DNS     = 5,
    GM_REL_MODIFY  = 6,
    GM_REL_SPAWN   = 7,
    GM_REL_DELETE  = 8,
    GM_REL_ANY     = 255,       ///< Wildcard — matches everything.
};
typedef uint8_t RelTypeTag;

// ---------------------------------------------------------------------------
// Temporal edge — the fundamental record in the CSR edge list.
// Packed for cache-friendly sequential access.
// ---------------------------------------------------------------------------

/// A single directed temporal edge in the CSR store.
/// 20 bytes: fits 3.2 edges per cache line (64B), enabling prefetch-friendly scans.
#pragma pack(push, 1)
typedef struct {
    NodeId     target;       ///< Destination node.
    RelTypeTag rel_type;     ///< Relation type tag.
    uint8_t    _pad[3];      ///< Padding for 8-byte alignment of timestamp.
    Timestamp  timestamp;    ///< Unix milliseconds.
} TemporalEdge;
#pragma pack(pop)

#ifdef __cplusplus
static_assert(sizeof(TemporalEdge) == 16, "TemporalEdge must be 16 bytes");
#else
_Static_assert(sizeof(TemporalEdge) == 16, "TemporalEdge must be 16 bytes");
#endif

// ---------------------------------------------------------------------------
// SIMD ISA tags
// ---------------------------------------------------------------------------

enum {
    GM_ISA_SCALAR = 0,
    GM_ISA_SSE42  = 1,
    GM_ISA_AVX2   = 2,
    GM_ISA_AVX512 = 3,
    GM_ISA_NEON   = 4,
};
typedef uint8_t SimdIsa;

#ifdef __cplusplus
} // extern "C"
#endif

// ---------------------------------------------------------------------------
// C++ utilities (only visible in C++ translation units)
// ---------------------------------------------------------------------------
#ifdef __cplusplus

#include <cstdlib>
#include <cstring>
#include <new>

namespace gm {

/// Matches relation type with wildcard support.
[[nodiscard]] inline constexpr bool rel_matches(RelTypeTag pattern, RelTypeTag actual) noexcept {
    return pattern == GM_REL_ANY || pattern == actual;
}

/// Matches entity type with wildcard support.
[[nodiscard]] inline constexpr bool entity_matches(EntityTypeTag pattern, EntityTypeTag actual) noexcept {
    return pattern == GM_ENTITY_ANY || pattern == actual;
}

/// Aligned memory allocation (64-byte for AVX-512 compatibility).
inline void* aligned_malloc(size_t size, size_t alignment = 64) noexcept {
#if defined(_WIN32)
    return _aligned_malloc(size, alignment);
#else
    void* ptr = nullptr;
    if (posix_memalign(&ptr, alignment, size) != 0) return nullptr;
    return ptr;
#endif
}

inline void aligned_free(void* ptr) noexcept {
#if defined(_WIN32)
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}

/// RAII wrapper for aligned allocations.
template<typename T>
struct AlignedDeleter {
    void operator()(T* p) const noexcept { aligned_free(p); }
};

} // namespace gm

#endif // __cplusplus

#endif // GRAPHMATCH_TYPES_H
