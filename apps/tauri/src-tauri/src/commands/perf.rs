//! Performance-flag introspection.
//!
//! Read-only Tauri command exposing which M-track perf optimizations
//! are active in the running daemon. The frontend calls this once at
//! mount and renders a status badge so the user perceives the perf
//! wins are on without having to flip env vars manually.
//!
//! The flags themselves are wired to default-on at app startup
//! (see `crate::run` in `lib.rs`); this command just reflects the
//! resolved state back to the UI.

use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PerfStatus {
    /// Structural K_4 LFTJ dispatcher (M1). Default-on.
    pub lftj_planner: bool,
    /// Name-marker S3 K_4 LFTJ fast-path. Default-on.
    pub k4_lftj: bool,
    /// Yannakakis chain matcher (L1). Default-on for α-acyclic
    /// hypotheses (every chain hypothesis the DSL emits today
    /// qualifies).
    pub yannakakis: bool,
    /// AMAC interleaved DFS (C2). Opt-in.
    pub amac: bool,
    /// Bidirectional semi-join prune (D2-lite). Opt-in.
    pub semijoin: bool,
    /// MADV_HUGEPAGE for memmap regions (Linux only). Opt-in.
    pub hugepages: bool,
    /// Whether the matcher was compiled with `--features
    /// symmetry-nauty` on a `cfg(unix)` target. Compile-time
    /// capability, not an env var.
    pub has_nauty: bool,
    /// Heap budget (bytes) above which an auxiliary index (NLF,
    /// k-hop reachability) spills to a memory-mapped temp file
    /// instead of staying in heap. Reflects
    /// `GRAPHHUNTER_INDEX_HEAP_BUDGET` if set, else the 1 GiB
    /// default. Per-session "is currently spilled" comes via the
    /// dedicated session-memory command (heavy-logs #4); this is
    /// the static configuration value.
    pub index_heap_budget_bytes: u64,
    /// Human-readable summary the UI can show in a tooltip.
    pub summary: String,
}

fn flag(key: &str) -> bool {
    std::env::var(key)
        .map(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

#[tauri::command]
pub fn cmd_get_perf_status() -> PerfStatus {
    let lftj_planner = flag("GRAPHHUNTER_LFTJ_PLANNER");
    let k4_lftj = flag("GRAPHHUNTER_K4_LFTJ");
    let yannakakis = flag("GRAPHHUNTER_YANNAKAKIS");
    let amac = flag("GRAPHHUNTER_AMAC");
    let semijoin = flag("GRAPHHUNTER_SEMIJOIN");
    let hugepages = flag("GRAPHHUNTER_HUGEPAGES");
    let has_nauty = graph_hunter_core::nauty_symmetry::HAS_NAUTY;

    let mut active = Vec::new();
    if lftj_planner {
        active.push("LFTJ planner");
    }
    if k4_lftj {
        active.push("K4 fast-path");
    }
    if yannakakis {
        active.push("Yannakakis");
    }
    if amac {
        active.push("AMAC");
    }
    if semijoin {
        active.push("semi-join");
    }
    if hugepages {
        active.push("hugepages");
    }
    if has_nauty {
        active.push("nauty");
    }
    let summary = if active.is_empty() {
        "Legacy DFS only".to_string()
    } else {
        format!("M-track + L1 active: {}", active.join(", "))
    };

    let index_heap_budget_bytes = std::env::var("GRAPHHUNTER_INDEX_HEAP_BUDGET")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(graph_hunter_core::index_storage::DEFAULT_HEAP_BUDGET as u64);

    PerfStatus {
        lftj_planner,
        k4_lftj,
        yannakakis,
        amac,
        semijoin,
        hugepages,
        has_nauty,
        index_heap_budget_bytes,
        summary,
    }
}
