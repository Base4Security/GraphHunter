//! Heavy-logs #4 — soft-memory-ceiling telemetry.
//!
//! Returns the current process RSS + total host RAM so the
//! frontend can render a memory-pressure indicator without polling
//! OS APIs from JS. The frontend polls this every few seconds while
//! a session is active and shifts the perf badge from green
//! ("normal") to amber (≥75% of host RAM) to red (≥90%).
//!
//! No background thread, no opt-in flag — the command is read-only
//! and cheap (one `sysinfo::System::refresh_memory` call per
//! invocation), so the frontend's poll interval is the only knob.
//! The plug-and-play directive applies: the user perceives memory
//! pressure naturally without configuring anything.

use serde::Serialize;
use std::sync::Mutex;

/// Process-wide singleton so the System refresh state lives across
/// invocations of `cmd_get_memory_status` (avoids rebuilding the
/// kernel handle table each call). Each call still does a fresh
/// `refresh_memory` so values are current.
static SYSTEM: Mutex<Option<sysinfo::System>> = Mutex::new(None);

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryStatus {
    /// Resident Set Size of the current process, in bytes. Reflects
    /// what the OS shows as "memory in use" for the daemon.
    pub rss_bytes: u64,
    /// Total physical RAM available to the host, in bytes.
    pub host_total_bytes: u64,
    /// Available physical RAM (free + reclaimable cache), in bytes.
    pub host_available_bytes: u64,
    /// `rss_bytes / host_total_bytes` clamped to `[0, 1]`. Convenient
    /// for the frontend pressure badge.
    pub usage_ratio: f64,
    /// Amber threshold (default 0.75). Frontend can render the
    /// badge in warning state when `usage_ratio >= warn_at`.
    pub warn_at: f64,
    /// Red threshold (default 0.90). Frontend can render the badge
    /// in critical state when `usage_ratio >= critical_at`.
    pub critical_at: f64,
}

fn threshold(env_key: &str, default: f64) -> f64 {
    std::env::var(env_key)
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v > 0.0 && *v <= 1.0)
        .unwrap_or(default)
}

#[tauri::command]
pub fn cmd_get_memory_status() -> MemoryStatus {
    let warn_at = threshold("GRAPHHUNTER_MEM_WARN", 0.75);
    let critical_at = threshold("GRAPHHUNTER_MEM_CRITICAL", 0.90);

    let mut guard = SYSTEM.lock().expect("memory probe mutex poisoned");
    let sys = guard.get_or_insert_with(sysinfo::System::new);
    sys.refresh_memory();
    let pid = sysinfo::Pid::from_u32(std::process::id());
    sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
    let host_total_bytes = sys.total_memory();
    let host_available_bytes = sys.available_memory();
    let rss_bytes = sys
        .process(pid)
        .map(|p| p.memory())
        .unwrap_or(0);

    let usage_ratio = if host_total_bytes == 0 {
        0.0
    } else {
        (rss_bytes as f64 / host_total_bytes as f64).clamp(0.0, 1.0)
    };

    MemoryStatus {
        rss_bytes,
        host_total_bytes,
        host_available_bytes,
        usage_ratio,
        warn_at,
        critical_at,
    }
}
