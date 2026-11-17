//! Process start-up shared by the desktop app and `graph-hunter-server`.
//!
//! This used to live inline in the desktop app's `run()`. A second
//! transport that skipped any of it would still start and answer 200s —
//! with an empty dead-letter queue, no drift history and the slower
//! matcher — so the wiring lives here and both entry points call it.

use std::path::PathBuf;
use std::sync::Arc;

use graph_hunter_api::GraphHunterApi;

use crate::journal::store::JournalStore;

/// Load `.env`, walking up from the current directory until one is found.
pub fn load_dotenv() {
    let mut dir = std::env::current_dir().ok();
    while let Some(d) = dir {
        let candidate = d.join(".env");
        if candidate.is_file() && dotenvy::from_path(&candidate).is_ok() {
            tracing::info!(".env loaded from {}", candidate.display());
            return;
        }
        dir = d.parent().map(|p| p.to_path_buf());
    }
    tracing::warn!(".env not found in any parent directory");
}

/// Turn on the matcher's structural dispatch flags unless the operator
/// already set them. Each one is conservative: the dispatcher inspects
/// the hypothesis and falls back to the legacy DFS for any shape it does
/// not recognise. Override with `GRAPHHUNTER_LFTJ_PLANNER=0` etc.
///
/// # Safety
///
/// Mutates the process environment, so it must run before any other
/// thread exists — first thing in `main`, before the async runtime.
pub unsafe fn default_perf_flags() {
    for (key, default) in [
        ("GRAPHHUNTER_LFTJ_PLANNER", "1"),
        ("GRAPHHUNTER_K4_LFTJ", "1"),
        ("GRAPHHUNTER_YANNAKAKIS", "1"),
    ] {
        if std::env::var(key).is_err() {
            // SAFETY: single-threaded per this function's contract. The
            // matcher reads these lazily on the first hunt.
            unsafe { std::env::set_var(key, default) };
            tracing::info!("perf flag default-on: {}={}", key, default);
        } else {
            tracing::debug!("perf flag honored from env: {}", key);
        }
    }
}

/// `GRAPHHUNTER_API_PORT`, or the default (37891).
pub fn resolve_port() -> u16 {
    graph_hunter_api::util::resolve_api_port()
}

/// Bearer token for the HTTP API, and whether it was generated here.
///
/// `GRAPHHUNTER_API_TOKEN` wins when set and non-empty; otherwise a
/// random one is generated for this run. The flag lets the caller decide
/// how to hand a generated token to the operator — a supplied one never
/// needs to be shown again.
pub fn resolve_token() -> (String, bool) {
    match std::env::var("GRAPHHUNTER_API_TOKEN") {
        Ok(t) if !t.trim().is_empty() => (t, false),
        _ => (uuid::Uuid::new_v4().to_string(), true),
    }
}

fn data_root() -> Option<PathBuf> {
    dirs::data_dir().map(|d| d.join("GraphHunter"))
}

/// Open the on-disk stores the API degrades without: drift history, the
/// dead-letter queue and the mapping library. Each failure is logged and
/// leaves its slot empty — ingest still runs, the matching operations
/// just return nothing.
pub fn init_stores(api: &GraphHunterApi) {
    // Drift store, beside the session files.
    {
        let store = data_root().map(|d| d.join("sessions")).and_then(|dir| {
            std::fs::create_dir_all(&dir).ok()?;
            let path = dir.join("drift.sqlite");
            match graph_hunter_core::drift::DriftStore::open(&path) {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::warn!("DriftStore open failed at {}: {}", path.display(), e);
                    None
                }
            }
        });
        if store.is_some() {
            tracing::info!("Drift store initialized");
        }
        if let Ok(mut g) = api.drift_store_handle().lock() {
            *g = store;
        }
    }

    // DLQ store: JSONL shards under `<data>/GraphHunter/sessions/dlq/`.
    {
        let store = data_root()
            .map(|d| d.join("sessions").join("dlq"))
            .and_then(|dir| match graph_hunter_core::dlq::DlqStore::open(&dir) {
                Ok(s) => Some(Arc::new(s)),
                Err(e) => {
                    tracing::warn!("DlqStore open failed at {}: {}", dir.display(), e);
                    None
                }
            });
        if store.is_some() {
            tracing::info!("Dead-letter queue initialized");
        }
        if let Ok(mut g) = api.dlq_store_handle().lock() {
            *g = store;
        }
    }

    // Mapping library: JSONL catalog under `<data>/GraphHunter/mapping_library/`.
    {
        let store = data_root()
            .map(|d| d.join("mapping_library"))
            .and_then(|dir| {
                match graph_hunter_core::mapping_library::MappingLibraryStore::open(&dir) {
                    Ok(s) => Some(Arc::new(s)),
                    Err(e) => {
                        tracing::warn!(
                            "MappingLibraryStore open failed at {}: {}",
                            dir.display(),
                            e
                        );
                        None
                    }
                }
            });
        if store.is_some() {
            tracing::info!("Mapping library initialized");
        }
        if let Ok(mut g) = api.mapping_library_handle().lock() {
            *g = store;
        }
    }
}

/// Hunt journal under `<data>/GraphHunter/journals/`. Falls back to the
/// OS temp dir when there is no data dir: capture is mandatory, so the
/// journal must always have somewhere to write.
pub fn open_journal() -> Arc<JournalStore> {
    let base = dirs::data_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("GraphHunter")
        .join("journals");
    Arc::new(JournalStore::new(base))
}
