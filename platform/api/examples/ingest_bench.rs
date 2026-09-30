//! End-to-end memory/time bench of the streaming ingest path.
//!
//! Unlike `probe_ingest` (parse only, no graph), this drives the exact
//! call the Tauri UI makes — `load_data_streaming` into a real session —
//! and samples this process's private commit and working set while it
//! runs, so a change to the graph's storage shows up as a number.
//!
//! Usage:
//!   cargo run --release --example ingest_bench --manifest-path platform/api/Cargo.toml -- <file> [format]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use graph_hunter_api::dto::ingestion::LoadDataStreamingRequest;
use graph_hunter_api::dto::session::CreateSessionRequest;
use graph_hunter_api::events::FnEmitter;
use graph_hunter_api::GraphHunterApi;

// Same allocator as the desktop binary (apps/tauri/src-tauri/src/main.rs).
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(path) = args.first().cloned() else {
        eprintln!("usage: ingest_bench <file> [format]");
        std::process::exit(2);
    };
    if args.get(1).map(String::as_str) == Some("--phases") {
        phases(&path);
        return;
    }
    let format = args.get(1).cloned().unwrap_or_else(|| "auto".into());

    let done = Arc::new(AtomicBool::new(false));
    let outcome: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
    let (d, o) = (done.clone(), outcome.clone());
    let emitter = FnEmitter(move |event: &str, payload: serde_json::Value| {
        if event == "ingest-complete" || event == "ingest-error" {
            *o.lock().unwrap() = Some(serde_json::json!({ "event": event, "payload": payload }));
            d.store(true, Ordering::SeqCst);
        }
    });

    let api = GraphHunterApi::new(Arc::new(emitter));
    api.create_session(CreateSessionRequest {
        name: Some("bench".into()),
    })
    .expect("create_session");

    let (c0, _) = mem_mb();
    let t0 = Instant::now();
    api.load_data_streaming(
        LoadDataStreamingRequest {
            session: None,
            path: path.clone(),
            format,
            config: None,
            date_from: None,
            date_to: None,
        },
        &graph_hunter_api::paths::PathPolicy::LocalTrusted,
    )
    .expect("load_data_streaming");

    let mut peak_commit = c0;
    let mut last_print = Instant::now();
    while !done.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(250));
        let (c, w) = mem_mb();
        peak_commit = peak_commit.max(c);
        if last_print.elapsed() > Duration::from_secs(10) {
            eprintln!("t={:>6.1}s commit={c} MB ws={w} MB", t0.elapsed().as_secs_f64());
            last_print = Instant::now();
        }
    }
    let elapsed = t0.elapsed();
    let (c_end, w_end) = mem_mb();
    let peak_ws = peak_ws_mb();

    let out = outcome.lock().unwrap().take().unwrap_or_default();
    let result = &out["payload"]["result"];
    println!("file          : {path}");
    println!("event         : {}", out["event"]);
    if out["event"] == "ingest-error" {
        println!("error         : {}", out["payload"]["error"]);
    }
    println!("elapsed       : {:.1} s", elapsed.as_secs_f64());
    println!("entities      : {}", result["total_entities"]);
    println!("relations     : {}", result["total_relations"]);
    println!("stopped_early : {}", result["stopped_early"]);
    println!("commit start  : {c0} MB");
    println!("commit peak   : {peak_commit} MB");
    println!("commit end    : {c_end} MB (retained graph)");
    println!("ws end / peak : {w_end} / {peak_ws} MB");
    // Event-time span: `None` / zeros means the timestamp column never mapped.
    if let Ok(s) = api.get_graph_summary(graph_hunter_api::dto::geoip::GraphSummaryRequest {
        session: None,
    }) {
        let fmt = |t: i64| {
            chrono::DateTime::from_timestamp(t, 0).map(|d| d.to_rfc3339()).unwrap_or_default()
        };
        match s.summary.time_range {
            Some((a, b)) => println!("time range    : {} .. {}", fmt(a), fmt(b)),
            None => println!("time range    : NONE (no timestamps)"),
        }
    }
}

/// Times parse vs graph insert for successive batches of the file, with
/// the same auto `FieldConfig` the streaming path builds from the peek.
fn phases(path: &str) {
    use graph_hunter_core::parser::LogParser;
    let text = std::fs::read_to_string(path).expect("read");
    let peek: String = text.chars().take(8192).collect();
    let resolved = graph_hunter_api::format_registry::resolve_format(&peek, "auto");
    let cfg = graph_hunter_api::operations::ingestion::auto_field_config_for(&resolved, &peek);
    println!("format={resolved} auto_config={}", cfg.is_some());
    if let Some(c) = &cfg {
        for m in &c.mappings {
            println!("  map {:<14} role={:?} type={:?}", m.raw_name, m.role, m.entity_type);
        }
    }
    let parser: Box<dyn LogParser + Send + Sync> = match cfg {
        Some(c) => Box::new(graph_hunter_core::ConfigurableParser::new(c)),
        None => graph_hunter_api::format_registry::make_parser_for_format(&resolved).unwrap(),
    };
    let mut lines = text.lines();
    let header = lines.next().unwrap().to_string();
    let rows: Vec<&str> = lines.collect();
    let mut graph = graph_hunter_core::graph::GraphHunter::new();
    for (i, chunk) in rows.chunks(50_000).enumerate() {
        let batch = format!("{header}\n{}", chunk.join("\n"));
        let t = Instant::now();
        let (events, _) = parser.parse_raw_with_stats(&batch);
        let t_parse = t.elapsed();
        let n = events.len();
        if i == 0 {
            for ev in events.iter().take(6) {
                println!(
                    "  {:?}:{} -[{:?}]-> {:?}:{}\n    src_md={:?}\n    dst_md={:?}\n    rel_md={:?}\n    raw_line={}",
                    ev.src_type, ev.src_id, ev.rel_type, ev.dst_type, ev.dst_id,
                    ev.src_metadata, ev.dst_metadata, ev.rel_metadata,
                    ev.raw_line.as_ref().map(|s| s.len()).unwrap_or(0)
                );
            }
        }
        if i == 0 {
            journal_bytes(&events, chunk.len());
        }
        let t = Instant::now();
        graph.insert_raw_events(events, Some("ds")).unwrap();
        let t_insert = t.elapsed();
        let (c, _) = mem_mb();
        println!(
            "batch {i}: rows={} events={n} parse={:.2}s insert={:.2}s commit={c} MB",
            chunk.len(),
            t_parse.as_secs_f64(),
            t_insert.as_secs_f64()
        );
    }
    println!(
        "entities={} relations={} meta_store={} MB interner_strings={}",
        graph.entity_count(),
        graph.relation_count(),
        graph.meta_store.size_bytes() >> 20,
        graph.interner.len()
    );
    let mut key_freq: std::collections::HashMap<String, (usize, usize)> = Default::default();
    let mut per_type: std::collections::HashMap<String, usize> = Default::default();
    for e in graph.entities.values() {
        *per_type.entry(format!("{:?}", e.entity_type)).or_default() += 1;
        for (k, v) in &e.metadata {
            let s = key_freq.entry(k.clone()).or_default();
            s.0 += 1;
            s.1 += k.len() + v.len();
        }
    }
    let mut kf: Vec<_> = key_freq.into_iter().collect();
    kf.sort_by_key(|(_, (_, b))| std::cmp::Reverse(*b));
    println!("entity types: {per_type:?}");
    for (k, (n, b)) in kf.iter().take(12) {
        println!("  entity md key {k:<24} count={n:<8} bytes={b}");
    }
    // Commit released by dropping each component, largest-suspect first.
    drop(rows);
    drop(text);
    let mut prev = mem_mb().0;
    let mut step = |name: &str| {
        let now = mem_mb().0;
        println!("  drop {name:<12} -{} MB", prev.saturating_sub(now));
        prev = now;
    };
    step("input text");
    graph.entities = Default::default();
    step("entities");
    graph.reverse_adj = Default::default();
    step("reverse_adj");
    graph.type_index = Default::default();
    step("type_index");
    graph.meta_store = Default::default();
    step("meta_store");
    graph.interner = Default::default();
    step("interner");
    drop(graph);
    step("rest");
}

/// Journal bytes for one batch, written to a temp dir (never the real
/// journal). "unshared" gives every event a distinct source row — the
/// on-disk shape before rows were shared — at a cost of a few bytes a line.
fn journal_bytes(events: &[graph_hunter_core::RawIngestEvent], rows: usize) {
    use graph_hunter_api::journal::{journal_batch_keyed, JournalStore};
    let mut unshared = events.to_vec();
    for (i, ev) in unshared.iter_mut().enumerate() {
        if let Some(r) = ev.raw_line.as_mut() {
            r.push_str(&format!(" {i}"));
        }
    }
    for (name, evs) in [("shared", events), ("unshared", &unshared[..])] {
        let dir = std::env::temp_dir().join(format!("gh-jbench-{}-{name}", std::process::id()));
        let store = JournalStore::open(&dir).unwrap();
        let (_, err) = journal_batch_keyed(Some(&store), "s", "file_stream", "ds", "csv", evs, &[], 0);
        assert!(err.is_none());
        let bytes = ["journal.jsonl", "journal.jsonl.1"]
            .iter()
            .filter_map(|f| std::fs::metadata(dir.join(f)).ok())
            .map(|m| m.len())
            .sum::<u64>();
        println!(
            "  journal {name:<9} {:>6} MB  {:>5} B/event  {:>5} B/row",
            bytes >> 20,
            bytes / evs.len() as u64,
            bytes / rows as u64
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Default)]
struct Pmc {
    cb: u32,
    page_fault_count: u32,
    peak_working_set_size: usize,
    working_set_size: usize,
    quota_peak_paged_pool_usage: usize,
    quota_paged_pool_usage: usize,
    quota_peak_non_paged_pool_usage: usize,
    quota_non_paged_pool_usage: usize,
    pagefile_usage: usize,
    peak_pagefile_usage: usize,
}

#[cfg(target_os = "windows")]
fn pmc() -> Pmc {
    unsafe extern "system" {
        fn K32GetProcessMemoryInfo(process: isize, counters: *mut Pmc, cb: u32) -> i32;
        fn GetCurrentProcess() -> isize;
    }
    let mut c = Pmc {
        cb: std::mem::size_of::<Pmc>() as u32,
        ..Default::default()
    };
    unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) };
    c
}

/// `(private commit, working set)` in MB.
#[cfg(target_os = "windows")]
fn mem_mb() -> (usize, usize) {
    let c = pmc();
    (c.pagefile_usage >> 20, c.working_set_size >> 20)
}

#[cfg(target_os = "windows")]
fn peak_ws_mb() -> usize {
    pmc().peak_working_set_size >> 20
}

#[cfg(not(target_os = "windows"))]
fn mem_mb() -> (usize, usize) {
    (0, 0)
}

#[cfg(not(target_os = "windows"))]
fn peak_ws_mb() -> usize {
    0
}
