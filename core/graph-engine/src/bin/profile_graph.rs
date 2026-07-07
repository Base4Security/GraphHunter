//! Profiling harness for GraphHunter: measures RAM breakdown by struct field
//! and counts allocations/bytes during search_temporal_pattern.
//!
//! No external profiling deps — uses a custom GlobalAlloc that counts allocs
//! into atomic counters, plus std::mem::size_of and container capacity inspection.
//!
//! Run: cargo run --release --bin profile_graph

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use graph_hunter_core::benchmark::{
    build_lateral_movement_hypothesis, build_spawn_chain_hypothesis, generate_barabasi_albert,
};
use graph_hunter_core::entity::Entity;
use graph_hunter_core::graph::GraphHunter;
use graph_hunter_core::hypothesis::{Hypothesis, HypothesisStep};
use graph_hunter_core::interner::StrId;
use graph_hunter_core::relation::CompactRelation;
use graph_hunter_core::types::{EntityType, RelationType};

// ─────────────────────────── alloc-counting allocator ───────────────────────────

static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);
static DEALLOCS: AtomicUsize = AtomicUsize::new(0);
static DEALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);
static COUNTING_ENABLED: AtomicUsize = AtomicUsize::new(0);

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING_ENABLED.load(Ordering::Relaxed) == 1 {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if COUNTING_ENABLED.load(Ordering::Relaxed) == 1 {
            DEALLOCS.fetch_add(1, Ordering::Relaxed);
            DEALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

struct AllocSnapshot {
    allocs: usize,
    bytes: usize,
    deallocs: usize,
}

fn enable_counting() {
    ALLOCS.store(0, Ordering::Relaxed);
    ALLOC_BYTES.store(0, Ordering::Relaxed);
    DEALLOCS.store(0, Ordering::Relaxed);
    DEALLOC_BYTES.store(0, Ordering::Relaxed);
    COUNTING_ENABLED.store(1, Ordering::Relaxed);
}

fn disable_counting() -> AllocSnapshot {
    COUNTING_ENABLED.store(0, Ordering::Relaxed);
    AllocSnapshot {
        allocs: ALLOCS.load(Ordering::Relaxed),
        bytes: ALLOC_BYTES.load(Ordering::Relaxed),
        deallocs: DEALLOCS.load(Ordering::Relaxed),
    }
}

fn fmt_bytes(b: usize) -> String {
    if b >= 1 << 30 {
        format!("{:.2} GB", b as f64 / (1u64 << 30) as f64)
    } else if b >= 1 << 20 {
        format!("{:.2} MB", b as f64 / (1u64 << 20) as f64)
    } else if b >= 1 << 10 {
        format!("{:.2} KB", b as f64 / 1024.0)
    } else {
        format!("{} B", b)
    }
}

// ─────────────────────────── struct size report ───────────────────────────

fn report_type_sizes() {
    println!("=== Struct sizes (std::mem::size_of) ===");
    println!("{:<32} {:>6} bytes", "StrId", std::mem::size_of::<StrId>());
    println!(
        "{:<32} {:>6} bytes",
        "EntityType",
        std::mem::size_of::<EntityType>()
    );
    println!(
        "{:<32} {:>6} bytes",
        "RelationType",
        std::mem::size_of::<RelationType>()
    );
    println!(
        "{:<32} {:>6} bytes",
        "Entity (inline only)",
        std::mem::size_of::<Entity>()
    );
    println!(
        "{:<32} {:>6} bytes  <- claims 27 in docs",
        "CompactRelation",
        std::mem::size_of::<CompactRelation>()
    );
    println!(
        "{:<32} {:>6} bytes",
        "(StrId, Entity) pair",
        std::mem::size_of::<(StrId, Entity)>()
    );
    println!();
}

// ─────────────────────────── per-field RAM breakdown ───────────────────────────

fn report_graph_ram(g: &GraphHunter, label: &str) {
    println!("=== {} — per-field RAM (approximate) ===", label);
    let n = g.entity_count();
    let m = g.relation_count();
    println!("  entities (count): {}    relations (count): {}", n, m);

    // entities HashMap: AHashMap layout has ~1.0-1.5 bucket overhead per entry.
    // Inline cost = capacity * sizeof(StrId + Entity + control byte).
    // We can't read the AHashMap private fields, but len*sizeof gives a lower bound.
    let entities_inline = n * std::mem::size_of::<(StrId, Entity)>();
    // Heap behind each Entity: id String (~capacity bytes), metadata HashMap, etc.
    // Sample first 100 entities to estimate average heap.
    let mut heap_sample = 0usize;
    let mut sampled = 0usize;
    for entity in g.entities.values().take(200) {
        heap_sample += entity.id.capacity();
        // metadata HashMap: ignore here unless we observe non-empty
        for (k, v) in &entity.metadata {
            heap_sample += k.capacity() + v.capacity();
        }
        sampled += 1;
    }
    let avg_entity_heap = if sampled > 0 {
        heap_sample / sampled
    } else {
        0
    };
    let entities_heap_est = avg_entity_heap * n;
    let entities_total = entities_inline + entities_heap_est;
    println!(
        "  entities          inline ~{:>10}  + heap ~{:>10}  = {:>10}",
        fmt_bytes(entities_inline),
        fmt_bytes(entities_heap_est),
        fmt_bytes(entities_total)
    );

    // streaming: per-vertex Inline/Vec/Mmap with shared mmap handles
    let streaming_edges = g.relation_count();
    let streaming_buf_bytes =
        streaming_edges * std::mem::size_of::<graph_hunter_core::CompactRelation>();
    println!(
        "  streaming edges ({} × {} B) ≈ {}",
        streaming_edges,
        std::mem::size_of::<graph_hunter_core::CompactRelation>(),
        fmt_bytes(streaming_buf_bytes)
    );

    // reverse_adj: HashMap<StrId, Vec<StrId>>
    // Vec headers (24 bytes each) + per-edge StrId (4 bytes).
    let reverse_keys = g.reverse_adj.len();
    let reverse_vec_header = reverse_keys * std::mem::size_of::<Vec<StrId>>();
    let mut reverse_edges = 0usize;
    let mut reverse_cap = 0usize;
    for v in g.reverse_adj.values() {
        reverse_edges += v.len();
        reverse_cap += v.capacity();
    }
    let reverse_data = reverse_cap * std::mem::size_of::<StrId>();
    let reverse_total = reverse_vec_header + reverse_data;
    println!(
        "  reverse_adj       keys={:<7}  vec_headers={:>9}  data={:>9}  total={:>10}  (#edges={})",
        reverse_keys,
        fmt_bytes(reverse_vec_header),
        fmt_bytes(reverse_data),
        fmt_bytes(reverse_total),
        reverse_edges
    );

    // type_index: HashMap<EntityType, HashSet<StrId>>
    let type_keys = g.type_index.len();
    let type_total_entries: usize = g.type_index.values().map(|s| s.len()).sum();
    let type_index_est = type_keys * std::mem::size_of::<EntityType>()
        + type_total_entries * std::mem::size_of::<StrId>() * 2; // hash set overhead
    println!(
        "  type_index        types={}  total_entries={}  ~{}",
        type_keys,
        type_total_entries,
        fmt_bytes(type_index_est)
    );

    // dataset_tags
    let dt_count = g.dataset_tags.len();
    println!(
        "  dataset_tags      count={}  ~{}",
        dt_count,
        fmt_bytes(dt_count * 24)
    );

    // interner: strings vec + map. We can't iterate the private vec directly,
    // so resolve each StrId by index up to interner.len() and use str.len() as
    // a lower bound for the heap data.
    let mut interner_bytes = 0usize;
    for i in 0..g.interner.len() as u32 {
        if let Some(s) = g.interner.try_resolve(StrId::from_raw(i)) {
            interner_bytes += s.len() + 24; // String inline header (24) + bytes
        }
    }
    println!(
        "  interner.strings  ~{}  (n={}, avg_str={})",
        fmt_bytes(interner_bytes),
        n,
        if n > 0 { interner_bytes / n } else { 0 }
    );

    let estimated_total =
        entities_total + streaming_buf_bytes + reverse_total + type_index_est + interner_bytes;
    println!("  ─────────────────────────────────────────────────────────────────────");
    println!("  estimated total: {}", fmt_bytes(estimated_total));
    println!();
}

// ─────────────────────────── search profiling ───────────────────────────

fn profile_search(g: &mut GraphHunter, h: &Hypothesis, label: &str, iters: usize) {
    g.sort_edges_by_timestamp().expect("sort");

    // Warm-up (excluded from counts)
    let _ = g
        .search_temporal_pattern(h, None, Some(10_000))
        .expect("warmup search");

    // Measured run
    enable_counting();
    let t0 = Instant::now();
    let mut last_count = 0;
    for _ in 0..iters {
        let (results, _) = g
            .search_temporal_pattern(h, None, Some(10_000))
            .expect("search");
        last_count = results.len();
    }
    let elapsed = t0.elapsed();
    let snap = disable_counting();

    let avg_ms = elapsed.as_secs_f64() * 1000.0 / iters as f64;
    let avg_allocs = snap.allocs / iters;
    let avg_bytes = snap.bytes / iters;
    println!(
        "{:<36} {:>6} iters  results={:<6}  avg={:>7.3} ms  allocs/iter={:>7}  bytes/iter={:>10}  (deallocs/iter={})",
        label,
        iters,
        last_count,
        avg_ms,
        avg_allocs,
        fmt_bytes(avg_bytes),
        snap.deallocs / iters,
    );
}

fn build_any_chain(length: usize) -> Hypothesis {
    let mut h = Hypothesis::new(format!("any_chain_L{}", length));
    for _ in 0..length {
        h.steps.push(HypothesisStep::new(
            EntityType::Any,
            RelationType::Any,
            EntityType::Any,
        ));
    }
    h
}

fn main() {
    report_type_sizes();

    // ─── small graph ───
    let mut g_small = generate_barabasi_albert(5_000, 4, 0, 1_000_000, 42);
    report_graph_ram(&g_small, "small (5K nodes)");

    // ─── large graph ───
    let mut g_big = generate_barabasi_albert(20_000, 4, 0, 1_000_000, 43);
    report_graph_ram(&g_big, "big (20K nodes)");

    // ─── search profiling ───
    println!("=== Search profiling (allocs + bytes per iteration) ===");
    let h2 = build_spawn_chain_hypothesis(2);
    let h3 = build_spawn_chain_hypothesis(3);
    let h_lat3 = build_lateral_movement_hypothesis(3);
    let h_any2 = build_any_chain(2);
    let h_any3 = build_any_chain(3);
    let h_any4 = build_any_chain(4);

    profile_search(&mut g_small, &h2, "small / spawn_chain L=2", 20);
    profile_search(&mut g_small, &h3, "small / spawn_chain L=3", 20);
    profile_search(&mut g_small, &h_lat3, "small / lateral L=3", 20);
    profile_search(&mut g_small, &h_any2, "small / any_chain L=2 (sat)", 10);
    profile_search(&mut g_small, &h_any3, "small / any_chain L=3 (sat)", 10);
    profile_search(&mut g_small, &h_any4, "small / any_chain L=4 (sat)", 10);

    println!();
    profile_search(&mut g_big, &h2, "big   / spawn_chain L=2", 10);
    profile_search(&mut g_big, &h3, "big   / spawn_chain L=3", 10);
    profile_search(&mut g_big, &h_lat3, "big   / lateral L=3", 10);
    profile_search(&mut g_big, &h_any2, "big   / any_chain L=2 (sat)", 10);
    profile_search(&mut g_big, &h_any3, "big   / any_chain L=3 (sat)", 10);
    profile_search(&mut g_big, &h_any4, "big   / any_chain L=4 (sat)", 10);
}
