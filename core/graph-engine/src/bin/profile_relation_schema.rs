//! Profiles `GraphHunter::get_relation_schema` on a synthetic 7M-edge graph
//! matching the star-topology shape the analyst reported from the live Ator
//! dataset: 1 Host hub, ~7K IP peripheries, ~1.5K URL peripheries, heavy
//! metadata per edge.
//!
//! Uses differential timing across four variants to attribute wall-clock to
//! a specific phase (iteration vs entity lookup vs metadata decode vs triple
//! aggregation). Run:
//!
//!   cargo run --release --bin profile_relation_schema
//!
//! No overhead from `Instant::now()` inside the hot loop — we measure four
//! separate passes and subtract.

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use graph_hunter_core::entity::Entity;
use graph_hunter_core::graph::GraphHunter;
use graph_hunter_core::relation::Relation;
use graph_hunter_core::types::{EntityType, RelationType};

const N_IPS: usize = 7165;
const N_URLS: usize = 1536;
const N_EDGES: usize = 7_000_000;
const META_KV_PER_EDGE: usize = 6;

fn build_graph() -> GraphHunter {
    let mut g = GraphHunter::new();

    g.add_entity(Entity::new("host0".to_string(), EntityType::Host))
        .unwrap();
    for i in 0..N_IPS {
        g.add_entity(Entity::new(format!("ip{}", i), EntityType::IP))
            .unwrap();
    }
    for i in 0..N_URLS {
        g.add_entity(Entity::new(format!("url{}", i), EntityType::URL))
            .unwrap();
    }

    // ~85% Host→IP (Connect), ~15% Host→URL (DNS-ish bucket).
    let ip_share = (N_EDGES as f64 * 0.85) as usize;
    let url_share = N_EDGES - ip_share;

    let base_ts: i64 = 1_700_000_000;
    let keys = ["evt_id", "dst_port", "bytes", "proto", "action", "zone"];
    assert!(keys.len() >= META_KV_PER_EDGE);

    for e in 0..ip_share {
        let target = format!("ip{}", e % N_IPS);
        let ts = base_ts + (e as i64 % 86_400);
        let mut rel = Relation::new("host0".to_string(), target, RelationType::Connect, ts);
        for k in 0..META_KV_PER_EDGE {
            rel.metadata
                .insert(keys[k].to_string(), format!("v{}_{}", e, k));
        }
        g.add_relation(rel).unwrap();
    }
    for e in 0..url_share {
        let target = format!("url{}", e % N_URLS);
        let ts = base_ts + (e as i64 % 86_400);
        let mut rel = Relation::new("host0".to_string(), target, RelationType::DNS, ts);
        for k in 0..META_KV_PER_EDGE {
            rel.metadata
                .insert(keys[k].to_string(), format!("v{}_{}", e, k));
        }
        g.add_relation(rel).unwrap();
    }

    g
}

fn main() {
    println!("=== profile_relation_schema ===");
    println!(
        "Building synthetic graph: {} entities, {} edges, {} meta k/v per edge ...",
        1 + N_IPS + N_URLS,
        N_EDGES,
        META_KV_PER_EDGE
    );
    let build_start = Instant::now();
    let g = build_graph();
    let build_secs = build_start.elapsed().as_secs_f64();
    println!(
        "Build done in {:.2}s (entities={}, edges={})",
        build_secs,
        g.entity_count(),
        g.relation_count()
    );
    println!();

    // ── Variant 1: raw iter only (no work per edge) ──
    let t = Instant::now();
    let mut counter: usize = 0;
    g.streaming.for_each_edge(|_src, edge| {
        counter = counter.wrapping_add(edge.timestamp as usize);
    });
    let v1 = t.elapsed().as_secs_f64();
    std::hint::black_box(counter);

    // ── Variant 2: iter + entity lookups (src and dst) ──
    let t = Instant::now();
    let mut seen_types: usize = 0;
    g.streaming.for_each_edge(|src_sid, edge| {
        if g.entities.get(&src_sid).is_some() {
            seen_types += 1;
        }
        if g.entities.get(&edge.dest_sid).is_some() {
            seen_types += 1;
        }
    });
    let v2 = t.elapsed().as_secs_f64();
    std::hint::black_box(seen_types);

    // ── Variant 3: iter + entity lookups + meta_store.get (discard result) ──
    let t = Instant::now();
    let mut meta_key_total: usize = 0;
    g.streaming.for_each_edge(|src_sid, edge| {
        let _src = g.entities.get(&src_sid);
        let _dst = g.entities.get(&edge.dest_sid);
        if edge.metadata_offset != 0 {
            let meta = g.meta_store.get(edge.metadata_offset);
            meta_key_total += meta.len();
        }
    });
    let v3 = t.elapsed().as_secs_f64();
    std::hint::black_box(meta_key_total);

    // ── Variant 4: full get_relation_schema (baseline) ──
    let t = Instant::now();
    let schema = g.get_relation_schema();
    let v4 = t.elapsed().as_secs_f64();

    // ── Variant 4b: second call — any accidental caching? ──
    let t = Instant::now();
    let _ = g.get_relation_schema();
    let v4b = t.elapsed().as_secs_f64();

    println!("── Phase breakdown (7M edges) ──");
    println!("V1  iter only (raw scan)              : {:>7.3}s", v1);
    println!(
        "V2  + entity lookups (src + dst)      : {:>7.3}s   Δ={:+.3}s",
        v2,
        v2 - v1
    );
    println!(
        "V3  + meta_store.get per edge         : {:>7.3}s   Δ={:+.3}s",
        v3,
        v3 - v2
    );
    println!(
        "V4  full get_relation_schema          : {:>7.3}s   Δ={:+.3}s",
        v4,
        v4 - v3
    );
    println!(
        "V4b 2nd call (cache check)            : {:>7.3}s   (should match V4 if uncached)",
        v4b
    );
    println!();
    println!("Schema triples found: {}", schema.len());
    for entry in &schema {
        println!(
            "  {}→{} via {}: {} edges, {} metadata keys",
            entry.source_type,
            entry.target_type,
            entry.rel_type,
            entry.edge_count,
            entry.metadata_keys.len()
        );
    }
    println!();

    let total = v4;
    let iter_pct = 100.0 * v1 / total;
    let lookup_pct = 100.0 * (v2 - v1) / total;
    let meta_pct = 100.0 * (v3 - v2) / total;
    let agg_pct = 100.0 * (v4 - v3) / total;
    println!("── Attribution (% of full call) ──");
    println!("  raw iteration:     {:>5.1}%", iter_pct);
    println!("  entity lookups:    {:>5.1}%", lookup_pct);
    println!("  metadata decode:   {:>5.1}%", meta_pct);
    println!("  triple aggregate:  {:>5.1}%", agg_pct);
}
