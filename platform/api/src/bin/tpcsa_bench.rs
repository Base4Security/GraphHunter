//! Regression harness for attack-chain reconstruction on the NODLINK
//! traces (hw20 / win10) and on exported instances.
//!
//! ```text
//! tpcsa_bench --etw <anomaly.json> [--n-false 20] [--seeds 0,1,2] [--k 1]
//!             [--detect 0.8] [--epsilon-ms 1] [--dump-instance out.json]
//! tpcsa_bench --instance <instance.json> [--k 2]
//! ```
//!
//! `--etw` runs the whole pipeline the product runs — parser → graph →
//! `build_instance` → prune → greedy → verify — with the paper's synthetic
//! terminals (§6.1: each `is_warn` process is a terminal with probability
//! `detect`, prize `10·U(0.6,1)`; `n_false` random benign processes get
//! `3·U(0.3,1)`), and reports what Table 1 reports: node precision/recall
//! over processes and recall of labelled parent→child `start` arcs.
//! `--instance` reconstructs an instance produced elsewhere (the Python
//! prototype's `Instance.to_json`) so objectives can be compared directly.
//!
//! ```text
//! tpcsa_bench --etw <anomaly.json> --scores <scores.json> [--top 400] [--k 3] [--flat]
//!             [--separation]
//! tpcsa_bench --session <saved-session-id> [--schema] [--seeds-file seeds.json]
//!             [--truth-file truth.json] [--k 2] [--window from,to] [--epsilon-ms 1000]
//! ```
//!
//! `--scores` replaces the synthetic terminals by a detector's output
//! (`{"<node>": {"p": 0.83, "score": 12.3, "tactic": "discovery"}}`, see
//! `tools/tpcsa_proxy_detector.py`): prize = `10·p`, or flat 10 with
//! `--flat`. `--separation` runs the GNN acceptance test of the work order
//! (§5): the tree holding the most labelled attack processes must also
//! carry the largest aggregate prize.
//!
//! `--session` loads a saved Graph Hunter session from the app's session
//! store (no running app needed), prints its schema with `--schema`, and
//! reconstructs from a seeds file (`{"<node>": {"prize": 10, "tactic": "…"}}`
//! or `[{"node": …}]`). `--truth-file` (a JSON list of node ids) gives
//! precision/recall per tree over those ids.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use graph_hunter_api::GraphHunterApi;
use graph_hunter_api::dto::session::LoadSessionRequest;
use graph_hunter_api::dto::tpcsa::{ReconstructChainRequest, TpcsaSeed, TpcsaWindow};
use graph_hunter_api::operations::tpcsa::{ExportOpts, build_instance};
use graph_hunter_core::GraphHunter;
use graph_hunter_core::parser::LogParser;
use graph_hunter_core::types::EntityType;
use graph_hunter_parsers::EtwNodlinkParser;
use graph_hunter_tpcsa::{
    GreedyOptions, Instance, ReconstructOptions, Reconstruction, reconstruct,
};
use rand::{Rng, SeedableRng, rngs::StdRng};

struct Args {
    etw: Option<String>,
    instance: Option<String>,
    n_false: usize,
    seeds: Vec<u64>,
    k: usize,
    detect: f64,
    epsilon_ms: f64,
    dump_instance: Option<String>,
    /// Write `{instance: <pruned>, k, time_limit, gap, warm_start}` for the sidecar.
    dump_certify: Option<String>,
    top_roots: usize,
    scores: Option<String>,
    top: usize,
    flat: bool,
    separation: bool,
    session: Option<String>,
    schema: bool,
    seeds_file: Option<String>,
    truth_file: Option<String>,
    window: Option<(i64, i64)>,
    /// `--session` only: print a node's edges instead of reconstructing.
    nodes: Vec<String>,
    /// `--etw` only: persist the parsed graph as a named session in the
    /// app's session store, so the desktop app can load it in seconds.
    save_session: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        etw: None,
        instance: None,
        n_false: 20,
        seeds: vec![0, 1, 2],
        k: 1,
        detect: 0.8,
        epsilon_ms: 1.0,
        dump_instance: None,
        dump_certify: None,
        top_roots: 8,
        scores: None,
        top: 400,
        flat: false,
        separation: false,
        session: None,
        schema: false,
        seeds_file: None,
        truth_file: None,
        window: None,
        nodes: Vec::new(),
        save_session: None,
    };
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        let key = argv[i].as_str();
        let val = || {
            argv.get(i + 1)
                .cloned()
                .ok_or_else(|| format!("{key} needs a value"))
        };
        match key {
            "--etw" => a.etw = Some(val()?),
            "--instance" => a.instance = Some(val()?),
            "--n-false" => a.n_false = val()?.parse().map_err(|e| format!("--n-false: {e}"))?,
            "--seeds" => {
                a.seeds = val()?
                    .split(',')
                    .map(|s| s.trim().parse::<u64>().map_err(|e| e.to_string()))
                    .collect::<Result<_, _>>()?
            }
            "--k" => a.k = val()?.parse().map_err(|e| format!("--k: {e}"))?,
            "--detect" => a.detect = val()?.parse().map_err(|e| format!("--detect: {e}"))?,
            "--epsilon-ms" => {
                a.epsilon_ms = val()?.parse().map_err(|e| format!("--epsilon-ms: {e}"))?
            }
            "--dump-instance" => a.dump_instance = Some(val()?),
            "--dump-certify" => a.dump_certify = Some(val()?),
            "--top-roots" => {
                a.top_roots = val()?.parse().map_err(|e| format!("--top-roots: {e}"))?
            }
            "--scores" => a.scores = Some(val()?),
            "--top" => a.top = val()?.parse().map_err(|e| format!("--top: {e}"))?,
            "--flat" => a.flat = true,
            "--separation" => a.separation = true,
            "--session" => a.session = Some(val()?),
            "--schema" => a.schema = true,
            "--seeds-file" => a.seeds_file = Some(val()?),
            "--truth-file" => a.truth_file = Some(val()?),
            "--node" => a.nodes.push(val()?),
            "--save-session" => a.save_session = Some(val()?),
            "--window" => {
                let v = val()?;
                let (f, t) = v.split_once(',').ok_or("--window needs from,to")?;
                a.window = Some((
                    f.trim()
                        .parse()
                        .map_err(|e| format!("--window from: {e}"))?,
                    t.trim().parse().map_err(|e| format!("--window to: {e}"))?,
                ));
            }
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument {other}")),
        }
        i += if matches!(
            key,
            "-h" | "--help" | "--flat" | "--separation" | "--schema"
        ) {
            1
        } else {
            2
        };
    }
    if a.etw.is_none() && a.instance.is_none() && a.session.is_none() {
        return Err(
            "pass --etw <anomaly.json>, --instance <instance.json> or --session <id>".into(),
        );
    }
    Ok(a)
}

/// Seeds from a detector / analyst file. Object form: `{"node": {"prize"?,
/// "p"?, "tactic"?}}`; list form: `[{"node", "prize"?, "tactic"?}]`.
/// `prize` wins over `10·p`; with `flat` every seed gets 10.
fn read_seeds_file(path: &str, flat: bool) -> Result<Vec<(TpcsaSeed, f64)>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("parse {path}: {e}"))?;
    let mut out = Vec::new();
    let mut push = |node: String, obj: &serde_json::Value| {
        let p = obj.get("p").and_then(|x| x.as_f64());
        let score = obj.get("score").and_then(|x| x.as_f64()).unwrap_or(0.0);
        let prize = if flat {
            10.0
        } else if let Some(pr) = obj.get("prize").and_then(|x| x.as_f64()) {
            pr
        } else if let Some(p) = p {
            10.0 * p
        } else {
            10.0
        };
        let tactic = obj
            .get("tactic")
            .and_then(|x| x.as_str())
            .map(str::to_string);
        out.push((
            TpcsaSeed {
                node,
                prize: prize.clamp(0.0, 10.0),
                tactic,
            },
            score,
        ));
    };
    match v {
        serde_json::Value::Object(map) => {
            for (node, obj) in map {
                push(node, &obj);
            }
        }
        serde_json::Value::Array(items) => {
            for obj in items {
                if let Some(node) = obj.get("node").and_then(|x| x.as_str()) {
                    push(node.to_string(), &obj);
                }
            }
        }
        _ => return Err(format!("{path}: expected an object or a list")),
    }
    Ok(out)
}

fn read_truth_file(path: &str) -> Result<HashSet<String>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("parse {path}: {e}"))?;
    let list = v
        .as_array()
        .ok_or_else(|| format!("{path}: expected a JSON list of node ids"))?;
    Ok(list
        .iter()
        .filter_map(|x| x.as_str().map(str::to_string))
        .collect())
}

/// The separation test (work order §5): the tree with the most labelled
/// attack processes must carry the largest aggregate prize.
fn separation_report(rec: &Reconstruction, truth: &Truth) {
    if rec.trees.is_empty() {
        println!("  SEPARATION: no trees");
        return;
    }
    let mut rows: Vec<(usize, usize, f64, usize, &str)> = rec
        .trees
        .iter()
        .map(|t| {
            let attack = t
                .nodes()
                .iter()
                .filter(|n| truth.attack.contains(**n))
                .count();
            (
                t.rank,
                attack,
                t.prize,
                t.tactics.len(),
                t.root.node.as_str(),
            )
        })
        .collect();
    let attack_tree = rows.iter().max_by_key(|r| r.1).copied().unwrap();
    rows.sort_by(|a, b| b.2.total_cmp(&a.2));
    let rank_by_prize = rows.iter().position(|r| r.0 == attack_tree.0).unwrap() + 1;
    println!(
        "  SEPARATION: attack tree = rank {} (root {}, {} attack processes, prize {:.1}, {} tactics); rank by prize alone = {} of {}; {}",
        attack_tree.0,
        attack_tree.4,
        attack_tree.1,
        attack_tree.2,
        attack_tree.3,
        rank_by_prize,
        rows.len(),
        if rank_by_prize == 1 {
            "PASS (prizes separate the attack)"
        } else {
            "FAIL (prizes do not separate; only tactic ranking does)"
        }
    );
    for r in &rows {
        println!(
            "      by prize: rank-by-tactics {} root {} prize {:.1} attack {} tactics {}",
            r.0, r.4, r.2, r.1, r.3
        );
    }
}

/// Saved-session mode: load from the app's session store and reconstruct.
fn run_session(args: &Args) -> Result<(), String> {
    let id = args.session.as_deref().unwrap();
    let api = GraphHunterApi::new_noop();
    let t0 = Instant::now();
    let info = api
        .load_session_blocking(LoadSessionRequest {
            session_id: id.to_string(),
        })
        .map_err(|e| format!("load session {id}: {e}"))?;
    let session = api
        .sessions()
        .current_session()
        .ok_or("no current session after load")?;
    {
        let g = session.graph.read().map_err(|e| e.to_string())?;
        println!(
            "session {} ({:?}) loaded in {:.1}s: {} entities, {} relations",
            id,
            info.name,
            t0.elapsed().as_secs_f64(),
            g.entity_count(),
            g.relation_count()
        );
    }
    if args.schema {
        let g = session.graph.read().map_err(|e| e.to_string())?;
        let mut kinds: HashMap<String, usize> = HashMap::new();
        for e in g.entities.values() {
            *kinds.entry(e.entity_type.to_string()).or_default() += 1;
        }
        let mut kinds: Vec<_> = kinds.into_iter().collect();
        kinds.sort_by(|a, b| b.1.cmp(&a.1));
        println!("  entity types: {:?}", kinds);
        let mut rels: HashMap<(String, String, String, String), usize> = HashMap::new();
        let mut meta_keys: HashMap<String, usize> = HashMap::new();
        let mut range = (i64::MAX, i64::MIN);
        g.streaming.for_each_edge(|src, e| {
            let (Some(s), Some(d)) = (g.entities.get(&src), g.entities.get(&e.dest_sid)) else {
                return;
            };
            let meta = g.meta_store.get(e.metadata_offset);
            let etype = meta.get("event_type").cloned().unwrap_or_default();
            let rel = g.resolve_rel_type_name_raw(e.rel_type_tag, e.metadata_offset);
            *rels
                .entry((
                    rel,
                    etype,
                    s.entity_type.to_string(),
                    d.entity_type.to_string(),
                ))
                .or_default() += 1;
            for k in meta.keys() {
                *meta_keys.entry(k.clone()).or_default() += 1;
            }
            range.0 = range.0.min(e.timestamp);
            range.1 = range.1.max(e.timestamp);
        });
        let mut rels: Vec<_> = rels.into_iter().collect();
        rels.sort_by(|a, b| b.1.cmp(&a.1));
        println!("  timestamp range: {} .. {}", range.0, range.1);
        println!("  relations (rel_type, event_type, tail kind -> head kind): count");
        for ((rel, et, tk, hk), c) in rels.iter().take(40) {
            println!("    {rel:<12} {et:<28} {tk} -> {hk}: {c}");
        }
        let mut mk: Vec<_> = meta_keys.into_iter().collect();
        mk.sort_by(|a, b| b.1.cmp(&a.1));
        println!(
            "  edge metadata keys: {:?}",
            mk.iter().take(20).collect::<Vec<_>>()
        );
    }
    for id in &args.nodes {
        let g = session.graph.read().map_err(|e| e.to_string())?;
        let Some(sid) = g.interner.get(id) else {
            println!("  node {id}: not in graph");
            continue;
        };
        let ent = g
            .entities
            .get(&sid)
            .map(|e| e.entity_type.to_string())
            .unwrap_or_default();
        let mut rows: Vec<(i64, String, String, String)> = Vec::new();
        g.streaming.for_each_edge(|src, e| {
            if src != sid && e.dest_sid != sid {
                return;
            }
            let meta = g.meta_store.get(e.metadata_offset);
            let et = meta
                .get("event_type")
                .or_else(|| meta.get("type"))
                .cloned()
                .unwrap_or_else(|| g.resolve_rel_type_name_raw(e.rel_type_tag, e.metadata_offset));
            let other = if src == sid {
                g.interner.resolve(e.dest_sid)
            } else {
                g.interner.resolve(src)
            };
            let dir = if src == sid { "→" } else { "←" };
            rows.push((e.timestamp, dir.to_string(), et, other.to_string()));
        });
        rows.sort();
        let users: HashSet<&str> = rows.iter().map(|r| r.3.as_str()).collect();
        let mut kinds: HashMap<&str, usize> = HashMap::new();
        for r in &rows {
            *kinds.entry(r.2.as_str()).or_default() += 1;
        }
        println!(
            "  node {id} ({ent}): {} edges, {} distinct neighbours, t {} .. {}, types {:?}",
            rows.len(),
            users.len(),
            rows.first().map(|r| r.0).unwrap_or(0),
            rows.last().map(|r| r.0).unwrap_or(0),
            kinds
        );
        for r in rows.iter().take(40) {
            println!("      {} {} {:<28} {}", r.0, r.1, r.2, r.3);
        }
        if rows.len() > 40 {
            println!("      … {} more", rows.len() - 40);
        }
    }
    let Some(seeds_path) = &args.seeds_file else {
        return Ok(());
    };
    let seeds: Vec<TpcsaSeed> = read_seeds_file(seeds_path, args.flat)?
        .into_iter()
        .map(|(s, _)| s)
        .collect();
    println!("  {} seeds from {}", seeds.len(), seeds_path);
    let truth = match &args.truth_file {
        Some(p) => Some(read_truth_file(p)?),
        None => None,
    };
    let t1 = Instant::now();
    let resp = api
        .reconstruct_chain(ReconstructChainRequest {
            seeds,
            window: args.window.map(|(from, to)| TpcsaWindow { from, to }),
            k: Some(args.k),
            epsilon_ms: Some(args.epsilon_ms),
            top_roots: Some(args.top_roots),
            ..Default::default()
        })
        .map_err(|e| format!("reconstruct_chain: {e}"))?;
    let costs: Vec<String> = resp
        .export
        .etype_costs
        .iter()
        .map(|(k, v)| format!("{k}={v:.2}"))
        .collect();
    println!(
        "  exported {} nodes, {} arcs ({} flipped, {} skipped), {} terminals, {} roots, unknown seeds {:?} | costs {}",
        resp.export.nodes,
        resp.export.arcs,
        resp.export.flipped_arcs,
        resp.export.skipped_edges,
        resp.export.terminals,
        resp.export.root_candidates,
        resp.export.unknown_seeds,
        costs.join(" ")
    );
    let rec = Reconstruction {
        trees: resp.trees,
        ties: resp.ties,
        pruning: resp.pruning,
        objective: resp.objective,
        total_prize: resp.total_prize,
        rejected: resp.rejected,
    };
    report(&rec, None, t1.elapsed().as_secs_f64());
    if let Some(truth) = truth {
        for t in &rec.trees {
            let nodes = t.nodes();
            let hits: Vec<&str> = nodes
                .iter()
                .copied()
                .filter(|n| truth.contains(*n))
                .collect();
            println!(
                "  tree {} vs truth: {} of {} tree nodes are in the truth set ({} of {} truth ids covered); hits: {:?}",
                t.rank,
                hits.len(),
                nodes.len(),
                hits.len(),
                truth.len(),
                hits.iter().take(12).collect::<Vec<_>>()
            );
        }
    }
    for t in &rec.trees {
        println!("  tree {} arcs (root-first):", t.rank);
        for a in t.arcs.iter().take(40) {
            println!("      {} -[{} @ {}]-> {}", a.tail, a.etype, a.t, a.head);
        }
        if t.arcs.len() > 40 {
            println!("      … {} more", t.arcs.len() - 40);
        }
    }
    Ok(())
}

/// Loads the trace through the product parser into a graph, merging
/// metadata when an entity is seen twice (a start after a pre-start event
/// of the same PID must not lose its `is_warn` label).
fn load_etw(path: &str) -> Result<GraphHunter, String> {
    let t0 = Instant::now();
    let data = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    eprintln!(
        "read {:.1} MB in {:.1}s",
        data.len() as f64 / 1e6,
        t0.elapsed().as_secs_f64()
    );
    let t1 = Instant::now();
    let triples = EtwNodlinkParser.parse(&data);
    eprintln!(
        "parsed {} triples in {:.1}s",
        triples.len(),
        t1.elapsed().as_secs_f64()
    );
    drop(data);
    let t2 = Instant::now();
    let mut g = GraphHunter::new();
    g.reserve(triples.len() / 4, triples.len());
    for (src, rel, dst) in triples {
        for ent in [src, dst] {
            match g.get_entity_mut(&ent.id) {
                Some(existing) => {
                    for (k, v) in ent.metadata {
                        let overwrite = k == "is_warn" && v == "true";
                        if overwrite || !existing.metadata.contains_key(&k) {
                            existing.metadata.insert(k, v);
                        }
                    }
                }
                None => {
                    g.add_entity(ent).map_err(|e| e.to_string())?;
                }
            }
        }
        g.add_relation(rel).map_err(|e| e.to_string())?;
    }
    eprintln!(
        "graph: {} entities, {} relations in {:.1}s",
        g.entity_count(),
        g.relation_count(),
        t2.elapsed().as_secs_f64()
    );
    Ok(g)
}

struct Truth {
    attack: HashSet<String>,
    /// Labelled parent → child start arcs.
    start_arcs: HashSet<(String, String)>,
    processes: Vec<String>,
}

fn ground_truth(g: &GraphHunter) -> Truth {
    let mut attack = HashSet::new();
    let mut processes = Vec::new();
    for e in g.entities.values() {
        if e.entity_type == EntityType::Process {
            processes.push(e.id.clone());
            if e.metadata.get("is_warn").map(String::as_str) == Some("true") {
                attack.insert(e.id.clone());
            }
        }
    }
    processes.sort();
    let mut start_arcs = HashSet::new();
    g.streaming.for_each_edge(|src, e| {
        let (Some(s), Some(d)) = (g.entities.get(&src), g.entities.get(&e.dest_sid)) else {
            return;
        };
        if attack.contains(&s.id) && attack.contains(&d.id) {
            let meta = g.meta_store.get(e.metadata_offset);
            if meta.get("event_type").map(String::as_str) == Some("start") {
                start_arcs.insert((s.id.clone(), d.id.clone()));
            }
        }
    });
    Truth {
        attack,
        start_arcs,
        processes,
    }
}

fn synthetic_seeds(truth: &Truth, seed: u64, detect: f64, n_false: usize) -> Vec<TpcsaSeed> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut seeds = Vec::new();
    let mut attack: Vec<&String> = truth.attack.iter().collect();
    attack.sort();
    for id in attack {
        if rng.gen_range(0.0..1.0) < detect {
            seeds.push(TpcsaSeed {
                node: id.clone(),
                prize: 10.0 * rng.gen_range(0.6..1.0),
                tactic: None,
            });
        }
    }
    let benign: Vec<&String> = truth
        .processes
        .iter()
        .filter(|p| !truth.attack.contains(*p))
        .collect();
    let mut chosen = HashSet::new();
    while chosen.len() < n_false.min(benign.len()) {
        let idx = rng.gen_range(0..benign.len());
        if chosen.insert(idx) {
            seeds.push(TpcsaSeed {
                node: benign[idx].clone(),
                prize: 3.0 * rng.gen_range(0.3..1.0),
                tactic: None,
            });
        }
    }
    seeds
}

fn report(rec: &Reconstruction, truth: Option<&Truth>, elapsed_s: f64) {
    println!(
        "  pruning: {} → {} arcs, {} → {} nodes | objective {:.2} (total prize {:.2}) | {} trees, {} rejected, ties {:?} | {:.2}s",
        rec.pruning.arcs_before,
        rec.pruning.arcs_after,
        rec.pruning.nodes_before,
        rec.pruning.nodes_after,
        rec.objective,
        rec.total_prize,
        rec.trees.len(),
        rec.rejected.len(),
        rec.ties,
        elapsed_s
    );
    for t in &rec.trees {
        let nodes: Vec<&str> = t.nodes();
        let mut line = format!(
            "  tree {} root {} ({}, entry t={}) arcs {} collected {} dropped {} prize {:.1} cost {:.1} tactics {:?}",
            t.rank,
            t.root.node,
            t.root.kind,
            t.root.entry_time,
            t.arcs.len(),
            t.collected.len(),
            t.dropped.len(),
            t.prize,
            t.cost,
            t.tactics
        );
        if let Some(truth) = truth {
            let procs: Vec<&str> = nodes.iter().copied().filter(|n| n.contains('|')).collect();
            let tp = procs.iter().filter(|n| truth.attack.contains(**n)).count();
            let precision = if procs.is_empty() {
                0.0
            } else {
                tp as f64 / procs.len() as f64
            };
            let recall = if truth.attack.is_empty() {
                0.0
            } else {
                tp as f64 / truth.attack.len() as f64
            };
            let arc_hits = t
                .arcs
                .iter()
                .filter(|a| {
                    a.etype == "start"
                        && truth.start_arcs.contains(&(a.tail.clone(), a.head.clone()))
                })
                .count();
            let arc_recall = if truth.start_arcs.is_empty() {
                0.0
            } else {
                arc_hits as f64 / truth.start_arcs.len() as f64
            };
            line += &format!(
                " | processes {} P {:.2} R {:.2} arcR {:.2} ({}/{})",
                procs.len(),
                precision,
                recall,
                arc_recall,
                arc_hits,
                truth.start_arcs.len()
            );
        }
        println!("{line}");
        for c in t.connectors.iter().take(5) {
            let label = truth
                .map(|tr| {
                    if tr.attack.contains(&c.node) {
                        " [attack]"
                    } else {
                        " [unlabelled]"
                    }
                })
                .unwrap_or("");
            println!(
                "      connector {} ({}) terminal children {} descendants {}{}",
                c.node, c.kind, c.terminal_children, c.terminal_descendants, label
            );
        }
    }
    for r in &rec.rejected {
        println!("  REJECTED root {}: {:?}", r.root, r.problems);
    }
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            if !msg.is_empty() {
                eprintln!("error: {msg}");
            }
            eprintln!(
                "usage: tpcsa_bench --etw <anomaly.json> [--n-false 20] [--seeds 0,1,2] [--k 1] [--detect 0.8] [--epsilon-ms 1] [--dump-instance out.json]\n       tpcsa_bench --instance <instance.json> [--k 2]"
            );
            std::process::exit(if msg.is_empty() { 0 } else { 2 });
        }
    };
    let ropts = |k: usize| ReconstructOptions {
        greedy: GreedyOptions {
            k,
            budget: None,
            top_roots: args.top_roots,
        },
        ..Default::default()
    };

    if args.session.is_some() {
        if let Err(e) = run_session(&args) {
            eprintln!("{e}");
            std::process::exit(1);
        }
        return;
    }

    if let Some(path) = &args.instance {
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
            eprintln!("read {path}: {e}");
            std::process::exit(1)
        });
        let inst = Instance::from_json(&text).unwrap_or_else(|e| {
            eprintln!("parse {path}: {e}");
            std::process::exit(1)
        });
        println!(
            "instance {}: {} nodes, {} arcs, {} terminals, epsilon {}",
            path,
            inst.nodes.len(),
            inst.arcs.len(),
            inst.terminals().count(),
            inst.epsilon
        );
        let t0 = Instant::now();
        let rec = reconstruct(&inst, &ropts(args.k)).unwrap_or_else(|e| {
            eprintln!("reconstruct: {e}");
            std::process::exit(1)
        });
        report(&rec, None, t0.elapsed().as_secs_f64());
        return;
    }

    let path = args.etw.as_deref().unwrap();
    let graph = load_etw(path).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1)
    });
    if let Some(name) = &args.save_session {
        let api = GraphHunterApi::new_noop();
        let info = api
            .create_session(graph_hunter_api::dto::session::CreateSessionRequest {
                name: Some(name.clone()),
            })
            .unwrap_or_else(|e| {
                eprintln!("create session: {e}");
                std::process::exit(1)
            });
        {
            let session = api.sessions().current_session().expect("current session");
            let mut g = session.graph.write().expect("graph lock");
            *g = graph.clone();
        }
        let t0 = Instant::now();
        api.save_session_blocking(graph_hunter_api::dto::session::SaveSessionRequest {
            session_id: None,
        })
        .unwrap_or_else(|e| {
            eprintln!("save session: {e}");
            std::process::exit(1)
        });
        println!(
            "saved session {} ({:?}) in {:.1}s — load it in the app or pass --session-id to the demo",
            info.id,
            info.name,
            t0.elapsed().as_secs_f64()
        );
    }

    let truth = ground_truth(&graph);
    println!(
        "ground truth: {} processes, {} labelled attack, {} labelled start arcs",
        truth.processes.len(),
        truth.attack.len(),
        truth.start_arcs.len()
    );

    // Detector mode: one run with the scores file instead of synthetic seeds.
    let runs: Vec<(u64, Vec<TpcsaSeed>)> = if let Some(path) = &args.scores {
        let mut scored = read_seeds_file(path, args.flat).unwrap_or_else(|e| {
            eprintln!("{e}");
            std::process::exit(1)
        });
        scored.sort_by(|a, b| b.1.total_cmp(&a.1));
        if args.top > 0 {
            scored.truncate(args.top);
        }
        let seeds: Vec<TpcsaSeed> = scored.into_iter().map(|(s, _)| s).collect();
        let unknown = seeds
            .iter()
            .filter(|s| graph.get_entity(&s.node).is_none())
            .count();
        let n_attack = seeds
            .iter()
            .filter(|s| truth.attack.contains(&s.node))
            .count();
        let labelled = seeds.iter().filter(|s| s.tactic.is_some()).count();
        println!(
            "detector: {} terminals from {} ({} attack, {} unknown ids, {} with tactic, prizes {})",
            seeds.len(),
            path,
            n_attack,
            unknown,
            labelled,
            if args.flat { "flat 10" } else { "10·p" }
        );
        vec![(0, seeds)]
    } else {
        args.seeds
            .iter()
            .map(|&s| (s, synthetic_seeds(&truth, s, args.detect, args.n_false)))
            .collect()
    };

    for (seed, seeds) in runs {
        if args.scores.is_none() {
            let n_attack = seeds
                .iter()
                .filter(|s| truth.attack.contains(&s.node))
                .count();
            println!(
                "seed {seed}: {} terminals ({} attack, {} false)",
                seeds.len(),
                n_attack,
                seeds.len() - n_attack
            );
        }
        let opts = ExportOpts {
            seeds,
            window: None,
            epsilon_us: (args.epsilon_ms * 1000.0).round() as i64,
            score_threshold: None,
            kappa: graph_hunter_tpcsa::DEFAULT_KAPPA,
            external_ip_root_cost: 2.0,
            process_root_cost: 6.0,
            max_arcs: None,
        };
        let t0 = Instant::now();
        let (inst, stats) = build_instance(&graph, &opts).unwrap_or_else(|e| {
            eprintln!("export: {e}");
            std::process::exit(1)
        });
        let costs: Vec<String> = stats
            .etype_costs
            .iter()
            .map(|(k, v)| format!("{k}={v:.2}"))
            .collect();
        println!(
            "  exported {} nodes, {} arcs ({} flipped), {} terminals, {} roots in {:.1}s | costs {}",
            stats.nodes,
            stats.arcs,
            stats.flipped_arcs,
            stats.terminals,
            stats.root_candidates,
            t0.elapsed().as_secs_f64(),
            costs.join(" ")
        );
        if let Some(out) = &args.dump_instance {
            let out_path = if args.seeds.len() > 1 {
                format!("{out}.seed{seed}.json")
            } else {
                out.clone()
            };
            std::fs::write(&out_path, inst.to_json()).unwrap_or_else(|e| {
                eprintln!("write {out_path}: {e}");
                std::process::exit(1)
            });
            println!("  wrote {out_path}");
        }
        let t1 = Instant::now();
        let rec = reconstruct(&inst, &ropts(args.k)).unwrap_or_else(|e| {
            eprintln!("reconstruct: {e}");
            std::process::exit(1)
        });
        report(&rec, Some(&truth), t1.elapsed().as_secs_f64());
        if args.separation {
            separation_report(&rec, &truth);
        }
        if let Some(out) = &args.dump_certify {
            let (pruned, _) = graph_hunter_tpcsa::temporal_prune(&inst).expect("prune");
            let payload = serde_json::json!({
                "instance": pruned,
                "k": args.k,
                "time_limit": 120.0,
                "gap": 0.005,
                "warm_start": {
                    "roots": rec.trees.iter().map(|t| t.root.node.clone()).collect::<Vec<_>>(),
                    "arcs": rec.trees.iter().flat_map(|t| t.arcs.iter()).map(|a| serde_json::json!({"tail": a.tail, "head": a.head, "etype": a.etype, "t": a.t})).collect::<Vec<_>>(),
                },
            });
            let out_path = if args.seeds.len() > 1 {
                format!("{out}.seed{seed}.json")
            } else {
                out.clone()
            };
            std::fs::write(&out_path, serde_json::to_string(&payload).unwrap())
                .expect("write certify payload");
            println!(
                "  wrote certify payload {out_path} ({} pruned arcs)",
                pruned.arcs.len()
            );
        }
    }
}
