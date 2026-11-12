//! Benchmark infrastructure for empirical evaluation.
//!
//! Provides synthetic graph generators (Erdős–Rényi, Barabási–Albert),
//! instrumented DFS with per-rule pruning counters, and ablation support.

use std::collections::HashMap;

use crate::entity::Entity;
use crate::graph::GraphHunter;
use crate::hypothesis::{Hypothesis, HypothesisStep};
use crate::relation::Relation;
use crate::types::{EntityType, RelationType, entity_type_matches, relation_type_matches};

// ── Concrete type arrays (excluding Any/wildcard) ──

const ENTITY_TYPES: [EntityType; 9] = [
    EntityType::IP,
    EntityType::Host,
    EntityType::User,
    EntityType::Process,
    EntityType::File,
    EntityType::Domain,
    EntityType::Registry,
    EntityType::URL,
    EntityType::Service,
];

const RELATION_TYPES: [RelationType; 9] = [
    RelationType::Auth,
    RelationType::Connect,
    RelationType::Execute,
    RelationType::Read,
    RelationType::Write,
    RelationType::DNS,
    RelationType::Modify,
    RelationType::Spawn,
    RelationType::Delete,
];

// ── Simple deterministic PRNG (xorshift64) for reproducibility ──

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 { 1 } else { seed })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_usize(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }

    fn next_f64(&mut self) -> f64 {
        (self.next_u64() as f64) / (u64::MAX as f64)
    }
}

// ── Synthetic Graph Generators ──

/// Generates an Erdős–Rényi random graph G(n, p).
/// Each directed edge (u, v) exists independently with probability p.
/// Entity/relation types are assigned uniformly at random.
/// Timestamps are uniform in [t_min, t_max].
pub fn generate_erdos_renyi(n: usize, p: f64, t_min: i64, t_max: i64, seed: u64) -> GraphHunter {
    let mut rng = Rng::new(seed);
    let mut g = GraphHunter::new();

    // Create entities with random types
    for i in 0..n {
        let etype = ENTITY_TYPES[rng.next_usize(ENTITY_TYPES.len())].clone();
        let entity = Entity::new(format!("v{}", i), etype);
        let _ = g.add_entity(entity);
    }

    // Create edges with probability p
    let t_range = (t_max - t_min).max(1);
    for i in 0..n {
        for j in 0..n {
            if i == j {
                continue;
            }
            if rng.next_f64() < p {
                let rtype = RELATION_TYPES[rng.next_usize(RELATION_TYPES.len())].clone();
                let ts = t_min + (rng.next_u64() % t_range as u64) as i64;
                let rel = Relation::new(format!("v{}", i), format!("v{}", j), rtype, ts);
                let _ = g.add_relation(rel);
            }
        }
    }

    g
}

/// Generates a Barabási–Albert preferential attachment graph.
/// Starts with m0 fully-connected seed nodes, then adds (n - m0) nodes
/// each connecting to m existing nodes with probability proportional to degree.
pub fn generate_barabasi_albert(
    n: usize,
    m: usize,
    t_min: i64,
    t_max: i64,
    seed: u64,
) -> GraphHunter {
    let mut rng = Rng::new(seed);
    let mut g = GraphHunter::new();
    let m0 = m.max(2);
    let t_range = (t_max - t_min).max(1);

    // Create seed nodes
    for i in 0..m0 {
        let etype = ENTITY_TYPES[rng.next_usize(ENTITY_TYPES.len())].clone();
        let entity = Entity::new(format!("v{}", i), etype);
        let _ = g.add_entity(entity);
    }

    // Fully connect seed nodes
    for i in 0..m0 {
        for j in 0..m0 {
            if i != j {
                let rtype = RELATION_TYPES[rng.next_usize(RELATION_TYPES.len())].clone();
                let ts = t_min + (rng.next_u64() % t_range as u64) as i64;
                let rel = Relation::new(format!("v{}", i), format!("v{}", j), rtype, ts);
                let _ = g.add_relation(rel);
            }
        }
    }

    // Track degrees for preferential attachment
    let mut degrees: Vec<usize> = vec![2 * (m0 - 1); m0]; // each seed has m0-1 in + m0-1 out
    let mut total_degree: usize = degrees.iter().sum();

    // Add remaining nodes with preferential attachment
    for i in m0..n {
        let etype = ENTITY_TYPES[rng.next_usize(ENTITY_TYPES.len())].clone();
        let entity = Entity::new(format!("v{}", i), etype);
        let _ = g.add_entity(entity);
        degrees.push(0);

        // Connect to m existing nodes with probability proportional to degree
        let mut targets = Vec::new();
        let current_n = i;
        for _ in 0..m.min(current_n) {
            let mut attempts = 0;
            loop {
                // Weighted random selection by degree
                let mut r = rng.next_usize(total_degree.max(1));
                let mut target = 0;
                for (idx, &deg) in degrees[..current_n].iter().enumerate() {
                    let d = deg.max(1); // ensure at least weight 1
                    if r < d {
                        target = idx;
                        break;
                    }
                    r = r.saturating_sub(d);
                }
                if !targets.contains(&target) {
                    targets.push(target);
                    break;
                }
                attempts += 1;
                if attempts > 100 {
                    // Fallback: pick any non-duplicate
                    for t in 0..current_n {
                        if !targets.contains(&t) {
                            targets.push(t);
                            break;
                        }
                    }
                    break;
                }
            }
        }

        for &t in &targets {
            let rtype = RELATION_TYPES[rng.next_usize(RELATION_TYPES.len())].clone();
            let ts = t_min + (rng.next_u64() % t_range as u64) as i64;
            // Bidirectional edges for BA model
            let rel = Relation::new(format!("v{}", i), format!("v{}", t), rtype.clone(), ts);
            let _ = g.add_relation(rel);
            let rel2 = Relation::new(format!("v{}", t), format!("v{}", i), rtype, ts + 1);
            let _ = g.add_relation(rel2);
            degrees[i] += 2;
            degrees[t] += 2;
            total_degree += 4;
        }
    }

    g
}

/// Plants one attack path that matches `hypothesis` exactly into `g`,
/// with strictly increasing edge timestamps so temporal monotonicity
/// holds and the chain is emitted rather than pruned.
///
/// The planted shape is derived from the hypothesis itself, not hard-
/// coded: vertex at position `i` takes `step[i].origin_type` (and the
/// last takes the final `dest_type`), each edge takes its step's relation
/// type. So whatever the hypothesis looks for, the plant provides exactly
/// that — the two can never drift apart the way a hard-coded chain would.
///
/// Vertex ids are prefixed `plant{idx}_` so a planted chain collides
/// neither with the generator's `v{i}` vertices nor with another planted
/// chain. `base_ts` is the first edge's timestamp; each subsequent hop is
/// `+1`, keeping the whole chain inside any realistic window.
///
/// An `Any` origin/dest type is materialised as a concrete `IP` — a
/// wildcard cannot be a real node's type. The harness's hypotheses are
/// fully concrete, so this only guards misuse.
pub fn plant_chain(g: &mut GraphHunter, hypothesis: &Hypothesis, idx: usize, base_ts: i64) {
    let steps = &hypothesis.steps;
    if steps.is_empty() {
        return;
    }
    let concrete = |t: &EntityType| -> EntityType {
        match t {
            EntityType::Any => EntityType::IP,
            other => other.clone(),
        }
    };
    let vid = |pos: usize| format!("plant{idx}_{pos}");

    for (i, step) in steps.iter().enumerate() {
        let _ = g.add_entity(Entity::new(vid(i), concrete(&step.origin_type)));
    }
    let last = steps.len() - 1;
    let _ = g.add_entity(Entity::new(
        vid(steps.len()),
        concrete(&steps[last].dest_type),
    ));

    for (i, step) in steps.iter().enumerate() {
        let ts = base_ts + i as i64;
        let _ = g.add_relation(Relation::new(
            vid(i),
            vid(i + 1),
            step.relation_type.clone(),
            ts,
        ));
    }
}

// ── Instrumented DFS with per-rule pruning counters ──

/// Detailed pruning statistics from an instrumented DFS run.
#[derive(Clone, Debug, Default)]
pub struct PruningStats {
    /// Total edges examined across all DFS nodes
    pub edges_examined: usize,
    /// Edges rejected by relation type pruning (Prune 1)
    pub rejected_rel_type: usize,
    /// Edges rejected by entity type pruning (Prune 2)
    pub rejected_ent_type: usize,
    /// Edges rejected by causal monotonicity (Prune 3)
    pub rejected_temporal: usize,
    /// Edges rejected by time window (Prune 4)
    pub rejected_time_window: usize,
    /// Edges rejected by k-simplicity (Prune 5)
    pub rejected_k_simple: usize,
    /// Total DFS nodes visited (recursive calls)
    pub nodes_visited: usize,
    /// Nodes visited per search tree level
    pub nodes_per_level: Vec<usize>,
    /// Results found
    pub results_count: usize,
}

impl PruningStats {
    /// Compute the measured effective branching factor.
    /// b_eff = (nodes at level L) / (nodes at level 0), geometric mean.
    pub fn measured_beff(&self) -> f64 {
        if self.nodes_per_level.len() < 2 {
            return 0.0;
        }
        let l0 = self.nodes_per_level[0] as f64;
        if l0 == 0.0 {
            return 0.0;
        }
        let depth = self.nodes_per_level.len() - 1;
        let l_last = self.nodes_per_level[depth] as f64;
        if l_last == 0.0 {
            return 0.0;
        }
        // Geometric mean branching factor: (N_L / N_0)^(1/L)
        (l_last / l0).powf(1.0 / depth as f64)
    }

    /// Per-rule rejection rates as fractions of total edges examined.
    pub fn rejection_rates(&self) -> (f64, f64, f64, f64, f64) {
        let total = self.edges_examined.max(1) as f64;
        (
            self.rejected_rel_type as f64 / total,
            self.rejected_ent_type as f64 / total,
            self.rejected_temporal as f64 / total,
            self.rejected_time_window as f64 / total,
            self.rejected_k_simple as f64 / total,
        )
    }
}

/// Runs the DFS search with full instrumentation, collecting per-rule pruning counts.
pub fn search_instrumented(
    graph: &GraphHunter,
    hypothesis: &Hypothesis,
    time_window: Option<(i64, i64)>,
) -> Result<(Vec<Vec<String>>, PruningStats), crate::errors::GraphError> {
    hypothesis
        .validate()
        .map_err(crate::errors::GraphError::InvalidHypothesis)?;

    let mut results: Vec<Vec<String>> = Vec::new();
    let k = hypothesis.k_simplicity.max(1);
    let depth = hypothesis.steps.len();
    let mut stats = PruningStats {
        nodes_per_level: vec![0; depth + 1],
        ..Default::default()
    };

    // Find starting candidates
    let first_step = &hypothesis.steps[0];
    let start_nodes: Vec<&str> = if first_step.origin_type == EntityType::Any {
        graph
            .entities
            .keys()
            .map(|sid| graph.interner.resolve(*sid))
            .collect()
    } else {
        graph
            .type_index
            .get(&first_step.origin_type)
            .map(|ids| ids.iter().map(|sid| graph.interner.resolve(*sid)).collect())
            .unwrap_or_default()
    };

    stats.nodes_per_level[0] = start_nodes.len();

    for &start_id in &start_nodes {
        let mut visit_count: HashMap<&str, usize> = HashMap::new();
        *visit_count.entry(start_id).or_insert(0) += 1;
        let mut path = vec![start_id.to_string()];
        stats.nodes_visited += 1;

        dfs_instrumented(
            graph,
            start_id,
            &hypothesis.steps,
            0,
            i64::MIN,
            time_window,
            &mut visit_count,
            k,
            &mut path,
            &mut results,
            &mut stats,
        );
    }

    stats.results_count = results.len();
    Ok((results, stats))
}

// Recursive DFS state threaded explicitly (same shape as the production
// matcher it instruments); a context struct would only obscure the mirror.
#[allow(clippy::too_many_arguments)]
fn dfs_instrumented<'a>(
    graph: &'a GraphHunter,
    current_node: &str,
    steps: &[HypothesisStep],
    step_idx: usize,
    last_timestamp: i64,
    time_window: Option<(i64, i64)>,
    visit_count: &mut HashMap<&'a str, usize>,
    k: usize,
    path: &mut Vec<String>,
    results: &mut Vec<Vec<String>>,
    stats: &mut PruningStats,
) {
    if step_idx >= steps.len() {
        results.push(path.clone());
        return;
    }

    let step = &steps[step_idx];

    // Get materialized edges (this is the instrumented path, not hot path)
    let edges = if step.relation_type != RelationType::Any {
        graph.get_relations_by_type(current_node, &step.relation_type)
    } else {
        graph.get_relations(current_node)
    };

    for edge in &edges {
        stats.edges_examined += 1;

        // Prune 1: relation type
        if !relation_type_matches(&step.relation_type, &edge.rel_type) {
            stats.rejected_rel_type += 1;
            continue;
        }

        // Prune 2: entity type
        let dest_sid = match graph.interner.get(&edge.dest_id) {
            Some(sid) => sid,
            None => {
                stats.rejected_ent_type += 1;
                continue;
            }
        };
        let dest_entity = match graph.entities.get(&dest_sid) {
            Some(e) if entity_type_matches(&step.dest_type, &e.entity_type) => e,
            _ => {
                stats.rejected_ent_type += 1;
                continue;
            }
        };

        // Prune 3: causal monotonicity
        if edge.timestamp < last_timestamp {
            stats.rejected_temporal += 1;
            continue;
        }

        // Prune 4: time window
        if let Some((tw_start, tw_end)) = time_window
            && (edge.timestamp < tw_start || edge.timestamp > tw_end)
        {
            stats.rejected_time_window += 1;
            continue;
        }

        // Prune 5: k-simplicity
        let dest_id_str = dest_entity.id.as_str();
        let count = visit_count.get(dest_id_str).copied().unwrap_or(0);
        if count >= k {
            stats.rejected_k_simple += 1;
            continue;
        }

        // Recurse
        stats.nodes_visited += 1;
        if step_idx + 1 < stats.nodes_per_level.len() {
            stats.nodes_per_level[step_idx + 1] += 1;
        }

        *visit_count.entry(dest_id_str).or_insert(0) += 1;
        path.push(dest_entity.id.clone());

        dfs_instrumented(
            graph,
            dest_id_str,
            steps,
            step_idx + 1,
            edge.timestamp,
            time_window,
            visit_count,
            k,
            path,
            results,
            stats,
        );

        path.pop();
        let c = visit_count.get_mut(dest_id_str).unwrap();
        *c -= 1;
        if *c == 0 {
            visit_count.remove(dest_id_str);
        }
    }
}

// ── Benchmark result struct ──

/// Complete benchmark result for a single configuration.
#[derive(Clone, Debug)]
pub struct BenchmarkResult {
    pub label: String,
    pub n_entities: usize,
    pub n_relations: usize,
    pub d_max: usize,
    pub d_avg: f64,
    pub n_entity_types: usize,
    pub n_relation_types: usize,
    pub hypothesis_length: usize,
    pub results_found: usize,
    pub time_us: u64,
    pub nodes_visited_pruned: usize,
    pub nodes_visited_naive: usize,
    pub pruning_stats: PruningStats,
    pub speedup: f64,
    pub measured_beff: f64,
    pub memory_bytes_approx: usize,
}

/// Compute graph structural parameters.
pub fn graph_params(g: &GraphHunter) -> (usize, usize, usize, f64, usize, usize) {
    let n = g.entity_count();
    let m = g.relation_count();
    let d_max = g
        .entities
        .keys()
        .map(|&sid| g.streaming.degree_of(sid))
        .max()
        .unwrap_or(0);
    let d_avg = if n > 0 { m as f64 / n as f64 } else { 0.0 };
    let n_etypes = g.type_index.keys().count();
    let n_rtypes: usize = {
        let mut rt_set = std::collections::HashSet::new();
        g.streaming.for_each_edge(|_src, e| {
            rt_set.insert(e.rel_type_tag);
        });
        rt_set.len()
    };
    (n, m, d_max, d_avg, n_etypes, n_rtypes)
}

/// Approximate memory usage of the graph in bytes.
pub fn approx_memory(g: &GraphHunter) -> usize {
    let entity_size = 200; // id + type + scores + metadata overhead
    let relation_size = 150; // ids + type + timestamp + metadata
    let n = g.entity_count();
    let m = g.relation_count();
    // entities HashMap + adjacency + type_index + reverse_adj + rel_index
    n * entity_size + m * relation_size * 3 // relations stored in adj, rel_index, plus reverse_adj ptrs
}

/// Run a full benchmark: instrumented pruned search + naive baseline.
pub fn run_benchmark(
    g: &GraphHunter,
    hypothesis: &Hypothesis,
    time_window: Option<(i64, i64)>,
    label: &str,
) -> BenchmarkResult {
    let (n, m, d_max, d_avg, n_etypes, n_rtypes) = graph_params(g);

    // Pruned instrumented search
    let start = std::time::Instant::now();
    let (results, stats) = search_instrumented(g, hypothesis, time_window).expect("search failed");
    let elapsed = start.elapsed();

    // Naive baseline
    let (_, naive_visited) = g
        .search_naive_dfs(hypothesis)
        .unwrap_or_else(|_| (vec![], 0));

    let speedup = if stats.nodes_visited > 0 {
        naive_visited as f64 / stats.nodes_visited as f64
    } else {
        f64::INFINITY
    };

    BenchmarkResult {
        label: label.to_string(),
        n_entities: n,
        n_relations: m,
        d_max,
        d_avg,
        n_entity_types: n_etypes,
        n_relation_types: n_rtypes,
        hypothesis_length: hypothesis.steps.len(),
        results_found: results.len(),
        time_us: elapsed.as_micros() as u64,
        nodes_visited_pruned: stats.nodes_visited,
        nodes_visited_naive: naive_visited,
        pruning_stats: stats.clone(),
        speedup,
        measured_beff: stats.measured_beff(),
        memory_bytes_approx: approx_memory(g),
    }
}

/// Build a typed hypothesis chain of given length with concrete types.
/// Pattern: User -[Execute]-> Process -[Spawn]-> Process -[Write]-> File
/// (alternates Spawn for intermediate steps, Write for final)
pub fn build_spawn_chain_hypothesis(length: usize) -> Hypothesis {
    let mut h = Hypothesis::new(format!("spawn_chain_L{}", length));
    if length == 0 {
        return h;
    }

    // First step: User -[Execute]-> Process
    h.steps.push(HypothesisStep::new(
        EntityType::User,
        RelationType::Execute,
        EntityType::Process,
    ));

    // Intermediate steps: Process -[Spawn]-> Process
    for _ in 1..length.saturating_sub(1) {
        h.steps.push(HypothesisStep::new(
            EntityType::Process,
            RelationType::Spawn,
            EntityType::Process,
        ));
    }

    // Final step: Process -[Write]-> File (if length > 1)
    if length > 1 {
        h.steps.push(HypothesisStep::new(
            EntityType::Process,
            RelationType::Write,
            EntityType::File,
        ));
    }

    h
}

/// Build a lateral movement hypothesis of given length.
/// IP -[Connect]-> Host -[Auth]-> User -[Execute]-> Process -[Write]-> File
pub fn build_lateral_movement_hypothesis(length: usize) -> Hypothesis {
    let steps_template = [
        HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host),
        HypothesisStep::new(EntityType::Host, RelationType::Auth, EntityType::User),
        HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process),
        HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File),
        HypothesisStep::new(EntityType::File, RelationType::Read, EntityType::Process),
    ];

    let mut h = Hypothesis::new(format!("lateral_L{}", length));
    h.steps.extend(steps_template.iter().take(length).cloned());
    h
}

// ── Reproducible performance harness (WS1.5) ──
//
// `run_benchmark` above measures one run and pairs it with the naive
// baseline for the pruning-ablation table. This harness answers a
// different question — latency *distribution* vs graph size — and is
// built to be run, not read: a fixed config set, a fixed seed, N repeats
// per config, and structured rows a script turns into a table or figure.
//
// SCOPE, stated honestly: this measures *performance* (latency, scale,
// approximate memory) on synthetic ER/BA graphs. It does NOT measure
// *efficacy* (step recall, path precision) — those need ground-truth
// labels from the DARPA datasets and belong to WS2. Emitting them here
// with no ground truth would be a fabricated number, so the harness
// leaves them out rather than invent them.
//
// Run under `--release`: debug DFS is several times slower and not
// representative of the numbers a paper reports.

/// Which synthetic generator produces a config's graph.
#[derive(Debug, Clone, Copy)]
pub enum BenchGenerator {
    /// Erdős–Rényi G(n, p).
    ErdosRenyi { n: usize, p: f64 },
    /// Barabási–Albert with m edges per new node.
    BarabasiAlbert { n: usize, m: usize },
}

impl BenchGenerator {
    fn name(&self) -> &'static str {
        match self {
            BenchGenerator::ErdosRenyi { .. } => "erdos_renyi",
            BenchGenerator::BarabasiAlbert { .. } => "barabasi_albert",
        }
    }

    fn build(&self, seed: u64) -> GraphHunter {
        match *self {
            BenchGenerator::ErdosRenyi { n, p } => {
                generate_erdos_renyi(n, p, 1_000_000, 2_000_000, seed)
            }
            BenchGenerator::BarabasiAlbert { n, m } => {
                generate_barabasi_albert(n, m, 1_000_000, 2_000_000, seed)
            }
        }
    }
}

/// One configuration in the performance suite.
#[derive(Debug, Clone, Copy)]
pub struct PerfConfig {
    pub label: &'static str,
    pub generator: BenchGenerator,
    /// Hypothesis chain length (lateral-movement shape).
    pub hypothesis_len: usize,
    /// Attack paths planted into the graph before search. Zero measures
    /// pure scan-and-prune work (the common no-match case); a positive
    /// value guarantees the emitter runs, so the latency reflects finding
    /// and materialising real paths, not just rejecting candidates.
    pub planted_chains: usize,
}

/// One row of the performance table: a config's latency distribution over
/// `runs` repeats. Serializable so the CLI can emit CSV or JSON verbatim.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PerfRow {
    pub config: String,
    pub generator: String,
    pub seed: u64,
    pub n_entities: usize,
    pub n_relations: usize,
    pub d_avg: f64,
    pub hypothesis_len: usize,
    pub planted_chains: usize,
    pub runs: usize,
    pub paths_found: usize,
    pub latency_p50_us: u64,
    pub latency_p95_us: u64,
    pub latency_mean_us: u64,
    pub latency_min_us: u64,
    pub latency_max_us: u64,
    /// Structural estimate (`approx_memory`), not measured RSS. Labelled
    /// so no reader mistakes it for a heap measurement.
    pub memory_bytes_approx: usize,
}

/// The fixed config set. Deliberately hard-coded, not parameterised: the
/// point of a reproducible harness is that everyone runs the *same*
/// configs, so the table is comparable across machines and commits.
pub fn default_perf_configs() -> Vec<PerfConfig> {
    use BenchGenerator::{BarabasiAlbert, ErdosRenyi};
    vec![
        PerfConfig {
            label: "ER-100",
            generator: ErdosRenyi { n: 100, p: 0.10 },
            hypothesis_len: 3,
            planted_chains: 0,
        },
        PerfConfig {
            label: "ER-500",
            generator: ErdosRenyi { n: 500, p: 0.02 },
            hypothesis_len: 3,
            planted_chains: 0,
        },
        PerfConfig {
            label: "ER-1K",
            generator: ErdosRenyi { n: 1000, p: 0.01 },
            hypothesis_len: 3,
            planted_chains: 0,
        },
        PerfConfig {
            label: "ER-5K",
            generator: ErdosRenyi { n: 5000, p: 0.002 },
            hypothesis_len: 3,
            planted_chains: 0,
        },
        PerfConfig {
            label: "BA-100",
            generator: BarabasiAlbert { n: 100, m: 3 },
            hypothesis_len: 3,
            planted_chains: 0,
        },
        PerfConfig {
            label: "BA-500",
            generator: BarabasiAlbert { n: 500, m: 3 },
            hypothesis_len: 3,
            planted_chains: 0,
        },
        PerfConfig {
            label: "BA-1K",
            generator: BarabasiAlbert { n: 1000, m: 3 },
            hypothesis_len: 3,
            planted_chains: 0,
        },
        PerfConfig {
            label: "BA-5K",
            generator: BarabasiAlbert { n: 5000, m: 3 },
            hypothesis_len: 3,
            planted_chains: 0,
        },
    ]
}

/// The `q`-th percentile (0.0–1.0) of a sorted slice via nearest-rank.
fn percentile_us(sorted: &[u64], q: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (q * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[rank.min(sorted.len() - 1)]
}

/// Runs one config `runs` times and summarises the latency distribution.
///
/// The graph is generated once and edges sorted once (so the binary-
/// search successor path is active), then the *search* is timed `runs`
/// times. Generation and sort are setup, not the thing being measured.
pub fn run_perf_config(config: &PerfConfig, seed: u64, runs: usize) -> PerfRow {
    measure_one(
        config.label.to_string(),
        config.generator,
        config.hypothesis_len,
        config.planted_chains,
        seed,
        runs,
    )
}

/// The measurement primitive: generate → plant → sort → time the search
/// `runs` times → summarise. An owned `label` lets callers (the fixed
/// suite and the scaling sweep) name rows however they need.
pub fn measure_one(
    label: String,
    generator: BenchGenerator,
    hypothesis_len: usize,
    planted_chains: usize,
    seed: u64,
    runs: usize,
) -> PerfRow {
    let mut g = generator.build(seed);
    let hypothesis = build_lateral_movement_hypothesis(hypothesis_len);
    // Plant BEFORE the sort so the planted edges land in the sorted CSR
    // the binary-search successor path reads. Timestamps are spaced far
    // apart per chain so chains never interleave into a spurious match.
    for idx in 0..planted_chains {
        plant_chain(&mut g, &hypothesis, idx, 1_500_000 + (idx as i64) * 1000);
    }
    let _ = g.sort_edges_by_timestamp();
    let (n, m, _d_max, d_avg, _et, _rt) = graph_params(&g);

    let runs = runs.max(1);
    let mut latencies: Vec<u64> = Vec::with_capacity(runs);
    let mut paths_found = 0usize;
    for _ in 0..runs {
        let start = std::time::Instant::now();
        let (paths, _truncated) = g
            .search_temporal_pattern(&hypothesis, None, None)
            .expect("search must not fail on a generated graph");
        latencies.push(start.elapsed().as_micros() as u64);
        paths_found = paths.len();
    }
    latencies.sort_unstable();
    let sum: u128 = latencies.iter().map(|&x| x as u128).sum();

    PerfRow {
        config: label,
        generator: generator.name().to_string(),
        seed,
        n_entities: n,
        n_relations: m,
        d_avg,
        hypothesis_len,
        planted_chains,
        runs,
        paths_found,
        latency_p50_us: percentile_us(&latencies, 0.50),
        latency_p95_us: percentile_us(&latencies, 0.95),
        latency_mean_us: (sum / runs as u128) as u64,
        latency_min_us: *latencies.first().unwrap(),
        latency_max_us: *latencies.last().unwrap(),
        memory_bytes_approx: approx_memory(&g),
    }
}

/// Scaling sweep for the "where does the DFS break?" study (D3.1).
///
/// Erdős–Rényi at a **fixed average degree** — `p = avg_degree / (n−1)`
/// holds density constant as `n` grows, so the row-to-row change isolates
/// the effect of |E| rather than confounding it with densification. Sizes
/// are swept in one place so a latency-vs-|E| curve falls out of the CSV
/// directly. `plant` guarantees the emitter runs; set 0 for the pure-scan
/// curve.
pub fn run_perf_scaling(
    seed: u64,
    runs: usize,
    sizes: &[usize],
    avg_degree: f64,
    hypothesis_len: usize,
    plant: usize,
) -> Vec<PerfRow> {
    sizes
        .iter()
        .map(|&n| {
            let denom = n.saturating_sub(1).max(1) as f64;
            let p = (avg_degree / denom).clamp(0.0, 1.0);
            measure_one(
                format!("ER-{n}"),
                BenchGenerator::ErdosRenyi { n, p },
                hypothesis_len,
                plant,
                seed,
                runs,
            )
        })
        .collect()
}

/// Runs the full fixed suite. Single-threaded and deterministic: same
/// seed, same machine → same graphs and comparable latencies.
///
/// `paths_found` is typically 0 on these synthetic graphs, and that is
/// expected, not a bug: types are assigned uniformly at random, so a
/// specific 3-step *typed* chain almost never closes. What the harness
/// measures is search *work* — start selection, NLF/k-hop/semijoin
/// pruning, temporal expansion — which the DFS does in full whether or
/// not it emits. That is also the common case in real hunting: most
/// hypotheses run and find nothing, and their latency is what an analyst
/// waits on. Planting attack subgraphs to exercise the emitter is WS2
/// work (it needs a ground-truth model), tracked separately.
pub fn run_perf_suite(seed: u64, runs: usize) -> Vec<PerfRow> {
    run_perf_suite_planted(seed, runs, 0)
}

/// Like [`run_perf_suite`] but plants `planted_chains` attack paths into
/// every config first. `planted_chains = 0` is the pure-scan suite; a
/// positive value makes every config's search emit that many paths, so
/// the table measures the find-and-materialise cost rather than only the
/// reject-everything cost. Both are reproducible for a given seed.
pub fn run_perf_suite_planted(seed: u64, runs: usize, planted_chains: usize) -> Vec<PerfRow> {
    default_perf_configs()
        .iter()
        .map(|c| {
            let cfg = PerfConfig {
                planted_chains,
                ..*c
            };
            run_perf_config(&cfg, seed, runs)
        })
        .collect()
}

/// CSV serialization of a perf table — header plus one row each. Kept
/// dependency-free (no csv crate) since every field is a plain scalar.
pub fn perf_rows_to_csv(rows: &[PerfRow]) -> String {
    let mut out = String::from(
        "config,generator,seed,n_entities,n_relations,d_avg,hypothesis_len,planted_chains,runs,\
         paths_found,latency_p50_us,latency_p95_us,latency_mean_us,latency_min_us,latency_max_us,\
         memory_bytes_approx\n",
    );
    for r in rows {
        out.push_str(&format!(
            "{},{},{},{},{},{:.4},{},{},{},{},{},{},{},{},{},{}\n",
            r.config,
            r.generator,
            r.seed,
            r.n_entities,
            r.n_relations,
            r.d_avg,
            r.hypothesis_len,
            r.planted_chains,
            r.runs,
            r.paths_found,
            r.latency_p50_us,
            r.latency_p95_us,
            r.latency_mean_us,
            r.latency_min_us,
            r.latency_max_us,
            r.memory_bytes_approx,
        ));
    }
    out
}

/// Format benchmark results as a LaTeX table row.
pub fn format_latex_row(r: &BenchmarkResult) -> String {
    let (rr_rel, rr_ent, rr_temp, _rr_win, _rr_cycle) = r.pruning_stats.rejection_rates();
    format!(
        "{} & {} & {} & {} & {:.1} & {} & {} & {:.1} & {} & {:.1} & {:.1} & {:.1} & {:.1} & {:.1} \\\\",
        r.label,
        r.n_entities,
        r.n_relations,
        r.d_max,
        r.d_avg,
        r.hypothesis_length,
        r.results_found,
        r.time_us as f64 / 1000.0, // ms
        r.nodes_visited_pruned,
        r.measured_beff,
        rr_rel * 100.0,
        rr_ent * 100.0,
        rr_temp * 100.0,
        r.speedup,
    )
}

#[cfg(test)]
mod perf_harness_tests {
    use super::*;

    /// The same seed produces the same graph and therefore the same
    /// structural numbers — the property the whole harness rests on. (The
    /// *latencies* are wall-clock and will vary; the graph shape must not.)
    #[test]
    fn the_suite_is_deterministic_in_graph_shape() {
        let a = run_perf_config(&default_perf_configs()[0], 42, 2);
        let b = run_perf_config(&default_perf_configs()[0], 42, 2);
        assert_eq!(a.n_entities, b.n_entities);
        assert_eq!(a.n_relations, b.n_relations);
        assert_eq!(a.paths_found, b.paths_found);
        assert_eq!(a.seed, 42);
    }

    /// Percentiles must be ordered and inside the observed range — a
    /// guard against an off-by-one in the nearest-rank index.
    #[test]
    fn percentiles_are_ordered_and_bounded() {
        let row = run_perf_config(&default_perf_configs()[0], 7, 20);
        assert!(row.latency_min_us <= row.latency_p50_us);
        assert!(row.latency_p50_us <= row.latency_p95_us);
        assert!(row.latency_p95_us <= row.latency_max_us);
        assert_eq!(row.runs, 20);
    }

    #[test]
    fn percentile_nearest_rank_endpoints() {
        let xs = [10u64, 20, 30, 40, 50];
        assert_eq!(percentile_us(&xs, 0.0), 10);
        assert_eq!(percentile_us(&xs, 1.0), 50);
        assert_eq!(percentile_us(&xs, 0.5), 30);
        assert_eq!(percentile_us(&[], 0.5), 0);
    }

    /// The CSV header column count must match every data row's field
    /// count, or a downstream parser silently misaligns.
    #[test]
    fn csv_header_and_rows_have_equal_arity() {
        let rows = run_perf_suite_planted(1, 2, 3);
        let csv = perf_rows_to_csv(&rows);
        let mut lines = csv.lines();
        let header_cols = lines.next().unwrap().split(',').count();
        for line in lines {
            assert_eq!(line.split(',').count(), header_cols, "row: {line}");
        }
    }

    /// Planting a matching chain must make the search emit it. Without a
    /// plant the same config finds nothing, so this also pins that the
    /// plant — not incidental structure — is what produced the match.
    #[test]
    fn planting_a_chain_makes_the_search_find_it() {
        let base = PerfConfig {
            planted_chains: 0,
            ..default_perf_configs()[0]
        };
        let planted = PerfConfig {
            planted_chains: 5,
            ..default_perf_configs()[0]
        };
        let none = run_perf_config(&base, 3, 1);
        let some = run_perf_config(&planted, 3, 1);
        assert_eq!(none.paths_found, 0, "no plant, no match on this seed");
        assert!(
            some.paths_found >= 5,
            "5 planted chains must each be found; got {}",
            some.paths_found
        );
        assert_eq!(some.planted_chains, 5);
        // Planting adds vertices and edges — the graph really grew.
        assert!(some.n_entities > none.n_entities);
    }

    /// The scaling sweep holds average degree roughly constant as n grows,
    /// so latency rows compare on |E| and not on a moving density.
    #[test]
    fn scaling_sweep_holds_density_across_sizes() {
        let rows = run_perf_scaling(9, 2, &[1_000, 4_000], 10.0, 3, 0);
        assert_eq!(rows.len(), 2);
        // Avg degree stays near the requested 10 at both sizes.
        for r in &rows {
            assert!((r.d_avg - 10.0).abs() < 2.0, "d_avg drifted: {}", r.d_avg);
        }
        // Larger n → more edges.
        assert!(rows[1].n_relations > rows[0].n_relations);
    }

    /// A planted chain honours temporal monotonicity, so it survives the
    /// strict matcher — a guard that the plant's increasing timestamps
    /// are actually increasing.
    #[test]
    fn a_planted_chain_is_temporally_valid() {
        use crate::graph::GraphHunter;
        let mut g = GraphHunter::new();
        let h = build_lateral_movement_hypothesis(3);
        plant_chain(&mut g, &h, 0, 1000);
        let _ = g.sort_edges_by_timestamp();
        let (paths, _) = g.search_temporal_pattern(&h, None, None).unwrap();
        assert_eq!(
            paths.len(),
            1,
            "one planted chain → one match, got {paths:?}"
        );
    }
}
