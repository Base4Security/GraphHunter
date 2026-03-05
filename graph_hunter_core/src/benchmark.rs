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
pub fn generate_erdos_renyi(
    n: usize,
    p: f64,
    t_min: i64,
    t_max: i64,
    seed: u64,
) -> GraphHunter {
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
        graph.entities.keys().map(|sid| graph.interner.resolve(*sid)).collect()
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

    // Use secondary index when concrete relation type
    let edges: &[Relation] = if step.relation_type != RelationType::Any {
        graph.get_relations_by_type(current_node, &step.relation_type)
    } else {
        graph.get_relations(current_node)
    };

    for edge in edges {
        stats.edges_examined += 1;

        // Prune 1: relation type
        if !relation_type_matches(&step.relation_type, &edge.rel_type) {
            stats.rejected_rel_type += 1;
            continue;
        }

        // Prune 2: entity type
        let dest_sid = match graph.interner.get(&edge.dest_id) {
            Some(sid) => sid,
            None => { stats.rejected_ent_type += 1; continue; }
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
        if let Some((tw_start, tw_end)) = time_window {
            if edge.timestamp < tw_start || edge.timestamp > tw_end {
                stats.rejected_time_window += 1;
                continue;
            }
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
        .adjacency_list
        .values()
        .map(|edges| edges.len())
        .max()
        .unwrap_or(0);
    let d_avg = if n > 0 { m as f64 / n as f64 } else { 0.0 };
    let n_etypes = g.type_index.keys().count();
    let n_rtypes: usize = {
        let mut rt_set = std::collections::HashSet::new();
        for edges in g.adjacency_list.values() {
            for e in edges {
                rt_set.insert(std::mem::discriminant(&e.rel_type));
            }
        }
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
    let (results, stats) =
        search_instrumented(g, hypothesis, time_window).expect("search failed");
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
    let steps_template = vec![
        HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host),
        HypothesisStep::new(EntityType::Host, RelationType::Auth, EntityType::User),
        HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process),
        HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File),
        HypothesisStep::new(EntityType::File, RelationType::Read, EntityType::Process),
    ];

    let mut h = Hypothesis::new(format!("lateral_L{}", length));
    for i in 0..length.min(steps_template.len()) {
        h.steps.push(steps_template[i].clone());
    }
    h
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
