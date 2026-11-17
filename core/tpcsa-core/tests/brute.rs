//! Brute-force cross-checks on small random instances:
//!
//! * `temporal_prune` keeps exactly the arcs that lie on some
//!   time-respecting root→terminal walk (enumerated by DFS);
//! * every tree the greedy returns passes `verify`, and its forest
//!   objective is never below the exact optimum over all arborescence
//!   forests with ≤ k non-terminal roots (enumerated over arc subsets).

use std::collections::{HashMap, HashSet};

use graph_hunter_tpcsa::{
    Arc, GreedyOptions, Instance, Node, ReconstructOptions, reconstruct, schedule, temporal_prune,
    verify,
};

/// Tiny deterministic LCG so the test needs no crates.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn unit(&mut self) -> f64 {
        (self.next() % 10_000) as f64 / 10_000.0
    }
}

fn random_instance(seed: u64, n: usize, m: usize) -> Instance {
    let mut rng = Lcg(seed);
    let mut inst = Instance::new(1);
    for i in 0..n {
        let mut node = Node::new(format!("n{i}"), "process");
        let roll = rng.below(10);
        if roll < 3 {
            node.prize = 2.0 + 8.0 * rng.unit();
            node.tactic = Some(format!("tac{}", rng.below(3)));
        }
        if rng.below(10) < 6 {
            node.root_cost = Some(if rng.below(2) == 0 { 2.0 } else { 6.0 });
        }
        inst.nodes.push(node);
    }
    for _ in 0..m {
        let t = rng.below(n as u64) as usize;
        let mut h = rng.below(n as u64) as usize;
        if h == t {
            h = (h + 1) % n;
        }
        let time = rng.below(20) as i64;
        inst.arcs.push(Arc::point(
            format!("n{t}"),
            format!("n{h}"),
            "e",
            time,
            0.5 + 2.0 * rng.unit(),
        ));
    }
    inst
}

/// Arcs on some time-respecting walk from a root candidate to a terminal.
fn brute_prune(inst: &Instance) -> HashSet<usize> {
    let index = inst.index();
    let n = inst.nodes.len();
    let mut out: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, a) in inst.arcs.iter().enumerate() {
        out[index[a.tail.as_str()]].push(i);
    }
    let mut keep = HashSet::new();
    // DFS over (node, last_time, path) — bounded because times strictly increase.
    fn dfs(
        inst: &Instance,
        index: &HashMap<&str, usize>,
        out: &[Vec<usize>],
        u: usize,
        last: Option<i64>,
        path: &mut Vec<usize>,
        keep: &mut HashSet<usize>,
    ) {
        if inst.nodes[u].is_terminal() && !path.is_empty() {
            for &a in path.iter() {
                keep.insert(a);
            }
        }
        for &ai in &out[u] {
            let a = &inst.arcs[ai];
            let ok = match last {
                None => true,
                Some(t) => a.lo >= t + inst.epsilon,
            };
            if !ok {
                continue;
            }
            path.push(ai);
            dfs(
                inst,
                index,
                out,
                index[a.head.as_str()],
                Some(a.lo),
                path,
                keep,
            );
            path.pop();
        }
    }
    for (i, node) in inst.nodes.iter().enumerate() {
        if node.is_root_candidate() {
            dfs(inst, &index, &out, i, None, &mut Vec::new(), &mut keep);
        }
    }
    keep
}

/// Exact optimum (paper convention) over arc subsets forming a forest of
/// ≤ k arborescences rooted at non-terminal root candidates.
fn brute_optimum(inst: &Instance, k: usize) -> f64 {
    let index = inst.index();
    let m = inst.arcs.len();
    assert!(m <= 14, "brute force is exponential in arcs");
    let total_prize = inst.total_prize();
    let mut best = total_prize; // empty forest
    for mask in 1u32..(1 << m) {
        let chosen: Vec<usize> = (0..m).filter(|i| mask & (1 << i) != 0).collect();
        // in-degree ≤ 1
        let mut indeg: HashMap<&str, usize> = HashMap::new();
        let mut tails: HashSet<&str> = HashSet::new();
        for &i in &chosen {
            let a = &inst.arcs[i];
            *indeg.entry(a.head.as_str()).or_default() += 1;
            tails.insert(a.tail.as_str());
        }
        if indeg.values().any(|&c| c > 1) {
            continue;
        }
        // roots = tails with no incoming
        let roots: Vec<&str> = tails
            .iter()
            .copied()
            .filter(|t| !indeg.contains_key(t))
            .collect();
        if roots.len() > k || roots.is_empty() {
            continue;
        }
        if roots.iter().any(|r| {
            let nd = &inst.nodes[index[r]];
            !nd.is_root_candidate() || nd.is_terminal()
        }) {
            continue;
        }
        // Every arc reachable from some root (no cycles) and time-feasible per tree.
        let mut ok = true;
        let mut covered = 0;
        for r in &roots {
            // collect arcs in this root's component via BFS
            let mut comp: Vec<usize> = Vec::new();
            let mut frontier = vec![*r];
            while let Some(u) = frontier.pop() {
                for &i in &chosen {
                    let a = &inst.arcs[i];
                    if a.tail == u && !comp.contains(&i) {
                        comp.push(i);
                        frontier.push(a.head.as_str());
                    }
                }
            }
            covered += comp.len();
            let quads: Vec<(&str, &str, i64, i64)> = comp
                .iter()
                .map(|&i| {
                    let a = &inst.arcs[i];
                    (a.tail.as_str(), a.head.as_str(), a.lo, a.hi)
                })
                .collect();
            if schedule(inst.epsilon, r, &quads).is_err() {
                ok = false;
                break;
            }
        }
        if !ok || covered != chosen.len() {
            continue;
        }
        let arc_cost: f64 = chosen.iter().map(|&i| inst.arcs[i].cost).sum();
        let root_cost: f64 = roots
            .iter()
            .map(|r| inst.nodes[index[r]].root_cost.unwrap())
            .sum();
        let collected: f64 = indeg.keys().map(|h| inst.nodes[index[h]].prize).sum();
        let obj = arc_cost + root_cost + (total_prize - collected);
        if obj < best {
            best = obj;
        }
    }
    best
}

#[test]
fn prune_matches_walk_enumeration() {
    for seed in 0..60u64 {
        let inst = random_instance(seed, 7, 12);
        let expected = brute_prune(&inst);
        let (pruned, stats) = temporal_prune(&inst).unwrap();
        let got: HashSet<(String, String, i64)> = pruned
            .arcs
            .iter()
            .map(|a| (a.tail.clone(), a.head.clone(), a.lo))
            .collect();
        let want: HashSet<(String, String, i64)> = expected
            .iter()
            .map(|&i| {
                let a = &inst.arcs[i];
                (a.tail.clone(), a.head.clone(), a.lo)
            })
            .collect();
        assert_eq!(got, want, "seed {seed}");
        assert_eq!(stats.arcs_after, pruned.arcs.len());
    }
}

#[test]
fn greedy_is_verified_and_never_beats_the_exact_optimum() {
    let mut optimal_hits = 0;
    let mut total = 0;
    for seed in 100..160u64 {
        let inst = random_instance(seed, 6, 10);
        for k in 1..=2 {
            let opts = ReconstructOptions {
                greedy: GreedyOptions {
                    k,
                    ..Default::default()
                },
                ..Default::default()
            };
            let r = reconstruct(&inst, &opts).unwrap();
            assert!(r.rejected.is_empty(), "seed {seed} k {k}: {:?}", r.rejected);
            for t in &r.trees {
                assert!(verify(&inst, t).is_empty(), "seed {seed}");
                assert!(t.net_gain() > 0.0, "a kept tree must pay for itself");
            }
            let opt = brute_optimum(&inst, k);
            assert!(
                r.objective >= opt - 1e-9,
                "seed {seed} k {k}: greedy {} < optimum {}",
                r.objective,
                opt
            );
            total += 1;
            if (r.objective - opt).abs() < 1e-9 {
                optimal_hits += 1;
            }
        }
    }
    // The heuristic should be exact most of the time on these tiny instances.
    eprintln!("greedy matched the exact optimum in {optimal_hits}/{total} (instance, k) cases");
    assert!(
        optimal_hits * 10 >= total * 7,
        "only {optimal_hits}/{total} optimal"
    );
}
