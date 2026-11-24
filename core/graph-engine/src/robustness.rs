//! Robustness of an attribution against lost evidence.
//!
//! A hunt match says a hypothesis holds between two entities. Two numbers say
//! how much evidence that conclusion rests on:
//!
//! - **λ**, the least number of records whose loss leaves no match between
//!   them;
//! - **ρ**, the least number of failure domains (datasets, collectors,
//!   connectors…) whose loss does.
//!
//! ρ ≤ λ when every record sits in one domain. A *gap* (λ ≥ 2, ρ = 1) is
//! evidence that looks redundant record by record but falls with a single
//! domain.
//!
//! λ is a minimum cut over the DAG of matches. Each candidate edge group is a
//! unit-capacity node; consecutive steps meet through a time ladder per
//! vertex, so a step-`i` edge reaches every step-`i+1` edge at or after its
//! timestamp (minus the hypothesis' clock skew δ) with a number of arcs
//! linear in the candidates. ρ is a colored cut, NP-hard in general. It is
//! bracketed by domain-disjoint chains (each needs its own failure, a lower
//! bound) and by the domains of the λ cut (an upper bound), and computed
//! exactly by enumerating domain sets when the bounds differ and the support
//! has few domains. Whether ρ = 1 is always exact: every domain is dropped in
//! turn.
//!
//! Scope of this first version: chain hypotheses (one step after another)
//! with their types, predicates, clock skew and an optional time window.
//! k-simplicity is not enforced here, so a chain that revisits a vertex
//! (a self-loop, a cycle) counts as support.

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::graph::GraphHunter;
use crate::hypothesis::{Hypothesis, all_predicates_match};
use crate::relation::Relation;
use crate::types::{entity_type_matches, relation_type_matches};

/// What counts as one record when λ is counted.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "keys", rename_all = "snake_case")]
pub enum RecordKey {
    /// Every edge is its own record.
    Edge,
    /// Edges equal in endpoints, type, timestamp and dataset are one record:
    /// the same event ingested twice, or emitted twice by a parser.
    #[default]
    Identical,
    /// Edges that share these metadata values are one record, e.g.
    /// `["Computer", "EventRecordID"]`. An edge missing any of the keys falls
    /// back to `Identical`.
    Metadata(Vec<String>),
}

/// Where an edge's failure domain is read from.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "key", rename_all = "snake_case")]
pub enum DomainBase {
    /// The dataset the edge was loaded from.
    #[default]
    Dataset,
    /// The value of one metadata field, e.g. the Sentinel table (`Type`).
    Metadata(String),
}

/// How edges map to failure domains.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DomainSpec {
    #[serde(default)]
    pub base: DomainBase,
    /// Expands a base value into the components it depends on (a shared risk
    /// group): the edge is lost when any of them fails. Values not listed
    /// stand for themselves.
    #[serde(default)]
    pub groups: HashMap<String, Vec<String>>,
}

/// Options for [`attribution_robustness`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RobustnessOptions {
    #[serde(default)]
    pub record_key: RecordKey,
    #[serde(default)]
    pub domains: DomainSpec,
    #[serde(default)]
    pub time_window: Option<(i64, i64)>,
    /// ρ is enumerated exactly only when the support has at most this many
    /// domains; above it the result carries the bounds.
    #[serde(default = "default_max_exact_domains")]
    pub max_exact_domains: usize,
}

fn default_max_exact_domains() -> usize {
    16
}

/// Hard ceiling on `max_exact_domains`, whatever the caller asks for: the
/// enumeration grows with the binomial of the domain count, and 20 domains
/// already mean up to 184,756 candidate sets per size.
pub const MAX_EXACT_DOMAINS: usize = 20;

/// Error returned when the enclosing [`crate::cancel::scope`] token is
/// cancelled mid-computation; the partial result is discarded.
pub const CANCELLED: &str = "attribution robustness cancelled";

impl Default for RobustnessOptions {
    fn default() -> Self {
        Self {
            record_key: RecordKey::default(),
            domains: DomainSpec::default(),
            time_window: None,
            max_exact_domains: default_max_exact_domains(),
        }
    }
}

/// λ and ρ for one attribution, with the cuts that witness them.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttributionRobustness {
    pub source: String,
    pub target: String,
    /// Whether some match joins them with all the evidence present.
    pub holds: bool,
    /// Matching edge chains (saturating).
    pub chains: u64,
    /// Distinct records in the support.
    pub records: usize,
    pub lambda: usize,
    /// False when one record supports more than one step or edge; `lambda`
    /// is then an upper bound.
    pub lambda_exact: bool,
    /// Records whose loss leaves no match.
    pub lambda_cut: Vec<String>,
    /// Failure domains present in the support.
    pub domains: Vec<String>,
    pub rho_lower: usize,
    pub rho_upper: usize,
    /// Domains whose loss leaves no match: the smallest set found.
    pub rho_cut: Vec<String>,
    /// Domains that break the attribution on their own (ρ = 1 iff non-empty).
    pub single_domain_breaks: Vec<String>,
}

impl AttributionRobustness {
    /// ρ when the bounds meet.
    pub fn rho(&self) -> Option<usize> {
        (self.rho_lower == self.rho_upper).then_some(self.rho_lower)
    }

    /// λ ≥ 2 with ρ = 1: redundancy that a single domain takes away.
    pub fn gap(&self) -> bool {
        self.holds && self.lambda_exact && self.lambda >= 2 && !self.single_domain_breaks.is_empty()
    }
}

/// One node of the match DAG: the edges at one step that share endpoints,
/// timestamp and record.
struct Group {
    step: usize,
    src: String,
    dst: String,
    ts: i64,
    record: String,
    /// Domain labels of each edge in the group; the group survives while one
    /// edge keeps all its labels.
    edges: Vec<Vec<String>>,
}

/// Computes λ and ρ for the attribution `hypothesis` from `source` to
/// `target`: the endpoints of a hunt result, whatever the interior.
pub fn attribution_robustness(
    graph: &GraphHunter,
    hypothesis: &Hypothesis,
    source: &str,
    target: &str,
    options: &RobustnessOptions,
) -> Result<AttributionRobustness, String> {
    hypothesis.validate()?;
    let cancel = crate::cancel::current();
    let delta = hypothesis.resolve_skew_delta();
    let groups = support(graph, hypothesis, source, target, options, delta);
    if cancel.is_cancelled() {
        return Err(CANCELLED.into());
    }
    let steps = hypothesis.steps.len();
    let dag = Dag::new(&groups, steps, delta);

    let mut out = AttributionRobustness {
        source: source.to_string(),
        target: target.to_string(),
        holds: false,
        chains: 0,
        records: 0,
        lambda: 0,
        lambda_exact: true,
        lambda_cut: Vec::new(),
        domains: Vec::new(),
        rho_lower: 0,
        rho_upper: 0,
        rho_cut: Vec::new(),
        single_domain_breaks: Vec::new(),
    };
    if dag.chain(|_| true).is_none() {
        return Ok(out);
    }
    out.holds = true;
    out.chains = dag.count_chains();

    // λ: records per group, exact when no record spans two groups.
    let mut groups_of_record: HashMap<&str, usize> = HashMap::new();
    for g in &groups {
        *groups_of_record.entry(g.record.as_str()).or_default() += 1;
    }
    out.records = groups_of_record.len();
    out.lambda_exact = groups_of_record.values().all(|&n| n == 1);
    let (flow, cut) = dag.min_cut();
    let cut_records: BTreeSet<&str> = cut.iter().map(|&g| groups[g].record.as_str()).collect();
    out.lambda = if out.lambda_exact {
        flow
    } else {
        cut_records.len()
    };
    out.lambda_cut = cut_records.iter().map(|r| r.to_string()).collect();

    // ρ.
    let domains: BTreeSet<&str> = groups
        .iter()
        .flat_map(|g| g.edges.iter().flatten())
        .map(String::as_str)
        .collect();
    out.domains = domains.iter().map(|d| d.to_string()).collect();
    let survives = |g: &Group, failed: &HashSet<&str>| {
        g.edges
            .iter()
            .any(|labels| labels.iter().all(|l| !failed.contains(l.as_str())))
    };
    for &d in &domains {
        if cancel.is_cancelled() {
            return Err(CANCELLED.into());
        }
        let failed: HashSet<&str> = [d].into_iter().collect();
        if dag.chain(|i| survives(&groups[i], &failed)).is_none() {
            out.single_domain_breaks.push(d.to_string());
        }
    }

    // Lower bound: chains kept alive by pairwise disjoint label sets.
    let mut used: HashSet<&str> = HashSet::new();
    let mut lower = 0usize;
    let usable = |g: &Group, used: &HashSet<&str>| {
        g.edges
            .iter()
            .find(|labels| labels.iter().all(|l| !used.contains(l.as_str())))
            .cloned()
    };
    while !cancel.is_cancelled()
        && let Some(chain) = dag.chain(|i| usable(&groups[i], &used).is_some())
    {
        for &g in &chain {
            if let Some(labels) = usable(&groups[g], &used) {
                for l in labels {
                    let l: &str = domains.get(l.as_str()).copied().unwrap_or("");
                    used.insert(l);
                }
            }
        }
        lower += 1;
    }

    // Upper bound: one label per edge of every group in the λ cut.
    let mut upper_set: BTreeSet<&str> = BTreeSet::new();
    for &g in &cut {
        for labels in &groups[g].edges {
            if let Some(l) = labels.first() {
                upper_set.insert(domains.get(l.as_str()).copied().unwrap_or(""));
            }
        }
    }
    let mut upper = upper_set.len();
    let mut rho_cut: Vec<String> = upper_set.iter().map(|d| d.to_string()).collect();
    if let Some(d) = out.single_domain_breaks.first() {
        upper = 1;
        rho_cut = vec![d.clone()];
    }
    // No single domain breaks it, so at least two are needed (and any one
    // that did would already be the upper bound).
    let floor = if out.single_domain_breaks.is_empty() {
        2
    } else {
        1
    };
    let mut lower = lower.max(floor).min(upper);

    // Exact ρ between the bounds, when there are few domains.
    let max_exact = options.max_exact_domains.min(MAX_EXACT_DOMAINS);
    if lower < upper && domains.len() <= max_exact {
        let all: Vec<&str> = domains.iter().copied().collect();
        // The smallest failing set below the upper bound, if any. A
        // cancellation also stops the search; it is reported below.
        let smaller = (lower..upper).find_map(|k| {
            combinations(all.len(), k).find(|combo| {
                if cancel.is_cancelled() {
                    return true;
                }
                let failed: HashSet<&str> = combo.iter().map(|&i| all[i]).collect();
                dag.chain(|i| survives(&groups[i], &failed)).is_none()
            })
        });
        if cancel.is_cancelled() {
            return Err(CANCELLED.into());
        }
        if let Some(combo) = smaller {
            upper = combo.len();
            rho_cut = combo.iter().map(|&i| all[i].to_string()).collect();
        }
        lower = upper;
    }
    if cancel.is_cancelled() {
        return Err(CANCELLED.into());
    }
    out.rho_lower = lower;
    out.rho_upper = upper;
    out.rho_cut = rho_cut;
    Ok(out)
}

/// The edges that can take part in some match from `source` to `target`,
/// grouped by step, endpoints, timestamp and record.
fn support(
    graph: &GraphHunter,
    hypothesis: &Hypothesis,
    source: &str,
    target: &str,
    options: &RobustnessOptions,
    delta: i64,
) -> Vec<Group> {
    let steps = &hypothesis.steps;
    let cancel = crate::cancel::current();
    let type_ok = |id: &str, t: &crate::types::EntityType| {
        graph
            .get_entity(id)
            .is_some_and(|e| entity_type_matches(t, &e.entity_type))
    };
    let mut groups: Vec<Group> = Vec::new();
    let mut index: HashMap<(usize, String, String, i64, String), usize> = HashMap::new();
    let mut frontier: BTreeSet<String> = BTreeSet::new();
    if type_ok(source, &steps[0].origin_type) {
        frontier.insert(source.to_string());
    }
    let mut edge_serial = 0usize;
    for (i, step) in steps.iter().enumerate() {
        let last = i + 1 == steps.len();
        let mut next = BTreeSet::new();
        for v in &frontier {
            // A hub frontier can be long; the caller checks the token after
            // this returns and discards what was collected.
            if cancel.is_cancelled() {
                return Vec::new();
            }
            if !type_ok(v, &step.origin_type) {
                continue;
            }
            for rel in graph.snapshot_relations(v) {
                if !relation_type_matches(&step.relation_type, &rel.rel_type)
                    || (last && rel.dest_id != target)
                {
                    continue;
                }
                if let Some((lo, hi)) = options.time_window
                    && (rel.timestamp < lo || rel.timestamp > hi)
                {
                    continue;
                }
                let Some(dest) = graph.get_entity(&rel.dest_id) else {
                    continue;
                };
                if !entity_type_matches(&step.dest_type, &dest.entity_type)
                    || !all_predicates_match(&step.edge_predicates, &rel.metadata)
                    || !all_predicates_match(&step.dest_predicates, &dest.metadata)
                {
                    continue;
                }
                edge_serial += 1;
                let record = record_key(&rel, &options.record_key, edge_serial);
                let labels = domain_labels(&rel, &options.domains);
                let key = (i, v.clone(), rel.dest_id.clone(), rel.timestamp, record);
                let g = *index.entry(key.clone()).or_insert_with(|| {
                    groups.push(Group {
                        step: i,
                        src: key.1.clone(),
                        dst: key.2.clone(),
                        ts: key.3,
                        record: key.4.clone(),
                        edges: Vec::new(),
                    });
                    groups.len() - 1
                });
                groups[g].edges.push(labels);
                next.insert(rel.dest_id.clone());
            }
        }
        frontier = next;
    }
    prune(groups, steps.len(), delta)
}

/// Keeps the groups that lie on a complete, temporally valid chain.
fn prune(groups: Vec<Group>, steps: usize, delta: i64) -> Vec<Group> {
    let mut forward = vec![false; groups.len()];
    let mut min_in: HashMap<&str, i64> = HashMap::new();
    for i in 0..steps {
        let mut next_min: HashMap<&str, i64> = HashMap::new();
        for (g, grp) in groups.iter().enumerate().filter(|(_, g)| g.step == i) {
            let ok = i == 0
                || min_in
                    .get(grp.src.as_str())
                    .is_some_and(|&t| grp.ts >= t.saturating_sub(delta));
            if ok {
                forward[g] = true;
                let e = next_min.entry(grp.dst.as_str()).or_insert(grp.ts);
                *e = (*e).min(grp.ts);
            }
        }
        min_in = next_min;
    }
    let mut keep = forward.clone();
    let mut max_out: HashMap<&str, i64> = HashMap::new();
    for i in (0..steps).rev() {
        let mut next_max: HashMap<&str, i64> = HashMap::new();
        for (g, grp) in groups.iter().enumerate().filter(|(_, g)| g.step == i) {
            let ok = forward[g]
                && (i + 1 == steps
                    || max_out
                        .get(grp.dst.as_str())
                        .is_some_and(|&t| t >= grp.ts.saturating_sub(delta)));
            keep[g] = ok;
            if ok {
                let e = next_max.entry(grp.src.as_str()).or_insert(grp.ts);
                *e = (*e).max(grp.ts);
            }
        }
        max_out = next_max;
    }
    groups
        .into_iter()
        .zip(keep)
        .filter_map(|(g, k)| k.then_some(g))
        .collect()
}

fn record_key(rel: &Relation, key: &RecordKey, serial: usize) -> String {
    let identical = || {
        format!(
            "{}>{}#{:?}@{}/{}",
            rel.source_id,
            rel.dest_id,
            rel.rel_type,
            rel.timestamp,
            rel.dataset_id.as_deref().unwrap_or("")
        )
    };
    match key {
        RecordKey::Edge => format!("{}~{serial}", identical()),
        RecordKey::Identical => identical(),
        RecordKey::Metadata(keys) => {
            let values: Option<Vec<String>> = keys
                .iter()
                .map(|k| rel.metadata.get(k).map(|v| format!("{k}={v}")))
                .collect();
            values.map(|v| v.join(";")).unwrap_or_else(identical)
        }
    }
}

fn domain_labels(rel: &Relation, spec: &DomainSpec) -> Vec<String> {
    let base = match &spec.base {
        DomainBase::Dataset => match rel.dataset_id.as_deref() {
            Some(d) if !d.is_empty() => d.to_string(),
            _ => "(no dataset)".to_string(),
        },
        DomainBase::Metadata(k) => rel
            .metadata
            .get(k)
            .cloned()
            .unwrap_or_else(|| format!("(no {k})")),
    };
    spec.groups
        .get(&base)
        .cloned()
        .unwrap_or_else(|| vec![base])
}

/// The match DAG over the support's groups.
struct Dag<'a> {
    groups: &'a [Group],
    by_step: Vec<Vec<usize>>,
    delta: i64,
}

impl<'a> Dag<'a> {
    fn new(groups: &'a [Group], steps: usize, delta: i64) -> Self {
        let mut by_step = vec![Vec::new(); steps];
        for (g, grp) in groups.iter().enumerate() {
            by_step[grp.step].push(g);
        }
        Self {
            groups,
            by_step,
            delta,
        }
    }

    /// A chain through groups that pass `alive`, if any. Each group keeps
    /// the earliest compatible predecessor: if any predecessor fits, that
    /// one does.
    fn chain(&self, alive: impl Fn(usize) -> bool) -> Option<Vec<usize>> {
        let mut pred: HashMap<usize, Option<usize>> = HashMap::new();
        let mut best_in: HashMap<&str, (i64, usize)> = HashMap::new();
        for (i, step) in self.by_step.iter().enumerate() {
            let mut next: HashMap<&str, (i64, usize)> = HashMap::new();
            for &g in step {
                if !alive(g) {
                    continue;
                }
                let grp = &self.groups[g];
                let p = if i == 0 {
                    Some(None)
                } else {
                    best_in
                        .get(grp.src.as_str())
                        .filter(|(t, _)| grp.ts >= t.saturating_sub(self.delta))
                        .map(|&(_, p)| Some(p))
                };
                if let Some(p) = p {
                    pred.insert(g, p);
                    let e = next.entry(grp.dst.as_str()).or_insert((grp.ts, g));
                    if grp.ts < e.0 {
                        *e = (grp.ts, g);
                    }
                }
            }
            best_in = next;
        }
        let last = self.by_step.last()?;
        let mut g = *last.iter().find(|g| pred.contains_key(g))?;
        let mut chain = vec![g];
        while let Some(Some(p)) = pred.get(&g) {
            g = *p;
            chain.push(g);
        }
        chain.reverse();
        Some(chain)
    }

    /// Number of edge chains: each group stands for as many edges as it
    /// holds.
    fn count_chains(&self) -> u64 {
        let mut ways = vec![0u64; self.groups.len()];
        let mut prev: HashMap<&str, Vec<(i64, u64)>> = HashMap::new();
        for (i, step) in self.by_step.iter().enumerate() {
            for list in prev.values_mut() {
                list.sort_unstable();
                let mut acc = 0u64;
                for e in list.iter_mut() {
                    acc = acc.saturating_add(e.1);
                    e.1 = acc;
                }
            }
            let mut next: HashMap<&str, Vec<(i64, u64)>> = HashMap::new();
            for &g in step {
                let grp = &self.groups[g];
                let incoming = if i == 0 {
                    1
                } else {
                    prev.get(grp.src.as_str()).map_or(0, |list| {
                        let n = list.partition_point(|&(t, _)| t <= grp.ts);
                        if n == 0 { 0 } else { list[n - 1].1 }
                    })
                };
                ways[g] = incoming.saturating_mul(grp.edges.len() as u64);
                next.entry(grp.dst.as_str())
                    .or_default()
                    .push((grp.ts.saturating_sub(self.delta), ways[g]));
            }
            prev = next;
        }
        self.by_step.last().map_or(0, |s| {
            s.iter().fold(0u64, |a, &g| a.saturating_add(ways[g]))
        })
    }

    /// Max flow from the source to the target with unit-capacity groups, and
    /// the groups on the source side of a minimum cut.
    fn min_cut(&self) -> (usize, Vec<usize>) {
        const INF: i64 = 1 << 40;
        let n_groups = self.groups.len();
        let (s, t) = (0usize, 1usize);
        let node_in = |g: usize| 2 + 2 * g;
        let node_out = |g: usize| 3 + 2 * g;
        let mut net = FlowNet::new(2 + 2 * n_groups);
        for g in 0..n_groups {
            net.add(node_in(g), node_out(g), 1);
        }
        let steps = self.by_step.len();
        for &g in &self.by_step[0] {
            net.add(s, node_in(g), INF);
        }
        for &g in &self.by_step[steps - 1] {
            net.add(node_out(g), t, INF);
        }
        for i in 0..steps.saturating_sub(1) {
            // Ladder per vertex: one node per distinct timestamp of the next
            // step's groups leaving it, chained forward in time.
            let mut leaving: HashMap<&str, Vec<(i64, usize)>> = HashMap::new();
            for &f in &self.by_step[i + 1] {
                let grp = &self.groups[f];
                leaving
                    .entry(grp.src.as_str())
                    .or_default()
                    .push((grp.ts, f));
            }
            let mut ladders: HashMap<&str, (Vec<i64>, Vec<usize>)> = HashMap::new();
            for (v, mut list) in leaving {
                list.sort_unstable();
                let mut times: Vec<i64> = Vec::new();
                let mut rungs: Vec<usize> = Vec::new();
                for (ts, f) in list {
                    if times.last() != Some(&ts) {
                        let r = net.node();
                        if let Some(&prev) = rungs.last() {
                            net.add(prev, r, INF);
                        }
                        times.push(ts);
                        rungs.push(r);
                    }
                    net.add(*rungs.last().unwrap(), node_in(f), INF);
                }
                ladders.insert(v, (times, rungs));
            }
            for &e in &self.by_step[i] {
                let grp = &self.groups[e];
                if let Some((times, rungs)) = ladders.get(grp.dst.as_str()) {
                    let floor = grp.ts.saturating_sub(self.delta);
                    let j = times.partition_point(|&ts| ts < floor);
                    if j < rungs.len() {
                        net.add(node_out(e), rungs[j], INF);
                    }
                }
            }
        }
        let flow = net.max_flow(s, t);
        let reach = net.reachable(s);
        let cut = (0..n_groups)
            .filter(|&g| reach[node_in(g)] && !reach[node_out(g)])
            .collect();
        (flow as usize, cut)
    }
}

/// Dinic's max flow over an adjacency list of paired arcs.
struct FlowNet {
    head: Vec<Vec<usize>>,
    to: Vec<usize>,
    cap: Vec<i64>,
}

impl FlowNet {
    fn new(n: usize) -> Self {
        Self {
            head: vec![Vec::new(); n],
            to: Vec::new(),
            cap: Vec::new(),
        }
    }

    fn node(&mut self) -> usize {
        self.head.push(Vec::new());
        self.head.len() - 1
    }

    fn add(&mut self, a: usize, b: usize, c: i64) {
        self.head[a].push(self.to.len());
        self.to.push(b);
        self.cap.push(c);
        self.head[b].push(self.to.len());
        self.to.push(a);
        self.cap.push(0);
    }

    fn levels(&self, s: usize) -> Vec<i32> {
        let mut level = vec![-1; self.head.len()];
        level[s] = 0;
        let mut queue = std::collections::VecDeque::from([s]);
        while let Some(u) = queue.pop_front() {
            for &a in &self.head[u] {
                if self.cap[a] > 0 && level[self.to[a]] < 0 {
                    level[self.to[a]] = level[u] + 1;
                    queue.push_back(self.to[a]);
                }
            }
        }
        level
    }

    fn reachable(&self, s: usize) -> Vec<bool> {
        self.levels(s).iter().map(|&l| l >= 0).collect()
    }

    fn max_flow(&mut self, s: usize, t: usize) -> i64 {
        let mut flow = 0;
        loop {
            let level = self.levels(s);
            if level[t] < 0 {
                return flow;
            }
            let mut next = vec![0usize; self.head.len()];
            loop {
                let pushed = self.push(s, t, i64::MAX, &level, &mut next);
                if pushed == 0 {
                    break;
                }
                flow += pushed;
            }
        }
    }

    /// One augmenting path in the level graph, iteratively.
    fn push(&mut self, s: usize, t: usize, limit: i64, level: &[i32], next: &mut [usize]) -> i64 {
        let mut path: Vec<usize> = Vec::new();
        let mut u = s;
        loop {
            if u == t {
                let f = path.iter().map(|&a| self.cap[a]).fold(limit, i64::min);
                for &a in &path {
                    self.cap[a] -= f;
                    self.cap[a ^ 1] += f;
                }
                return f;
            }
            let mut advanced = false;
            while next[u] < self.head[u].len() {
                let a = self.head[u][next[u]];
                let v = self.to[a];
                if self.cap[a] > 0 && level[v] == level[u] + 1 {
                    path.push(a);
                    u = v;
                    advanced = true;
                    break;
                }
                next[u] += 1;
            }
            if !advanced {
                // Dead end: retreat one arc and skip it next time.
                let Some(a) = path.pop() else {
                    return 0;
                };
                u = self.to[a ^ 1];
                next[u] += 1;
            }
        }
    }
}

/// All `k`-subsets of `0..n`, in lexicographic order.
fn combinations(n: usize, k: usize) -> impl Iterator<Item = Vec<usize>> {
    let mut idx: Vec<usize> = (0..k).collect();
    let mut done = k > n;
    std::iter::from_fn(move || {
        if done {
            return None;
        }
        let out = idx.clone();
        let mut i = k;
        loop {
            if i == 0 {
                done = true;
                break;
            }
            i -= 1;
            if idx[i] != i + n - k {
                idx[i] += 1;
                for j in i + 1..k {
                    idx[j] = idx[j - 1] + 1;
                }
                break;
            }
        }
        Some(out)
    })
}
