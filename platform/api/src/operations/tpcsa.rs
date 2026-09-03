//! Attack-chain reconstruction: the loaded graph → a TPCSA instance →
//! ranked, verified trees.
//!
//! # Mapping (instructions §1)
//!
//! | Instance field | Source |
//! |---|---|
//! | node `id`, `kind` | entity id; entity type lowercased (`process`, `ip`, …) |
//! | arc `tail → head` | causal flow: who acts → what is acted on. Stored reads/loads that point process→file are reversed |
//! | arc `etype` | edge metadata `event_type` (lowercased), else the relation name |
//! | arc `lo = hi` | microseconds: metadata `ts_us`, else `ts_nanos / 1000`, else `timestamp · 10⁶` |
//! | arc `cost` | rarity of `etype`, κ = 3 |
//! | node `prize` | seeds (explicit) and/or entity `score` above a threshold, scaled to `[0, 10]` |
//! | node `tactic` | from the seed; [`tactic_for_technique`] derives it from a catalog `mitre_id` |
//! | node `root_cost` | public IP: 2; process / user: 6; everything else: not a root |

use std::collections::{BTreeMap, HashMap};

use graph_hunter_core::GraphHunter;
use graph_hunter_core::ip_utils::is_public;
use graph_hunter_core::types::EntityType;
use graph_hunter_tpcsa::{
    Arc as TArc, DEFAULT_KAPPA, GreedyOptions, Instance, Node, ReconstructOptions, rarity_costs,
    reconstruct,
};

use crate::dto::tpcsa::{
    ExportStats, ExportTpcsaInstanceRequest, ExportTpcsaInstanceResponse, ReconstructChainRequest,
    ReconstructChainResponse, TpcsaSeed,
};
use crate::{ApiError, ApiResult, GraphHunterApi};

pub const TIME_UNIT: &str = "us";
pub const DEFAULT_EPSILON_MS: f64 = 1.0;
pub const DEFAULT_EXTERNAL_IP_ROOT_COST: f64 = 2.0;
pub const DEFAULT_PROCESS_ROOT_COST: f64 = 6.0;
pub const DEFAULT_K: usize = 2;
pub const MAX_PRIZE: f64 = 10.0;

/// Resolved export options (defaults applied).
#[derive(Debug, Clone)]
pub struct ExportOpts {
    pub seeds: Vec<TpcsaSeed>,
    pub window: Option<(i64, i64)>,
    pub epsilon_us: i64,
    pub score_threshold: Option<f64>,
    pub kappa: f64,
    pub external_ip_root_cost: f64,
    pub process_root_cost: f64,
    pub max_arcs: Option<usize>,
}

impl ExportOpts {
    pub fn from_request(req: &ExportTpcsaInstanceRequest) -> ApiResult<Self> {
        let epsilon_ms = req.epsilon_ms.unwrap_or(DEFAULT_EPSILON_MS);
        if !(epsilon_ms.is_finite() && epsilon_ms >= 0.0) {
            return Err(ApiError::InvalidInput(format!(
                "epsilon_ms must be >= 0, got {epsilon_ms}"
            )));
        }
        if let Some(w) = req.window {
            if w.from > w.to {
                return Err(ApiError::InvalidInput(format!(
                    "window.from ({}) > window.to ({})",
                    w.from, w.to
                )));
            }
        }
        for s in &req.seeds {
            if !(s.prize.is_finite() && s.prize >= 0.0) {
                return Err(ApiError::InvalidInput(format!(
                    "seed {:?} has an invalid prize {}",
                    s.node, s.prize
                )));
            }
        }
        Ok(Self {
            seeds: req.seeds.clone(),
            window: req.window.map(|w| (w.from, w.to)),
            epsilon_us: (epsilon_ms * 1000.0).round() as i64,
            score_threshold: req.score_threshold,
            kappa: req.kappa.unwrap_or(DEFAULT_KAPPA),
            external_ip_root_cost: req
                .external_ip_root_cost
                .unwrap_or(DEFAULT_EXTERNAL_IP_ROOT_COST),
            process_root_cost: req.process_root_cost.unwrap_or(DEFAULT_PROCESS_ROOT_COST),
            max_arcs: req.max_arcs,
        })
    }
}

/// Primary ATT&CK tactic for the techniques the built-in catalog uses.
/// Techniques that ATT&CK lists under several tactics get the one that
/// matters for reconstruction ranking (e.g. Valid Accounts → initial
/// access). Sub-techniques fall back to their parent.
pub fn tactic_for_technique(mitre_id: &str) -> Option<&'static str> {
    let id = mitre_id.trim().to_ascii_uppercase();
    let lookup = |t: &str| -> Option<&'static str> {
        Some(match t {
            "T1078" | "T1078.004" => "initial-access",
            "T1059" | "T1059.001" | "T1569.002" | "T1053.005" | "T1204.002" => "execution",
            "T1021" | "T1021.001" | "T1563" => "lateral-movement",
            "T1003" | "T1110.003" | "T1528" => "credential-access",
            "T1071" => "command-and-control",
            "T1055" | "T1564.008" | "T1218" | "T1014" | "T1562.001" => "defense-evasion",
            "T1048.003" => "exfiltration",
            "T1547.001" | "T1098.003" => "persistence",
            "T1087.004" => "discovery",
            _ => return None,
        })
    };
    lookup(&id).or_else(|| id.split('.').next().and_then(lookup))
}

/// Whether a stored edge must be reversed to read as causal flow. Reads
/// and loads are "the file flows into the process"; parsers that store
/// them as `subject → object` (CDM, Sysmon) point the other way.
pub fn should_flip(etype: &str, tail: &EntityType, head: &EntityType) -> bool {
    let read_like = matches!(
        etype,
        "read"
            | "load"
            | "event_read"
            | "event_open"
            | "event_mmap"
            | "event_lseek"
            | "event_check_file_attributes"
    );
    if read_like && *tail == EntityType::Process && *head == EntityType::File {
        return true;
    }
    // Identity sources store "user authenticated from IP" as User → IP; the
    // causal actor is the remote address acting on the account (§1: external
    // IP → user), so an IP can be an entry point.
    let auth_like = etype == "auth"
        || etype.starts_with("login")
        || etype.contains("password")
        || etype.contains("token");
    auth_like && *tail == EntityType::User && *head == EntityType::IP
}

fn kind_of(t: &EntityType) -> String {
    t.to_string().to_ascii_lowercase()
}

fn root_cost_for(kind: &EntityType, id: &str, opts: &ExportOpts) -> Option<f64> {
    match kind {
        EntityType::IP if is_public(id) => Some(opts.external_ip_root_cost),
        EntityType::Process | EntityType::User => Some(opts.process_root_cost),
        _ => None,
    }
}

/// Edge time in microseconds from the metadata the parsers leave behind,
/// falling back to the engine's second-resolution timestamp.
fn edge_time_us(timestamp_s: i64, meta: &HashMap<String, String>) -> i64 {
    if let Some(us) = meta.get("ts_us").and_then(|v| v.parse::<i64>().ok()) {
        return us;
    }
    if let Some(ns) = meta.get("ts_nanos").and_then(|v| v.parse::<i64>().ok()) {
        return ns / 1_000;
    }
    timestamp_s.saturating_mul(1_000_000)
}

struct RawArc {
    tail: String,
    head: String,
    etype: String,
    t: i64,
}

/// Pure conversion of a loaded graph into a solver instance.
pub fn build_instance(
    graph: &GraphHunter,
    opts: &ExportOpts,
) -> ApiResult<(Instance, ExportStats)> {
    let mut raw: Vec<RawArc> = Vec::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut flipped = 0usize;
    let mut skipped = 0usize;
    let empty: HashMap<String, String> = HashMap::new();

    graph.streaming.for_each_edge(|src_sid, e| {
        if let Some((lo, hi)) = opts.window {
            if e.timestamp < lo || e.timestamp > hi {
                skipped += 1;
                return;
            }
        }
        let (Some(src), Some(dst)) = (
            graph.entities.get(&src_sid),
            graph.entities.get(&e.dest_sid),
        ) else {
            skipped += 1;
            return;
        };
        let meta = if e.metadata_offset != 0 {
            graph.meta_store.get(e.metadata_offset)
        } else {
            empty.clone()
        };
        // Event type for rarity pricing: parsers that know it write
        // `event_type`; identity sources (Keycloak, Sentinel) carry the
        // event name under `type`; otherwise the relation name.
        let etype = meta
            .get("event_type")
            .or_else(|| meta.get("type"))
            .filter(|s| !s.is_empty())
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_else(|| {
                graph
                    .resolve_rel_type_name_raw(e.rel_type_tag, e.metadata_offset)
                    .to_ascii_lowercase()
            });
        let t = edge_time_us(e.timestamp, &meta);
        let (tail, head) = if should_flip(&etype, &src.entity_type, &dst.entity_type) {
            flipped += 1;
            (dst.id.clone(), src.id.clone())
        } else {
            (src.id.clone(), dst.id.clone())
        };
        *counts.entry(etype.clone()).or_default() += 1;
        raw.push(RawArc {
            tail,
            head,
            etype,
            t,
        });
    });

    // Deterministic order: the streaming backend iterates a HashMap, and
    // node indices (hence greedy tie-breaks) must not depend on it.
    raw.sort_by(|a, b| {
        a.t.cmp(&b.t)
            .then_with(|| a.tail.cmp(&b.tail))
            .then_with(|| a.head.cmp(&b.head))
            .then_with(|| a.etype.cmp(&b.etype))
    });

    if let Some(max) = opts.max_arcs {
        if raw.len() > max {
            return Err(ApiError::PayloadTooLarge(format!(
                "{} arcs in the window exceed max_arcs = {max}; narrow the window or raise the cap",
                raw.len()
            )));
        }
    }

    let costs = rarity_costs(&counts, opts.kappa);

    // Nodes: everything an arc touches, plus every seed that exists.
    let mut node_index: HashMap<String, usize> = HashMap::new();
    let mut nodes: Vec<Node> = Vec::new();
    let mut ensure = |id: &str, nodes: &mut Vec<Node>| -> Option<usize> {
        if let Some(&i) = node_index.get(id) {
            return Some(i);
        }
        let sid = graph.interner.get(id)?;
        let ent = graph.entities.get(&sid)?;
        let mut node = Node::new(id, kind_of(&ent.entity_type));
        node.root_cost = root_cost_for(&ent.entity_type, id, opts);
        nodes.push(node);
        node_index.insert(id.to_string(), nodes.len() - 1);
        Some(nodes.len() - 1)
    };
    let mut arcs: Vec<TArc> = Vec::with_capacity(raw.len());
    for a in &raw {
        let (Some(_), Some(_)) = (ensure(&a.tail, &mut nodes), ensure(&a.head, &mut nodes)) else {
            skipped += 1;
            continue;
        };
        arcs.push(TArc {
            tail: a.tail.clone(),
            head: a.head.clone(),
            etype: a.etype.clone(),
            lo: a.t,
            hi: a.t,
            cost: costs.get(&a.etype).copied().unwrap_or(1.0),
        });
    }

    // Prizes from scores.
    if let Some(th) = opts.score_threshold {
        let max_score = graph
            .entities
            .values()
            .map(|e| e.score)
            .fold(0.0_f64, f64::max);
        if max_score > 0.0 {
            let scored: Vec<(String, f64)> = graph
                .entities
                .values()
                .filter(|e| e.score >= th && e.score > 0.0)
                .map(|e| {
                    (
                        e.id.clone(),
                        (MAX_PRIZE * e.score / max_score).clamp(0.0, MAX_PRIZE),
                    )
                })
                .collect();
            for (id, prize) in scored {
                if let Some(i) = ensure(&id, &mut nodes) {
                    nodes[i].prize = nodes[i].prize.max(prize);
                }
            }
        }
    }
    // Prizes from seeds (explicit wins over score-derived).
    let mut unknown_seeds = Vec::new();
    for s in &opts.seeds {
        match ensure(&s.node, &mut nodes) {
            Some(i) => {
                let p = s.prize.clamp(0.0, MAX_PRIZE);
                if p > 0.0 {
                    nodes[i].prize = p;
                }
                if s.tactic.is_some() {
                    nodes[i].tactic = s.tactic.clone();
                }
            }
            None => unknown_seeds.push(s.node.clone()),
        }
    }

    let stats = ExportStats {
        nodes: nodes.len(),
        arcs: arcs.len(),
        terminals: nodes.iter().filter(|n| n.is_terminal()).count(),
        root_candidates: nodes.iter().filter(|n| n.is_root_candidate()).count(),
        flipped_arcs: flipped,
        skipped_edges: skipped,
        unknown_seeds,
        etype_costs: costs.into_iter().collect::<BTreeMap<_, _>>(),
        time_unit: TIME_UNIT.to_string(),
        epsilon: opts.epsilon_us,
    };
    Ok((
        Instance {
            epsilon: opts.epsilon_us,
            nodes,
            arcs,
        },
        stats,
    ))
}

impl GraphHunterApi {
    /// Export the session graph (or a window of it) as a TPCSA instance.
    pub fn export_tpcsa_instance(
        &self,
        req: ExportTpcsaInstanceRequest,
    ) -> ApiResult<ExportTpcsaInstanceResponse> {
        let opts = ExportOpts::from_request(&req)?;
        let (instance, stats) =
            self.with_graph_read(req.session.as_ref(), |graph| build_instance(graph, &opts))?;
        Ok(ExportTpcsaInstanceResponse { instance, stats })
    }

    /// Reconstruct attack chains from seeds: export, prune, greedy forest,
    /// verify, rank. `certificate` is always `None` here — the transport
    /// layer calls the certification sidecar when `certify` is set.
    pub fn reconstruct_chain(
        &self,
        req: ReconstructChainRequest,
    ) -> ApiResult<ReconstructChainResponse> {
        let k = req.k.unwrap_or(DEFAULT_K);
        if k == 0 {
            return Err(ApiError::InvalidInput("k must be >= 1".into()));
        }
        let export_req = req.export_request();
        let opts = ExportOpts::from_request(&export_req)?;
        let (instance, stats) =
            self.with_graph_read(req.session.as_ref(), |graph| build_instance(graph, &opts))?;
        let ropts = ReconstructOptions {
            greedy: GreedyOptions {
                k,
                budget: req.budget,
                top_roots: req.top_roots.unwrap_or(GreedyOptions::default().top_roots),
            },
            ..Default::default()
        };
        let rec = reconstruct(&instance, &ropts)
            .map_err(|e| ApiError::Internal(format!("tpcsa: {e}")))?;
        let pruned_instance = if req.certify.unwrap_or(false) {
            let (pruned, _) = graph_hunter_tpcsa::temporal_prune(&instance)
                .map_err(|e| ApiError::Internal(format!("tpcsa prune: {e}")))?;
            Some(pruned)
        } else {
            None
        };
        let keep_instance = req.include_instance.unwrap_or(false);
        Ok(ReconstructChainResponse {
            trees: rec.trees,
            ties: rec.ties,
            certificate: None,
            pruning: rec.pruning,
            objective: rec.objective,
            total_prize: rec.total_prize,
            rejected: rec.rejected,
            export: stats,
            instance: keep_instance.then_some(instance),
            pruned_instance,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::session::CreateSessionRequest;
    use graph_hunter_core::entity::Entity;
    use graph_hunter_core::relation::Relation;
    use graph_hunter_core::types::RelationType;

    fn ent(id: &str, t: EntityType) -> Entity {
        Entity::new(id, t)
    }

    fn rel(s: &str, d: &str, rt: RelationType, secs: i64, etype: &str, ts_us: i64) -> Relation {
        Relation::new(s, d, rt, secs)
            .with_metadata("event_type", etype)
            .with_metadata("ts_us", ts_us.to_string())
    }

    /// ip → p0 → {p1, p2}; p1 writes f; p2 reads g (stored process→file, must flip);
    /// plus a benign chrome → tab chain and a CDM-style read without ts_us.
    fn graph() -> GraphHunter {
        let mut g = GraphHunter::new();
        for (id, t) in [
            ("8.8.8.8", EntityType::IP),
            ("10.0.0.5", EntityType::IP),
            ("p0", EntityType::Process),
            ("p1", EntityType::Process),
            ("p2", EntityType::Process),
            ("f", EntityType::File),
            ("g", EntityType::File),
            ("chrome", EntityType::Process),
            ("tab", EntityType::Process),
            ("alice", EntityType::User),
        ] {
            g.add_entity(ent(id, t)).unwrap();
        }
        g.add_relation(rel(
            "8.8.8.8",
            "p0",
            RelationType::Connect,
            10,
            "recv",
            10_000_000,
        ))
        .unwrap();
        g.add_relation(rel(
            "p0",
            "p1",
            RelationType::Spawn,
            20,
            "start",
            20_000_000,
        ))
        .unwrap();
        g.add_relation(rel(
            "p0",
            "p2",
            RelationType::Spawn,
            30,
            "start",
            30_000_000,
        ))
        .unwrap();
        g.add_relation(rel("p1", "f", RelationType::Write, 40, "write", 40_000_000))
            .unwrap();
        // Stored the CDM way: process → file for a read. Must be flipped.
        g.add_relation(rel("p2", "g", RelationType::Read, 50, "read", 50_000_000))
            .unwrap();
        g.add_relation(rel(
            "chrome",
            "tab",
            RelationType::Spawn,
            60,
            "start",
            60_000_000,
        ))
        .unwrap();
        // No ts_us / event_type: falls back to seconds and the relation name.
        g.add_relation(Relation::new("alice", "p0", RelationType::Auth, 5))
            .unwrap();
        g.add_relation(rel(
            "p2",
            "10.0.0.5",
            RelationType::Connect,
            55,
            "send",
            55_000_000,
        ))
        .unwrap();
        g
    }

    fn opts(seeds: Vec<TpcsaSeed>) -> ExportOpts {
        ExportOpts::from_request(&ExportTpcsaInstanceRequest {
            seeds,
            ..Default::default()
        })
        .unwrap()
    }

    fn seed(node: &str, prize: f64, tactic: Option<&str>) -> TpcsaSeed {
        TpcsaSeed {
            node: node.into(),
            prize,
            tactic: tactic.map(str::to_string),
        }
    }

    #[test]
    fn mapping_follows_the_contract() {
        let g = graph();
        let (inst, stats) =
            build_instance(&g, &opts(vec![seed("p1", 8.0, Some("execution"))])).unwrap();
        assert_eq!(inst.epsilon, 1_000, "1 ms in microseconds");
        assert_eq!(stats.time_unit, "us");
        assert_eq!(stats.arcs, 8);
        assert_eq!(stats.flipped_arcs, 1);

        let by = |tail: &str, head: &str| {
            inst.arcs
                .iter()
                .find(|a| a.tail == tail && a.head == head)
                .cloned()
        };
        // Read stored process→file now flows file→process.
        assert!(by("g", "p2").is_some(), "read flipped to file → process");
        assert!(by("p2", "g").is_none());
        assert!(by("p1", "f").is_some(), "write stays process → file");
        // Times: ts_us wins; fallback is seconds · 10⁶.
        assert_eq!(by("p0", "p1").unwrap().lo, 20_000_000);
        let auth = by("alice", "p0").unwrap();
        assert_eq!(auth.lo, 5_000_000);
        assert_eq!(
            auth.etype, "auth",
            "relation name lowercased when event_type is absent"
        );
        // Rarity: start (3) is the commonest → κ; singletons → 1.
        assert!((stats.etype_costs["start"] - 3.0).abs() < 1e-9);
        assert!((stats.etype_costs["recv"] - 1.0).abs() < 1e-9);
        // Roots: public IP 2, private IP none, process/user 6, file none.
        let node = |id: &str| inst.nodes.iter().find(|n| n.id == id).unwrap().clone();
        assert_eq!(node("8.8.8.8").root_cost, Some(2.0));
        assert_eq!(node("10.0.0.5").root_cost, None);
        assert_eq!(node("p0").root_cost, Some(6.0));
        assert_eq!(node("alice").root_cost, Some(6.0));
        assert_eq!(node("f").root_cost, None);
        assert_eq!(node("f").kind, "file");
        // Seed → prize + tactic.
        assert_eq!(node("p1").prize, 8.0);
        assert_eq!(node("p1").tactic.as_deref(), Some("execution"));
        assert_eq!(stats.terminals, 1);
        inst.validate().unwrap();
    }

    #[test]
    fn identity_auth_edges_flow_from_the_ip_and_price_by_keycloak_type() {
        let mut g = GraphHunter::new();
        g.add_entity(ent("alice", EntityType::User)).unwrap();
        g.add_entity(ent("8.8.8.8", EntityType::IP)).unwrap();
        g.add_relation(
            Relation::new("alice", "8.8.8.8", RelationType::Auth, 100)
                .with_metadata("type", "LOGIN"),
        )
        .unwrap();
        g.add_relation(
            Relation::new("8.8.8.8", "alice", RelationType::Auth, 101)
                .with_metadata("type", "UPDATE_PASSWORD"),
        )
        .unwrap();
        let (inst, stats) = build_instance(&g, &opts(vec![])).unwrap();
        assert_eq!(stats.flipped_arcs, 1, "User → IP auth is reversed");
        assert!(
            inst.arcs
                .iter()
                .all(|a| a.tail == "8.8.8.8" && a.head == "alice")
        );
        let types: Vec<&str> = inst.arcs.iter().map(|a| a.etype.as_str()).collect();
        assert!(types.contains(&"login") && types.contains(&"update_password"));
        assert!(should_flip(
            "login_error",
            &EntityType::User,
            &EntityType::IP
        ));
        assert!(!should_flip("connect", &EntityType::User, &EntityType::URL));
    }

    #[test]
    fn window_filters_edges_and_unknown_seeds_are_reported() {
        let g = graph();
        let mut o = opts(vec![seed("ghost", 5.0, None), seed("p2", 12.0, None)]);
        o.window = Some((15, 35));
        let (inst, stats) = build_instance(&g, &o).unwrap();
        assert_eq!(stats.arcs, 2, "only the two starts at 20 and 30");
        assert_eq!(stats.skipped_edges, 6);
        assert_eq!(stats.unknown_seeds, vec!["ghost"]);
        let p2 = inst.nodes.iter().find(|n| n.id == "p2").unwrap();
        assert_eq!(p2.prize, 10.0, "clamped to 10");
    }

    #[test]
    fn score_threshold_adds_scaled_terminals() {
        let mut g = graph();
        g.get_entity_mut("p1").unwrap().score = 50.0;
        g.get_entity_mut("p2").unwrap().score = 100.0;
        g.get_entity_mut("tab").unwrap().score = 10.0;
        let mut o = opts(vec![]);
        o.score_threshold = Some(50.0);
        let (inst, stats) = build_instance(&g, &o).unwrap();
        assert_eq!(stats.terminals, 2);
        let p = |id: &str| inst.nodes.iter().find(|n| n.id == id).unwrap().prize;
        assert_eq!(p("p2"), 10.0);
        assert_eq!(p("p1"), 5.0);
        assert_eq!(p("tab"), 0.0);
    }

    #[test]
    fn max_arcs_refuses_oversized_exports() {
        let g = graph();
        let mut o = opts(vec![]);
        o.max_arcs = Some(3);
        assert!(matches!(
            build_instance(&g, &o),
            Err(ApiError::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn technique_to_tactic_covers_the_builtin_catalog_and_parents() {
        assert_eq!(tactic_for_technique("T1003"), Some("credential-access"));
        assert_eq!(tactic_for_technique("t1071"), Some("command-and-control"));
        assert_eq!(tactic_for_technique("T1021.001"), Some("lateral-movement"));
        assert_eq!(
            tactic_for_technique("T1059.999"),
            Some("execution"),
            "unknown sub-technique → parent"
        );
        assert_eq!(tactic_for_technique("T9999"), None);
        for id in [
            "T1078",
            "T1059.001",
            "T1021.001",
            "T1003",
            "T1071",
            "T1569.002",
            "T1053.005",
            "T1055",
            "T1048.003",
            "T1204.002",
            "T1547.001",
            "T1021",
            "T1059",
            "T1110.003",
            "T1087.004",
            "T1078.004",
            "T1528",
            "T1098.003",
            "T1564.008",
            "T1218",
            "T1014",
            "T1562.001",
            "T1563",
        ] {
            assert!(tactic_for_technique(id).is_some(), "{id} must map");
        }
    }

    #[test]
    fn reconstruct_chain_end_to_end_through_a_session() {
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("tpcsa".into()),
        })
        .unwrap();
        let session = api.sessions().current_session().unwrap();
        {
            let mut g = session.graph.write().unwrap();
            *g = graph();
        }
        let resp = api
            .reconstruct_chain(ReconstructChainRequest {
                seeds: vec![
                    seed("p1", 9.0, Some("execution")),
                    seed("p2", 9.0, Some("credential-access")),
                    seed("tab", 10.0, Some("execution")),
                ],
                k: Some(2),
                ..Default::default()
            })
            .unwrap();
        assert!(resp.rejected.is_empty(), "{:?}", resp.rejected);
        assert_eq!(resp.trees.len(), 2);
        let t = &resp.trees[0];
        assert_eq!(t.rank, 1);
        assert_eq!(
            t.root.node, "8.8.8.8",
            "the public IP is the cheapest entry point"
        );
        assert_eq!(t.tactics, vec!["credential-access", "execution"]);
        assert_eq!(t.collected, vec!["p1", "p2"]);
        assert_eq!(t.connectors.len(), 1);
        assert_eq!(
            t.connectors[0].node, "p0",
            "p0 was never seeded but both detections hang off it"
        );
        assert_eq!(resp.trees[1].root.node, "chrome");
        assert!(resp.certificate.is_none());
        assert!(resp.instance.is_none(), "instance only on request");
        assert_eq!(resp.export.terminals, 3);

        let with_inst = api
            .reconstruct_chain(ReconstructChainRequest {
                seeds: vec![seed("p1", 9.0, None)],
                certify: Some(true),
                ..Default::default()
            })
            .unwrap();
        assert!(with_inst.instance.is_none());
        let pruned = with_inst
            .pruned_instance
            .expect("certify needs the pruned instance downstream");
        assert!(pruned.arcs.len() <= with_inst.export.arcs);

        assert!(matches!(
            api.reconstruct_chain(ReconstructChainRequest {
                k: Some(0),
                ..Default::default()
            }),
            Err(ApiError::InvalidInput(_))
        ));
    }
}
