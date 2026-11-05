//! Projection rule v0: OCSF provenance events → attack-graph edge changes.
//!
//! Implements `docs/unificacion/proyeccion-procedencia-ataque.md`. The rule is
//! pure and deterministic: the same envelope stream with the same identity
//! table always yields the same `AttackDelta`s and the same edge state, so the
//! Rust engine and the Python reference (`research/gtdin/proyeccion.py`) are
//! checked against one conformance file
//! (`docs/unificacion/conformidad/proyeccion.json`).
//!
//! Input envelopes are JSON objects `{event_id, change, ocsf}` with `change` in
//! `Insert | Correction | Tombstone | Skipped`, the shape of
//! `CanonicalEnvelope`. The OCSF payload is read as a `serde_json::Value` so
//! this crate does not depend on the canonical crate's struct layout; the
//! fields it needs (`logon_type_id`, `device.hostname`) are the ones the spec
//! lists as prerequisites P1 and P6.

pub mod ingest;

use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap, HashSet};

const AUTHENTICATION: u64 = 3002;
const PROCESS_ACTIVITY: u64 = 1007;
const LOGON: u64 = 1;
const LOGOFF: u64 = 2;
const LAUNCH: u64 = 1;

/// Logon types (OCSF `logon_type_id`, numbered as Windows 4624 for 2–13).
const LT_SESSION_CONFIRMED: [u64; 4] = [2, 10, 11, 12]; // R1
const LT_RDP: u64 = 10; // R2
const LT_SESSION_INFERRED: [u64; 3] = [4, 5, 9]; // R3, R4

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct Edge {
    pub src: String,
    pub kind: String,
    pub dst: String,
}

impl Edge {
    fn new(src: &str, kind: &str, dst: &str) -> Self {
        Self {
            src: src.into(),
            kind: kind.into(),
            dst: dst.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Inferred,
    Confirmed,
}

/// One change to the attack graph. Serialises to the conformance-file shape.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "op")]
pub enum AttackDelta {
    Assert {
        edge: Edge,
        event_id: String,
        confidence: Confidence,
        expires_at: i64,
    },
    Close {
        edge: Edge,
        event_id: String,
        expires_at: i64,
    },
    Retract {
        edge: Edge,
        event_id: String,
    },
    Unresolved {
        event_id: String,
        reason: &'static str,
    },
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct EdgeState {
    pub origins: BTreeSet<&'static str>,
    pub support: BTreeSet<String>,
    pub first_seen: Option<i64>,
    pub last_seen: Option<i64>,
    pub expires_at: Option<i64>,
    pub confidence: Option<Confidence>,
}

#[derive(Clone, Debug)]
pub struct Params {
    pub session_grace_ms: i64,
    pub session_ttl_ms: i64,
    pub process_ttl_ms: i64,
    pub permission_ttl_ms: i64,
}

impl Default for Params {
    fn default() -> Self {
        const H: i64 = 3_600_000;
        Self {
            session_grace_ms: 8 * H,
            session_ttl_ms: 24 * H,
            process_ttl_ms: H,
            permission_ttl_ms: 30 * 24 * H,
        }
    }
}

impl Params {
    /// Reads the `params` object of the conformance file; missing keys keep the defaults.
    pub fn from_json(v: &Value) -> Self {
        let d = Self::default();
        let get = |k: &str, def: i64| v.get(k).and_then(Value::as_i64).unwrap_or(def);
        Self {
            session_grace_ms: get("session_grace_ms", d.session_grace_ms),
            session_ttl_ms: get("session_ttl_ms", d.session_ttl_ms),
            process_ttl_ms: get("process_ttl_ms", d.process_ttl_ms),
            permission_ttl_ms: get("permission_ttl_ms", d.permission_ttl_ms),
        }
    }
}

/// Identity resolution against the snapshot (§6 of the spec). Never guesses:
/// anything ambiguous or unknown is an `Unresolved` with a reason.
#[derive(Clone, Debug, Default)]
pub struct Identities {
    domains: HashMap<String, String>, // NETBIOS (upper) → DNS (lower)
    dns: HashSet<String>,
    hosts: HashSet<String>,
    system_accounts: HashSet<String>,
    machine_suffix: String,
}

impl Identities {
    pub fn from_json(v: &Value) -> Self {
        let domains: HashMap<String, String> = v
            .get("domains")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, d)| Some((k.to_uppercase(), d.as_str()?.to_lowercase())))
                    .collect()
            })
            .unwrap_or_default();
        let strs = |k: &str| -> Vec<String> {
            v.get(k)
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        };
        Self {
            dns: domains.values().cloned().collect(),
            domains,
            hosts: strs("hosts")
                .into_iter()
                .map(|h| h.to_lowercase())
                .collect(),
            system_accounts: strs("system_accounts")
                .into_iter()
                .map(|s| s.to_uppercase())
                .collect(),
            machine_suffix: v
                .get("machine_account_suffix")
                .and_then(Value::as_str)
                .unwrap_or("$")
                .to_string(),
        }
    }

    fn is_system_account(&self, user: &Value) -> bool {
        let name = user
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_uppercase();
        // `NT AUTHORITY\SYSTEM`, `CORP\WS01$`: judge the account, not its domain.
        let name = name.rsplit('\\').next().unwrap_or_default();
        self.system_accounts.contains(name) || name.ends_with(&self.machine_suffix)
    }

    fn user(&self, user: Option<&Value>) -> Result<String, &'static str> {
        let user = user.filter(|u| {
            u.get("name")
                .and_then(Value::as_str)
                .is_some_and(|n| !n.is_empty())
        });
        let user = user.ok_or("user_missing")?;
        if let Some(uid) = user
            .get("uid")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            return Ok(uid.to_uppercase()); // SID: the only exact identity
        }
        let full = user["name"]
            .as_str()
            .unwrap_or_default()
            .trim()
            .to_lowercase();
        let mut domain = user
            .get("domain")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_uppercase();
        // NETBIOS\user, the form the Windows parsers emit.
        let name = match full.split_once('\\') {
            Some((dom, local)) => {
                domain = dom.to_uppercase();
                local.to_string()
            }
            None => full,
        };
        if let Some((local, dom)) = name.split_once('@') {
            return if self.dns.contains(dom) {
                Ok(format!("{local}@{dom}"))
            } else {
                Err("domain_unknown")
            };
        }
        if domain.is_empty() {
            return Err("domain_missing");
        }
        let dns = match self.domains.get(&domain) {
            Some(d) => d.clone(),
            None if self.dns.contains(&domain.to_lowercase()) => domain.to_lowercase(),
            None => return Err("domain_unknown"),
        };
        Ok(format!("{name}@{dns}"))
    }

    fn host(&self, name: Option<&str>) -> Result<String, &'static str> {
        let name = name
            .filter(|n| !n.is_empty())
            .ok_or("host_missing")?
            .trim()
            .to_lowercase();
        if name.contains('.') {
            return if self.hosts.contains(&name) {
                Ok(name)
            } else {
                Err("host_unknown")
            };
        }
        let candidates: Vec<&String> = self
            .hosts
            .iter()
            .filter(|h| h.split('.').next() == Some(name.as_str()))
            .collect();
        match candidates.as_slice() {
            [one] => Ok((*one).clone()),
            [] => Err("host_unknown"),
            _ => Err("host_ambiguous"),
        }
    }
}

enum Plan {
    Assert(Edge, Confidence, i64),
    Close(Edge),
}

/// Projector state: attack edges with their support, and the event ids seen.
pub struct Projector {
    ids: Identities,
    p: Params,
    pub edges: HashMap<Edge, EdgeState>,
    supported: HashMap<String, Vec<Edge>>, // event_id → edges it sustains
    seen: HashSet<String>,
}

fn is_success(status: Option<&str>) -> bool {
    matches!(
        status.map(|s| s.trim().to_lowercase()).as_deref(),
        Some("success" | "succeeded")
    )
}

impl Projector {
    pub fn new(ids: Identities, p: Params) -> Self {
        Self {
            ids,
            p,
            edges: HashMap::new(),
            supported: HashMap::new(),
            seen: HashSet::new(),
        }
    }

    /// Marks BloodHound snapshot edges (origin `snapshot`, never expires).
    pub fn load_snapshot(&mut self, edges: impl IntoIterator<Item = Edge>) {
        for e in edges {
            self.edges.entry(e).or_default().origins.insert("snapshot");
        }
    }

    pub fn apply(&mut self, env: &Value) -> Vec<AttackDelta> {
        let eid = env
            .get("event_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let empty = Value::Null;
        let ocsf = env.get("ocsf").unwrap_or(&empty);
        match env
            .get("change")
            .and_then(Value::as_str)
            .unwrap_or("Insert")
        {
            "Skipped" => Vec::new(),
            "Tombstone" => self.retract(&eid),
            "Correction" => {
                let mut out = self.retract(&eid);
                out.extend(self.project(&eid, ocsf));
                out
            }
            _ if self.seen.contains(&eid) => Vec::new(), // idempotence (§3)
            _ => self.project(&eid, ocsf),
        }
    }

    /// Edges that exist in G_t at the given watermark (§2, §5).
    pub fn live(&self, watermark: i64) -> impl Iterator<Item = (&Edge, &EdgeState)> {
        self.edges.iter().filter(move |(_, s)| {
            s.origins.contains("snapshot")
                || (!s.support.is_empty() && s.expires_at.is_some_and(|x| x > watermark))
        })
    }

    fn project(&mut self, eid: &str, ev: &Value) -> Vec<AttackDelta> {
        self.seen.insert(eid.to_string());
        let plans = match self.rules(ev) {
            Ok(p) => p,
            Err(reason) => {
                return vec![AttackDelta::Unresolved {
                    event_id: eid.to_string(),
                    reason,
                }];
            }
        };
        let t = ev.get("time").and_then(Value::as_i64).unwrap_or(0);
        let mut out = Vec::new();
        for plan in plans {
            match plan {
                Plan::Assert(edge, conf, ttl) => out.push(self.assert(eid, edge, conf, t, ttl)),
                Plan::Close(edge) => out.extend(self.close(eid, edge, t)),
            }
        }
        out
    }

    /// Identities are resolved only when some rule applies, so an irrelevant
    /// event never counts as `Unresolved`.
    fn rules(&self, ev: &Value) -> Result<Vec<Plan>, &'static str> {
        let class = ev.get("class_uid").and_then(Value::as_u64);
        let act = ev.get("activity_id").and_then(Value::as_u64);
        let hostname = |k: &str| {
            ev.get(k)
                .and_then(|o| o.get("hostname"))
                .and_then(Value::as_str)
        };
        match (class, act) {
            (Some(AUTHENTICATION), Some(LOGON)) => {
                if !is_success(ev.get("status").and_then(Value::as_str)) {
                    return Ok(Vec::new()); // R6
                }
                let lt = ev.get("logon_type_id").and_then(Value::as_u64);
                let conf = match lt {
                    Some(x) if LT_SESSION_CONFIRMED.contains(&x) => Confidence::Confirmed,
                    Some(x) if LT_SESSION_INFERRED.contains(&x) => Confidence::Inferred,
                    _ => return Ok(Vec::new()), // R5 and logons without a type: never guessed
                };
                let u = self.ids.user(ev.get("actor_user"))?;
                let h = self.ids.host(hostname("dst_endpoint"))?;
                let mut plans = vec![Plan::Assert(
                    Edge::new(&h, "HasSession", &u),
                    conf,
                    self.p.session_ttl_ms,
                )];
                if lt == Some(LT_RDP) {
                    plans.push(Plan::Assert(
                        Edge::new(&u, "CanRDP", &h),
                        Confidence::Confirmed,
                        self.p.permission_ttl_ms,
                    ));
                }
                Ok(plans)
            }
            (Some(AUTHENTICATION), Some(LOGOFF)) => {
                // R7
                let u = self.ids.user(ev.get("actor_user"))?;
                let h = self.ids.host(hostname("dst_endpoint"))?;
                Ok(vec![Plan::Close(Edge::new(&h, "HasSession", &u))])
            }
            (Some(PROCESS_ACTIVITY), Some(LAUNCH)) => {
                // R8
                let Some(user) = ev
                    .get("actor_user")
                    .filter(|u| u.as_object().is_some_and(|o| !o.is_empty()))
                else {
                    return Ok(Vec::new());
                };
                if self.ids.is_system_account(user) {
                    return Ok(Vec::new());
                }
                let u = self.ids.user(Some(user))?;
                let h = self.ids.host(hostname("device"))?;
                Ok(vec![Plan::Assert(
                    Edge::new(&h, "HasSession", &u),
                    Confidence::Inferred,
                    self.p.process_ttl_ms,
                )])
            }
            _ => Ok(Vec::new()),
        }
    }

    fn assert(&mut self, eid: &str, edge: Edge, conf: Confidence, t: i64, ttl: i64) -> AttackDelta {
        let s = self.edges.entry(edge.clone()).or_default();
        s.origins.insert("observed");
        s.support.insert(eid.to_string());
        s.first_seen = Some(s.first_seen.map_or(t, |x| x.min(t)));
        s.last_seen = Some(s.last_seen.map_or(t, |x| x.max(t)));
        // An earlier event never advances expiry (§5).
        s.expires_at = Some(s.expires_at.map_or(t + ttl, |x| x.max(t + ttl)));
        s.confidence = Some(s.confidence.map_or(conf, |c| c.max(conf)));
        let expires_at = s.expires_at.unwrap_or_default();
        self.supported
            .entry(eid.to_string())
            .or_default()
            .push(edge.clone());
        AttackDelta::Assert {
            edge,
            event_id: eid.to_string(),
            confidence: conf,
            expires_at,
        }
    }

    fn close(&mut self, eid: &str, edge: Edge, t: i64) -> Option<AttackDelta> {
        let s = self
            .edges
            .get_mut(&edge)
            .filter(|s| !s.support.is_empty())?; // no observed session to close
        let expires_at = t + self.p.session_grace_ms;
        s.expires_at = Some(expires_at);
        Some(AttackDelta::Close {
            edge,
            event_id: eid.to_string(),
            expires_at,
        })
    }

    fn retract(&mut self, eid: &str) -> Vec<AttackDelta> {
        self.seen.remove(eid);
        let mut out = Vec::new();
        for edge in self.supported.remove(eid).unwrap_or_default() {
            let Some(s) = self.edges.get_mut(&edge) else {
                continue;
            };
            if !s.support.remove(eid) {
                continue;
            }
            if s.support.is_empty() {
                s.origins.remove("observed");
                if s.origins.is_empty() {
                    self.edges.remove(&edge);
                }
            }
            out.push(AttackDelta::Retract {
                edge,
                event_id: eid.to_string(),
            });
        }
        out
    }
}
