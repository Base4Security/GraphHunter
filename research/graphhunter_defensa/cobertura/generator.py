"""Synthetic Active-Directory-like attack graphs and detection-rule catalogs.

Shape (BloodHound-inspired, simplified):
    ENTRY --T1566 phishing--> some users
    user  --T1021 remote services--> hosts where the user is local admin
    host  --T1003 credential dumping--> users with sessions on that host
    host  --T1550 pass-the-hash--> hosts sharing a local admin password
    user  --(membership, unobservable)--> groups
    group --T1021--> hosts / servers it administers
    server --T1003--> users with sessions on the server
    user  --(membership)--> AUTH --T1558 kerberoasting--> service accounts
    user  --T1098 ACL abuse--> groups
    Domain Admins group --(membership)--> DA ; DCSync-capable account --T1003.006--> DA

Costs are synthetic FP/day; they are NOT calibrated against real SOC data.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Set, Tuple

import numpy as np

from .model import Edge, Instance, Rule

# Base noise (FP/day per monitored unit) per technique: synthetic assumptions.
NOISE = {
    "T1566": 3.0,
    "T1021": 2.0,
    "T1003": 0.6,
    "T1550": 1.2,
    "T1558": 0.4,
    "T1003.006": 0.1,
    "T1098": 0.3,
    "T1190": 5.0,
    # Agregadas para el grafo de AD (ADCS y coerción); mismo carácter de
    # supuesto sintético que el resto de la tabla.
    "T1649": 0.2,
    "T1187": 0.5,
}


@dataclass
class GenParams:
    n_users: int = 60
    n_hosts: int = 40
    n_servers: int = 10
    n_groups: int = 8
    n_segments: int = 4
    phish_frac: float = 0.1
    svc_frac: float = 0.08
    rule_prob: float = 0.85
    bundle_discount: float = 0.8
    assume_breach: bool = True
    seed: int = 0


def generate(p: GenParams) -> Instance:
    rng = np.random.default_rng(p.seed)
    users = [f"U{i}" for i in range(p.n_users)]
    hosts = [f"H{i}" for i in range(p.n_hosts)]
    servers = [f"S{i}" for i in range(p.n_servers)]
    groups = [f"G{i}" for i in range(p.n_groups)]  # G0 = Domain Admins
    nodes = ["ENTRY", "AUTH", "DA"] + users + hosts + servers + groups

    seg_of: Dict[str, str] = {h: f"ws{rng.integers(p.n_segments)}" for h in hosts}
    for s in servers:
        seg_of[s] = "srv"
    edges: Set[Tuple[str, str, object, object]] = set()

    def add(u, v, t, sc):
        if u != v:
            edges.add((u, v, t, sc))

    da_members = rng.choice(users, max(1, p.n_users // 30), replace=False)
    # initial access. assume_breach: the foothold is given (unobservable), so
    # the perimeter cannot serve as the cut -- the interesting regime.
    n_ph = max(1, int(round(p.phish_frac * p.n_users)))
    for u in rng.choice([u for u in users if u not in set(da_members)], n_ph, replace=False):
        if p.assume_breach:
            add("ENTRY", u, None, None)
        else:
            add("ENTRY", u, "T1566", "mail")
    if not p.assume_breach:
        add("ENTRY", rng.choice(servers), "T1190", "dmz")
    # local admin + sessions
    for u in users:
        for h in rng.choice(hosts, rng.integers(1, 3), replace=False):
            add(u, h, "T1021", seg_of[h])
        add(u, "AUTH", None, None)
    for h in hosts:
        for u in rng.choice(users, rng.integers(1, 4), replace=False):
            add(h, u, "T1003", seg_of[h])
    # password reuse within segment
    for h in hosts:
        same = [x for x in hosts if seg_of[x] == seg_of[h] and x != h]
        if same and rng.random() < 0.3:
            add(h, rng.choice(same), "T1550", seg_of[h])
    # groups
    for u in users:
        for g in rng.choice(groups[1:], rng.integers(0, 2), replace=False):
            add(u, g, None, None)
    for u in da_members:
        add(u, "G0", None, None)
    add("G0", "DA", None, None)
    for g in groups[1:]:
        for s in rng.choice(servers, rng.integers(1, 3), replace=False):
            add(g, s, "T1021", "srv")
        if rng.random() < 0.4:
            for h in rng.choice(hosts, rng.integers(2, 6), replace=False):
                add(g, h, "T1021", seg_of[h])
    for s in servers:
        for u in rng.choice(users, rng.integers(1, 3), replace=False):
            add(s, u, "T1003", "srv")
        if rng.random() < 0.3:  # an admin of the domain logs on to this server
            add(s, rng.choice(da_members), "T1003", "srv")
    # kerberoastable service accounts
    n_svc = max(1, int(round(p.svc_frac * p.n_users)))
    svc = rng.choice(users, n_svc, replace=False)
    for u in svc:
        add("AUTH", u, "T1558", "dc")
    add(rng.choice(svc), "DA", "T1003.006", "dc")  # DCSync rights
    # ACL abuse
    for u in rng.choice(users, max(1, p.n_users // 15), replace=False):
        add(u, rng.choice(groups), "T1098", "dc")

    edge_list = [Edge(u, v, t, sc) for (u, v, t, sc) in sorted(edges, key=str)]
    rules = _catalog(edge_list, seg_of, p, rng)
    return Instance(nodes, edge_list, rules, "ENTRY", {"DA"},
                    meta={"params": p.__dict__.copy(), "segments": seg_of})


def _catalog(edges: List[Edge], seg_of, p: GenParams, rng) -> List[Rule]:
    # monitored units per scope (hosts in segment; fixed for mail/dc)
    units: Dict[str, int] = {"mail": p.n_users, "dc": 1, "dmz": 1}
    for n, sc in seg_of.items():
        units[sc] = units.get(sc, 0) + 1
    pairs = sorted({(e.technique, e.scope) for e in edges if e.technique})

    def noisy(t, sc):
        return NOISE[t] * units.get(sc, 1) * float(rng.lognormal(0.0, 0.5))

    rules: List[Rule] = []
    single_cost: Dict[Tuple[str, str], float] = {}
    for t, sc in pairs:
        c = noisy(t, sc)
        single_cost[(t, sc)] = c
        if rng.random() < p.rule_prob:
            rules.append(Rule(f"{t}@{sc}", frozenset([t]), frozenset([sc]), round(c, 2)))
    # EDR bundle per workstation segment / server tier
    for sc in sorted({sc for _, sc in pairs if sc.startswith("ws") or sc == "srv"}):
        ts = [t for (t, s) in pairs if s == sc and t in ("T1003", "T1550", "T1021")]
        if len(ts) >= 2:
            c = p.bundle_discount * sum(single_cost[(t, sc)] for t in ts)
            rules.append(Rule(f"EDR@{sc}", frozenset(ts), frozenset([sc]), round(c, 2)))
    # domain-wide technique rules (one detection across all workstation segments)
    ws = sorted({sc for _, sc in pairs if sc.startswith("ws")})
    for t in ("T1003", "T1550"):
        scs = [sc for sc in ws if (t, sc) in single_cost]
        if len(scs) >= 2:
            c = 0.9 * sum(single_cost[(t, sc)] for sc in scs)
            rules.append(Rule(f"{t}@all-ws", frozenset([t]), frozenset(scs), round(c, 2)))
    # DC audit bundle
    dc_ts = [t for (t, s) in pairs if s == "dc"]
    if len(dc_ts) >= 2:
        c = p.bundle_discount * sum(single_cost[(t, "dc")] for t in dc_ts)
        rules.append(Rule("DC-audit", frozenset(dc_ts), frozenset(["dc"]), round(c, 2)))
    return rules
