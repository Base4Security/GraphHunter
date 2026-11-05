# SPDX-License-Identifier: LGPL-3.0-or-later
# Re-implementation of logic from BloodHound-Tools/DBCreator.py (LGPL-3.0).
# Copyright (c) 2026 Lucas Sotomayor. See LICENSE.
"""DBCreator-like Active Directory attack graphs (benchmark used by Guo et al.,
AAAI 2022/2023), re-implemented from a reading of BloodHound-Tools/DBCreator.py
(generate_data). Only the three edge types Guo et al. keep are generated:
MemberOf, AdminTo and HasSession. Neo4j is not needed.

Faithful to DBCreator (same constants, same random structure):
  * N computers, N users, N groups (dept-weighted names: IT 7%, HR 13%,
    MARKETING 30%, OPERATIONS 20%, BIDNESS 30%); 10 domain controllers.
  * Domain Admins (DA) group is AdminTo every computer and DC.
  * DA users: ceil(N * U{3..5}%) capped at 30.
  * Group nesting: each group w.p. 10% nests into randrange(1, round(log10 N))
    groups of its department.
  * Users join floor(log10(N)^2) + randrange(-2*ceil(log10 N), 0) groups of a
    random department.
  * Local admin: 4 IT "super groups" admin 85% of computers; the other IT
    groups admin 1/2/10/50 computers with weights 60/30/7/3 %.
  * Sessions: each user randrange(0, ceil(log10 N)) sessions (DA users >= 1).
  * Computers are split into 10 OUs (states) -> used here as telemetry scopes.

Differences (deliberate): python `random.Random(seed)` instead of the global
RNG; the generic MemberOf edges to "DOMAIN USERS"/"DOMAIN COMPUTERS" are kept
but carry no privilege (those groups have no outgoing edges here); DA's own
outgoing edges are dropped (as in Guo et al.). Entry nodes follow Guo et al.:
20 nodes sampled from the 40 farthest (in hops) from DA.

Detection mapping (ours, an assumption): MemberOf = unobservable;
AdminTo g->c = T1021 (lateral movement) in scope OU(c);
HasSession c->u = T1003 (credential dumping) in scope OU(c).
"""
from __future__ import annotations

import math
import random
from collections import deque
from typing import Dict, List, Tuple

import numpy as np

from .ad_graph import to_instance
from .model import Edge, Instance

PARTS = ["IT"] * 7 + ["HR"] * 13 + ["MARKETING"] * 30 + ["OPERATIONS"] * 20 + ["BIDNESS"] * 30
STATES = ["WA", "MD", "AL", "IN", "NV", "VA", "CA", "NY", "TX", "FL"]


def generate_dbc(n: int, seed: int, n_entries: int = 20, entry_pool: int = 40,
                 rule_prob: float = 0.85, bundle_discount: float = 0.8) -> Instance:
    rnd = random.Random(seed)
    computers = [f"COMP{i:05d}" for i in range(1, n + 1)]
    users = [f"USER{i:05d}" for i in range(1, n + 1)]
    groups = [f"{rnd.choice(PARTS)}{i:05d}" for i in range(1, n + 1)]
    DA = "DOMAIN ADMINS"
    edges: set = set()

    def add(u, v, kind):
        if u != v:
            edges.add((u, v, kind))

    for c in computers:
        add(c, "DOMAIN COMPUTERS", "MemberOf")
    for u in users:
        add(u, "DOMAIN USERS", "MemberOf")
    # DA AdminTo all computers: outgoing edges of the target are dropped later.
    danum = min(int(math.ceil(n * rnd.randint(3, 5) / 100)), 30)
    das = rnd.sample(users, danum)
    for d in das:
        add(d, DA, "MemberOf")
    # nesting
    max_nest = int(round(math.log10(n)))
    dept_of = {g: g.rstrip("0123456789") for g in groups}
    by_dept: Dict[str, List[str]] = {}
    for g in groups:
        by_dept.setdefault(dept_of[g], []).append(g)
    for g in groups:
        if rnd.randrange(0, 100) < 10 and max_nest > 1:
            num = rnd.randrange(1, max_nest)
            pool = by_dept[dept_of[g]]
            if num > len(pool):
                num = rnd.randrange(1, len(pool))
            for h in rnd.sample(pool, num):
                add(g, h, "MemberOf")
    # users -> groups
    base = int(math.floor(math.log10(n) ** 2))
    var = int(math.ceil(math.log10(n)))
    it_users = []
    for u in users:
        dept = rnd.choice(PARTS)
        if dept == "IT":
            it_users.append(u)
        pool = by_dept.get(dept, [])
        k = base + rnd.randrange(-(var * 2), 0)
        if k > len(pool):
            k = int(math.floor(len(pool) / 4))
        if k <= 0:
            continue
        for g in rnd.sample(pool, k):
            add(u, g, "MemberOf")
    # local admin rights
    it_groups = [g for g in groups if dept_of[g] == "IT"]
    rnd.shuffle(it_groups)
    supers = rnd.sample(it_groups, min(4, len(it_groups)))
    super_num = int(math.floor(len(computers) * 0.85))
    rest = [g for g in it_groups if g not in supers]
    t = len(rest)
    dist = ([1] * int(math.ceil(t * .6)) + [2] * int(math.ceil(t * .3))
            + [10] * int(math.ceil(t * .07)) + [50] * int(math.ceil(t * .03)))
    for x, g in enumerate(rest):
        for c in rnd.sample(computers, min(dist[x], len(computers))):
            add(g, c, "AdminTo")
    for g in supers:
        for c in rnd.sample(computers, super_num):
            add(g, c, "AdminTo")
    # sessions
    max_s = int(math.ceil(math.log10(n)))
    for u in users:
        k = rnd.randrange(0, max_s)
        if u in das:
            k = max(k, 1)
        for c in rnd.sample(computers, k):
            add(c, u, "HasSession")
    # OUs (computers split in 10 chunks), used as scopes ws0..ws9
    comps = computers[:]
    rnd.shuffle(comps)
    split = int(math.ceil(n / 10))
    seg_of = {c: f"ws{i // split}" for i, c in enumerate(comps)}

    return dbc_edges_to_instance(edges, seg_of, DA, seed, rnd, n_entries, entry_pool,
                                 rule_prob, bundle_discount,
                                 meta={"generator": "dbcreator_like", "n": n})


def dbc_edges_to_instance(edges, seg_of, target, seed, rnd, n_entries=20, entry_pool=40,
                          rule_prob=0.85, bundle_discount=0.8, meta=None) -> Instance:
    """MemberOf -> unobservable; AdminTo g->c -> T1021 @ OU(c);
    HasSession c->u -> T1003 @ OU(c). Also used for graphs captured from the
    original DBCreator (dbcreator_capture)."""
    typed = []
    for (u, v, kind) in sorted(edges):
        if kind == "MemberOf":
            typed.append((u, v, None, None))
        elif kind == "AdminTo":
            if v in seg_of:
                typed.append((u, v, "T1021", seg_of[v]))
        elif kind == "HasSession":
            if u in seg_of:
                typed.append((u, v, "T1003", seg_of[u]))
    m = dict(meta or {})
    m["raw_edges"] = len(edges)
    return to_instance(typed, {target}, seg_of, seed, rnd, n_entries, entry_pool,
                       rule_prob, bundle_discount, meta=m)
