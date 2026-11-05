"""Correlated detectors (RQ5): how wrong is the independence assumption, and
what does a guarantee that does not rely on it cost?

1. Conservative model (book, Prop. 9.7): within an edge only the strongest
   active rule counts (valid for any dependence among the rules of an edge;
   edges still independent):
       ev(P) <= prod_e min_{r active on e} (1 - q_r)
   Linear with selectors s_{e,r} in [0,1]: s_{e,r} <= x_r, sum_r s_{e,r} <= 1,
   pi_v - pi_u <= sum_r w_r s_{e,r}.

2. Common-cause model: the observation of an edge needs the telemetry of its
   scope (the OU's endpoint agents, or the DC logs) to be up. Each scope is up
   with probability a, once per attack; given that, rules fire independently.
   An analyst who measures each rule alone sees the marginal rate a*q_r and,
   assuming independence, predicts prod_e prod_r (1 - a q_r). The true
   evasion of a path P touching scopes S is
       sum_{U subset S} a^|U| (1-a)^|S-U| prod_{e in P, scope(e) in U} prod_r (1 - q_r).
   (book, Prop. 13.3, generalised to a path.)
"""
from __future__ import annotations

import itertools
import math
import time
from dataclasses import dataclass, field, replace
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np
from scipy.optimize import Bounds, LinearConstraint, milp
from scipy.sparse import coo_matrix

from .model import Instance
from .prob import Q_MAX, rule_weight, theta_of


@dataclass
class ConsSolution:
    status: str
    rules: List[int] = field(default_factory=list)
    cost: float = float("nan")
    seconds: float = 0.0


def solve_conservative(inst: Instance, delta: float,
                       time_limit: Optional[float] = None) -> ConsSolution:
    theta = theta_of(delta)
    R, E, V = len(inst.rules), len(inst.edges), len(inst.nodes)
    idx = {n: i for i, n in enumerate(inst.nodes)}
    w = [rule_weight(r) for r in inst.rules]
    pairs = [(ei, r) for ei in range(E) for r in inst.coverage[ei]]
    S = len(pairs)
    nv = R + S + V
    off_s, off_p = R, R + S
    rows, cols, vals, lo, hi = [], [], [], [], []
    k = 0
    # potential rows: pi_v - pi_u - sum_r w_r s_{e,r} <= 0
    by_edge: Dict[int, List[int]] = {}
    for j, (ei, r) in enumerate(pairs):
        by_edge.setdefault(ei, []).append(j)
    for ei, e in enumerate(inst.edges):
        u, v = idx[e.u], idx[e.v]
        if u != v:
            rows += [k, k]; cols += [off_p + v, off_p + u]; vals += [1.0, -1.0]
        for j in by_edge.get(ei, []):
            rows.append(k); cols.append(off_s + j); vals.append(-w[pairs[j][1]])
        lo.append(-np.inf); hi.append(0.0); k += 1
    # selector rows: sum_r s_{e,r} <= 1 ; s_{e,r} - x_r <= 0
    for ei, js in by_edge.items():
        for j in js:
            rows.append(k); cols.append(off_s + j); vals.append(1.0)
        lo.append(-np.inf); hi.append(1.0); k += 1
    for j, (ei, r) in enumerate(pairs):
        rows += [k, k]; cols += [off_s + j, r]; vals += [1.0, -1.0]
        lo.append(-np.inf); hi.append(0.0); k += 1
    A = coo_matrix((vals, (rows, cols)), shape=(k, nv)).tocsr()
    c = np.zeros(nv); c[:R] = [r.cost for r in inst.rules]
    lb = np.zeros(nv); ub = np.ones(nv)
    ub[off_p:] = theta
    ub[off_p + idx[inst.source]] = 0.0
    for t in inst.targets:
        lb[off_p + idx[t]] = theta
    integ = np.zeros(nv); integ[:R] = 1
    opts = {"disp": False}
    if time_limit is not None:
        opts["time_limit"] = float(time_limit)
    t0 = time.perf_counter()
    res = milp(c, constraints=LinearConstraint(A, lo, hi), integrality=integ,
               bounds=Bounds(lb, ub), options=opts)
    dt = time.perf_counter() - t0
    status = {0: "optimal", 1: "limit", 2: "infeasible"}.get(res.status, f"error{res.status}")
    if res.x is None:
        return ConsSolution(status, seconds=dt)
    chosen = [i for i in range(R) if res.x[i] > 0.5]
    return ConsSolution(status, chosen, inst.rule_cost(chosen), dt)


def conservative_rule_weights(inst: Instance, rules: Sequence[int]) -> List[float]:
    """Per-edge weight under the conservative model: max over active rules."""
    chosen = set(rules)
    return [max((rule_weight(inst.rules[r]) for r in rs if r in chosen), default=0.0)
            for rs in inst.coverage]


def scaled(inst: Instance, a: float) -> Instance:
    """Same instance with every rate multiplied by a (what per-rule measurement
    sees when the rule's telemetry is up with probability a)."""
    rules = [replace(r, tpr=max(1e-6, a * r.tpr)) for r in inst.rules]
    return Instance(list(inst.nodes), list(inst.edges), rules, inst.source,
                    set(inst.targets), dict(inst.meta))


def true_evasion_common_cause(inst: Instance, rules: Sequence[int], path: Sequence[int],
                              a: float) -> float:
    """Exact evasion of `path` when each scope's telemetry is up with prob a
    (once per attack) and, given that, rules fire independently with q_r."""
    chosen = set(rules)
    per_scope: Dict[str, float] = {}  # prob. of evading all active rules on the path's edges of that scope
    for ei in path:
        e = inst.edges[ei]
        qs = [min(inst.rules[r].tpr, Q_MAX) for r in inst.coverage[ei] if r in chosen]
        if not qs:
            continue
        ev = math.prod(1 - q for q in qs)
        per_scope[e.scope] = per_scope.get(e.scope, 1.0) * ev
    # scopes are independent: each contributes (1-a) + a * ev_scope
    return math.prod((1 - a) + a * ev for ev in per_scope.values())


def predicted_evasion_independent(inst: Instance, rules: Sequence[int], path: Sequence[int],
                                  a: float) -> float:
    chosen = set(rules)
    return math.prod(1 - a * min(inst.rules[r].tpr, Q_MAX)
                     for ei in path for r in inst.coverage[ei] if r in chosen)
