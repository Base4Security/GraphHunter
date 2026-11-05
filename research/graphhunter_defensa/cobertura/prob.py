"""Probabilistic detection: every s->T path must be detected with prob >= 1 - delta.

Assumption (explicit, probably optimistic): firings of different (rule, edge)
pairs are independent; rule r fires on a covered edge with probability q_r.

    P(path P evades) = prod_{e in P} prod_{r active, covers e} (1 - q_r)
    -log P(evade)    = sum_{e in P} w_e(x),   w_e(x) = sum_{r covers e} w_r x_r,
                                              w_r = -log(1 - q_r)

so the condition is linear in x: shortest s->t distance under weights w_e(x)
must be >= theta = -log(delta) for every target t. Potentials encode it:

    min  sum c_r x_r
    s.t. pi_v - pi_u - sum_{r covers e} w_r x_r <= 0     for every edge (u,v)
         pi_s = 0,  pi_t >= theta,  0 <= pi_v <= theta

Sound: summing along a path gives its length >= pi_t - pi_s >= theta.
Complete: if every distance is >= theta, pi_v = min(dist(s,v), theta) is feasible.
With all q_r equal to q and theta = -log(1-q) it reduces to the deterministic cut.
"""
from __future__ import annotations

import heapq
import math
import time
from dataclasses import dataclass, field, replace
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np
from scipy.optimize import Bounds, LinearConstraint, linprog, milp
from scipy.sparse import coo_matrix

from .model import Instance, Rule

Q_MAX = 1.0 - 1e-6  # caps w_r at ~13.8 so q_r = 1 stays finite


def rule_weight(r: Rule) -> float:
    return -math.log(1.0 - min(r.tpr, Q_MAX))


def theta_of(delta: float) -> float:
    if not (0.0 < delta < 1.0):
        raise ValueError("delta must be in (0, 1)")
    return -math.log(delta)


@dataclass
class ProbSolution:
    status: str
    rules: List[int] = field(default_factory=list)
    cost: float = float("nan")
    seconds: float = 0.0


@dataclass
class ProbLP:
    status: str
    cost: float
    x: np.ndarray
    edge_price: np.ndarray
    seconds: float


def _build(inst: Instance, theta: float):
    R, E, V = len(inst.rules), len(inst.edges), len(inst.nodes)
    idx = {n: i for i, n in enumerate(inst.nodes)}
    w = [rule_weight(r) for r in inst.rules]
    rows, cols, vals = [], [], []
    for ei, e in enumerate(inst.edges):
        u, v = idx[e.u], idx[e.v]
        if u != v:
            rows += [ei, ei]; cols += [R + v, R + u]; vals += [1.0, -1.0]
        for ri in inst.coverage[ei]:
            rows.append(ei); cols.append(ri); vals.append(-w[ri])
    A = coo_matrix((vals, (rows, cols)), shape=(E, R + V)).tocsr()
    c = np.zeros(R + V)
    c[:R] = [r.cost for r in inst.rules]
    lb = np.zeros(R + V)
    ub = np.ones(R + V)
    ub[R:] = theta
    ub[R + idx[inst.source]] = 0.0
    for t in inst.targets:
        lb[R + idx[t]] = theta
    integ = np.zeros(R + V)
    integ[:R] = 1
    return A, c, lb, ub, integ, R


def solve_prob_milp(inst: Instance, delta: float,
                    time_limit: Optional[float] = None) -> ProbSolution:
    A, c, lb, ub, integ, R = _build(inst, theta_of(delta))
    opts = {"disp": False}
    if time_limit is not None:
        opts["time_limit"] = float(time_limit)
    t0 = time.perf_counter()
    res = milp(c, constraints=LinearConstraint(A, -np.inf, 0.0), integrality=integ,
               bounds=Bounds(lb, ub), options=opts)
    dt = time.perf_counter() - t0
    status = {0: "optimal", 1: "limit", 2: "infeasible"}.get(res.status, f"error{res.status}")
    if res.x is None:
        return ProbSolution(status, seconds=dt)
    chosen = [i for i in range(R) if res.x[i] > 0.5]
    return ProbSolution(status, chosen, inst.rule_cost(chosen), dt)


def solve_prob_lp(inst: Instance, delta: float) -> ProbLP:
    A, c, lb, ub, _, R = _build(inst, theta_of(delta))
    t0 = time.perf_counter()
    res = linprog(c, A_ub=A, b_ub=np.zeros(A.shape[0]), bounds=list(zip(lb, ub)),
                  method="highs")
    dt = time.perf_counter() - t0
    if res.status != 0:
        E = len(inst.edges)
        return ProbLP("infeasible" if res.status == 2 else f"error{res.status}",
                      float("nan"), np.full(R, np.nan), np.full(E, np.nan), dt)
    return ProbLP("optimal", float(res.fun), res.x[:R].copy(),
                  np.abs(res.ineqlin.marginals), dt)


# ---------------------------------------------------------------- verification
def _edge_weights(inst: Instance, rule_idx: Sequence[int],
                  rule_w: Optional[Sequence[float]] = None) -> List[float]:
    """Per-edge -log P(evade). rule_w (per-rule weight, 0 = inactive) overrides
    rule_idx; used by the randomized-defender model."""
    if rule_w is None:
        chosen = set(rule_idx)
        rule_w = [rule_weight(r) if i in chosen else 0.0 for i, r in enumerate(inst.rules)]
    return [sum(rule_w[r] for r in rs) for rs in inst.coverage]


def evasion_distances(inst: Instance, rule_idx: Sequence[int],
                      rule_w: Optional[Sequence[float]] = None
                      ) -> Tuple[Dict[str, float], Dict[str, Optional[int]]]:
    """Dijkstra from source with weights w_e(x) = -log P(edge evades).
    Independent of the MILP code. Returns (dist, predecessor edge)."""
    we = _edge_weights(inst, rule_idx, rule_w)
    adj: Dict[str, list] = {n: [] for n in inst.nodes}
    for ei, e in enumerate(inst.edges):
        adj[e.u].append((e.v, we[ei], ei))
    dist = {inst.source: 0.0}
    pred: Dict[str, Optional[int]] = {inst.source: None}
    pq = [(0.0, inst.source)]
    done = set()
    while pq:
        d, n = heapq.heappop(pq)
        if n in done:
            continue
        done.add(n)
        for m, w, ei in adj[n]:
            nd = d + w
            if nd < dist.get(m, math.inf) - 1e-12:
                dist[m] = nd
                pred[m] = ei
                heapq.heappush(pq, (nd, m))
    return dist, pred


def worst_path(inst: Instance, rule_idx: Sequence[int],
               rule_w: Optional[Sequence[float]] = None) -> Tuple[float, List[int]]:
    """Most evasive s->T path: (its evasion probability, edge indices)."""
    dist, pred = evasion_distances(inst, rule_idx, rule_w)
    reach = [t for t in inst.targets if t in dist]
    if not reach:
        return 0.0, []
    t = min(reach, key=lambda x: dist[x])
    path, n = [], t
    while pred[n] is not None:
        path.append(pred[n])
        n = inst.edges[pred[n]].u
    return math.exp(-dist[t]), path[::-1]


def achieved_delta(inst: Instance, rule_idx: Sequence[int]) -> float:
    """max over s->T paths of P(path evades all active rules)."""
    return worst_path(inst, rule_idx)[0]


def meets(inst: Instance, rule_idx: Sequence[int], delta: float, rtol: float = 1e-6) -> bool:
    return achieved_delta(inst, rule_idx) <= delta * (1 + rtol)


def best_possible_delta(inst: Instance) -> float:
    return achieved_delta(inst, range(len(inst.rules)))


def monte_carlo_evasion(inst: Instance, rule_idx: Sequence[int], path: Sequence[int],
                        n: int = 20000, seed: int = 0) -> float:
    """Simulate independent firings along a fixed path; fraction that evades."""
    rng = np.random.default_rng(seed)
    chosen = set(rule_idx)
    qs = [min(inst.rules[r].tpr, Q_MAX) for ei in path for r in inst.coverage[ei] if r in chosen]
    if not qs:
        return 1.0
    fires = rng.random((n, len(qs))) < np.array(qs)
    return float(np.mean(~fires.any(axis=1)))


# ---------------------------------------------------------------- baseline
def greedy_weakest_path(inst: Instance, delta: float, prune: bool = True) -> List[int]:
    """Patch the currently most evasive path with the rule of least cost per
    unit of added -log evasion on it; repeat until the guarantee holds."""
    theta = theta_of(delta)
    w = [rule_weight(r) for r in inst.rules]
    chosen: List[int] = []
    for _ in range(10 * len(inst.rules) + 10):
        p_evade, path = worst_path(inst, chosen)
        if p_evade <= delta * (1 + 1e-9):
            break
        best, ratio = None, math.inf
        for ri in range(len(inst.rules)):
            if ri in chosen:
                continue
            gain = sum(w[ri] for ei in path if ri in inst.coverage[ei])
            if gain > 0 and inst.rules[ri].cost / gain < ratio:
                best, ratio = ri, inst.rules[ri].cost / gain
        if best is None:
            break  # infeasible: no unused rule sees the weakest path
        chosen.append(best)
    if prune and meets(inst, chosen, delta):
        for ri in sorted(chosen, key=lambda i: -inst.rules[i].cost):
            trial = [r for r in chosen if r != ri]
            if meets(inst, trial, delta):
                chosen = trial
    return chosen


# ---------------------------------------------------------------- data
TPR_MEAN = {"T1566": 0.5, "T1190": 0.4, "T1021": 0.35, "T1003": 0.7, "T1550": 0.5,
            "T1558": 0.6, "T1003.006": 0.85, "T1098": 0.55}


def assign_tpr(inst: Instance, seed: int, concentration: float = 20.0,
               bundle_penalty: float = 0.1) -> Instance:
    """Synthetic TPRs (not calibrated): Beta around a per-technique mean; rules
    covering several techniques pay a penalty. Uses its own RNG stream so the
    graph and costs stay identical to the deterministic experiment."""
    rng = np.random.default_rng([seed, 7919])
    rules = []
    for r in inst.rules:
        m = float(np.mean([TPR_MEAN.get(t, 0.5) for t in r.techniques]))
        if len(r.techniques) > 1:
            m -= bundle_penalty
        m = min(max(m, 0.05), 0.95)
        q = float(rng.beta(m * concentration, (1 - m) * concentration))
        rules.append(replace(r, tpr=round(min(max(q, 0.02), 0.98), 3)))
    return Instance(inst.nodes, inst.edges, rules, inst.source, set(inst.targets),
                    meta=dict(inst.meta, tpr_seed=seed))
