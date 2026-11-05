"""Randomized defender (Stackelberg commitment) via partial alert triage.

Game. The defender commits to review rates z_r in [0,1]: each alert of rule r
is triaged independently with probability z_r (expected analyst load c_r z_r).
The attacker observes z (not the coin flips) and picks the most evasive s->T
path. With z in {0,1} this is exactly the pure model of prob.py, whose
worst-path guarantee already IS the attacker's best response.

Per edge, rule r detects with probability z_r q_r independently, so
    -log P(path evades) = sum_{e in P} sum_{r covers e} w_r(z_r),
    w_r(z) = -log(1 - z q_r)          (convex, increasing, w_r(0) = 0)

Because w_r is convex the continuous problem is non-convex. We solve it exactly
on the grid z_r in {0, 1/K, ..., 1} as a multiple-choice MILP:

    b_{r,k} in {0,1},  sum_k b_{r,k} <= 1,  z_r = sum_k (k/K) b_{r,k}
    min  sum_{r,k} c_r (k/K) b_{r,k}
    s.t. pi_v - pi_u - sum_{r covers e} sum_k w_r(k/K) b_{r,k} <= 0
         pi_s = 0, pi_t >= theta, 0 <= pi <= theta

Bounds:  LP_pure <= OPT_cont <= OPT_K <= OPT_1 = OPT_pure, and OPT_{K'} <= OPT_K
when K | K'. The LP of the pure model is a valid lower bound for the continuous
randomized problem because w_r(z) <= z w_r(1) (chord above a convex function).
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

import numpy as np
from scipy.optimize import Bounds, LinearConstraint, milp
from scipy.sparse import coo_matrix

from .model import Instance
from .prob import Q_MAX, theta_of, worst_path


def w_of(q: float, z: float) -> float:
    return -math.log(1.0 - z * min(q, Q_MAX))


def rule_weights_z(inst: Instance, z: Sequence[float]) -> List[float]:
    return [w_of(r.tpr, float(zi)) for r, zi in zip(inst.rules, z)]


@dataclass
class MixedSolution:
    status: str
    z: np.ndarray = field(default_factory=lambda: np.zeros(0))
    cost: float = float("nan")
    seconds: float = 0.0
    mip_gap: Optional[float] = None


def solve_mixed(inst: Instance, delta: float, K: int,
                time_limit: Optional[float] = None) -> MixedSolution:
    if K < 1:
        raise ValueError("K >= 1")
    theta = theta_of(delta)
    R, V, E = len(inst.rules), len(inst.nodes), len(inst.edges)
    nb = R * K
    idx = {n: i for i, n in enumerate(inst.nodes)}
    W = np.array([[w_of(r.tpr, k / K) for k in range(1, K + 1)] for r in inst.rules])
    rows, cols, vals = [], [], []
    for ei, e in enumerate(inst.edges):
        u, v = idx[e.u], idx[e.v]
        if u != v:
            rows += [ei, ei]; cols += [nb + v, nb + u]; vals += [1.0, -1.0]
        for r in inst.coverage[ei]:
            for k in range(K):
                rows.append(ei); cols.append(r * K + k); vals.append(-W[r, k])
    for r in range(R):  # multiple choice
        for k in range(K):
            rows.append(E + r); cols.append(r * K + k); vals.append(1.0)
    A = coo_matrix((vals, (rows, cols)), shape=(E + R, nb + V)).tocsr()
    hi = np.concatenate([np.zeros(E), np.ones(R)])
    c = np.zeros(nb + V)
    for r, rule in enumerate(inst.rules):
        for k in range(K):
            c[r * K + k] = rule.cost * (k + 1) / K
    lb = np.zeros(nb + V)
    ub = np.ones(nb + V)
    ub[nb:] = theta
    ub[nb + idx[inst.source]] = 0.0
    for t in inst.targets:
        lb[nb + idx[t]] = theta
    integ = np.zeros(nb + V)
    integ[:nb] = 1
    opts = {"disp": False}
    if time_limit is not None:
        opts["time_limit"] = float(time_limit)
    t0 = time.perf_counter()
    res = milp(c, constraints=LinearConstraint(A, -np.inf, hi), integrality=integ,
               bounds=Bounds(lb, ub), options=opts)
    dt = time.perf_counter() - t0
    status = {0: "optimal", 1: "limit", 2: "infeasible"}.get(res.status, f"error{res.status}")
    if res.x is None:
        return MixedSolution(status, seconds=dt)
    b = np.round(res.x[:nb]).reshape(R, K)
    z = (b * (np.arange(1, K + 1) / K)).sum(axis=1)
    cost = float(sum(r.cost * zi for r, zi in zip(inst.rules, z)))
    return MixedSolution(status, z, cost, dt, getattr(res, "mip_gap", None))


def solve_mixed_lb(inst: Instance, delta: float, K: int,
                   time_limit: Optional[float] = None) -> MixedSolution:
    """Lower bound on OPT_cont via piecewise-linear interpolation of w_r on the
    grid {0, 1/K, ..., 1}. For convex w_r the interpolant lies ABOVE w_r, so the
    resulting MILP is a relaxation: LP <= LB_K <= OPT_cont <= OPT_K.
    (Same idea as the PWL over/under-estimates of Guo et al., AAAI 2023, for
    per-edge blocking; here applied to shared-coverage rules.)
    Per rule: segment selectors s_{r,k} in {0,1}, sum_k s_{r,k} <= 1, and an
    offset d_{r,k} in [0, s_{r,k}/K];  z_r = sum_k ((k-1)/K s_{r,k} + d_{r,k}).
    The returned z is the relaxation's point; it need NOT meet delta."""
    theta = theta_of(delta)
    R, V, E = len(inst.rules), len(inst.nodes), len(inst.edges)
    nS = R * K
    S0, D0, P0 = 0, nS, 2 * nS
    nvar = 2 * nS + V
    idx = {n: i for i, n in enumerate(inst.nodes)}
    Wk = np.array([[w_of(r.tpr, k / K) for k in range(K + 1)] for r in inst.rules])
    rows, cols, vals = [], [], []
    for ei, e in enumerate(inst.edges):
        u, v = idx[e.u], idx[e.v]
        if u != v:
            rows += [ei, ei]; cols += [P0 + v, P0 + u]; vals += [1.0, -1.0]
        for r in inst.coverage[ei]:
            for k in range(K):  # segment k covers [k/K, (k+1)/K]
                rows.append(ei); cols.append(S0 + r * K + k); vals.append(-Wk[r, k])
                slope = K * (Wk[r, k + 1] - Wk[r, k])
                rows.append(ei); cols.append(D0 + r * K + k); vals.append(-slope)
    row = E
    for r in range(R):  # one segment per rule
        for k in range(K):
            rows.append(row); cols.append(S0 + r * K + k); vals.append(1.0)
        row += 1
    for r in range(R):  # d <= s / K
        for k in range(K):
            rows += [row, row]; cols += [D0 + r * K + k, S0 + r * K + k]; vals += [1.0, -1.0 / K]
            row += 1
    A = coo_matrix((vals, (rows, cols)), shape=(row, nvar)).tocsr()
    hi = np.concatenate([np.zeros(E), np.ones(R), np.zeros(R * K)])
    c = np.zeros(nvar)
    for r, rule in enumerate(inst.rules):
        for k in range(K):
            c[S0 + r * K + k] = rule.cost * k / K
            c[D0 + r * K + k] = rule.cost
    lb = np.zeros(nvar)
    ub = np.ones(nvar)
    ub[D0:D0 + nS] = 1.0 / K
    ub[P0:] = theta
    ub[P0 + idx[inst.source]] = 0.0
    for t in inst.targets:
        lb[P0 + idx[t]] = theta
    integ = np.zeros(nvar)
    integ[S0:S0 + nS] = 1
    opts = {"disp": False}
    if time_limit is not None:
        opts["time_limit"] = float(time_limit)
    t0 = time.perf_counter()
    res = milp(c, constraints=LinearConstraint(A, -np.inf, hi), integrality=integ,
               bounds=Bounds(lb, ub), options=opts)
    dt = time.perf_counter() - t0
    status = {0: "optimal", 1: "limit", 2: "infeasible"}.get(res.status, f"error{res.status}")
    if res.x is None:
        return MixedSolution(status, seconds=dt)
    s = np.round(res.x[S0:S0 + nS]).reshape(R, K)
    d = res.x[D0:D0 + nS].reshape(R, K)
    z = (s * (np.arange(K) / K) + d).sum(axis=1)
    # with a time limit the incumbent is not a bound; report HiGHS's dual bound
    bound = float(getattr(res, "mip_dual_bound", res.fun) if status != "optimal" else res.fun)
    return MixedSolution(status, z, bound, dt, getattr(res, "mip_gap", None))


def achieved_delta_z(inst: Instance, z: Sequence[float]) -> float:
    """Attacker best response to commitment z: max_P P(P evades). Uses the
    Dijkstra verifier of prob.py, not the MILP."""
    return worst_path(inst, [], rule_weights_z(inst, z))[0]


def meets_z(inst: Instance, z: Sequence[float], delta: float, rtol: float = 1e-6) -> bool:
    return achieved_delta_z(inst, z) <= delta * (1 + rtol)


def monte_carlo_z(inst: Instance, z: Sequence[float], path: Sequence[int],
                  n: int = 40000, seed: int = 0) -> float:
    """Simulate fire (q_r) AND review (z_r), independently per (edge, rule)."""
    rng = np.random.default_rng(seed)
    ps = [float(z[r]) * min(inst.rules[r].tpr, Q_MAX)
          for ei in path for r in inst.coverage[ei] if z[r] > 0]
    if not ps:
        return 1.0
    det = rng.random((n, len(ps))) < np.array(ps)
    return float(np.mean(~det.any(axis=1)))
