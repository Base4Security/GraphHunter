"""Minimum-cost detection cut as a MILP (potential / min-cut formulation).

Variables
    x_r in {0,1}  rule r active
    y_e in [0,1]  edge e counts as detected
    pi_v in [0,1] potential; pi_source = 0, pi_t = 1 for t in targets

    min  sum_r c_r x_r
    s.t. y_e - sum_{r covers e} x_r <= 0          (cover)
         pi_v - pi_u - y_e          <= 0          (potential, per edge (u,v))

Correctness: summing (potential) along any s->t path P gives
sum_{e in P} y_e >= pi_t - pi_s = 1. An edge with no active covering rule has
y_e = 0, so a path made only of undetected edges would give 0 >= 1. Hence every
feasible solution detects every s->T path. y need not be integral once x is.
Conversely any rule set that cuts admits pi_v = [v unreachable from s via
undetected edges], so the formulation is exact.

The LP relaxation is solved separately; its duals on the potential constraints
form an s->T flow, and the cover duals price each edge.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np
from scipy.optimize import Bounds, LinearConstraint, linprog, milp
from scipy.sparse import coo_matrix

from .model import Instance


@dataclass
class Solution:
    status: str
    rules: List[int] = field(default_factory=list)
    cost: float = float("nan")
    seconds: float = 0.0
    mip_gap: Optional[float] = None


@dataclass
class LPResult:
    status: str
    cost: float
    x: np.ndarray
    edge_flow: np.ndarray       # |dual| of potential constraints, per edge
    edge_price: np.ndarray      # |dual| of cover constraints, per edge
    rule_reduced_cost: np.ndarray
    seconds: float


def _build(inst: Instance, free_edges: frozenset = frozenset()):
    """free_edges: edges treated as detected at zero cost (their cover row is
    left empty, i.e. 0 <= 0). Used to measure the true marginal value of
    covering an edge."""
    R, E = len(inst.rules), len(inst.edges)
    node_idx: Dict[str, int] = {n: i for i, n in enumerate(inst.nodes)}
    V = len(inst.nodes)
    nvar = R + E + V
    X0, Y0, P0 = 0, R, R + E

    rows, cols, vals = [], [], []
    row = 0
    # cover constraints: rows 0..E-1
    for ei, rs in enumerate(inst.coverage):
        if ei in free_edges:
            row += 1
            continue
        rows.append(row); cols.append(Y0 + ei); vals.append(1.0)
        for ri in rs:
            rows.append(row); cols.append(X0 + ri); vals.append(-1.0)
        row += 1
    # potential constraints: rows E..2E-1
    for ei, e in enumerate(inst.edges):
        u, v = node_idx[e.u], node_idx[e.v]
        if u == v:
            rows.append(row); cols.append(Y0 + ei); vals.append(-1.0)
        else:
            rows.append(row); cols.append(P0 + v); vals.append(1.0)
            rows.append(row); cols.append(P0 + u); vals.append(-1.0)
            rows.append(row); cols.append(Y0 + ei); vals.append(-1.0)
        row += 1
    A = coo_matrix((vals, (rows, cols)), shape=(row, nvar)).tocsr()

    c = np.zeros(nvar)
    c[X0:X0 + R] = [r.cost for r in inst.rules]

    lb = np.zeros(nvar)
    ub = np.ones(nvar)
    s = node_idx[inst.source]
    ub[P0 + s] = 0.0
    for t in inst.targets:
        lb[P0 + node_idx[t]] = 1.0

    integrality = np.zeros(nvar)
    integrality[X0:X0 + R] = 1
    return A, c, lb, ub, integrality, (R, E, V)


def solve_milp(inst: Instance, time_limit: Optional[float] = None,
               free_edges: frozenset = frozenset()) -> Solution:
    A, c, lb, ub, integ, (R, E, V) = _build(inst, frozenset(free_edges))
    opts = {"disp": False}
    if time_limit is not None:
        opts["time_limit"] = float(time_limit)
    t0 = time.perf_counter()
    res = milp(
        c,
        constraints=LinearConstraint(A, -np.inf, 0.0),
        integrality=integ,
        bounds=Bounds(lb, ub),
        options=opts,
    )
    dt = time.perf_counter() - t0
    if res.x is None:
        return Solution(status=_status(res.status), seconds=dt)
    chosen = [i for i in range(R) if res.x[i] > 0.5]
    return Solution(
        status=_status(res.status),
        rules=chosen,
        cost=inst.rule_cost(chosen),
        seconds=dt,
        mip_gap=getattr(res, "mip_gap", None),
    )


def solve_lp(inst: Instance) -> LPResult:
    A, c, lb, ub, _, (R, E, V) = _build(inst)
    t0 = time.perf_counter()
    res = linprog(
        c,
        A_ub=A,
        b_ub=np.zeros(A.shape[0]),
        bounds=list(zip(lb, ub)),
        method="highs",
    )
    dt = time.perf_counter() - t0
    if res.status != 0:
        z = np.full(E, np.nan)
        return LPResult(_lp_status(res.status), float("nan"), np.full(R, np.nan),
                        z, z.copy(), np.full(R, np.nan), dt)
    duals = np.abs(res.ineqlin.marginals)
    return LPResult(
        status="optimal",
        cost=float(res.fun),
        x=res.x[:R].copy(),
        edge_price=duals[:E].copy(),
        edge_flow=duals[E:2 * E].copy(),
        rule_reduced_cost=res.lower.marginals[:R].copy(),
        seconds=dt,
    )


def _status(code: int) -> str:
    return {0: "optimal", 1: "limit", 2: "infeasible", 3: "unbounded"}.get(code, f"error{code}")


def _lp_status(code: int) -> str:
    return {0: "optimal", 1: "limit", 2: "infeasible", 3: "unbounded"}.get(code, f"error{code}")
