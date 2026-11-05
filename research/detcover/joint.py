"""Joint prevention + detection: block edges (hardening) and/or deploy rules.

A path is neutralised if it uses a blocked edge or is detected with probability
>= 1 - delta. With blocking variables b_e in {0,1} for blockable edges B:

    min  sum_r c_r x_r + lam * sum_{e in B} h_e b_e
    s.t. pi_v - pi_u - sum_{r covers e} w_r x_r - theta * b_e <= 0   for every edge
         sum_{e in B} h_e b_e <= H                                  (optional budget)
         pi_s = 0,  pi_t >= theta,  0 <= pi <= theta

A blocked edge carries weight theta, so no path through it can bind: blocking is
exactly edge removal (pi is capped at theta). With B empty (or H = 0) the model is
the probabilistic model of prob.py; with tpr = 1 for every rule it is the
deterministic cut plus blocking.

Hardening costs h_e are a modelling assumption. default_block_costs() prices an
edge by its technique (a proxy for the BloodHound edge type); edges out of the
super-source and memberships into a target group are not blockable.

Related work: Nguyen, Song & Smith (Networks 2023) combine arc interdiction with
per-arc monitoring in a simultaneous game. Here monitoring is a shared rule
(one rule covers many edges), the objective is alert load under a per-path
guarantee, and triage commitment is handled in stackelberg.py.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np
from scipy.optimize import Bounds, LinearConstraint, milp
from scipy.sparse import coo_matrix

from .model import Instance
from .prob import rule_weight, theta_of, worst_path

# Synthetic hardening cost per technique (proxy for the BloodHound edge type):
#   None       MemberOf/Contains: remove a group membership
#   T1021      AdminTo/CanRDP/...: revoke local admin or remote access
#   T1003      HasSession: keep the privileged account off that host (tiering)
#   T1098      ACL abuse: fix the misconfigured ACE
#   T1558      delegation: remove the delegation right
#   T1003.006  DCSync rights: remove the replication right
TECH_BLOCK_COST: Dict[Optional[str], float] = {
    None: 2.0, "T1021": 2.0, "T1003": 3.0, "T1098": 1.0, "T1558": 2.0, "T1003.006": 1.0,
}


def default_block_costs(inst: Instance,
                        costs: Dict[Optional[str], float] = TECH_BLOCK_COST
                        ) -> Dict[int, float]:
    """Blockable edges and their hardening cost. Not blockable: edges out of the
    source (the super-source ENTRY models the foothold, not a privilege) and
    unobservable edges into a target (membership of the target group itself)."""
    out: Dict[int, float] = {}
    for ei, e in enumerate(inst.edges):
        if e.u == inst.source:
            continue
        if e.v in inst.targets and e.technique is None:
            continue
        if e.technique in costs:
            out[ei] = float(costs[e.technique])
    return out


@dataclass
class JointSolution:
    status: str
    rules: List[int] = field(default_factory=list)
    blocked: List[int] = field(default_factory=list)
    alert_cost: float = float("nan")
    harden_cost: float = float("nan")
    seconds: float = 0.0


def solve_joint(inst: Instance, delta: float, block_cost: Dict[int, float],
                budget: Optional[float] = None, lam: float = 0.0,
                allow_rules: bool = True, time_limit: Optional[float] = None
                ) -> JointSolution:
    """Exact MILP. budget caps sum h_e b_e; lam prices hardening in the objective.
    allow_rules=False gives the hardening-only baseline (then the objective is
    the hardening cost)."""
    theta = theta_of(delta)
    R, E, V = len(inst.rules), len(inst.edges), len(inst.nodes)
    blk = sorted(block_cost)
    Bn = len(blk)
    bpos = {ei: k for k, ei in enumerate(blk)}
    idx = {n: i for i, n in enumerate(inst.nodes)}
    w = [rule_weight(r) for r in inst.rules]
    nv = R + Bn + V
    rows, cols, vals = [], [], []
    for ei, e in enumerate(inst.edges):
        u, v = idx[e.u], idx[e.v]
        if u != v:
            rows += [ei, ei]; cols += [R + Bn + v, R + Bn + u]; vals += [1.0, -1.0]
        for ri in inst.coverage[ei]:
            rows.append(ei); cols.append(ri); vals.append(-w[ri])
        if ei in bpos:
            rows.append(ei); cols.append(R + bpos[ei]); vals.append(-theta)
    A = coo_matrix((vals, (rows, cols)), shape=(E, nv)).tocsr()
    cons = [LinearConstraint(A, -np.inf, 0.0)]
    h = np.array([block_cost[ei] for ei in blk], dtype=float)
    if budget is not None and Bn:
        row = np.zeros(nv); row[R:R + Bn] = h
        cons.append(LinearConstraint(row.reshape(1, -1), -np.inf, float(budget)))
    c = np.zeros(nv)
    if allow_rules:
        c[:R] = [r.cost for r in inst.rules]
        c[R:R + Bn] = lam * h
    else:
        c[R:R + Bn] = h
    lb = np.zeros(nv)
    ub = np.ones(nv)
    if not allow_rules:
        ub[:R] = 0.0
    ub[R + Bn:] = theta
    ub[R + Bn + idx[inst.source]] = 0.0
    for t in inst.targets:
        lb[R + Bn + idx[t]] = theta
    integ = np.zeros(nv)
    integ[:R + Bn] = 1
    opts = {"disp": False}
    if time_limit is not None:
        opts["time_limit"] = float(time_limit)
    t0 = time.perf_counter()
    res = milp(c, constraints=cons, integrality=integ, bounds=Bounds(lb, ub), options=opts)
    dt = time.perf_counter() - t0
    status = {0: "optimal", 1: "limit", 2: "infeasible"}.get(res.status, f"error{res.status}")
    if res.x is None:
        return JointSolution(status, seconds=dt)
    rules = [i for i in range(R) if res.x[i] > 0.5]
    blocked = [blk[k] for k in range(Bn) if res.x[R + k] > 0.5]
    return JointSolution(status, rules, blocked, inst.rule_cost(rules),
                         float(sum(block_cost[e] for e in blocked)), dt)


# ---------------------------------------------------------------- verification
def residual(inst: Instance, blocked: Sequence[int]) -> Instance:
    """The instance with blocked edges removed (independent of the MILP)."""
    gone = set(blocked)
    return Instance(list(inst.nodes), [e for i, e in enumerate(inst.edges) if i not in gone],
                    list(inst.rules), inst.source, set(inst.targets), dict(inst.meta))


def joint_achieved_delta(inst: Instance, rules: Sequence[int], blocked: Sequence[int]) -> float:
    """Worst-path evasion probability after removing blocked edges (0 = no path)."""
    return worst_path(residual(inst, blocked), rules)[0]


def joint_meets(inst: Instance, sol: JointSolution, delta: float, rtol: float = 1e-6) -> bool:
    return joint_achieved_delta(inst, sol.rules, sol.blocked) <= delta * (1 + rtol)


# ---------------------------------------------------------------- frontier
def pareto(inst: Instance, delta: float, block_cost: Dict[int, float],
           budgets: Sequence[float], time_limit: Optional[float] = None
           ) -> List[Tuple[float, JointSolution]]:
    """Minimum alert cost for each hardening budget H (alert <-> hardening frontier)."""
    return [(H, solve_joint(inst, delta, block_cost, budget=H, time_limit=time_limit))
            for H in budgets]
