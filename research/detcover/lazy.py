"""Lazy path generation for the probabilistic and joint models.

Path formulation (no node potentials): for every s->T path P,

    sum_r w_r * n_r(P) * x_r + theta * sum_{e in P, e blockable} b_e >= theta

where n_r(P) = number of edges of P covered by rule r. It has exponentially many
rows, so we generate them: solve the master on the paths found so far, then run
Dijkstra on the current weights w_e(x, b) = sum_{r covers e} w_r x_r + theta b_e
and add every s->T path shorter than theta. The master is a relaxation of the
full problem, so the first master solution with no violated path is optimal for
the full problem, and an infeasible master proves infeasibility.

Blocking variables exist only for blockable edges that appear in some generated
path; the others are never useful (they enter no row). That is what keeps memory
bounded on graphs with tens of thousands of blockable edges.

Separation uses scipy.sparse.csgraph.dijkstra from the source and from each of
its out-neighbours (the sampled entries), so one round can add up to one path
per entry.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np
from scipy.optimize import Bounds, LinearConstraint, milp
from scipy.sparse import coo_matrix, csr_matrix
from scipy.sparse.csgraph import dijkstra

from .model import Instance
from .prob import rule_weight, theta_of

TOL = 1e-7
EPS_W = 1e-12  # csgraph needs strictly positive stored weights


@dataclass
class LazySolution:
    status: str
    rules: List[int] = field(default_factory=list)
    blocked: List[int] = field(default_factory=list)
    alert_cost: float = float("nan")
    harden_cost: float = float("nan")
    iterations: int = 0
    n_paths: int = 0
    seconds: float = 0.0


class _Separator:
    def __init__(self, inst: Instance, theta: float):
        self.inst = inst
        self.theta = theta
        self.idx = {n: i for i, n in enumerate(inst.nodes)}
        self.U = np.array([self.idx[e.u] for e in inst.edges])
        self.V = np.array([self.idx[e.v] for e in inst.edges])
        self.n = len(inst.nodes)
        src = self.idx[inst.source]
        outs = sorted({int(v) for u, v in zip(self.U, self.V) if u == src and v != src})
        self.sources = [src] + outs[:200]
        self.targets = np.array(sorted(self.idx[t] for t in inst.targets))
        # rule -> covered edges, edge -> rules (as arrays) for fast weights
        self.cov = inst.coverage

    def weights(self, rule_w: np.ndarray, block_w: Dict[int, float]) -> np.ndarray:
        we = np.array([sum(rule_w[r] for r in rs) for rs in self.cov], dtype=float)
        for ei, x in block_w.items():
            we[ei] += x
        return we

    def violated(self, we: np.ndarray) -> List[List[int]]:
        """Distinct s->T edge paths with total weight < theta."""
        keep = self.U != self.V
        U, V, W, I = self.U[keep], self.V[keep], we[keep], np.nonzero(keep)[0]
        # parallel edges: keep the lightest per (u, v)
        order = np.lexsort((W, V, U))
        U, V, W, I = U[order], V[order], W[order], I[order]
        first = np.ones(len(U), dtype=bool)
        first[1:] = (U[1:] != U[:-1]) | (V[1:] != V[:-1])
        U, V, W, I = U[first], V[first], W[first], I[first]
        best_edge = {(int(u), int(v)): int(i) for u, v, i in zip(U, V, I)}
        G = csr_matrix((W + EPS_W, (U, V)), shape=(self.n, self.n))
        dist, pred = dijkstra(G, directed=True, indices=self.sources, return_predecessors=True)
        paths, seen = [], set()
        src = self.sources[0]
        wmap = {(int(u), int(v)): float(x) for u, v, x in zip(U, V, W)}
        for k, s in enumerate(self.sources):
            dt = dist[k, self.targets]
            if s != src:  # the full path also pays the source -> entry edge
                dt = dt + wmap.get((src, s), np.inf)
            j = int(np.argmin(dt))
            if not np.isfinite(dt[j]) or dt[j] >= self.theta - TOL:
                continue
            t = int(self.targets[j])
            nodes = [t]
            while nodes[-1] != s:
                p = pred[k, nodes[-1]]
                if p < 0:
                    break
                nodes.append(int(p))
            nodes.reverse()
            ep = [best_edge[(a, b)] for a, b in zip(nodes[:-1], nodes[1:])]
            if s != src:  # prepend the source -> entry edge (weight on it counts too)
                pre = best_edge.get((src, s))
                if pre is not None:
                    ep = [pre] + ep
            key = tuple(ep)
            if key not in seen:
                seen.add(key)
                paths.append(ep)
        return paths


def solve_lazy(inst: Instance, delta: float, block_cost: Optional[Dict[int, float]] = None,
               budget: Optional[float] = None, lam: float = 0.0, allow_rules: bool = True,
               time_limit: Optional[float] = None, max_iter: int = 1000) -> LazySolution:
    """Same optimum as joint.solve_joint (or prob.solve_prob_milp when block_cost is
    empty), computed by row generation."""
    t0 = time.perf_counter()
    theta = theta_of(delta)
    block_cost = dict(block_cost or {})
    R = len(inst.rules)
    w = np.array([rule_weight(r) for r in inst.rules])
    sep = _Separator(inst, theta)
    rows: List[Dict[int, float]] = []  # path rows: col -> coef (cols: rules, then b)
    bcols: List[int] = []              # edge index of each blocking column
    bpos: Dict[int, int] = {}
    x = np.zeros(R)
    blocked: List[int] = []
    it = 0
    while True:
        rule_w = w * (x > 0.5)
        we = sep.weights(rule_w, {e: theta for e in blocked})
        new = sep.violated(we)
        if not new:
            rules = [i for i in range(R) if x[i] > 0.5]
            return LazySolution("optimal", rules, blocked, inst.rule_cost(rules),
                                float(sum(block_cost[e] for e in blocked)), it, len(rows),
                                time.perf_counter() - t0)
        if it >= max_iter:
            return LazySolution("limit", iterations=it, n_paths=len(rows),
                                seconds=time.perf_counter() - t0)
        for p in new:
            row: Dict[int, float] = {}
            for ei in p:
                for r in inst.coverage[ei]:
                    row[r] = row.get(r, 0.0) + w[r]
                if ei in block_cost:
                    if ei not in bpos:
                        bpos[ei] = len(bcols)
                        bcols.append(ei)
                    c = R + bpos[ei]
                    row[c] = row.get(c, 0.0) + theta
            rows.append(row)
        it += 1
        nv = R + len(bcols)
        ri, ci, vi = [], [], []
        for k, row in enumerate(rows):
            for c, v in row.items():
                ri.append(k); ci.append(c); vi.append(v)
        A = coo_matrix((vi, (ri, ci)), shape=(len(rows), nv)).tocsr()
        cons = [LinearConstraint(A, theta * (1 - 1e-9), np.inf)]
        h = np.array([block_cost[e] for e in bcols], dtype=float)
        if budget is not None and bcols:
            brow = np.zeros(nv); brow[R:] = h
            cons.append(LinearConstraint(brow.reshape(1, -1), -np.inf, float(budget)))
        cvec = np.zeros(nv)
        if allow_rules:
            cvec[:R] = [r.cost for r in inst.rules]
            cvec[R:] = lam * h
        else:
            cvec[R:] = h
        ub = np.ones(nv)
        if not allow_rules:
            ub[:R] = 0.0
        opts = {"disp": False}
        if time_limit is not None:
            left = time_limit - (time.perf_counter() - t0)
            if left <= 0:
                return LazySolution("limit", iterations=it, n_paths=len(rows),
                                    seconds=time.perf_counter() - t0)
            opts["time_limit"] = left
        res = milp(cvec, constraints=cons, integrality=np.ones(nv),
                   bounds=Bounds(np.zeros(nv), ub), options=opts)
        if res.status == 2:
            return LazySolution("infeasible", iterations=it, n_paths=len(rows),
                                seconds=time.perf_counter() - t0)
        if res.x is None or res.status != 0:
            return LazySolution("limit", iterations=it, n_paths=len(rows),
                                seconds=time.perf_counter() - t0)
        x = res.x[:R]
        blocked = [bcols[k] for k in range(len(bcols)) if res.x[R + k] > 0.5]
