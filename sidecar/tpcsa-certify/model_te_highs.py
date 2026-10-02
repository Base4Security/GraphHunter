"""Time-expanded MILP for TPCSA, solved with HiGHS directly (highspy).

The compact big-M formulation is numerically unreliable (the paper shows two
solvers returning "optimal" solutions that violate their own rows); this
one is linear in the number of events and big-M free:

* every node ``u`` gets an *arrival* copy ``(u, lo_a)`` per incoming arc and a
  *departure* copy ``(u, hi_b - eps)`` per outgoing arc, chained in time by
  zero-cost wait arcs (arrival before departure on ties);
* a real arc ``a = (u, v)`` becomes ``(u, hi_a - eps) -> (v, lo_a)``;
* binaries ``z_a`` (real arc), ``q_w`` (wait arc), ``s_c`` (copy),
  ``r_v`` (root arc from the super-root into ``v``'s earliest copy);
* (6) one selected incoming expanded arc per selected copy;
* (7) arcs only leave selected copies;
* (8) at most one real arc into each original node, none into a root;
* at most ``k`` roots, and terminals are never roots (same feasible set as
  the greedy).

Objective (paper convention): ``sum c_a z_a + sum rho_v r_v +
sum_{v in T} p_v (1 - y_v)`` where ``y_v`` is the real in-degree of ``v``.

This mirrors ``graph_hunter_tpcsa::expand`` exactly so the greedy forest is
a valid warm start.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any

import highspy

NONE = -1


@dataclass
class Instance:
    epsilon: int
    nodes: list[dict[str, Any]]
    arcs: list[dict[str, Any]]

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Instance":
        return Instance(int(d["epsilon"]), list(d["nodes"]), list(d["arcs"]))

    def index(self) -> dict[str, int]:
        return {n["id"]: i for i, n in enumerate(self.nodes)}


@dataclass
class TeGraph:
    copies: list[tuple[int, int, bool]] = field(default_factory=list)  # (node, time, arrival)
    node_copies: list[list[int]] = field(default_factory=list)
    wait_arcs: list[tuple[int, int]] = field(default_factory=list)  # (from, to)
    real_arcs: list[tuple[int, int, int]] = field(default_factory=list)  # (from, to, orig arc idx)


def expand(inst: Instance) -> TeGraph:
    idx = inst.index()
    key: dict[tuple[int, int, bool], int] = {}
    te = TeGraph()

    def intern(node: int, t: int, arrival: bool) -> int:
        k = (node, t, arrival)
        if k not in key:
            key[k] = len(te.copies)
            te.copies.append(k)
        return key[k]

    ends = []
    for ai, a in enumerate(inst.arcs):
        dep = intern(idx[a["tail"]], int(a["hi"]) - inst.epsilon, False)
        arr = intern(idx[a["head"]], int(a["lo"]), True)
        ends.append((dep, arr, ai))
    te.node_copies = [[] for _ in inst.nodes]
    for ci, (node, _, _) in enumerate(te.copies):
        te.node_copies[node].append(ci)
    for lst in te.node_copies:
        lst.sort(key=lambda c: (te.copies[c][1], not te.copies[c][2]))
        for a, b in zip(lst, lst[1:]):
            te.wait_arcs.append((a, b))
    te.real_arcs = ends
    return te


@dataclass
class Result:
    status: str
    objective: float | None = None
    dual_bound: float | None = None
    gap: float | None = None
    solve_seconds: float | None = None
    arcs: list[dict[str, Any]] = field(default_factory=list)
    roots: list[str] = field(default_factory=list)
    message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = {"status": self.status, "arcs": self.arcs, "roots": self.roots}
        for k in ("objective", "dual_bound", "gap", "solve_seconds", "message"):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        return d


def _status_name(h: highspy.Highs) -> str:
    return h.modelStatusToString(h.getModelStatus())


def verify_solution(inst: Instance, roots: list[str], arcs: list[int], k: int) -> str | None:
    """Independent re-check: in-degree, root rules, time-respect, k."""
    idx = inst.index()
    indeg: dict[str, int] = {}
    children: dict[str, list[int]] = {}
    for ai in arcs:
        a = inst.arcs[ai]
        indeg[a["head"]] = indeg.get(a["head"], 0) + 1
        children.setdefault(a["tail"], []).append(ai)
    for v, c in indeg.items():
        if c > 1:
            return f"in-degree {c} at {v}"
    if len(roots) > k:
        return f"{len(roots)} roots > k={k}"
    for r in roots:
        n = inst.nodes[idx[r]]
        if n.get("root_cost") is None:
            return f"root {r} is not a candidate"
        if float(n.get("prize", 0.0)) > 0:
            return f"root {r} is a terminal"
        if r in indeg:
            return f"root {r} has an incoming arc"
    # Every arc must hang off a root through selected arcs; schedule earliest-feasible times.
    seen_arcs: set[int] = set()
    for r in roots:
        stack: list[tuple[str, int | None]] = [(r, None)]
        while stack:
            u, at = stack.pop()
            for ai in children.get(u, []):
                a = inst.arcs[ai]
                theta = int(a["lo"]) if at is None else max(int(a["lo"]), at + inst.epsilon)
                if theta > int(a["hi"]):
                    return f"time violation on {a['tail']}->{a['head']}: need {theta} > hi {a['hi']}"
                seen_arcs.add(ai)
                stack.append((a["head"], theta))
    if seen_arcs != set(arcs):
        return "selected arcs not all reachable from the roots"
    return None


def objective_of(inst: Instance, roots: list[str], arcs: list[int]) -> float:
    idx = inst.index()
    total = sum(float(n.get("prize", 0.0)) for n in inst.nodes)
    collected = sum(float(inst.nodes[idx[inst.arcs[ai]["head"]]].get("prize", 0.0)) for ai in arcs)
    cost = sum(float(inst.arcs[ai]["cost"]) for ai in arcs)
    rho = sum(float(inst.nodes[idx[r]]["root_cost"]) for r in roots)
    return cost + rho + (total - collected)


def solve_te_highs(
    inst: Instance,
    k: int = 2,
    time_limit: float = 120.0,
    gap: float = 0.005,
    warm_start: dict[str, Any] | None = None,
    threads: int = 0,
    log: bool = False,
) -> Result:
    t0 = time.time()
    idx = inst.index()
    n = len(inst.nodes)
    if not inst.arcs:
        # Nothing to select: the empty forest is optimal and pays every prize.
        return Result(status="Optimal", objective=objective_of(inst, [], []), dual_bound=objective_of(inst, [], []), gap=0.0, solve_seconds=time.time() - t0)
    te = expand(inst)
    n_copies = len(te.copies)
    n_wait = len(te.wait_arcs)
    n_real = len(te.real_arcs)

    prize = [float(x.get("prize", 0.0)) for x in inst.nodes]
    root_cost = [x.get("root_cost") for x in inst.nodes]
    root_ok = [root_cost[v] is not None and prize[v] <= 0 and len(te.node_copies[v]) > 0 for v in range(n)]

    # Column layout: z (real) | q (wait) | s (copy) | r (root per node)
    off_z, off_q, off_s, off_r = 0, n_real, n_real + n_wait, n_real + n_wait + n_copies
    n_cols = off_r + n

    h = highspy.Highs()
    h.setOptionValue("output_flag", log)
    h.setOptionValue("time_limit", float(time_limit))
    h.setOptionValue("mip_rel_gap", float(gap))
    if threads:
        h.setOptionValue("threads", int(threads))

    inf = highspy.kHighsInf
    lower = [0.0] * n_cols
    upper = [1.0] * n_cols
    cost = [0.0] * n_cols
    for j, (_, _, ai) in enumerate(te.real_arcs):
        cost[off_z + j] = float(inst.arcs[ai]["cost"])
    for v in range(n):
        rc = root_cost[v]
        if root_ok[v] and rc is not None:
            cost[off_r + v] = float(rc)
        else:
            upper[off_r + v] = 0.0
    # Prize term: sum_v p_v (1 - y_v) = const - sum_a p_head(a) z_a
    const = sum(prize)
    for j, (_, _, ai) in enumerate(te.real_arcs):
        cost[off_z + j] -= prize[idx[inst.arcs[ai]["head"]]]
    h.addVars(n_cols, lower, upper)
    h.changeColsCost(n_cols, list(range(n_cols)), cost)
    h.changeColsIntegrality(n_cols, list(range(n_cols)), [highspy.HighsVarType.kInteger] * n_cols)

    # Incoming expanded arcs per copy.
    in_real: list[list[int]] = [[] for _ in range(n_copies)]
    in_wait: list[list[int]] = [[] for _ in range(n_copies)]
    for j, (_, to, _) in enumerate(te.real_arcs):
        in_real[to].append(j)
    for j, (_, to) in enumerate(te.wait_arcs):
        in_wait[to].append(j)
    entry = [lst[0] if lst else NONE for lst in te.node_copies]

    def add_row(coefs: dict[int, float], lo: float, hi: float) -> None:
        cols = list(coefs.keys())
        h.addRow(lo, hi, len(cols), cols, [coefs[c] for c in cols])

    # (6): sum in z + sum in q + r (entry copy) - s_c = 0
    for c in range(n_copies):
        coefs: dict[int, float] = {off_s + c: -1.0}
        for j in in_real[c]:
            coefs[off_z + j] = coefs.get(off_z + j, 0.0) + 1.0
        for j in in_wait[c]:
            coefs[off_q + j] = coefs.get(off_q + j, 0.0) + 1.0
        v = te.copies[c][0]
        if entry[v] == c and root_ok[v]:
            coefs[off_r + v] = 1.0
        add_row(coefs, 0.0, 0.0)
    # (7): z_a <= s_dep(a), q_w <= s_from(w)
    for j, (frm, _, _) in enumerate(te.real_arcs):
        add_row({off_z + j: 1.0, off_s + frm: -1.0}, -inf, 0.0)
    for j, (frm, _) in enumerate(te.wait_arcs):
        add_row({off_q + j: 1.0, off_s + frm: -1.0}, -inf, 0.0)
    # (8): sum_{a into v} z_a + r_v <= 1
    into_node: list[list[int]] = [[] for _ in range(n)]
    for j, (_, _, ai) in enumerate(te.real_arcs):
        into_node[idx[inst.arcs[ai]["head"]]].append(j)
    for v in range(n):
        coefs = {off_z + j: 1.0 for j in into_node[v]}
        coefs[off_r + v] = coefs.get(off_r + v, 0.0) + 1.0
        add_row(coefs, -inf, 1.0)
    # at most k roots
    add_row({off_r + v: 1.0 for v in range(n)}, -inf, float(k))

    # Warm start from the greedy forest.
    if warm_start:
        sol = [0.0] * n_cols
        chosen_real: set[int] = set()
        arc_lookup: dict[tuple[str, str, str], list[int]] = {}
        for ai, a in enumerate(inst.arcs):
            arc_lookup.setdefault((a["tail"], a["head"], a["etype"]), []).append(ai)
        for wa in warm_start.get("arcs", []):
            cands = arc_lookup.get((wa["tail"], wa["head"], wa.get("etype", "")), [])
            best = None
            for ai in cands:
                a = inst.arcs[ai]
                if int(a["lo"]) <= int(wa.get("t", a["lo"])) <= int(a["hi"]):
                    best = ai
                    break
            if best is None and cands:
                best = cands[0]
            if best is not None:
                chosen_real.add(best)
        real_by_orig = {ai: j for j, (_, _, ai) in enumerate(te.real_arcs)}
        selected_copies: set[int] = set()
        for ai in chosen_real:
            j = real_by_orig[ai]
            sol[off_z + j] = 1.0
            selected_copies.add(te.real_arcs[j][1])
            selected_copies.add(te.real_arcs[j][0])
        for r in warm_start.get("roots", []):
            if r in idx and root_ok[idx[r]]:
                sol[off_r + idx[r]] = 1.0
                selected_copies.add(entry[idx[r]])
        # Wait arcs: everything between the first and last selected copy of a node.
        wait_index = {w: j for j, w in enumerate(te.wait_arcs)}
        for v in range(n):
            lst = te.node_copies[v]
            sel = [i for i, c in enumerate(lst) if c in selected_copies]
            if len(sel) >= 2:
                for i in range(sel[0], sel[-1]):
                    sol[off_q + wait_index[(lst[i], lst[i + 1])]] = 1.0
                    selected_copies.add(lst[i + 1])
        for c in selected_copies:
            if c != NONE:
                sol[off_s + c] = 1.0
        hs = highspy.HighsSolution()
        hs.col_value = sol
        hs.value_valid = True
        h.setSolution(hs)

    h.run()
    status = _status_name(h)
    info = h.getInfo()
    elapsed = time.time() - t0
    res = Result(status=status, solve_seconds=elapsed)
    if status in ("Optimal", "Time limit reached", "Interrupt", "Iteration limit reached"):
        sol = h.getSolution().col_value
        sel_real = [te.real_arcs[j][2] for j in range(n_real) if sol[off_z + j] > 0.5]
        roots = [inst.nodes[v]["id"] for v in range(n) if sol[off_r + v] > 0.5]
        reported = float(info.objective_function_value) + const
        recomputed = objective_of(inst, roots, sel_real)
        problem = verify_solution(inst, roots, sel_real, k)
        if problem is None and abs(reported - recomputed) > 1e-6 * max(1.0, abs(recomputed)):
            problem = f"objective mismatch: solver {reported:.6f} vs recomputed {recomputed:.6f}"
        if problem is not None:
            res.status = "InvalidNumerics"
            res.message = problem
            return res
        res.objective = recomputed
        res.dual_bound = float(info.mip_dual_bound) + const if math.isfinite(info.mip_dual_bound) else None
        res.gap = float(info.mip_gap) if math.isfinite(info.mip_gap) else None
        res.arcs = [
            {"tail": inst.arcs[ai]["tail"], "head": inst.arcs[ai]["head"], "etype": inst.arcs[ai]["etype"], "lo": inst.arcs[ai]["lo"], "hi": inst.arcs[ai]["hi"]}
            for ai in sel_real
        ]
        res.roots = roots
        res.status = "Optimal" if status == "Optimal" else "TimeLimit"
    elif status == "Infeasible":
        res.status = "Infeasible"
    else:
        res.status = "Error"
        res.message = f"HiGHS status: {status}"
    return res
