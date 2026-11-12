"""Tests for the certification sidecar (run: python -m pytest sidecar/tpcsa-certify)."""

from __future__ import annotations

import itertools

from model_te_highs import Instance, objective_of, solve_te_highs, verify_solution
from server import certify


def node(id_, kind="process", prize=0.0, root_cost=None, tactic=None):
    n = {"id": id_, "kind": kind, "prize": prize}
    if root_cost is not None:
        n["root_cost"] = root_cost
    if tactic:
        n["tactic"] = tactic
    return n


def arc(tail, head, etype, t, cost=1.0):
    return {"tail": tail, "head": head, "etype": etype, "lo": t, "hi": t, "cost": cost}


def base() -> dict:
    """ip -(10)-> p0 -(20)-> p1 -(30)-> p2 ; p0 -(25)-> p3 ; p3 -(5)-> p2 (too early)."""
    return {
        "epsilon": 1,
        "nodes": [
            node("ip", "ip", root_cost=2.0),
            node("p0", root_cost=6.0),
            node("p1", prize=8.0, root_cost=6.0),
            node("p2", prize=8.0, root_cost=6.0),
            node("p3", prize=8.0, root_cost=6.0),
        ],
        "arcs": [
            arc("ip", "p0", "recv", 10),
            arc("p0", "p1", "start", 20),
            arc("p1", "p2", "start", 30),
            arc("p0", "p3", "start", 25),
            arc("p3", "p2", "start", 5, cost=0.1),
        ],
    }


def brute_optimum(inst: Instance, k: int) -> float:
    best = objective_of(inst, [], [])
    m = len(inst.arcs)
    idx = inst.index()
    for r in range(1, m + 1):
        for chosen in itertools.combinations(range(m), r):
            heads = {inst.arcs[a]["head"] for a in chosen}
            tails = {inst.arcs[a]["tail"] for a in chosen}
            roots = sorted(tails - heads)
            if not roots or len(roots) > k:
                continue
            if verify_solution(inst, roots, list(chosen), k) is not None:
                continue
            if any(float(inst.nodes[idx[x]].get("prize", 0)) > 0 for x in roots):
                continue
            best = min(best, objective_of(inst, roots, list(chosen)))
    return best


def test_optimal_certificate_matches_brute_force():
    inst = Instance.from_dict(base())
    res = solve_te_highs(inst, k=1, time_limit=30)
    assert res.status == "Optimal", res
    assert abs(res.objective - brute_optimum(inst, 1)) < 1e-6
    assert res.roots == ["ip"]
    # The t=5 arc into p2 cannot follow arrival at p3 (t=25): p2 comes via p1.
    used = {(a["tail"], a["head"]) for a in res.arcs}
    assert ("p1", "p2") in used and ("p3", "p2") not in used
    assert res.gap is not None and res.gap <= 0.005 + 1e-9


def test_warm_start_is_accepted_and_result_unchanged():
    inst = Instance.from_dict(base())
    warm = {"roots": ["ip"], "arcs": [
        {"tail": "ip", "head": "p0", "etype": "recv", "t": 10},
        {"tail": "p0", "head": "p1", "etype": "start", "t": 20},
        {"tail": "p1", "head": "p2", "etype": "start", "t": 30},
        {"tail": "p0", "head": "p3", "etype": "start", "t": 25},
    ]}
    res = solve_te_highs(inst, k=1, time_limit=30, warm_start=warm)
    assert res.status == "Optimal"
    assert abs(res.objective - brute_optimum(inst, 1)) < 1e-6


def test_forest_with_k2_recovers_second_chain():
    d = base()
    d["nodes"] += [node("ip2", "ip", root_cost=2.0), node("q0", root_cost=6.0), node("q1", prize=8.0, root_cost=6.0)]
    d["arcs"] += [arc("ip2", "q0", "recv", 100), arc("q0", "q1", "start", 110)]
    inst = Instance.from_dict(d)
    one = solve_te_highs(inst, k=1, time_limit=30)
    two = solve_te_highs(inst, k=2, time_limit=30)
    assert one.status == two.status == "Optimal"
    assert two.objective < one.objective
    assert sorted(two.roots) == ["ip", "ip2"]
    assert abs(two.objective - brute_optimum(inst, 2)) < 1e-6


def test_terminals_are_never_roots_and_empty_is_allowed():
    d = base()
    for n in d["nodes"]:
        if n["prize"] == 0.0:
            n.pop("root_cost", None)
    inst = Instance.from_dict(d)
    res = solve_te_highs(inst, k=2, time_limit=30)
    assert res.status == "Optimal"
    assert res.roots == [] and res.arcs == []
    assert abs(res.objective - 24.0) < 1e-6


def test_too_large_guard_and_error_paths():
    out = certify({"instance": base(), "k": 1}, max_arcs=3)
    assert out["status"] == "TooLarge"
    ok = certify({"instance": base(), "k": 1, "time_limit": 30}, max_arcs=100)
    assert ok["status"] == "Optimal"
    assert "objective" in ok and "dual_bound" in ok
