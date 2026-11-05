import itertools
import math
import random

import pytest

from detcover import Edge, Instance, Rule
from detcover.correlation import (conservative_rule_weights, predicted_evasion_independent,
                                  scaled, solve_conservative, true_evasion_common_cause)
from detcover.prob import assign_tpr, solve_prob_milp
from test_core import random_instance


def _cons_worst(inst, rules):
    w = conservative_rule_weights(inst, rules)
    import heapq
    adj = {n: [] for n in inst.nodes}
    for ei, e in enumerate(inst.edges):
        adj[e.u].append((e.v, w[ei]))
    dist = {inst.source: 0.0}
    pq = [(0.0, inst.source)]
    while pq:
        d, n = heapq.heappop(pq)
        if d > dist.get(n, math.inf):
            continue
        for m, x in adj[n]:
            if d + x < dist.get(m, math.inf) - 1e-12:
                dist[m] = d + x
                heapq.heappush(pq, (d + x, m))
    ds = [dist[t] for t in inst.targets if t in dist]
    return math.exp(-min(ds)) if ds else 0.0


@pytest.mark.parametrize("seed", range(30))
@pytest.mark.parametrize("delta", [0.5, 0.2])
def test_conservative_matches_brute_force(seed, delta):
    inst = assign_tpr(random_instance(seed, n=6, m=10, k=6), seed)
    sol = solve_conservative(inst, delta)
    best = None
    for j in range(len(inst.rules) + 1):
        for rs in itertools.combinations(range(len(inst.rules)), j):
            if _cons_worst(inst, rs) <= delta * (1 + 1e-9):
                c = inst.rule_cost(rs)
                if best is None or c < best - 1e-9:
                    best = c
    if best is None:
        assert sol.status == "infeasible"
    else:
        assert sol.status == "optimal" and math.isclose(sol.cost, best, rel_tol=1e-6, abs_tol=1e-6)
        assert _cons_worst(inst, sol.rules) <= delta * (1 + 1e-6)


@pytest.mark.parametrize("seed", range(20))
def test_conservative_costs_at_least_independent(seed):
    inst = assign_tpr(random_instance(seed), seed)
    a, b = solve_conservative(inst, 0.2), solve_prob_milp(inst, 0.2)
    if a.status == "optimal":
        assert b.status == "optimal" and b.cost <= a.cost + 1e-6


def test_common_cause_single_edge_two_rules():
    nodes = ["s", "t"]
    edges = [Edge("s", "t", "T1", "x")]
    rules = [Rule("r1", frozenset({"T1"}), frozenset({"x"}), 1, tpr=0.5),
             Rule("r2", frozenset({"T1"}), frozenset({"x"}), 1, tpr=0.4)]
    inst = Instance(nodes, edges, rules, "s", {"t"})
    a = 0.9
    true = true_evasion_common_cause(inst, [0, 1], [0], a)
    pred = predicted_evasion_independent(inst, [0, 1], [0], a)
    assert math.isclose(true, (1 - a) + a * 0.5 * 0.6)
    assert math.isclose(true - pred, a * (1 - a) * 0.5 * 0.4)


def test_common_cause_matches_monte_carlo():
    nodes = ["s", "u", "v", "t"]
    edges = [Edge("s", "u", "T1", "x"), Edge("u", "v", "T2", "x"), Edge("v", "t", "T1", "y")]
    rules = [Rule("r1", frozenset({"T1"}), frozenset({"x", "y"}), 1, tpr=0.6),
             Rule("r2", frozenset({"T2"}), frozenset({"x"}), 1, tpr=0.5)]
    inst = Instance(nodes, edges, rules, "s", {"t"})
    a, rng, n, ev = 0.8, random.Random(3), 200000, 0
    for _ in range(n):
        up = {"x": rng.random() < a, "y": rng.random() < a}
        fired = False
        for ei, e in enumerate(edges):
            if up[e.scope]:
                for r in inst.coverage[ei]:
                    if rng.random() < rules[r].tpr:
                        fired = True
        ev += not fired
    exact = true_evasion_common_cause(inst, [0, 1], [0, 1, 2], a)
    assert abs(ev / n - exact) < 4 * math.sqrt(exact * (1 - exact) / n)


def test_scaled_rates():
    inst = assign_tpr(random_instance(1), 1)
    s = scaled(inst, 0.5)
    assert all(math.isclose(x.tpr, max(1e-6, 0.5 * y.tpr)) for x, y in zip(s.rules, inst.rules))
