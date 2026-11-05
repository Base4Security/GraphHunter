import itertools
import math
from dataclasses import replace

import pytest

from graphhunter_defensa.cobertura import Edge, Instance, Rule, solve_milp
from graphhunter_defensa.cobertura.generator import GenParams, generate
from graphhunter_defensa.cobertura.prob import (achieved_delta, assign_tpr, best_possible_delta,
                           greedy_weakest_path, meets, monte_carlo_evasion,
                           solve_prob_lp, solve_prob_milp, worst_path)
from .test_core import random_instance


def with_tpr(inst, q):
    return Instance(inst.nodes, inst.edges, [replace(r, tpr=q) for r in inst.rules],
                    inst.source, set(inst.targets))


def test_defense_in_depth_single_edge():
    e = [Edge("s", "t", "t1", "x")]
    rules = [Rule("a", frozenset({"t1"}), frozenset({"x"}), 1.0, tpr=0.5),
             Rule("b", frozenset({"t1"}), frozenset({"x"}), 1.0, tpr=0.5)]
    inst = Instance(["s", "t"], e, rules, "s", {"t"})
    assert solve_prob_milp(inst, 0.5).cost == pytest.approx(1.0)
    assert solve_prob_milp(inst, 0.3).cost == pytest.approx(2.0)   # 0.25 <= 0.3
    assert solve_prob_milp(inst, 0.2).status == "infeasible"       # best is 0.25
    assert best_possible_delta(inst) == pytest.approx(0.25)


def test_path_accumulates_across_edges():
    # two edges in series, each seen by a q=0.5 rule: evasion 0.25 with both
    e = [Edge("s", "a", "t1", "x"), Edge("a", "t", "t2", "x")]
    rules = [Rule("r1", frozenset({"t1"}), frozenset({"x"}), 1.0, tpr=0.5),
             Rule("r2", frozenset({"t2"}), frozenset({"x"}), 3.0, tpr=0.5)]
    inst = Instance(["s", "a", "t"], e, rules, "s", {"t"})
    assert solve_prob_milp(inst, 0.5).cost == pytest.approx(1.0)
    assert solve_prob_milp(inst, 0.25).cost == pytest.approx(4.0)


@pytest.mark.parametrize("seed", range(30))
def test_reduces_to_deterministic(seed):
    q = 0.9
    inst = with_tpr(random_instance(seed), q)
    det = solve_milp(inst)
    pr = solve_prob_milp(inst, 1 - q)
    assert det.status == pr.status
    if det.status == "optimal":
        assert pr.cost == pytest.approx(det.cost, abs=1e-6)


@pytest.mark.parametrize("seed", range(30))
@pytest.mark.parametrize("delta", [0.5, 0.2, 0.05])
def test_prob_milp_matches_brute_force(seed, delta):
    base = random_instance(seed)
    inst = assign_tpr(base, seed)
    best = None
    for k in range(len(inst.rules) + 1):
        for sub in itertools.combinations(range(len(inst.rules)), k):
            if meets(inst, sub, delta):
                c = inst.rule_cost(sub)
                if best is None or c < best - 1e-9:
                    best = c
    sol = solve_prob_milp(inst, delta)
    if best is None:
        assert sol.status == "infeasible"
        assert best_possible_delta(inst) > delta
        return
    assert sol.status == "optimal"
    assert sol.cost == pytest.approx(best, abs=1e-6)
    assert meets(inst, sol.rules, delta)
    assert solve_prob_lp(inst, delta).cost <= sol.cost + 1e-6
    g = greedy_weakest_path(inst, delta)
    assert meets(inst, g, delta) and inst.rule_cost(g) >= sol.cost - 1e-6


@pytest.mark.parametrize("seed", range(3))
def test_generated_monte_carlo_and_monotone(seed):
    inst = assign_tpr(generate(GenParams(seed=seed)), seed)
    floor = best_possible_delta(inst)
    deltas = [d for d in (0.5, 0.2, 0.1, 0.05) if d > floor]
    costs = []
    for d in deltas:
        sol = solve_prob_milp(inst, d)
        assert sol.status == "optimal" and meets(inst, sol.rules, d)
        p, path = worst_path(inst, sol.rules)
        mc = monte_carlo_evasion(inst, sol.rules, path, n=40000, seed=seed)
        sigma = math.sqrt(max(p * (1 - p), 1e-12) / 40000)
        assert abs(mc - p) < 4 * sigma + 1e-3
        costs.append(sol.cost)
    assert all(a >= b - 1e-6 for a, b in zip(costs[1:], costs))  # stricter delta costs more
