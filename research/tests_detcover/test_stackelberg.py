import itertools
import math

import numpy as np
import pytest

from detcover import Edge, Instance, Rule
from detcover.generator import GenParams, generate
from detcover.prob import assign_tpr, best_possible_delta, solve_prob_lp, solve_prob_milp
from detcover.stackelberg import (achieved_delta_z, meets_z, monte_carlo_z,
                                  rule_weights_z, solve_mixed)
from detcover.prob import worst_path
from test_core import random_instance


def test_partial_triage_beats_pure_single_edge():
    # one edge, one rule q=0.9 cost 10, need evasion <= 0.5
    inst = Instance(["s", "t"], [Edge("s", "t", "t1", "x")],
                    [Rule("r", frozenset({"t1"}), frozenset({"x"}), 10.0, tpr=0.9)], "s", {"t"})
    assert solve_mixed(inst, 0.5, 1).cost == pytest.approx(10.0)
    # continuous optimum: 1 - 0.9 z <= 0.5 -> z = 5/9; grid K=10 -> z = 0.6
    s10 = solve_mixed(inst, 0.5, 10)
    assert s10.z[0] == pytest.approx(0.6) and s10.cost == pytest.approx(6.0)
    assert solve_prob_lp(inst, 0.5).cost <= s10.cost + 1e-9


@pytest.mark.parametrize("seed", range(20))
@pytest.mark.parametrize("delta", [0.5, 0.2])
def test_K1_equals_pure(seed, delta):
    inst = assign_tpr(random_instance(seed), seed)
    a, b = solve_mixed(inst, delta, 1), solve_prob_milp(inst, delta)
    assert a.status == b.status
    if a.status == "optimal":
        assert a.cost == pytest.approx(b.cost, abs=1e-6)


@pytest.mark.parametrize("seed", range(12))
@pytest.mark.parametrize("delta", [0.5, 0.3])
def test_grid_milp_matches_brute_force(seed, delta):
    K = 2
    inst = assign_tpr(random_instance(seed, n=6, m=10, k=6), seed)
    grid = [k / K for k in range(K + 1)]
    best = None
    for z in itertools.product(grid, repeat=len(inst.rules)):
        if meets_z(inst, z, delta):
            c = sum(r.cost * zi for r, zi in zip(inst.rules, z))
            if best is None or c < best - 1e-9:
                best = c
    sol = solve_mixed(inst, delta, K)
    if best is None:
        assert sol.status == "infeasible"
        return
    assert sol.status == "optimal" and sol.cost == pytest.approx(best, abs=1e-6)
    assert meets_z(inst, sol.z, delta)


@pytest.mark.parametrize("seed", range(3))
def test_bound_chain_and_monte_carlo(seed):
    inst = assign_tpr(generate(GenParams(seed=seed)), seed)
    d = 0.3
    if best_possible_delta(inst) > d:
        pytest.skip("infeasible at this delta")
    lp = solve_prob_lp(inst, d).cost
    costs = {K: solve_mixed(inst, d, K) for K in (1, 2, 4)}
    assert all(s.status == "optimal" and meets_z(inst, s.z, d) for s in costs.values())
    assert lp <= costs[4].cost + 1e-6
    assert costs[4].cost <= costs[2].cost + 1e-6 <= costs[1].cost + 2e-6
    z = costs[4].z
    p, path = worst_path(inst, [], rule_weights_z(inst, z))
    mc = monte_carlo_z(inst, z, path, n=40000, seed=seed)
    assert abs(mc - p) < 4 * math.sqrt(p * (1 - p) / 40000) + 1e-3


@pytest.mark.parametrize("seed", range(10))
@pytest.mark.parametrize("delta", [0.5, 0.3])
def test_pwl_lower_bound(seed, delta):
    from detcover.stackelberg import solve_mixed_lb
    inst = assign_tpr(random_instance(seed), seed)
    lp = solve_prob_lp(inst, delta)
    lb2, lb4 = solve_mixed_lb(inst, delta, 2), solve_mixed_lb(inst, delta, 4)
    g4 = solve_mixed(inst, delta, 4)
    if g4.status == "infeasible":
        assert lb4.status == "infeasible"
        return
    assert lp.cost <= lb2.cost + 1e-6          # PWL relaxation tighter than the chord
    assert lb2.cost <= lb4.cost + 1e-6         # finer interpolation, higher bound (2 | 4)
    assert lb4.cost <= g4.cost + 1e-6          # bound below the grid optimum


def test_pwl_single_edge_exactness():
    from detcover.stackelberg import solve_mixed_lb
    inst = Instance(["s", "t"], [Edge("s", "t", "t1", "x")],
                    [Rule("r", frozenset({"t1"}), frozenset({"x"}), 10.0, tpr=0.9)], "s", {"t"})
    # continuous optimum 50/9; PWL bound must be <= it and close for K = 50
    lb = solve_mixed_lb(inst, 0.5, 50).cost
    assert lb <= 50 / 9 + 1e-9 and lb > 50 / 9 - 0.05
