import itertools
import math

import pytest

from detcover import Edge, Instance, Rule
from detcover.generator import GenParams, generate
from detcover.joint import (default_block_costs, joint_achieved_delta, joint_meets,
                            pareto, solve_joint)
from detcover.prob import assign_tpr, solve_prob_milp
from test_core import random_instance

EPS = 1e-6


def _uniform_blocks(inst, cost=1.0):
    return {ei: cost for ei, e in enumerate(inst.edges) if e.u != inst.source}


def _brute(inst, delta, blocks, budget):
    """Exhaustive: every rule subset x every block subset within budget."""
    best = None
    bl = sorted(blocks)
    for k in range(len(bl) + 1):
        for bs in itertools.combinations(bl, k):
            h = sum(blocks[e] for e in bs)
            if h > budget + EPS:
                continue
            for j in range(len(inst.rules) + 1):
                for rs in itertools.combinations(range(len(inst.rules)), j):
                    if joint_achieved_delta(inst, rs, bs) <= delta * (1 + 1e-9):
                        c = inst.rule_cost(rs)
                        if best is None or c < best - EPS:
                            best = c
    return best


def _small(seed):
    inst = assign_tpr(random_instance(seed, n=5, m=7, k=4), seed)
    return inst


@pytest.mark.parametrize("seed", range(25))
@pytest.mark.parametrize("budget", [0.0, 1.0, 2.0])
def test_joint_matches_brute_force(seed, budget):
    inst = _small(seed)
    blocks = _uniform_blocks(inst)
    if len(blocks) > 7:
        pytest.skip("too many blockable edges for brute force")
    delta = 0.3
    sol = solve_joint(inst, delta, blocks, budget=budget)
    bf = _brute(inst, delta, blocks, budget)
    if bf is None:
        assert sol.status == "infeasible"
    else:
        assert sol.status == "optimal"
        assert math.isclose(sol.alert_cost, bf, rel_tol=1e-6, abs_tol=1e-6)
        assert sol.harden_cost <= budget + EPS
        assert joint_meets(inst, sol, delta)


@pytest.mark.parametrize("seed", range(15))
def test_no_blocking_equals_prob_model(seed):
    inst = _small(seed)
    for delta in (0.5, 0.2):
        a = solve_joint(inst, delta, {}, budget=None)
        b = solve_prob_milp(inst, delta)
        assert a.status == b.status
        if b.status == "optimal":
            assert math.isclose(a.alert_cost, b.cost, rel_tol=1e-6, abs_tol=1e-6)
        z = solve_joint(inst, delta, _uniform_blocks(inst), budget=0.0)
        assert z.status == b.status
        if b.status == "optimal":
            assert math.isclose(z.alert_cost, b.cost, rel_tol=1e-6, abs_tol=1e-6)


def test_blind_path_fixed_by_blocking():
    # s -> a (unobservable) -> t: no rule can see it, so detection alone is infeasible.
    nodes = ["s", "a", "t"]
    edges = [Edge("s", "a", None, None), Edge("a", "t", None, None)]
    rules = [Rule("r", frozenset({"x"}), frozenset({"z"}), 1.0, tpr=0.9)]
    inst = Instance(nodes, edges, rules, "s", {"t"})
    assert solve_prob_milp(inst, 0.5).status == "infeasible"
    sol = solve_joint(inst, 0.5, {0: 5.0, 1: 2.0}, budget=10.0, lam=1e-3)
    assert sol.status == "optimal"
    assert sol.blocked == [1] and sol.rules == [] and sol.alert_cost == 0.0
    assert joint_achieved_delta(inst, sol.rules, sol.blocked) == 0.0


def test_hardening_only_baseline():
    nodes = ["s", "a", "b", "t"]
    edges = [Edge("s", "a", "T1", "x"), Edge("a", "t", "T2", "x"),
             Edge("s", "b", "T1", "y"), Edge("b", "t", "T2", "y")]
    rules = [Rule("r", frozenset({"T2"}), frozenset({"x", "y"}), 3.0, tpr=0.99)]
    inst = Instance(nodes, edges, rules, "s", {"t"})
    blocks = {1: 1.0, 3: 4.0, 0: 2.0, 2: 2.0}
    only = solve_joint(inst, 0.5, blocks, allow_rules=False)
    assert only.status == "optimal" and only.rules == []
    assert math.isclose(only.harden_cost, 3.0)  # block a->t (1) and s->b (2)
    assert joint_achieved_delta(inst, [], only.blocked) == 0.0


@pytest.mark.parametrize("seed", range(4))
def test_pareto_monotone_and_verified(seed):
    inst = assign_tpr(generate(GenParams(seed=seed)), seed)
    blocks = default_block_costs(inst)
    budgets = [0, 2, 5, 10, 20]
    prev = math.inf
    for H, sol in pareto(inst, 0.2, blocks, budgets, time_limit=60):
        if sol.status != "optimal":
            continue
        assert sol.alert_cost <= prev + 1e-6
        prev = sol.alert_cost
        assert sol.harden_cost <= H + EPS
        assert joint_meets(inst, sol, 0.2)


def test_default_block_costs_excludes_source_and_target_membership():
    nodes = ["ENTRY", "u", "DA"]
    edges = [Edge("ENTRY", "u", None, None), Edge("u", "DA", None, None),
             Edge("u", "DA", "T1003", "ws")]
    inst = Instance(nodes, edges, [], "ENTRY", {"DA"})
    assert default_block_costs(inst) == {2: 3.0}
