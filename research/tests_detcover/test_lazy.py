import math

import pytest

from detcover.generator import GenParams, generate
from detcover.joint import default_block_costs, joint_meets, solve_joint
from detcover.lazy import solve_lazy
from detcover.prob import assign_tpr, solve_prob_milp
from test_core import random_instance


def _blocks(inst):
    return {ei: 1.0 + (ei % 3) for ei, e in enumerate(inst.edges) if e.u != inst.source}


@pytest.mark.parametrize("seed", range(40))
@pytest.mark.parametrize("delta", [0.5, 0.2, 0.05])
def test_lazy_matches_prob_milp(seed, delta):
    inst = assign_tpr(random_instance(seed), seed)
    a = solve_lazy(inst, delta)
    b = solve_prob_milp(inst, delta)
    assert a.status == b.status
    if b.status == "optimal":
        assert math.isclose(a.alert_cost, b.cost, rel_tol=1e-6, abs_tol=1e-6)


@pytest.mark.parametrize("seed", range(30))
@pytest.mark.parametrize("budget", [0.0, 2.0, 5.0])
def test_lazy_matches_joint(seed, budget):
    inst = assign_tpr(random_instance(seed), seed)
    blocks = _blocks(inst)
    a = solve_lazy(inst, 0.2, blocks, budget=budget)
    b = solve_joint(inst, 0.2, blocks, budget=budget)
    assert a.status == b.status
    if b.status == "optimal":
        assert math.isclose(a.alert_cost, b.alert_cost, rel_tol=1e-6, abs_tol=1e-6)
        assert a.harden_cost <= budget + 1e-9
        assert joint_meets(inst, a, 0.2)


@pytest.mark.parametrize("seed", range(20))
def test_lazy_hardening_only(seed):
    inst = assign_tpr(random_instance(seed), seed)
    blocks = _blocks(inst)
    a = solve_lazy(inst, 0.2, blocks, allow_rules=False)
    b = solve_joint(inst, 0.2, blocks, allow_rules=False)
    assert a.status == b.status
    if b.status == "optimal":
        assert math.isclose(a.harden_cost, b.harden_cost, rel_tol=1e-6, abs_tol=1e-6)


@pytest.mark.parametrize("seed", range(5))
def test_lazy_on_generated_graphs(seed):
    inst = assign_tpr(generate(GenParams(seed=seed)), seed)
    blocks = default_block_costs(inst)
    for delta, H in [(0.5, 0.0), (0.2, 6.0)]:
        a = solve_lazy(inst, delta, blocks, budget=H)
        b = solve_joint(inst, delta, blocks, budget=H, time_limit=120)
        assert a.status == b.status
        if b.status == "optimal":
            assert math.isclose(a.alert_cost, b.alert_cost, rel_tol=1e-6, abs_tol=1e-6)
            assert joint_meets(inst, a, delta)
