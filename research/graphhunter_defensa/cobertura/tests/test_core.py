import itertools
import random

import pytest

from graphhunter_defensa.cobertura import (Edge, Instance, Rule, coverable_cut_exists, is_cut,
                      solve_lp, solve_milp, undetected_disjoint_paths)
from graphhunter_defensa.cobertura.baselines import all_rules, attack_coverage_first, greedy_ratio
from graphhunter_defensa.cobertura.generator import GenParams, generate
from graphhunter_defensa.cobertura.verify import blind_path

EPS = 1e-6


def R(name, pairs, cost):
    ts = frozenset(t for t, _ in pairs)
    ss = frozenset(s for _, s in pairs)
    return Rule(name, ts, ss, cost)


def diamond():
    # each edge has its own technique/scope so rules can target edges exactly
    E = [Edge("s", "a", "t1", "x"), Edge("s", "b", "t2", "x"),
         Edge("a", "t", "t3", "x"), Edge("b", "t", "t4", "x")]
    rules = [
        Rule("r1", frozenset({"t1", "t2"}), frozenset({"x"}), 5.0),
        Rule("r2", frozenset({"t3"}), frozenset({"x"}), 1.0),
        Rule("r3", frozenset({"t4"}), frozenset({"x"}), 1.0),
        Rule("r4", frozenset({"t1", "t4"}), frozenset({"x"}), 1.5),
    ]
    return Instance(["s", "a", "b", "t"], E, rules, "s", {"t"})


def test_diamond_optimum():
    inst = diamond()
    sol = solve_milp(inst)
    assert sol.status == "optimal"
    assert sorted(inst.rules[i].name for i in sol.rules) == ["r4"]
    assert abs(sol.cost - 1.5) < EPS
    assert is_cut(inst, sol.rules)
    assert undetected_disjoint_paths(inst, sol.rules) == 0
    assert undetected_disjoint_paths(inst, []) == 2


def test_infeasible_reports_blind_path():
    E = [Edge("s", "a", None, None), Edge("a", "t", None, None),
         Edge("s", "t", "t1", "x")]
    inst = Instance(["s", "a", "t"], E, [Rule("r", frozenset({"t1"}), frozenset({"x"}), 1.0)],
                    "s", {"t"})
    assert not coverable_cut_exists(inst)
    assert solve_milp(inst).status == "infeasible"
    assert blind_path(inst) == [0, 1]


def test_instance_validation():
    with pytest.raises(ValueError):
        Instance(["s"], [], [], "s", {"s"})
    with pytest.raises(ValueError):
        Instance(["s", "t"], [Edge("s", "z", None, None)], [], "s", {"t"})
    with pytest.raises(ValueError):
        Instance(["s", "t"], [], [Rule("r", frozenset(), frozenset(), -1)], "s", {"t"})


def random_instance(seed, n=7, m=14, k=9):
    rnd = random.Random(seed)
    nodes = [f"n{i}" for i in range(n)]
    techs = [f"t{i}" for i in range(5)]
    scopes = ["a", "b"]
    edges = []
    for _ in range(m):
        u, v = rnd.sample(nodes, 2)
        t = rnd.choice(techs + [None])
        edges.append(Edge(u, v, t, rnd.choice(scopes) if t else None))
    rules = []
    for i in range(k):
        ts = frozenset(rnd.sample(techs, rnd.randint(1, 2)))
        ss = frozenset(rnd.sample(scopes, rnd.randint(1, 2)))
        rules.append(Rule(f"r{i}", ts, ss, round(rnd.uniform(0.1, 10), 2)))
    return Instance(nodes, edges, rules, "n0", {f"n{n - 1}"})


def brute_force(inst):
    best = None
    for k in range(len(inst.rules) + 1):
        for sub in itertools.combinations(range(len(inst.rules)), k):
            if is_cut(inst, sub):
                c = inst.rule_cost(sub)
                if best is None or c < best - EPS:
                    best = c
    return best


@pytest.mark.parametrize("seed", range(40))
def test_milp_matches_brute_force(seed):
    inst = random_instance(seed)
    bf = brute_force(inst)
    sol = solve_milp(inst)
    if bf is None:
        assert sol.status == "infeasible"
        assert blind_path(inst) is not None
        return
    assert sol.status == "optimal"
    assert abs(sol.cost - bf) < 1e-6, (sol.cost, bf)
    assert is_cut(inst, sol.rules)
    lp = solve_lp(inst)
    assert lp.cost <= sol.cost + 1e-6
    for heur in (greedy_ratio, attack_coverage_first, all_rules):
        h = heur(inst)
        assert is_cut(inst, h)
        assert inst.rule_cost(h) >= sol.cost - 1e-6


@pytest.mark.parametrize("seed", range(5))
def test_generated_instances(seed):
    inst = generate(GenParams(seed=seed))
    sol = solve_milp(inst)
    if not coverable_cut_exists(inst):
        assert sol.status == "infeasible"
        path = blind_path(inst)
        assert path and all(not inst.coverage[ei] for ei in path)
        return
    assert sol.status == "optimal" and is_cut(inst, sol.rules)
    # making an edge free can never increase the optimum
    for ei in range(0, len(inst.edges), 25):
        assert solve_milp(inst, free_edges=frozenset({ei})).cost <= sol.cost + 1e-6
