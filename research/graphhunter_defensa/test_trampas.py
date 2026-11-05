"""La reducción de trampas a reglas da el mismo óptimo que resolver el
problema original (reglas en aristas + trampas en nodos) por fuerza bruta."""

import itertools
import math
import random

import pytest

from graphhunter_defensa.cobertura.model import Edge, Instance, Rule
from graphhunter_defensa.cobertura.prob import evasion_distances, solve_prob_milp, theta_of
from graphhunter_defensa.trampas import con_trampas, evasion_con_trampas, resolver_con_tope


def instancia(semilla: int) -> Instance:
    rng = random.Random(semilla)
    nodos = ["s"] + [f"n{i}" for i in range(7)] + ["t"]
    aristas = set()
    for _ in range(18):
        u, v = rng.sample(nodos, 2)
        if u != "t" and v != "s":
            aristas.add((u, v))
    aristas |= {("s", "n0"), ("n0", "n1"), ("n1", "t")}  # al menos un camino
    tecnicas, alcances = ["T1", "T2", "T3"], ["a", "b"]
    E = [Edge(u, v, rng.choice(tecnicas + [None]), rng.choice(alcances)) for u, v in sorted(aristas)]
    R = [Rule(f"r{i}", frozenset(rng.sample(tecnicas, rng.randint(1, 2))), frozenset(rng.sample(alcances, rng.randint(1, 2))),
              round(rng.uniform(1, 10), 2), round(rng.uniform(0.3, 0.9), 2)) for i in range(5)]
    return Instance(nodos, E, R, "s", {"t"})


def fuerza_bruta(inst, candidatos, costo_trampa, delta, k=None):
    theta, mejor = theta_of(delta), (math.inf, None)
    R = range(len(inst.rules))
    for nr in range(len(inst.rules) + 1):
        for reglas in itertools.combinations(R, nr):
            for j in range((len(candidatos) if k is None else min(k, len(candidatos))) + 1):
                for tr in itertools.combinations(candidatos, j):
                    costo = inst.rule_cost(reglas) + costo_trampa * len(tr)
                    if costo < mejor[0] and min(evasion_con_trampas(inst, reglas, tr).values()) >= theta * (1 - 1e-9):
                        mejor = (costo, (reglas, tr))
    return mejor


@pytest.mark.parametrize("semilla", range(25))
def test_optimo_igual_a_fuerza_bruta(semilla):
    inst = instancia(semilla)
    rng = random.Random(100 + semilla)
    candidatos = rng.sample([n for n in inst.nodes if n not in ("s", "t")], 3)
    costo_trampa = rng.choice([0.5, 3.0, 20.0])
    delta = rng.choice([0.05, 0.2])
    esperado, _ = fuerza_bruta(inst, candidatos, costo_trampa, delta)
    partida, _ = con_trampas(inst, candidatos, costo_trampa)
    sol = solve_prob_milp(partida, delta)
    if esperado == math.inf:
        assert sol.status == "infeasible"
    else:
        assert sol.status == "optimal"
        assert sol.cost == pytest.approx(esperado, rel=1e-6, abs=1e-9)


@pytest.mark.parametrize("semilla", range(10))
def test_distancias_coinciden(semilla):
    """Para cualquier elección de reglas y trampas, la evasión en la instancia
    partida es la misma que en la original con trampas en nodos."""
    inst = instancia(semilla)
    rng = random.Random(semilla)
    candidatos = [n for n in inst.nodes if n not in ("s", "t")]
    partida, idx = con_trampas(inst, candidatos, 1.0)
    for _ in range(20):
        reglas = [i for i in range(len(inst.rules)) if rng.random() < 0.5]
        tr = [v for v in candidatos if rng.random() < 0.3]
        d, _ = evasion_distances(partida, reglas + [idx[v] for v in tr])
        assert d.get("t", math.inf) == pytest.approx(evasion_con_trampas(inst, reglas, tr)["t"])


def test_origen_y_terminal_no_se_parten():
    inst = instancia(0)
    with pytest.raises(ValueError):
        con_trampas(inst, ["t"], 1.0)
    with pytest.raises(ValueError):
        con_trampas(inst, ["s"], 1.0)


@pytest.mark.parametrize("semilla", range(25))
@pytest.mark.parametrize("k", [0, 1, 2])
def test_tope_de_trampas_igual_a_fuerza_bruta(semilla, k):
    inst = instancia(semilla)
    rng = random.Random(200 + semilla)
    candidatos = rng.sample([n for n in inst.nodes if n not in ("s", "t")], 4)
    costo_trampa = rng.choice([0.5, 3.0])
    delta = rng.choice([0.05, 0.2])
    esperado, _ = fuerza_bruta(inst, candidatos, costo_trampa, delta, k=k)
    partida, idx = con_trampas(inst, candidatos, costo_trampa)
    sol = resolver_con_tope(partida, delta, idx, k)
    if esperado == math.inf:
        assert sol.status == "infeasible"
    else:
        assert sol.status == "optimal"
        assert sol.cost == pytest.approx(esperado, rel=1e-6, abs=1e-9)
        assert sum(1 for i in sol.rules if i in idx.values()) <= k
